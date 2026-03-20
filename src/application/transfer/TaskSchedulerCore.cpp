
#include "TaskSchedulerCore.hpp"

#include "domain/client/ClientDomainService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/time.hpp"


#include <algorithm>
#include <chrono>
#include <utility>

namespace AMApplication::TransferRuntime {

size_t TaskSchedulerCore::ClampThreadCount(size_t count) {
  constexpr size_t kMinThreads = 1;
  constexpr size_t kMaxThreads = 64;
  return std::max<size_t>(kMinThreads, std::min<size_t>(count, kMaxThreads));
}

bool TaskSchedulerCore::IsValidThreadId(int thread_id) const {
  const size_t active_count =
      desired_thread_count_.load(std::memory_order_relaxed);
  return thread_id >= 0 && static_cast<size_t>(thread_id) < active_count &&
         static_cast<size_t>(thread_id) < affinity_queues_.size();
}

bool TaskSchedulerCore::IsTaskIdUsed_(const TaskId &task_id) const {
  std::scoped_lock lock(registry_mtx_, result_mtx_, conducting_mtx_);
  if (task_registry_.find(task_id) != task_registry_.end()) {
    return true;
  }
  if (results_.find(task_id) != results_.end()) {
    return true;
  }
  return conducting_tasks_.find(task_id) != conducting_tasks_.end();
}

TaskSchedulerCore::TaskId TaskSchedulerCore::GenerateTaskId_() const {
  static std::atomic<uint64_t> counter{0};
  while (true) {
    const uint64_t value = counter.fetch_add(1, std::memory_order_relaxed);
    TaskId candidate = std::to_string(value);
    if (!IsTaskIdUsed_(candidate)) {
      return candidate;
    }
  }
}

bool TaskSchedulerCore::HasPendingTasksLocked() const {
  if (!public_queue_.empty()) {
    return true;
  }
  for (const auto &queue : affinity_queues_) {
    if (!queue.empty()) {
      return true;
    }
  }
  return false;
}

void TaskSchedulerCore::SetTaskPool_(
    const TaskId &task_id,
    const std::shared_ptr<
        AMApplication::TransferRuntime::ITransferClientPoolPort> &pool) {
  if (task_id.empty()) {
    return;
  }
  std::lock_guard<std::mutex> lock(task_pool_mtx_);
  if (pool) {
    task_pools_[task_id] = pool;
  } else {
    task_pools_.erase(task_id);
  }
}

std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
TaskSchedulerCore::GetTaskPool_(const TaskId &task_id) const {
  if (task_id.empty()) {
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(task_pool_mtx_);
  auto it = task_pools_.find(task_id);
  if (it == task_pools_.end()) {
    return nullptr;
  }
  return it->second;
}

std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
TaskSchedulerCore::TakeTaskPool_(const TaskId &task_id) {
  if (task_id.empty()) {
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(task_pool_mtx_);
  auto it = task_pools_.find(task_id);
  if (it == task_pools_.end()) {
    return nullptr;
  }
  auto pool = it->second;
  task_pools_.erase(it);
  return pool;
}

void TaskSchedulerCore::ReleaseTaskResources_(const TaskId &task_id) {
  auto pool = TakeTaskPool_(task_id);
  if (pool) {
    pool->ReleaseTask(task_id);
  }
}

void TaskSchedulerCore::CancelPendingTasksOnExit_(const std::string &reason) {
  std::vector<std::shared_ptr<TaskInfo>> canceled_tasks;
  {
    std::scoped_lock<std::mutex, std::mutex> lock(registry_mtx_, queue_mtx_);
    auto cancel_one = [&](const TaskId &task_id) {
      auto it = task_registry_.find(task_id);
      if (it == task_registry_.end() || !it->second) {
        return;
      }
      auto task_info = it->second;
      task_registry_.erase(it);
      if (task_info->pd) {
        task_info->pd->set_terminate();
      }
      task_info->SetResult({EC::Terminate, reason});
      task_info->SetStatus(TaskStatus::Finished);
      task_info->finished_time.store(AMTime::seconds(),
                                     std::memory_order_relaxed);
      task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
      canceled_tasks.push_back(std::move(task_info));
    };

    for (const auto &task_id : public_queue_) {
      cancel_one(task_id);
    }
    public_queue_.clear();

    for (auto &queue : affinity_queues_) {
      for (const auto &task_id : queue) {
        cancel_one(task_id);
      }
      queue.clear();
    }
  }

  for (const auto &task_info : canceled_tasks) {
    ReleaseTaskResources_(task_info->id);
    HandleCompletedTask(task_info);
  }
}

void TaskSchedulerCore::EnsureProgressData(
    const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info->control_token) {
    task_info->control_token = std::make_shared<TaskControlToken>();
  }
  if (!task_info->pd) {
    task_info->pd = std::make_shared<WkProgressData>(task_info);
  }
  task_info->pd->interrupt_flag = task_info->control_token;
  if (!task_info->pd->inner_callback) {
    std::weak_ptr<TaskInfo> ti_w = task_info;
    std::weak_ptr<WkProgressData> pd_w = task_info->pd;
    task_info->pd->inner_callback = [this, ti_w, pd_w](bool force) {
      auto ti_s = ti_w.lock();
      auto pd_s = pd_w.lock();
      if (!ti_s || !pd_s) {
        return;
      }
      this->InnerCallback(ti_s, *pd_s, force);
    };
  }
  task_info->pd->task_info = task_info;
  task_info->pd->SyncInterruptFlagFromTaskInfo();
}

void TaskSchedulerCore::RegisterTask(const std::shared_ptr<TaskInfo> &task_info,
                                     TaskAssignType assign_type,
                                     int affinity_thread) {
  std::scoped_lock<std::mutex, std::mutex> lock(registry_mtx_, queue_mtx_);
  std::list<TaskId> *target_queue = nullptr;
  if (assign_type == TaskAssignType::Affinity &&
      IsValidThreadId(affinity_thread)) {
    target_queue = &affinity_queues_[static_cast<size_t>(affinity_thread)];
  } else {
    assign_type = TaskAssignType::Public;
    affinity_thread = -1;
    target_queue = &public_queue_;
  }

  target_queue->push_back(task_info->id);

  task_info->assign_type.store(assign_type, std::memory_order_relaxed);
  task_info->affinity_thread.store(affinity_thread, std::memory_order_relaxed);
  task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
  task_registry_[task_info->id] = task_info;
}
std::optional<std::pair<TaskSchedulerCore::TaskId, std::shared_ptr<TaskInfo>>>
TaskSchedulerCore::DequeueTask(size_t thread_index) {
  while (true) {
    {
      std::unique_lock<std::mutex> lock(queue_mtx_);
      queue_cv_.wait(lock, [this, thread_index]() {
        return !running_.load(std::memory_order_acquire) ||
               HasPendingTasksLocked() ||
               thread_index >=
                   desired_thread_count_.load(std::memory_order_relaxed);
      });

      if (!running_.load(std::memory_order_relaxed) &&
          !HasPendingTasksLocked()) {
        return std::nullopt;
      }

      if (thread_index >=
          desired_thread_count_.load(std::memory_order_relaxed)) {
        const bool has_affinity = thread_index < affinity_queues_.size() &&
                                  !affinity_queues_[thread_index].empty();
        if (!has_affinity) {
          return std::nullopt;
        }
      }

      TaskId task_id;
      if (thread_index < affinity_queues_.size() &&
          !affinity_queues_[thread_index].empty()) {
        task_id = affinity_queues_[thread_index].front();
        affinity_queues_[thread_index].pop_front();
      } else if (!public_queue_.empty()) {
        task_id = public_queue_.front();
        public_queue_.pop_front();
      } else {
        continue;
      }

      lock.unlock();

      std::lock_guard<std::mutex> registry_lock(registry_mtx_);
      auto it = task_registry_.find(task_id);
      if (it == task_registry_.end()) {
        continue;
      }
      auto task_info = it->second;
      return {{task_id, task_info}};
    }
  }
}

void TaskSchedulerCore::HandleCompletedTask(
    const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info || !task_info->TryMarkCompletionDispatched()) {
    return;
  }
  if (task_info->result_callback) {
    CallCallbackSafe(task_info->result_callback, task_info);
    return;
  }
  std::lock_guard<std::mutex> lock(result_mtx_);
  results_[task_info->id] = task_info;
}

void TaskSchedulerCore::SetConducting(
    size_t thread_index, const TaskId &task_id,
    const std::shared_ptr<TaskInfo> &task_info) {
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  if (thread_index >= conducting_by_thread_.size()) {
    conducting_by_thread_.resize(thread_index + 1);
    conducting_infos_.resize(thread_index + 1);
  }
  conducting_by_thread_[thread_index] = task_id;
  conducting_infos_[thread_index] = task_info;
  conducting_tasks_.insert(task_id);
}

void TaskSchedulerCore::ClearConducting(size_t thread_index) {
  bool removed_task = false;
  std::shared_ptr<TaskInfo> finished_info = nullptr;
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (thread_index < conducting_by_thread_.size()) {
      const TaskId id = conducting_by_thread_[thread_index];
      if (!id.empty()) {
        conducting_tasks_.erase(id);
        removed_task = true;
      }
      finished_info = conducting_infos_[thread_index];
      conducting_by_thread_[thread_index].clear();
      conducting_infos_[thread_index] = nullptr;
    }
  }
  if (finished_info) {
    finished_info->OnWhichThread.store(-1, std::memory_order_relaxed);
  }
  if (removed_task) {
    conducting_cv_.notify_all();
  }
}

void TaskSchedulerCore::InnerCallback(std::shared_ptr<TaskInfo> task_info,
                                      WkProgressData &pd, bool force) {
  if (!task_info->callback.need_progress_cb) {
    return;
  }
  TransferTask *cur_task = nullptr;
  {
    std::lock_guard<std::mutex> lock(task_info->mtx);
    cur_task = task_info->cur_task;
  }
  if (!cur_task) {
    return;
  }

  auto time_now = AMTime::seconds();
  if (!force &&
      ((time_now - pd.cb_time) <= task_info->callback.cb_interval_s)) {
    return;
  }

  pd.cb_time = time_now;
  ECM cb_error = {EC::Success, ""};
  auto ctrl_opt = task_info->callback.CallProgress(
      ProgressCBInfo(
          cur_task->src, cur_task->dst, cur_task->src_host, cur_task->dst_host,
          cur_task->transferred, cur_task->size,
          task_info->total_transferred_size.load(std::memory_order_relaxed),
          task_info->total_size.load(std::memory_order_relaxed)),
      &cb_error);

  if (cb_error.first != EC::Success && task_info->callback.need_error_cb) {
    task_info->callback.CallError(ErrorCBInfo(cb_error, cur_task->src,
                                              cur_task->dst, cur_task->src_host,
                                              cur_task->dst_host));
  }

  if (!ctrl_opt.has_value()) {
    return;
  }

  switch (*ctrl_opt) {
  case TransferControl::Running:
    pd.set_running();
    break;
  case TransferControl::Pause:
    pd.set_pause();
    break;
  case TransferControl::Terminate:
    pd.set_terminate();
    break;
  default:
    break;
  }
}

bool TaskSchedulerCore::ShouldSkipTask(std::shared_ptr<TaskInfo> task_info) {
  if (task_info->pd && task_info->pd->is_terminate_only()) {
    task_info->SetResult({EC::Terminate, "Task terminated before start"});
    task_info->SetStatus(TaskStatus::Finished);
    task_info->finished_time.store(AMTime::seconds(),
                                   std::memory_order_relaxed);
    return true;
  }
  return false;
}

ssize_t TaskSchedulerCore::ResolveBufferHint_(const ClientHandle &client) {
  if (!client) {
    return -1;
  }
  return client->ConfigPort().GetRequest().buffer_size;
}

ssize_t TaskSchedulerCore::CalculateBufferSize(const ClientHandle &src_client,
                                               const ClientHandle &dst_client,
                                               ssize_t provided_size) {
  const ssize_t src_size = ResolveBufferHint_(src_client);
  const ssize_t dst_size = ResolveBufferHint_(dst_client);
  const bool is_local = !src_client && !dst_client;
  if (provided_size > AMMinBufferSize && provided_size < AMMaxBufferSize) {
    return provided_size;
  }
  if (src_size < 0 && dst_size < 0) {
    return is_local ? AMDefaultLocalBufferSize : AMDefaultRemoteBufferSize;
  }
  if (src_size > 0 && dst_size < 0) {
    return std::max<ssize_t>(std::min<ssize_t>(src_size, AMMaxBufferSize),
                             AMMinBufferSize);
  }
  if (src_size > 0 && dst_size > 0) {
    return std::max<ssize_t>(
        std::min<ssize_t>({src_size, dst_size, AMMaxBufferSize}),
        AMMinBufferSize);
  }
  return std::max<ssize_t>(std::min<ssize_t>(dst_size, AMMaxBufferSize),
                           AMMinBufferSize);
}

std::string
TaskSchedulerCore::CanonicalTaskNickname_(const std::string &nickname) {
  if (nickname.empty() ||
      AMDomain::host::HostManagerService::IsLocalNickname(nickname)) {
    return "local";
  }
  return AMDomain::client::ClientDomainService::NormalizeNickname(nickname);
}

std::vector<std::string> TaskSchedulerCore::CollectTaskNicknames_(
    const std::shared_ptr<TaskInfo> &task_info) const {
  std::vector<std::string> nicknames;
  if (!task_info || !task_info->tasks) {
    return nicknames;
  }

  std::unordered_set<std::string> seen;
  for (const auto &task : *task_info->tasks) {
    const std::string src_name = CanonicalTaskNickname_(task.src_host);
    if (!src_name.empty() && seen.insert(src_name).second) {
      nicknames.push_back(src_name);
    }
    const std::string dst_name = CanonicalTaskNickname_(task.dst_host);
    if (!dst_name.empty() && seen.insert(dst_name).second) {
      nicknames.push_back(dst_name);
    }
  }
  return nicknames;
}

std::pair<TaskSchedulerCore::ECM, TaskSchedulerCore::TaskClientCollection>
TaskSchedulerCore::AcquireTaskClients_(
    const std::shared_ptr<TaskInfo> &task_info,
    const std::shared_ptr<
        AMApplication::TransferRuntime::ITransferClientPoolPort> &pool) {
  if (!task_info) {
    return {{EC::InvalidArg, "TaskInfo is nullptr"}, TaskClientCollection{}};
  }
  if (!pool) {
    return {{EC::InvalidHandle, "Transfer client pool is not bound"},
            TaskClientCollection{}};
  }

  auto [acquire_rcm, primary] =
      pool->AcquireClients(task_info->id, CollectTaskNicknames_(task_info));
  if (acquire_rcm.first != EC::Success) {
    return {acquire_rcm, TaskClientCollection{}};
  }

  TaskClientCollection collection;
  collection.primary_clients = std::move(primary);

  std::unordered_set<std::string> same_host_nicknames;
  if (task_info->tasks) {
    for (const auto &task : *(task_info->tasks)) {
      const std::string src_key = CanonicalTaskNickname_(task.src_host);
      const std::string dst_key = CanonicalTaskNickname_(task.dst_host);
      if (!src_key.empty() && src_key == dst_key) {
        same_host_nicknames.insert(src_key);
      }
    }
  }

  for (const auto &nickname : same_host_nicknames) {
    auto [extra_rcm, extra_client] =
        pool->AcquireClient(task_info->id, nickname, -1, -1, true);
    if (extra_rcm.first != EC::Success || !extra_client) {
      if (extra_rcm.first == EC::Success) {
        extra_rcm = {
            EC::InvalidHandle,
            AMStr::fmt("Failed to acquire extra client for {}", nickname)};
      }
      return {extra_rcm, TaskClientCollection{}};
    }
    auto primary_it = collection.primary_clients.find(nickname);
    if (primary_it != collection.primary_clients.end() && primary_it->second &&
        primary_it->second->GetUID() == extra_client->GetUID()) {
      return {{EC::InvalidHandle,
               AMStr::fmt("Acquire extra client for {} returned same id {}",
                          nickname, extra_client->GetUID())},
              TaskClientCollection{}};
    }
    collection.secondary_clients[nickname] = std::move(extra_client);
  }
  return {{EC::Success, ""}, std::move(collection)};
}

TaskSchedulerCore::ClientHandle
TaskSchedulerCore::ResolveTaskClient_(const TaskClientCollection &clients,
                                      const std::string &nickname,
                                      bool prefer_secondary) const {
  const std::string key = CanonicalTaskNickname_(nickname);
  if (prefer_secondary) {
    auto secondary_it = clients.secondary_clients.find(key);
    if (secondary_it != clients.secondary_clients.end()) {
      return secondary_it->second;
    }
    return nullptr;
  }
  auto primary_it = clients.primary_clients.find(key);
  if (primary_it == clients.primary_clients.end()) {
    return nullptr;
  }
  return primary_it->second;
}

void TaskSchedulerCore::WorkerLoop(size_t thread_index) {
  while (running_.load(std::memory_order_relaxed)) {
    if (thread_index >= desired_thread_count_.load(std::memory_order_relaxed)) {
      std::lock_guard<std::mutex> lock(queue_mtx_);
      const bool has_affinity = thread_index < affinity_queues_.size() &&
                                !affinity_queues_[thread_index].empty();
      if (!has_affinity) {
        break;
      }
    }

    auto task_opt = DequeueTask(thread_index);
    if (!task_opt.has_value()) {
      break;
    }

    const auto &[task_id, task_info] = *task_opt;
    SetConducting(thread_index, task_id, task_info);
    task_info->OnWhichThread.store(static_cast<int>(thread_index),
                                   std::memory_order_relaxed);

    if (ShouldSkipTask(task_info)) {
      task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
      {
        std::lock_guard<std::mutex> registry_lock(registry_mtx_);
        task_registry_.erase(task_id);
      }
      ReleaseTaskResources_(task_info->id);
      HandleCompletedTask(task_info);
      ClearConducting(thread_index);
      continue;
    }

    EnsureProgressData(task_info);
    ExecuteTask(task_info);
    task_info->DeleteProgressData();

    if (task_info->GetStatus() != TaskStatus::Paused) {
      {
        std::lock_guard<std::mutex> registry_lock(registry_mtx_);
        task_registry_.erase(task_info->id);
      }
      ReleaseTaskResources_(task_info->id);
      HandleCompletedTask(task_info);
    }
    ClearConducting(thread_index);
  }

  ClearConducting(thread_index);
}

void TaskSchedulerCore::ExecuteTask(std::shared_ptr<TaskInfo> task_info) {
  task_info->SetStatus(TaskStatus::Conducting);
  if (!task_info->keep_start_time.load(std::memory_order_relaxed) ||
      task_info->start_time.load(std::memory_order_relaxed) <= 0.0) {
    task_info->start_time.store(AMTime::seconds(), std::memory_order_relaxed);
  }

  if (task_info->callback.need_total_size_cb) {
    task_info->callback.CallTotalSize(
        task_info->total_size.load(std::memory_order_relaxed));
  }

  auto &pd = *(task_info->pd);
  pd.task_info = task_info;

  if (!task_info->tasks) {
    task_info->SetStatus(TaskStatus::Finished);
    task_info->SetResult({EC::InvalidArg, "No task is provided"});
    task_info->finished_time.store(AMTime::seconds(),
                                   std::memory_order_relaxed);
    return;
  }

  auto pool = GetTaskPool_(task_info->id);
  auto [acquire_rcm, task_clients] = AcquireTaskClients_(task_info, pool);
  if (acquire_rcm.first != EC::Success) {
    task_info->SetStatus(TaskStatus::Finished);
    task_info->SetResult(acquire_rcm);
    task_info->finished_time.store(AMTime::seconds(),
                                   std::memory_order_relaxed);
    return;
  }

  for (auto &task : *(task_info->tasks)) {
    if (pd.is_pause_only()) {
      task_info->SetStatus(TaskStatus::Paused);
      task_info->keep_start_time.store(true, std::memory_order_relaxed);
      return;
    }
    if (pd.is_terminate_only()) {
      task.rcm = {EC::Terminate, "Task terminated by user"};
      task.IsFinished = true;
      continue;
    }

    if (task.IsFinished) {
      continue;
    }

    const std::string src_key = CanonicalTaskNickname_(task.src_host);
    const std::string dst_key = CanonicalTaskNickname_(task.dst_host);
    const bool same_host_transfer = !src_key.empty() && src_key == dst_key;
    auto src_client = ResolveTaskClient_(task_clients, task.src_host, false);
    auto dst_client =
        ResolveTaskClient_(task_clients, task.dst_host, same_host_transfer);
    if (!src_client || !dst_client) {
      task.rcm = {EC::ClientNotFound, "Task client is not available in pool"};
      task.IsFinished = true;
      if (task_info->callback.need_error_cb) {
        task_info->callback.CallError(ErrorCBInfo(
            task.rcm, task.src, task.dst, task.src_host, task.dst_host));
      }
      continue;
    }

    if (task.path_type == PathType::DIR) {
      task.rcm = dst_client->IOPort().mkdirs({task.dst, {}});
      task.IsFinished = true;
      continue;
    }

    task_info->SetCurrentTask(&task);
    task.rcm = ECM(EC::Success, "");
    size_t resume_offset = task.transferred;
    if (resume_offset > 0) {
      if (resume_offset > task.size) {
        task.rcm = {EC::InvalidOffset, "Offset exceeds src size"};
        task.IsFinished = true;
        if (task_info->callback.need_error_cb) {
          task_info->callback.CallError(ErrorCBInfo(
              task.rcm, task.src, task.dst, task.src_host, task.dst_host));
        }
        continue;
      }
      auto dst_stat = dst_client->IOPort().stat({task.dst, false, {}});
      if (dst_stat.rcm.first != EC::Success) {
        task.rcm = {EC::InvalidOffset, "Dst stat failed but offset is given"};
        task.IsFinished = true;
        goto OffsetErrorCB;
      }
      if (dst_stat.info.type == PathType::DIR) {
        task.rcm = {EC::NotAFile, "Dst already exists but is a directory"};
        task.IsFinished = true;
        goto OffsetErrorCB;
      }
      if (resume_offset > dst_stat.info.size) {
        task.rcm = {EC::InvalidOffset, "Offset exceeds dst file size"};
        task.IsFinished = true;
        goto OffsetErrorCB;
      }
      goto PassOffsetCheck;
    OffsetErrorCB:
      if (task_info->callback.need_error_cb) {
        task_info->callback.CallError(ErrorCBInfo(
            task.rcm, task.src, task.dst, task.src_host, task.dst_host));
      }
      continue;
    }
  PassOffsetCheck:
    task_info->this_task_transferred_size.store(resume_offset,
                                                std::memory_order_relaxed);
    if (resume_offset > 0) {
      task_info->total_transferred_size.fetch_add(resume_offset,
                                                  std::memory_order_relaxed);
    }

    pd.ring_buffer = std::make_shared<StreamRingBuffer>(CalculateBufferSize(
        src_client, dst_client,
        task_info->buffer_size.load(std::memory_order_relaxed)));

    task.rcm = execution_engine_->TransferSignleFile(src_client, dst_client,
                                                     task_info);
    if (pd.is_pause_only()) {
      task.rcm = {EC::TransferPause, "Task paused by user"};
      task_info->SetStatus(TaskStatus::Paused);
      task_info->keep_start_time.store(true, std::memory_order_relaxed);
      return;
    }
    task.IsFinished = true;
    if (task.rcm.first == EC::Success) {
      task_info->success_filenum.fetch_add(1, std::memory_order_relaxed);
    } else if (task.rcm.first != EC::Success &&
               task_info->callback.need_error_cb &&
               task.rcm.first != EC::Terminate &&
               task.rcm.first != EC::TransferPause) {
      task_info->callback.CallError(ErrorCBInfo(task.rcm, task.src, task.dst,
                                                task.src_host, task.dst_host));
    }

    InnerCallback(task_info, pd, true);
  }

  if (!task_info->pd->is_terminate_only()) {
    bool any_error = false;
    for (auto &task : *(task_info->tasks)) {
      if (task.rcm.first != EC::Success) {
        any_error = true;
        task_info->SetResult(task.rcm);
        break;
      }
    }
    if (!any_error) {
      task_info->SetResult({EC::Success, ""});
    }
  } else {
    task_info->SetResult({EC::Terminate, "Task terminated by user"});
  }
  task_info->SetStatus(TaskStatus::Finished);
  task_info->finished_time.store(AMTime::seconds(), std::memory_order_relaxed);
}

TaskSchedulerCore::TaskSchedulerCore()
    : execution_engine_(
          AMDomain::transfer::CreateDefaultTransferExecutionPort()) {
  affinity_queues_.resize(1);
  conducting_by_thread_.resize(1);
  conducting_infos_.resize(1);
  worker_threads_.emplace_back([this]() { WorkerLoop(0); });
}

TaskSchedulerCore::~TaskSchedulerCore() { (void)GracefulTerminate(-1); }

TaskSchedulerCore::ECM TaskSchedulerCore::GracefulTerminate(int timeout_ms) {
  if (is_deconstruct.load(std::memory_order_relaxed)) {
    return {EC::Success, ""};
  }
  running_.store(false, std::memory_order_relaxed);
  CancelPendingTasksOnExit_();
  queue_cv_.notify_all();
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    for (const auto &info : conducting_infos_) {
      if (info && info->pd) {
        info->pd->set_terminate();
      }
    }
  }
  {
    std::unique_lock<std::mutex> lock(conducting_mtx_);
    if (timeout_ms < 0) {
      conducting_cv_.wait(lock, [this]() { return conducting_tasks_.empty(); });
    } else {
      const bool no_conducting = conducting_cv_.wait_for(
          lock, std::chrono::milliseconds(timeout_ms),
          [this]() { return conducting_tasks_.empty(); });
      if (!no_conducting) {
        return {EC::OperationTimeout, "Graceful terminate timed out"};
      }
    }
  }

  for (auto &thread : worker_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  is_deconstruct.store(true, std::memory_order_relaxed);
  return {EC::Success, ""};
}

size_t TaskSchedulerCore::ChunkSize(int64_t size) {
  if (size < 32 * AMKB) {
    return chunk_size_;
  }
  chunk_size_ = std::min<size_t>(static_cast<size_t>(size), 4 * AMMB);
  return chunk_size_;
}

size_t TaskSchedulerCore::ThreadCount(size_t new_count) {
  if (new_count == 0) {
    return desired_thread_count_.load(std::memory_order_relaxed);
  }

  new_count = ClampThreadCount(new_count);
  const size_t current = desired_thread_count_.load(std::memory_order_relaxed);
  if (new_count == current) {
    return current;
  }

  if (new_count > current) {
    {
      std::lock_guard<std::mutex> lock(queue_mtx_);
      if (new_count > affinity_queues_.size()) {
        affinity_queues_.resize(new_count);
      }
    }
    {
      std::lock_guard<std::mutex> lock(conducting_mtx_);
      if (new_count > conducting_by_thread_.size()) {
        conducting_by_thread_.resize(new_count);
        conducting_infos_.resize(new_count);
      }
    }

    desired_thread_count_.store(new_count, std::memory_order_relaxed);
    const size_t existing_threads = worker_threads_.size();
    for (size_t idx = existing_threads; idx < new_count; ++idx) {
      worker_threads_.emplace_back([this, idx]() { WorkerLoop(idx); });
    }
    queue_cv_.notify_all();
    return new_count;
  }

  desired_thread_count_.store(new_count, std::memory_order_relaxed);
  queue_cv_.notify_all();
  return new_count;
}

std::pair<std::vector<size_t>, std::vector<size_t>>
TaskSchedulerCore::GetThreadIds() const {
  std::vector<size_t> occupied;
  std::vector<size_t> idle;
  const size_t count = desired_thread_count_.load(std::memory_order_relaxed);
  occupied.reserve(count);
  idle.reserve(count);
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  for (size_t i = 0; i < count; ++i) {
    const bool busy =
        i < conducting_by_thread_.size() && !conducting_by_thread_[i].empty();
    if (busy) {
      occupied.push_back(i);
    } else {
      idle.push_back(i);
    }
  }
  return {occupied, idle};
}

TaskSchedulerCore::ECM
TaskSchedulerCore::Submit(std::shared_ptr<TaskInfo> task_info) {
  if (!task_info) {
    return {EC::InvalidArg, "TaskInfo is nullptr"};
  }
  if (!running_.load(std::memory_order_acquire)) {
    return {EC::OperationUnsupported, "Work manager is shutting down"};
  }
  if (!task_info->tasks || task_info->tasks->empty()) {
    return {EC::InvalidArg, "Tasks is nullptr or empty"};
  }

  if (task_info->id.empty() || IsTaskIdUsed_(task_info->id)) {
    task_info->id = GenerateTaskId_();
  }
  task_info->ResetCompletionDispatch();
  task_info->submit_time.store(AMTime::seconds(), std::memory_order_relaxed);
  task_info->SetStatus(TaskStatus::Pending);

  task_info->CalTotalSize();
  task_info->CalFileNum();

  task_info->total_transferred_size.store(0, std::memory_order_relaxed);
  task_info->OnWhichThread.store(-1, std::memory_order_relaxed);

  const int requested_thread_id =
      task_info->affinity_thread.load(std::memory_order_relaxed);
  const bool affinity_valid = IsValidThreadId(requested_thread_id);
  const TaskAssignType assign_type =
      affinity_valid ? TaskAssignType::Affinity : TaskAssignType::Public;
  const int affinity_id = affinity_valid ? requested_thread_id : -1;

  RegisterTask(task_info, assign_type, affinity_id);
  queue_cv_.notify_all();
  return {EC::Success, ""};
}

std::shared_ptr<TaskInfo> TaskSchedulerCore::CreateTaskInfo(
    std::shared_ptr<TASKS> tasks,
    const std::shared_ptr<
        AMApplication::TransferRuntime::ITransferClientPoolPort> &pool,
    TransferCallback callback, ssize_t buffer_size, bool quiet, int thread_id) {
  auto task_info = std::make_shared<TaskInfo>(quiet);
  task_info->id = GenerateTaskId_();
  task_info->tasks = tasks;
  task_info->CalTotalSize();
  task_info->CalFileNum();

  SetTaskPool_(task_info->id, pool);
  task_info->callback = callback;
  task_info->buffer_size.store(buffer_size, std::memory_order_relaxed);
  task_info->affinity_thread.store(thread_id, std::memory_order_relaxed);
  return task_info;
}

std::optional<TaskStatus> TaskSchedulerCore::GetStatus(const TaskId &id) const {
  {
    std::lock_guard<std::mutex> lock(registry_mtx_);
    auto it = task_registry_.find(id);
    if (it != task_registry_.end() && it->second) {
      return it->second->GetStatus();
    }
  }
  {
    std::lock_guard<std::mutex> lock(result_mtx_);
    auto it = results_.find(id);
    if (it != results_.end() && it->second) {
      return it->second->GetStatus();
    }
  }
  return std::nullopt;
}

std::shared_ptr<TaskInfo> TaskSchedulerCore::GetResult(const TaskId &id,
                                                       bool remove) {
  std::lock_guard<std::mutex> lock(result_mtx_);
  auto it = results_.find(id);
  if (it == results_.end()) {
    return nullptr;
  }
  auto task_info = it->second;
  if (remove) {
    results_.erase(it);
    ReleaseTaskResources_(id);
  }
  return task_info;
}

std::pair<std::shared_ptr<TaskInfo>, bool>
TaskSchedulerCore::GetTask(const TaskId &id) const {
  std::lock_guard<std::mutex> lock(registry_mtx_);
  auto it = task_registry_.find(id);
  if (it != task_registry_.end()) {
    return {it->second, true};
  }

  return {nullptr, false};
}
TaskSchedulerCore::ECM TaskSchedulerCore::Pause(const TaskId &id,
                                                int timeout_ms) {
  auto [task_info, active] = GetTask(id);
  if (!task_info || !active) {
    return {EC::TaskNotFound, AMStr::fmt("Task not found: {}", id)};
  }
  auto status_t = task_info->GetStatus();
  if (status_t == TaskStatus::Pending) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task is still pending: {}", id)};
  }
  if (status_t == TaskStatus::Finished) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task is already finished: {}", id)};
  }
  if (status_t == TaskStatus::Paused ||
      (task_info->pd && task_info->pd->is_pause_only())) {
    return {EC::Success, AMStr::fmt("Task already paused: {}", id)};
  }
  if (task_info->pd) {
    task_info->pd->set_pause();
  }
  const int64_t start = AMTime::miliseconds();
  while (timeout_ms < 0 || (AMTime::miliseconds() - start) < timeout_ms) {
    status_t = task_info->GetStatus();
    if (status_t == TaskStatus::Paused) {
      return {EC::Success, ""};
    }
    if (status_t == TaskStatus::Finished) {
      return {EC::OperationUnsupported,
              AMStr::fmt("Task is already finished: {}", id)};
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return {EC::OperationTimeout, AMStr::fmt("Task pause timeout: {}", id)};
}

TaskSchedulerCore::ECM TaskSchedulerCore::Resume(const TaskId &id,
                                                 int timeout_ms) {
  auto [task_info, active] = GetTask(id);
  if (!task_info || !active) {
    return {EC::TaskNotFound, AMStr::fmt("Task not found: {}", id)};
  }
  auto status_t = task_info->GetStatus();
  if (status_t == TaskStatus::Pending) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task is still pending: {}", id)};
  }
  if (status_t == TaskStatus::Finished) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task is already finished: {}", id)};
  }
  if (task_info->pd && task_info->pd->is_pause_only() &&
      status_t != TaskStatus::Paused) {
    const int64_t start = AMTime::miliseconds();
    while (timeout_ms < 0 || (AMTime::miliseconds() - start) < timeout_ms) {
      status_t = task_info->GetStatus();
      if (status_t == TaskStatus::Paused) {
        break;
      }
      if (status_t == TaskStatus::Finished) {
        return {EC::OperationUnsupported,
                AMStr::fmt("Task is already finished: {}", id)};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (status_t != TaskStatus::Paused) {
      return {EC::OperationTimeout, AMStr::fmt("Task pause timeout: {}", id)};
    }
  }
  status_t = task_info->GetStatus();
  if (status_t == TaskStatus::Paused ||
      (task_info->pd && task_info->pd->is_pause_only())) {
    if (task_info->pd) {
      task_info->pd->set_running();
    }
    const int on_thread =
        task_info->OnWhichThread.load(std::memory_order_relaxed);
    if (on_thread >= 0) {
      task_info->SetStatus(TaskStatus::Conducting);
      return {EC::Success, ""};
    }
    task_info->SetStatus(TaskStatus::Pending);
    task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
    const int affinity_thread =
        task_info->affinity_thread.load(std::memory_order_relaxed);
    TaskAssignType assign_type =
        task_info->assign_type.load(std::memory_order_relaxed);
    if (assign_type == TaskAssignType::Affinity &&
        !IsValidThreadId(affinity_thread)) {
      assign_type = TaskAssignType::Public;
    }
    RegisterTask(task_info, assign_type,
                 assign_type == TaskAssignType::Affinity ? affinity_thread
                                                         : -1);
    queue_cv_.notify_all();
    return {EC::Success, ""};
  }
  return {EC::Success, AMStr::fmt("Task is conducting: {}", id)};
}

std::pair<std::shared_ptr<TaskInfo>, TaskSchedulerCore::ECM>
TaskSchedulerCore::Terminate(const TaskId &id, int timeout_ms) {
  auto [existing, active] = GetTask(id);
  if (!existing) {
    return {nullptr, {EC::TaskNotFound, AMStr::fmt("Task not found: {}", id)}};
  }
  if (existing->GetStatus() == TaskStatus::Finished) {
    return {existing,
            {EC::OperationUnsupported,
             AMStr::fmt("Task already finished: {}", id)}};
  }

  if (existing->GetStatus() == TaskStatus::Paused) {
    std::scoped_lock<std::mutex, std::mutex> lock(registry_mtx_, queue_mtx_);
    auto it = task_registry_.find(id);
    if (it != task_registry_.end() && it->second) {
      const auto &task_info = it->second;
      if (task_info->pd) {
        task_info->pd->set_terminate();
      }
      task_info->SetResult({EC::Terminate, "Task terminated while paused"});
      task_info->SetStatus(TaskStatus::Finished);
      task_info->finished_time.store(AMTime::seconds(),
                                     std::memory_order_relaxed);
      task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
      task_registry_.erase(it);
      ReleaseTaskResources_(id);
      HandleCompletedTask(task_info);
      queue_cv_.notify_all();
      return {task_info, {EC::Success, ""}};
    }
  }

  if (existing->GetStatus() == TaskStatus::Pending) {
    std::scoped_lock<std::mutex, std::mutex> lock(registry_mtx_, queue_mtx_);
    auto it = task_registry_.find(id);
    if (it != task_registry_.end() && it->second) {
      const auto &task_info = it->second;
      const int affinity_thread =
          task_info->affinity_thread.load(std::memory_order_relaxed);
      const TaskAssignType assign_type =
          task_info->assign_type.load(std::memory_order_relaxed);
      if (assign_type == TaskAssignType::Affinity && affinity_thread >= 0 &&
          static_cast<size_t>(affinity_thread) < affinity_queues_.size()) {
        affinity_queues_[static_cast<size_t>(affinity_thread)].remove(id);
      } else {
        public_queue_.remove(id);
      }
      task_registry_.erase(it);
      if (task_info->pd) {
        task_info->pd->set_terminate();
      }
      task_info->SetResult({EC::Terminate, "Task terminated before start"});
      task_info->SetStatus(TaskStatus::Finished);
      task_info->finished_time.store(AMTime::seconds(),
                                     std::memory_order_relaxed);
      task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
      queue_cv_.notify_all();
      ReleaseTaskResources_(id);
      HandleCompletedTask(task_info);
      return {task_info, {EC::Success, ""}};
    }
  }

  if (existing->pd) {
    existing->pd->set_terminate();
  }

  if (existing->WaitFinished(timeout_ms)) {
    return {existing, {EC::Success, ""}};
  }
  return {existing,
          {EC::OperationTimeout, AMStr::fmt("Task terminate timeout: {}", id)}};
}

size_t TaskSchedulerCore::PendingCount() const {
  std::lock_guard<std::mutex> lock(queue_mtx_);
  size_t count = public_queue_.size();
  for (const auto &queue : affinity_queues_) {
    count += queue.size();
  }
  return count;
}

bool TaskSchedulerCore::IsConducting() const {
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  return !conducting_tasks_.empty();
}

std::unordered_set<TaskSchedulerCore::TaskId>
TaskSchedulerCore::GetConductingIds() const {
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  return conducting_tasks_;
}
void TaskSchedulerCore::ClearResults() {
  std::vector<TaskId> removed_ids = {};
  {
    std::lock_guard<std::mutex> lock(result_mtx_);
    removed_ids.reserve(results_.size());
    for (const auto &pair : results_) {
      removed_ids.push_back(pair.first);
    }
    results_.clear();
  }
  for (const auto &id : removed_ids) {
    ReleaseTaskResources_(id);
  }
}

bool TaskSchedulerCore::RemoveResult(const TaskId &id) {
  std::lock_guard<std::mutex> lock(result_mtx_);
  const bool removed = results_.erase(id) > 0;
  if (removed) {
    ReleaseTaskResources_(id);
  }
  return removed;
}

std::vector<std::string> TaskSchedulerCore::GetResultIds() const {
  std::lock_guard<std::mutex> lock(result_mtx_);
  std::vector<std::string> ids;
  ids.reserve(results_.size());
  for (const auto &[id, _] : results_) {
    ids.push_back(id);
  }
  return ids;
}

std::unordered_map<std::string, std::shared_ptr<TaskInfo>>
TaskSchedulerCore::GetRegistryCopy() const {
  std::lock_guard<std::mutex> lock(registry_mtx_);
  return task_registry_;
}

std::vector<std::shared_ptr<TaskInfo>>
TaskSchedulerCore::GetPendingTasks() const {
  std::vector<std::shared_ptr<TaskInfo>> tasks;
  std::lock_guard<std::mutex> lock(registry_mtx_);
  tasks.reserve(task_registry_.size());
  for (const auto &pair : task_registry_) {
    if (pair.second && pair.second->GetStatus() == TaskStatus::Pending) {
      tasks.push_back(pair.second);
    }
  }
  return tasks;
}

std::vector<std::shared_ptr<TaskInfo>>
TaskSchedulerCore::GetConductingTasks() const {
  std::vector<std::shared_ptr<TaskInfo>> tasks;
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  tasks.reserve(conducting_infos_.size());
  for (const auto &info : conducting_infos_) {
    if (info) {
      tasks.push_back(info);
    }
  }
  return tasks;
}

} // namespace AMApplication::TransferRuntime
