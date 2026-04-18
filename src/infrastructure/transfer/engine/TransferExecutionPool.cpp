#include "foundation/tools/time.hpp"
#include "infrastructure/transfer/Pool.hpp"
#include "infrastructure/transfer/engine/TransferExecutionDetail.hpp"

namespace {
using AMTime::miliseconds;
using AMTime::seconds;
using ClientHandle = AMInfra::transfer::ClientHandle;
using EC = ErrorCode;
using TaskAssignType = AMDomain::transfer::TaskAssignType;
using TaskHandle = AMInfra::transfer::TaskHandle;
using TaskID = AMDomain::transfer::TaskID;
using TaskStatus = AMInfra::transfer::TaskStatus;
using TransferBufferPolicy = AMInfra::transfer::TransferBufferPolicy;
} // namespace

namespace AMInfra::transfer {
void TransferExecutionPool::CancelPendingTasksOnExit_(
    const std::string &reason) {
  std::vector<TaskHandle> canceled_tasks = {};
  {
    std::lock_guard<std::mutex> queue_lock(queue_mtx_);
    auto task_registry = task_registry_.lock();
    auto cancel_one = [&](const TaskID &task_id) {
      auto it = task_registry->find(task_id);
      if (it == task_registry->end() || !it->second) {
        return;
      }
      auto task_info = it->second;
      task_registry->erase(it);
      task_info->RequestInterrupt();
      const ECM terminate_rcm = {EC::Terminate, "", "", reason};
      task_info->State.rcm.lock().store(terminate_rcm);
      detail::MarkUnfinishedTransferEntries(task_info, terminate_rcm);
      task_info->SetStatus(TaskStatus::Finished);
      task_info->Time.finish.store(seconds(), std::memory_order_relaxed);
      task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
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
    HandleCompletedTask(task_info);
  }
}

void TransferExecutionPool::RegisterTask(const TaskHandle &task_info,
                                         TaskAssignType assign_type,
                                         int affinity_thread) {
  std::lock_guard<std::mutex> queue_lock(queue_mtx_);
  auto task_registry = task_registry_.lock();
  std::list<TaskID> *target_queue = nullptr;
  const size_t active_count =
      desired_thread_count_.load(std::memory_order_relaxed);
  const bool affinity_valid =
      affinity_thread >= 0 &&
      static_cast<size_t>(affinity_thread) < active_count &&
      static_cast<size_t>(affinity_thread) < affinity_queues_.size();
  if (assign_type == TaskAssignType::Affinity && affinity_valid) {
    target_queue = &affinity_queues_[static_cast<size_t>(affinity_thread)];
  } else {
    assign_type = TaskAssignType::Public;
    affinity_thread = -1;
    target_queue = &public_queue_;
  }

  target_queue->push_back(task_info->id);
  task_info->Set.assign_type.store(assign_type, std::memory_order_relaxed);
  task_info->Set.affinity_thread.store(affinity_thread,
                                       std::memory_order_relaxed);
  task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
  (*task_registry)[task_info->id] = task_info;
}

std::optional<std::pair<TaskID, TaskHandle>>
TransferExecutionPool::DequeueTask(std::stop_token stop_token,
                                   size_t thread_index) {
  while (true) {
    std::unique_lock<std::mutex> lock(queue_mtx_);
    queue_cv_.wait(lock, [this, &stop_token, thread_index]() {
      if (stop_token.stop_requested()) {
        return true;
      }
      if (!running_.load(std::memory_order_acquire)) {
        return true;
      }
      const bool has_affinity = thread_index < affinity_queues_.size() &&
                                !affinity_queues_[thread_index].empty();
      if (has_affinity) {
        return true;
      }
      const size_t desired =
          desired_thread_count_.load(std::memory_order_relaxed);
      if (thread_index >= desired) {
        return false;
      }
      return HasPendingTasksUnsafe_();
    });

    if (stop_token.stop_requested()) {
      return std::nullopt;
    }

    if (!running_.load(std::memory_order_relaxed) &&
        !HasPendingTasksUnsafe_()) {
      return std::nullopt;
    }

    const size_t desired =
        desired_thread_count_.load(std::memory_order_relaxed);
    if (thread_index >= desired) {
      const bool has_affinity = thread_index < affinity_queues_.size() &&
                                !affinity_queues_[thread_index].empty();
      if (!has_affinity) {
        continue;
      }
    }

    TaskID task_id = 0;
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

    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(task_id);
    if (it == task_registry->end()) {
      continue;
    }
    return {{task_id, it->second}};
  }
}

void TransferExecutionPool::HandleCompletedTask(const TaskHandle &task_info) {
  if (!task_info || !task_info->TryMarkCompletionDispatched()) {
    return;
  }
  task_info->Core.clients.ReleaseAll();
  if (task_info->Callback.result) {
    CallCallbackSafe(task_info->Callback.result, task_info);
  }
}

void TransferExecutionPool::SetConducting(size_t thread_index,
                                          const TaskID &task_id,
                                          const TaskHandle &task_info) {
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (thread_index >= conducting_by_thread_.size()) {
      conducting_by_thread_.resize(thread_index + 1);
      conducting_infos_.resize(thread_index + 1);
    }
    conducting_by_thread_[thread_index] = task_id;
    conducting_infos_[thread_index] = task_info;
    conducting_tasks_.insert(task_id);
  }
  RecomputeDesiredThreadCount_();
}

void TransferExecutionPool::ClearConducting(size_t thread_index) {
  bool removed_task = false;
  TaskHandle finished_info = nullptr;
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (thread_index < conducting_by_thread_.size()) {
      const TaskID id = conducting_by_thread_[thread_index];
      if (id != 0) {
        conducting_tasks_.erase(id);
        removed_task = true;
      }
      finished_info = conducting_infos_[thread_index];
      conducting_by_thread_[thread_index] = 0;
      conducting_infos_[thread_index] = nullptr;
    }
  }
  if (finished_info) {
    finished_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
  }
  if (removed_task) {
    conducting_cv_.notify_all();
  }
  RecomputeDesiredThreadCount_();
}

void TransferExecutionPool::WorkerLoop(std::stop_token stop_token,
                                       size_t thread_index) {
  while (running_.load(std::memory_order_relaxed) &&
         !stop_token.stop_requested()) {
    auto task_opt = DequeueTask(stop_token, thread_index);
    if (!task_opt.has_value()) {
      break;
    }

    const auto &[task_id, task_info] = *task_opt;
    SetConducting(thread_index, task_id, task_info);
    task_info->Set.OnWhichThread.store(static_cast<int>(thread_index),
                                       std::memory_order_relaxed);

    if (detail::ShouldSkipTask(task_info)) {
      task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
      {
        auto task_registry = task_registry_.lock();
        task_registry->erase(task_id);
      }
      HandleCompletedTask(task_info);
      ClearConducting(thread_index);
      continue;
    }

    TransferExecutionEngine *engine = nullptr;
    if (thread_index < engines_.size()) {
      engine = engines_[thread_index].get();
    }
    if (!engine) {
      task_info->SetStatus(TaskStatus::Finished);
      task_info->SetResult(
          Err(EC::InvalidHandle, "", "", "Worker transfer engine is null"));
      task_info->Time.finish.store(seconds(), std::memory_order_relaxed);
    } else {
      engine->ExecuteTask(task_info);
    }

    {
      auto task_registry = task_registry_.lock();
      task_registry->erase(task_info->id);
    }
    HandleCompletedTask(task_info);
    ClearConducting(thread_index);
  }

  ClearConducting(thread_index);
}

TransferExecutionPool::TransferExecutionPool(
    const AMDomain::transfer::TransferManagerArg &arg)
    : manager_arg_(arg) {
  const size_t max_threads = ClampMaxThreads_(
      static_cast<size_t>(std::max(1, manager_arg_.max_threads)));
  max_thread_count_.store(max_threads, std::memory_order_relaxed);
  desired_thread_count_.store(0, std::memory_order_relaxed);

  {
    std::lock_guard<std::mutex> lock(queue_mtx_);
    affinity_queues_.resize(max_threads);
  }
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    conducting_by_thread_.resize(max_threads);
    conducting_infos_.resize(max_threads);
  }

  heartbeat_interval_s_.store(std::max(0, manager_arg_.heartbeat_interval_s),
                              std::memory_order_relaxed);
  heartbeat_timeout_ms_.store(std::max(1, manager_arg_.heartbeat_timeout_ms),
                              std::memory_order_relaxed);
  StartHeartbeat_();
  RecomputeDesiredThreadCount_();
}

TransferExecutionPool::~TransferExecutionPool() { (void)Shutdown(3000); }

ECM TransferExecutionPool::Shutdown(int timeout_ms) {
  if (is_deconstruct.load(std::memory_order_relaxed)) {
    return OK;
  }
  running_.store(false, std::memory_order_relaxed);
  StopHeartbeat_();
  CancelPendingTasksOnExit_();
  queue_cv_.notify_all();
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    for (const auto &info : conducting_infos_) {
      if (info) {
        info->RequestInterrupt();
      }
    }
  }
  std::vector<TaskHandle> paused_tasks = {};
  {
    auto task_registry = task_registry_.lock();
    for (auto it = task_registry->begin(); it != task_registry->end();) {
      const TaskHandle &task_info = it->second;
      if (!task_info || task_info->GetStatus() != TaskStatus::Paused) {
        ++it;
        continue;
      }
      task_info->RequestInterrupt();
      task_info->SetResult(
          {EC::Terminate, "", "", "Task canceled while shutting down"});
      task_info->SetStatus(TaskStatus::Finished);
      task_info->Time.finish.store(seconds(), std::memory_order_relaxed);
      task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
      paused_tasks.push_back(task_info);
      it = task_registry->erase(it);
    }
  }
  for (const auto &task_info : paused_tasks) {
    HandleCompletedTask(task_info);
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
        return {EC::OperationTimeout, "", "", "Graceful terminate timed out"};
      }
    }
  }

  {
    std::lock_guard<std::mutex> worker_lock(worker_mtx_);
    for (auto &thread : worker_threads_) {
      if (thread.joinable()) {
        thread.join();
      }
    }
  }
  engines_.clear();
  is_deconstruct.store(true, std::memory_order_relaxed);
  return OK;
}

size_t TransferExecutionPool::ClampMaxThreads_(size_t value) const {
  constexpr size_t kHardMaxThreads = 1024;
  if (value == 0) {
    return 1;
  }
  return std::min(value, kHardMaxThreads);
}

bool TransferExecutionPool::HasPendingTasksUnsafe_() const {
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

size_t TransferExecutionPool::ComputeDesiredThreadCount_() const {
  size_t pending_count = 0;
  {
    std::lock_guard<std::mutex> lock(queue_mtx_);
    pending_count += public_queue_.size();
    for (const auto &queue : affinity_queues_) {
      pending_count += queue.size();
    }
  }

  size_t conducting_count = 0;
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    conducting_count = conducting_tasks_.size();
  }

  const size_t max_threads =
      ClampMaxThreads_(max_thread_count_.load(std::memory_order_relaxed));
  const size_t active_count = pending_count + conducting_count;
  return std::min(max_threads, active_count);
}

void TransferExecutionPool::EnsureWorkerCapacity_(size_t worker_count) {
  const size_t max_threads =
      ClampMaxThreads_(max_thread_count_.load(std::memory_order_relaxed));
  worker_count = std::min(worker_count, max_threads);
  if (worker_count == 0) {
    return;
  }

  std::lock_guard<std::mutex> worker_lock(worker_mtx_);
  if (worker_count <= worker_threads_.size()) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock(queue_mtx_);
    if (worker_count > affinity_queues_.size()) {
      affinity_queues_.resize(worker_count);
    }
  }
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (worker_count > conducting_by_thread_.size()) {
      conducting_by_thread_.resize(worker_count);
      conducting_infos_.resize(worker_count);
    }
  }

  const TransferBufferPolicy policy = {manager_arg_.buffer_size,
                                       manager_arg_.min_buffer,
                                       manager_arg_.max_buffer};
  if (worker_count > engines_.size()) {
    engines_.reserve(worker_count);
    for (size_t idx = engines_.size(); idx < worker_count; ++idx) {
      engines_.push_back(std::make_unique<TransferExecutionEngine>(policy));
    }
  }

  const size_t begin = worker_threads_.size();
  for (size_t idx = begin; idx < worker_count; ++idx) {
    worker_threads_.emplace_back([this, idx](std::stop_token stop_token) {
      WorkerLoop(stop_token, idx);
    });
  }
}

void TransferExecutionPool::RecomputeDesiredThreadCount_() {
  const size_t desired = ComputeDesiredThreadCount_();
  EnsureWorkerCapacity_(desired);
  desired_thread_count_.store(desired, std::memory_order_relaxed);
  queue_cv_.notify_all();
}

void TransferExecutionPool::StartHeartbeat_() {
  if (heartbeat_interval_s_.load(std::memory_order_relaxed) <= 0) {
    heartbeat_running_.store(false, std::memory_order_relaxed);
    return;
  }
  if (heartbeat_running_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  heartbeat_thread_ = std::jthread(
      [this](std::stop_token stop_token) { HeartbeatLoop_(stop_token); });
}

void TransferExecutionPool::StopHeartbeat_() {
  heartbeat_running_.store(false, std::memory_order_release);
  if (heartbeat_thread_.joinable()) {
    heartbeat_thread_.request_stop();
  }
  heartbeat_cv_.notify_all();
  if (heartbeat_thread_.joinable()) {
    heartbeat_thread_.join();
  }
}

void TransferExecutionPool::HeartbeatLoop_(std::stop_token stop_token) {
  while (running_.load(std::memory_order_acquire) &&
         heartbeat_running_.load(std::memory_order_acquire) &&
         !stop_token.stop_requested()) {
    const int interval_s =
        std::max(1, heartbeat_interval_s_.load(std::memory_order_relaxed));
    std::unique_lock<std::mutex> lock(heartbeat_wait_mtx_);
    (void)heartbeat_cv_.wait_for(
        lock, std::chrono::seconds(interval_s), [this, &stop_token]() {
          if (stop_token.stop_requested()) {
            return true;
          }
          return !running_.load(std::memory_order_acquire) ||
                 !heartbeat_running_.load(std::memory_order_acquire);
        });
    lock.unlock();
    if (!running_.load(std::memory_order_acquire) ||
        !heartbeat_running_.load(std::memory_order_acquire) ||
        stop_token.stop_requested()) {
      break;
    }
    HeartbeatTick_();
  }
}

void TransferExecutionPool::HeartbeatTick_() {
  const int timeout_ms =
      std::max(1, heartbeat_timeout_ms_.load(std::memory_order_relaxed));
  const auto active_tasks = GetRegistryCopy();
  for (const auto &[id, task_info] : active_tasks) {
    (void)id;
    if (!task_info) {
      continue;
    }
    const auto status = task_info->GetStatus();
    if (status != TaskStatus::Pending && status != TaskStatus::Conducting) {
      continue;
    }
    if (task_info->IsPauseRequested() || task_info->IsTerminateRequested()) {
      continue;
    }

    std::unordered_set<AMDomain::client::IClientPort *> visited = {};
    std::vector<ClientHandle> clients = {};
    const auto collect_client = [&visited,
                                 &clients](const ClientHandle &client) {
      if (!client) {
        return;
      }
      if (!visited.insert(client.get()).second) {
        return;
      }
      clients.push_back(client);
    };

    for (const auto &nickname : task_info->Core.nicknames) {
      collect_client(task_info->Core.clients.GetSrcClient(nickname));
      collect_client(task_info->Core.clients.GetDstClient(nickname));
    }

    if (clients.empty()) {
      const auto collect_from_tasks = [&collect_client,
                                       task_info](auto &tasks) {
        auto task_lock = tasks.lock();
        for (const auto &task : *task_lock) {
          collect_client(task_info->Core.clients.GetSrcClient(task.src_host));
          collect_client(task_info->Core.clients.GetDstClient(task.dst_host));
        }
      };
      collect_from_tasks(task_info->Core.dir_tasks);
      collect_from_tasks(task_info->Core.file_tasks);
    }

    for (const auto &client : clients) {
      if (!client) {
        continue;
      }
      const auto lease_state =
          client->MetaDataPort().QueryNamedValue<bool>("transfer.lease");
      if (lease_state.name_found && lease_state.type_match &&
          lease_state.value.has_value() && lease_state.value.value()) {
        continue;
      }

      auto check_result =
          client->IOPort().Check({}, ControlComponent(nullptr, timeout_ms));
      if (!(check_result.rcm)) {
        if (!task_info->IsPauseRequested() &&
            !task_info->IsTerminateRequested()) {
          task_info->RequestInterrupt();
        }
        break;
      }
    }
  }
}

size_t TransferExecutionPool::ThreadCount(size_t new_count) {
  if (new_count > 0) {
    (void)MaxThreadCount(new_count);
  }
  return desired_thread_count_.load(std::memory_order_relaxed);
}

size_t TransferExecutionPool::MaxThreadCount(size_t new_max) {
  if (new_max == 0) {
    return max_thread_count_.load(std::memory_order_relaxed);
  }
  const size_t clamped = ClampMaxThreads_(new_max);
  max_thread_count_.store(clamped, std::memory_order_relaxed);
  manager_arg_.max_threads = static_cast<int>(clamped);
  RecomputeDesiredThreadCount_();
  return clamped;
}

std::unordered_map<size_t, bool> TransferExecutionPool::GetThreadIDs() const {
  std::unordered_map<size_t, bool> states = {};
  const size_t count = desired_thread_count_.load(std::memory_order_relaxed);
  states.reserve(count);
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  for (size_t i = 0; i < count; ++i) {
    const bool busy =
        i < conducting_by_thread_.size() && conducting_by_thread_[i] != 0;
    states.emplace(i, busy);
  }
  return states;
}

ECM TransferExecutionPool::Submit(TaskHandle task_info) {
  if (!task_info) {
    return {EC::InvalidArg, "", "", "TaskInfo is nullptr"};
  }
  if (!running_.load(std::memory_order_acquire)) {
    return {EC::OperationUnsupported, "", "", "Work manager is shutting down"};
  }
  const bool has_dir_tasks = !task_info->Core.dir_tasks.lock()->empty();
  const bool has_file_tasks = !task_info->Core.file_tasks.lock()->empty();
  if (!has_dir_tasks && !has_file_tasks) {
    return {EC::InvalidArg, "", "", "Tasks is nullptr or empty"};
  }
  if (task_info->Core.clients.empty()) {
    return {EC::InvalidArg, "", "", "Transfer clients is empty"};
  }

  if (task_info->id == 0 ||
      detail::IsTaskIDUsed(task_info->id, task_registry_, conducting_mtx_,
                           conducting_tasks_)) {
    return {EC::InvalidArg, "", "", "Task ID is invalid or already used"};
  }
  task_info->ResetCompletionDispatch();
  task_info->State.intent.store(AMDomain::transfer::ControlIntent::Running,
                                std::memory_order_relaxed);
  task_info->Time.submit.store(seconds(), std::memory_order_relaxed);
  task_info->SetStatus(TaskStatus::Pending);
  task_info->CalTotalSize();
  task_info->CalFileNum();

  const bool keep_progress =
      task_info->Set.keep_start_time.load(std::memory_order_relaxed);
  if (!keep_progress) {
    task_info->Size.transferred.store(0, std::memory_order_relaxed);
    task_info->Size.cur_task.store(0, std::memory_order_relaxed);
    task_info->Size.cur_task_transferred.store(0, std::memory_order_relaxed);
    task_info->Size.success_filenum.store(0, std::memory_order_relaxed);
  }
  task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);

  const int requested_thread_id =
      task_info->Set.affinity_thread.load(std::memory_order_relaxed);
  const size_t active_count =
      desired_thread_count_.load(std::memory_order_relaxed);
  const bool affinity_valid =
      requested_thread_id >= 0 &&
      static_cast<size_t>(requested_thread_id) < active_count &&
      static_cast<size_t>(requested_thread_id) < affinity_queues_.size();
  const TaskAssignType assign_type =
      affinity_valid ? TaskAssignType::Affinity : TaskAssignType::Public;
  const int affinity_id = affinity_valid ? requested_thread_id : -1;

  RegisterTask(task_info, assign_type, affinity_id);
  RecomputeDesiredThreadCount_();
  return OK;
}

std::optional<TaskStatus>
TransferExecutionPool::GetStatus(const TaskID &id) const {
  auto task_registry = task_registry_.lock();
  auto it = task_registry->find(id);
  if (it != task_registry->end() && it->second) {
    return it->second->GetStatus();
  }
  return std::nullopt;
}

std::pair<TaskHandle, ECM>
TransferExecutionPool::StopActive(const TaskID &id,
                                  AMDomain::transfer::ActiveStopReason reason,
                                  int timeout_ms, int grace_period_ms) {
  TaskHandle existing = nullptr;
  {
    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(id);
    if (it != task_registry->end()) {
      existing = it->second;
    }
  }
  if (!existing) {
    return {nullptr,
            {EC::TaskNotFound, "", AMStr::ToString(id),
             AMStr::fmt("Task not found: {}", id)}};
  }

  TaskStatus status_t = existing->GetStatus();
  if (status_t == TaskStatus::Finished || status_t == TaskStatus::Paused) {
    return {existing,
            {EC::OperationUnsupported, "", AMStr::ToString(id),
             AMStr::fmt("Task is not active: {}", id)}};
  }

  if (reason == AMDomain::transfer::ActiveStopReason::Pause) {
    if (existing->IsTerminateRequested()) {
      return {existing,
              {EC::OperationUnsupported, "", AMStr::ToString(id),
               AMStr::fmt("Task terminate requested: {}", id)}};
    }

    if (status_t == TaskStatus::Pending) {
      bool done_in_fast_path = false;
      {
        std::lock_guard<std::mutex> queue_lock(queue_mtx_);
        auto task_registry = task_registry_.lock();
        auto it = task_registry->find(id);
        if (it != task_registry->end() && it->second &&
            it->second->GetStatus() == TaskStatus::Pending) {
          TaskHandle task_info = it->second;
          const int affinity_thread =
              task_info->Set.affinity_thread.load(std::memory_order_relaxed);
          const TaskAssignType assign_type =
              task_info->Set.assign_type.load(std::memory_order_relaxed);
          if (assign_type == TaskAssignType::Affinity && affinity_thread >= 0 &&
              static_cast<size_t>(affinity_thread) < affinity_queues_.size()) {
            affinity_queues_[static_cast<size_t>(affinity_thread)].remove(id);
          } else {
            public_queue_.remove(id);
          }
          task_registry->erase(it);
          task_info->RequestPause(grace_period_ms > 0
                                      ? static_cast<size_t>(grace_period_ms)
                                      : size_t{0});
          task_info->SetResult(
              {EC::Success, "", AMStr::ToString(id), "Task paused"});
          task_info->SetStatus(TaskStatus::Paused);
          task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
          task_info->Time.finish.store(seconds(), std::memory_order_relaxed);
          queue_cv_.notify_all();
          existing = task_info;
          done_in_fast_path = true;
        }
      }
      if (done_in_fast_path) {
        RecomputeDesiredThreadCount_();
        HandleCompletedTask(existing);
        return {existing, OK};
      }
    }

    existing->RequestPause(
        grace_period_ms > 0 ? static_cast<size_t>(grace_period_ms) : size_t{0});
    const int64_t start_ms = miliseconds();
    while (timeout_ms < 0 || (miliseconds() - start_ms) < timeout_ms) {
      status_t = existing->GetStatus();
      if (status_t == TaskStatus::Finished) {
        const ECM final_rcm = existing->GetResult();
        if (final_rcm.code == EC::Terminate) {
          return {existing, final_rcm};
        }
        return {existing,
                {EC::OperationUnsupported, "", AMStr::ToString(id),
                 AMStr::fmt("Task finished before pause completed: {}", id)}};
      }
      const int on_thread =
          existing->Set.OnWhichThread.load(std::memory_order_relaxed);
      bool detached_from_worker = false;
      {
        std::lock_guard<std::mutex> lock(conducting_mtx_);
        detached_from_worker = !conducting_tasks_.contains(id);
      }
      if (status_t == TaskStatus::Paused && on_thread < 0 &&
          detached_from_worker) {
        return {existing, OK};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return {existing,
            {EC::OperationTimeout, "", AMStr::ToString(id),
             AMStr::fmt("Task pause timeout: {}", id)}};
  }

  TaskHandle completed_without_wait = nullptr;
  if (status_t == TaskStatus::Pending) {
    bool done_in_fast_path = false;
    {
      std::lock_guard<std::mutex> queue_lock(queue_mtx_);
      auto task_registry = task_registry_.lock();
      auto it = task_registry->find(id);
      if (it != task_registry->end() && it->second &&
          it->second->GetStatus() == TaskStatus::Pending) {
        TaskHandle task_info = it->second;
        const int affinity_thread =
            task_info->Set.affinity_thread.load(std::memory_order_relaxed);
        const TaskAssignType assign_type =
            task_info->Set.assign_type.load(std::memory_order_relaxed);
        if (assign_type == TaskAssignType::Affinity && affinity_thread >= 0 &&
            static_cast<size_t>(affinity_thread) < affinity_queues_.size()) {
          affinity_queues_[static_cast<size_t>(affinity_thread)].remove(id);
        } else {
          public_queue_.remove(id);
        }
        task_registry->erase(it);
        task_info->RequestInterrupt(grace_period_ms > 0
                                        ? static_cast<size_t>(grace_period_ms)
                                        : size_t{0});
        const ECM terminate_rcm = {EC::Terminate, "", AMStr::ToString(id),
                                   "Task terminated"};
        detail::MarkUnfinishedTransferEntries(task_info, terminate_rcm);
        task_info->SetResult(terminate_rcm);
        task_info->SetStatus(TaskStatus::Finished);
        task_info->Time.finish.store(seconds(), std::memory_order_relaxed);
        task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
        queue_cv_.notify_all();
        completed_without_wait = task_info;
        done_in_fast_path = true;
      }
    }
    if (done_in_fast_path && completed_without_wait) {
      RecomputeDesiredThreadCount_();
      HandleCompletedTask(completed_without_wait);
      return {completed_without_wait, OK};
    }
  }

  existing->RequestInterrupt(
      grace_period_ms > 0 ? static_cast<size_t>(grace_period_ms) : size_t{0});
  const int64_t start_ms = miliseconds();
  while (timeout_ms < 0 || (miliseconds() - start_ms) < timeout_ms) {
    if (existing->GetStatus() == TaskStatus::Finished) {
      return {existing, OK};
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return {existing,
          {EC::OperationTimeout, "", AMStr::ToString(id),
           AMStr::fmt("Task terminate timeout: {}", id)}};
}

std::pair<TaskHandle, ECM>
TransferExecutionPool::Terminate(const TaskID &id, int timeout_ms,
                                 int grace_period_ms) {
  return StopActive(id, AMDomain::transfer::ActiveStopReason::Terminate,
                    timeout_ms, grace_period_ms);
}

std::unordered_map<TaskID, TaskHandle>
TransferExecutionPool::GetRegistryCopy() const {
  auto task_registry = task_registry_.lock();
  return *task_registry;
}

TaskHandle TransferExecutionPool::GetActiveTask(const TaskID &id) const {
  auto task_registry = task_registry_.lock();
  auto it = task_registry->find(id);
  if (it == task_registry->end()) {
    return nullptr;
  }
  return it->second;
}

std::unordered_map<TaskID, TaskHandle>
TransferExecutionPool::GetAllActiveTasks() const {
  return GetRegistryCopy();
}

std::unordered_map<TaskID, TaskHandle>
TransferExecutionPool::GetPendingTasks() const {
  std::unordered_map<TaskID, TaskHandle> out = {};
  auto task_registry = task_registry_.lock();
  out.reserve(task_registry->size());
  for (const auto &[id, task] : *task_registry) {
    if (task && task->GetStatus() == TaskStatus::Pending) {
      out.emplace(id, task);
    }
  }
  return out;
}

std::unordered_map<TaskID, TaskHandle>
TransferExecutionPool::GetConductingTasks() const {
  std::unordered_map<TaskID, TaskHandle> out = {};
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  out.reserve(conducting_infos_.size());
  for (const auto &task : conducting_infos_) {
    if (task && task->id != 0) {
      out.emplace(task->id, task);
    }
  }
  return out;
}
} // namespace AMInfra::transfer
