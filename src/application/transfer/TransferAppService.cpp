#include "application/transfer/TransferAppService.hpp"

#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"

#include <algorithm>
#include <unordered_set>

namespace AMApplication::transfer {

namespace {
using EC = ErrorCode;
}

TransferAppService::TransferAppService(
    AMDomain::transfer::ITransferPoolPort &transfer_pool,
    AMApplication::filesystem::FilesystemAppService &filesystem_service)
    : transfer_pool_(transfer_pool), filesystem_service_(filesystem_service) {}

ECM TransferAppService::Submit(const TaskHandle &task_info) {
  if (!task_info) {
    return Err(EC::InvalidArg, __func__, "", "TaskInfo is null");
  }
  if (task_info->id == 0) {
    return Err(EC::InvalidArg, __func__, "", "Task ID must be > 0");
  }

  {
    auto paused = paused_tasks_.lock();
    paused->erase(task_info->id);
  }
  {
    auto finished = finished_tasks_.lock();
    finished->erase(task_info->id);
  }

  task_info->Callback.result = [this](TaskHandle done_task) {
    OnTaskCompleted_(done_task);
  };

  const ECM submit_rcm = transfer_pool_.Submit(task_info);
  if (!(submit_rcm)) {
    task_info->Callback.result = {};
    return submit_rcm;
  }
  return OK;
}

ECM TransferAppService::Pause(TaskId id, int timeout_ms) {
  if (id == 0) {
    return Err(EC::InvalidArg, __func__, "", "Task ID must be > 0");
  }

  {
    auto paused = paused_tasks_.lock();
    if (paused->find(id) != paused->end()) {
      return OK;
    }
  }
  {
    auto finished = finished_tasks_.lock();
    auto it = finished->find(id);
    if (it != finished->end() && it->second) {
      const ECM final_rcm = it->second->GetResult();
      if (final_rcm.code == EC::Terminate) {
        return final_rcm;
      }
      return Err(EC::OperationUnsupported, __func__, AMStr::ToString(id),
                 "Task is already finished");
    }
  }

  auto [task_info, rcm] = transfer_pool_.StopActive(
      id, AMDomain::transfer::ActiveStopReason::Pause, timeout_ms);
  if (!(rcm)) {
    return rcm;
  }
  if (!task_info) {
    return Err(EC::InvalidHandle, __func__, AMStr::ToString(id),
               "Pause returned null task");
  }

  StorePaused_(task_info);
  return OK;
}

ECM TransferAppService::Resume(TaskId id, int timeout_ms) {
  (void)timeout_ms;
  if (id == 0) {
    return Err(EC::InvalidArg, __func__, "", "Task ID must be > 0");
  }

  TaskHandle task_info = nullptr;
  {
    auto paused = paused_tasks_.lock();
    auto it = paused->find(id);
    if (it == paused->end()) {
      return Err(EC::TaskNotFound, __func__, AMStr::ToString(id),
                 AMStr::fmt("Paused task not found: {}", id));
    }
    task_info = it->second;
    paused->erase(it);
  }

  auto recollect_result = filesystem_service_.RecollectTransferClients(task_info);
  if (!(recollect_result.rcm)) {
    if (task_info) {
      StorePaused_(task_info);
    }
    return recollect_result.rcm;
  }

  task_info->Core.clients.ReleaseAll();
  task_info->Core.clients = std::move(recollect_result.data);
  task_info->Set.keep_start_time.store(true, std::memory_order_relaxed);
  task_info->SetRunningIntent();
  task_info->ClearInterrupt();
  task_info->SetStatus(TaskStatus::Pending);
  task_info->Time.finish.store(0.0, std::memory_order_relaxed);
  task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
  task_info->ResetCompletionDispatch();

  const ECM submit_rcm = Submit(task_info);
  if (!(submit_rcm)) {
    task_info->Core.clients.ReleaseAll();
    task_info->SetStatus(TaskStatus::Paused);
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    StorePaused_(task_info);
    return submit_rcm;
  }
  return OK;
}

std::pair<TransferAppService::TaskHandle, ECM>
TransferAppService::Terminate(TaskId id, int timeout_ms) {
  if (id == 0) {
    return {nullptr, Err(EC::InvalidArg, __func__, "", "Task ID must be > 0")};
  }

  {
    auto finished = finished_tasks_.lock();
    auto it = finished->find(id);
    if (it != finished->end()) {
      return {it->second,
              Err(EC::OperationUnsupported, __func__, AMStr::ToString(id),
                  "Task already finished")};
    }
  }

  {
    auto paused = paused_tasks_.lock();
    auto it = paused->find(id);
    if (it != paused->end()) {
      TaskHandle task_info = it->second;
      paused->erase(it);
      const ECM terminate_rcm =
          Err(EC::Terminate, __func__, AMStr::ToString(id), "Task terminated");
      MarkUnfinishedEntries_(task_info, terminate_rcm);
      task_info->SetResult(terminate_rcm);
      task_info->SetStatus(TaskStatus::Finished);
      task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
      ReleaseClients_(task_info);
      StoreFinished_(task_info);
      return {task_info, OK};
    }
  }

  auto [task_info, stop_rcm] = transfer_pool_.StopActive(
      id, AMDomain::transfer::ActiveStopReason::Terminate, timeout_ms);
  if (!(stop_rcm)) {
    return {task_info, stop_rcm};
  }
  if (task_info) {
    StoreFinished_(task_info);
  }
  return {task_info, OK};
}

std::optional<TransferAppService::TaskStatus>
TransferAppService::GetStatus(TaskId id) const {
  if (id == 0) {
    return std::nullopt;
  }
  auto active = transfer_pool_.GetStatus(id);
  if (active.has_value()) {
    return active;
  }
  {
    auto paused = paused_tasks_.lock();
    auto it = paused->find(id);
    if (it != paused->end() && it->second) {
      return it->second->GetStatus();
    }
  }
  {
    auto finished = finished_tasks_.lock();
    auto it = finished->find(id);
    if (it != finished->end() && it->second) {
      return it->second->GetStatus();
    }
  }
  return std::nullopt;
}

TransferAppService::TaskHandle TransferAppService::FindTask(TaskId id) const {
  if (id == 0) {
    return nullptr;
  }
  auto active = transfer_pool_.GetActiveTask(id);
  if (active) {
    return active;
  }
  {
    auto paused = paused_tasks_.lock();
    auto it = paused->find(id);
    if (it != paused->end()) {
      return it->second;
    }
  }
  {
    auto finished = finished_tasks_.lock();
    auto it = finished->find(id);
    if (it != finished->end()) {
      return it->second;
    }
  }
  return nullptr;
}

TransferAppService::TaskHandle TransferAppService::GetActiveTask(TaskId id) const {
  if (id == 0) {
    return nullptr;
  }
  return transfer_pool_.GetActiveTask(id);
}

std::unordered_map<TransferAppService::TaskId, TransferAppService::TaskHandle>
TransferAppService::GetAllActiveTasks() const {
  return transfer_pool_.GetAllActiveTasks();
}

std::unordered_map<TransferAppService::TaskId, TransferAppService::TaskHandle>
TransferAppService::GetAllHistoryTasks() const {
  return GetFinishedTasks();
}

std::unordered_map<TransferAppService::TaskId, TransferAppService::TaskHandle>
TransferAppService::GetPendingTasks() const {
  return transfer_pool_.GetPendingTasks();
}

std::unordered_map<TransferAppService::TaskId, TransferAppService::TaskHandle>
TransferAppService::GetConductingTasks() const {
  return transfer_pool_.GetConductingTasks();
}

std::unordered_map<TransferAppService::TaskId, TransferAppService::TaskHandle>
TransferAppService::GetPausedTasks() const {
  auto paused = paused_tasks_.lock();
  return *paused;
}

std::unordered_map<TransferAppService::TaskId, TransferAppService::TaskHandle>
TransferAppService::GetFinishedTasks() const {
  auto finished = finished_tasks_.lock();
  return *finished;
}

TransferAppService::TaskHandle TransferAppService::GetFinishedTask(TaskId id,
                                                                   bool remove) {
  auto finished = finished_tasks_.lock();
  auto it = finished->find(id);
  if (it == finished->end()) {
    return nullptr;
  }
  TaskHandle task_info = it->second;
  if (remove) {
    finished->erase(it);
  }
  return task_info;
}

TransferAppService::TaskHandle TransferAppService::GetResultTask(TaskId id,
                                                                 bool remove) {
  return GetFinishedTask(id, remove);
}

bool TransferAppService::RemoveFinished(TaskId id) {
  auto finished = finished_tasks_.lock();
  return finished->erase(id) > 0;
}

void TransferAppService::ClearFinished() {
  auto finished = finished_tasks_.lock();
  finished->clear();
}

std::vector<TransferAppService::TaskId> TransferAppService::ListTaskIds() const {
  std::unordered_set<TaskId> seen = {};
  std::vector<TaskId> ids = {};
  const auto add_ids = [&seen, &ids](
                           const std::unordered_map<TaskId, TaskHandle> &tasks) {
    for (const auto &[id, task] : tasks) {
      if (!task || id == 0) {
        continue;
      }
      if (seen.insert(id).second) {
        ids.push_back(id);
      }
    }
  };
  add_ids(transfer_pool_.GetAllActiveTasks());
  add_ids(GetPausedTasks());
  add_ids(GetFinishedTasks());
  std::sort(ids.begin(), ids.end());
  return ids;
}

void TransferAppService::OnTaskCompleted_(const TaskHandle &task_info) {
  if (!task_info || task_info->id == 0) {
    return;
  }
  ReleaseClients_(task_info);
  if (task_info->GetStatus() == TaskStatus::Paused) {
    StorePaused_(task_info);
    return;
  }
  StoreFinished_(task_info);
}

void TransferAppService::MarkUnfinishedEntries_(const TaskHandle &task_info,
                                                const ECM &entry_rcm) {
  if (!task_info) {
    return;
  }
  const auto mark_one = [&entry_rcm](auto *tasks_atomic) {
    if (!tasks_atomic) {
      return;
    }
    auto tasks = tasks_atomic->lock();
    for (auto &task : *tasks) {
      if (task.IsFinished) {
        continue;
      }
      task.rcm = entry_rcm;
      task.IsFinished = true;
    }
  };
  mark_one(&task_info->Core.dir_tasks);
  mark_one(&task_info->Core.file_tasks);
}

void TransferAppService::ReleaseClients_(const TaskHandle &task_info) {
  if (!task_info) {
    return;
  }
  task_info->Core.clients.ReleaseAll();
}

void TransferAppService::StorePaused_(const TaskHandle &task_info) {
  if (!task_info || task_info->id == 0) {
    return;
  }
  {
    auto finished = finished_tasks_.lock();
    finished->erase(task_info->id);
  }
  auto paused = paused_tasks_.lock();
  (*paused)[task_info->id] = task_info;
}

void TransferAppService::StoreFinished_(const TaskHandle &task_info) {
  if (!task_info || task_info->id == 0) {
    return;
  }
  {
    auto paused = paused_tasks_.lock();
    paused->erase(task_info->id);
  }
  auto finished = finished_tasks_.lock();
  (*finished)[task_info->id] = task_info;
}

} // namespace AMApplication::transfer
