#include "application/transfer/TransferAppService.hpp"

#include "application/log/LoggerAppService.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"

#include <algorithm>
#include <unordered_set>

namespace AMApplication::transfer {

namespace {
using EC = ErrorCode;
using ClientHandle = AMDomain::client::ClientHandle;
using TaskHandle = TransferAppService::TaskHandle;
using TaskID = TransferAppService::TaskID;
using TaskStatus = AMDomain::transfer::TaskStatus;
using TraceLevel = AMDomain::client::TraceLevel;

std::string TaskTarget_(TaskID id) {
  return id == 0 ? std::string("task:<invalid>") : AMStr::fmt("task:{}", id);
}

const char *TaskStatusText_(TaskStatus status) {
  switch (status) {
  case TaskStatus::Pending:
    return "Pending";
  case TaskStatus::Conducting:
    return "Conducting";
  case TaskStatus::Paused:
    return "Paused";
  case TaskStatus::Finished:
    return "Finished";
  default:
    return "Unknown";
  }
}

TraceLevel TraceLevelForResult_(const ECM &rcm) {
  if ((rcm)) {
    return TraceLevel::Info;
  }
  if (rcm.code == EC::Terminate || rcm.code == EC::OperationTimeout) {
    return TraceLevel::Warning;
  }
  return TraceLevel::Error;
}

std::string BuildTaskSummary_(const TaskHandle &task_info,
                              const std::string &message) {
  if (!task_info) {
    return message.empty() ? std::string("task handle is null") : message;
  }

  const size_t total = task_info->Size.total.load(std::memory_order_relaxed);
  const size_t transferred =
      task_info->Size.transferred.load(std::memory_order_relaxed);
  const size_t file_num =
      task_info->Size.filenum.load(std::memory_order_relaxed);
  const size_t finished_file_num =
      task_info->Size.finished_filenum.load(std::memory_order_relaxed);

  std::string out = message;
  if (!out.empty()) {
    out += "; ";
  }

  std::string dir_tasks_text = "?";
  if (auto dir_tasks = task_info->Core.dir_tasks.try_lock();
      dir_tasks.has_value()) {
    dir_tasks_text = AMStr::ToString(dir_tasks->get().size());
  }

  out += AMStr::fmt("status={} dir_tasks={} file_num={}/{} transferred={}/{}",
                    TaskStatusText_(task_info->GetStatus()), dir_tasks_text,
                    finished_file_num, file_num, transferred, total);
  if (!task_info->Core.nicknames.empty()) {
    out += AMStr::fmt(" nicknames={}",
                      AMStr::join(task_info->Core.nicknames, ","));
  }
  return out;
}

ECM CheckTransferClientsBeforeSubmit_(
    AMApplication::client::ClientAppService &client_service,
    const TaskHandle &task_info) {
  if (!task_info) {
    return Err(EC::InvalidArg, "transfer.submit.check", "<task>",
               "Task info is null");
  }

  std::unordered_set<AMDomain::client::IClientPort *> visited = {};
  std::vector<ClientHandle> clients = {};
  const auto collect_client = [&visited, &clients](const ClientHandle &client) {
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
    const auto collect_from_tasks = [&collect_client, task_info](auto &tasks) {
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
    auto check_result =
        client_service.CheckClientHandle(client, false, true, std::nullopt, 0);
    if (!(check_result.rcm)) {
      return check_result.rcm;
    }
  }
  return OK;
}
} // namespace

TransferAppService::TransferAppService(
    AMDomain::transfer::ITransferPoolPort &transfer_pool,
    AMApplication::client::ClientAppService &client_service,
    AMApplication::filesystem::FileSystemAppService &filesystem_service,
    AMApplication::log::LoggerAppService *logger)
    : transfer_pool_(transfer_pool), client_service_(client_service),
      filesystem_service_(filesystem_service), logger_(logger) {}

ECM TransferAppService::Submit(const TaskHandle &task_info) {
  if (!task_info) {
    TraceTask_(TraceLevel::Error, EC::InvalidArg, 0, "transfer.submit",
               "TaskInfo is null");
    return Err(EC::InvalidArg, "", "", "TaskInfo is null");
  }
  if (task_info->id == 0) {
    TraceTask_(TraceLevel::Error, EC::InvalidArg, 0, "transfer.submit",
               "Task ID must be > 0");
    return Err(EC::InvalidArg, "", "", "Task ID must be > 0");
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

  const ECM precheck_rcm =
      CheckTransferClientsBeforeSubmit_(client_service_, task_info);
  if (!(precheck_rcm)) {
    task_info->Callback.result = {};
    TraceTask_(TraceLevelForResult_(precheck_rcm), precheck_rcm, task_info,
               "transfer.submit", "pre-submit client check failed");
    return precheck_rcm;
  }

  const ECM submit_rcm = transfer_pool_.Submit(task_info);
  if (!(submit_rcm)) {
    task_info->Callback.result = {};
    TraceTask_(TraceLevelForResult_(submit_rcm), submit_rcm, task_info,
               "transfer.submit", "submit failed");
    return submit_rcm;
  }
  TraceTask_(TraceLevel::Info, submit_rcm, task_info, "transfer.submit",
             "submitted");
  return OK;
}

ECM TransferAppService::Pause(TaskID id, int timeout_ms, int grace_period_ms) {
  if (id == 0) {
    TraceTask_(TraceLevel::Error, EC::InvalidArg, id, "transfer.pause",
               "Task ID must be > 0");
    return Err(EC::InvalidArg, "", "", "Task ID must be > 0");
  }

  {
    auto paused = paused_tasks_.lock();
    if (paused->contains(id)) {
      TraceTask_(TraceLevel::Info, EC::Success, id, "transfer.pause",
                 "task is already paused");
      return OK;
    }
  }
  {
    auto finished = finished_tasks_.lock();
    auto it = finished->find(id);
    if (it != finished->end() && it->second) {
      const ECM final_rcm = it->second->GetResult();
      if (final_rcm.code == EC::Terminate) {
        TraceTask_(TraceLevelForResult_(final_rcm), final_rcm, it->second,
                   "transfer.pause", "finished task already terminated");
        return final_rcm;
      }
      const ECM rcm = Err(EC::OperationUnsupported, "", AMStr::ToString(id),
                          "Task is already finished");
      TraceTask_(TraceLevelForResult_(rcm), rcm, it->second, "transfer.pause",
                 "pause rejected");
      return rcm;
    }
  }

  auto [task_info, rcm] =
      transfer_pool_.StopActive(id, AMDomain::transfer::ActiveStopReason::Pause,
                                timeout_ms, grace_period_ms);
  if (!(rcm)) {
    TraceTask_(TraceLevelForResult_(rcm), rcm, id, "transfer.pause",
               "stop active failed");
    return rcm;
  }
  if (!task_info) {
    const ECM err = Err(EC::InvalidHandle, "", AMStr::ToString(id),
                        "Pause returned null task");
    TraceTask_(TraceLevelForResult_(err), err, id, "transfer.pause",
               "pause returned null task");
    return err;
  }

  StorePaused_(task_info);
  TraceTask_(TraceLevel::Info, OK, task_info, "transfer.pause", "paused");
  return OK;
}

ECM TransferAppService::Resume(TaskID id, int timeout_ms) {
  (void)timeout_ms;
  if (id == 0) {
    TraceTask_(TraceLevel::Error, EC::InvalidArg, id, "transfer.resume",
               "Task ID must be > 0");
    return Err(EC::InvalidArg, "", "", "Task ID must be > 0");
  }

  TaskHandle task_info = nullptr;
  {
    auto paused = paused_tasks_.lock();
    auto it = paused->find(id);
    if (it == paused->end()) {
      const ECM rcm = Err(EC::TaskNotFound, "", AMStr::ToString(id),
                          AMStr::fmt("Paused task not found: {}", id));
      TraceTask_(TraceLevelForResult_(rcm), rcm, id, "transfer.resume",
                 "paused task not found");
      return rcm;
    }
    task_info = it->second;
    paused->erase(it);
  }

  ReleaseClients_(task_info);

  auto recollect_result = RecollectTransferClients_(task_info);
  if (!(recollect_result.rcm)) {
    if (task_info) {
      StorePaused_(task_info);
    }
    TraceTask_(TraceLevelForResult_(recollect_result.rcm), recollect_result.rcm,
               task_info, "transfer.resume", "failed to recollect clients");
    return recollect_result.rcm;
  }

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
    ReleaseClients_(task_info);
    task_info->SetStatus(TaskStatus::Paused);
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    StorePaused_(task_info);
    TraceTask_(TraceLevelForResult_(submit_rcm), submit_rcm, task_info,
               "transfer.resume", "resume submit failed");
    return submit_rcm;
  }
  TraceTask_(TraceLevel::Info, OK, task_info, "transfer.resume", "resumed");
  return OK;
}

std::pair<TransferAppService::TaskHandle, ECM>
TransferAppService::Terminate(TaskID id, int timeout_ms, int grace_period_ms) {
  if (id == 0) {
    TraceTask_(TraceLevel::Error, EC::InvalidArg, id, "transfer.terminate",
               "Task ID must be > 0");
    return {nullptr, Err(EC::InvalidArg, "", "", "Task ID must be > 0")};
  }

  {
    auto finished = finished_tasks_.lock();
    auto it = finished->find(id);
    if (it != finished->end()) {
      const ECM rcm = Err(EC::OperationUnsupported, "", AMStr::ToString(id),
                          "Task already finished");
      TraceTask_(TraceLevelForResult_(rcm), rcm, it->second,
                 "transfer.terminate", "terminate rejected");
      return {it->second, rcm};
    }
  }

  TaskHandle paused_task = nullptr;
  {
    auto paused = paused_tasks_.lock();
    auto it = paused->find(id);
    if (it != paused->end()) {
      paused_task = it->second;
      paused->erase(it);
    }
  }
  if (paused_task) {
    const ECM terminate_rcm =
        Err(EC::Terminate, "", AMStr::ToString(id), "Task terminated");
    MarkUnfinishedEntries_(paused_task, terminate_rcm);
    paused_task->SetResult(terminate_rcm);
    paused_task->SetStatus(TaskStatus::Finished);
    paused_task->Time.finish.store(AMTime::seconds(),
                                   std::memory_order_relaxed);
    ReleaseClients_(paused_task);
    StoreFinished_(paused_task);
    TraceTask_(TraceLevel::Warning, terminate_rcm, paused_task,
               "transfer.terminate", "paused task terminated");
    return {paused_task, OK};
  }

  auto [task_info, stop_rcm] = transfer_pool_.StopActive(
      id, AMDomain::transfer::ActiveStopReason::Terminate, timeout_ms,
      grace_period_ms);
  if (!(stop_rcm)) {
    TraceTask_(TraceLevelForResult_(stop_rcm), stop_rcm, id,
               "transfer.terminate", "stop active failed");
    return {task_info, stop_rcm};
  }
  if (task_info) {
    StoreFinished_(task_info);
    TraceTask_(TraceLevel::Warning, OK, task_info, "transfer.terminate",
               "active task terminated");
  } else {
    TraceTask_(TraceLevel::Warning, EC::Success, id, "transfer.terminate",
               "terminate returned no active task");
  }
  return {task_info, OK};
}

std::optional<TransferAppService::TaskStatus>
TransferAppService::GetStatus(TaskID id) const {
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

TransferAppService::TaskHandle TransferAppService::FindTask(TaskID id) const {
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

TransferAppService::TaskHandle
TransferAppService::GetActiveTask(TaskID id) const {
  if (id == 0) {
    return nullptr;
  }
  return transfer_pool_.GetActiveTask(id);
}

std::unordered_map<TransferAppService::TaskID, TransferAppService::TaskHandle>
TransferAppService::GetAllActiveTasks() const {
  return transfer_pool_.GetAllActiveTasks();
}

std::unordered_map<TransferAppService::TaskID, TransferAppService::TaskHandle>
TransferAppService::GetAllHistoryTasks() const {
  return GetFinishedTasks();
}

std::unordered_map<TransferAppService::TaskID, TransferAppService::TaskHandle>
TransferAppService::GetPendingTasks() const {
  return transfer_pool_.GetPendingTasks();
}

std::unordered_map<TransferAppService::TaskID, TransferAppService::TaskHandle>
TransferAppService::GetConductingTasks() const {
  return transfer_pool_.GetConductingTasks();
}

std::unordered_map<TransferAppService::TaskID, TransferAppService::TaskHandle>
TransferAppService::GetPausedTasks() const {
  auto paused = paused_tasks_.lock();
  return *paused;
}

std::unordered_map<TransferAppService::TaskID, TransferAppService::TaskHandle>
TransferAppService::GetFinishedTasks() const {
  auto finished = finished_tasks_.lock();
  return *finished;
}

TransferAppService::TaskHandle
TransferAppService::GetFinishedTask(TaskID id, bool remove) {
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

TransferAppService::TaskHandle TransferAppService::GetResultTask(TaskID id,
                                                                 bool remove) {
  return GetFinishedTask(id, remove);
}

bool TransferAppService::RemoveFinished(TaskID id) {
  auto finished = finished_tasks_.lock();
  return finished->erase(id) > 0;
}

void TransferAppService::ClearFinished() {
  auto finished = finished_tasks_.lock();
  finished->clear();
}

std::vector<TransferAppService::TaskID>
TransferAppService::ListTaskIDs() const {
  std::unordered_set<TaskID> seen = {};
  std::vector<TaskID> ids = {};
  const auto add_ids =
      [&seen, &ids](const std::unordered_map<TaskID, TaskHandle> &tasks) {
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
  if (task_info->GetStatus() == TaskStatus::Paused) {
    StorePaused_(task_info);
    TraceTask_(TraceLevel::Info, OK, task_info, "transfer.complete",
               "task moved to paused");
    return;
  }
  StoreFinished_(task_info);
  const ECM result = task_info->GetResult();
  TraceTask_(TraceLevelForResult_(result), result, task_info,
             "transfer.complete", "task finished");
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
  task_info->Core.clients = {};
}

void TransferAppService::TraceTask_(AMDomain::client::TraceLevel level, EC code,
                                    TaskID id, const std::string &action,
                                    const std::string &message) const {
  if (logger_ == nullptr) {
    return;
  }
  (void)logger_->Trace(AMDomain::log::LoggerType::Program, level, code, "",
                       TaskTarget_(id), action, message);
}

void TransferAppService::TraceTask_(AMDomain::client::TraceLevel level,
                                    const ECM &rcm, TaskID id,
                                    const std::string &action,
                                    const std::string &message) const {
  std::string detail = message;
  if (!(rcm)) {
    if (!detail.empty()) {
      detail += "; ";
    }
    detail +=
        AMStr::fmt("result={} error={}", AMStr::ToString(rcm.code), rcm.msg());
  }
  TraceTask_(level, rcm.code, id, action, detail);
}

void TransferAppService::TraceTask_(AMDomain::client::TraceLevel level,
                                    const ECM &rcm, const TaskHandle &task_info,
                                    const std::string &action,
                                    const std::string &message) const {
  std::string detail = message;
  if (!(rcm)) {
    if (!detail.empty()) {
      detail += "; ";
    }
    detail +=
        AMStr::fmt("result={} error={}", AMStr::ToString(rcm.code), rcm.msg());
  }
  TraceTask_(level, rcm.code, task_info ? task_info->id : 0, action,
             BuildTaskSummary_(task_info, detail));
}

void TransferAppService::StorePaused_(const TaskHandle &task_info) {
  if (!task_info || task_info->id == 0) {
    return;
  }
  ReleaseClients_(task_info);
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
