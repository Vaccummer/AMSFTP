#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/time.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>
#include <unordered_set>
#include <utility>

namespace AMInterface::transfer {
namespace {
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using TaskInfo = AMDomain::transfer::TaskInfo;
using TransferTask = AMDomain::transfer::TransferTask;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using ClientHandle = AMDomain::client::ClientHandle;

constexpr int kTaskPollIntervalMs = 80;

std::string NormalizeNickname_(const std::string &nickname) {
  return AMDomain::host::HostService::NormalizeNickname(nickname);
}

std::string NormalizePath_(const std::string &path) {
  return AMDomain::filesystem::services::NormalizePath(path);
}

std::string DisplayHost_(const std::string &nickname) {
  const std::string normalized = NormalizeNickname_(nickname);
  return normalized.empty() ? std::string("local") : normalized;
}

std::string BuildTaskKey_(const TransferTask &task) {
  return AMStr::fmt("{}\t{}\t{}\t{}\t{}", task.src_host, task.src, task.dst_host,
                    task.dst, static_cast<int>(task.path_type));
}

void DedupTasks_(std::vector<TransferTask> *tasks) {
  if (!tasks || tasks->empty()) {
    return;
  }
  std::unordered_set<std::string> seen = {};
  std::vector<TransferTask> dedup = {};
  dedup.reserve(tasks->size());
  for (const auto &task : *tasks) {
    const std::string key = BuildTaskKey_(task);
    if (seen.insert(key).second) {
      dedup.push_back(task);
    }
  }
  tasks->swap(dedup);
}

std::string BuildTaskId_() {
  static std::atomic<uint64_t> seq{1};
  const uint64_t id = seq.fetch_add(1, std::memory_order_relaxed);
  return AMStr::fmt("T{}-{}", static_cast<uint64_t>(AMTime::miliseconds()), id);
}

void PutPrimaryClient_(TransferClientContainer *clients,
                       const std::string &nickname, const ClientHandle &client) {
  if (!clients || !client) {
    return;
  }
  const std::string key = DisplayHost_(nickname);
  auto &slot = (*clients)[key];
  if (std::holds_alternative<ClientHandle>(slot)) {
    auto &primary = std::get<ClientHandle>(slot);
    if (!primary) {
      primary = client;
    }
    return;
  }
  auto &pair_slot = std::get<std::pair<ClientHandle, ClientHandle>>(slot);
  if (!pair_slot.first) {
    pair_slot.first = client;
  }
}

void PutSecondaryClient_(TransferClientContainer *clients,
                         const std::string &nickname,
                         const ClientHandle &client) {
  if (!clients || !client) {
    return;
  }
  const std::string key = DisplayHost_(nickname);
  auto &slot = (*clients)[key];
  if (std::holds_alternative<ClientHandle>(slot)) {
    ClientHandle primary = std::get<ClientHandle>(slot);
    slot = std::make_pair(primary ? primary : client, client);
    return;
  }
  auto &pair_slot = std::get<std::pair<ClientHandle, ClientHandle>>(slot);
  if (!pair_slot.first) {
    pair_slot.first = client;
  }
  if (!pair_slot.second) {
    pair_slot.second = client;
  }
}
} // namespace

TransferInterfaceService::TransferInterfaceService(
    AMApplication::filesystem::FilesystemAppService &filesystem_service,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
    AMDomain::transfer::ITransferPoolPort &transfer_pool,
    std::function<ClientControlComponent(AMDomain::client::amf)>
        control_component_factory,
    AMInterface::style::AMStyleService *style_service)
    : filesystem_service_(filesystem_service),
      prompt_io_manager_(prompt_io_manager), transfer_pool_(transfer_pool),
      control_component_factory_(std::move(control_component_factory)),
      style_service_(style_service) {}

const char *TransferInterfaceService::TaskStatusText_(
    AMDomain::transfer::TaskStatus status) {
  switch (status) {
  case AMDomain::transfer::TaskStatus::Pending:
    return "Pending";
  case AMDomain::transfer::TaskStatus::Conducting:
    return "Conducting";
  case AMDomain::transfer::TaskStatus::Paused:
    return "Paused";
  case AMDomain::transfer::TaskStatus::Finished:
    return "Finished";
  default:
    return "Unknown";
  }
}

const char *TransferInterfaceService::PathTypeText_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return "FILE";
  case PathType::DIR:
    return "DIR";
  default:
    return "OTHER";
  }
}

ClientControlComponent
TransferInterfaceService::ResolveControl_(AMDomain::client::amf token) const {
  if (control_component_factory_) {
    return control_component_factory_(token);
  }
  return AMDomain::client::MakeClientControlComponent(token, -1);
}

void TransferInterfaceService::PrintTaskSummary_(
    const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const {
  if (!task_info) {
    return;
  }
  prompt_io_manager_.FmtPrint(
      "Task {} [{}] files {}/{} size {}/{} result {} {}",
      task_info->id, TaskStatusText_(task_info->GetStatus()),
      std::to_string(task_info->Size.success_filenum.load(
          std::memory_order_relaxed)),
      std::to_string(task_info->Size.filenum.load(std::memory_order_relaxed)),
      AMStr::FormatSize(
          task_info->Size.transferred.load(std::memory_order_relaxed)),
      AMStr::FormatSize(task_info->Size.total.load(std::memory_order_relaxed)),
      AMStr::ToString(task_info->GetResult().first), task_info->GetResult().second);
}

void TransferInterfaceService::PrintTaskSummaryDetailed_(
    const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const {
  if (!task_info) {
    return;
  }
  PrintTaskSummary_(task_info);
  prompt_io_manager_.FmtPrint(
      "  submit={} start={} finish={} thread={} quiet={}",
      std::to_string(task_info->Time.submit.load(std::memory_order_relaxed)),
      std::to_string(task_info->Time.start.load(std::memory_order_relaxed)),
      std::to_string(task_info->Time.finish.load(std::memory_order_relaxed)),
      std::to_string(task_info->Set.OnWhichThread.load(std::memory_order_relaxed)),
      task_info->Set.quiet ? "true" : "false");
}

void TransferInterfaceService::PrintTaskEntries_(
    const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const {
  if (!task_info) {
    return;
  }
  auto task_lock = task_info->Core.tasks.lock();
  if (task_lock->empty()) {
    prompt_io_manager_.FmtPrint("Task {} has no entries.", task_info->id);
    return;
  }
  size_t index = 1;
  for (const auto &entry : *task_lock) {
    prompt_io_manager_.FmtPrint(
        "  [{}] {}:{} {}@{} -> {}@{} size={} transferred={} overwrite={} "
        "result={} {}",
        std::to_string(index++), task_info->id, PathTypeText_(entry.path_type),
        DisplayHost_(entry.src_host), NormalizePath_(entry.src),
        DisplayHost_(entry.dst_host), NormalizePath_(entry.dst),
        AMStr::FormatSize(entry.size), AMStr::FormatSize(entry.transferred),
        entry.overwrite ? "true" : "false", AMStr::ToString(entry.rcm.first),
        entry.rcm.second);
  }
}

void TransferInterfaceService::PrintTaskSets_(
    const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const {
  if (!task_info) {
    return;
  }
  if (!task_info->Set.transfer_sets || task_info->Set.transfer_sets->empty()) {
    prompt_io_manager_.FmtPrint("Task {} has no transfer sets.", task_info->id);
    return;
  }
  size_t set_index = 1;
  for (const auto &set : *task_info->Set.transfer_sets) {
    prompt_io_manager_.FmtPrint(
        "  Set {} dst={}@{} clone={} mkdir={} overwrite={} ignore_special={} "
        "resume={}",
        std::to_string(set_index++), DisplayHost_(set.dst.nickname),
        NormalizePath_(set.dst.path), set.clone ? "true" : "false",
        set.mkdir ? "true" : "false", set.overwrite ? "true" : "false",
        set.ignore_special_file ? "true" : "false",
        set.resume ? "true" : "false");
    for (const auto &src : set.srcs) {
      prompt_io_manager_.FmtPrint("    src {}@{}", DisplayHost_(src.nickname),
                                  NormalizePath_(src.path));
    }
  }
}

ECM TransferInterfaceService::ConfirmWildcard_(
    const std::vector<WildcardConfirmRequest> &requests,
    TransferConfirmPolicy policy) const {
  if (requests.empty()) {
    return Ok();
  }
  if (policy == TransferConfirmPolicy::AutoApprove) {
    return Ok();
  }
  if (policy == TransferConfirmPolicy::DenyIfConfirmNeeded) {
    return Err(EC::ConfigCanceled,
               "Transfer requires confirmation but confirm policy denied");
  }
  for (const auto &request : requests) {
    if (request.matches.empty()) {
      continue;
    }
    const std::string src = DisplayHost_(request.src_host);
    const std::string dst = DisplayHost_(request.dst_host);
    prompt_io_manager_.FmtPrint("Found {} wildcard matches ({} -> {})",
                                std::to_string(request.matches.size()), src,
                                dst);
    for (const auto &item : request.matches) {
      prompt_io_manager_.FmtPrint("  {} {}", item.type == PathType::DIR ? "d" : "f",
                                  NormalizePath_(item.path));
    }
    bool canceled = false;
    const bool accepted =
        prompt_io_manager_.PromptYesNo("Continue transfer? (y/N): ", &canceled);
    if (!accepted || canceled) {
      return Err(EC::ConfigCanceled, "Transfer canceled by user");
    }
  }
  return Ok();
}

ECM TransferInterfaceService::BuildTaskInfo_(
    const TransferRunArg &arg, const ClientControlComponent &control,
    std::shared_ptr<TaskInfo> *out_task_info, std::vector<ECM> *warnings) const {
  if (!out_task_info) {
    return Err(EC::InvalidArg, "null output task info");
  }
  *out_task_info = nullptr;
  if (arg.transfer_sets.empty()) {
    return Err(EC::InvalidArg, "Transfer set list is empty");
  }

  std::vector<TransferTask> all_tasks = {};
  TransferClientContainer clients = {};
  std::unordered_set<std::string> nicknames = {};

  for (const auto &set : arg.transfer_sets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted before task generation");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "Timeout before task generation");
    }

    auto resolved_dst = filesystem_service_.ResolveTransferDst(set.dst, control);
    if (!isok(resolved_dst.rcm)) {
      return resolved_dst.rcm;
    }

    auto resolved_src =
        filesystem_service_.ResolveTransferSrc(set.srcs, &clients, control, true);
    if (!isok(resolved_src.rcm)) {
      return resolved_src.rcm;
    }

    for (const auto &[nickname, transfer_path] : resolved_src.data.data) {
      if (transfer_path.client) {
        PutPrimaryClient_(&clients, nickname, transfer_path.client);
      }
      nicknames.insert(DisplayHost_(nickname));
    }
    if (resolved_dst.data.client) {
      PutPrimaryClient_(&clients, resolved_dst.data.target.nickname,
                        resolved_dst.data.client);
      nicknames.insert(DisplayHost_(resolved_dst.data.target.nickname));
    }

    AMApplication::filesystem::BuildTransferTaskOptions options = {};
    options.clone = set.clone;
    options.mkdir = set.mkdir;
    options.ignore_special_file = set.ignore_special_file;
    options.resume = set.resume;

    auto build_result = filesystem_service_.BuildTransferTasks(
        resolved_src.data, resolved_dst.data, control, options);
    if (!isok(build_result.rcm)) {
      return build_result.rcm;
    }
    for (auto &task : build_result.data.dir_tasks) {
      task.overwrite = set.overwrite;
    }
    for (auto &task : build_result.data.file_tasks) {
      task.overwrite = set.overwrite;
    }
    all_tasks.insert(all_tasks.end(), build_result.data.dir_tasks.begin(),
                     build_result.data.dir_tasks.end());
    all_tasks.insert(all_tasks.end(), build_result.data.file_tasks.begin(),
                     build_result.data.file_tasks.end());
    if (warnings) {
      for (const auto &warning : build_result.data.warnings) {
        warnings->push_back(Err(
            warning.rcm.first,
            AMStr::fmt("{} -> {}: {}", NormalizePath_(warning.src),
                       NormalizePath_(warning.dst), warning.rcm.second)));
      }
    }
  }

  for (const auto &task : all_tasks) {
    const std::string src_host = DisplayHost_(task.src_host);
    const std::string dst_host = DisplayHost_(task.dst_host);
    if (src_host != dst_host) {
      continue;
    }
    auto it = clients.find(src_host);
    if (it == clients.end()) {
      continue;
    }
    ClientHandle src_client = nullptr;
    if (std::holds_alternative<ClientHandle>(it->second)) {
      src_client = std::get<ClientHandle>(it->second);
    } else {
      auto pair_slot = std::get<std::pair<ClientHandle, ClientHandle>>(it->second);
      src_client = pair_slot.first ? pair_slot.first : pair_slot.second;
    }
    if (src_client) {
      PutSecondaryClient_(&clients, src_host, src_client);
    }
  }

  DedupTasks_(&all_tasks);
  if (all_tasks.empty()) {
    return Err(EC::InvalidArg, "No transfer task generated");
  }

  auto task_info = std::make_shared<TaskInfo>();
  task_info->id = BuildTaskId_();
  task_info->Set.quiet = arg.quiet;
  task_info->Core.control = control;
  task_info->Set.transfer_sets =
      std::make_shared<std::vector<AMDomain::transfer::UserTransferSet>>(
          arg.transfer_sets);
  {
    auto tasks_lock = task_info->Core.tasks.lock();
    tasks_lock.store(all_tasks);
  }
  task_info->Core.clients = clients;
  task_info->Core.nicknames.assign(nicknames.begin(), nicknames.end());
  task_info->CalTotalSize(true);
  task_info->CalFileNum(true);
  *out_task_info = task_info;
  return Ok();
}

ECM TransferInterfaceService::WaitTask_(
    const TaskInfo::ID &task_id, const ClientControlComponent &control) const {
  while (true) {
    if (control.IsInterrupted()) {
      (void)transfer_pool_.Terminate(task_id, 1000);
      return Err(EC::Terminate, "Transfer interrupted");
    }
    if (control.IsTimeout()) {
      (void)transfer_pool_.Terminate(task_id, 1000);
      return Err(EC::OperationTimeout, "Transfer timeout");
    }

    auto done = transfer_pool_.GetResultTask(task_id, false);
    if (done) {
      return done->GetResult();
    }

    auto status = transfer_pool_.GetStatus(task_id);
    if (!status.has_value()) {
      return Err(EC::TaskNotFound, AMStr::fmt("Task not found: {}", task_id));
    }
    if (*status == AMDomain::transfer::TaskStatus::Finished) {
      done = transfer_pool_.GetResultTask(task_id, false);
      return done ? done->GetResult() : Ok();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(kTaskPollIntervalMs));
  }
}

std::shared_ptr<AMDomain::transfer::TaskInfo>
TransferInterfaceService::FindTask_(const std::string &task_id) const {
  if (task_id.empty()) {
    return nullptr;
  }
  auto active = transfer_pool_.GetActiveTask(task_id);
  if (active) {
    return active;
  }
  return transfer_pool_.GetResultTask(task_id, false);
}

ECM TransferInterfaceService::Transfer(const TransferRunArg &arg) const {
  const ClientControlComponent control = ResolveControl_(arg.control_token);

  std::vector<WildcardConfirmRequest> confirm_requests = {};
  for (const auto &set : arg.transfer_sets) {
    for (const auto &src : set.srcs) {
      const bool has_wildcard =
          src.is_wildcard || AMDomain::filesystem::services::HasWildcard(src.path);
      if (!has_wildcard) {
        continue;
      }
      auto find_result = filesystem_service_.find(src, SearchType::All, control);
      if (!isok(find_result.rcm)) {
        return find_result.rcm;
      }
      confirm_requests.push_back(
          {std::move(find_result.data), src.nickname, set.dst.nickname});
    }
  }

  ECM confirm_rcm = ConfirmWildcard_(confirm_requests, arg.confirm_policy);
  if (!isok(confirm_rcm)) {
    return confirm_rcm;
  }

  std::vector<ECM> warnings = {};
  std::shared_ptr<TaskInfo> task_info = nullptr;
  ECM build_rcm = BuildTaskInfo_(arg, control, &task_info, &warnings);
  for (const auto &warning : warnings) {
    prompt_io_manager_.ErrorFormat(warning);
  }
  if (!isok(build_rcm)) {
    return build_rcm;
  }
  if (!task_info) {
    return Err(EC::InvalidHandle, "BuildTaskInfo returned null task");
  }

  const ECM submit_rcm = transfer_pool_.Submit(task_info, task_info->Core.clients);
  if (!isok(submit_rcm)) {
    return submit_rcm;
  }
  prompt_io_manager_.FmtPrint("Submitted task {}", task_info->id);

  if (arg.run_async) {
    return Ok();
  }
  return WaitTask_(task_info->id, control);
}

ECM TransferInterfaceService::TaskList(const TransferTaskListArg &arg) const {
  std::unordered_set<std::string> seen_ids = {};
  std::vector<std::string> ids = {};
  const auto add_ids =
      [&seen_ids, &ids](const auto &map_data) {
        for (const auto &[id, task_info] : map_data) {
          if (id.empty() || !task_info) {
            continue;
          }
          if (seen_ids.insert(id).second) {
            ids.push_back(id);
          }
        }
      };
  add_ids(transfer_pool_.GetPendingTasks());
  add_ids(transfer_pool_.GetConductingTasks());
  add_ids(transfer_pool_.GetAllHistoryTasks());
  std::sort(ids.begin(), ids.end());

  const bool has_filter =
      arg.pending || arg.suspend || arg.finished || arg.conducting;
  size_t shown = 0;
  for (const auto &id : ids) {
    auto task_info = FindTask_(id);
    if (!task_info) {
      continue;
    }
    const auto status = task_info->GetStatus();
    const bool selected =
        !has_filter || (arg.pending && status == AMDomain::transfer::TaskStatus::Pending) ||
        (arg.suspend && status == AMDomain::transfer::TaskStatus::Paused) ||
        (arg.finished && status == AMDomain::transfer::TaskStatus::Finished) ||
        (arg.conducting && status == AMDomain::transfer::TaskStatus::Conducting);
    if (!selected) {
      continue;
    }
    PrintTaskSummary_(task_info);
    ++shown;
  }
  if (shown == 0) {
    prompt_io_manager_.Print("No transfer task matched.");
  }
  return Ok();
}

ECM TransferInterfaceService::TaskShow(const TransferTaskShowArg &arg) const {
  if (arg.ids.empty()) {
    return TaskList({});
  }
  ECM status = Ok();
  for (const auto &id : arg.ids) {
    auto task_info = FindTask_(id);
    if (!task_info) {
      status = Err(EC::TaskNotFound, AMStr::fmt("Task not found: {}", id));
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
    PrintTaskSummary_(task_info);
    PrintTaskEntries_(task_info);
  }
  return status;
}

ECM TransferInterfaceService::TaskPause(const TransferTaskControlArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "task ids are required");
  }
  ECM status = Ok();
  for (const auto &id : arg.ids) {
    ECM rcm = transfer_pool_.Pause(id, arg.timeout_ms);
    if (!isok(rcm)) {
      status = rcm;
      prompt_io_manager_.ErrorFormat(rcm);
    }
  }
  return status;
}

ECM TransferInterfaceService::TaskResume(
    const TransferTaskControlArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "task ids are required");
  }
  ECM status = Ok();
  for (const auto &id : arg.ids) {
    ECM rcm = transfer_pool_.Resume(id, arg.timeout_ms);
    if (!isok(rcm)) {
      status = rcm;
      prompt_io_manager_.ErrorFormat(rcm);
    }
  }
  return status;
}

ECM TransferInterfaceService::TaskTerminate(
    const TransferTaskControlArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "task ids are required");
  }
  ECM status = Ok();
  for (const auto &id : arg.ids) {
    auto [task_info, rcm] = transfer_pool_.Terminate(id, arg.timeout_ms);
    (void)task_info;
    if (!isok(rcm)) {
      status = rcm;
      prompt_io_manager_.ErrorFormat(rcm);
    }
  }
  return status;
}

ECM TransferInterfaceService::TaskInspect(
    const TransferTaskInspectArg &arg) const {
  const std::string id = AMStr::Strip(arg.id);
  if (id.empty()) {
    return Err(EC::InvalidArg, "task id is required");
  }
  auto task_info = FindTask_(id);
  if (!task_info) {
    return Err(EC::TaskNotFound, AMStr::fmt("Task not found: {}", id));
  }

  const bool include_sets = arg.show_sets || (!arg.show_sets && !arg.show_entries);
  const bool include_entries = arg.show_entries;

  PrintTaskSummaryDetailed_(task_info);
  if (include_sets) {
    PrintTaskSets_(task_info);
  }
  if (include_entries) {
    PrintTaskEntries_(task_info);
  }
  return Ok();
}

ECM TransferInterfaceService::TaskResult(const TransferTaskResultArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "task ids are required");
  }
  ECM status = Ok();
  for (const auto &id : arg.ids) {
    auto task_info = transfer_pool_.GetResultTask(id, arg.remove);
    if (!task_info) {
      status = Err(EC::TaskNotFound, AMStr::fmt("Task result not found: {}", id));
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
    prompt_io_manager_.PrintTaskResult(task_info);
  }
  return status;
}
} // namespace AMInterface::transfer
