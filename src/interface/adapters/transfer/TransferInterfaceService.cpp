#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/bar.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "infrastructure/client/http/HTTP.hpp"
#include "interface/style/StyleManager.hpp"

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

constexpr int kTaskPollIntervalMs = 80;
constexpr int kMinTaskRefreshIntervalMs = 30;

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

bool StartsWith_(const std::string &value, const std::string &prefix) {
  return value.size() >= prefix.size() &&
         std::equal(prefix.begin(), prefix.end(), value.begin());
}

bool IsHttpUrl_(const std::string &url) {
  const std::string lower = AMStr::lowercase(AMStr::Strip(url));
  return StartsWith_(lower, "http://") || StartsWith_(lower, "https://");
}

std::string UrlWithoutQueryFragment_(const std::string &url) {
  const size_t query = url.find('?');
  const size_t fragment = url.find('#');
  size_t cut = std::string::npos;
  if (query != std::string::npos) {
    cut = query;
  }
  if (fragment != std::string::npos) {
    cut = (cut == std::string::npos) ? fragment : std::min(cut, fragment);
  }
  return (cut == std::string::npos) ? url : url.substr(0, cut);
}

bool IsDirectoryUrl_(const std::string &url) {
  const std::string clean = UrlWithoutQueryFragment_(AMStr::Strip(url));
  return !clean.empty() && clean.back() == '/';
}

std::string UrlBasename_(const std::string &url) {
  const std::string clean = UrlWithoutQueryFragment_(AMStr::Strip(url));
  const size_t slash = clean.find_last_of('/');
  if (slash == std::string::npos || slash + 1 >= clean.size()) {
    return "";
  }
  return clean.substr(slash + 1);
}

std::string BuildTaskKey_(const TransferTask &task) {
  return AMStr::fmt("{}\t{}\t{}\t{}\t{}", task.src_host, task.src,
                    task.dst_host, task.dst, static_cast<int>(task.path_type));
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
  return AMStr::ToString(seq.fetch_add(1, std::memory_order_relaxed));
}

int ResolveTransferProgressRefreshMs_(
    const AMInterface::style::AMStyleService *style_service) {
  int refresh_ms = kTaskPollIntervalMs;
  if (style_service != nullptr) {
    refresh_ms = static_cast<int>(
        style_service->GetInitArg().style.progress_bar.refresh_interval_ms);
  }
  return std::max(kMinTaskRefreshIntervalMs, refresh_ms);
}

size_t ResolveTransferProgressSpeedWindow_(
    const AMInterface::style::AMStyleService *style_service) {
  size_t window = 25;
  if (style_service != nullptr) {
    const auto value =
        style_service->GetInitArg().style.progress_bar.speed_window_size;
    if (value > 0) {
      window = static_cast<size_t>(value);
    }
  }
  return std::max<size_t>(1, window);
}

std::string
BuildTransferProgressPrefix_(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info) {
    return "Task";
  }
  auto cur_task = task_info->GetCurrentTaskSnapshot();
  if (!cur_task.has_value()) {
    return AMStr::fmt("Task {}", task_info->id);
  }
  const std::string src_host = DisplayHost_(cur_task->src_host);
  const std::string dst_host = DisplayHost_(cur_task->dst_host);
  return AMStr::fmt("{}@{} -> {}@{}", src_host, AMPath::basename(cur_task->src),
                    dst_host, AMPath::basename(cur_task->dst));
}

std::string ResolveStopLabel_(EC code) {
  if (code == EC::OperationTimeout) {
    return "Timeout";
  }
  return "Terminated";
}

int64_t ResolveElapsedMs_(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info) {
    return 0;
  }
  const double start_s = task_info->Time.start.load(std::memory_order_relaxed);
  if (start_s <= 0.0) {
    return 0;
  }
  double finish_s = task_info->Time.finish.load(std::memory_order_relaxed);
  if (finish_s <= 0.0 || finish_s < start_s) {
    finish_s = AMTime::seconds();
  }
  const int64_t elapsed_ms =
      static_cast<int64_t>((finish_s - start_s) * 1000.0);
  return std::max<int64_t>(0, elapsed_ms);
}

std::string FormatElapsedMs_(int64_t elapsed_ms) {
  const int64_t total_sec = std::max<int64_t>(0, elapsed_ms / 1000);
  const int64_t hours = total_sec / 3600;
  const int64_t mins = (total_sec % 3600) / 60;
  const int64_t secs = total_sec % 60;
  const auto p2 = [](int64_t v) -> std::string {
    if (v >= 0 && v < 10) {
      return "0" + std::to_string(v);
    }
    return std::to_string(v);
  };
  if (hours > 0) {
    return AMStr::fmt("{}:{}:{}", p2(hours), p2(mins), p2(secs));
  }
  return AMStr::fmt("{}:{}", p2(mins), p2(secs));
}

bool PrintWaitTaskResultSummary_(
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
    const std::shared_ptr<TaskInfo> &task_info, const ECM &result) {
  if (!task_info || task_info->Set.quiet) {
    return false;
  }

  const auto file_tasks = task_info->Core.file_tasks.lock().load();
  const auto total_transferred =
      task_info->Size.transferred.load(std::memory_order_relaxed);
  const auto total_size = task_info->Size.total.load(std::memory_order_relaxed);

  if (result.code == EC::Terminate || result.code == EC::OperationTimeout) {
    const std::string msg = result.error.empty() ? result.msg() : result.error;
    prompt_io_manager.FmtPrint("❌ {} {}/{} {}", ResolveStopLabel_(result.code),
                               AMStr::FormatSize(total_transferred),
                               AMStr::FormatSize(total_size), msg);
    return true;
  }

  if (file_tasks.size() == 1) {
    const auto &entry = file_tasks.front();
    if (entry.rcm.code == EC::Success) {
      prompt_io_manager.FmtPrint("✅ {}/{}",
                                 AMStr::FormatSize(entry.transferred),
                                 AMStr::FormatSize(entry.size));
      return true;
    }
    const ECM line_rcm = (entry.rcm.code == EC::Success) ? result : entry.rcm;
    const std::string err_msg =
        line_rcm.error.empty() ? line_rcm.msg() : line_rcm.error;
    prompt_io_manager.FmtPrint("❌ {} {}/{}  {}",
                               AMStr::ToString(line_rcm.code),
                               AMStr::FormatSize(entry.transferred),
                               AMStr::FormatSize(entry.size), err_msg);
    return true;
  }

  if (file_tasks.size() > 1) {
    size_t success = 0;
    size_t failed = 0;
    for (const auto &entry : file_tasks) {
      const std::string src_host = DisplayHost_(entry.src_host);
      const std::string src_path = NormalizePath_(entry.src);
      const bool has_size = entry.size > 0;
      if (entry.rcm.code == EC::Success) {
        ++success;
        continue;
      }

      ++failed;
      if (has_size) {
        prompt_io_manager.FmtPrint("❌ \\[{}] {} {}", src_host, src_path,
                                   AMStr::FormatSize(entry.size));
      } else {
        prompt_io_manager.FmtPrint("❌ \\[{}] {}", src_host, src_path);
      }
      const std::string err_msg =
          entry.rcm.error.empty() ? entry.rcm.msg() : entry.rcm.error;
      prompt_io_manager.FmtPrint("    {}: {}", AMStr::ToString(entry.rcm.code),
                                 err_msg);
    }

    const std::string size_summary =
        AMStr::fmt("{}/{}", AMStr::FormatSize(total_transferred),
                   AMStr::FormatSize(total_size));
    const std::string elapsed = FormatElapsedMs_(ResolveElapsedMs_(task_info));
    prompt_io_manager.FmtPrint(
        "Summary: {} total | {} success | {} failed | {} | {}",
        std::to_string(file_tasks.size()), std::to_string(success),
        std::to_string(failed), size_summary, elapsed);
    return true;
  }

  return false;
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
      style_service_(style_service) {
  (void)control_component_factory;
}

void TransferInterfaceService::SetDefaultControlToken(
    const AMDomain::client::amf &token) {
  default_control_token_ = token;
}

AMDomain::client::amf TransferInterfaceService::GetDefaultControlToken() const {
  return default_control_token_;
}

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

ClientControlComponent TransferInterfaceService::ResolveControl_(
    const std::optional<ClientControlComponent> &component,
    int timeout_ms) const {
  if (component.has_value()) {
    return *component;
  }
  return {default_control_token_, timeout_ms};
}

void TransferInterfaceService::PrintTaskSummary_(
    const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const {
  if (!task_info) {
    return;
  }
  prompt_io_manager_.FmtPrint(
      "Task {} [{}] files {}/{} size {}/{} result {} {}", task_info->id,
      task_info->GetStatus(),
      task_info->Size.success_filenum.load(std::memory_order_relaxed),
      task_info->Size.filenum.load(std::memory_order_relaxed),
      AMStr::FormatSize(
          task_info->Size.transferred.load(std::memory_order_relaxed)),
      AMStr::FormatSize(task_info->Size.total.load(std::memory_order_relaxed)),
      task_info->GetResult().code, task_info->GetResult().error);
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
      std::to_string(
          task_info->Set.OnWhichThread.load(std::memory_order_relaxed)),
      task_info->Set.quiet ? "true" : "false");
}

void TransferInterfaceService::PrintTaskEntries_(
    const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const {
  if (!task_info) {
    return;
  }
  auto dir_tasks = task_info->Core.dir_tasks.lock().load();
  auto file_tasks = task_info->Core.file_tasks.lock().load();
  if (dir_tasks.empty() && file_tasks.empty()) {
    prompt_io_manager_.FmtPrint("Task {} has no entries.", task_info->id);
    return;
  }
  size_t index = 1;
  if (!dir_tasks.empty()) {
    prompt_io_manager_.FmtPrint("  [Directories]");
  }
  for (const auto &entry : dir_tasks) {
    prompt_io_manager_.FmtPrint(
        "  [{}] {}:{} {}@{} -> {}@{} size={} transferred={} overwrite={} "
        "result={} {}",
        std::to_string(index++), task_info->id, PathTypeText_(entry.path_type),
        DisplayHost_(entry.src_host), NormalizePath_(entry.src),
        DisplayHost_(entry.dst_host), NormalizePath_(entry.dst),
        AMStr::FormatSize(entry.size), AMStr::FormatSize(entry.transferred),
        entry.overwrite ? "true" : "false", AMStr::ToString(entry.rcm.code),
        entry.rcm.msg());
  }
  if (!file_tasks.empty()) {
    prompt_io_manager_.FmtPrint("  [Files]");
  }
  for (const auto &entry : file_tasks) {
    prompt_io_manager_.FmtPrint(
        "  [{}] {}:{} {}@{} -> {}@{} size={} transferred={} overwrite={} "
        "result={} {}",
        std::to_string(index++), task_info->id, PathTypeText_(entry.path_type),
        DisplayHost_(entry.src_host), NormalizePath_(entry.src),
        DisplayHost_(entry.dst_host), NormalizePath_(entry.dst),
        AMStr::FormatSize(entry.size), AMStr::FormatSize(entry.transferred),
        entry.overwrite ? "true" : "false", AMStr::ToString(entry.rcm.code),
        entry.rcm.msg());
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
    return OK;
  }
  if (policy == TransferConfirmPolicy::AutoApprove) {
    return OK;
  }
  if (policy == TransferConfirmPolicy::DenyIfConfirmNeeded) {
    return Err(EC::ConfigCanceled, "", "",
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
      prompt_io_manager_.FmtPrint("  {} {}",
                                  item.type == PathType::DIR ? "d" : "f",
                                  NormalizePath_(item.path));
    }
    bool canceled = false;
    const bool accepted =
        prompt_io_manager_.PromptYesNo("Continue transfer? (y/N): ", &canceled);
    if (!accepted || canceled) {
      return Err(EC::ConfigCanceled, "", "", "Transfer canceled by user");
    }
  }
  return OK;
}

ECM TransferInterfaceService::BuildTaskInfo_(
    const TransferRunArg &arg, const ClientControlComponent &control,
    std::shared_ptr<TaskInfo> *out_task_info,
    std::vector<ECM> *warnings) const {
  if (!out_task_info) {
    return Err(EC::InvalidArg, "", "", "null output task info");
  }
  *out_task_info = nullptr;
  if (arg.transfer_sets.empty()) {
    return Err(EC::InvalidArg, "", "", "Transfer set list is empty");
  }

  std::vector<TransferTask> all_dir_tasks = {};
  std::vector<TransferTask> all_file_tasks = {};
  TransferClientContainer clients = {};
  struct ScopedClientRelease_ {
    TransferClientContainer *clients = nullptr;
    bool commit = false;
    ~ScopedClientRelease_() {
      if (!commit && clients != nullptr) {
        clients->ReleaseAll();
      }
    }
  } scoped_client_release{&clients, false};

  std::unordered_set<std::string> nicknames = {};

  for (const auto &set : arg.transfer_sets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted before task generation");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "",
                 "Timeout before task generation");
    }

    auto resolved_dst =
        filesystem_service_.ResolveTransferDst(set.dst, &clients, control);
    if (!(resolved_dst.rcm)) {
      return resolved_dst.rcm;
    }

    auto resolved_src = filesystem_service_.ResolveTransferSrc(
        set.srcs, &clients, control, true);
    if (!(resolved_src.rcm)) {
      return resolved_src.rcm;
    }
    for (const auto &[host, grouped_errors] : resolved_src.data.error_data) {
      for (const auto &[error_path, error_rcm] : grouped_errors) {
        if (!warnings) {
          continue;
        }
        const std::string display_host = DisplayHost_(host);
        const std::string display_path = NormalizePath_(error_path.path);
        warnings->push_back(Err(error_rcm.code, "", "",
                                AMStr::fmt("{}@{}: {}", display_host,
                                           display_path, error_rcm.msg())));
      }
    }

    AMApplication::filesystem::BuildTransferTaskOptions options = {};
    options.clone = set.clone;
    options.mkdir = set.mkdir;
    options.ignore_special_file = set.ignore_special_file;
    options.resume = set.resume;

    auto build_result = filesystem_service_.BuildTransferTasks(
        resolved_src.data, resolved_dst.data, control, options);
    if (!(build_result.rcm)) {
      return build_result.rcm;
    }
    for (auto &task : build_result.data.dir_tasks) {
      task.overwrite = set.overwrite;
    }
    for (auto &task : build_result.data.file_tasks) {
      task.overwrite = set.overwrite;
    }
    all_dir_tasks.insert(all_dir_tasks.end(),
                         build_result.data.dir_tasks.begin(),
                         build_result.data.dir_tasks.end());
    all_file_tasks.insert(all_file_tasks.end(),
                          build_result.data.file_tasks.begin(),
                          build_result.data.file_tasks.end());
    nicknames.insert(DisplayHost_(resolved_dst.data.target.nickname));
    if (warnings) {
      for (const auto &warning : build_result.data.warnings) {
        warnings->push_back(
            Err(warning.rcm.code, "", "",
                AMStr::fmt("{} -> {}: {}", NormalizePath_(warning.src),
                           NormalizePath_(warning.dst), warning.rcm.msg())));
      }
    }
  }

  DedupTasks_(&all_dir_tasks);
  DedupTasks_(&all_file_tasks);
  if (all_dir_tasks.empty() && all_file_tasks.empty()) {
    return Err(EC::InvalidArg, "", "", "No transfer task generated");
  }

  for (const auto &task : all_dir_tasks) {
    nicknames.insert(DisplayHost_(task.src_host));
    nicknames.insert(DisplayHost_(task.dst_host));
  }
  for (const auto &task : all_file_tasks) {
    nicknames.insert(DisplayHost_(task.src_host));
    nicknames.insert(DisplayHost_(task.dst_host));
  }

  auto task_info = std::make_shared<TaskInfo>();
  task_info->id = BuildTaskId_();
  task_info->Set.quiet = arg.quiet;
  int task_timeout_ms = -1;
  if (const auto remain_ms = control.RemainingTimeMs(); remain_ms.has_value()) {
    task_timeout_ms = static_cast<int>(*remain_ms);
  }
  auto task_control_token = AMDomain::client::CreateClientControlToken();
  if (!task_control_token) {
    return Err(EC::InvalidHandle, "", "",
               "failed to create transfer task control token");
  }
  task_info->Core.control =
      ClientControlComponent(task_control_token, task_timeout_ms);
  task_info->Set.transfer_sets =
      std::make_shared<std::vector<AMDomain::transfer::UserTransferSet>>(
          arg.transfer_sets);
  task_info->Core.dir_tasks.lock().store(all_dir_tasks);
  task_info->Core.file_tasks.lock().store(all_file_tasks);
  task_info->Core.clients = std::move(clients);
  scoped_client_release.commit = true;
  task_info->Core.nicknames.assign(nicknames.begin(), nicknames.end());
  task_info->CalTotalSize(true);
  task_info->CalFileNum(true);
  *out_task_info = task_info;
  return OK;
}

ECM TransferInterfaceService::WaitTask_(
    const std::shared_ptr<TaskInfo> &task_info,
    const ClientControlComponent &control) const {
  if (!task_info) {
    return {EC::InvalidArg, "", "", "TaskInfo is null"};
  }

  const bool show_progress = !task_info->Set.quiet;
  const int refresh_ms = ResolveTransferProgressRefreshMs_(style_service_);
  const size_t speed_window =
      ResolveTransferProgressSpeedWindow_(style_service_);

  struct ScopedRefresh_ {
    AMInterface::prompt::AMPromptIOManager *prompt = nullptr;
    bool active = false;
    ~ScopedRefresh_() {
      if (active && prompt != nullptr) {
        prompt->RefreshEnd();
      }
    }
  } scoped_refresh{&prompt_io_manager_, false};

  struct ScopedCursor_ {
    AMInterface::prompt::AMPromptIOManager *prompt = nullptr;
    bool hidden = false;
    ~ScopedCursor_() {
      if (hidden && prompt != nullptr) {
        prompt->SetCursorVisible(true);
      }
    }
  } scoped_cursor{&prompt_io_manager_, false};

  auto build_bar = [this, &task_info]() -> AMProgressBar {
    const auto total_size = static_cast<int64_t>(
        task_info->Size.total.load(std::memory_order_relaxed));
    const std::string prefix = BuildTransferProgressPrefix_(task_info);
    if (style_service_ != nullptr) {
      return style_service_->CreateProgressBar(total_size, prefix);
    }
    return AMProgressBar(total_size, prefix);
  };

  AMProgressBar progress_bar = build_bar();
  std::string final_line = "";
  std::string last_progress_line = "";
  if (show_progress) {
    progress_bar.SetSpeedWindowSize(speed_window);
    prompt_io_manager_.SetCursorVisible(false);
    scoped_cursor.hidden = true;
    prompt_io_manager_.RefreshBegin(1);
    scoped_refresh.active = true;
  }

  auto finalize_and_return = [&](ECM rcm) -> ECM {
    if (show_progress) {
      progress_bar.SetTotal(
          task_info->Size.total.load(std::memory_order_relaxed));
      progress_bar.SetPrefix(BuildTransferProgressPrefix_(task_info));
      progress_bar.SetProgress(
          task_info->Size.transferred.load(std::memory_order_relaxed));
      const std::string candidate_line = progress_bar.RenderLine();
      if (!last_progress_line.empty() &&
          candidate_line.size() < last_progress_line.size()) {
        final_line = last_progress_line;
      } else {
        final_line = candidate_line;
      }
      prompt_io_manager_.RefreshRender({final_line});
      scoped_refresh.active = false;
      prompt_io_manager_.RefreshEnd();
      if (!final_line.empty()) {
        prompt_io_manager_.Print(final_line);
      }
    }
    if (scoped_cursor.hidden) {
      prompt_io_manager_.SetCursorVisible(true);
      scoped_cursor.hidden = false;
    }
    const bool printed_summary =
        PrintWaitTaskResultSummary_(prompt_io_manager_, task_info, rcm);
    if (!printed_summary && !(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
    return rcm;
  };

  while (true) {
    const auto status = task_info->GetStatus();
    if (status == AMDomain::transfer::TaskStatus::Finished) {
      const ECM result = task_info->GetResult();
      return finalize_and_return(result);
    }

    if (control.IsInterrupted()) {
      (void)transfer_pool_.Terminate(task_info->id, 1000);
      return finalize_and_return(
          Err(EC::Terminate, "", "", "Task is terminated by user"));
    }
    if (control.IsTimeout()) {
      (void)transfer_pool_.Terminate(task_info->id, 1000);
      return finalize_and_return(
          Err(EC::OperationTimeout, "", "", "Task timeout"));
    }

    if (show_progress) {
      const auto total_size = static_cast<int64_t>(
          task_info->Size.total.load(std::memory_order_relaxed));
      const auto transferred = static_cast<int64_t>(
          task_info->Size.transferred.load(std::memory_order_relaxed));
      progress_bar.SetTotal(total_size);
      progress_bar.SetPrefix(BuildTransferProgressPrefix_(task_info));
      progress_bar.SetProgress(transferred);
      last_progress_line = progress_bar.RenderLine();
      prompt_io_manager_.RefreshRender({last_progress_line});
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
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

ECM TransferInterfaceService::Transfer(
    const TransferRunArg &arg,
    const std::optional<ClientControlComponent> &component) const {

  const ClientControlComponent control =
      ResolveControl_(component, arg.timeout_ms);
  if (const auto &token = control.ControlToken(); token) {
    token->ClearInterrupt();
  }
  std::vector<WildcardConfirmRequest> confirm_requests = {};
  for (const auto &set : arg.transfer_sets) {
    for (const auto &src : set.srcs) {
      const bool has_wildcard =
          AMDomain::filesystem::services::HasWildcard(src.path);
      if (!has_wildcard) {
        continue;
      }
      auto find_result =
          filesystem_service_.find(src, SearchType::All, control);
      if (!(find_result.rcm)) {
        return find_result.rcm;
      }
      confirm_requests.push_back(
          {std::move(find_result.data), src.nickname, set.dst.nickname});
    }
  }

  ECM confirm_rcm = ConfirmWildcard_(confirm_requests, arg.confirm_policy);
  if (!(confirm_rcm)) {
    return confirm_rcm;
  }

  std::vector<ECM> warnings = {};
  std::shared_ptr<TaskInfo> task_info = nullptr;
  ECM build_rcm = BuildTaskInfo_(arg, control, &task_info, &warnings);
  for (const auto &warning : warnings) {
    prompt_io_manager_.ErrorFormat(warning);
  }
  if (!(build_rcm)) {
    return build_rcm;
  }
  if (!task_info) {
    return {EC::InvalidHandle, "", "", "BuildTaskInfo returned null task"};
  }

  const ECM submit_rcm = transfer_pool_.Submit(task_info);
  if (!(submit_rcm)) {
    task_info->Core.clients.ReleaseAll();
    return submit_rcm;
  }
  if (arg.run_async) {
    prompt_io_manager_.FmtPrint("Submitted task {}", task_info->id);
    return OK;
  }
  return WaitTask_(task_info, control);
}

ECM TransferInterfaceService::HttpGet(
    const HttpGetArg &arg,
    const std::optional<ClientControlComponent> &component) const {
  const ClientControlComponent control =
      ResolveControl_(component, arg.timeout_ms);
  if (const auto &token = control.ControlToken(); token) {
    token->ClearInterrupt();
  }

  const std::string src_url = AMStr::Strip(arg.src_url);
  const std::string src_url_lower = AMStr::lowercase(src_url);
  if (src_url.empty()) {
    return Err(EC::InvalidArg, "wget", "", "Source URL is empty");
  }
  if (!IsHttpUrl_(src_url)) {
    return Err(EC::InvalidArg, "wget", src_url,
               "Only http:// and https:// are supported");
  }
  if (IsDirectoryUrl_(src_url)) {
    return Err(EC::NotAFile, "wget", src_url,
               "HTTP directory URL is unsupported");
  }

  const std::string suggested_name = [&]() -> std::string {
    const std::string name = AMStr::Strip(UrlBasename_(src_url));
    return name.empty() ? std::string("download.bin") : name;
  }();

  auto plan_result = filesystem_service_.BuildHttpDownloadPlan(
      arg.dst_target, suggested_name, control);
  if (!(plan_result.rcm)) {
    return plan_result.rcm;
  }
  const auto &plan = plan_result.data;
  if (!plan.resolved_target.client) {
    return Err(EC::InvalidHandle, "wget", src_url, "Destination client is null");
  }
  if (plan.final_target.is_wildcard) {
    return Err(EC::InvalidArg, "wget", plan.final_target.path,
               "Destination wildcard is invalid");
  }

  const bool dst_exists = plan.dst_info.has_value();
  if (dst_exists && !arg.overwrite) {
    if (arg.confirm_policy == TransferConfirmPolicy::DenyIfConfirmNeeded) {
      return Err(EC::ConfigCanceled, "wget", plan.final_target.path,
                 "Overwrite requires confirmation but denied");
    }
    if (arg.confirm_policy == TransferConfirmPolicy::RequireConfirm) {
      bool canceled = false;
      const bool confirmed = prompt_io_manager_.PromptYesNo(
          AMStr::fmt("Destination exists: {}. Overwrite? (y/N): ",
                     plan.final_target.path),
          &canceled);
      if (!confirmed || canceled) {
        return Err(EC::ConfigCanceled, "wget", plan.final_target.path,
                   "Overwrite canceled by user");
      }
    }
  }

  std::string effective_proxy = arg.proxy;
  if (StartsWith_(src_url_lower, "https://") &&
      !AMStr::Strip(arg.https_proxy).empty()) {
    effective_proxy = arg.https_proxy;
  }
  auto [http_client_rcm, http_client] =
      AMInfra::client::HTTP::CreateTransientHttpSourceClient(
          src_url, effective_proxy, arg.bear_token);
  if (!(http_client_rcm) || !http_client) {
    return http_client_rcm;
  }

  auto src_stat = http_client->IOPort().stat({src_url, false}, control);
  if (!(src_stat.rcm)) {
    return src_stat.rcm;
  }
  if (src_stat.data.info.type != PathType::FILE) {
    return Err(EC::NotAFile, "wget", src_url, "HTTP source is not a file");
  }
  if (auto *http_io =
          dynamic_cast<AMInfra::client::HTTP::AMHTTPIOCore *>(
              &http_client->IOPort());
      http_io != nullptr && !http_io->HasKnownSize()) {
    return Err(EC::OperationUnsupported, "wget", src_url,
               "HTTP source size is unknown; Content-Length is required");
  }

  size_t resume_offset = 0;
  if (arg.resume && dst_exists) {
    resume_offset = plan.dst_info->size;
    if (src_stat.data.info.size > 0 && resume_offset >= src_stat.data.info.size) {
      resume_offset = 0;
    } else if (auto *http_io =
                   dynamic_cast<AMInfra::client::HTTP::AMHTTPIOCore *>(
                       &http_client->IOPort());
               http_io != nullptr) {
      if (!http_io->SupportsRange()) {
        resume_offset = 0;
      }
    } else {
      resume_offset = 0;
    }
  }

  auto task_info = std::make_shared<TaskInfo>();
  task_info->id = BuildTaskId_();
  task_info->Set.quiet = arg.quiet;
  int task_timeout_ms = -1;
  if (const auto remain_ms = control.RemainingTimeMs(); remain_ms.has_value()) {
    task_timeout_ms = static_cast<int>(*remain_ms);
  }
  auto task_control_token = AMDomain::client::CreateClientControlToken();
  if (!task_control_token) {
    return Err(EC::InvalidHandle, "wget", src_url,
               "failed to create transfer task control token");
  }
  task_info->Core.control =
      ClientControlComponent(task_control_token, task_timeout_ms);

  AMDomain::transfer::TransferTask file_task = {};
  file_task.src = src_url;
  file_task.src_host = AMInfra::client::HTTP::kTransientSourceNickname;
  file_task.dst = plan.resolved_target.abs_path;
  file_task.dst_host = plan.resolved_target.target.nickname;
  file_task.size = src_stat.data.info.size;
  file_task.path_type = PathType::FILE;
  file_task.overwrite = arg.overwrite || dst_exists;
  file_task.transferred = resume_offset;

  {
    auto dir_guard = task_info->Core.dir_tasks.lock();
    dir_guard.store(std::vector<AMDomain::transfer::TransferTask>{});
  }
  {
    auto file_guard = task_info->Core.file_tasks.lock();
    file_guard.store(std::vector<AMDomain::transfer::TransferTask>{file_task});
  }
  const ECM add_src_rcm =
      task_info->Core.clients.AddSrcClient(file_task.src_host, http_client);
  if (!(add_src_rcm)) {
    task_info->Core.clients.ReleaseAll();
    return add_src_rcm;
  }
  const ECM add_dst_rcm = task_info->Core.clients.AddDstClient(
      file_task.dst_host, plan.resolved_target.client);
  if (!(add_dst_rcm)) {
    task_info->Core.clients.ReleaseAll();
    return add_dst_rcm;
  }
  task_info->Core.nicknames = {file_task.src_host, file_task.dst_host};
  task_info->CalTotalSize(true);
  task_info->CalFileNum(true);

  const ECM submit_rcm = transfer_pool_.Submit(task_info);
  if (!(submit_rcm)) {
    task_info->Core.clients.ReleaseAll();
    return submit_rcm;
  }
  if (arg.run_async) {
    prompt_io_manager_.FmtPrint("Submitted task {}", task_info->id);
    return OK;
  }
  return WaitTask_(task_info, control);
}

ECM TransferInterfaceService::TaskList(const TransferTaskListArg &arg) const {
  std::unordered_set<std::string> seen_ids = {};
  std::vector<std::string> ids = {};
  const auto add_ids = [&seen_ids, &ids](const auto &map_data) {
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
        !has_filter ||
        (arg.pending && status == AMDomain::transfer::TaskStatus::Pending) ||
        (arg.suspend && status == AMDomain::transfer::TaskStatus::Paused) ||
        (arg.finished && status == AMDomain::transfer::TaskStatus::Finished) ||
        (arg.conducting &&
         status == AMDomain::transfer::TaskStatus::Conducting);
    if (!selected) {
      continue;
    }
    PrintTaskSummary_(task_info);
    ++shown;
  }
  if (shown == 0) {
    prompt_io_manager_.Print("No transfer task matched.");
  }
  return OK;
}

ECM TransferInterfaceService::TaskShow(const TransferTaskShowArg &arg) const {
  if (arg.ids.empty()) {
    return TaskList({});
  }
  ECM status = OK;
  for (const auto &id : arg.ids) {
    auto task_info = FindTask_(id);
    if (!task_info) {
      status =
          Err(EC::TaskNotFound, "", "", AMStr::fmt("Task not found: {}", id));
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
    PrintTaskSummary_(task_info);
    PrintTaskEntries_(task_info);
  }
  return status;
}

ECM TransferInterfaceService::TaskPause(
    const TransferTaskControlArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "", "", "task ids are required");
  }
  ECM status = OK;
  for (const auto &id : arg.ids) {
    ECM rcm = transfer_pool_.Pause(id, arg.timeout_ms);
    if (!(rcm)) {
      status = rcm;
      prompt_io_manager_.ErrorFormat(rcm);
    }
  }
  return status;
}

ECM TransferInterfaceService::TaskResume(
    const TransferTaskControlArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "", "", "task ids are required");
  }
  ECM status = OK;
  for (const auto &id : arg.ids) {
    ECM rcm = transfer_pool_.Resume(id, arg.timeout_ms);
    if (!(rcm)) {
      status = rcm;
      prompt_io_manager_.ErrorFormat(rcm);
    }
  }
  return status;
}

ECM TransferInterfaceService::TaskTerminate(
    const TransferTaskControlArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "", "", "task ids are required");
  }
  ECM status = OK;
  for (const auto &id : arg.ids) {
    auto [task_info, rcm] = transfer_pool_.Terminate(id, arg.timeout_ms);
    (void)task_info;
    if (!(rcm)) {
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
    return Err(EC::InvalidArg, "", "", "task id is required");
  }
  auto task_info = FindTask_(id);
  if (!task_info) {
    return Err(EC::TaskNotFound, "", "", AMStr::fmt("Task not found: {}", id));
  }

  const bool include_sets =
      arg.show_sets || (!arg.show_sets && !arg.show_entries);
  const bool include_entries = arg.show_entries;

  PrintTaskSummaryDetailed_(task_info);
  if (include_sets) {
    PrintTaskSets_(task_info);
  }
  if (include_entries) {
    PrintTaskEntries_(task_info);
  }
  return OK;
}

ECM TransferInterfaceService::TaskResult(
    const TransferTaskResultArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "", "", "task ids are required");
  }
  ECM status = OK;
  for (const auto &id : arg.ids) {
    auto task_info = transfer_pool_.GetResultTask(id, arg.remove);
    if (!task_info) {
      status = Err(EC::TaskNotFound, "", "",
                   AMStr::fmt("Task result not found: {}", id));
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
    prompt_io_manager_.PrintTaskResult(task_info);
  }
  return status;
}

void TransferInterfaceService::GetTaskCounts(size_t *pending_count,
                                             size_t *conducting_count) const {
  if (pending_count) {
    *pending_count = transfer_pool_.GetPendingTasks().size();
  }
  if (conducting_count) {
    *conducting_count = transfer_pool_.GetConductingTasks().size();
  }
}
} // namespace AMInterface::transfer
