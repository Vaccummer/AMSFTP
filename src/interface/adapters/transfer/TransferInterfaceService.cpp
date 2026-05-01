#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "foundation/tools/bar.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "foundation/tools/url.hpp"
#include "infrastructure/client/http/HTTP.hpp"
#include "interface/style/StyleManager.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <semaphore>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace AMInterface::transfer {
namespace {
using AMDomain::filesystem::SearchType;
using AMDomain::transfer::TaskID;
using TaskInfo = AMDomain::transfer::TaskInfo;
using TransferTask = AMDomain::transfer::TransferTask;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;

constexpr int kTaskPollIntervalMs = 1000;
constexpr int kMinTaskRefreshIntervalMs = 1000;
constexpr int64_t kDefaultTaskSpeedWindowMs = 7000;

std::string NormalizeNickname_(const std::string &nickname) {
  return AMDomain::host::HostService::NormalizeNickname(nickname);
}

std::string NormalizePath_(const std::string &path) {
  return AMDomain::filesystem::service::NormalizePath(path);
}

std::string DisplayHost_(const std::string &nickname) {
  const std::string normalized = NormalizeNickname_(nickname);
  return normalized.empty() ? std::string("local") : normalized;
}

std::string BuildTaskKey_(const TransferTask &task) {
  return AMStr::fmt("{}\t{}\t{}\t{}\t{}", task.src_host, task.src,
                    task.dst_host, task.dst, static_cast<int>(task.path_type));
}

void DedupTasks_(std::vector<TransferTask> *tasks) {
  if (!tasks || tasks->empty()) {
    return;
  }
  *tasks = AMStr::DedupVectorKeepOrder(
      *tasks, [](const TransferTask &task) { return BuildTaskKey_(task); });
}

std::vector<std::string>
CollectOverwriteTargets_(const std::vector<TransferTask> &tasks) {
  std::vector<std::string> out = {};
  out.reserve(tasks.size());
  for (const auto &task : tasks) {
    if (!task.overwrite) {
      continue;
    }
    out.push_back(AMStr::fmt("{}@{}", DisplayHost_(task.dst_host),
                             NormalizePath_(task.dst)));
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

TaskID BuildTaskId_() {
  static std::atomic<TaskID> seq{1};
  return seq.fetch_add(1, std::memory_order_relaxed);
}

void PrintTransferStage_(AMInterface::prompt::PromptIOManager &prompt,
                         bool show_report, int index, int total,
                         const std::string &name) {
  if (!show_report) {
    return;
  }
  prompt.FmtPrint("[Transfer Stage {}/{}] {}", index, total, name);
}

void ReportTransferSubStage_(
    const std::function<void(const std::string &)> &stage_reporter,
    const std::string &name) {
  if (!stage_reporter) {
    return;
  }
  stage_reporter(name);
}

int ResolveTransferProgressRefreshMs_(
    const AMInterface::style::AMStyleService *style_service,
    int transfer_refresh_interval_ms) {
  int refresh_ms = kTaskPollIntervalMs;
  if (transfer_refresh_interval_ms > 0) {
    refresh_ms = transfer_refresh_interval_ms;
  } else if (style_service != nullptr) {
    refresh_ms = static_cast<int>(
        style_service->GetInitArg().style.progress_bar.refresh_interval_ms);
  }
  return std::max(kMinTaskRefreshIntervalMs, refresh_ms);
}

int64_t ResolveElapsedMs_(const std::shared_ptr<TaskInfo> &task_info);

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
  if (AMUrl::IsHttpUrl(cur_task->src)) {
    const std::string dst_name = AMPath::basename(cur_task->dst);
    return AMStr::fmt("{}@{}", dst_host,
                      dst_name.empty() ? cur_task->dst : dst_name);
  }
  const std::string src_name = AMUrl::IsHttpUrl(cur_task->src)
                                   ? (AMUrl::Basename(cur_task->src).empty()
                                          ? cur_task->src
                                          : AMUrl::Basename(cur_task->src))
                                   : AMPath::basename(cur_task->src);
  return AMStr::fmt("{}@{} -> {}@{}", src_host, src_name, dst_host,
                    AMPath::basename(cur_task->dst));
}

AMBar::BaseProgressBar::RenderArgs
BuildTransferProgressRenderArgs_(const std::shared_ptr<TaskInfo> &task_info,
                                 int64_t speed_window_ms) {
  AMBar::BaseProgressBar::RenderArgs args = {};
  if (!task_info) {
    args.filename = "Task";
    return args;
  }
  auto cur_task = task_info->GetCurrentTaskSnapshot();
  if (!cur_task.has_value()) {
    args.filename = AMStr::fmt("Task {}", task_info->id);
    args.elapsed_ms = ResolveElapsedMs_(task_info);
    args.speed_bps = task_info->GetSpeedBytesPerSecond(speed_window_ms);
    return args;
  }
  args.src_host = DisplayHost_(cur_task->src_host);
  args.dst_host = DisplayHost_(cur_task->dst_host);
  const std::string dst_name = AMPath::basename(cur_task->dst);
  const std::string src_name = AMUrl::IsHttpUrl(cur_task->src)
                                   ? AMUrl::Basename(cur_task->src)
                                   : AMPath::basename(cur_task->src);
  if (!dst_name.empty()) {
    args.filename = dst_name;
  } else if (!src_name.empty()) {
    args.filename = src_name;
  } else {
    args.filename = cur_task->dst.empty() ? cur_task->src : cur_task->dst;
  }
  args.elapsed_ms = ResolveElapsedMs_(task_info);
  args.speed_bps = task_info->GetSpeedBytesPerSecond(speed_window_ms);
  return args;
}

std::string ResolveStopLabel_(EC code) {
  if (code == EC::OperationTimeout) {
    return "Timeout";
  }
  return "Terminated";
}

void WriteTransientHttpRuntimeMetadata_(AMDomain::client::IClientPort &client,
                                        const std::string &proxy,
                                        int max_redirect_times,
                                        const std::string &bear_token) {
  auto &metadata = client.MetaDataPort();
  (void)metadata.StoreNamedData("http.proxy", proxy, true);
  (void)metadata.StoreNamedData("http.max_redirect_times",
                                std::max(0, max_redirect_times), true);
  (void)metadata.StoreNamedData("http.bear_token", bear_token, true);
}

std::string EntryResultCodeText_(const std::optional<ECM> &rcm) {
  if (!rcm.has_value()) {
    return "Pending";
  }
  return AMStr::ToString(rcm->code);
}

std::string EntryResultMessageText_(const std::optional<ECM> &rcm) {
  if (!rcm.has_value()) {
    return "Pending";
  }
  return rcm->error.empty() ? rcm->msg() : rcm->error;
}

bool EntryResultIsSuccess_(const std::optional<ECM> &rcm) {
  return rcm.has_value() && rcm->code == EC::Success;
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

int64_t ResolveTaskSpeedWindowMs_(
    const AMInterface::style::AMStyleService *style_service) {
  if (style_service == nullptr) {
    return kDefaultTaskSpeedWindowMs;
  }
  return std::max<int64_t>(
      1, style_service->GetInitArg().style.progress_bar.speed.speed_window_ms);
}

std::string FormatTaskSpeed_(const std::shared_ptr<TaskInfo> &task_info,
                             int64_t speed_window_ms) {
  if (!task_info) {
    return AMStr::PadLeftAscii("-", 7);
  }
  const double speed_bps = task_info->GetSpeedBytesPerSecond(speed_window_ms);
  if (speed_bps <= 0.0) {
    return AMStr::PadLeftAscii("-", 7);
  }
  return AMStr::FormatSpeed(speed_bps, 3, 1, 7, true);
}

std::string BuildTaskResultCell_(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info ||
      task_info->GetStatus() != AMDomain::transfer::TaskStatus::Finished) {
    return "-";
  }

  const ECM result = task_info->GetResult();
  if (result.code == EC::Success) {
    return "✅";
  }
  return AMStr::fmt("❌ {}", AMStr::ToString(result.code));
}

int ResolveTaskProgressPercent_(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info) {
    return 0;
  }
  const size_t transferred =
      task_info->Size.transferred.load(std::memory_order_relaxed);
  const size_t total = task_info->Size.total.load(std::memory_order_relaxed);
  if (total == 0) {
    return 0;
  }
  const size_t percent = (transferred * 100) / total;
  return static_cast<int>(std::clamp<size_t>(percent, 0, 100));
}

struct TaskTableRow_ {
  TaskID id = 0;
  std::string state = {};
  std::string percentage = {};
  std::string size = {};
  std::string speed = {};
  std::string files_num = {};
  std::string result = {};
};

struct TaskRemovePreviewEntry_ {
  TaskID id = 0;
  std::string result = {};
  std::string size = {};
  std::string elapse = {};
  std::string summary = {};
};

struct TaskInspectSetSnapshot_ {
  AMDomain::filesystem::PathTarget dst = {};
  bool clone = false;
  bool mkdir = false;
  bool overwrite = false;
  bool ignore_special_file = false;
  bool resume = false;
  std::vector<AMDomain::filesystem::PathTarget> srcs = {};
};

struct TaskInspectEntrySnapshot_ {
  size_t index = 0;
  PathType type = PathType::FILE;
  std::string src_host = {};
  std::string src = {};
  std::string dst_host = {};
  std::string dst = {};
  size_t size = 0;
  size_t transferred = 0;
  bool overwrite = false;
  bool finished = false;
  std::optional<ECM> result = std::nullopt;
};

struct TaskInspectSnapshot_ {
  TaskID id = 0;
  AMDomain::transfer::TaskStatus status =
      AMDomain::transfer::TaskStatus::Pending;
  AMDomain::transfer::ControlIntent intent =
      AMDomain::transfer::ControlIntent::Running;
  ECM result = OK;

  double submit_time_s = 0;
  double start_time_s = 0;
  double finish_time_s = 0;
  int64_t elapsed_ms = 0;

  size_t total = 0;
  size_t transferred = 0;
  size_t finished_files = 0;
  size_t total_files = 0;
  size_t current_task_index = 0;
  size_t current_task_transferred = 0;
  int progress_percent = 0;
  double speed_bps = 0.0;

  bool interrupted = false;
  bool timeout = false;
  std::optional<unsigned int> timeout_remaining_ms = std::nullopt;
  std::optional<TaskInfo::CurrentTaskSnapshot> current_task = std::nullopt;
  std::string source_display = {};
  std::string destination_display = {};

  std::vector<TaskInspectSetSnapshot_> sets = {};
  std::vector<TaskInspectEntrySnapshot_> entries = {};
};

const char *TaskStatusTextLocal_(AMDomain::transfer::TaskStatus status) {
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

const char *PathTypeTextLocal_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return "FILE";
  case PathType::DIR:
    return "DIR";
  default:
    return "OTHER";
  }
}

std::string FormatClockTimeLocal_(double epoch_seconds) {
  if (epoch_seconds <= 0.0) {
    return "-";
  }
  return FormatTime(static_cast<size_t>(epoch_seconds), "%H:%M:%S");
}

std::string IntentTextLocal_(AMDomain::transfer::ControlIntent intent) {
  switch (intent) {
  case AMDomain::transfer::ControlIntent::Running:
    return "RUNNING";
  case AMDomain::transfer::ControlIntent::Pause:
    return "PAUSE";
  case AMDomain::transfer::ControlIntent::Terminate:
    return "TERMINATE";
  default:
    return "UNKNOWN";
  }
}

struct InspectStateView_ {
  std::string icon = {};
  std::string text = {};
};

InspectStateView_ BuildInspectStateView_(const TaskInspectSnapshot_ &snapshot) {
  InspectStateView_ out = {};
  switch (snapshot.status) {
  case AMDomain::transfer::TaskStatus::Conducting:
    out.icon = "🟡";
    out.text = "RUNNING";
    return out;
  case AMDomain::transfer::TaskStatus::Paused:
    out.icon = "🔴";
    out.text = "PAUSE";
    return out;
  case AMDomain::transfer::TaskStatus::Pending:
    out.icon = "⚪";
    out.text = "WAIT";
    return out;
  case AMDomain::transfer::TaskStatus::Finished:
    if (snapshot.result.code == EC::Success) {
      out.icon = "🟢";
      out.text = "DONE";
    } else {
      out.icon = "❌";
      out.text = "FAIL";
    }
    return out;
  default:
    out.icon = "⚪";
    out.text = "UNKNOWN";
    return out;
  }
}

TaskTableRow_ BuildTaskTableRow_(const std::shared_ptr<TaskInfo> &task_info,
                                 int64_t speed_window_ms) {
  TaskTableRow_ row = {};
  if (!task_info) {
    return row;
  }
  const size_t transferred =
      task_info->Size.transferred.load(std::memory_order_relaxed);
  const size_t total = task_info->Size.total.load(std::memory_order_relaxed);
  const size_t finished_files =
      task_info->Size.finished_filenum.load(std::memory_order_relaxed);
  const size_t total_files =
      task_info->Size.filenum.load(std::memory_order_relaxed);
  row.id = task_info->id;
  row.state = TaskStatusTextLocal_(task_info->GetStatus());
  row.percentage = AMStr::fmt("{}%", ResolveTaskProgressPercent_(task_info));
  row.size = AMStr::fmt("{}/{}", AMStr::FormatSize(transferred),
                        AMStr::FormatSize(total));
  row.speed = FormatTaskSpeed_(task_info, speed_window_ms);
  row.files_num = AMStr::fmt("{}/{}", finished_files, total_files);
  row.result = BuildTaskResultCell_(task_info);
  return row;
}

std::string
BuildTaskRemoveSummary_(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info) {
    return "<unknown>";
  }

  const auto current_task = task_info->GetCurrentTaskSnapshot();
  if (current_task.has_value()) {
    const std::string src_name = AMUrl::IsHttpUrl(current_task->src)
                                     ? AMUrl::Basename(current_task->src)
                                     : AMPath::basename(current_task->src);
    const std::string dst_name = AMPath::basename(current_task->dst);
    const std::string src_label =
        src_name.empty() ? current_task->src : src_name;
    const std::string dst_label =
        dst_name.empty() ? current_task->dst : dst_name;
    return AMStr::fmt("{}@{} -> {}@{}", DisplayHost_(current_task->src_host),
                      src_label, DisplayHost_(current_task->dst_host),
                      dst_label);
  }

  auto sets = task_info->Set.transfer_sets;
  if (!sets || sets->empty()) {
    return AMStr::fmt("Task {}", task_info->id);
  }

  const auto &set = sets->front();
  const std::string dst_name = AMPath::basename(set.dst.path);
  const std::string dst_label = dst_name.empty() ? set.dst.path : dst_name;
  if (set.srcs.empty()) {
    return AMStr::fmt("{}@{}", DisplayHost_(set.dst.nickname), dst_label);
  }

  const auto &src = set.srcs.front();
  const std::string src_name = AMPath::basename(src.path);
  const std::string src_label = src_name.empty() ? src.path : src_name;
  return AMStr::fmt("{}@{} -> {}@{}", DisplayHost_(src.nickname), src_label,
                    DisplayHost_(set.dst.nickname), dst_label);
}

TaskRemovePreviewEntry_
BuildTaskRemovePreviewEntry_(const std::shared_ptr<TaskInfo> &task_info) {
  TaskRemovePreviewEntry_ row = {};
  if (!task_info) {
    return row;
  }

  const ECM result = task_info->GetResult();
  row.id = task_info->id;
  row.result = (result.code == EC::Success) ? "✅ Success"
                                            : AMStr::fmt("❌ {}", result.msg());
  row.size = BuildTaskTableRow_(task_info, kDefaultTaskSpeedWindowMs).size;
  row.elapse = FormatElapsedMs_(ResolveElapsedMs_(task_info));
  row.summary = BuildTaskRemoveSummary_(task_info);
  return row;
}

void PrintTaskRemovePreview_(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    const std::vector<TaskRemovePreviewEntry_> &rows) {
  if (rows.empty()) {
    return;
  }

  size_t id_width = 0;
  size_t size_width = 0;
  size_t elapse_width = 0;
  for (const auto &row : rows) {
    id_width =
        std::max(id_width, AMStr::DisplayWidthUtf8(AMStr::fmt("#{}", row.id)));
    size_width = std::max(size_width, AMStr::DisplayWidthUtf8(row.size));
    elapse_width = std::max(elapse_width, AMStr::DisplayWidthUtf8(row.elapse));
  }

  for (const auto &row : rows) {
    const std::string id_text = AMStr::fmt("#{}", row.id);
    prompt_io_manager.Print(
        AMStr::fmt("{} {} {} {} {}", AMStr::PadRightUtf8(id_text, id_width),
                   AMStr::PadRightUtf8(row.size, size_width),
                   AMStr::PadRightUtf8(row.elapse, elapse_width), row.summary,
                   row.result));
  }
}

std::string BuildTaskTableText_(const std::vector<TaskTableRow_> &rows) {
  if (rows.empty()) {
    return "";
  }
  const std::vector<std::string> headers = {"ID",    "State",   "Per",   "Size",
                                            "Speed", "FileNum", "Result"};
  std::vector<std::vector<std::string>> table_rows = {};
  table_rows.reserve(rows.size());
  for (const auto &row : rows) {
    table_rows.push_back({AMStr::fmt("{}", row.id), row.state, row.percentage,
                          row.size, row.speed, row.files_num, row.result});
  }
  return AMStr::FormatUtf8Table(headers, table_rows, "", 1, 1, 0, 0);
}

void PrintTaskTable_(AMInterface::prompt::PromptIOManager &prompt_io_manager,
                     const std::vector<TaskTableRow_> &rows) {
  const std::string table = BuildTaskTableText_(rows);
  if (table.empty()) {
    return;
  }
  prompt_io_manager.Print(table);
}

struct TaskListSnapshot_ {
  std::vector<TaskTableRow_> rows = {};
  bool has_conducting = false;
};

TaskListSnapshot_ BuildTaskListSnapshot_(
    AMApplication::transfer::TransferAppService &transfer_app_service,
    const TransferTaskListArg &arg, int64_t speed_window_ms) {
  TaskListSnapshot_ snapshot = {};
  std::unordered_map<TaskID, std::shared_ptr<TaskInfo>> tasks = {};

  const auto add_tasks = [&tasks](const auto &map_data) {
    for (const auto &[id, task_info] : map_data) {
      if (id == 0 || !task_info) {
        continue;
      }
      tasks.emplace(id, task_info);
    }
  };
  add_tasks(transfer_app_service.GetAllActiveTasks());
  add_tasks(transfer_app_service.GetPausedTasks());
  add_tasks(transfer_app_service.GetFinishedTasks());

  std::vector<TaskID> ids = {};
  ids.reserve(tasks.size());
  for (const auto &[id, _] : tasks) {
    ids.push_back(id);
  }
  std::sort(ids.begin(), ids.end());

  const bool has_filter =
      arg.pending || arg.suspend || arg.finished || arg.conducting;
  snapshot.rows.reserve(ids.size());
  for (const auto id : ids) {
    auto it = tasks.find(id);
    if (it == tasks.end() || !it->second) {
      continue;
    }
    const auto status = it->second->GetStatus();
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
    snapshot.rows.push_back(BuildTaskTableRow_(it->second, speed_window_ms));
    if (status == AMDomain::transfer::TaskStatus::Conducting) {
      snapshot.has_conducting = true;
    }
  }
  return snapshot;
}

TaskInspectSnapshot_
BuildTaskInspectSnapshot_(const std::shared_ptr<TaskInfo> &task_info,
                          bool include_sets, bool include_entries,
                          int64_t speed_window_ms) {
  TaskInspectSnapshot_ snapshot = {};
  if (!task_info) {
    return snapshot;
  }

  snapshot.id = task_info->id;
  snapshot.status = task_info->GetStatus();
  snapshot.intent = task_info->GetIntent();
  snapshot.result = task_info->GetResult();

  snapshot.submit_time_s =
      task_info->Time.submit.load(std::memory_order_relaxed);
  snapshot.start_time_s = task_info->Time.start.load(std::memory_order_relaxed);
  snapshot.finish_time_s =
      task_info->Time.finish.load(std::memory_order_relaxed);
  snapshot.elapsed_ms = ResolveElapsedMs_(task_info);

  snapshot.total = task_info->Size.total.load(std::memory_order_relaxed);
  snapshot.transferred =
      task_info->Size.transferred.load(std::memory_order_relaxed);
  snapshot.finished_files =
      task_info->Size.finished_filenum.load(std::memory_order_relaxed);
  snapshot.total_files =
      task_info->Size.filenum.load(std::memory_order_relaxed);
  snapshot.current_task_index =
      task_info->Size.cur_task.load(std::memory_order_relaxed);
  snapshot.current_task_transferred =
      task_info->Size.cur_task_transferred.load(std::memory_order_relaxed);
  snapshot.progress_percent = ResolveTaskProgressPercent_(task_info);
  snapshot.speed_bps = task_info->GetSpeedBytesPerSecond(speed_window_ms);

  snapshot.interrupted = task_info->IsInterrupted();
  snapshot.timeout = task_info->Core.control.IsTimeout();
  snapshot.timeout_remaining_ms = task_info->Core.control.RemainingTimeMs();
  snapshot.current_task = task_info->GetCurrentTaskSnapshot();
  if (snapshot.current_task.has_value()) {
    snapshot.source_display =
        AMStr::fmt("{}:{}", DisplayHost_(snapshot.current_task->src_host),
                   NormalizePath_(snapshot.current_task->src));
    snapshot.destination_display =
        AMStr::fmt("{}:{}", DisplayHost_(snapshot.current_task->dst_host),
                   NormalizePath_(snapshot.current_task->dst));
  } else if (task_info->Set.transfer_sets &&
             !task_info->Set.transfer_sets->empty()) {
    const auto &set = task_info->Set.transfer_sets->front();
    snapshot.destination_display = AMStr::fmt(
        "{}:{}", DisplayHost_(set.dst.nickname), NormalizePath_(set.dst.path));
    if (!set.srcs.empty()) {
      snapshot.source_display =
          AMStr::fmt("{}:{}", DisplayHost_(set.srcs.front().nickname),
                     NormalizePath_(set.srcs.front().path));
    }
  }

  if (include_sets) {
    auto sets = task_info->Set.transfer_sets;
    if (sets) {
      snapshot.sets.reserve(sets->size());
      for (const auto &set : *sets) {
        TaskInspectSetSnapshot_ item = {};
        item.dst = set.dst;
        item.clone = set.clone;
        item.mkdir = set.mkdir;
        item.overwrite = set.overwrite;
        item.ignore_special_file = set.ignore_special_file;
        item.resume = set.resume;
        item.srcs = set.srcs;
        snapshot.sets.push_back(std::move(item));
      }
    }
  }

  if (include_entries) {
    auto collect_entries = [&snapshot](const std::vector<TransferTask> &tasks,
                                       size_t *index_seed) -> void {
      for (const auto &entry : tasks) {
        TaskInspectEntrySnapshot_ item = {};
        item.index = (*index_seed)++;
        item.type = entry.path_type;
        item.src_host = entry.src_host;
        item.src = entry.src;
        item.dst_host = entry.dst_host;
        item.dst = entry.dst;
        item.size = entry.size;
        item.transferred = entry.transferred;
        item.overwrite = entry.overwrite;
        item.finished = entry.IsFinished;
        item.result = entry.rcm;
        snapshot.entries.push_back(std::move(item));
      }
    };

    size_t index_seed = 1;
    const auto dir_tasks = task_info->GetDirTasksSnapshot();
    const auto file_tasks = task_info->GetFileTasksSnapshot();
    snapshot.entries.reserve(dir_tasks.size() + file_tasks.size());
    collect_entries(dir_tasks, &index_seed);
    collect_entries(file_tasks, &index_seed);
  }

  return snapshot;
}

void PrintTaskInspectSummary_(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    const TaskInspectSnapshot_ &snapshot) {
  const auto state_view = BuildInspectStateView_(snapshot);
  prompt_io_manager.FmtPrint("[Task {}] {} {}", snapshot.id, state_view.icon,
                             state_view.text);
  prompt_io_manager.Print("----------------------------------------");
  prompt_io_manager.FmtPrint("Progress     : {}% ({} / {})",
                             std::to_string(snapshot.progress_percent),
                             AMStr::FormatSize(snapshot.transferred),
                             AMStr::FormatSize(snapshot.total));
  prompt_io_manager.FmtPrint("Files        : {} / {}",
                             std::to_string(snapshot.finished_files),
                             std::to_string(snapshot.total_files));
  prompt_io_manager.FmtPrint(
      "Speed        : {}",
      snapshot.speed_bps > 0.0
          ? AMStr::Strip(AMStr::FormatSpeed(snapshot.speed_bps, 3, 1, 0, false))
          : std::string("-"));
  prompt_io_manager.FmtPrint("Status       : {}", state_view.text);
  prompt_io_manager.FmtPrint("Intent       : {}",
                             IntentTextLocal_(snapshot.intent));

  if (!snapshot.source_display.empty()) {
    prompt_io_manager.Print("");
    prompt_io_manager.FmtPrint("Source       : {}", snapshot.source_display);
    prompt_io_manager.FmtPrint("Destination  : {}",
                               snapshot.destination_display);
  }

  if (snapshot.current_task.has_value()) {
    const auto &current = *snapshot.current_task;
    const int file_progress =
        current.size == 0
            ? 0
            : static_cast<int>(std::clamp<size_t>(
                  (current.transferred * 100) / current.size, 0, 100));
    prompt_io_manager.Print("");
    prompt_io_manager.Print("Current File :");
    prompt_io_manager.FmtPrint("  file       : {}",
                               NormalizePath_(current.src));
    prompt_io_manager.FmtPrint(
        "  progress   : {} / {} ({}%)", AMStr::FormatSize(current.transferred),
        AMStr::FormatSize(current.size), std::to_string(file_progress));
    prompt_io_manager.FmtPrint("  from       : {}",
                               DisplayHost_(current.src_host));
    prompt_io_manager.FmtPrint("  to         : {}",
                               DisplayHost_(current.dst_host));
  }

  prompt_io_manager.Print("");
  prompt_io_manager.Print("Time :");
  prompt_io_manager.FmtPrint("  submit     : {}",
                             FormatClockTimeLocal_(snapshot.submit_time_s));
  prompt_io_manager.FmtPrint("  start      : {}",
                             FormatClockTimeLocal_(snapshot.start_time_s));
  if (snapshot.finish_time_s > 0.0) {
    prompt_io_manager.FmtPrint("  finish     : {}",
                               FormatClockTimeLocal_(snapshot.finish_time_s));
  }
  prompt_io_manager.FmtPrint("  elapsed    : {}",
                             FormatElapsedMs_(snapshot.elapsed_ms));

  if (snapshot.result.code != EC::Success &&
      snapshot.status == AMDomain::transfer::TaskStatus::Finished) {
    prompt_io_manager.Print("");
    prompt_io_manager.FmtPrint("Error        : {}", snapshot.result.msg());
  }
}

void PrintTaskInspectSets_(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    const TaskInspectSnapshot_ &snapshot) {
  prompt_io_manager.Print("");
  prompt_io_manager.Print("Transfer Sets:");
  if (snapshot.sets.empty()) {
    prompt_io_manager.Print("  (none)");
    return;
  }
  size_t index = 1;
  for (const auto &set : snapshot.sets) {
    prompt_io_manager.FmtPrint(
        "  [{}] dst {}@{} | clone={} mkdir={} overwrite={} ignore_special={} "
        "resume={}",
        std::to_string(index++), DisplayHost_(set.dst.nickname),
        NormalizePath_(set.dst.path), set.clone ? "true" : "false",
        set.mkdir ? "true" : "false", set.overwrite ? "true" : "false",
        set.ignore_special_file ? "true" : "false",
        set.resume ? "true" : "false");
    if (set.srcs.empty()) {
      prompt_io_manager.Print("      src (none)");
      continue;
    }
    for (const auto &src : set.srcs) {
      prompt_io_manager.FmtPrint("      src {}@{}", DisplayHost_(src.nickname),
                                 NormalizePath_(src.path));
    }
  }
}

void PrintTaskInspectEntries_(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    const TaskInspectSnapshot_ &snapshot) {
  prompt_io_manager.Print("");
  prompt_io_manager.Print("Entries:");
  if (snapshot.entries.empty()) {
    prompt_io_manager.Print("  (none)");
    return;
  }

  std::vector<const TaskInspectEntrySnapshot_ *> ordered = {};
  ordered.reserve(snapshot.entries.size());
  for (const auto &entry : snapshot.entries) {
    if (entry.result.has_value() && entry.result->code != EC::Success) {
      ordered.push_back(&entry);
    }
  }
  for (const auto &entry : snapshot.entries) {
    if (!entry.result.has_value() || entry.result->code == EC::Success) {
      ordered.push_back(&entry);
    }
  }

  struct EntryRow_ {
    std::string idx = {};
    std::string type = {};
    std::string src = {};
    std::string dst = {};
    std::string size = {};
    std::string xfer = {};
    std::string result = {};
    std::string error = {};
  };

  std::vector<EntryRow_> rows = {};
  rows.reserve(ordered.size());
  for (const auto *entry : ordered) {
    if (!entry) {
      continue;
    }
    EntryRow_ row = {};
    row.idx = std::to_string(entry->index);
    row.type = PathTypeTextLocal_(entry->type);
    row.src = AMStr::fmt("[{}] {}", DisplayHost_(entry->src_host),
                         NormalizePath_(entry->src));
    row.dst = AMStr::fmt("[{}] {}", DisplayHost_(entry->dst_host),
                         NormalizePath_(entry->dst));
    row.size = AMStr::FormatSize(entry->size);
    row.xfer = AMStr::FormatSize(entry->transferred);
    row.result = EntryResultCodeText_(entry->result);
    row.error = EntryResultMessageText_(entry->result);
    rows.push_back(std::move(row));
  }

  constexpr size_t kColCount = 7;
  const std::array<std::string, kColCount> headers = {
      "IDX", "TYPE", "SRC", "DST", "SIZE", "XFER", "RESULT"};
  std::array<size_t, kColCount> widths = {headers[0].size(), headers[1].size(),
                                          headers[2].size(), headers[3].size(),
                                          headers[4].size(), headers[5].size(),
                                          headers[6].size()};
  for (const auto &row : rows) {
    widths[0] = std::max(widths[0], row.idx.size());
    widths[1] = std::max(widths[1], row.type.size());
    widths[2] = std::max(widths[2], row.src.size());
    widths[3] = std::max(widths[3], row.dst.size());
    widths[4] = std::max(widths[4], row.size.size());
    widths[5] = std::max(widths[5], row.xfer.size());
    widths[6] = std::max(widths[6], row.result.size());
  }
  const size_t gap = 2;
  const size_t total_width = widths[0] + widths[1] + widths[2] + widths[3] +
                             widths[4] + widths[5] + widths[6] + gap * 6;

  prompt_io_manager.FmtPrint(
      "  {}{}{}{}{}{}{}{}{}{}{}{}{}",
      AMStr::PadRightAscii(headers[0], widths[0]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[1], widths[1]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[2], widths[2]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[3], widths[3]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[4], widths[4]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[5], widths[5]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[6], widths[6]));
  prompt_io_manager.Print(AMStr::fmt("  {}", std::string(total_width, '-')));

  for (const auto &row : rows) {
    prompt_io_manager.FmtPrint(
        "  {}{}{}{}{}{}{}{}{}{}{}{}{}",
        AMStr::PadRightAscii(row.idx, widths[0]), std::string(gap, ' '),
        AMStr::PadRightAscii(row.type, widths[1]), std::string(gap, ' '),
        AMStr::PadRightAscii(row.src, widths[2]), std::string(gap, ' '),
        AMStr::PadRightAscii(row.dst, widths[3]), std::string(gap, ' '),
        AMStr::PadRightAscii(row.size, widths[4]), std::string(gap, ' '),
        AMStr::PadRightAscii(row.xfer, widths[5]), std::string(gap, ' '),
        AMStr::PadRightAscii(row.result, widths[6]));
    if (row.result != "Success" && row.result != "Pending" &&
        !row.error.empty()) {
      prompt_io_manager.FmtPrint("    error: {}", row.error);
    }
  }
}

bool PrintWaitTaskResultSummary_(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
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
    if (EntryResultIsSuccess_(entry.rcm)) {
      prompt_io_manager.FmtPrint("✅ {}/{}",
                                 AMStr::FormatSize(entry.transferred),
                                 AMStr::FormatSize(entry.size));
      return true;
    }
    const std::string line_code = EntryResultCodeText_(entry.rcm);
    const std::string err_msg = EntryResultMessageText_(entry.rcm);
    prompt_io_manager.FmtPrint("❌ {} {}/{}  {}", line_code,
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
      if (EntryResultIsSuccess_(entry.rcm)) {
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
      const std::string err_code = EntryResultCodeText_(entry.rcm);
      const std::string err_msg = EntryResultMessageText_(entry.rcm);
      prompt_io_manager.FmtPrint("    {}: {}", err_code, err_msg);
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
    AMApplication::filesystem::FileSystemAppService &filesystem_service,
    AMApplication::transfer::TransferAppService &transfer_service,
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    std::function<ControlComponent(AMDomain::client::amf)>
        control_component_factory,
    AMInterface::style::AMStyleService *style_service,
    int transfer_refresh_interval_ms)
    : filesystem_service_(filesystem_service),
      prompt_io_manager_(prompt_io_manager),
      transfer_app_service_(transfer_service), style_service_(style_service),
      transfer_refresh_interval_ms_(transfer_refresh_interval_ms) {
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

ControlComponent TransferInterfaceService::ResolveControl_(
    const std::optional<ControlComponent> &component, int timeout_ms) const {
  if (component.has_value()) {
    return *component;
  }
  if (timeout_ms > 0) {
    return {default_control_token_, timeout_ms};
  }
  return {default_control_token_, 0};
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
        entry.overwrite ? "true" : "false", EntryResultCodeText_(entry.rcm),
        EntryResultMessageText_(entry.rcm));
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
        entry.overwrite ? "true" : "false", EntryResultCodeText_(entry.rcm),
        EntryResultMessageText_(entry.rcm));
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
    const TransferRunArg &arg, const ControlComponent &control,
    std::shared_ptr<TaskInfo> *out_task_info, std::vector<ECM> *warnings,
    const std::function<void(const std::string &)> &stage_reporter) const {
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

  const size_t total_sets = arg.transfer_sets.size();
  size_t set_index = 0;
  for (const auto &set : arg.transfer_sets) {
    ++set_index;
    ReportTransferSubStage_(
        stage_reporter,
        AMStr::fmt("set {}/{}: resolve destination", set_index, total_sets));
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted before task generation");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "",
                 "Timeout before task generation");
    }

    auto resolved_dst =
        transfer_app_service_.ResolveTransferDst(set.dst, &clients, control);
    if (!(resolved_dst.rcm)) {
      return resolved_dst.rcm;
    }

    ReportTransferSubStage_(
        stage_reporter,
        AMStr::fmt("set {}/{}: resolve source", set_index, total_sets));
    auto resolved_src = transfer_app_service_.ResolveTransferSrc(
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

    AMApplication::transfer::BuildTransferTaskOptions options = {};
    options.clone = set.clone;
    options.mkdir = set.mkdir;
    options.ignore_special_file = set.ignore_special_file;
    options.resume = set.resume;

    ReportTransferSubStage_(stage_reporter, AMStr::fmt("set {}/{}: build tasks",
                                                       set_index, total_sets));
    auto build_result = transfer_app_service_.BuildTransferTasks(
        resolved_src.data, resolved_dst.data, control, options);
    if (!(build_result.rcm)) {
      return build_result.rcm;
    }

    if (!set.overwrite) {
      ReportTransferSubStage_(
          stage_reporter,
          AMStr::fmt("set {}/{}: check overwrite", set_index, total_sets));
      const std::vector<std::string> overwrite_targets =
          CollectOverwriteTargets_(build_result.data.file_tasks);
      if (!overwrite_targets.empty()) {
        if (arg.confirm_policy == TransferConfirmPolicy::DenyIfConfirmNeeded) {
          return Err(EC::ConfigCanceled, "", "",
                     "Transfer requires overwrite confirmation but confirm "
                     "policy denied");
        }
        if (arg.confirm_policy == TransferConfirmPolicy::RequireConfirm) {
          prompt_io_manager_.FmtPrint(
              "Destination file exists and will be overwritten:");
          for (const auto &target : overwrite_targets) {
            prompt_io_manager_.FmtPrint("  {}", target);
          }
          bool canceled = false;
          const bool accepted = prompt_io_manager_.PromptYesNo(
              "Continue and overwrite existing destination file(s)? (y/N): ",
              &canceled);
          if (!accepted || canceled) {
            return Err(EC::ConfigCanceled, "", "", "Transfer canceled by user");
          }
        }
      }
    }

    for (auto &task : build_result.data.dir_tasks) {
      task.overwrite = set.overwrite;
    }
    for (auto &task : build_result.data.file_tasks) {
      if (set.overwrite) {
        task.overwrite = true;
      }
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
        warnings->emplace_back(
            warning.rcm.code, "", "",
            AMStr::fmt("{} -> {}: {}", NormalizePath_(warning.src),
                       NormalizePath_(warning.dst), warning.rcm.msg()));
      }
    }
  }

  ReportTransferSubStage_(stage_reporter, "deduplicate task entries");
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

  ReportTransferSubStage_(stage_reporter, "finalize task payload");
  auto task_info = std::make_shared<TaskInfo>();
  task_info->id = BuildTaskId_();
  task_info->Set.quiet = arg.quiet;
  int task_timeout_ms = 0;
  if (const auto remain_ms = control.RemainingTimeMs(); remain_ms.has_value()) {
    task_timeout_ms = static_cast<int>(*remain_ms);
  }
  auto task_control_token = CreateInterruptControl();
  if (!task_control_token) {
    return Err(EC::InvalidHandle, "", "",
               "failed to create transfer task control token");
  }
  task_info->Core.control =
      ControlComponent(task_control_token, task_timeout_ms);
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
    const ControlComponent &control) const {
  if (!task_info) {
    return {EC::InvalidArg, "", "", "TaskInfo is null"};
  }

  const bool show_progress = !task_info->Set.quiet;
  const int refresh_ms = ResolveTransferProgressRefreshMs_(
      style_service_, transfer_refresh_interval_ms_);

  struct ScopedRefresh_ {
    AMInterface::prompt::PromptIOManager *prompt = nullptr;
    bool active = false;
    ~ScopedRefresh_() {
      if (active && prompt != nullptr) {
        prompt->RefreshEnd();
      }
    }
  } scoped_refresh(&prompt_io_manager_, false);

  struct ScopedCursor_ {
    AMInterface::prompt::PromptIOManager *prompt = nullptr;
    bool hidden = false;
    ~ScopedCursor_() {
      if (hidden && prompt != nullptr) {
        prompt->SetCursorVisible(true);
      }
    }
  } scoped_cursor(&prompt_io_manager_, false);

  auto build_bar =
      [this, &task_info]() -> std::unique_ptr<AMBar::BaseProgressBar> {
    const auto total_size = static_cast<int64_t>(
        task_info->Size.total.load(std::memory_order_relaxed));
    const std::string prefix = BuildTransferProgressPrefix_(task_info);
    if (style_service_ != nullptr) {
      return style_service_->CreateProgressBar(total_size, prefix);
    }
    auto bar = std::make_unique<AMBar::BaseProgressBar>();
    bar->SetTotal(total_size);
    return bar;
  };

  auto progress_bar = build_bar();
  if (!progress_bar) {
    return Err(EC::InvalidHandle, "transfer.wait",
               AMStr::fmt("task:{}", task_info ? task_info->id : 0),
               "Progress bar is null");
  }
  std::string final_line = "";
  std::string last_progress_line = "";
  AMBar::BaseProgressBar::RenderArgs last_render_args = {};
  auto is_generic_task_label = [](const std::string &s) -> bool {
    return s.starts_with("Task ");
  };
  auto render_progress_line = [&]() -> std::string {
    AMBar::BaseProgressBar::RenderArgs args = BuildTransferProgressRenderArgs_(
        task_info, ResolveTaskSpeedWindowMs_(style_service_));
    if (is_generic_task_label(args.filename) &&
        !last_render_args.filename.empty() &&
        !is_generic_task_label(last_render_args.filename)) {
      args.src_host = last_render_args.src_host;
      args.dst_host = last_render_args.dst_host;
      args.filename = last_render_args.filename;
    }
    args.total = static_cast<int64_t>(
        task_info->Size.total.load(std::memory_order_relaxed));
    const int64_t transferred_now = static_cast<int64_t>(
        task_info->Size.transferred.load(std::memory_order_relaxed));
    args.transferred = transferred_now;
    last_render_args = args;
    return progress_bar->Render(args);
  };
  if (show_progress) {
    progress_bar->StartTraceWithElapsedMs(ResolveElapsedMs_(task_info));
    prompt_io_manager_.SetCursorVisible(false);
    scoped_cursor.hidden = true;
    prompt_io_manager_.RefreshBegin();
    scoped_refresh.active = true;
  }

  auto finalize_and_return = [&](ECM rcm) -> ECM {
    if (show_progress) {
      const int64_t total_now = static_cast<int64_t>(
          task_info->Size.total.load(std::memory_order_relaxed));
      int64_t transferred_now = static_cast<int64_t>(
          task_info->Size.transferred.load(std::memory_order_relaxed));
      if (rcm.code == EC::Success) {
        transferred_now = total_now;
      }
      std::string final_prefix = last_render_args.filename;
      if (final_prefix.empty() || is_generic_task_label(final_prefix)) {
        auto latest_args = BuildTransferProgressRenderArgs_(
            task_info, ResolveTaskSpeedWindowMs_(style_service_));
        if (!latest_args.filename.empty()) {
          final_prefix = latest_args.filename;
        }
      }
      AMBar::BaseProgressBar::RenderArgs final_args = last_render_args;
      final_args.filename = final_prefix;
      final_args.total = total_now;
      final_args.transferred = transferred_now;
      final_args.elapsed_ms = ResolveElapsedMs_(task_info);
      final_args.speed_bps = task_info->GetSpeedBytesPerSecond(
          ResolveTaskSpeedWindowMs_(style_service_));
      const std::string candidate_line = progress_bar->Render(final_args);
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

  struct CompletionWakeupState_ {
    std::counting_semaphore<8> semaphore{0};
    std::atomic<bool> active{true};
  };
  auto completion_wakeup = std::make_shared<CompletionWakeupState_>();
  const std::weak_ptr<CompletionWakeupState_> completion_wakeup_weak =
      completion_wakeup;
  const size_t completion_token =
      task_info->RegisterCompletionWakeup([completion_wakeup_weak]() {
        auto state = completion_wakeup_weak.lock();
        if (!state || !state->active.load(std::memory_order_acquire)) {
          return;
        }
        state->semaphore.release();
      });
  struct ScopedCompletionWakeup_ {
    std::shared_ptr<CompletionWakeupState_> state = nullptr;
    TaskInfo *task_info = nullptr;
    size_t token = 0;
    ~ScopedCompletionWakeup_() {
      if (state) {
        state->active.store(false, std::memory_order_release);
      }
      if (task_info != nullptr && token != 0) {
        (void)task_info->UnregisterCompletionWakeup(token);
      }
    }
  } scoped_completion_wakeup{completion_wakeup, task_info.get(),
                             completion_token};

  const auto control_token = control.ControlToken();
  const AMDomain::client::InterruptWakeupSafeGuard interrupt_wakeup_guard(
      control_token, [completion_wakeup_weak]() {
        auto state = completion_wakeup_weak.lock();
        if (!state || !state->active.load(std::memory_order_acquire)) {
          return;
        }
        state->semaphore.release();
      });

  auto resolve_wait_ms = [&]() -> int {
    if (show_progress) {
      return std::max(1, refresh_ms);
    }
    if (const auto remain_ms = control.RemainingTimeMs();
        remain_ms.has_value()) {
      return static_cast<int>(
          std::max<size_t>(1, std::min<size_t>(*remain_ms, 2000)));
    }
    return 2000;
  };

  while (true) {
    const auto status = task_info->GetStatus();
    if (status == AMDomain::transfer::TaskStatus::Finished) {
      const ECM result = task_info->GetResult();
      return finalize_and_return(result);
    }

    if (control.IsInterrupted()) {
      (void)transfer_app_service_.Terminate(task_info->id, 1000);
      return finalize_and_return(
          Err(EC::Terminate, "", "", "Task is terminated by user"));
    }
    if (control.IsTimeout()) {
      (void)transfer_app_service_.Terminate(task_info->id, 1000);
      return finalize_and_return(
          Err(EC::OperationTimeout, "", "", "Task timeout"));
    }

    if (show_progress) {
      last_progress_line = render_progress_line();
      prompt_io_manager_.RefreshRender({last_progress_line});
    }

    const int wait_ms = resolve_wait_ms();
    (void)completion_wakeup->semaphore.try_acquire_for(
        std::chrono::milliseconds(std::max(1, wait_ms)));
  }
}

std::shared_ptr<AMDomain::transfer::TaskInfo>
TransferInterfaceService::FindTask_(TaskID task_id) const {
  if (task_id == 0) {
    return nullptr;
  }
  return transfer_app_service_.FindTask(task_id);
}

ECM TransferInterfaceService::Transfer(
    const TransferRunArg &arg,
    const std::optional<ControlComponent> &component) const {
  const auto fail = [this](const ECM &rcm) -> ECM {
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
    return rcm;
  };

  const ControlComponent control = ResolveControl_(component, arg.timeout_ms);
  if (const auto &token = control.ControlToken(); token) {
    token->ClearInterrupt();
  }
  const bool show_report = arg.verbose && !arg.quiet;
  constexpr int kTransferStageCount = 5;
  PrintTransferStage_(prompt_io_manager_, show_report, 1, kTransferStageCount,
                      "Search wildcard sources");
  std::vector<WildcardConfirmRequest> confirm_requests = {};
  for (const auto &set : arg.transfer_sets) {
    for (const auto &src : set.srcs) {
      const bool has_wildcard =
          AMDomain::filesystem::service::HasWildcard(src.path);
      if (!has_wildcard) {
        continue;
      }
      auto find_result =
          filesystem_service_.find(src, SearchType::All, control);
      if (!(find_result.rcm)) {
        return fail(find_result.rcm);
      }
      confirm_requests.push_back(
          {std::move(find_result.data), src.nickname, set.dst.nickname});
    }
  }

  PrintTransferStage_(prompt_io_manager_, show_report, 2, kTransferStageCount,
                      "Confirm wildcard matches");
  ECM confirm_rcm = ConfirmWildcard_(confirm_requests, arg.confirm_policy);
  if (!(confirm_rcm)) {
    return fail(confirm_rcm);
  }

  PrintTransferStage_(prompt_io_manager_, show_report, 3, kTransferStageCount,
                      "Collect clients and resolve paths");
  std::vector<ECM> warnings = {};
  std::shared_ptr<TaskInfo> task_info = nullptr;
  ECM build_rcm = BuildTaskInfo_(arg, control, &task_info, &warnings,
                                 [this, show_report](const std::string &name) {
                                   if (!show_report) {
                                     return;
                                   }
                                   prompt_io_manager_.FmtPrint("  - {}", name);
                                 });
  for (const auto &warning : warnings) {
    prompt_io_manager_.ErrorFormat(warning);
  }
  if (!(build_rcm)) {
    return fail(build_rcm);
  }
  if (!task_info) {
    return fail(
        {EC::InvalidHandle, "", "", "BuildTaskInfo returned null task"});
  }

  PrintTransferStage_(prompt_io_manager_, show_report, 4, kTransferStageCount,
                      "Submit transfer task");
  const ECM submit_rcm = transfer_app_service_.Submit(task_info);
  if (!(submit_rcm)) {
    task_info->Core.clients.ReleaseAll();
    return fail(submit_rcm);
  }
  if (arg.run_async) {
    prompt_io_manager_.FmtPrint("Submitted task {}", task_info->id);
    return OK;
  }
  PrintTransferStage_(prompt_io_manager_, show_report, 5, kTransferStageCount,
                      "Run and wait task");
  return WaitTask_(task_info, control);
}

ECM TransferInterfaceService::HttpGet(
    const HttpGetArg &arg,
    const std::optional<ControlComponent> &component) const {
  const auto fail = [this](const ECM &rcm) -> ECM {
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
    return rcm;
  };
  const ControlComponent control = ResolveControl_(component, arg.timeout_ms);
  if (const auto &token = control.ControlToken(); token) {
    token->ClearInterrupt();
  }

  const std::string src_url = AMStr::Strip(arg.src_url);
  if (src_url.empty()) {
    return fail(
        Err(EC::InvalidArg, "wget", "<src_url>", "Source URL is empty"));
  }
  if (!AMUrl::IsHttpUrl(src_url)) {
    return fail(Err(EC::InvalidArg, "wget", src_url,
                    "Only http:// and https:// are supported"));
  }
  if (AMUrl::IsDirectoryUrl(src_url)) {
    return fail(Err(EC::NotAFile, "wget", src_url,
                    "HTTP directory URL is unsupported"));
  }

  const std::string suggested_name = [&]() -> std::string {
    const std::string name = AMStr::Strip(AMUrl::Basename(src_url));
    return name.empty() ? std::string("download.bin") : name;
  }();

  auto plan_result = transfer_app_service_.BuildHttpDownloadPlan(
      arg.dst_target, suggested_name, control);
  if (!(plan_result.rcm)) {
    return fail(plan_result.rcm);
  }
  const auto &plan = plan_result.data;
  if (!plan.resolved_target.client) {
    return fail(
        Err(EC::InvalidHandle, "wget", src_url, "Destination client is null"));
  }
  if (plan.final_target.is_wildcard) {
    return fail(Err(EC::InvalidArg, "wget", plan.final_target.path,
                    "Destination wildcard is invalid"));
  }

  const bool dst_exists = plan.dst_info.has_value();
  if (dst_exists && !arg.overwrite) {
    if (arg.confirm_policy == TransferConfirmPolicy::DenyIfConfirmNeeded) {
      return fail(Err(EC::ConfigCanceled, "wget", plan.final_target.path,
                      "Overwrite requires confirmation but denied"));
    }
    if (arg.confirm_policy == TransferConfirmPolicy::RequireConfirm) {
      bool canceled = false;
      const bool confirmed = prompt_io_manager_.PromptYesNo(
          AMStr::fmt("Destination exists: {}. Overwrite? (y/N): ",
                     plan.final_target.path),
          &canceled);
      if (!confirmed || canceled) {
        return fail(Err(EC::ConfigCanceled, "wget", plan.final_target.path,
                        "Overwrite canceled by user"));
      }
    }
  }

  std::string effective_proxy = arg.proxy;
  if (AMUrl::IsHttpsUrl(src_url) && !AMStr::Strip(arg.https_proxy).empty()) {
    effective_proxy = arg.https_proxy;
  }
  int max_redirect = arg.redirect_times;
  if (max_redirect < 0) {
    max_redirect = filesystem_service_.GetInitArg().wget_max_redirect;
  }
  max_redirect = std::max(0, max_redirect);
  std::string request_username = AMStr::Strip(arg.username);
  if (request_username.empty()) {
    request_username = AMUrl::ExtractUsername(src_url);
  }
  std::string request_password = arg.password;
  if (request_password.empty()) {
    request_password = AMUrl::ExtractPassword(src_url);
  }
  auto [http_client_rcm, http_client] =
      AMInfra::client::HTTP::BuildTransientHttpSourceClient(
          src_url, "", request_username, request_password);
  if (!(http_client_rcm) || !http_client) {
    return fail(http_client_rcm);
  }

  auto *http_io = dynamic_cast<AMInfra::client::HTTP::AMHTTPIOCore *>(
      &http_client->IOPort());
  if (http_io == nullptr) {
    return fail(Err(EC::InvalidHandle, "wget", src_url,
                    "HTTP IO port implementation mismatch"));
  }
  WriteTransientHttpRuntimeMetadata_(*http_client, effective_proxy,
                                     max_redirect, arg.bear_token);
  auto redirect_result = http_io->FollowRedirects(src_url, control);
  if (!redirect_result.rcm) {
    return fail(redirect_result.rcm);
  }
  const std::string effective_src_url =
      AMStr::Strip(redirect_result.data).empty() ? src_url
                                                 : redirect_result.data;

  auto src_stat =
      http_client->IOPort().stat({effective_src_url, false}, control);
  if (!(src_stat.rcm)) {
    return fail(src_stat.rcm);
  }
  if (src_stat.data.info.type != PathType::FILE) {
    return fail(Err(EC::NotAFile, "wget", effective_src_url,
                    "HTTP source is not a file"));
  }

  if (src_stat.data.info.size == 0) {
    auto redirect_chain = http_io->ResolveRedirectChain(src_url, -1, control);
    if (!(redirect_chain.rcm)) {
      return fail(redirect_chain.rcm);
    }
    if (redirect_chain.data.content_length.has_value() &&
        *redirect_chain.data.content_length > 0) {
      src_stat.data.info.size =
          static_cast<size_t>(*redirect_chain.data.content_length);
    }
  }

  size_t resume_offset = 0;
  if (arg.resume && dst_exists) {
    resume_offset = plan.dst_info->size;
    if (src_stat.data.info.size > 0 &&
        resume_offset >= src_stat.data.info.size) {
      resume_offset = 0;
    } else {
      auto resume_probe = http_io->ProbeResumeSupport(effective_src_url,
                                                      resume_offset, control);
      if (resume_probe.rcm.code == EC::Terminate ||
          resume_probe.rcm.code == EC::OperationTimeout) {
        return fail(resume_probe.rcm);
      }
      if (!(resume_probe.rcm) || !resume_probe.data) {
        resume_offset = 0;
      }
    }
  }

  auto task_info = std::make_shared<TaskInfo>();
  task_info->id = BuildTaskId_();
  task_info->Set.quiet = arg.quiet;
  int task_timeout_ms = 0;
  if (const auto remain_ms = control.RemainingTimeMs(); remain_ms.has_value()) {
    task_timeout_ms = static_cast<int>(*remain_ms);
  }
  auto task_control_token = CreateInterruptControl();
  if (!task_control_token) {
    return fail(Err(EC::InvalidHandle, "wget", src_url,
                    "failed to create transfer task control token"));
  }
  task_info->Core.control =
      ControlComponent(task_control_token, task_timeout_ms);

  AMDomain::transfer::TransferTask file_task = {};
  file_task.src = effective_src_url;
  file_task.src_host = http_client->ConfigPort().GetNickname();
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
    return fail(add_src_rcm);
  }
  const ECM add_dst_rcm = task_info->Core.clients.AddDstClient(
      file_task.dst_host, plan.resolved_target.client);
  if (!(add_dst_rcm)) {
    task_info->Core.clients.ReleaseAll();
    return fail(add_dst_rcm);
  }
  task_info->Core.nicknames = {file_task.src_host, file_task.dst_host};
  task_info->CalTotalSize(true);
  task_info->CalFileNum(true);

  const ECM submit_rcm = transfer_app_service_.Submit(task_info);
  if (!(submit_rcm)) {
    task_info->Core.clients.ReleaseAll();
    return fail(submit_rcm);
  }
  if (arg.run_async) {
    prompt_io_manager_.FmtPrint("Submitted task {}", task_info->id);
    return OK;
  }
  return WaitTask_(task_info, control);
}

ECM TransferInterfaceService::TaskList(const TransferTaskListArg &arg) const {
  const int64_t speed_window_ms = ResolveTaskSpeedWindowMs_(style_service_);
  auto snapshot =
      BuildTaskListSnapshot_(transfer_app_service_, arg, speed_window_ms);
  if (!snapshot.has_conducting) {
    if (snapshot.rows.empty()) {
      prompt_io_manager_.Print("No transfer task matched.");
      return OK;
    }
    PrintTaskTable_(prompt_io_manager_, snapshot.rows);
    return OK;
  }

  const int refresh_ms = ResolveTransferProgressRefreshMs_(
      style_service_, transfer_refresh_interval_ms_);
  struct ScopedRefresh_ {
    AMInterface::prompt::PromptIOManager *prompt = nullptr;
    bool active = false;
    ~ScopedRefresh_() {
      if (active && prompt != nullptr) {
        prompt->RefreshEnd();
      }
    }
  } scoped_refresh{&prompt_io_manager_, false};

  struct ScopedCursor_ {
    AMInterface::prompt::PromptIOManager *prompt = nullptr;
    bool hidden = false;
    ~ScopedCursor_() {
      if (hidden && prompt != nullptr) {
        prompt->SetCursorVisible(true);
      }
    }
  } scoped_cursor{&prompt_io_manager_, false};

  prompt_io_manager_.SetCursorVisible(false);
  scoped_cursor.hidden = true;
  prompt_io_manager_.RefreshBegin();
  scoped_refresh.active = true;

  const auto token = GetDefaultControlToken();
  constexpr int kInterruptPollSliceMs = 20;
  bool watch_canceled = false;
  std::string last_frame = {};
  while (true) {
    snapshot =
        BuildTaskListSnapshot_(transfer_app_service_, arg, speed_window_ms);
    last_frame = snapshot.rows.empty()
                     ? std::string("No transfer task matched.")
                     : BuildTaskTableText_(snapshot.rows);
    prompt_io_manager_.RefreshRender({last_frame});
    if (!snapshot.has_conducting) {
      break;
    }

    int remaining_ms = refresh_ms;
    while (remaining_ms > 0) {
      if (token && token->IsInterruptRequest()) {
        watch_canceled = true;
        break;
      }
      const int sleep_ms = std::min(remaining_ms, kInterruptPollSliceMs);
      std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
      remaining_ms -= sleep_ms;
    }
    if (watch_canceled) {
      break;
    }
  }

  scoped_refresh.active = false;
  prompt_io_manager_.RefreshEnd();
  if (!last_frame.empty()) {
    prompt_io_manager_.Print(last_frame);
  }
  if (scoped_cursor.hidden) {
    prompt_io_manager_.SetCursorVisible(true);
    scoped_cursor.hidden = false;
  }
  if (watch_canceled && token) {
    token->ClearInterrupt();
  }
  return OK;
}

ECM TransferInterfaceService::TaskShow(const TransferTaskShowArg &arg) const {
  if (arg.ids.empty()) {
    return TaskList({});
  }
  std::vector<TaskID> unique_ids = {};
  {
    std::unordered_set<TaskID> seen_ids = {};
    unique_ids.reserve(arg.ids.size());
    for (const auto id : arg.ids) {
      if (seen_ids.insert(id).second) {
        unique_ids.push_back(id);
      }
    }
  }

  std::vector<TaskID> missing_ids = {};
  std::vector<std::shared_ptr<TaskInfo>> non_conducting_tasks = {};
  std::vector<std::shared_ptr<TaskInfo>> conducting_tasks = {};
  for (const auto id : unique_ids) {
    if (id == 0) {
      missing_ids.push_back(id);
      continue;
    }
    auto task_info = FindTask_(id);
    if (!task_info) {
      missing_ids.push_back(id);
      continue;
    }
    if (task_info->GetStatus() == AMDomain::transfer::TaskStatus::Conducting) {
      conducting_tasks.push_back(std::move(task_info));
    } else {
      non_conducting_tasks.push_back(std::move(task_info));
    }
  }

  if (!missing_ids.empty()) {
    std::vector<std::string> ids_text = {};
    ids_text.reserve(missing_ids.size());
    for (const auto id : missing_ids) {
      ids_text.push_back(std::to_string(id));
    }
    prompt_io_manager_.ErrorFormat(
        Err(EC::TaskNotFound, "", "",
            AMStr::fmt("Task not found: {}", AMStr::join(ids_text, ", "))));
  }

  if (!non_conducting_tasks.empty()) {
    std::vector<TaskTableRow_> rows = {};
    rows.reserve(non_conducting_tasks.size());
    for (const auto &task_info : non_conducting_tasks) {
      rows.push_back(BuildTaskTableRow_(
          task_info, ResolveTaskSpeedWindowMs_(style_service_)));
    }
    PrintTaskTable_(prompt_io_manager_, rows);
  }

  if (!conducting_tasks.empty()) {
    const int refresh_ms = ResolveTransferProgressRefreshMs_(
        style_service_, transfer_refresh_interval_ms_);
    struct TaskWatchItem_ {
      std::shared_ptr<TaskInfo> task_info = nullptr;
      std::unique_ptr<AMBar::BaseProgressBar> bar = nullptr;
      std::optional<std::string> rendered_line = std::nullopt;
      AMBar::BaseProgressBar::RenderArgs last_render_args = {};
      bool frozen = false;
    };
    std::vector<TaskWatchItem_> watch_items = {};
    watch_items.reserve(conducting_tasks.size());
    auto make_bar = [this](const std::shared_ptr<TaskInfo> &task_info)
        -> std::unique_ptr<AMBar::BaseProgressBar> {
      const auto total_size = static_cast<int64_t>(
          task_info->Size.total.load(std::memory_order_relaxed));
      const std::string prefix = BuildTransferProgressPrefix_(task_info);
      if (style_service_ != nullptr) {
        auto bar = style_service_->CreateProgressBar(total_size, prefix);
        if (bar) {
          return bar;
        }
      }
      auto bar = std::make_unique<AMBar::BaseProgressBar>();
      bar->SetTotal(total_size);
      return bar;
    };
    for (const auto &task_info : conducting_tasks) {
      auto bar = make_bar(task_info);
      if (!bar) {
        continue;
      }
      bar->StartTraceWithElapsedMs(ResolveElapsedMs_(task_info));
      watch_items.push_back(
          {task_info, std::move(bar), std::nullopt, {}, false});
    }

    if (!watch_items.empty()) {
      struct ScopedRefresh_ {
        AMInterface::prompt::PromptIOManager *prompt = nullptr;
        bool active = false;
        ~ScopedRefresh_() {
          if (active && prompt != nullptr) {
            prompt->RefreshEnd();
          }
        }
      } scoped_refresh{&prompt_io_manager_, false};

      struct ScopedCursor_ {
        AMInterface::prompt::PromptIOManager *prompt = nullptr;
        bool hidden = false;
        ~ScopedCursor_() {
          if (hidden && prompt != nullptr) {
            prompt->SetCursorVisible(true);
          }
        }
      } scoped_cursor{&prompt_io_manager_, false};

      prompt_io_manager_.SetCursorVisible(false);
      scoped_cursor.hidden = true;
      prompt_io_manager_.RefreshBegin();
      scoped_refresh.active = true;

      const auto token = GetDefaultControlToken();
      constexpr int kInterruptPollSliceMs = 20;
      bool watch_canceled = false;
      auto is_generic_task_label = [](const std::string &s) -> bool {
        return s.starts_with("Task ");
      };
      while (true) {
        if (token && token->IsInterruptRequest()) {
          watch_canceled = true;
          break;
        }

        size_t frozen_count = 0;
        std::vector<std::optional<std::string>> lines(watch_items.size(),
                                                      std::nullopt);
        for (size_t i = 0; i < watch_items.size(); ++i) {
          auto &item = watch_items[i];
          if (item.frozen) {
            ++frozen_count;
            lines[i] = item.rendered_line;
            continue;
          }
          const auto status = item.task_info->GetStatus();
          if (status != AMDomain::transfer::TaskStatus::Conducting) {
            item.frozen = true;
            ++frozen_count;
            if (!item.rendered_line.has_value()) {
              AMBar::BaseProgressBar::RenderArgs args =
                  BuildTransferProgressRenderArgs_(
                      item.task_info,
                      ResolveTaskSpeedWindowMs_(style_service_));
              args.total = static_cast<int64_t>(
                  item.task_info->Size.total.load(std::memory_order_relaxed));
              args.transferred =
                  static_cast<int64_t>(item.task_info->Size.transferred.load(
                      std::memory_order_relaxed));
              item.last_render_args = args;
              item.rendered_line = item.bar->Render(args);
            }
            lines[i] = item.rendered_line;
            continue;
          }

          AMBar::BaseProgressBar::RenderArgs args =
              BuildTransferProgressRenderArgs_(
                  item.task_info, ResolveTaskSpeedWindowMs_(style_service_));
          if (is_generic_task_label(args.filename) &&
              !item.last_render_args.filename.empty() &&
              !is_generic_task_label(item.last_render_args.filename)) {
            args.src_host = item.last_render_args.src_host;
            args.dst_host = item.last_render_args.dst_host;
            args.filename = item.last_render_args.filename;
          }
          args.total = static_cast<int64_t>(
              item.task_info->Size.total.load(std::memory_order_relaxed));
          args.transferred = static_cast<int64_t>(
              item.task_info->Size.transferred.load(std::memory_order_relaxed));
          item.last_render_args = args;
          item.rendered_line = item.bar->Render(args);
          lines[i] = item.rendered_line;
        }
        prompt_io_manager_.RefreshRender(lines);
        if (frozen_count >= watch_items.size()) {
          break;
        }
        int remaining_ms = refresh_ms;
        while (remaining_ms > 0) {
          if (token && token->IsInterruptRequest()) {
            watch_canceled = true;
            break;
          }
          const int sleep_ms = std::min(remaining_ms, kInterruptPollSliceMs);
          std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
          remaining_ms -= sleep_ms;
        }
        if (watch_canceled) {
          break;
        }
      }

      scoped_refresh.active = false;
      prompt_io_manager_.RefreshEnd();
      for (const auto &item : watch_items) {
        if (item.rendered_line.has_value() && !item.rendered_line->empty()) {
          prompt_io_manager_.Print(*item.rendered_line);
        }
      }
      if (scoped_cursor.hidden) {
        prompt_io_manager_.SetCursorVisible(true);
        scoped_cursor.hidden = false;
      }
      if (watch_canceled) {
        if (token) {
          token->ClearInterrupt();
        }
        return OK;
      }
    }
  }

  if (!missing_ids.empty()) {
    return Err(EC::TaskNotFound, "", "", "One or more tasks were not found");
  }
  return OK;
}

ECM TransferInterfaceService::TaskPause(
    const TransferTaskControlArg &arg) const {
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, "", "", "task ids are required");
  }
  ECM status = OK;
  for (const auto &id : arg.ids) {
    if (id == 0) {
      status = Err(EC::InvalidArg, "", "", "task id must be > 0");
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
    ECM rcm =
        transfer_app_service_.Pause(id, arg.timeout_ms, arg.grace_period_ms);
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
    return {EC::InvalidArg, "", "", "task ids are required"};
  }
  ECM status = OK;
  for (const auto &id : arg.ids) {
    if (id == 0) {
      status = Err(EC::InvalidArg, "", "", "task id must be > 0");
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
    ECM rcm = transfer_app_service_.Resume(id, arg.timeout_ms);
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
    if (id == 0) {
      status = Err(EC::InvalidArg, "", "", "task id must be > 0");
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
    auto [task_info, rcm] = transfer_app_service_.Terminate(
        id, arg.timeout_ms, arg.grace_period_ms);
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
  const TaskID id = arg.id;
  if (id == 0) {
    return Err(EC::InvalidArg, "", "", "task id is required");
  }
  auto task_info = FindTask_(id);
  if (!task_info) {
    return Err(EC::TaskNotFound, "", "", AMStr::fmt("Task not found: {}", id));
  }

  const bool include_sets = arg.show_sets;
  const bool include_entries = arg.show_entries;
  const TaskInspectSnapshot_ snapshot =
      BuildTaskInspectSnapshot_(task_info, include_sets, include_entries,
                                ResolveTaskSpeedWindowMs_(style_service_));

  PrintTaskInspectSummary_(prompt_io_manager_, snapshot);
  if (include_sets) {
    PrintTaskInspectSets_(prompt_io_manager_, snapshot);
  }
  if (include_entries) {
    PrintTaskInspectEntries_(prompt_io_manager_, snapshot);
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
    if (id == 0) {
      status = Err(EC::InvalidArg, "", "", "task id must be > 0");
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
    auto task_info = transfer_app_service_.GetResultTask(id, arg.remove);
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

ECM TransferInterfaceService::TaskRemove(
    const TransferTaskRemoveArg &arg) const {
  constexpr const char *kOp = "task.remove";
  if (arg.ids.empty()) {
    return Err(EC::InvalidArg, kOp, "", "task ids are required");
  }

  std::vector<TaskID> unique_ids = {};
  {
    std::unordered_set<TaskID> seen_ids = {};
    unique_ids.reserve(arg.ids.size());
    for (const auto id : arg.ids) {
      if (seen_ids.insert(id).second) {
        unique_ids.push_back(id);
      }
    }
  }

  ECM status = OK;
  std::vector<TaskID> remove_ids = {};
  std::vector<TaskRemovePreviewEntry_> preview_rows = {};
  remove_ids.reserve(unique_ids.size());
  preview_rows.reserve(unique_ids.size());

  for (const auto id : unique_ids) {
    if (id == 0) {
      status = Err(EC::InvalidArg, kOp, "", "task id must be > 0");
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }

    auto task_info = FindTask_(id);
    if (!task_info) {
      status = Err(EC::TaskNotFound, kOp, AMStr::ToString(id),
                   AMStr::fmt("Task not found: {}", id));
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }

    if (task_info->GetStatus() != AMDomain::transfer::TaskStatus::Finished) {
      status = Err(EC::OperationUnsupported, kOp, AMStr::ToString(id),
                   AMStr::fmt("Only finished tasks can be removed: {}", id));
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }

    remove_ids.push_back(id);
    preview_rows.push_back(BuildTaskRemovePreviewEntry_(task_info));
  }

  if (preview_rows.empty()) {
    return (status)
               ? Err(EC::TaskNotFound, kOp, "", "No finished tasks to remove")
               : status;
  }

  PrintTaskRemovePreview_(prompt_io_manager_, preview_rows);

  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      "Are you sure to remove these finished tasks? (y/n) :", &canceled);
  if (canceled || !confirmed) {
    return Err(EC::ConfigCanceled, "task.remove.confirm", "",
               "Remove finished tasks canceled");
  }

  for (const auto id : remove_ids) {
    if (!transfer_app_service_.RemoveFinished(id)) {
      const ECM remove_rcm =
          Err(EC::TaskNotFound, kOp, AMStr::ToString(id),
              AMStr::fmt("Finished task record not found: {}", id));
      prompt_io_manager_.ErrorFormat(remove_rcm);
      status = remove_rcm;
    }
  }
  return status;
}

void TransferInterfaceService::GetTaskCounts(size_t *pending_count,
                                             size_t *conducting_count) const {
  if (pending_count) {
    *pending_count = transfer_app_service_.GetPendingTasks().size();
  }
  if (conducting_count) {
    *conducting_count = transfer_app_service_.GetConductingTasks().size();
  }
}
} // namespace AMInterface::transfer
