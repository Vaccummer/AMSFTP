#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/bar.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "foundation/tools/url.hpp"
#include "infrastructure/client/http/HTTP.hpp"
#include "interface/style/StyleManager.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <memory>
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

std::vector<std::string>
CollectOverwriteTargets_(const std::vector<TransferTask> &tasks) {
  std::vector<std::string> out = {};
  out.reserve(tasks.size());
  for (const auto &task : tasks) {
    if (!task.overwrite) {
      continue;
    }
    out.push_back(
        AMStr::fmt("{}@{}", DisplayHost_(task.dst_host), NormalizePath_(task.dst)));
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

TaskInfo::ID BuildTaskId_() {
  static std::atomic<TaskInfo::ID> seq{1};
  return seq.fetch_add(1, std::memory_order_relaxed);
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

BaseProgressBar::RenderArgs
BuildTransferProgressRenderArgs_(const std::shared_ptr<TaskInfo> &task_info) {
  BaseProgressBar::RenderArgs args = {};
  if (!task_info) {
    args.filename = "Task";
    return args;
  }
  auto cur_task = task_info->GetCurrentTaskSnapshot();
  if (!cur_task.has_value()) {
    args.filename = AMStr::fmt("Task {}", task_info->id);
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
  return args;
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
  TaskInfo::ID id = 0;
  std::string status = {};
  std::string progress = {};
  std::string size = {};
  std::string elapse = {};
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
  ECM result = OK;
};

struct TaskInspectSnapshot_ {
  TaskInfo::ID id = 0;
  AMDomain::transfer::TaskStatus status = AMDomain::transfer::TaskStatus::Pending;
  AMDomain::transfer::ControlIntent intent =
      AMDomain::transfer::ControlIntent::Running;
  ECM result = OK;

  double submit_time_s = 0;
  double start_time_s = 0;
  double finish_time_s = 0;
  int64_t elapsed_ms = 0;

  size_t total = 0;
  size_t transferred = 0;
  size_t success_files = 0;
  size_t total_files = 0;
  size_t current_task_index = 0;
  size_t current_task_transferred = 0;
  int progress_percent = 0;

  bool interrupted = false;
  bool timeout = false;
  std::optional<unsigned int> timeout_remaining_ms = std::nullopt;
  std::optional<TaskInfo::CurrentTaskSnapshot> current_task = std::nullopt;
  std::string source_display = {};
  std::string destination_display = {};

  std::vector<TaskInspectSetSnapshot_> sets = {};
  std::vector<TaskInspectEntrySnapshot_> entries = {};
  bool entries_snapshot_busy = false;
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

TaskTableRow_ BuildTaskTableRow_(const std::shared_ptr<TaskInfo> &task_info) {
  TaskTableRow_ row = {};
  if (!task_info) {
    return row;
  }
  const size_t transferred =
      task_info->Size.transferred.load(std::memory_order_relaxed);
  const size_t total = task_info->Size.total.load(std::memory_order_relaxed);
  row.id = task_info->id;
  row.status = TaskStatusTextLocal_(task_info->GetStatus());
  row.progress = AMStr::fmt("{}%", ResolveTaskProgressPercent_(task_info));
  row.size =
      AMStr::fmt("{}/{}", AMStr::FormatSize(transferred), AMStr::FormatSize(total));
  row.elapse = FormatElapsedMs_(ResolveElapsedMs_(task_info));
  return row;
}

void PrintTaskTable_(AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
                     const std::vector<TaskTableRow_> &rows) {
  if (rows.empty()) {
    return;
  }
  constexpr size_t kColCount = 5;
  const std::array<std::string, kColCount> headers = {
      "ID", "STATUS", "PROGRESS", "SIZE", "ELAPSE"};
  std::array<size_t, kColCount> widths = {
      headers[0].size(), headers[1].size(), headers[2].size(),
      headers[3].size(), headers[4].size()};
  for (const auto &row : rows) {
    widths[0] = std::max(widths[0], AMStr::fmt("{}", row.id).size());
    widths[1] = std::max(widths[1], row.status.size());
    widths[2] = std::max(widths[2], row.progress.size());
    widths[3] = std::max(widths[3], row.size.size());
    widths[4] = std::max(widths[4], row.elapse.size());
  }
  const size_t gap = 3;
  const size_t total_width =
      widths[0] + widths[1] + widths[2] + widths[3] + widths[4] + gap * 4;

  const std::string header_line = AMStr::fmt(
      "{}{}{}{}{}{}{}{}{}",
      AMStr::PadRightAscii(headers[0], widths[0]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[1], widths[1]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[2], widths[2]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[3], widths[3]), std::string(gap, ' '),
      AMStr::PadRightAscii(headers[4], widths[4]));
  prompt_io_manager.Print(header_line);
  prompt_io_manager.Print(std::string(total_width, '-'));
  for (const auto &row : rows) {
    prompt_io_manager.FmtPrint(
        "{}{}{}{}{}{}{}{}{}",
        AMStr::PadRightAscii(AMStr::fmt("{}", row.id), widths[0]),
        std::string(gap, ' '), AMStr::PadRightAscii(row.status, widths[1]),
        std::string(gap, ' '), AMStr::PadRightAscii(row.progress, widths[2]),
        std::string(gap, ' '), AMStr::PadRightAscii(row.size, widths[3]),
        std::string(gap, ' '), AMStr::PadRightAscii(row.elapse, widths[4]));
  }
  prompt_io_manager.Print("");
}

TaskInspectSnapshot_ BuildTaskInspectSnapshot_(
    const std::shared_ptr<TaskInfo> &task_info, bool include_sets,
    bool include_entries) {
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
  snapshot.success_files =
      task_info->Size.success_filenum.load(std::memory_order_relaxed);
  snapshot.total_files = task_info->Size.filenum.load(std::memory_order_relaxed);
  snapshot.current_task_index =
      task_info->Size.cur_task.load(std::memory_order_relaxed);
  snapshot.current_task_transferred =
      task_info->Size.cur_task_transferred.load(std::memory_order_relaxed);
  snapshot.progress_percent = ResolveTaskProgressPercent_(task_info);

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
    snapshot.destination_display =
        AMStr::fmt("{}:{}", DisplayHost_(set.dst.nickname),
                   NormalizePath_(set.dst.path));
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
    if (snapshot.status == AMDomain::transfer::TaskStatus::Conducting) {
      auto dir_tasks = task_info->Core.dir_tasks.try_lock();
      auto file_tasks = task_info->Core.file_tasks.try_lock();
      if (!dir_tasks.has_value() || !file_tasks.has_value()) {
        snapshot.entries_snapshot_busy = true;
      } else {
        snapshot.entries.reserve(dir_tasks->get().size() + file_tasks->get().size());
        collect_entries(dir_tasks->get(), &index_seed);
        collect_entries(file_tasks->get(), &index_seed);
      }
    } else {
      auto dir_tasks = task_info->Core.dir_tasks.lock();
      auto file_tasks = task_info->Core.file_tasks.lock();
      snapshot.entries.reserve(dir_tasks->size() + file_tasks->size());
      collect_entries(*dir_tasks, &index_seed);
      collect_entries(*file_tasks, &index_seed);
    }
  }

  return snapshot;
}

void PrintTaskInspectSummary_(
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
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
                             std::to_string(snapshot.success_files),
                             std::to_string(snapshot.total_files));

  double speed_bps = 0.0;
  if (snapshot.elapsed_ms > 0) {
    speed_bps = static_cast<double>(snapshot.transferred) /
                (static_cast<double>(snapshot.elapsed_ms) / 1000.0);
  }
  prompt_io_manager.FmtPrint("Speed        : {}",
                             AMStr::Strip(
                                 AMStr::FormatSpeed(speed_bps, 3, 1, 0, false)));
  prompt_io_manager.FmtPrint("Status       : {}", state_view.text);
  prompt_io_manager.FmtPrint("Intent       : {}", IntentTextLocal_(snapshot.intent));

  if (!snapshot.source_display.empty()) {
    prompt_io_manager.Print("");
    prompt_io_manager.FmtPrint("Source       : {}", snapshot.source_display);
    prompt_io_manager.FmtPrint("Destination  : {}", snapshot.destination_display);
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
    prompt_io_manager.FmtPrint("  file       : {}", NormalizePath_(current.src));
    prompt_io_manager.FmtPrint("  progress   : {} / {} ({}%)",
                               AMStr::FormatSize(current.transferred),
                               AMStr::FormatSize(current.size),
                               std::to_string(file_progress));
    prompt_io_manager.FmtPrint("  from       : {}", DisplayHost_(current.src_host));
    prompt_io_manager.FmtPrint("  to         : {}", DisplayHost_(current.dst_host));
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
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
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
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
    const TaskInspectSnapshot_ &snapshot) {
  prompt_io_manager.Print("");
  prompt_io_manager.Print("Entries:");
  if (snapshot.entries_snapshot_busy) {
    prompt_io_manager.Print(
        "  Entry snapshot busy; showing runtime summary only.");
    return;
  }
  if (snapshot.entries.empty()) {
    prompt_io_manager.Print("  (none)");
    return;
  }

  std::vector<const TaskInspectEntrySnapshot_ *> ordered = {};
  ordered.reserve(snapshot.entries.size());
  for (const auto &entry : snapshot.entries) {
    if (entry.result.code != EC::Success) {
      ordered.push_back(&entry);
    }
  }
  for (const auto &entry : snapshot.entries) {
    if (entry.result.code == EC::Success) {
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
    row.result = AMStr::ToString(entry->result.code);
    row.error = entry->result.msg();
    rows.push_back(std::move(row));
  }

  constexpr size_t kColCount = 7;
  const std::array<std::string, kColCount> headers = {
      "IDX", "TYPE", "SRC", "DST", "SIZE", "XFER", "RESULT"};
  std::array<size_t, kColCount> widths = {
      headers[0].size(), headers[1].size(), headers[2].size(),
      headers[3].size(), headers[4].size(), headers[5].size(),
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
    if (row.result != "Success" && !row.error.empty()) {
      prompt_io_manager.FmtPrint("    error: {}", row.error);
    }
  }
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

    if (!set.overwrite) {
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
            return Err(EC::ConfigCanceled, "", "",
                       "Transfer canceled by user");
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

  auto build_bar = [this, &task_info]() -> std::unique_ptr<BaseProgressBar> {
    const auto total_size = static_cast<int64_t>(
        task_info->Size.total.load(std::memory_order_relaxed));
    const std::string prefix = BuildTransferProgressPrefix_(task_info);
    if (style_service_ != nullptr) {
      return style_service_->CreateProgressBar(total_size, prefix);
    }
    auto bar = std::make_unique<BaseProgressBar>();
    bar->SetTotal(total_size);
    return bar;
  };

  auto progress_bar = build_bar();
  if (!progress_bar) {
    return Err(EC::InvalidHandle, "transfer.wait", "", "Progress bar is null");
  }
  std::string final_line = "";
  std::string last_progress_line = "";
  BaseProgressBar::RenderArgs last_render_args = {};
  auto is_generic_task_label = [](const std::string &s) -> bool {
    return s.rfind("Task ", 0) == 0;
  };
  auto render_progress_line = [&]() -> std::string {
    BaseProgressBar::RenderArgs args =
        BuildTransferProgressRenderArgs_(task_info);
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
    prompt_io_manager_.RefreshBegin(1);
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
        auto latest_args = BuildTransferProgressRenderArgs_(task_info);
        if (!latest_args.filename.empty()) {
          final_prefix = latest_args.filename;
        }
      }
      const std::string candidate_line =
          progress_bar->RenderFinal(final_prefix, transferred_now);
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
      task_info->Core.clients.ReleaseAll();
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
      last_progress_line = render_progress_line();
      prompt_io_manager_.RefreshRender({last_progress_line});
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
  }
}

std::shared_ptr<AMDomain::transfer::TaskInfo>
TransferInterfaceService::FindTask_(TaskInfo::ID task_id) const {
  if (task_id == 0) {
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
  const auto fail = [this](const ECM &rcm) -> ECM {
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
    return rcm;
  };

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
        return fail(find_result.rcm);
      }
      confirm_requests.push_back(
          {std::move(find_result.data), src.nickname, set.dst.nickname});
    }
  }

  ECM confirm_rcm = ConfirmWildcard_(confirm_requests, arg.confirm_policy);
  if (!(confirm_rcm)) {
    return fail(confirm_rcm);
  }

  std::vector<ECM> warnings = {};
  std::shared_ptr<TaskInfo> task_info = nullptr;
  ECM build_rcm = BuildTaskInfo_(arg, control, &task_info, &warnings);
  for (const auto &warning : warnings) {
    prompt_io_manager_.ErrorFormat(warning);
  }
  if (!(build_rcm)) {
    return fail(build_rcm);
  }
  if (!task_info) {
    return fail({EC::InvalidHandle, "", "", "BuildTaskInfo returned null task"});
  }

  const ECM submit_rcm = transfer_pool_.Submit(task_info);
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

ECM TransferInterfaceService::HttpGet(
    const HttpGetArg &arg,
    const std::optional<ClientControlComponent> &component) const {
  const auto fail = [this](const ECM &rcm) -> ECM {
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
    return rcm;
  };
  const ClientControlComponent control =
      ResolveControl_(component, arg.timeout_ms);
  if (const auto &token = control.ControlToken(); token) {
    token->ClearInterrupt();
  }

  const std::string src_url = AMStr::Strip(arg.src_url);
  if (src_url.empty()) {
    return fail(Err(EC::InvalidArg, "wget", "", "Source URL is empty"));
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

  auto plan_result = filesystem_service_.BuildHttpDownloadPlan(
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
  auto [http_client_rcm, http_client] =
      AMInfra::client::HTTP::CreateTransientHttpSourceClient(
          src_url, effective_proxy, arg.bear_token, request_username,
          max_redirect);
  if (!(http_client_rcm) || !http_client) {
    return fail(http_client_rcm);
  }

  auto *http_io = dynamic_cast<AMInfra::client::HTTP::AMHTTPIOCore *>(
      &http_client->IOPort());
  if (http_io == nullptr) {
    return fail(Err(EC::InvalidHandle, "wget", src_url,
                    "HTTP IO port implementation mismatch"));
  }
  auto redirect_result =
      http_io->ResolveRedirectChain(src_url, max_redirect, control);
  if (!redirect_result.rcm) {
    return fail(redirect_result.rcm);
  }
  const std::string effective_src_url =
      AMStr::Strip(redirect_result.data.final_url).empty()
          ? src_url
          : redirect_result.data.final_url;
  bool metadata_updated = false;
  http_client->MetaDataPort()
      .MutateTypeValue<AMInfra::client::HTTP::HttpRuntimeMetadata>(
          [&effective_src_url, &metadata_updated](
              AMInfra::client::HTTP::HttpRuntimeMetadata *meta) {
            if (meta == nullptr) {
              return;
            }
            meta->effective_url = effective_src_url;
            metadata_updated = true;
          });
  if (!metadata_updated) {
    (void)http_client->MetaDataPort().StoreTypedValue(
        AMInfra::client::HTTP::HttpRuntimeMetadata{
            true, src_url, effective_src_url, effective_proxy, max_redirect},
        true);
  }

  auto src_stat =
      http_client->IOPort().stat({effective_src_url, false}, control);
  if (!(src_stat.rcm)) {
    return fail(src_stat.rcm);
  }
  if (src_stat.data.info.type != PathType::FILE) {
    return fail(Err(EC::NotAFile, "wget", effective_src_url,
                    "HTTP source is not a file"));
  }

  if (src_stat.data.info.size == 0 &&
      redirect_result.data.content_length.has_value() &&
      *redirect_result.data.content_length > 0) {
    src_stat.data.info.size =
        static_cast<size_t>(*redirect_result.data.content_length);
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
  int task_timeout_ms = -1;
  if (const auto remain_ms = control.RemainingTimeMs(); remain_ms.has_value()) {
    task_timeout_ms = static_cast<int>(*remain_ms);
  }
  auto task_control_token = AMDomain::client::CreateClientControlToken();
  if (!task_control_token) {
    return fail(Err(EC::InvalidHandle, "wget", src_url,
                    "failed to create transfer task control token"));
  }
  task_info->Core.control =
      ClientControlComponent(task_control_token, task_timeout_ms);

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

  const ECM submit_rcm = transfer_pool_.Submit(task_info);
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
  std::unordered_set<TaskInfo::ID> seen_ids = {};
  std::vector<TaskInfo::ID> ids = {};
  const auto add_ids = [&seen_ids, &ids](const auto &map_data) {
    for (const auto &[id, task_info] : map_data) {
      if (id == 0 || !task_info) {
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
  std::vector<TaskTableRow_> rows = {};
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
    rows.push_back(BuildTaskTableRow_(task_info));
  }
  if (rows.empty()) {
    prompt_io_manager_.Print("No transfer task matched.");
    return OK;
  }
  PrintTaskTable_(prompt_io_manager_, rows);
  return OK;
}

ECM TransferInterfaceService::TaskShow(const TransferTaskShowArg &arg) const {
  if (arg.ids.empty()) {
    return TaskList({});
  }
  std::vector<TaskInfo::ID> unique_ids = {};
  {
    std::unordered_set<TaskInfo::ID> seen_ids = {};
    unique_ids.reserve(arg.ids.size());
    for (const auto id : arg.ids) {
      if (seen_ids.insert(id).second) {
        unique_ids.push_back(id);
      }
    }
  }

  std::vector<TaskInfo::ID> missing_ids = {};
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
      rows.push_back(BuildTaskTableRow_(task_info));
    }
    PrintTaskTable_(prompt_io_manager_, rows);
  }

  if (!conducting_tasks.empty()) {
    const int refresh_ms = ResolveTransferProgressRefreshMs_(style_service_);
    struct TaskWatchItem_ {
      std::shared_ptr<TaskInfo> task_info = nullptr;
      std::unique_ptr<BaseProgressBar> bar = nullptr;
      std::optional<std::string> rendered_line = std::nullopt;
      BaseProgressBar::RenderArgs last_render_args = {};
      bool frozen = false;
    };
    std::vector<TaskWatchItem_> watch_items = {};
    watch_items.reserve(conducting_tasks.size());
    auto make_bar = [this](const std::shared_ptr<TaskInfo> &task_info)
        -> std::unique_ptr<BaseProgressBar> {
      const auto total_size = static_cast<int64_t>(
          task_info->Size.total.load(std::memory_order_relaxed));
      const std::string prefix = BuildTransferProgressPrefix_(task_info);
      if (style_service_ != nullptr) {
        auto bar = style_service_->CreateProgressBar(total_size, prefix);
        if (bar) {
          return bar;
        }
      }
      auto bar = std::make_unique<BaseProgressBar>();
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

      prompt_io_manager_.SetCursorVisible(false);
      scoped_cursor.hidden = true;
      prompt_io_manager_.RefreshBegin(static_cast<int>(watch_items.size()));
      scoped_refresh.active = true;

      const auto token = GetDefaultControlToken();
      bool watch_canceled = false;
      auto is_generic_task_label = [](const std::string &s) -> bool {
        return s.rfind("Task ", 0) == 0;
      };
      while (true) {
        if (token && token->IsInterrupted()) {
          token->ClearInterrupt();
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
              BaseProgressBar::RenderArgs args =
                  BuildTransferProgressRenderArgs_(item.task_info);
              args.total = static_cast<int64_t>(
                  item.task_info->Size.total.load(std::memory_order_relaxed));
              args.transferred = static_cast<int64_t>(item.task_info->Size
                                                          .transferred.load(
                                                              std::memory_order_relaxed));
              item.last_render_args = args;
              item.rendered_line = item.bar->Render(args);
            }
            lines[i] = item.rendered_line;
            continue;
          }

          BaseProgressBar::RenderArgs args =
              BuildTransferProgressRenderArgs_(item.task_info);
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
        std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
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
    if (id == 0) {
      status = Err(EC::InvalidArg, "", "", "task id must be > 0");
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
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
    if (id == 0) {
      status = Err(EC::InvalidArg, "", "", "task id must be > 0");
      prompt_io_manager_.ErrorFormat(status);
      continue;
    }
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
  const TaskInfo::ID id = arg.id;
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
      BuildTaskInspectSnapshot_(task_info, include_sets, include_entries);

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
