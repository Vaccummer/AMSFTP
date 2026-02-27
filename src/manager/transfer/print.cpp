#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Path.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "AMManager/Transfer.hpp"
#include "third_party/indicators/dynamic_progress.hpp"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <deque>
#include <functional>
#include <iomanip>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace {

/**
 * @brief Format elapsed seconds into "XmYs" or "XhYmZs".
 */
std::string FormatElapsed_(double seconds) {
  const int64_t total = static_cast<int64_t>(std::max<int64_t>(0, seconds));
  const int64_t hours = total / 3600;
  const int64_t minutes = (total % 3600) / 60;
  const int64_t secs = total % 60;
  std::ostringstream oss;
  if (hours > 0) {
    oss << hours << "h";
  }
  if (hours > 0 || minutes > 0) {
    oss << minutes << "m";
  }
  oss << secs << "s";
  return oss.str();
}

/**
 * @brief Build a progress bar prefix from the current task info.
 */
std::string BuildTaskPrefix_(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info) {
    return "Task";
  }
  TransferTask task_copy;
  bool has_task = false;
  {
    std::lock_guard<std::mutex> lock(task_info->mtx);
    if (task_info->cur_task) {
      task_copy = *task_info->cur_task;
      has_task = true;
    }
  }
  if (!has_task) {
    return AMStr::amfmt("Task {}", task_info->id);
  }
  const std::string src_host =
      task_copy.src_host.empty() ? "local" : task_copy.src_host;
  const std::string dst_host =
      task_copy.dst_host.empty() ? "local" : task_copy.dst_host;
  const std::string src_name = AMPathStr::basename(task_copy.src);
  const std::string dst_name = AMPathStr::basename(task_copy.dst);
  return AMStr::amfmt("{}@{} -> {}@{}", src_host, src_name, dst_host, dst_name);
}

struct TaskRowData {
  std::string id;
  std::string status;
  std::string elapsed;
  std::string files;
  std::string size;
  std::string speed;
  std::string thread_id;
  std::string task_now;
  std::string ec;
  int order = 0;
  bool conducting = false;
};

/**
 * @brief Format bytes for task tables with a fixed width (up to "999.9MB").
 */
std::string FormatTableSize_(size_t bytes) {
  static const std::vector<std::string> units = {"B", "KB", "MB", "GB", "TB"};
  constexpr double kUnitSwitch = 1024.0;
  constexpr size_t kMaxUnit = 4;
  constexpr size_t kWidth = 7;
  double value = static_cast<double>(bytes);
  size_t idx = 0;
  while (value >= kUnitSwitch && idx < kMaxUnit) {
    value /= kUnitSwitch;
    ++idx;
  }
  if (idx == kMaxUnit && value >= kUnitSwitch) {
    value = kUnitSwitch - 0.1;
  }
  if (idx > 0) {
    value = std::floor(value * 10.0) / 10.0;
    if (value >= kUnitSwitch && idx < kMaxUnit) {
      value /= kUnitSwitch;
      ++idx;
      value = std::floor(value * 10.0) / 10.0;
    }
  }
  std::ostringstream oss;
  if (idx == 0) {
    oss << static_cast<size_t>(value);
  } else {
    oss << std::fixed << std::setprecision(1) << value;
  }
  const std::string out = AMStr::amfmt("{}{}", oss.str(), units[idx]);
  return AMStr::PadLeftAscii(out, kWidth);
}

/**
 * @brief Format bytes-per-second for task tables with fixed width (up to
 * "999MB/s").
 */
std::string FormatSpeedBps_(double bps) {
  constexpr size_t kWidth = 7;
  if (bps <= 0.0) {
    return AMStr::PadLeftAscii("-", kWidth);
  }
  static const std::vector<std::string> units = {"B", "KB", "MB", "GB", "TB"};
  constexpr double kUnitSwitch = 1024.0;
  constexpr size_t kMaxUnit = 4;
  double value = std::max<double>(0.0, bps);
  size_t idx = 0;
  while (value >= kUnitSwitch && idx < kMaxUnit) {
    value /= kUnitSwitch;
    ++idx;
  }
  if (idx == kMaxUnit && value >= kUnitSwitch) {
    value = kUnitSwitch - 1.0;
  }
  value = std::floor(value);
  if (value >= kUnitSwitch && idx < kMaxUnit) {
    value /= kUnitSwitch;
    ++idx;
    value = std::floor(value);
  }
  const std::string out =
      AMStr::amfmt("{}{}/s", static_cast<int64_t>(value), units[idx]);
  return AMStr::PadLeftAscii(out, kWidth);
}

/**
 * @brief Update rolling speed samples and produce speed text for conducting
 * tasks.
 */
void UpdateSpeedCache_(
    const std::vector<std::shared_ptr<TaskInfo>> &conducting_tasks,
    size_t window_size, std::unordered_map<std::string, std::string> *out_speed,
    std::unordered_map<std::string, std::deque<std::pair<double, size_t>>>
        *speed_samples,
    std::mutex *speed_mtx) {
  if (!out_speed || !speed_samples || !speed_mtx) {
    return;
  }

  out_speed->clear();
  const double now = timenow();
  std::unordered_set<std::string> active_ids;
  active_ids.reserve(conducting_tasks.size());

  std::lock_guard<std::mutex> lock(*speed_mtx);
  for (const auto &task : conducting_tasks) {
    if (!task) {
      continue;
    }
    active_ids.insert(task->id);
    const size_t transferred =
        task->total_transferred_size.load(std::memory_order_relaxed);
    auto &samples = (*speed_samples)[task->id];
    samples.emplace_back(now, transferred);
    while (samples.size() > window_size) {
      samples.pop_front();
    }
    if (samples.size() >= 2) {
      const auto &first = samples.front();
      const auto &last = samples.back();
      const double dt = last.first - first.first;
      if (dt > 0.0 && last.second >= first.second) {
        const double bps = static_cast<double>(last.second - first.second) / dt;
        const std::string speed_text = FormatSpeedBps_(bps);
        if (speed_text != "-") {
          (*out_speed)[task->id] = speed_text;
        }
      }
    }
  }

  for (auto it = speed_samples->begin(); it != speed_samples->end();) {
    if (active_ids.find(it->first) == active_ids.end()) {
      it = speed_samples->erase(it);
    } else {
      ++it;
    }
  }
}

int StatusOrder_(const std::string &status) {
  if (status == "Pending")
    return 0;
  if (status == "Paused")
    return 1;
  if (status == "Finished")
    return 2;
  if (status == "Conducting")
    return 3;
  return 4;
}

inline bool IsInterrupted_(const std::shared_ptr<TaskControlToken> &flag) {
  if (flag && flag->check()) {
    return true;
  }
  return false;
}

inline void ResetInterruptFlag_(const std::shared_ptr<TaskControlToken> &flag) {
  if (flag && !flag->iskill()) {
    flag->reset();
  }
}

class SignalHookGuard {
public:
  SignalHookGuard() : monitor_(AMCliSignalMonitor::Instance()) {
    monitor_.ResumeHook("GLOBAL");
    monitor_.SilenceHook("PROMPT");
    monitor_.SilenceHook("COREPROMPT");
  }
  ~SignalHookGuard() {
    monitor_.ResumeHook("GLOBAL");
    monitor_.SilenceHook("PROMPT");
    monitor_.SilenceHook("COREPROMPT");
  }

private:
  AMCliSignalMonitor &monitor_;
};

/**
 * @brief Build a single row for the task list table.
 */
TaskRowData BuildTaskRow_(
    const std::shared_ptr<TaskInfo> &task_info,
    const std::unordered_map<std::string, std::string> *speed_map = nullptr) {
  TaskRowData row;
  if (!task_info) {
    row.id = "-";
    row.status = "-";
    row.elapsed = "-";
    row.files = "-";
    row.size = "-";
    row.speed = "-";
    row.thread_id = "-";
    row.task_now = "-";
    row.ec = "-";
    row.order = 3;
    row.conducting = false;
    return row;
  }

  const TaskStatus status = task_info->GetStatus();
  const bool is_paused = status == TaskStatus::Paused ||
                         (status == TaskStatus::Conducting && task_info->pd &&
                          task_info->pd->is_pause_only());
  row.status = is_paused ? "Paused" : std::string(AM_ENUM_NAME(status));
  row.order = StatusOrder_(row.status);
  row.conducting = status == TaskStatus::Conducting;

  double start_time = 0.0;
  double finished_time = 0.0;
  size_t transferred = 0;
  size_t total = 0;
  size_t filenum = 0;
  size_t success_num = 0;
  int thread_id = 0;
  ECM rcm = {EC::Success, ""};
  std::string task_now;
  {
    std::lock_guard<std::mutex> lock(task_info->mtx);
    row.id = task_info->id;
    start_time = task_info->start_time.load(std::memory_order_relaxed);
    finished_time = task_info->finished_time.load(std::memory_order_relaxed);
    transferred =
        task_info->total_transferred_size.load(std::memory_order_relaxed);
    total = task_info->total_size.load(std::memory_order_relaxed);
    filenum = task_info->filenum.load(std::memory_order_relaxed);
    success_num = task_info->success_filenum.load(std::memory_order_relaxed);
    thread_id = task_info->OnWhichThread.load(std::memory_order_relaxed);
    rcm = task_info->rcm;
    if (task_info->cur_task) {
      task_now = AMPathStr::basename(task_info->cur_task->src);
    }
  }

  if (row.status == "Pending") {
    row.elapsed = "-";
  } else if (row.status == "Finished") {
    if (start_time > 0.0 && finished_time > 0.0) {
      row.elapsed = FormatElapsed_(finished_time - start_time);
    } else {
      row.elapsed = "-";
    }
  } else {
    row.elapsed =
        start_time > 0.0 ? FormatElapsed_(timenow() - start_time) : "-";
  }

  row.files = AMStr::amfmt("{}/{}", success_num, filenum);
  row.size =
      AMStr::amfmt("{}/{}", FormatTableSize_(transferred), FormatSize(total));
  row.speed = FormatSpeedBps_(0.0);
  if (row.status == "Conducting" && speed_map) {
    auto it = speed_map->find(row.id);
    if (it != speed_map->end() && !it->second.empty()) {
      row.speed = it->second;
    }
  }
  row.thread_id = thread_id < 0 ? "-" : std::to_string(thread_id);
  if (row.status == "Conducting" || row.status == "Paused") {
    row.task_now = task_now.empty() ? "-" : task_now;
  } else {
    row.task_now = "-";
  }
  if (row.status == "Finished") {
    row.ec = AM_ENUM_NAME(rcm.first);
  } else {
    row.ec = "-";
  }
  return row;
}

std::string BuildTaskTable_(
    const std::vector<std::shared_ptr<TaskInfo>> &tasks,
    bool include_conducting,
    const std::unordered_map<std::string, std::string> *speed_map = nullptr) {
  static const std::vector<std::string> keys = {
      "ID", "Status", "Elapsed", "Size", "Speed", "Files", "TaskNow", "EC"};
  std::vector<TaskRowData> rows;
  rows.reserve(tasks.size());
  for (const auto &task : tasks) {
    TaskRowData row = BuildTaskRow_(task, speed_map);
    if (!include_conducting && row.conducting) {
      continue;
    }
    rows.push_back(std::move(row));
  }
  if (rows.empty()) {
    return "";
  }
  std::sort(rows.begin(), rows.end(),
            [](const TaskRowData &a, const TaskRowData &b) {
              if (a.order != b.order) {
                return a.order < b.order;
              }
              return a.id < b.id;
            });
  std::vector<std::vector<std::string>> lines;
  lines.reserve(rows.size());
  for (const auto &row : rows) {
    lines.push_back({row.id, row.status, row.elapsed, row.size, row.speed,
                     row.files, row.task_now, row.ec});
  }
  return AMConfigManager::Instance().FormatUtf8Table(keys, lines);
}

/**
 * @brief Build ANSI output to redraw a multi-line table in-place.
 */
std::string BuildTableRefreshOutput_(const std::string &table,
                                     size_t last_lines, size_t *out_lines) {
  std::vector<std::string> lines;
  lines.reserve(std::max<size_t>(1, AMStr::CountLines(table)));
  std::string current;
  for (char ch : table) {
    if (ch == '\n') {
      lines.push_back(current);
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  lines.push_back(current);

  const size_t new_lines = lines.size();
  if (out_lines) {
    *out_lines = new_lines;
  }

  std::string out;
  if (last_lines > 0) {
    out += AMStr::amfmt("\x1b[{}A", last_lines);
  }

  const size_t extra_lines =
      last_lines > new_lines ? last_lines - new_lines : 0;
  for (size_t i = 0; i < new_lines; ++i) {
    out += "\r";
    out += lines[i];
    out += "\x1b[K";
    if (i + 1 < new_lines || extra_lines > 0) {
      out += "\n";
    }
  }

  if (extra_lines > 0) {
    for (size_t i = 0; i < extra_lines; ++i) {
      out += "\r";
      out += "\x1b[2K";
      if (i + 1 < extra_lines) {
        out += "\n";
      }
    }
    if (extra_lines > 1) {
      out += AMStr::amfmt("\x1b[{}A", extra_lines - 1);
    }
  } else {
    out += "\n";
  }

  return out;
}

/**
 * @brief Progress bar wrapper for task status display in
 * AMTransferManager::Show.
 */
class TaskInfoProgressPrinter {
public:
  /**
   * @brief Construct a progress printer for a task.
   * @param task_info Task info used for live updates (nullable).
   */
  explicit TaskInfoProgressPrinter(const std::shared_ptr<TaskInfo> &task_info)
      : task_info_(task_info),
        bar_(AMConfigManager::Instance().CreateProgressBar(
            static_cast<int64_t>(task_info ? task_info->total_size.load(
                                                 std::memory_order_relaxed)
                                           : 0),
            BuildTaskPrefix_(task_info))) {
    if (task_info_) {
      bar_.SetStartTimeEpoch(
          task_info_->start_time.load(std::memory_order_relaxed));
    }
  }

  /**
   * @brief Start rendering the progress bar.
   */
  void Start() { bar_.Print(); }

  /**
   * @brief Update the bar state from task info.
   * @return Current task status.
   */
  TaskStatus Update() {
    if (!task_info_) {
      return TaskStatus::Pending;
    }
    const size_t total = task_info_->total_size.load(std::memory_order_relaxed);
    const size_t transferred =
        task_info_->total_transferred_size.load(std::memory_order_relaxed);
    bar_.SetTotal(static_cast<int64_t>(total));
    bar_.SetProgress(static_cast<int64_t>(transferred));
    bar_.SetPrefix(BuildTaskPrefix_(task_info_));
    return task_info_->GetStatus();
  }

  /**
   * @brief Finish the progress display and restore the terminal state.
   * @param completed Whether to mark the bar as completed.
   */
  void Finish(bool completed) {
    if (completed) {
      bar_.Finish();
    }
    bar_.EndDisplay();
  }

private:
  std::shared_ptr<TaskInfo> task_info_;
  AMProgressBar bar_;
};

int GetRefreshIntervalMs_() {
  std::function<int(int)> funcf = [](int para) {
    if (para < 0)
      return 300;
    return std::max<int>(para, 5);
  };
  static const int refresh_ms = AMConfigManager::Instance().ResolveArg(
      DocumentKind::Settings, {"Style", "ProgressBar", "refresh_interval_ms"},
      300, funcf);
  return refresh_ms;
}

size_t GetSpeedWindowSize() {
  std::function<size_t(size_t)> funct = [](size_t para) {
    if (para < 0)
      return static_cast<size_t>(5);
    return std::max<size_t>(1, para);
  };
  static const size_t speed_window_size =
      AMConfigManager::Instance().ResolveArg(
          DocumentKind::Settings, {"Style", "ProgressBar", "speed_window_size"},
          static_cast<size_t>(300), funct);
  return speed_window_size;
}

void PrintTaskProgress_(const std::shared_ptr<TaskInfo> &task_info,
                        const std::shared_ptr<TaskControlToken> &interrupt_flag) {
  if (!task_info) {
    return;
  }
  TaskInfoProgressPrinter progress_printer(task_info);
  progress_printer.Start();
  static const int refresh_ms = GetRefreshIntervalMs_();

  bool finished = false;
  PrintLock();
  while (true) {
    if (interrupt_flag && interrupt_flag->check()) {
      break;
    }
    const TaskStatus current_status = progress_printer.Update();
    if (current_status == TaskStatus::Finished) {
      finished = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
  }
  progress_printer.Finish(finished);
}

struct TaskProgressGroupBar {
  std::shared_ptr<TaskInfo> task_info;
  AMProgressBar bar;
  std::atomic<bool> multi_progress_mode_{false};

  explicit TaskProgressGroupBar(const std::shared_ptr<TaskInfo> &task)
      : task_info(task),
        bar(AMConfigManager::Instance().CreateProgressBar(
            task ? task->total_size.load(std::memory_order_relaxed) : 0,
            BuildTaskPrefix_(task))) {
    if (task) {
      const double start_time =
          task->start_time.load(std::memory_order_relaxed);
      if (start_time > 0.0) {
        bar.SetStartTimeEpoch(start_time);
      }
    }
  }

  void Update(bool *any_running) {
    if (!task_info) {
      return;
    }
    const size_t total = task_info->total_size.load(std::memory_order_relaxed);
    const size_t transferred =
        task_info->total_transferred_size.load(std::memory_order_relaxed);
    bar.SetTotal(static_cast<int64_t>(total));
    bar.SetProgress(static_cast<int64_t>(transferred));
    bar.SetPrefix(BuildTaskPrefix_(task_info));

    if (task_info->GetStatus() == TaskStatus::Finished) {
      bar.Finish();
    } else if (any_running) {
      *any_running = true;
    }
  }

  void print_progress(bool from_multi_progress = true) {
    (void)from_multi_progress;
    bar.Print(true);
  }

  bool is_completed() const { return bar.IsFinished(); }
};

void PrintTaskProgressGroup_(
    const std::vector<std::shared_ptr<TaskInfo>> &tasks,
    const std::shared_ptr<TaskControlToken> &interrupt_flag) {
  if (tasks.empty()) {
    return;
  }
  SignalHookGuard hook_guard;
  std::vector<std::unique_ptr<TaskProgressGroupBar>> bars;
  bars.reserve(tasks.size());
  for (const auto &task : tasks) {
    bars.push_back(std::make_unique<TaskProgressGroupBar>(task));
  }

  indicators::DynamicProgress<TaskProgressGroupBar> group(*bars[0]);
  for (size_t i = 1; i < bars.size(); ++i) {
    group.push_back(*bars[i]);
  }

  static const int refresh_ms = GetRefreshIntervalMs_();
  PrintLock();
  while (true) {
    if (IsInterrupted_(interrupt_flag)) {
      break;
    }
    bool any_running = false;
    for (auto &bar : bars) {
      bar->Update(&any_running);
    }
    group.print_progress();
    if (!any_running) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
  }

  for (auto &bar : bars) {
    bar->bar.EndDisplay();
  }
}
} // namespace

/**
 * @brief Show task status by ID.
 */
ECM AMTransferManager::Show(
    const ID &task_id, const std::shared_ptr<TaskControlToken> &interrupt_flag) {
  return Show(std::vector<ID>{task_id}, interrupt_flag);
}

ECM AMTransferManager::Show(
    const std::vector<ID> &task_ids,
    const std::shared_ptr<TaskControlToken> &interrupt_flag) {
  if (task_ids.empty()) {
    return {EC::InvalidArg, "Task id required"};
  }

  ResetInterruptFlag_(interrupt_flag);
  ResetInterruptFlag_(amgif);

  std::unordered_set<ID> seen;
  std::vector<std::shared_ptr<TaskInfo>> valid_tasks;
  valid_tasks.reserve(task_ids.size());
  ECM last_error = {EC::Success, ""};

  for (const auto &id : task_ids) {
    if (id.empty()) {
      continue;
    }
    if (!seen.insert(id).second) {
      continue;
    }
    auto task_info = FindTaskById_(id);
    if (!task_info) {
      last_error =
          ECM{EC::TaskNotFound, AMStr::amfmt("Task not found: {}", id)};
      prompt_.ErrorFormat(last_error);
      continue;
    }
    valid_tasks.push_back(task_info);
  }

  if (valid_tasks.empty()) {
    return last_error.first == EC::Success
               ? ECM{EC::TaskNotFound, "Task id not found"}
               : last_error;
  }

  std::vector<std::shared_ptr<TaskInfo>> non_conducting;
  std::vector<std::shared_ptr<TaskInfo>> conducting;
  for (const auto &task : valid_tasks) {
    TaskRowData row = BuildTaskRow_(task);
    if (row.conducting) {
      conducting.push_back(task);
    } else {
      non_conducting.push_back(task);
    }
  }

  const std::string table = BuildTaskTable_(non_conducting, false);
  if (!table.empty()) {
    prompt_.Print(table);
  }

  if (!conducting.empty()) {
    if (conducting.size() > 1) {
      PrintTaskProgressGroup_(conducting, interrupt_flag);
    } else {
      PrintTaskProgress_(conducting[0], interrupt_flag);
    }
  }

  ResetInterruptFlag_(interrupt_flag);
  ResetInterruptFlag_(amgif);

  return last_error.first == EC::Success ? ECM{EC::Success, ""} : last_error;
}

/**
 * @brief List tasks by status.
 */
ECM AMTransferManager::List(
    bool pending, bool suspend, bool finished, bool conducting,
    const std::shared_ptr<TaskControlToken> &interrupt_flag) {
  if (!pending && !suspend && !finished && !conducting) {
    pending = true;
    suspend = true;
    finished = true;
    conducting = true;
  }

  std::vector<std::shared_ptr<TaskInfo>> pending_tasks;
  std::vector<std::shared_ptr<TaskInfo>> paused_tasks;
  std::vector<std::shared_ptr<TaskInfo>> finished_tasks;
  std::vector<std::shared_ptr<TaskInfo>> conducting_tasks;

  auto collect_tasks = [&]() {
    auto registry_snapshot = worker_.get_registry_copy();

    pending_tasks.reserve(registry_snapshot.size());
    paused_tasks.reserve(registry_snapshot.size());
    conducting_tasks.reserve(registry_snapshot.size());
    finished_tasks.reserve(registry_snapshot.size());

    std::unordered_set<std::string> finished_ids;
    finished_ids.reserve(registry_snapshot.size());

    for (const auto &entry : registry_snapshot) {
      const auto &task = entry.second;
      if (!task) {
        continue;
      }
      const TaskStatus status = task->GetStatus();
      const bool is_paused = status == TaskStatus::Paused ||
                             (status == TaskStatus::Conducting && task->pd &&
                              task->pd->is_pause_only());
      if (status == TaskStatus::Finished) {
        if (finished) {
          finished_tasks.push_back(task);
          finished_ids.insert(task->id);
        }
        continue;
      }
      if (is_paused) {
        if (suspend) {
          paused_tasks.push_back(task);
        }
        continue;
      }
      if (status == TaskStatus::Pending) {
        if (pending) {
          pending_tasks.push_back(task);
        }
        continue;
      }
      if (status == TaskStatus::Conducting) {
        if (conducting) {
          conducting_tasks.push_back(task);
        }
        continue;
      }
    }

    if (finished) {
      auto history_tasks = SnapshotHistory_();
      for (const auto &task : history_tasks) {
        if (!task) {
          continue;
        }
        if (finished_ids.find(task->id) == finished_ids.end()) {
          finished_tasks.push_back(task);
        }
      }
    }
  };

  collect_tasks();

  static const size_t speed_window_size = GetSpeedWindowSize();
  std::unordered_map<ID, std::string> speed_map;
  if (conducting) {
    UpdateSpeedCache_(conducting_tasks, speed_window_size, &speed_map,
                      &speed_samples_, &speed_mtx_);
  }

  const bool enable_dynamic =
      conducting && interrupt_flag && !conducting_tasks.empty();
  if (!enable_dynamic) {
    std::vector<std::shared_ptr<TaskInfo>> all_tasks;
    all_tasks.reserve(pending_tasks.size() + paused_tasks.size() +
                      finished_tasks.size() + conducting_tasks.size());
    all_tasks.insert(all_tasks.end(), pending_tasks.begin(),
                     pending_tasks.end());
    all_tasks.insert(all_tasks.end(), paused_tasks.begin(), paused_tasks.end());
    all_tasks.insert(all_tasks.end(), conducting_tasks.begin(),
                     conducting_tasks.end());
    all_tasks.insert(all_tasks.end(), finished_tasks.begin(),
                     finished_tasks.end());
    const std::string table = BuildTaskTable_(all_tasks, true, &speed_map);
    if (!table.empty()) {
      prompt_.Print(table);
    }
    return {EC::Success, ""};
  }

  prompt_.SetCacheOutputOnly(true);
  static const int refresh_ms = GetRefreshIntervalMs_();
  SignalHookGuard hook_guard;
  size_t last_lines = 0;
  std::string last_table;
  while (true) {
    if (IsInterrupted_(interrupt_flag)) {
      break;
    }
    pending_tasks.clear();
    paused_tasks.clear();
    finished_tasks.clear();
    conducting_tasks.clear();
    collect_tasks();
    UpdateSpeedCache_(conducting_tasks, speed_window_size, &speed_map,
                      &speed_samples_, &speed_mtx_);

    std::vector<std::shared_ptr<TaskInfo>> all_tasks;
    all_tasks.reserve(pending_tasks.size() + paused_tasks.size() +
                      finished_tasks.size() + conducting_tasks.size());
    all_tasks.insert(all_tasks.end(), pending_tasks.begin(),
                     pending_tasks.end());
    all_tasks.insert(all_tasks.end(), paused_tasks.begin(), paused_tasks.end());
    all_tasks.insert(all_tasks.end(), conducting_tasks.begin(),
                     conducting_tasks.end());
    all_tasks.insert(all_tasks.end(), finished_tasks.begin(),
                     finished_tasks.end());
    const std::string table = BuildTaskTable_(all_tasks, true, &speed_map);
    if (table.empty()) {
      prompt_.Print("table is empty");
      break;
    }

    if (table != last_table) {
      size_t new_lines = 0;
      const std::string output =
          BuildTableRefreshOutput_(table, last_lines, &new_lines);
      prompt_.PrintRaw(output, false);
      last_lines = new_lines;
      last_table = table;
    }

    if (conducting_tasks.empty()) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
  }
  prompt_.SetCacheOutputOnly(false);
  prompt_.FlushCachedOutput();
  return {EC::Success, ""};
}
