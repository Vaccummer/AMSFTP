#include "foundation/DataClass.hpp"
#include "interface/adapters/ApplicationAdapters.hpp"
#include "application/filesystem/PathResolutionService.hpp"
#include "foundation/Path.hpp"
#include "foundation/tools/bar.hpp"
#include "domain/host/HostDomainService.hpp"
#include "application/transfer/runtime/AMWorkManager.hpp"
#include "domain/config/ConfigModel.hpp"
#include "interface/prompt/Prompt.hpp"
#include "domain/transfer/TransferManager.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#endif

AMDomain::transfer::AMTransferManager::AMTransferManager()
    : worker_(std::make_shared<AMWorkManager>()) {}

ECM AMDomain::transfer::AMTransferManager::Init() {
  if (!worker_) {
    worker_ = std::make_shared<AMWorkManager>();
  }
  int init_thread_num =
      AMInterface::ApplicationAdapters::Runtime::ResolveSettingInt(
          {"Options", "TransferManager", "init_thread_num"}, 1);

  init_thread_num = std::min(std::max(1, init_thread_num), 128);
  worker_->ThreadCount(init_thread_num);
  return Ok();
}

namespace {
#ifdef _WIN32
/**
 * @brief Temporarily ensure STDIN has ENABLE_PROCESSED_INPUT on Windows.
 *
 * This guarantees Ctrl+C is delivered as CTRL_C_EVENT while blocking sync
 * transfer is running, then restores the original console mode on scope exit.
 */
class ScopedProcessedInputMode_ {
public:
  /**
   * @brief Capture current mode and enable processed input when possible.
   */
  ScopedProcessedInputMode_() {
    input_handle_ = GetStdHandle(STD_INPUT_HANDLE);
    if (input_handle_ == INVALID_HANDLE_VALUE || input_handle_ == nullptr) {
      return;
    }
    if (!GetConsoleMode(input_handle_, &original_mode_)) {
      return;
    }
    const DWORD desired_mode = original_mode_ | ENABLE_PROCESSED_INPUT;
    if (desired_mode == original_mode_) {
      return;
    }
    if (!SetConsoleMode(input_handle_, desired_mode)) {
      return;
    }
    applied_ = true;
  }

  /**
   * @brief Restore original console mode when this guard changed it.
   */
  ~ScopedProcessedInputMode_() {
    if (!applied_) {
      return;
    }
    if (input_handle_ == INVALID_HANDLE_VALUE || input_handle_ == nullptr) {
      return;
    }
    (void)SetConsoleMode(input_handle_, original_mode_);
  }

private:
  HANDLE input_handle_ = INVALID_HANDLE_VALUE;
  DWORD original_mode_ = 0;
  bool applied_ = false;
};
#endif

/**
 * @brief Build a unique key for a transfer task.
 */
std::string BuildTaskKey_(const TransferTask &task) {
  std::ostringstream oss;
  oss << task.src_host << '\t' << task.src << '\t' << task.dst_host << '\t'
      << task.dst << '\t' << static_cast<int>(task.path_type);
  return oss.str();
}

/**
 * @brief Remove duplicate tasks while preserving original order.
 */
void DeduplicateTasks_(TASKS *tasks) {
  if (!tasks || tasks->empty()) {
    return;
  }
  std::unordered_set<std::string> seen;
  seen.reserve(tasks->size());
  TASKS unique;
  unique.reserve(tasks->size());
  for (const auto &task : *tasks) {
    std::string key = BuildTaskKey_(task);
    if (seen.insert(key).second) {
      unique.push_back(task);
    }
  }
  tasks->swap(unique);
}

/**
 * @brief Print submit information for transfer_async.
 */
void PrintTaskSubmit_(AMPromptManager &prompt,
                      const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info) {
    return;
  }
  const size_t file_num = task_info->tasks ? task_info->tasks->size() : 0;
  const size_t total_size =
      task_info->total_size.load(std::memory_order_relaxed);
  std::vector<std::string> nicknames = task_info->nicknames;
  std::string nickname_str = AMStr::join(nicknames, " ");
  if (nickname_str.empty()) {
    nickname_str = "local";
  }
  prompt.FmtPrint(
      "SubmitInfo ID: {}; FileNum: {}; TotalSize: {}; Clients: {}",
      task_info->id, file_num, AMStr::FormatSize(total_size), nickname_str);
}

/**
 * @brief Print task result information after completion.
 */
void PrintTaskResult_(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info) {
    return;
  }
  auto &prompt = AMPromptManager::Instance();
  size_t transferred = 0;
  size_t total = 0;
  int thread_id = 0;
  ECM result;
  bool success = false;
  size_t filenum;
  size_t success_num;
  decltype(task_info->id) task_id;
  {
    std::lock_guard<std::mutex> lock(task_info->mtx);
    if (task_info->quiet) {
      return;
    }
    transferred =
        task_info->total_transferred_size.load(std::memory_order_relaxed);
    total = task_info->total_size.load(std::memory_order_relaxed);
    thread_id = task_info->OnWhichThread.load(std::memory_order_relaxed);
    task_id = task_info->id;
    filenum = task_info->filenum.load(std::memory_order_relaxed);
    success_num = task_info->success_filenum.load(std::memory_order_relaxed);

    result = task_info->rcm;
    success = result.first == EC::Success;
    if (success && task_info->tasks) {
      for (const auto &task : *task_info->tasks) {
        if (task.rcm.first != EC::Success) {
          result = task.rcm;
          success = false;
        }
      }
    }
  }

  const std::string prefix = success ? "✅" : "❌";
  std::string rcm_text =
      success
          ? ""
          : AMStr::fmt(" {}: {}", AMStr::ToString(result.first), result.second);

  prompt.FmtPrint(
      "TaskResult  {} ID: {}; Files: {}/{}; Size: {}/{}; ThreadID: {};{}",
      prefix, task_id, success_num, filenum, AMStr::FormatSize(transferred),
      AMStr::FormatSize(total), thread_id, rcm_text);
}

/**
 * @brief Build a progress bar prefix from the current transfer task.
 */
std::string
BuildTransferProgressPrefix_(const std::shared_ptr<TaskInfo> &task_info) {
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
    return AMStr::fmt("Task {}", task_info->id);
  }
  const std::string src_host =
      task_copy.src_host.empty() ? "local" : task_copy.src_host;
  const std::string dst_host =
      task_copy.dst_host.empty() ? "local" : task_copy.dst_host;
  const std::string src_name = AMPathStr::basename(task_copy.src);
  const std::string dst_name = AMPathStr::basename(task_copy.dst);
  return AMStr::fmt("{}@{} -> {}@{}", src_host, src_name, dst_host, dst_name);
}

/**
 * @brief Read refresh interval for progress rendering.
 */
int GetTransferProgressRefreshMs_() {
  std::function<int(int)> clamp_refresh = [](int value) {
    if (value < 30) {
      return 30;
    }
    return value;
  };
  return clamp_refresh(AMInterface::ApplicationAdapters::Runtime::ResolveSettingInt(
      {"Style", "ProgressBar", "refresh_interval_ms"}, 300));
}

/**
 * @brief Read speed window size for progress rendering.
 */
size_t GetTransferProgressSpeedWindow_() {
  std::function<size_t(size_t)> clamp_window = [](size_t value) {
    return std::max<size_t>(1, value);
  };
  return clamp_window(static_cast<size_t>(AMInterface::ApplicationAdapters::Runtime::ResolveSettingInt(
      {"Style", "ProgressBar", "speed_window_size"}, 300)));
}

/**
 * @brief Update and print one progress frame.
 */
void UpdateTransferProgressBar_(AMProgressBar *bar,
                                const std::shared_ptr<TaskInfo> &task_info,
                                bool finish = false) {
  if (!bar || !task_info) {
    return;
  }
  const size_t total = task_info->total_size.load(std::memory_order_relaxed);
  const size_t transferred =
      task_info->total_transferred_size.load(std::memory_order_relaxed);
  bar->SetTotal(static_cast<int64_t>(total));
  bar->SetProgress(static_cast<int64_t>(transferred));
  bar->SetPrefix(BuildTransferProgressPrefix_(task_info));
  if (finish) {
    bar->Finish();
    return;
  }
  bar->Print();
}

bool HasWildcard_(const std::string &path) {
  return path.find('*') != std::string::npos ||
         (path.find('<') != std::string::npos &&
          path.find('>') != std::string::npos);
}
} // namespace

/**
 * @brief Set the public result callback wrapper for all task completions.
 */
void AMDomain::transfer::AMTransferManager::SetPublicResultCallback(PublicResultCallback cb) {
  std::lock_guard<std::mutex> lock(callback_mtx_);
  public_result_cb_ = std::move(cb);
}

/**
 * @brief Prompt the user to confirm matched wildcard results.
 */
bool AMDomain::transfer::AMTransferManager::ConfirmWildcard_(const std::vector<PathInfo> &matches,
                                         const std::string &src_host,
                                         const std::string &dst_host) {
  if (matches.empty()) {
    return false;
  }
  std::string host_name = src_host.empty() ? "local" : src_host;
  std::string dst_name = dst_host.empty() ? "local" : dst_host;
  AMPromptManager::Instance().FmtPrint("Found {} paths to transfer", std::to_string(matches.size()));

  std::vector<PathInfo> sorted = matches;
  std::sort(sorted.begin(), sorted.end(),
            [](const PathInfo &lhs, const PathInfo &rhs) {
              return lhs.type == PathType::DIR && rhs.type != PathType::DIR;
            });

  for (const auto &path : sorted) {
    if (path.type == PathType::DIR) {
      AMPromptManager::Instance().FmtPrint("📁   {}@{}", host_name, path.path);
    } else {
      AMPromptManager::Instance().FmtPrint("📑   {}@{}", host_name, path.path);
    }
  }

  std::string input;
  const std::string prompt = AMStr::fmt(
      "Are you sure to transfer these paths to {}? (y/n): ", dst_name);
  if (!AMPromptManager::Instance().Prompt(prompt, "", &input)) {
    return false;
  }
  std::string lowered = input;
  std::transform(
      lowered.begin(), lowered.end(), lowered.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (lowered != "y") {
    AMPromptManager::Instance().Print("Transfer cancelled");
    return false;
  }
  return true;
}

TaskInfo::ResultCallback
AMDomain::transfer::AMTransferManager::BindResultCallback(UserResultCallback user_cb) {
  return [this, user_cb](std::shared_ptr<TaskInfo> task_info) {
    PublicResultCallback public_cb;
    {
      std::lock_guard<std::mutex> lock(callback_mtx_);
      public_cb = public_result_cb_;
    }
    this->ResultCallback(task_info, public_cb, user_cb);
  };
}

void AMDomain::transfer::AMTransferManager::ResultCallback(std::shared_ptr<TaskInfo> task_info,
                                       PublicResultCallback public_cb,
                                       UserResultCallback user_cb) {
  if (!task_info) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(history_mtx_);
    history_.push_front(task_info);
  }
  if (user_cb) {
    user_cb(task_info);
  }
  if (public_cb) {
    public_cb(task_info);
  }
}

/**
 * @brief Blocking transfer entry point.
 */
ECM AMDomain::transfer::AMTransferManager::transfer(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    std::shared_ptr<TaskControlToken> interrupt_flag) {
  bool has_resume = false;
  for (const auto &set : transfer_sets) {
    if (!set.resume) {
      continue;
    }
    has_resume = true;
    if (set.srcs.size() != 1 || set.dst.empty()) {
      return {EC::InvalidArg,
              "Resume transfer requires exactly one src and one dst"};
    }
  }
  if (has_resume && transfer_sets.size() != 1) {
    return {EC::InvalidArg, "Resume transfer requires a single transfer set"};
  }
  auto flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  auto [rcm, task_info] = PrepareTasks_(transfer_sets, quiet, flag);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (task_info) {
    task_info->control_token = TaskControlToken::Instance()
                                   ? TaskControlToken::Instance()
                                   : std::make_shared<TaskControlToken>();
  }
  return transfer(task_info, task_info ? task_info->control_token : flag);
}

/**
 * @brief Blocking transfer entry point for prepared task info.
 */
ECM AMDomain::transfer::AMTransferManager::transfer(
    const std::shared_ptr<TaskInfo> &task_info,
    std::shared_ptr<TaskControlToken> interrupt_flag) {
#ifdef _WIN32
  ScopedProcessedInputMode_ processed_input_guard;
  (void)processed_input_guard;
#endif
  if (!task_info) {
    return {EC::Success, ""};
  }

  if (!task_info->tasks || task_info->tasks->empty()) {
      return {EC::Success, ""};
  }

  task_info->control_token = TaskControlToken::Instance()
                                 ? TaskControlToken::Instance()
                                 : std::make_shared<TaskControlToken>();
  auto flag = task_info->control_token;
  if (interrupt_flag && !interrupt_flag->IsRunning() && flag) {
    flag->SetStatus(ControlSignal::Interrupt);
  }
  const int refresh_interval_ms = GetTransferProgressRefreshMs_();

  std::mutex done_mtx;
  std::condition_variable done_cv;
  std::atomic<int> remaining(1);

  UserResultCallback user_callback = [this, &remaining, &done_cv, &done_mtx](
                                         std::shared_ptr<TaskInfo> task_info) {
    --remaining;
    std::lock_guard<std::mutex> lock(done_mtx);
    done_cv.notify_all();
  };

  task_info->result_callback = BindResultCallback(std::move(user_callback));

  auto submit_rcm = worker_->Submit(task_info);
  if (submit_rcm.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(submit_rcm);
    return submit_rcm;
  }

  const bool show_progress = !task_info->quiet;
  AMProgressBar progress_bar = AMInterface::ApplicationAdapters::Runtime::CreateProgressBar(
      static_cast<int64_t>(
          task_info->total_size.load(std::memory_order_relaxed)),
      BuildTransferProgressPrefix_(task_info));
  std::unique_ptr<AMPrintLockGuard> print_guard;
  (void)print_guard;
  if (show_progress) {
    progress_bar.SetSpeedWindowSize(GetTransferProgressSpeedWindow_());
    const double start_time =
        task_info->start_time.load(std::memory_order_relaxed);
    if (start_time > 0.0) {
      progress_bar.SetStartTimeEpoch(start_time);
    }
    print_guard = std::make_unique<AMPrintLockGuard>();
  }

  bool all_finished = false;
  while (!all_finished) {
    const bool interrupted = (flag && !flag->IsRunning()) ||
                             (TaskControlToken::Instance() &&
                              !TaskControlToken::Instance()->IsRunning());
    if (interrupted) {
      if (show_progress) {
        progress_bar.EndDisplay();
      }
      (void)worker_->Terminate(task_info->id, 1000);
      break;
    }
    if (show_progress) {
      UpdateTransferProgressBar_(&progress_bar, task_info, false);
    }
    all_finished = task_info->GetStatus() == TaskStatus::Finished;
    if (all_finished && show_progress) {
      UpdateTransferProgressBar_(&progress_bar, task_info, true);
      progress_bar.EndDisplay();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_interval_ms));
  }

  {
    std::unique_lock<std::mutex> lock(done_mtx);
    done_cv.wait(
        lock, [&]() { return remaining.load(std::memory_order_relaxed) <= 0; });
  }
  PrintTaskResult_(task_info);
  return task_info->GetResult();
}

/**
 * @brief Non-blocking transfer entry point.
 */
ECM AMDomain::transfer::AMTransferManager::transfer_async(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    std::shared_ptr<TaskControlToken> interrupt_flag) {
  bool has_resume = false;
  for (const auto &set : transfer_sets) {
    if (!set.resume) {
      continue;
    }
    has_resume = true;
    if (set.srcs.size() != 1 || set.dst.empty()) {
      return {EC::InvalidArg,
              "Resume transfer requires exactly one src and one dst"};
    }
  }
  if (has_resume && transfer_sets.size() != 1) {
    return {EC::InvalidArg, "Resume transfer requires a single transfer set"};
  }
  auto flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  auto [rcm, task_info] = PrepareTasks_(transfer_sets, quiet, flag);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (task_info) {
    task_info->control_token = std::make_shared<TaskControlToken>();
    if (interrupt_flag && !interrupt_flag->IsRunning()) {
      task_info->control_token->SetStatus(ControlSignal::Interrupt);
    }
  }
  return transfer_async(task_info, task_info ? task_info->control_token : flag);
}

/**
 * @brief Non-blocking transfer entry point for prepared task info.
 */
ECM AMDomain::transfer::AMTransferManager::transfer_async(
    const std::shared_ptr<TaskInfo> &task_info,
    std::shared_ptr<TaskControlToken> interrupt_flag) {
  if (!task_info) {
    return {EC::Success, ""};
  }

  if (!task_info->tasks || task_info->tasks->empty()) {
      return {EC::InvalidArg, "Task List is empty"};
  }

  task_info->control_token = std::make_shared<TaskControlToken>();
  if (interrupt_flag && !interrupt_flag->IsRunning()) {
    task_info->control_token->SetStatus(ControlSignal::Interrupt);
  }

  UserResultCallback user_callback =
      [this](const std::shared_ptr<TaskInfo> &finished_task_info) {
        PrintTaskResult_(finished_task_info);

        UserResultCallback user_cb;
        {
          std::lock_guard<std::mutex> lock(callback_mtx_);
          user_cb = user_result_cb_;
        }
        if (user_cb) {
          CallCallbackSafe(user_cb, finished_task_info);
        }
      };
  task_info->result_callback = BindResultCallback(std::move(user_callback));

  auto submit_rcm = worker_->Submit(task_info);
  if (submit_rcm.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(submit_rcm);
    return submit_rcm;
  }

  if (!task_info->quiet) {
    PrintTaskSubmit_(AMPromptManager::Instance(), task_info);
  }
  return {EC::Success, ""};
}

/**
 * @brief Prepare pooled task info from user transfer sets.
 */
std::pair<ECM, std::shared_ptr<TaskInfo>> AMDomain::transfer::AMTransferManager::PrepareTasks_(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    std::shared_ptr<TaskControlToken> flag) {
  if (transfer_sets.empty()) {
    return {ECM{EC::Success, ""}, nullptr};
  }

  auto &runtime_port =
      AMInterface::ApplicationAdapters::Runtime::ClientRuntimePortOrThrow();
  auto &lifecycle_port =
      AMInterface::ApplicationAdapters::Runtime::ClientLifecyclePortOrThrow();
  auto &path_port =
      AMInterface::ApplicationAdapters::Runtime::ClientPathPortOrThrow();
  auto &client_service =
      AMInterface::ApplicationAdapters::Runtime::ClientServiceOrThrow();

  std::vector<std::string> nickname_list = {};
  std::unordered_set<std::string> nickname_seen = {};
  bool local_used = false;

  auto record_nickname = [&](const std::string &nickname) {
    if (nickname.empty() ||
        AMDomain::host::HostManagerService::IsLocalNickname(nickname)) {
      local_used = true;
      return;
    }
    if (nickname_seen.insert(nickname).second) {
      nickname_list.push_back(nickname);
    }
  };

  for (const auto &set : transfer_sets) {
    auto dst_parsed =
        AMApplication::filesystem::PathResolutionService::ParsePathTarget(
            set.dst, runtime_port, path_port, nullptr);
    if (!isok(dst_parsed.rcm)) {
      return {dst_parsed.rcm, nullptr};
    }
    record_nickname(dst_parsed.target.nickname);
    for (const auto &src : set.srcs) {
      auto src_parsed =
          AMApplication::filesystem::PathResolutionService::ParsePathTarget(
              src, runtime_port, path_port, nullptr);
      if (!isok(src_parsed.rcm)) {
        return {src_parsed.rcm, nullptr};
      }
      record_nickname(src_parsed.target.nickname);
    }
  }

  std::vector<std::string> display_names = nickname_list;
  if (local_used) {
    display_names.emplace_back("local");
  }

  auto tasks_ptr = std::make_shared<TASKS>();
  for (const auto &set : transfer_sets) {
    auto dst_resolved =
        AMApplication::filesystem::PathResolutionService::ResolveReadyPath(
            set.dst, runtime_port, lifecycle_port, path_port, flag, 10000);
    if (!isok(dst_resolved.rcm) || !dst_resolved.client) {
      return {dst_resolved.rcm, nullptr};
    }
    const std::string dst_host = dst_resolved.target.nickname;
    const std::string dst_path = dst_resolved.abs_path;

    for (const auto &src : set.srcs) {
      if (flag && !flag->IsRunning()) {
        return {ECM{EC::Terminate, "Interrupted before task generation"},
                nullptr};
      }

      auto src_resolved =
          AMApplication::filesystem::PathResolutionService::ResolveReadyPath(
              src, runtime_port, lifecycle_port, path_port, flag, 10000);
      if (!isok(src_resolved.rcm) || !src_resolved.client) {
        return {src_resolved.rcm, nullptr};
      }
      const std::string src_host = src_resolved.target.nickname;
      const std::string src_path = src_resolved.abs_path;
      auto src_client = src_resolved.client;

      std::vector<std::string> src_paths = {src_path};
      if (HasWildcard_(src_path)) {
        auto matches =
            src_client->IOPort().find(src_path, SearchType::All, 5000);
        src_paths.clear();
        for (const auto &m : matches) {
          src_paths.push_back(m.path);
        }
        if (!quiet && !ConfirmWildcard_(matches, src_host, dst_host)) {
          return {ECM{EC::Terminate, "Wildcard transfer canceled by user"},
                  nullptr};
        }
      }

      for (const auto &resolved_src : src_paths) {
        auto [rcm, tasks] = AMWorkManager::LoadTasks(
            resolved_src, dst_path, runtime_port, lifecycle_port, src_host,
            dst_host, set.clone, set.overwrite, set.mkdir,
            set.ignore_special_file, set.resume, flag, 10000);
        if (rcm.first != EC::Success) {
          AMPromptManager::Instance().ErrorFormat(rcm);
          continue;
        }
        tasks_ptr->insert(tasks_ptr->end(), tasks.begin(), tasks.end());
      }
    }
  }

  DeduplicateTasks_(tasks_ptr.get());
  if (tasks_ptr->empty()) {
    return {ECM{EC::Success, ""}, nullptr};
  }

  auto task_info = worker_->CreateTaskInfo(tasks_ptr, client_service.PublicPool(),
                                           TransferCallback(), -1, quiet, -1);
  task_info->transfer_sets =
      std::make_shared<std::vector<UserTransferSet>>(std::move(transfer_sets));
  task_info->nicknames = std::move(display_names);
  return {ECM{EC::Success, ""}, task_info};
}

/**
 * @brief Resolve one task by identifier across runtime and history storage.
 */
std::shared_ptr<TaskInfo>
AMDomain::transfer::AMTransferManager::FindTask(const ID &task_id) const {
  return FindTaskById_(task_id);
}

/**
 * @brief Find a task by ID across pending, conducting, and history caches.
 */
std::shared_ptr<TaskInfo>
AMDomain::transfer::AMTransferManager::FindTaskById_(const ID &task_id) const {
  if (task_id.empty()) {
    return nullptr;
  }
  auto task_info = worker_->GetTask(task_id);
  if (task_info.first) {
    return task_info.first;
  }
  std::lock_guard<std::mutex> lock(history_mtx_);
  for (const auto &item : history_) {
    if (item && item->id == task_id) {
      return item;
    }
  }
  return nullptr;
}

/**
 * @brief Snapshot completed task history.
 */
std::vector<std::shared_ptr<TaskInfo>>
AMDomain::transfer::AMTransferManager::SnapshotHistory_() const {
  std::vector<std::shared_ptr<TaskInfo>> items;
  std::lock_guard<std::mutex> lock(history_mtx_);
  items.reserve(history_.size());
  for (const auto &task : history_) {
    if (task) {
      items.push_back(task);
    }
  }
  return items;
}

/**
 * @brief Parse an entry ID of the form "<task_id>:<index>" (1-based index).
 */
bool AMDomain::transfer::AMTransferManager::ParseEntryId_(const ID &entry_id, ID *task_id,
                                      size_t *entry_index) const {
  if (!task_id || !entry_index) {
    return false;
  }
  const size_t pos = entry_id.find(':');
  if (pos == std::string::npos || pos == 0 || pos + 1 >= entry_id.size()) {
    return false;
  }
  const std::string id_part = entry_id.substr(0, pos);
  const std::string index_part = entry_id.substr(pos + 1);
  try {
    size_t parsed = std::stoul(index_part);
    if (parsed == 0) {
      return false;
    }
    *task_id = id_part;
    *entry_index = parsed;
    return true;
  } catch (const std::exception &) {
    return false;
  }
}
