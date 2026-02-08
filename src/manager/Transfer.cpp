#include "AMManager/Transfer.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Path.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <exception>
#include <sstream>
#include <unordered_set>

namespace {
/**
 * @brief Parse a transfer path into nickname and path using client manager.
 *
 * Host config not found is treated as an error; missing clients are allowed
 * so that transfer can create them later.
 */
ECM ParseTransferPath(AMClientManager &client_manager, const std::string &input,
                      const std::shared_ptr<BaseClient> &client,
                      std::string *nickname, std::string *path) {
  auto [parsed_name, parsed_path, _client, rcm] =
      client_manager.ParsePath(input);
  if (rcm.first == EC::HostConfigNotFound) {
    return rcm;
  }
  std::string resolved_path = parsed_path;
  if (client) {
    resolved_path = client_manager.AbsPath(parsed_path, client);
  }
  if (nickname) {
    *nickname = parsed_name;
  }
  if (path) {
    *path = resolved_path;
  }
  return {EC::Success, ""};
}

/**
 * @brief Join strings with a separator.
 */
std::string JoinStrings_(const std::vector<std::string> &items,
                         const std::string &sep) {
  if (items.empty()) {
    return "";
  }
  std::ostringstream oss;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i > 0) {
      oss << sep;
    }
    oss << items[i];
  }
  return oss.str();
}

/**
 * @brief Format a unix timestamp as "HH:MM".
 */
std::string FormatTimeHM_(double timestamp) {
  if (timestamp <= 0.0) {
    return "-";
  }
  return FormatTime(static_cast<size_t>(timestamp), "%H:%M");
}

/**
 * @brief Format elapsed seconds into "XmYs" or "XhYmZs".
 */
std::string FormatElapsed_(double seconds) {
  const int64_t total = static_cast<int64_t>(std::max(0.0, seconds));
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

/**
 * @brief Print a task control result line.
 */
// void PrintTaskControlResult_(AMPromptManager &prompt,
//                                     const std::string &action,
//                                     const std::string &task_id,
//                                     const ECM &rcm) {
//   if (rcm.first == EC::Success) {
//     prompt.Print(AMStr::amfmt("✅ {} {}", action, task_id));
//     return;
//   }
//   prompt.Print(AMStr::amfmt("❌ {} {} : {}", action, task_id, rcm.second));
// }
} // namespace

/**
 * @brief Construct a task info printer bound to a prompt manager.
 */
TaskInfoPrint::TaskInfoPrint(AMPromptManager &prompt) : prompt_(prompt) {}

/**
 * @brief Print submit information for transfer_async.
 */
void TaskInfoPrint::TaskSubmitPrint(
    const std::shared_ptr<TaskInfo> &task_info) const {
  if (!task_info) {
    return;
  }
  const size_t file_num = task_info->tasks ? task_info->tasks->size() : 0;
  const size_t total_size =
      task_info->total_size.load(std::memory_order_relaxed);
  std::vector<std::string> nicknames = task_info->nicknames;
  std::string nickname_str = JoinStrings_(nicknames, " ");
  if (nickname_str.empty()) {
    nickname_str = "local";
  }
  prompt_.Print(AMStr::amfmt("ID: {}; FileNum: {}; TotalSize: {}; Clients: {}",
                             task_info->id, file_num, FormatSize(total_size),
                             nickname_str));
}

/**
 * @brief Print task result information after completion.
 */
void TaskInfoPrint::TaskResultPrint(
    const std::shared_ptr<TaskInfo> &task_info) const {
  if (!task_info) {
    return;
  }
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
    success = task_info->success_filenum.load(std::memory_order_relaxed);

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
          : AMStr::amfmt(" {}: {}", AM_ENUM_NAME(result.first), result.second);
  if (success) {
    prompt_.Print(AMStr::amfmt(
        "TaskResult  {} ID: {}; Files: {}/{}; Size: {}/{}; ThreadID: {};{}",
        prefix, task_id, success_num, filenum, FormatSize(transferred),
        FormatSize(total), thread_id, rcm_text));
    return;
  }
}

/**
 * @brief Show task status for quick queries.
 */
void TaskInfoPrint::Show(const std::shared_ptr<TaskInfo> &task_info,
                         const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  if (!task_info) {
    return;
  }

  const TaskStatus status = task_info->GetStatus();
  const std::string status_name = AM_ENUM_NAME(status);

  if (status == TaskStatus::Pending) {
    const size_t total =
        task_info->total_size.load(std::memory_order_relaxed);
    const int affinity =
        task_info->affinity_thread.load(std::memory_order_relaxed);
    const std::string submit_time =
        FormatTimeHM_(task_info->submit_time.load(std::memory_order_relaxed));
    prompt_.Print(AMStr::amfmt(
        "[{}] Status: {} TotalSize: {} AffinityThread: {} SubmitTime: {}",
        task_info->id, status_name, FormatSize(total), affinity, submit_time));
    return;
  }

  if (status == TaskStatus::Finished) {
    const size_t transferred =
        task_info->total_transferred_size.load(std::memory_order_relaxed);
    const size_t total =
        task_info->total_size.load(std::memory_order_relaxed);
    const int thread_id =
        task_info->OnWhichThread.load(std::memory_order_relaxed);
    const double start_time =
        task_info->start_time.load(std::memory_order_relaxed);
    const double finished_time =
        task_info->finished_time.load(std::memory_order_relaxed);
    const std::string elapsed = FormatElapsed_(finished_time - start_time);
    prompt_.Print(
        AMStr::amfmt("[{}] Status: {} {}/{} ThreadID: {} ElapsedTime: {}",
                     task_info->id, status_name, FormatSize(transferred),
                     FormatSize(total), thread_id, elapsed));
    return;
  }

  if (status == TaskStatus::Conducting && task_info->pd &&
      task_info->pd->is_pause()) {
    const size_t transferred =
        task_info->total_transferred_size.load(std::memory_order_relaxed);
    const size_t total =
        task_info->total_size.load(std::memory_order_relaxed);
    const int thread_id =
        task_info->OnWhichThread.load(std::memory_order_relaxed);
    const double start_time =
        task_info->start_time.load(std::memory_order_relaxed);
    const double elapsed_time = timenow() - start_time;
    const std::string elapsed = FormatElapsed_(elapsed_time);
    prompt_.Print(
        AMStr::amfmt("[{}] Status: {} {}/{} ThreadID: {} ElapsedTime: {}",
                     task_info->id, "Paused", FormatSize(transferred),
                     FormatSize(total), thread_id, elapsed));
    return;
  }

  AMProgressBar bar = AMConfigManager::Instance().CreateProgressBar(
      static_cast<int64_t>(
          task_info->total_size.load(std::memory_order_relaxed)),
      BuildTaskPrefix_(task_info));
  bar.SetStartTimeEpoch(
      task_info->start_time.load(std::memory_order_relaxed));
  bar.Print();
  const int refresh_ms = 300;
  while (true) {
    if (interrupt_flag && interrupt_flag->check()) {
      break;
    }
    const TaskStatus current_status = task_info->GetStatus();
    const size_t total =
        task_info->total_size.load(std::memory_order_relaxed);
    const size_t transferred =
        task_info->total_transferred_size.load(std::memory_order_relaxed);
    bar.SetTotal(static_cast<int64_t>(total));
    bar.SetProgress(static_cast<int64_t>(transferred));
    bar.SetPrefix(BuildTaskPrefix_(task_info));
    if (current_status == TaskStatus::Finished) {
      bar.Finish();
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
  }
  bar.EndDisplay();
}

/**
 * @brief Print multiple tasks in batch.
 */
void TaskInfoPrint::List(
    const std::vector<std::shared_ptr<TaskInfo>> &pending,
    const std::vector<std::shared_ptr<TaskInfo>> &finished,
    const std::vector<std::shared_ptr<TaskInfo>> &conducting,
    const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  for (const auto &task : pending) {
    Show(task, interrupt_flag);
  }
  for (const auto &task : finished) {
    Show(task, interrupt_flag);
  }

  if (conducting.empty()) {
    return;
  }

  // AMProgressBarGroup group(48);
  // group.Start();
  // std::vector<std::shared_ptr<AMProgressBar>> bars;
  // bars.reserve(conducting.size());
  // for (const auto &task : conducting) {
  //   auto bar = std::make_shared<AMProgressBar>(
  //       static_cast<int64_t>(task ? task->total_size.load(std::memory_order_relaxed) : 0),
  //       BuildTaskPrefix_(task));
  //   group.AddBar(bar);
  //   bars.push_back(bar);
  // }

  // const int refresh_ms = 100;
  // while (true) {
  //   if (interrupt_flag && interrupt_flag->check()) {
  //     break;
  //   }

  //   bool any_running = false;
  //   for (size_t i = 0; i < conducting.size(); ++i) {
  //     const auto &task = conducting[i];
  //     const auto &bar = bars[i];
  //     if (!task) {
  //       continue;
  //     }
  //     const size_t total = task->total_size.load(std::memory_order_relaxed);
  //     const size_t transferred = task->total_transferred_size.load(std::memory_order_relaxed);
  //     bar->SetTotal(static_cast<int64_t>(total));
  //     bar->SetProgress(static_cast<int64_t>(transferred));
  //     bar->SetPrefix(BuildTaskPrefix_(task));
  //     if (task->GetStatus() == TaskStatus::Finished) {
  //       bar->Finish();
  //     } else {
  //       any_running = true;
  //     }
  //   }

  //   if (!any_running) {
  //     break;
  //   }
  //   std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
  // }
  // group.Stop();
}

/**
 * @brief Print detailed task information.
 */
void TaskInfoPrint::Inspect(const std::shared_ptr<TaskInfo> &task_info,
                            bool show_task_entries,
                            bool show_transfer_sets) const {
  if (!task_info) {
    return;
  }

  const auto status_name =
      std::string(magic_enum::enum_name(task_info->GetStatus()));
  const std::string submit_time =
      task_info->submit_time.load(std::memory_order_relaxed) > 0.0
          ? FormatTime(static_cast<size_t>(
                task_info->submit_time.load(std::memory_order_relaxed)))
          : "-";
  const std::string start_time =
      task_info->start_time.load(std::memory_order_relaxed) > 0.0
          ? FormatTime(static_cast<size_t>(
                task_info->start_time.load(std::memory_order_relaxed)))
          : "-";
  const std::string finished_time =
      task_info->finished_time.load(std::memory_order_relaxed) > 0.0
          ? FormatTime(static_cast<size_t>(
                task_info->finished_time.load(std::memory_order_relaxed)))
          : "-";

  ECM rcm = task_info->GetResult();
  std::string rcm_name = std::string(magic_enum::enum_name(rcm.first));
  std::string rcm_text = rcm_name;
  if (!rcm.second.empty()) {
    rcm_text = AMStr::amfmt("{}: {}", rcm_name, rcm.second);
  }

  size_t files_num = task_info->tasks ? task_info->tasks->size() : 0;

  std::vector<std::string> client_names = task_info->nicknames;
  if (client_names.empty()) {
    client_names.emplace_back("local");
  }

  std::vector<std::pair<std::string, std::string>> fields = {
      {"id", task_info->id},
      {"status", status_name},
      {"submit_time", submit_time},
      {"start_time", start_time},
      {"finished_time", finished_time},
      {"rcm", rcm_text},
      {"total_transferred_size",
       FormatSize(task_info->total_transferred_size.load(
           std::memory_order_relaxed))},
      {"total_size", FormatSize(task_info->total_size.load(
                        std::memory_order_relaxed))},
      {"files_num", std::to_string(files_num)},
      {"quiet", task_info->quiet ? "true" : "false"},
      {"affinity_thread", std::to_string(task_info->affinity_thread.load(
                              std::memory_order_relaxed))},
      {"on_which_thread", std::to_string(task_info->OnWhichThread.load(
                             std::memory_order_relaxed))},
      {"buffer_size", std::to_string(task_info->buffer_size.load(
                         std::memory_order_relaxed))},
      {"client_names", JoinStrings_(client_names, ", ")}};

  size_t max_len = 0;
  for (const auto &field : fields) {
    max_len = std::max(max_len, field.first.size());
  }

  for (const auto &field : fields) {
    std::string label = field.first;
    if (label.size() < max_len) {
      label.append(max_len - label.size(), ' ');
    }
    prompt_.Print(AMStr::amfmt("{} : {}", label, field.second));
  }

  if (show_task_entries) {
    InspectTaskEntries(task_info);
  }
  if (show_transfer_sets) {
    InspectTransferSets(task_info);
  }
}

/**
 * @brief Print individual task entries inside task_info.
 */
void TaskInfoPrint::InspectTaskEntries(
    const std::shared_ptr<TaskInfo> &task_info) const {
  if (!task_info || !task_info->tasks) {
    return;
  }

  const auto &tasks = *task_info->tasks;
  for (size_t i = 0; i < tasks.size(); ++i) {
    const auto &task = tasks[i];
    prompt_.Print(AMStr::amfmt("[{}]", i + 1));
    prompt_.Print("");
    const std::string src_host =
        task.src_host.empty() ? "local" : task.src_host;
    const std::string dst_host =
        task.dst_host.empty() ? "local" : task.dst_host;
    prompt_.Print(AMStr::amfmt("src: {}@{}", src_host, task.src));
    prompt_.Print("");
    prompt_.Print(AMStr::amfmt("dst: {}@{}", dst_host, task.dst));
    prompt_.Print("");
    prompt_.Print(AMStr::amfmt("size: {}", FormatSize(task.size)));
    prompt_.Print("");
    prompt_.Print(
        AMStr::amfmt("transferred: {}", FormatSize(task.transferred)));
    if (task.IsFinished) {
      std::string rcm_name = std::string(magic_enum::enum_name(task.rcm.first));
      std::string rcm_text = rcm_name;
      if (!task.rcm.second.empty()) {
        rcm_text = AMStr::amfmt("{}: {}", rcm_name, task.rcm.second);
      }
      prompt_.Print("");
      prompt_.Print(AMStr::amfmt("rcm: {}", rcm_text));
    }
    if (i + 1 < tasks.size()) {
      prompt_.Print("");
    }
  }
}

/**
 * @brief Print original UserTransferSet settings for the task.
 */
void TaskInfoPrint::InspectTransferSets(
    const std::shared_ptr<TaskInfo> &task_info) const {
  if (!task_info || !task_info->transfer_sets) {
    return;
  }

  const auto &sets = *task_info->transfer_sets;
  const bool show_index = sets.size() > 1;
  for (size_t i = 0; i < sets.size(); ++i) {
    const auto &set = sets[i];
    if (show_index) {
      prompt_.Print(AMStr::amfmt("[{}]", i + 1));
      prompt_.Print("");
    }
    for (const auto &src : set.srcs) {
      prompt_.Print(src);
    }
    prompt_.Print("");
    prompt_.Print(AMStr::amfmt(" ->  {}", set.dst));
    prompt_.Print("");
    prompt_.Print(AMStr::amfmt("clone = {}", set.clone ? "true" : "false"));
    prompt_.Print(AMStr::amfmt("mkdir = {}", set.mkdir ? "true" : "false"));
    prompt_.Print(
        AMStr::amfmt("overwrite = {}", set.overwrite ? "true" : "false"));
    prompt_.Print(AMStr::amfmt("no special = {}",
                               set.ignore_special_file ? "true" : "false"));
    prompt_.Print(AMStr::amfmt("resume = {}", set.resume ? "true" : "false"));
    if (i + 1 < sets.size()) {
      prompt_.Print("");
    }
  }
}

/**
 * @brief Return the singleton transfer manager instance.
 */
AMTransferManager &AMTransferManager::Instance() {
  static AMTransferManager instance;
  return instance;
}

/**
 * @brief Construct a transfer manager using singleton managers.
 */
AMTransferManager::AMTransferManager()
    : config_(AMConfigManager::Instance()),
      client_manager_(AMClientManager::Instance(config_)),
      prompt_(AMPromptManager::Instance()), task_printer_(prompt_) {}

/**
 * @brief Set the public result callback wrapper for all task completions.
 */
void AMTransferManager::SetPublicResultCallback(PublicResultCallback cb) {
  std::lock_guard<std::mutex> lock(callback_mtx_);
  public_result_cb_ = std::move(cb);
}

/**
 * @brief Get a copy of transfer history (newest first).
 */
std::list<std::shared_ptr<TaskInfo>> AMTransferManager::GetHistory() const {
  std::lock_guard<std::mutex> lock(history_mtx_);
  return history_;
}

/**
 * @brief Check whether a path contains wildcard tokens.
 */
bool AMTransferManager::HasWildcard_(const std::string &path) {
  return path.find('*') != std::string::npos ||
         (path.find('<') != std::string::npos &&
          path.find('>') != std::string::npos);
}

/**
 * @brief Prompt the user to confirm matched wildcard results.
 */
bool AMTransferManager::ConfirmWildcard_(const std::vector<PathInfo> &matches,
                                         const std::string &src_host,
                                         const std::string &dst_host) {
  if (matches.empty()) {
    return false;
  }
  std::string host_name = src_host.empty() ? "local" : src_host;
  std::string dst_name = dst_host.empty() ? "local" : dst_host;
  prompt_.Print(AMStr::amfmt("Found {} paths to transfer",
                             std::to_string(matches.size())));

  std::vector<PathInfo> sorted = matches;
  std::sort(sorted.begin(), sorted.end(),
            [](const PathInfo &lhs, const PathInfo &rhs) {
              return lhs.type == PathType::DIR && rhs.type != PathType::DIR;
            });

  for (const auto &path : sorted) {
    if (path.type == PathType::DIR) {
      prompt_.Print(AMStr::amfmt("📁   {}@{}", host_name, path.path));
    } else {
      prompt_.Print(AMStr::amfmt("📑   {}@{}", host_name, path.path));
    }
  }

  std::string input;
  const std::string prompt = AMStr::amfmt(
      "Are you sure to transfer these paths to {}? (y/n): ", dst_name);
  if (!prompt_.Prompt(prompt, "", &input)) {
    return false;
  }
  std::string lowered = input;
  std::transform(
      lowered.begin(), lowered.end(), lowered.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (lowered != "y") {
    prompt_.Print("Transfer cancelled");
    return false;
  }
  return true;
}

/**
 * @brief Acquire or create a validated client for a nickname.
 */
std::pair<ECM, std::shared_ptr<BaseClient>>
AMTransferManager::AcquireClient_(const std::string &nickname,
                                  const std::shared_ptr<InterruptFlag> &flag) {
  if (flag && flag->check()) {
    return {ECM{EC::Terminate, "Interrupted during client preparation"},
            nullptr};
  }

  const std::string key = nickname.empty() ? "local" : nickname;
  {
    std::lock_guard<std::mutex> lock(idle_mtx_);
    auto it = idle_pool_.find(key);
    if (it != idle_pool_.end() && !it->second.empty()) {
      auto client = it->second.front();
      it->second.pop_front();
      return {ECM{EC::Success, ""}, client};
    }
  }

  auto created =
      client_manager_.AddClient(nickname, false, true, {}, flag, false);
  if (created.first.first != EC::Success || !created.second) {
    return created;
  }
  return {ECM{EC::Success, ""}, created.second};
}

/**
 * @brief Collect clients and build a maintainer for required nicknames.
 */
std::pair<ECM, std::shared_ptr<ClientMaintainer>>
AMTransferManager::CollectClients(const std::vector<std::string> &nicknames,
                                  const std::shared_ptr<InterruptFlag> &flag) {
  auto maintainer = std::make_shared<ClientMaintainer>(
      -1, ClientMaintainer::DisconnectCallback(),
      client_manager_.LocalClient());
  for (const auto &name : nicknames) {
    if (name.empty() || name == "local") {
      continue;
    }
    if (maintainer->GetHost(name)) {
      continue;
    }
    auto [rcm, client] = AcquireClient_(name, flag);
    if (rcm.first != EC::Success || !client) {
      ReturnClientsToIdle_(maintainer);
      return {rcm, nullptr};
    }
    maintainer->add_client(name, client);
  }

  return {ECM{EC::Success, ""}, maintainer};
}

/**
 * @brief Return all maintainer clients to the idle pool.
 */
void AMTransferManager::ReturnClientsToIdle_(
    const std::shared_ptr<ClientMaintainer> &maintainer) {
  if (!maintainer) {
    return;
  }
  std::lock_guard<std::mutex> lock(idle_mtx_);
  for (const auto &pair : maintainer->hosts) {
    if (!pair.second) {
      continue;
    }
    idle_pool_[pair.first].push_front(pair.second);
  }
}

TaskInfo::ResultCallback
AMTransferManager::BindResultCallback(UserResultCallback user_cb) {
  return [this, user_cb](std::shared_ptr<TaskInfo> task_info) {
    PublicResultCallback public_cb;
    {
      std::lock_guard<std::mutex> lock(callback_mtx_);
      public_cb = public_result_cb_;
    }
    this->ResultCallback(task_info, public_cb, user_cb);
  };
}

void AMTransferManager::ResultCallback(std::shared_ptr<TaskInfo> task_info,
                                       PublicResultCallback public_cb,
                                       UserResultCallback user_cb) {
  if (!task_info) {
    return;
  }
  task_printer_.TaskResultPrint(task_info);
  if (task_info->hostm) {
    ReturnClientsToIdle_(task_info->hostm);
    task_info->hostm.reset();
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
 * @brief Submit a transfer set into the cache pool.
 */
size_t
AMTransferManager::SubmitTransferSet(const UserTransferSet &transfer_set) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  cached_sets_.emplace_back(transfer_set);
  return cached_sets_.size() - 1;
}

/**
 * @brief Submit multiple transfer sets into the cache pool.
 */
std::vector<size_t> AMTransferManager::SubmitTransferSets(
    const std::vector<UserTransferSet> &transfer_sets) {
  std::vector<size_t> ids;
  ids.reserve(transfer_sets.size());
  std::lock_guard<std::mutex> lock(cache_mtx_);
  for (const auto &set : transfer_sets) {
    cached_sets_.emplace_back(set);
    ids.push_back(cached_sets_.size() - 1);
  }
  return ids;
}

/**
 * @brief Query a cached transfer set by ID.
 */
ECM AMTransferManager::QueryTransferSet(size_t set_index,
                                        UserTransferSet *out_set) const {
  if (!out_set) {
    return {EC::InvalidArg, "Output reciever is nullptr"};
  }
  std::lock_guard<std::mutex> lock(cache_mtx_);
  if (set_index >= cached_sets_.size()) {
    return {EC::IndexOutOfRange,
            AMStr::amfmt("Max is {}, but recieve {}", set_index,
                         cached_sets_.size() - 1)};
  }
  const auto &entry = cached_sets_[set_index];
  if (!entry.has_value()) {
    return {EC::TaskNotFound,
            AMStr::amfmt("Index {} is already dleted", set_index)};
  }
  *out_set = *entry;
  return {EC::Success, ""};
}

/**
 * @brief List all cached transfer set IDs.
 */
std::vector<size_t> AMTransferManager::ListTransferSetIds() const {
  std::vector<size_t> indices;
  std::lock_guard<std::mutex> lock(cache_mtx_);
  indices.reserve(cached_sets_.size());
  for (size_t i = 0; i < cached_sets_.size(); ++i) {
    if (cached_sets_[i].has_value()) {
      indices.push_back(i);
    }
  }
  return indices;
}

/**
 * @brief List task IDs across pending, conducting, and finished tasks.
 */
std::vector<AMTransferManager::ID> AMTransferManager::ListTaskIds() const {
  std::unordered_set<ID> seen;
  std::vector<ID> ids;

  auto add_id = [&seen, &ids](const ID &id) {
    if (id.empty()) {
      return;
    }
    if (seen.insert(id).second) {
      ids.push_back(id);
    }
  };

  auto pending = worker_.get_pending_tasks();
  for (const auto &task : pending) {
    if (task) {
      add_id(task->id);
    }
  }

  auto conducting = worker_.get_conducting_tasks();
  for (const auto &task : conducting) {
    if (task) {
      add_id(task->id);
    }
  }

  auto result_ids = worker_.get_result_ids();
  for (const auto &id : result_ids) {
    add_id(id);
  }

  {
    std::lock_guard<std::mutex> lock(history_mtx_);
    for (const auto &task : history_) {
      if (task) {
        add_id(task->id);
      }
    }
  }

  std::sort(ids.begin(), ids.end());
  return ids;
}

/**
 * @brief Get counts of pending and conducting tasks for prompt display.
 *
 * @param pending_count Output count of pending tasks (nullable).
 * @param conducting_count Output count of conducting tasks (nullable).
 */
void AMTransferManager::GetTaskCounts(size_t *pending_count,
                                      size_t *conducting_count) const {
  if (pending_count) {
    *pending_count = 0;
  }
  if (conducting_count) {
    *conducting_count = 0;
  }
  if (!pending_count && !conducting_count) {
    return;
  }

  const auto pending = worker_.get_pending_tasks();
  const auto conducting = worker_.get_conducting_tasks();
  if (pending_count) {
    *pending_count = pending.size();
  }
  if (conducting_count) {
    *conducting_count = conducting.size();
  }
}

/**
 * @brief Delete cached transfer sets by indices.
 */
size_t
AMTransferManager::DeleteTransferSets(const std::vector<size_t> &set_indices) {
  if (set_indices.empty()) {
    return 0;
  }
  const std::vector<size_t> unique_indices =
      UniqueTargetsKeepOrder(set_indices);

  size_t removed = 0;
  std::lock_guard<std::mutex> lock(cache_mtx_);
  std::string msg = "";
  for (size_t index : unique_indices) {
    if (index >= cached_sets_.size()) {
      msg =
          AMStr::amfmt("Get index {}, but max is ", index, cached_sets_.size());
      prompt_.ErrorFormat(ECM{EC::IndexOutOfRange, msg});
      continue;
    } else if (!cached_sets_[index].has_value()) {
      prompt_.ErrorFormat(
          ECM{EC::TaskNotFound,
              AMStr::amfmt("Index {} is already deleted", index)});
    }
    cached_sets_[index].reset();
    removed++;
  }
  return removed;
}

/**
 * @brief Clear all cached transfer sets.
 */
void AMTransferManager::ClearCachedTransferSets() {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  cached_sets_.clear();
}

/**
 * @brief Submit cached transfer sets as a task.
 */
ECM AMTransferManager::SubmitCachedTransferSets(
    bool quiet, const std::shared_ptr<InterruptFlag> &interrupt_flag,
    bool is_async) {
  std::vector<UserTransferSet> transfer_sets;
  {
    std::lock_guard<std::mutex> lock(cache_mtx_);
    transfer_sets.reserve(cached_sets_.size());
    for (const auto &entry : cached_sets_) {
      if (entry.has_value()) {
        transfer_sets.push_back(*entry);
      }
    }
  }

  if (transfer_sets.empty()) {
    std::string msg = "Cached transfer set is empty";
    prompt_.ErrorFormat(ECM{EC::InvalidArg, msg});
    return {EC::InvalidArg, msg};
  }

  if (!quiet) {
    auto temp = std::make_shared<TaskInfo>(true);
    temp->transfer_sets =
        std::make_shared<std::vector<UserTransferSet>>(transfer_sets);
    task_printer_.InspectTransferSets(temp);
    bool canceled = false;
    if (!prompt_.PromptYesNo("Submit cached transfer sets? (y/N): ",
                             &canceled)) {
      prompt_.Print(
          AMStr::amfmt("🚫  {}\n", config_.Format("Add Canceled", "abort")));
      return {EC::Terminate, "Task submission canceled"};
    }
  }

  ECM rcm = is_async ? transfer_async(transfer_sets, quiet, interrupt_flag)
                     : transfer(transfer_sets, quiet, interrupt_flag);
  if (rcm.first == EC::Success) {
    ClearCachedTransferSets();
  }
  prompt_.ErrorFormat(rcm);
  return rcm;
}

/**
 * @brief Show task status by ID using TaskInfoPrint.
 */
ECM AMTransferManager::Show(
    const ID &task_id, const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  auto task_info = FindTaskById_(task_id);
  if (!task_info) {
    return {EC::TaskNotFound, AMStr::amfmt("Task not found: {}", task_id)};
  }
  task_printer_.Show(task_info, interrupt_flag);
  return {EC::Success, ""};
}

/**
 * @brief List tasks by status using TaskInfoPrint.
 */
ECM AMTransferManager::List(
    bool pending, bool finished, bool conducting,
    const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  if (!pending && !finished && !conducting) {
    pending = true;
    finished = true;
    conducting = true;
  }

  std::vector<std::shared_ptr<TaskInfo>> pending_tasks;
  std::vector<std::shared_ptr<TaskInfo>> finished_tasks;
  std::vector<std::shared_ptr<TaskInfo>> conducting_tasks;

  if (pending) {
    pending_tasks = worker_.get_pending_tasks();
  }
  if (finished) {
    finished_tasks = SnapshotHistory_();
  }
  if (conducting) {
    conducting_tasks = worker_.get_conducting_tasks();
  }

  task_printer_.List(pending_tasks, finished_tasks, conducting_tasks,
                     interrupt_flag);
  return {EC::Success, ""};
}

/**
 * @brief Inspect a task by ID.
 */
ECM AMTransferManager::Inspect(const ID &task_id, bool show_sets,
                               bool show_entries) const {
  auto task_info = FindTaskById_(task_id);
  if (!task_info) {
    return {EC::TaskNotFound, AMStr::amfmt("Task ID not found: {}", task_id)};
  }
  task_printer_.Inspect(task_info, show_entries, show_sets);
  return {EC::Success, ""};
}

/**
 * @brief Inspect only transfer sets for a task by ID.
 */
ECM AMTransferManager::InspectTransferSets(const ID &task_id) const {
  auto task_info = FindTaskById_(task_id);
  if (!task_info) {
    return {EC::TaskNotFound, AMStr::amfmt("Task ID not found: {}", task_id)};
  }
  task_printer_.InspectTransferSets(task_info);
  return {EC::Success, ""};
}

/**
 * @brief Inspect only task entries for a task by ID.
 */
ECM AMTransferManager::InspectTaskEntries(const ID &task_id) const {
  auto task_info = FindTaskById_(task_id);
  if (!task_info) {
    return {EC::TaskNotFound, AMStr::amfmt("Task ID not found: {}", task_id)};
  }
  task_printer_.InspectTaskEntries(task_info);
  return {EC::Success, ""};
}

/**
 * @brief Inspect a cached user transfer set by cache ID.
 */
ECM AMTransferManager::QueryCachedUserSet(size_t set_index) const {
  UserTransferSet transfer_set;
  ECM rcm = QueryTransferSet(set_index, &transfer_set);
  if (rcm.first != EC::Success) {
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  auto temp = std::make_shared<TaskInfo>(true);
  temp->transfer_sets = std::make_shared<std::vector<UserTransferSet>>(
      std::vector<UserTransferSet>{transfer_set});
  task_printer_.InspectTransferSets(temp);
  return {EC::Success, ""};
}

/**
 * @brief Inspect a single task entry by entry ID.
 */
ECM AMTransferManager::QuerySetEntry(const ID &entry_id) const {
  ID task_id;
  size_t entry_index = 0;
  if (!ParseEntryId_(entry_id, &task_id, &entry_index)) {
    return {EC::InvalidArg,
            "Entry ID format invalid (expected <task_id>:<index>)"};
  }

  auto task_info = FindTaskById_(task_id);
  if (!task_info || !task_info->tasks) {
    return {EC::InvalidArg, AMStr::amfmt("Task not found: {}", task_id)};
  }

  if (entry_index == 0 || entry_index > task_info->tasks->size()) {
    return {EC::InvalidArg,
            AMStr::amfmt("Entry index out of range: {}", entry_index)};
  }

  const auto &task = task_info->tasks->at(entry_index - 1);
  prompt_.Print(AMStr::amfmt("[{}]", entry_index));
  prompt_.Print("");
  const std::string src_host = task.src_host.empty() ? "local" : task.src_host;
  const std::string dst_host = task.dst_host.empty() ? "local" : task.dst_host;
  prompt_.Print(AMStr::amfmt("src: {}@{}", src_host, task.src));
  prompt_.Print("");
  prompt_.Print(AMStr::amfmt("dst: {}@{}", dst_host, task.dst));
  prompt_.Print("");
  prompt_.Print(AMStr::amfmt("size: {}", FormatSize(task.size)));
  prompt_.Print("");
  prompt_.Print(AMStr::amfmt("transferred: {}", FormatSize(task.transferred)));
  if (task.IsFinished) {
    std::string rcm_name = std::string(magic_enum::enum_name(task.rcm.first));
    std::string rcm_text = rcm_name;
    if (!task.rcm.second.empty()) {
      rcm_text = AMStr::amfmt("{}: {}", rcm_name, task.rcm.second);
    }
    prompt_.Print("");
    prompt_.Print(AMStr::amfmt("rcm: {}", rcm_text));
  }
  return {EC::Success, ""};
}

/**
 * @brief Terminate a running task by ID.
 */
ECM AMTransferManager::Terminate(const ID &task_id, int timeout_ms) {
  auto result = worker_.terminate(task_id, timeout_ms);
  if (!result.first) {
    if (result.second.first != EC::Success) {
      if (result.second.second.empty()) {
        prompt_.ErrorFormat(result.second);
      } else {
        prompt_.ErrorFormat(result.second);
      }
    }
    return result.second;
  }
  if (result.second.first != EC::Success) {
    prompt_.ErrorFormat(result.second);
    return result.second;
  } else if (!result.second.second.empty()) {
    prompt_.Print(result.second.second);
  }
  return result.second;
}

/**
 * @brief Pause a running task by ID.
 */
ECM AMTransferManager::Pause(const ID &task_id) {
  ECM rcm = worker_.pause(task_id);
  if (rcm.first != EC::Success) {
    if (rcm.second.empty()) {
      prompt_.ErrorFormat(rcm);
    } else if (!rcm.second.empty()) {
      prompt_.Print(rcm.second);
    }
  }
  return rcm;
}

/**
 * @brief Resume a paused task by ID.
 */
ECM AMTransferManager::Resume(const ID &task_id) {
  ECM rcm = worker_.resume(task_id);
  if (rcm.first != EC::Success) {
    if (rcm.second.empty()) {
      prompt_.ErrorFormat(rcm);
    } else if (!rcm.second.empty()) {
      prompt_.Print(rcm.second);
    }
  }
  return rcm;
}

/**
 * @brief Terminate tasks in batch by IDs.
 */
ECM AMTransferManager::Terminate(const std::vector<ID> &task_ids,
                                 int timeout_ms) {
  ECM last = {EC::Success, ""};
  ECM rcm = {EC::Success, ""};
  for (const auto &id : task_ids) {
    rcm = Terminate(id, timeout_ms);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Pause tasks in batch by IDs.
 */
ECM AMTransferManager::Pause(const std::vector<ID> &task_ids) {
  ECM last = {EC::Success, ""};
  ECM rcm = {EC::Success, ""};
  for (const auto &id : task_ids) {
    rcm = Pause(id);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Resume tasks in batch by IDs.
 */
ECM AMTransferManager::Resume(const std::vector<ID> &task_ids) {
  ECM last = {EC::Success, ""};
  ECM rcm = {EC::Success, ""};
  for (const auto &id : task_ids) {
    rcm = Resume(id);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Retry a completed task by rebuilding failed entries.
 */
ECM AMTransferManager::retry(const ID &task_id, bool is_async, bool quiet,
                             const std::vector<int> &indices) {

  auto original = FindTaskById_(task_id);
  if (!original || !original->tasks) {
    ECM rcm = {EC::TaskNotFound, AMStr::amfmt("Task not found: {}", task_id)};
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  const TaskStatus status = original->GetStatus();
  if (status != TaskStatus::Finished) {
    const std::string status_name = std::string(magic_enum::enum_name(status));
    ECM rcm = {EC::InvalidArg, AMStr::amfmt("Task not finished: {} (status {})",
                                            task_id, status_name)};
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  const size_t total_tasks = original->tasks->size();
  std::vector<size_t> selected_indices;
  std::vector<int> invalid_indices;

  if (!indices.empty()) {
    std::unordered_set<size_t> seen;
    selected_indices.reserve(indices.size());
    for (int idx : indices) {
      if (idx <= 0 || static_cast<size_t>(idx) > total_tasks) {
        invalid_indices.push_back(idx);
        continue;
      }
      size_t pos = static_cast<size_t>(idx - 1);
      if (seen.insert(pos).second) {
        selected_indices.push_back(pos);
      }
    }
    if (!invalid_indices.empty()) {
      std::vector<std::string> invalid_text;
      invalid_text.reserve(invalid_indices.size());
      for (int idx : invalid_indices) {
        invalid_text.push_back(std::to_string(idx));
      }
      prompt_.Print(AMStr::amfmt("Warning: invalid retry indices ignored: {}",
                                 JoinStrings_(invalid_text, ", ")));
    }
    if (selected_indices.empty()) {
      ECM rcm = {EC::InvalidArg, "No valid task indices to retry"};
      prompt_.ErrorFormat(rcm);
      return {EC::InvalidArg, "No valid task indices to retry"};
    }
  }

  auto tasks_ptr = std::make_shared<TASKS>();
  auto append_task = [&](const TransferTask &task) {
    if (task.rcm.first == EC::Success) {
      return;
    }
    TransferTask copy = task;
    copy.IsFinished = false;
    copy.rcm = {EC::Success, ""};
    tasks_ptr->push_back(std::move(copy));
  };

  if (indices.empty()) {
    tasks_ptr->reserve(total_tasks);
    for (const auto &task : *original->tasks) {
      append_task(task);
    }
  } else {
    tasks_ptr->reserve(selected_indices.size());
    for (size_t idx : selected_indices) {
      append_task(original->tasks->at(idx));
    }
  }

  if (tasks_ptr->empty()) {
    prompt_.Print("retry: all selected tasks already succeeded");
    return {EC::Success, ""};
  }

  std::vector<std::string> nickname_list;
  std::unordered_set<std::string> nickname_seen;
  bool local_used = false;
  auto record_nickname = [&](const std::string &name) {
    if (name.empty() || name == "local") {
      local_used = true;
      return;
    }
    if (nickname_seen.insert(name).second) {
      nickname_list.push_back(name);
    }
  };
  for (const auto &task : *tasks_ptr) {
    record_nickname(task.src_host);
    record_nickname(task.dst_host);
  }

  std::vector<std::string> display_names = nickname_list;
  if (local_used || display_names.empty()) {
    display_names.push_back("local");
  }

  auto [host_rcm, hostm] = CollectClients(nickname_list, nullptr);
  if (host_rcm.first != EC::Success || !hostm) {
    prompt_.ErrorFormat(host_rcm);
    return host_rcm;
  }

  const ssize_t buffer_size =
      original->buffer_size.load(std::memory_order_relaxed);
  const int affinity_thread =
      original->affinity_thread.load(std::memory_order_relaxed);
  auto task_info = worker_.cre_taskinfo(tasks_ptr, hostm, original->callback,
                                        buffer_size, quiet, affinity_thread);
  if (original->transfer_sets) {
    task_info->transfer_sets = original->transfer_sets;
  }
  task_info->nicknames = std::move(display_names);

  if (is_async) {
    return transfer_async(task_info);
  }
  return transfer(task_info);
}

/**
 * @brief Blocking transfer entry point.
 */
ECM AMTransferManager::transfer(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    const std::shared_ptr<InterruptFlag> &interrupt_flag) {
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
  auto flag =
      interrupt_flag ? interrupt_flag : std::make_shared<InterruptFlag>();
  auto [rcm, task_info] = PrepareTasks_(transfer_sets, quiet, flag);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return transfer(task_info, flag);
}

/**
 * @brief Blocking transfer entry point for prepared task info.
 */
ECM AMTransferManager::transfer(
    const std::shared_ptr<TaskInfo> &task_info,
    const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  if (!task_info) {
    return {EC::Success, ""};
  }

  if (!task_info->tasks || task_info->tasks->empty()) {
    if (task_info->hostm) {
      ReturnClientsToIdle_(task_info->hostm);
      task_info->hostm.reset();
    }
    return {EC::Success, ""};
  }

  auto flag =
      interrupt_flag ? interrupt_flag : std::make_shared<InterruptFlag>();
  const int refresh_interval_ms = config_.ResolveRefreshIntervalMs();

  std::mutex done_mtx;
  std::condition_variable done_cv;
  std::atomic<int> remaining(1);

  UserResultCallback user_callback = [this, &remaining, &done_cv, &done_mtx](
                                         std::shared_ptr<TaskInfo> task_info) {
    if (task_info) {
      task_printer_.TaskResultPrint(task_info);
    }

    UserResultCallback user_cb;
    {
      std::lock_guard<std::mutex> lock(callback_mtx_);
      user_cb = user_result_cb_;
    }
    if (user_cb) {
      CallCallbackSafe(user_cb, task_info);
    }

    --remaining;
    std::lock_guard<std::mutex> lock(done_mtx);
    done_cv.notify_all();
  };

  task_info->result_callback = BindResultCallback(std::move(user_callback));

  auto submit_rcm = worker_.submit(task_info);
  if (submit_rcm.first != EC::Success) {
    prompt_.ErrorFormat(submit_rcm);
    if (task_info->hostm) {
      ReturnClientsToIdle_(task_info->hostm);
      task_info->hostm.reset();
    }
    return submit_rcm;
  }

  bool all_finished = false;
  while (!all_finished) {
    if (flag && flag->check()) {
      (void)worker_.terminate(task_info->id, 1000);
      return {EC::Terminate, "Transfer interrupted during progress polling"};
    }
    all_finished = task_info->GetStatus() == TaskStatus::Finished;
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_interval_ms));
  }

  {
    std::unique_lock<std::mutex> lock(done_mtx);
    done_cv.wait(lock, [&]() {
      return remaining.load(std::memory_order_relaxed) <= 0;
    });
  }
  return task_info->GetResult();
}

/**
 * @brief Non-blocking transfer entry point.
 */
ECM AMTransferManager::transfer_async(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    const std::shared_ptr<InterruptFlag> &interrupt_flag) {
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
  auto flag =
      interrupt_flag ? interrupt_flag : std::make_shared<InterruptFlag>();
  auto [rcm, task_info] = PrepareTasks_(transfer_sets, quiet, flag);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return transfer_async(task_info, flag);
}

/**
 * @brief Non-blocking transfer entry point for prepared task info.
 */
ECM AMTransferManager::transfer_async(
    const std::shared_ptr<TaskInfo> &task_info,
    const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  (void)interrupt_flag;
  if (!task_info) {
    return {EC::Success, ""};
  }

  if (!task_info->tasks || task_info->tasks->empty()) {
    if (task_info->hostm) {
      ReturnClientsToIdle_(task_info->hostm);
      task_info->hostm.reset();
    }
    return {EC::InvalidArg, "Task List is empty"};
  }

  task_info->result_callback = BindResultCallback({});

  auto submit_rcm = worker_.submit(task_info);
  if (submit_rcm.first != EC::Success) {
    prompt_.ErrorFormat(submit_rcm);
    if (task_info->hostm) {
      ReturnClientsToIdle_(task_info->hostm);
      task_info->hostm.reset();
    }
    return submit_rcm;
  }

  if (!task_info->quiet) {
    task_printer_.TaskSubmitPrint(task_info);
  }
  return {EC::Success, ""};
}

/**
 * @brief Prepare host maintainer and TaskInfo from user transfer sets.
 */
std::pair<ECM, std::shared_ptr<TaskInfo>> AMTransferManager::PrepareTasks_(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    const std::shared_ptr<InterruptFlag> &flag) {
  if (transfer_sets.empty()) {
    return {ECM{EC::Success, ""}, nullptr};
  }

  std::vector<std::string> nickname_list = {};
  std::unordered_set<std::string> nickname_seen = {};
  bool local_used = false;

  for (const auto &set : transfer_sets) {
    std::string dst_host;
    std::string dst_path;
    auto dst_rcm = ParseTransferPath(client_manager_, set.dst, nullptr,
                                     &dst_host, &dst_path);
    if (dst_rcm.first != EC::Success) {
      return {dst_rcm, nullptr};
    }
    if (dst_host.empty() || AMStr::lowercase(dst_host) == "local") {
      local_used = true;
    } else if (nickname_seen.insert(dst_host).second) {
      nickname_list.push_back(dst_host);
    }
    for (const auto &src : set.srcs) {
      std::string src_host;
      std::string src_path;
      auto src_rcm = ParseTransferPath(client_manager_, src, nullptr, &src_host,
                                       &src_path);
      if (src_rcm.first != EC::Success) {
        return {src_rcm, nullptr};
      }
      if (src_host.empty() || AMStr::lowercase(src_host) == "local") {
        local_used = true;
      } else if (nickname_seen.insert(src_host).second) {
        nickname_list.push_back(src_host);
      }
    }
  }

  std::vector<std::string> display_names = nickname_list;
  if (local_used) {
    display_names.push_back("local");
  }

  auto [host_rcm, hostm] = CollectClients(nickname_list, flag);
  if (host_rcm.first != EC::Success || !hostm) {
    return {host_rcm, nullptr};
  }

  auto tasks_ptr = std::make_shared<TASKS>();
  for (const auto &set : transfer_sets) {
    std::string dst_host;
    std::string dst_path;
    auto dst_parse = ParseTransferPath(client_manager_, set.dst, nullptr,
                                       &dst_host, &dst_path);
    if (dst_parse.first != EC::Success) {
      ReturnClientsToIdle_(hostm);
      return {dst_parse, nullptr};
    }
    auto dst_client =
        dst_host.empty() ? hostm->local_client : hostm->GetHost(dst_host);
    if (!dst_client) {
      ReturnClientsToIdle_(hostm);
      return {ECM{EC::ClientNotFound, "Destination client not available"},
              nullptr};
    }
    auto dst_rcm = ParseTransferPath(client_manager_, set.dst, dst_client,
                                     &dst_host, &dst_path);
    if (dst_rcm.first != EC::Success) {
      ReturnClientsToIdle_(hostm);
      return {dst_rcm, nullptr};
    }
    for (const auto &src : set.srcs) {
      if (flag && flag->check()) {
        ReturnClientsToIdle_(hostm);
        return {ECM{EC::Terminate, "Interrupted before task generation"},
                nullptr};
      }

      std::string src_host;
      std::string src_path;
      auto src_parse = ParseTransferPath(client_manager_, src, nullptr,
                                         &src_host, &src_path);
      if (src_parse.first != EC::Success) {
        ReturnClientsToIdle_(hostm);
        return {src_parse, nullptr};
      }
      auto src_client =
          src_host.empty() ? hostm->local_client : hostm->GetHost(src_host);
      if (!src_client) {
        ReturnClientsToIdle_(hostm);
        return {ECM{EC::ClientNotFound, "Source client not available"},
                nullptr};
      }
      auto src_rcm = ParseTransferPath(client_manager_, src, src_client,
                                       &src_host, &src_path);
      if (src_rcm.first != EC::Success) {
        ReturnClientsToIdle_(hostm);
        return {src_rcm, nullptr};
      }

      std::vector<std::string> src_paths = {src_path};
      if (HasWildcard_(src_path)) {
        auto matches = src_client->find(src_path, SearchType::All, flag, 5000);
        src_paths.clear();
        for (const auto &m : matches) {
          src_paths.push_back(m.path);
        }
        if (!quiet && !ConfirmWildcard_(matches, src_host, dst_host)) {
          ReturnClientsToIdle_(hostm);
          return {ECM{EC::Terminate, "Wildcard transfer canceled by user"},
                  nullptr};
        }
      }

      for (const auto &resolved_src : src_paths) {
        auto [rcm, tasks] = AMWorkManager::load_tasks(
            resolved_src, dst_path, hostm, src_host, dst_host, set.clone,
            set.overwrite, set.mkdir, set.ignore_special_file, set.resume, flag,
            10000);
        if (rcm.first != EC::Success) {
          prompt_.ErrorFormat(rcm);
          continue;
        }
        tasks_ptr->insert(tasks_ptr->end(), tasks.begin(), tasks.end());
      }
    }
  }

  DeduplicateTasks_(tasks_ptr.get());
  if (tasks_ptr->empty()) {
    ReturnClientsToIdle_(hostm);
    return {ECM{EC::Success, ""}, nullptr};
  }

  auto task_info =
      worker_.cre_taskinfo(tasks_ptr, hostm, TransferCallback(), -1, quiet, -1);
  task_info->transfer_sets =
      std::make_shared<std::vector<UserTransferSet>>(std::move(transfer_sets));
  task_info->nicknames = std::move(display_names);
  return {ECM{EC::Success, ""}, task_info};
}

/**
 * @brief Find a task by ID across pending, conducting, and history caches.
 */
std::shared_ptr<TaskInfo>
AMTransferManager::FindTaskById_(const ID &task_id) const {
  if (task_id.empty()) {
    return nullptr;
  }
  auto task_info = worker_.get_task(task_id);
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
AMTransferManager::SnapshotHistory_() const {
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
bool AMTransferManager::ParseEntryId_(const ID &entry_id, ID *task_id,
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
