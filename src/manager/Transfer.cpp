#include "AMManager/Transfer.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/Path.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include <algorithm>
#include <cctype>
#include <exception>
#include <iomanip>
#include <sstream>
#include <unordered_set>

/**
 * @brief Parse a transfer path into nickname and path using client manager.
 *
 * Host config not found is treated as an error; missing clients are allowed
 * so that transfer can create them later.
 */
static ECM ParseTransferPath(AMClientManager &client_manager,
                             const std::string &input,
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
static std::string JoinStrings_(const std::vector<std::string> &items,
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
static std::string FormatTimeHM_(double timestamp) {
  if (timestamp <= 0.0) {
    return "-";
  }
  return FormatTime(static_cast<uint64_t>(timestamp), "%H:%M");
}

/**
 * @brief Format elapsed seconds into "XmYs" or "XhYmZs".
 */
static std::string FormatElapsed_(double seconds) {
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
 * @brief Build a progress bar prefix from the current task info.
 */
static std::string
BuildTaskPrefix_(const std::shared_ptr<TaskInfo> &task_info) {
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
static void PrintTaskControlResult_(AMPromptManager &prompt,
                                    const std::string &action,
                                    const std::string &task_id,
                                    const ECM &rcm) {
  if (rcm.first == EC::Success) {
    prompt.Print(AMStr::amfmt("✅ {} {}", action, task_id));
    return;
  }
  prompt.Print(AMStr::amfmt("❌ {} {} : {}", action, task_id, rcm.second));
}

/**
 * @brief Construct a task info printer bound to a prompt manager.
 */
TaskInfoPrint::TaskInfoPrint(AMPromptManager &prompt) : prompt_(prompt) {}

/**
 * @brief Print submit information for transfer_async.
 */
void TaskInfoPrint::TaskSubmitPrint(
    const std::shared_ptr<TaskInfo> &task_info,
    const ClientMaintainer &client_maintainer) const {
  if (!task_info) {
    return;
  }
  const size_t file_num = task_info->tasks ? task_info->tasks->size() : 0;
  const uint64_t total_size = task_info->total_size.load();
  std::vector<std::string> nicknames = client_maintainer.get_nicknames();
  std::string nickname_str = JoinStrings_(nicknames, ", ");
  if (nickname_str.empty()) {
    nickname_str = "local";
  }
  prompt_.Print(AMStr::amfmt(
      "Submit ID: [{}] FileNum: {} TotalSize: {} Clients: {}", task_info->id,
      file_num, AMClientManager::FormatSize(total_size), nickname_str));
}

/**
 * @brief Print task result information after completion.
 */
void TaskInfoPrint::TaskResultPrint(
    const std::shared_ptr<TaskInfo> &task_info) const {
  if (!task_info || task_info->quiet) {
    return;
  }
  const uint64_t transferred = task_info->total_transferred_size.load();
  const uint64_t total = task_info->total_size.load();
  const int thread_id = task_info->OnWhichThread.load();

  ECM result = task_info->GetResult();
  bool success = result.first == EC::Success;
  if (success && task_info->tasks) {
    for (const auto &task : *task_info->tasks) {
      if (task.rcm.first != EC::Success) {
        result = task.rcm;
        success = false;
      }
    }
  }

  const std::string prefix = success ? "✅" : "❌";
  if (success) {
    prompt_.Print(AMStr::amfmt("{} [{}] {}/{} ThreadID: {}", prefix,
                               task_info->id,
                               AMClientManager::FormatSize(transferred),
                               AMClientManager::FormatSize(total), thread_id));
    return;
  }

  std::string rcm_name = std::string(magic_enum::enum_name(result.first));
  std::string rcm_text = rcm_name;
  if (!result.second.empty()) {
    rcm_text = AMStr::amfmt("{}: {}", rcm_name, result.second);
  }
  prompt_.Print(
      AMStr::amfmt("{} [{}] {}/{} ThreadID: {} {}", prefix, task_info->id,
                   AMClientManager::FormatSize(transferred),
                   AMClientManager::FormatSize(total), thread_id, rcm_text));
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
  const std::string status_name = std::string(magic_enum::enum_name(status));

  if (status == TaskStatus::Pending) {
    const uint64_t total = task_info->total_size.load();
    const int affinity = task_info->affinity_thread.load();
    const std::string submit_time =
        FormatTimeHM_(task_info->submit_time.load());
    prompt_.Print(AMStr::amfmt(
        "[{}] Status: {} TotalSize: {} AffinityThread: {} SubmitTime: {}",
        task_info->id, status_name, AMClientManager::FormatSize(total),
        affinity, submit_time));
    return;
  }

  if (status == TaskStatus::Finished) {
    const uint64_t transferred = task_info->total_transferred_size.load();
    const uint64_t total = task_info->total_size.load();
    const int thread_id = task_info->OnWhichThread.load();
    const double start_time = task_info->start_time.load();
    const double finished_time = task_info->finished_time.load();
    const std::string elapsed = FormatElapsed_(finished_time - start_time);
    prompt_.Print(AMStr::amfmt(
        "[{}] Status: {} {}/{} ThreadID: {} ElapsedTime: {}", task_info->id,
        status_name, AMClientManager::FormatSize(transferred),
        AMClientManager::FormatSize(total), thread_id, elapsed));
    return;
  }

  AMProgressBarGroup group(48);
  group.Start();
  auto bar = std::make_shared<AMProgressBar>(
      static_cast<int64_t>(task_info->total_size.load()),
      BuildTaskPrefix_(task_info));
  group.AddBar(bar);

  const int refresh_ms = 100;
  while (true) {
    if (interrupt_flag && interrupt_flag->check()) {
      break;
    }
    const TaskStatus current_status = task_info->GetStatus();
    const uint64_t total = task_info->total_size.load();
    const uint64_t transferred = task_info->total_transferred_size.load();
    bar->SetTotal(static_cast<int64_t>(total));
    bar->SetProgress(static_cast<int64_t>(transferred));
    bar->SetPrefix(BuildTaskPrefix_(task_info));
    if (current_status == TaskStatus::Finished) {
      bar->Finish();
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
  }
  group.Stop();
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

  AMProgressBarGroup group(48);
  group.Start();
  std::vector<std::shared_ptr<AMProgressBar>> bars;
  bars.reserve(conducting.size());
  for (const auto &task : conducting) {
    auto bar = std::make_shared<AMProgressBar>(
        static_cast<int64_t>(task ? task->total_size.load() : 0),
        BuildTaskPrefix_(task));
    group.AddBar(bar);
    bars.push_back(bar);
  }

  const int refresh_ms = 100;
  while (true) {
    if (interrupt_flag && interrupt_flag->check()) {
      break;
    }

    bool any_running = false;
    for (size_t i = 0; i < conducting.size(); ++i) {
      const auto &task = conducting[i];
      const auto &bar = bars[i];
      if (!task) {
        continue;
      }
      const uint64_t total = task->total_size.load();
      const uint64_t transferred = task->total_transferred_size.load();
      bar->SetTotal(static_cast<int64_t>(total));
      bar->SetProgress(static_cast<int64_t>(transferred));
      bar->SetPrefix(BuildTaskPrefix_(task));
      if (task->GetStatus() == TaskStatus::Finished) {
        bar->Finish();
      } else {
        any_running = true;
      }
    }

    if (!any_running) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_ms));
  }
  group.Stop();
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
      task_info->submit_time.load() > 0.0
          ? FormatTime(static_cast<uint64_t>(task_info->submit_time.load()))
          : "-";
  const std::string start_time =
      task_info->start_time.load() > 0.0
          ? FormatTime(static_cast<uint64_t>(task_info->start_time.load()))
          : "-";
  const std::string finished_time =
      task_info->finished_time.load() > 0.0
          ? FormatTime(static_cast<uint64_t>(task_info->finished_time.load()))
          : "-";

  ECM rcm = task_info->GetResult();
  std::string rcm_name = std::string(magic_enum::enum_name(rcm.first));
  std::string rcm_text = rcm_name;
  if (!rcm.second.empty()) {
    rcm_text = AMStr::amfmt("{}: {}", rcm_name, rcm.second);
  }

  size_t files_num = task_info->tasks ? task_info->tasks->size() : 0;

  std::vector<std::string> client_names;
  if (auto hostm = task_info->hostm.lock()) {
    client_names = hostm->get_nicknames();
  }
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
       AMClientManager::FormatSize(task_info->total_transferred_size.load())},
      {"total_size", AMClientManager::FormatSize(task_info->total_size.load())},
      {"files_num", std::to_string(files_num)},
      {"quiet", task_info->quiet ? "true" : "false"},
      {"affinity_thread", std::to_string(task_info->affinity_thread.load())},
      {"on_which_thread", std::to_string(task_info->OnWhichThread.load())},
      {"buffer_size", std::to_string(task_info->buffer_size.load())},
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
    prompt_.Print(
        AMStr::amfmt("size: {}", AMClientManager::FormatSize(task.size)));
    prompt_.Print("");
    prompt_.Print(AMStr::amfmt("transferred: {}",
                               AMClientManager::FormatSize(task.transferred)));
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
    if (i + 1 < sets.size()) {
      prompt_.Print("");
    }
  }
}

/**
 * @brief Prepared task bundle used during transfer setup.
 */
struct AMTransferManager::PreparedTasks {
  std::shared_ptr<ClientMaintainer> hostm;
  std::shared_ptr<TASKS> tasks;
  std::vector<std::shared_ptr<BaseClient>> clients;
  std::vector<std::string> client_keys;
};

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
 * @brief Set a custom result callback invoked after the default callback.
 */
void AMTransferManager::SetResultCallback(UserResultCallback cb) {
  std::lock_guard<std::mutex> lock(callback_mtx_);
  user_result_cb_ = std::move(cb);
}

/**
 * @brief Get a copy of transfer history (newest first).
 */
std::list<std::shared_ptr<TaskInfo>> AMTransferManager::GetHistory() const {
  std::lock_guard<std::mutex> lock(history_mtx_);
  return history_;
}

/**
 * @brief Resolve progress refresh interval from settings.
 */
int AMTransferManager::ResolveRefreshIntervalMs_() const {
  int value =
      config_.GetSettingInt({"transfer_manager", "refresh_interval_ms"}, 200);
  if (value <= 0) {
    value = 200;
  }
  if (value < 30) {
    value = 30;
  }
  return value;
}

/**
 * @brief Check whether a path contains wildcard tokens.
 */
bool AMTransferManager::HasWildcard_(const std::string &path) {
  return path.find('*') != std::string::npos ||
         path.find('<') != std::string::npos ||
         path.find('>') != std::string::npos;
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
 * @brief Return a set of clients to the idle pool.
 */
void AMTransferManager::ReturnClientsToIdle_(
    const std::vector<std::shared_ptr<BaseClient>> &clients,
    const std::vector<std::string> &keys) {
  std::lock_guard<std::mutex> lock(idle_mtx_);
  const size_t count = std::min(clients.size(), keys.size());
  for (size_t i = 0; i < count; ++i) {
    if (!clients[i]) {
      continue;
    }
    idle_pool_[keys[i]].push_front(clients[i]);
  }
}

/**
 * @brief Build the default+user callback wrapper for task completion.
 */
TaskInfo::ResultCallback AMTransferManager::BuildResultCallback_(
    std::atomic<int> &remaining, std::condition_variable &done_cv,
    std::mutex &done_mtx, std::atomic<bool> &terminated,
    std::vector<std::shared_ptr<BaseClient>> clients,
    std::vector<std::string> client_keys) {
  return [this, &remaining, &done_cv, &done_mtx, &terminated, clients,
          client_keys](std::shared_ptr<TaskInfo> task_info) mutable {
    if (task_info) {
      prompt_.resultprint(task_info);
    }

    UserResultCallback user_cb;
    {
      std::lock_guard<std::mutex> lock(callback_mtx_);
      user_cb = user_result_cb_;
    }
    auto bound_cb = BindResultCallback(std::move(user_cb));
    if (bound_cb) {
      CallCallbackSafe(bound_cb, task_info);
    }

    const int left = --remaining;
    if (left <= 0 || terminated.load()) {
      ReturnClientsToIdle_(clients, client_keys);
    }

    std::lock_guard<std::mutex> lock(done_mtx);
    done_cv.notify_all();
  };
}

TaskInfo::ResultCallback
AMTransferManager::BindResultCallback(UserResultCallback user_cb) {
  PublicResultCallback public_cb;
  {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    public_cb = public_result_cb_;
  }

  if (public_cb || user_cb) {
    return [this, public_cb, user_cb](std::shared_ptr<TaskInfo> task_info) {
      this->ResultCallback(task_info, public_cb, user_cb);
    };
  }
  return {};
}

void AMTransferManager::ResultCallback(std::shared_ptr<TaskInfo> task_info,
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
    CallCallbackSafe(user_cb, task_info);
  }
  if (public_cb) {
    CallCallbackSafe(public_cb, task_info);
  }
}

/**
 * @brief Submit a transfer set into the cache pool.
 */
size_t
AMTransferManager::SubmitTransferSet(const UserTransferSet &transfer_set) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  cached_sets_.push_back(transfer_set);
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
    cached_sets_.push_back(set);
    ids.push_back(cached_sets_.size() - 1);
  }
  return ids;
}

/**
 * @brief Query a cached transfer set by ID.
 */
bool AMTransferManager::QueryTransferSet(size_t set_index,
                                         UserTransferSet *out_set) const {
  if (!out_set) {
    return false;
  }
  std::lock_guard<std::mutex> lock(cache_mtx_);
  if (set_index >= cached_sets_.size()) {
    return false;
  }
  const auto &entry = cached_sets_[set_index];
  if (!entry.has_value()) {
    return false;
  }
  *out_set = *entry;
  return true;
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
 * @brief Delete a cached transfer set by ID.
 */
bool AMTransferManager::DeleteTransferSet(size_t set_index) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  if (set_index >= cached_sets_.size()) {
    return false;
  }
  if (!cached_sets_[set_index].has_value()) {
    return false;
  }
  cached_sets_[set_index].reset();
  return true;
}

/**
 * @brief Delete cached transfer sets by indices.
 */
size_t AMTransferManager::DeleteTransferSets(
    const std::vector<size_t> &set_indices) {
  size_t removed = 0;
  std::lock_guard<std::mutex> lock(cache_mtx_);
  for (size_t index : set_indices) {
    if (index >= cached_sets_.size()) {
      continue;
    }
    if (!cached_sets_[index].has_value()) {
      continue;
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
 * @brief Execute all cached transfer sets.
 */
ECM AMTransferManager::ExecuteCachedTransferSets(
    bool quiet, const std::shared_ptr<InterruptFlag> &interrupt_flag) {
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
    return {EC::Success, ""};
  }
  return transfer(transfer_sets, quiet, interrupt_flag);
}

/**
 * @brief Submit cached transfer sets as an async task.
 */
ECM AMTransferManager::SubmitCachedTransferSets(
    bool quiet, const std::shared_ptr<InterruptFlag> &interrupt_flag) {
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
    prompt_.Print("❌ task submit: cache is empty");
    return {EC::InvalidArg, "Cached transfer set is empty"};
  }

  if (!quiet) {
    auto temp = std::make_shared<TaskInfo>(true);
    temp->transfer_sets =
        std::make_shared<std::vector<UserTransferSet>>(transfer_sets);
    task_printer_.InspectTransferSets(temp);
    bool canceled = false;
    if (!prompt_.PromptYesNo("Submit cached transfer sets? (y/N): ",
                             &canceled)) {
      return {EC::Terminate, "Task submission canceled"};
    }
  }

  ECM rcm = transfer_async(transfer_sets, quiet, interrupt_flag);
  if (rcm.first == EC::Success) {
    ClearCachedTransferSets();
  }
  return rcm;
}

/**
 * @brief Show task status by ID using TaskInfoPrint.
 */
ECM AMTransferManager::Show(
    const ID &task_id, const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  auto task_info = FindTaskById_(task_id);
  if (!task_info) {
    return {EC::InvalidArg, AMStr::amfmt("Task not found: {}", task_id)};
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
    return {EC::InvalidArg, AMStr::amfmt("Task not found: {}", task_id)};
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
    return {EC::InvalidArg, AMStr::amfmt("Task not found: {}", task_id)};
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
    return {EC::InvalidArg, AMStr::amfmt("Task not found: {}", task_id)};
  }
  task_printer_.InspectTaskEntries(task_info);
  return {EC::Success, ""};
}

/**
 * @brief Inspect a cached user transfer set by cache ID.
 */
ECM AMTransferManager::InspectUserSet(size_t set_index) const {
  UserTransferSet transfer_set;
  if (!QueryTransferSet(set_index, &transfer_set)) {
    return {EC::InvalidArg, AMStr::amfmt("User set not found: {}", set_index)};
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
ECM AMTransferManager::InspectTaskEntry(const ID &entry_id) const {
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
  prompt_.Print(
      AMStr::amfmt("size: {}", AMClientManager::FormatSize(task.size)));
  prompt_.Print("");
  prompt_.Print(AMStr::amfmt("transferred: {}",
                             AMClientManager::FormatSize(task.transferred)));
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
    return {EC::InvalidArg, AMStr::amfmt("Task not found: {}", task_id)};
  }
  if (!result.second) {
    return {EC::InvalidArg,
            AMStr::amfmt("Task already finished: {}", task_id)};
  }
  return result.first->GetResult();
}

/**
 * @brief Pause a running task by ID.
 */
ECM AMTransferManager::Pause(const ID &task_id) {
  if (!worker_.pause(task_id)) {
    return {EC::InvalidArg, AMStr::amfmt("Task not found: {}", task_id)};
  }
  return {EC::Success, ""};
}

/**
 * @brief Resume a paused task by ID.
 */
ECM AMTransferManager::Resume(const ID &task_id) {
  if (!worker_.resume(task_id)) {
    return {EC::InvalidArg, AMStr::amfmt("Task not found: {}", task_id)};
  }
  return {EC::Success, ""};
}

/**
 * @brief Terminate tasks in batch by IDs.
 */
ECM AMTransferManager::Terminate(const std::vector<ID> &task_ids,
                                 int timeout_ms) {
  ECM last = {EC::Success, ""};
  for (const auto &id : task_ids) {
    ECM rcm = Terminate(id, timeout_ms);
    PrintTaskControlResult_(prompt_, "terminate", id, rcm);
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
  for (const auto &id : task_ids) {
    ECM rcm = Pause(id);
    PrintTaskControlResult_(prompt_, "pause", id, rcm);
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
  for (const auto &id : task_ids) {
    ECM rcm = Resume(id);
    PrintTaskControlResult_(prompt_, "resume", id, rcm);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Prepare host maintainer and tasks from user transfer sets.
 */
std::pair<ECM, AMTransferManager::PreparedTasks>
AMTransferManager::PrepareTasks_(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    const std::shared_ptr<InterruptFlag> &flag) {
  PreparedTasks prepared;
  if (transfer_sets.empty()) {
    return {ECM{EC::Success, ""}, prepared};
  }

  std::unordered_set<std::string> nicknames;
  for (const auto &set : transfer_sets) {
    std::string dst_host;
    std::string dst_path;
    auto dst_rcm = ParseTransferPath(client_manager_, set.dst, nullptr,
                                     &dst_host, &dst_path);
    if (dst_rcm.first != EC::Success) {
      return {dst_rcm, prepared};
    }
    if (!dst_host.empty()) {
      nicknames.insert(dst_host);
    }
    for (const auto &src : set.srcs) {
      std::string src_host;
      std::string src_path;
      auto src_rcm = ParseTransferPath(client_manager_, src, nullptr, &src_host,
                                       &src_path);
      if (src_rcm.first != EC::Success) {
        return {src_rcm, prepared};
      }
      if (!src_host.empty()) {
        nicknames.insert(src_host);
      }
    }
  }

  std::unordered_map<std::string, std::shared_ptr<BaseClient>> host_map;
  prepared.clients.reserve(nicknames.size());
  prepared.client_keys.reserve(nicknames.size());

  for (const auto &name : nicknames) {
    auto [rcm, client] = AcquireClient_(name, flag);
    if (rcm.first != EC::Success || !client) {
      ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
      return {rcm, prepared};
    }
    host_map[name] = client;
    prepared.clients.push_back(client);
    prepared.client_keys.push_back(name.empty() ? "local" : name);
  }

  prepared.hostm = std::make_shared<ClientMaintainer>(
      -1, ClientMaintainer::DisconnectCallback(), client_manager_.LocalClient(),
      host_map);

  for (const auto &set : transfer_sets) {
    std::string dst_host;
    std::string dst_path;
    auto dst_parse = ParseTransferPath(client_manager_, set.dst, nullptr,
                                       &dst_host, &dst_path);
    if (dst_parse.first != EC::Success) {
      ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
      return {dst_parse, prepared};
    }
    auto dst_client = dst_host.empty() ? prepared.hostm->local_client
                                       : prepared.hostm->GetHost(dst_host);
    if (!dst_client) {
      ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
      return {ECM{EC::ClientNotFound, "Destination client not available"},
              prepared};
    }
    auto dst_rcm = ParseTransferPath(client_manager_, set.dst, dst_client,
                                     &dst_host, &dst_path);
    if (dst_rcm.first != EC::Success) {
      ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
      return {dst_rcm, prepared};
    }
    for (const auto &src : set.srcs) {
      if (flag && flag->check()) {
        ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
        return {ECM{EC::Terminate, "Interrupted before task generation"},
                prepared};
      }

      std::string src_host;
      std::string src_path;
      auto src_parse = ParseTransferPath(client_manager_, src, nullptr,
                                         &src_host, &src_path);
      if (src_parse.first != EC::Success) {
        ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
        return {src_parse, prepared};
      }
      auto src_client = src_host.empty() ? prepared.hostm->local_client
                                         : prepared.hostm->GetHost(src_host);
      if (!src_client) {
        ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
        return {ECM{EC::ClientNotFound, "Source client not available"},
                prepared};
      }
      auto src_rcm = ParseTransferPath(client_manager_, src, src_client,
                                       &src_host, &src_path);
      if (src_rcm.first != EC::Success) {
        ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
        return {src_rcm, prepared};
      }

      std::vector<std::string> src_paths = {src_path};
      if (HasWildcard_(src_path)) {
        auto src_client = src_host.empty() ? prepared.hostm->local_client
                                           : prepared.hostm->GetHost(src_host);
        if (!src_client) {
          ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
          return {ECM{EC::ClientNotFound, "Source client not available"},
                  prepared};
        }
        auto matches = src_client->find(src_path, SearchType::All, flag, 5000);
        src_paths.clear();
        for (const auto &m : matches) {
          src_paths.push_back(m.path);
        }
        if (!quiet && !ConfirmWildcard_(matches, src_host, dst_host)) {
          ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
          return {ECM{EC::Terminate, "Wildcard transfer canceled by user"},
                  prepared};
        }
      }
      prepared.tasks = std::make_shared<TASKS>();
      for (const auto &resolved_src : src_paths) {
        auto [rcm, tasks] = AMWorkManager::load_tasks(
            resolved_src, dst_path, prepared.hostm, src_host, dst_host,
            set.clone, set.overwrite, set.mkdir, set.ignore_special_file, flag,
            10000);
        if (rcm.first != EC::Success) {
          prompt_.ErrorFormat("LoadTasks", rcm.second, false, 0, __func__);
          continue;
        }
        prepared.tasks->insert(prepared.tasks->end(), tasks.begin(),
                               tasks.end());
      }
    }
  }

  return {ECM{EC::Success, ""}, prepared};
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

/**
 * @brief Blocking transfer entry point.
 */
ECM AMTransferManager::transfer(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  auto flag =
      interrupt_flag ? interrupt_flag : std::make_shared<InterruptFlag>();
  const int refresh_interval_ms = ResolveRefreshIntervalMs_();

  auto [rcm, prep] = PrepareTasks_(transfer_sets, quiet, flag);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  if (prep.tasks->empty()) {
    ReturnClientsToIdle_(prep.clients, prep.client_keys);
    return {EC::Success, ""};
  }

  std::mutex done_mtx;
  std::condition_variable done_cv;
  std::atomic<int> remaining(1);
  std::atomic<bool> terminated(false);

  auto tasks_ptr = prep.tasks;
  auto task_info = worker_.cre_taskinfo(tasks_ptr, prep.hostm,
                                        TransferCallback(), -1, quiet, -1);
  task_info->transfer_sets =
      std::make_shared<std::vector<UserTransferSet>>(transfer_sets);
  task_info->result_callback = BuildResultCallback_(
      remaining, done_cv, done_mtx, terminated, prep.clients, prep.client_keys);

  auto submit_rcm = worker_.submit(task_info);
  if (submit_rcm.first != EC::Success) {
    prompt_.ErrorFormat("SubmitTask", submit_rcm.second, false, 0, __func__);
    ReturnClientsToIdle_(prep.clients, prep.client_keys);
    return submit_rcm;
  }

  // TODO: Bar has problem
  // AMProgressBarGroup progress_group;
  // progress_group.Start();
  // auto bar = std::make_shared<AMProgressBar>(
  //     static_cast<int64_t>(task_info->total_size.load()), "transfer");
  // progress_group.AddBar(bar);

  bool all_finished = false;
  while (!all_finished) {
    if (flag && flag->check()) {
      terminated.store(true);
      (void)worker_.terminate(task_info->id, 1000);
      // progress_group.Stop();
      return {EC::Terminate, "Transfer interrupted during progress polling"};
    }
    all_finished = task_info->GetStatus() == TaskStatus::Finished;
    // bar->SetProgress(
    //     static_cast<int64_t>(task_info->total_transferred_size.load()));
    // progress_group.Refresh(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_interval_ms));
  }

  {
    std::unique_lock<std::mutex> lock(done_mtx);
    done_cv.wait(lock, [&]() { return remaining.load() <= 0; });
  }
  return task_info->GetResult();
}

/**
 * @brief Non-blocking transfer entry point.
 */
ECM AMTransferManager::transfer_async(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    const std::shared_ptr<InterruptFlag> &interrupt_flag) {
  auto flag =
      interrupt_flag ? interrupt_flag : std::make_shared<InterruptFlag>();
  auto [rcm, prep] = PrepareTasks_(transfer_sets, quiet, flag);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  if (prep.tasks->empty()) {
    ReturnClientsToIdle_(prep.clients, prep.client_keys);
    return {EC::Success, ""};
  }

  std::mutex done_mtx;
  std::condition_variable done_cv;
  std::atomic<int> remaining(1);
  std::atomic<bool> terminated(false);

  auto task_info = std::make_shared<TaskInfo>(quiet);
  task_info->hostm = prep.hostm;
  task_info->tasks = prep.tasks;
  task_info->transfer_sets =
      std::make_shared<std::vector<UserTransferSet>>(transfer_sets);
  task_info->result_callback = BuildResultCallback_(
      remaining, done_cv, done_mtx, terminated, prep.clients, prep.client_keys);

  auto submit_rcm = worker_.submit(task_info);
  if (submit_rcm.first != EC::Success) {
    prompt_.ErrorFormat("SubmitTask", submit_rcm.second, false, 0, __func__);
    ReturnClientsToIdle_(prep.clients, prep.client_keys);
    return submit_rcm;
  }
  return {EC::Success, ""};
}
