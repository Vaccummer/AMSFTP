#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Path.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Transfer.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <exception>
#include <memory>
#include <sstream>
#include <unordered_map>
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
  prompt.Print(AMStr::amfmt(
      "SubmitInfo ID: {}; FileNum: {}; TotalSize: {}; Clients: {}",
      task_info->id, file_num, FormatSize(total_size), nickname_str));
}

/**
 * @brief Print task result information after completion.
 */
void PrintTaskResult_(AMPromptManager &prompt,
                      const std::shared_ptr<TaskInfo> &task_info) {
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
          : AMStr::amfmt(" {}: {}", AM_ENUM_NAME(result.first), result.second);

  prompt.Print(AMStr::amfmt(
      "TaskResult  {} ID: {}; Files: {}/{}; Size: {}/{}; ThreadID: {};{}",
      prefix, task_id, success_num, filenum, FormatSize(transferred),
      FormatSize(total), thread_id, rcm_text));
}

} // namespace

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
      prompt_(AMPromptManager::Instance()) {
  const int max_threads =
      config_.GetSettingInt({"InternalVars", "MaxThreadNum"}, 16);
  int init_threads =
      config_.GetSettingInt({"InternalVars", "InitThreadNum"}, 1);
  init_threads = std::max<int>(1, std::min<int>(init_threads, max_threads));
  worker_.ThreadCount(static_cast<size_t>(init_threads));
}

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
      auto rcm2 = client->Check(flag);
      if (rcm2.first == EC::Success) {
        return {ECM{EC::Success, ""}, client};
      }
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
  PrintTaskResult_(prompt_, task_info);
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
      PrintTaskResult_(prompt_, task_info);
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
    done_cv.wait(
        lock, [&]() { return remaining.load(std::memory_order_relaxed) <= 0; });
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
    PrintTaskSubmit_(prompt_, task_info);
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
    display_names.emplace_back("local");
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
