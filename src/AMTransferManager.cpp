#include "AMTransferManager.hpp"
#include "AMClientManager.hpp"
#include "AMConfigManager.hpp"
#include "AMIOCore.hpp"
#include <algorithm>
#include <cctype>
#include <unordered_set>

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
 * @brief Construct a transfer manager bound to config and client manager.
 */
AMTransferManager::AMTransferManager(AMConfigManager &cfg,
                                     AMClientManager &client_manager)
    : config_(cfg), client_manager_(client_manager),
      prompt_(AMPromptManager::Instance()) {}

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
 * @brief Parse "nickname@path" into components.
 */
std::pair<std::string, std::string>
AMTransferManager::ParseAddress_(const std::string &input) {
  const auto pos = input.find('@');
  if (pos == std::string::npos) {
    return {"", input};
  }
  return {input.substr(0, pos), input.substr(pos + 1)};
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

  auto created = client_manager_.CreClient(nickname, flag);
  if (created.first.first != EC::Success || !created.second) {
    return created;
  }
  auto client = created.second;
  ECM rcm = client->Connect(false, flag);
  if (rcm.first != EC::Success) {
    return {rcm, client};
  }
  return {ECM{EC::Success, ""}, client};
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
    for (const auto &pair : set.transfers) {
      auto [src_host, _src_path] = ParseAddress_(pair.first);
      auto [dst_host, _dst_path] = ParseAddress_(pair.second);
      if (!src_host.empty()) {
        nicknames.insert(src_host);
      }
      if (!dst_host.empty()) {
        nicknames.insert(dst_host);
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
    for (const auto &pair : set.transfers) {
      if (flag && flag->check()) {
        ReturnClientsToIdle_(prepared.clients, prepared.client_keys);
        return {ECM{EC::Terminate, "Interrupted before task generation"},
                prepared};
      }

      auto [src_host, src_path] = ParseAddress_(pair.first);
      auto [dst_host, dst_path] = ParseAddress_(pair.second);

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

      for (const auto &resolved_src : src_paths) {
        auto [rcm, tasks] = AMWorkManager::load_tasks(
            resolved_src, dst_path, prepared.hostm, src_host, dst_host,
            set.overwrite, set.mkdir, set.ignore_special_file, flag, 10000);
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

  AMProgressBarGroup progress_group;
  progress_group.Start();
  auto bar = std::make_shared<AMProgressBar>(
      static_cast<int64_t>(task_info->total_size.load()), "transfer");
  progress_group.AddBar(bar);

  bool all_finished = false;
  while (!all_finished) {
    if (flag && flag->check()) {
      terminated.store(true);
      worker_.terminate(task_info->id, 1000);
      progress_group.Stop();
      return {EC::Terminate, "Transfer interrupted during progress polling"};
    }
    all_finished = task_info->GetStatus() == TaskStatus::Finished;
    bar->SetProgress(
        static_cast<int64_t>(task_info->total_transferred_size.load()));
    progress_group.Refresh(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(refresh_interval_ms));
  }

  {
    std::unique_lock<std::mutex> lock(done_mtx);
    done_cv.wait(lock, [&]() { return remaining.load() <= 0; });
  }

  progress_group.Stop();
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
