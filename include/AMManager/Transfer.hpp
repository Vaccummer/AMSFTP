#pragma once
#include "AMBase/DataClass.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <deque>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

class AMTransferManager : private NonCopyableNonMovable {
public:
  using ID = std::string;
  using UserResultCallback = std::function<void(std::shared_ptr<TaskInfo>)>;
  using PublicResultCallback = std::function<void(std::shared_ptr<TaskInfo>)>;
  using ResultCallbackFn = std::function<void(
      std::shared_ptr<TaskInfo>, PublicResultCallback, UserResultCallback)>;

  /**
   * @brief Return the singleton instance.
   */
  static AMTransferManager &Instance() {
    static AMTransferManager instance;
    return instance;
  };

  ECM Init() override {
    int init_thread_num = 1;
    config_.ResolveArg(DocumentKind::Settings,
                       {"TransferManager", "init_thread_num"},
                       &init_thread_num);

    init_thread_num = std::min(std::max(1, init_thread_num), 128);
    worker_.ThreadCount(init_thread_num);
    return Ok();
  }

  /**
   * @brief Set the public result callback wrapper for all task completions.
   */
  void SetPublicResultCallback(PublicResultCallback cb = {});
  [[nodiscard]] TaskInfo::ResultCallback
  BindResultCallback(UserResultCallback user_cb);
  std::list<std::shared_ptr<TaskInfo>> GetHistory() const;
  void ResultCallback(std::shared_ptr<TaskInfo> task_info,
                      PublicResultCallback public_cb,
                      UserResultCallback user_cb);

  /**
   * @brief Submit a transfer set into the cache pool.
   *
   * @param transfer_set Transfer set to cache.
   * @return Cache index for the transfer set.
   */
  size_t SubmitTransferSet(const UserTransferSet &transfer_set);

  /**
   * @brief Submit multiple transfer sets into the cache pool.
   *
   * @param transfer_sets Transfer sets to cache.
   * @return Cache indices for the transfer sets.
   */
  std::vector<size_t>
  SubmitTransferSets(const std::vector<UserTransferSet> &transfer_sets);

  /**
   * @brief Query a cached transfer set by index.
   *
   * @param set_index Cache index to query.
   * @param out_set Output transfer set.
   * @return True when found.
   */
  ECM QueryTransferSet(size_t set_index, UserTransferSet *out_set) const;

  /**
   * @brief List all cached transfer set indices.
   */
  std::vector<size_t> ListTransferSetIds() const;

  /**
   * @brief List task IDs across pending, conducting, and finished tasks.
   */
  std::vector<ID> ListTaskIds() const;

  /**
   * @brief Get counts of pending and conducting tasks for prompt display.
   *
   * @param pending_count Output count of pending tasks (nullable).
   * @param conducting_count Output count of conducting tasks (nullable).
   */
  void GetTaskCounts(size_t *pending_count, size_t *conducting_count) const;

  /**
   * @brief Delete cached transfer sets by indices.
   *
   * @param set_indices Cache indices to delete.
   * @return Count removed.
   */
  size_t DeleteTransferSets(const std::vector<size_t> &set_indices);

  /**
   * @brief Clear all cached transfer sets.
   */
  void ClearCachedTransferSets();

  /**
   * @brief Submit cached transfer sets as a task.
   *
   * @param quiet Whether to suppress output and confirmation.
   * @param interrupt_flag Optional interrupt flag.
   * @param is_async Whether to submit as an async task.
   */
  ECM SubmitCachedTransferSets(
      bool quiet,
      const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr,
      bool is_async = false);

  /**
   * @brief Show task status by ID.
   *
   * @param task_id Task ID.
   * @param interrupt_flag Optional flag to stop progress rendering.
   */
  ECM Show(const ID &task_id,
           const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

  /**
   * @brief Show task status by multiple IDs.
   *
   * The order of display follows status order (Pending, Paused, Conducting,
   * Finished). Invalid IDs will be reported and skipped.
   *
   * @param task_ids Task IDs to show.
   * @param interrupt_flag Optional flag to stop progress rendering.
   */
  ECM Show(const std::vector<ID> &task_ids,
           const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

  /**
   * @brief List tasks by status.
   *
   * @param pending Whether to list pending tasks.
   * @param suspend Whether to list paused tasks.
   * @param finished Whether to list finished tasks.
   * @param conducting Whether to list conducting tasks.
   * @param interrupt_flag Optional flag to stop progress rendering.
   */
  ECM List(bool pending, bool suspend, bool finished, bool conducting,
           const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

  /**
   * @brief Inspect a task by ID.
   *
   * @param task_id Task ID to inspect.
   * @param show_sets Whether to show transfer sets.
   * @param show_entries Whether to show task entries.
   */
  ECM Inspect(const ID &task_id, bool show_sets, bool show_entries) const;

  /**
   * @brief Inspect only transfer sets for a task by ID.
   */
  ECM InspectTransferSets(const ID &task_id) const;

  /**
   * @brief Inspect only task entries for a task by ID.
   */
  ECM InspectTaskEntries(const ID &task_id) const;

  /**
   * @brief Query a cached user transfer set by cache index.
   */
  ECM QueryCachedUserSet(size_t set_index) const;

  /**
   * @brief Get or set worker thread count.
   *
   * When num < 0, prints and returns current thread count. Otherwise clamps the
   * value to [1, InternalVars.MaxThreadNum], applies it, prints the new count,
   * and returns success.
   *
   * @param num Desired thread count, or negative to query.
   */
  ECM Thread(int num = -1);

  /**
   * @brief Query a single task entry by entry ID.
   */
  ECM QuerySetEntry(const ID &entry_id) const;

  /**
   * @brief Terminate a running task by ID.
   */
  ECM Terminate(const ID &task_id, int timeout_ms = 5000);

  /**
   * @brief Pause a running task by ID.
   *
   * If the task_id string contains comma/semicolon/whitespace separators,
   * it will be treated as multiple task IDs.
   */
  ECM Pause(const ID &task_id);

  /**
   * @brief Resume a paused task by ID.
   *
   * If the task_id string contains comma/semicolon/whitespace separators,
   * it will be treated as multiple task IDs.
   */
  ECM Resume(const ID &task_id);

  /**
   * @brief Terminate tasks in batch by IDs.
   */
  ECM Terminate(const std::vector<ID> &task_ids, int timeout_ms = 5000);

  /**
   * @brief Pause tasks in batch by IDs.
   */
  ECM Pause(const std::vector<ID> &task_ids);

  /**
   * @brief Resume tasks in batch by IDs.
   */
  ECM Resume(const std::vector<ID> &task_ids);

  /**
   * @brief Retry a completed task by rebuilding transfer tasks.
   *
   * @param task_id Task ID to retry (must be finished).
   * @param is_async Whether to submit asynchronously.
   * @param quiet Whether to suppress output.
   * @param indices Optional 1-based task indices to retry.
   */
  ECM retry(const ID &task_id, bool is_async = false, bool quiet = false,
            const std::vector<int> &indices = {});

  /**
   * @brief Execute transfer sets synchronously (blocking).
   *
   * @param transfer_sets Transfer sets to execute.
   * @param quiet Whether to suppress output.
   * @param interrupt_flag Optional interrupt flag.
   */
  ECM transfer(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
               const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);
  /**
   * @brief Execute a prepared TaskInfo synchronously.
   *
   * @param task_info Prepared task info containing tasks and host maintainer.
   * @param interrupt_flag Optional interrupt flag for cancellation.
   */
  ECM transfer(const std::shared_ptr<TaskInfo> &task_info,
               const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);
  /**
   * @brief Execute transfer sets asynchronously (non-blocking).
   *
   * @param transfer_sets Transfer sets to execute.
   * @param quiet Whether to suppress output.
   * @param interrupt_flag Optional interrupt flag.
   */
  ECM transfer_async(
      const std::vector<UserTransferSet> &transfer_sets, bool quiet,
      const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);
  /**
   * @brief Execute a prepared TaskInfo asynchronously.
   *
   * @param task_info Prepared task info containing tasks and host maintainer.
   * @param interrupt_flag Optional interrupt flag (unused).
   */
  ECM transfer_async(
      const std::shared_ptr<TaskInfo> &task_info,
      const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

private:
  /**
   * @brief Construct transfer manager using singleton managers.
   */
  AMTransferManager() = default;

  static bool HasWildcard_(const std::string &path);

  bool ConfirmWildcard_(const std::vector<PathInfo> &matches,
                        const std::string &src_host,
                        const std::string &dst_host);
  std::pair<ECM, std::shared_ptr<BaseClient>>
  AcquireClient_(const std::string &nickname,
                 const std::shared_ptr<InterruptFlag> &flag);
  std::pair<ECM, std::shared_ptr<ClientMaintainer>>
  CollectClients(const std::vector<std::string> &nicknames,
                 const std::shared_ptr<InterruptFlag> &flag);
  void
  ReturnClientsToIdle_(const std::shared_ptr<ClientMaintainer> &maintainer);
  std::pair<ECM, std::shared_ptr<TaskInfo>>
  PrepareTasks_(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
                const std::shared_ptr<InterruptFlag> &flag);
  std::shared_ptr<TaskInfo> FindTaskById_(const ID &task_id) const;
  std::vector<std::shared_ptr<TaskInfo>> SnapshotHistory_() const;
  bool ParseEntryId_(const ID &entry_id, ID *task_id,
                     size_t *entry_index) const;

private:
  AMConfigManager &config_ = AMConfigManager::Instance();
  AMClientManager &client_manager_ = AMClientManager::Instance();
  AMPromptManager &prompt_ = AMPromptManager::Instance();
  AMWorkManager worker_;
  mutable std::mutex idle_mtx_;
  std::unordered_map<ID, std::list<std::shared_ptr<BaseClient>>> idle_pool_;
  mutable std::mutex history_mtx_;
  std::list<std::shared_ptr<TaskInfo>> history_;
  mutable std::mutex cache_mtx_;
  std::vector<std::optional<UserTransferSet>> cached_sets_;
  mutable std::mutex callback_mtx_;
  PublicResultCallback public_result_cb_ = {};
  UserResultCallback user_result_cb_ = {};
  mutable std::mutex speed_mtx_;
  std::unordered_map<ID, std::deque<std::pair<double, size_t>>> speed_samples_;
};
