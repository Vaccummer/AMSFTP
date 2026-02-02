#include "AMClient/IOCore.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <condition_variable>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

class TaskInfoPrint {
public:
  /**
   * @brief Construct a task info printer bound to a prompt manager.
   *
   * @param prompt Prompt manager used for formatted output.
   */
  explicit TaskInfoPrint(AMPromptManager &prompt = AMPromptManager::Instance());

  /**
   * @brief Print submit information for transfer_async.
   *
   * Format: "Submit ID: [{taskid}] FileNum: {num} TotalSize: {size} Clients:
   * {nicknames}".
   *
   * @param task_info Task info to print.
   */
  void TaskSubmitPrint(const std::shared_ptr<TaskInfo> &task_info) const;

  /**
   * @brief Print task result information after completion.
   *
   * Do not print if task_info->quiet is true. Use a success/failure marker
   * followed by the task id and progress details. If the task succeeded, omit
   * the result code/message segment.
   *
   * @param task_info Task info to print.
   */
  void TaskResultPrint(const std::shared_ptr<TaskInfo> &task_info) const;

  /**
   * @brief Show task status for quick queries.
   *
   * Pending tasks print basic metadata, finished tasks include transferred
   * sizes and elapsed time, and conducting tasks render a progress bar that
   * refreshes until the interrupt flag is set.
   *
   * @param task_info Task info to show.
   * @param interrupt_flag Optional flag to stop progress rendering.
   */
  void Show(const std::shared_ptr<TaskInfo> &task_info,
            const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

  /**
   * @brief Print multiple tasks in batch.
   *
   * Pending and finished tasks are printed via Show(), while conducting tasks
   * create multiple progress bars for ongoing updates.
   *
   * @param pending Pending tasks to print.
   * @param finished Finished tasks to print.
   * @param conducting Conducting tasks to print with progress bars.
   * @param interrupt_flag Optional flag to stop progress rendering.
   */
  void List(const std::vector<std::shared_ptr<TaskInfo>> &pending,
            const std::vector<std::shared_ptr<TaskInfo>> &finished,
            const std::vector<std::shared_ptr<TaskInfo>> &conducting,
            const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

  /**
   * @brief Print detailed task information.
   *
   * This prints one attribute per line with aligned names. Use the optional
   * flags to also print task entries or transfer set details.
   *
   * @param task_info Task info to inspect.
   * @param show_task_entries Whether to print the task list.
   * @param show_transfer_sets Whether to print transfer set details.
   */
  void Inspect(const std::shared_ptr<TaskInfo> &task_info,
               bool show_task_entries = false,
               bool show_transfer_sets = false) const;

  /**
   * @brief Print individual task entries inside task_info.
   *
   * @param task_info Task info holding transfer tasks.
   */
  void InspectTaskEntries(const std::shared_ptr<TaskInfo> &task_info) const;

  /**
   * @brief Print original UserTransferSet settings for the task.
   *
   * @param task_info Task info holding transfer set configurations.
   */
  void InspectTransferSets(const std::shared_ptr<TaskInfo> &task_info) const;

private:
  AMPromptManager &prompt_;
};

class AMTransferManager {
public:
  using ID = std::string;
  using UserResultCallback = std::function<void(std::shared_ptr<TaskInfo>)>;
  using PublicResultCallback = std::function<void(std::shared_ptr<TaskInfo>)>;
  using ResultCallbackFn = std::function<void(
      std::shared_ptr<TaskInfo>, PublicResultCallback, UserResultCallback)>;

  /**
   * @brief Return the singleton instance.
   */
  static AMTransferManager &Instance();

  /** Disable copy construction. */
  AMTransferManager(const AMTransferManager &) = delete;
  /** Disable copy assignment. */
  AMTransferManager &operator=(const AMTransferManager &) = delete;
  /** Disable move construction. */
  AMTransferManager(AMTransferManager &&) = delete;
  /** Disable move assignment. */
  AMTransferManager &operator=(AMTransferManager &&) = delete;

  /**
   * @brief Set the public result callback wrapper for all task completions.
   */
  void SetPublicResultCallback(PublicResultCallback cb = {});
  void SetResultCallback(UserResultCallback cb = {});
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
  bool QueryTransferSet(size_t set_index, UserTransferSet *out_set) const;

  /**
   * @brief List all cached transfer set indices.
   */
  std::vector<size_t> ListTransferSetIds() const;

  /**
   * @brief Delete a cached transfer set by index.
   *
   * @param set_index Cache index to delete.
   * @return True when removed.
   */
  bool DeleteTransferSet(size_t set_index);

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
   * @brief Execute all cached transfer sets.
   *
   * @param quiet Whether to suppress output.
   * @param interrupt_flag Optional interrupt flag.
   */
  ECM ExecuteCachedTransferSets(
      bool quiet,
      const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

  /**
   * @brief Submit cached transfer sets as an async task.
   *
   * @param quiet Whether to suppress output and confirmation.
   * @param interrupt_flag Optional interrupt flag.
   */
  ECM SubmitCachedTransferSets(
      bool quiet,
      const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

  /**
   * @brief Show task status by ID using TaskInfoPrint.
   *
   * @param task_id Task ID.
   * @param interrupt_flag Optional flag to stop progress rendering.
   */
  ECM Show(const ID &task_id,
           const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

  /**
   * @brief List tasks by status using TaskInfoPrint.
   *
   * @param pending Whether to list pending tasks.
   * @param finished Whether to list finished tasks.
   * @param conducting Whether to list conducting tasks.
   * @param interrupt_flag Optional flag to stop progress rendering.
   */
  ECM List(bool pending, bool finished, bool conducting,
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
   * @brief Inspect a cached user transfer set by cache index.
   */
  ECM InspectUserSet(size_t set_index) const;

  /**
   * @brief Inspect a single task entry by entry ID.
   */
  ECM InspectTaskEntry(const ID &entry_id) const;

  /**
   * @brief Terminate a running task by ID.
   */
  ECM Terminate(const ID &task_id, int timeout_ms = 5000);

  /**
   * @brief Pause a running task by ID.
   */
  ECM Pause(const ID &task_id);

  /**
   * @brief Resume a paused task by ID.
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
   * @brief Resume a completed task by rebuilding transfer tasks.
   *
   * @param task_id Task ID to resume (must be finished).
   * @param is_async Whether to submit asynchronously.
   * @param quiet Whether to suppress output.
   * @param indices Optional 1-based task indices to resume.
   */
  ECM resume(const ID &task_id, bool is_async = false, bool quiet = false,
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
  AMTransferManager();

  int ResolveRefreshIntervalMs_() const;
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
  AMConfigManager &config_;
  AMClientManager &client_manager_;
  AMPromptManager &prompt_;
  TaskInfoPrint task_printer_;
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
};
