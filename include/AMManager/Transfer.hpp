#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Prompt.hpp"
#include <condition_variable>
#include <functional>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>

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
   * @param client_maintainer Host maintainer used to retrieve nicknames.
   */
  void TaskSubmitPrint(const std::shared_ptr<TaskInfo> &task_info,
                       const ClientMaintainer &client_maintainer) const;

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

  AMTransferManager(AMConfigManager &cfg, AMClientManager &client_manager);

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

  ECM transfer(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
               const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);
  ECM transfer_async(
      const std::vector<UserTransferSet> &transfer_sets, bool quiet,
      const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);

private:
  struct PreparedTasks;

  int ResolveRefreshIntervalMs_() const;
  static bool HasWildcard_(const std::string &path);
  bool ConfirmWildcard_(const std::vector<PathInfo> &matches,
                        const std::string &src_host,
                        const std::string &dst_host);
  std::pair<ECM, std::shared_ptr<BaseClient>>
  AcquireClient_(const std::string &nickname,
                 const std::shared_ptr<InterruptFlag> &flag);
  void
  ReturnClientsToIdle_(const std::vector<std::shared_ptr<BaseClient>> &clients,
                       const std::vector<std::string> &keys);
  TaskInfo::ResultCallback
  BuildResultCallback_(std::atomic<int> &remaining,
                       std::condition_variable &done_cv, std::mutex &done_mtx,
                       std::atomic<bool> &terminated,
                       std::vector<std::shared_ptr<BaseClient>> clients,
                       std::vector<std::string> client_keys);
  std::pair<ECM, PreparedTasks>
  PrepareTasks_(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
                const std::shared_ptr<InterruptFlag> &flag);

private:
  AMConfigManager &config_;
  AMClientManager &client_manager_;
  AMPromptManager &prompt_;
  AMWorkManager worker_;
  mutable std::mutex idle_mtx_;
  std::unordered_map<ID, std::list<std::shared_ptr<BaseClient>>> idle_pool_;
  mutable std::mutex history_mtx_;
  std::list<std::shared_ptr<TaskInfo>> history_;
  mutable std::mutex callback_mtx_;
  PublicResultCallback public_result_cb_ = {};
  UserResultCallback user_result_cb_ = {};
};


