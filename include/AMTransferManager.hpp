#include "AMClientManager.hpp"
#include "AMConfigManager.hpp"
#include "AMIOCore.hpp"
#include "AMPromptManager.hpp"
#include <condition_variable>
#include <functional>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>

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
  static std::pair<std::string, std::string>
  ParseAddress_(const std::string &input);
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
