#include "AMClient/AMCore.hpp"
#include "AMClientManager.hpp"
#include "AMConfigManager.hpp"
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
  using ResultCallback = std::function<void(std::shared_ptr<TaskInfo>)>;

  AMTransferManager(AMConfigManager &cfg, AMClientManager &client_manager);

  void SetResultCallback(ResultCallback cb = {});
  std::list<std::shared_ptr<TaskInfo>> GetHistory() const;

  ECM transfer(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
               const std::shared_ptr<InterruptFlag> &interrupt_flag = nullptr);
  ECM transfer_async(const std::vector<UserTransferSet> &transfer_sets,
                     bool quiet,
                     const std::shared_ptr<InterruptFlag> &interrupt_flag =
                         nullptr);

private:
  struct PreparedTasks;

  int ResolveRefreshIntervalMs_() const;
  static std::pair<std::string, std::string>
  ParseAddress_(const std::string &input);
  static bool HasWildcard_(const std::string &path);
  bool ConfirmWildcard_(const std::vector<PathInfo> &matches);
  std::pair<ECM, std::shared_ptr<BaseClient>>
  AcquireClient_(const std::string &nickname,
                 const std::shared_ptr<InterruptFlag> &flag);
  void
  ReturnClientsToIdle_(const std::vector<std::shared_ptr<BaseClient>> &clients,
                       const std::vector<std::string> &keys);
  ResultCallback
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
  ResultCallback user_result_cb_ = {};
};
