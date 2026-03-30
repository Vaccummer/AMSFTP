#pragma once

#include "application/transfer/TransferDtos.hpp"
#include "application/transfer/TransferWorkflows.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferCacheDomainService.hpp"
#include "domain/transfer/TransferPorts.hpp"
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace AMApplication::TransferRuntime {
class ITransferBackendPort;
class ITransferClientPoolPort;
} // namespace AMApplication::TransferRuntime

namespace AMApplication::client {
class ClientAppService;
} // namespace AMApplication::client

namespace AMApplication::filesystem {
class FilesystemAppService;
}

namespace AMApplication::TransferWorkflow {
/**
 * @brief Application-facing transfer facade that owns transfer workflow entry
 * points for upper layers.
 *
 * Runtime execution is routed through an application backend port.
 */
class TransferAppService final
    : private NonCopyableNonMovable,
      public AMDomain::transfer::ITransferExecutorPort,
      public AMDomain::transfer::ITransferTaskPort,
      public AMDomain::transfer::ITransferCachePort {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ID = std::string;
  using WildcardConfirmFn = std::function<bool(
      const std::vector<PathInfo> &, const std::string &, const std::string &)>;
  /**
   * @brief Wildcard confirmation item computed in pre-confirm slice.
   */
  struct WildcardConfirmRequest {
    std::vector<PathInfo> matches;
    std::string src_host;
    std::string dst_host;
  };

  /**
   * @brief Construct service with an internally created default backend.
   */
  TransferAppService(
      AMApplication::client::ClientAppService &client_service,
      std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
          transfer_pool,
      std::shared_ptr<AMApplication::filesystem::FilesystemAppService>
          filesystem_service = nullptr);

  /**
   * @brief Initialize the underlying transfer runtime.
   */
  ECM Init();

  /**
   * @brief Execute transfer sets synchronously.
   */
  ECM Transfer(const std::vector<UserTransferSet> &transfer_sets,
               bool quiet) override;

  /**
   * @brief Execute transfer sets asynchronously.
   */
  ECM TransferAsync(const std::vector<UserTransferSet> &transfer_sets,
                    bool quiet) override;

  /**
   * @brief Execute transfer sets synchronously with explicit control context.
   */
  ECM TransferWithControl(const std::vector<UserTransferSet> &transfer_sets,
                          bool quiet,
                          AMDomain::client::amf control_token,
                          TransferConfirmPolicy confirm_policy =
                              TransferConfirmPolicy::RequireConfirm,
                          const WildcardConfirmFn &confirm_wildcard = {},
                          std::vector<ECM> *warnings = nullptr);

  /**
   * @brief Execute transfer sets asynchronously with explicit control context.
   */
  ECM TransferAsyncWithControl(
      const std::vector<UserTransferSet> &transfer_sets, bool quiet,
      AMDomain::client::amf control_token,
      TransferConfirmPolicy confirm_policy =
          TransferConfirmPolicy::RequireConfirm,
      const WildcardConfirmFn &confirm_wildcard = {},
      std::vector<ECM> *warnings = nullptr);

  /**
   * @brief Return tracked transfer task identifiers.
   */
  [[nodiscard]] std::vector<ID> ListTaskIds() const override;

  /**
   * @brief Return task summaries for interface read/query flows.
   */
  ECM ListTaskSummaries(std::vector<TaskSummaryView> *out_summaries) const;

  /**
   * @brief Return one task detail view.
   */
  ECM GetTaskView(const ID &task_id, bool include_sets, bool include_entries,
                  TaskView *out_view) const;

  /**
   * @brief Resolve one task by identifier.
   */
  [[nodiscard]] std::shared_ptr<TaskInfo>
  FindTask(const ID &task_id) const override;

  /**
   * @brief Return counts of pending and conducting tasks.
   */
  void GetTaskCounts(size_t *pending_count, size_t *conducting_count) const;

  /**
   * @brief Get or set worker thread count.
   */
  ECM Thread(int num = -1);

  /**
   * @brief Apply worker thread count without CLI presentation side effects.
   */
  ECM SetWorkerThreadCount(size_t count);

  /**
   * @brief Terminate tasks by ids.
   */
  ECM Terminate(const std::vector<ID> &task_ids, int timeout_ms = 5000);

  /**
   * @brief Terminate one task by identifier.
   */
  ECM Terminate(const ID &task_id, int timeout_ms = 5000) override;

  /**
   * @brief Pause tasks by ids.
   */
  ECM Pause(const std::vector<ID> &task_ids);

  /**
   * @brief Pause one task by identifier.
   */
  ECM Pause(const ID &task_id) override;

  /**
   * @brief Resume tasks by ids.
   */
  ECM Resume(const std::vector<ID> &task_ids);

  /**
   * @brief Resume one task by identifier.
   */
  ECM Resume(const ID &task_id) override;

  /**
   * @brief Retry one finished task.
   */
  ECM Retry(const ID &task_id, bool is_async = false, bool quiet = false,
            const std::vector<int> &indices = {});

  /**
   * @brief Add one transfer set into the cached job list.
   */
  size_t AddCachedTransferSet(const UserTransferSet &transfer_set) override;

  /**
   * @brief Remove cached transfer sets by indices.
   */
  size_t
  RemoveCachedTransferSets(const std::vector<size_t> &set_indices) override;

  /**
   * @brief Remove cached transfer sets and return warning payloads.
   */
  size_t RemoveCachedTransferSets(const std::vector<size_t> &set_indices,
                                  std::vector<ECM> *warnings);

  /**
   * @brief Clear all cached transfer sets.
   */
  void ClearCachedTransferSets() override;

  /**
   * @brief Submit cached transfer sets.
   */
  ECM SubmitCachedTransferSets(bool quiet, bool is_async = false) override;

  /**
   * @brief Query one cached transfer set.
   */
  ECM QueryCachedTransferSet(size_t set_index) const override;

  /**
   * @brief Query one cached transfer set into output payload.
   */
  ECM GetCachedTransferSet(size_t set_index, UserTransferSet *out_set) const;

  /**
   * @brief Query one cached transfer set into application DTO.
   */
  ECM GetCachedTransferSetView(size_t set_index,
                               TransferSetView *out_view) const;

  /**
   * @brief List cached transfer-set identifiers.
   */
  [[nodiscard]] std::vector<size_t> ListCachedTransferSetIds() const override;

  /**
   * @brief Snapshot all valid cached transfer sets.
   */
  [[nodiscard]] std::vector<UserTransferSet> SnapshotCachedTransferSets() const;

  /**
   * @brief Snapshot cached transfer sets in application DTO shape.
   */
  [[nodiscard]] std::vector<TransferSetView>
  SnapshotCachedTransferSetViews() const;

  /**
   * @brief Submit cached transfer sets with explicit control and confirm
   * policy.
   */
  ECM SubmitCachedTransferSetsWithControl(
      bool quiet, bool is_async,
      AMDomain::client::amf control_token,
      TransferConfirmPolicy confirm_policy =
          TransferConfirmPolicy::RequireConfirm,
      const WildcardConfirmFn &confirm_wildcard = {},
      std::vector<ECM> *warnings = nullptr);

private:
  /**
   * @brief Construct service from an explicit transfer backend implementation.
   */
  explicit TransferAppService(
      std::shared_ptr<AMApplication::TransferRuntime::ITransferBackendPort>
          backend,
      AMApplication::client::ClientAppService &client_service,
      std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
          transfer_pool,
      std::shared_ptr<AMApplication::filesystem::FilesystemAppService>
          filesystem_service);

  std::pair<ECM, std::shared_ptr<TaskInfo>>
  PrepareTasks_(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
                AMDomain::client::amf flag,
                std::vector<WildcardConfirmRequest> *confirm_requests,
                std::vector<ECM> *warnings);
  /**
   * @brief Apply explicit confirm policy on pre-confirm wildcard requests.
   */
  ECM ResolveWildcardConfirm_(
      const std::vector<WildcardConfirmRequest> &confirm_requests,
      TransferConfirmPolicy confirm_policy,
      const WildcardConfirmFn &confirm_wildcard) const;

  mutable std::mutex cache_mtx_;
  AMDomain::transfer::TransferCacheDomainService
      transfer_cache_domain_service_ = {};
  std::vector<std::optional<UserTransferSet>> cached_sets_ = {};
  std::shared_ptr<AMApplication::TransferRuntime::ITransferBackendPort>
      backend_ = nullptr;
  AMApplication::client::ClientAppService *client_service_ = nullptr;
  std::shared_ptr<AMApplication::filesystem::FilesystemAppService>
      filesystem_service_ = nullptr;
  std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
      transfer_pool_ = nullptr;
};
} // namespace AMApplication::TransferWorkflow
