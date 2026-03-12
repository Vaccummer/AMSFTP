#pragma once

#include "domain/transfer/TransferManager.hpp"
#include "domain/transfer/TransferPorts.hpp"

namespace AMApplication::TransferWorkflow {
/**
 * @brief Application-facing transfer facade that owns transfer workflow entry
 * points for upper layers.
 *
 * The current implementation delegates to the legacy domain transfer manager
 * while migration is still in progress.
 */
class TransferAppService final : private NonCopyableNonMovable,
                                 public AMDomain::transfer::ITransferExecutorPort,
                                 public AMDomain::transfer::ITransferTaskPort,
                                 public AMDomain::transfer::ITransferCachePort {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ID = std::string;

  /**
   * @brief Construct service from the legacy transfer manager backend.
   */
  explicit TransferAppService(AMDomain::transfer::AMTransferManager &manager);

  /**
   * @brief Initialize the underlying transfer runtime.
   */
  ECM Init();

  /**
   * @brief Execute transfer sets synchronously.
   */
  ECM Transfer(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
               amf interrupt_flag = nullptr) override;

  /**
   * @brief Execute transfer sets asynchronously.
   */
  ECM TransferAsync(const std::vector<UserTransferSet> &transfer_sets,
                    bool quiet, amf interrupt_flag = nullptr) override;

  /**
   * @brief Return tracked transfer task identifiers.
   */
  [[nodiscard]] std::vector<ID> ListTaskIds() const override;

  /**
   * @brief Resolve one task by identifier.
   */
  [[nodiscard]] std::shared_ptr<TaskInfo> FindTask(const ID &task_id) const override;

  /**
   * @brief Return counts of pending and conducting tasks.
   */
  void GetTaskCounts(size_t *pending_count, size_t *conducting_count) const;

  /**
   * @brief List tasks by status.
   */
  ECM List(bool pending, bool suspend, bool finished, bool conducting,
           amf interrupt_flag = nullptr);

  /**
   * @brief Show one or more tasks.
   */
  ECM Show(const std::vector<ID> &task_ids, amf interrupt_flag = nullptr);

  /**
   * @brief Inspect one task.
   */
  ECM Inspect(const ID &task_id, bool show_sets, bool show_entries) const;

  /**
   * @brief Inspect only transfer sets for a task.
   */
  ECM InspectTransferSets(const ID &task_id) const;

  /**
   * @brief Inspect only task entries for a task.
   */
  ECM InspectTaskEntries(const ID &task_id) const;

  /**
   * @brief Query one task entry.
   */
  ECM QueryTaskEntry(const ID &entry_id) const;

  /**
   * @brief Get or set worker thread count.
   */
  ECM Thread(int num = -1);

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
  size_t RemoveCachedTransferSets(const std::vector<size_t> &set_indices) override;

  /**
   * @brief Clear all cached transfer sets.
   */
  void ClearCachedTransferSets() override;

  /**
   * @brief Submit cached transfer sets.
   */
  ECM SubmitCachedTransferSets(bool quiet, amf interrupt_flag = nullptr,
                               bool is_async = false) override;

  /**
   * @brief Query one cached transfer set.
   */
  ECM QueryCachedTransferSet(size_t set_index) const override;

  /**
   * @brief List cached transfer-set identifiers.
   */
  [[nodiscard]] std::vector<size_t> ListCachedTransferSetIds() const override;

private:
  AMDomain::transfer::AMTransferManager &manager_;
};
} // namespace AMApplication::TransferWorkflow
