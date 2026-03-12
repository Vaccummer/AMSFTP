#include "application/transfer/TransferAppService.hpp"

namespace AMApplication::TransferWorkflow {
/**
 * @brief Construct service from the legacy transfer manager backend.
 */
TransferAppService::TransferAppService(
    AMDomain::transfer::AMTransferManager &manager)
    : manager_(manager) {}

/**
 * @brief Initialize the underlying transfer runtime.
 */
TransferAppService::ECM TransferAppService::Init() { return manager_.Init(); }

/**
 * @brief Execute transfer sets synchronously.
 */
TransferAppService::ECM
TransferAppService::Transfer(const std::vector<UserTransferSet> &transfer_sets,
                             bool quiet, amf interrupt_flag) {
  return manager_.transfer(transfer_sets, quiet, interrupt_flag);
}

/**
 * @brief Execute transfer sets asynchronously.
 */
TransferAppService::ECM TransferAppService::TransferAsync(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    amf interrupt_flag) {
  return manager_.transfer_async(transfer_sets, quiet, interrupt_flag);
}

/**
 * @brief Return tracked transfer task identifiers.
 */
std::vector<TransferAppService::ID> TransferAppService::ListTaskIds() const {
  return manager_.ListTaskIds();
}

/**
 * @brief Resolve one task by identifier.
 */
std::shared_ptr<TaskInfo>
TransferAppService::FindTask(const ID &task_id) const {
  return manager_.FindTask(task_id);
}

/**
 * @brief Return counts of pending and conducting tasks.
 */
void TransferAppService::GetTaskCounts(size_t *pending_count,
                                       size_t *conducting_count) const {
  manager_.GetTaskCounts(pending_count, conducting_count);
}

/**
 * @brief List tasks by status.
 */
TransferAppService::ECM TransferAppService::List(
    bool pending, bool suspend, bool finished, bool conducting,
    amf interrupt_flag) {
  return manager_.List(pending, suspend, finished, conducting, interrupt_flag);
}

/**
 * @brief Show one or more tasks.
 */
TransferAppService::ECM
TransferAppService::Show(const std::vector<ID> &task_ids,
                         amf interrupt_flag) {
  return manager_.Show(task_ids, interrupt_flag);
}

/**
 * @brief Inspect one task.
 */
TransferAppService::ECM TransferAppService::Inspect(
    const ID &task_id, bool show_sets, bool show_entries) const {
  return manager_.Inspect(task_id, show_sets, show_entries);
}

/**
 * @brief Inspect only transfer sets for a task.
 */
TransferAppService::ECM
TransferAppService::InspectTransferSets(const ID &task_id) const {
  return manager_.InspectTransferSets(task_id);
}

/**
 * @brief Inspect only task entries for a task.
 */
TransferAppService::ECM
TransferAppService::InspectTaskEntries(const ID &task_id) const {
  return manager_.InspectTaskEntries(task_id);
}

/**
 * @brief Query one task entry.
 */
TransferAppService::ECM
TransferAppService::QueryTaskEntry(const ID &entry_id) const {
  return manager_.QuerySetEntry(entry_id);
}

/**
 * @brief Get or set worker thread count.
 */
TransferAppService::ECM TransferAppService::Thread(int num) {
  return manager_.Thread(num);
}

/**
 * @brief Terminate tasks by ids.
 */
TransferAppService::ECM
TransferAppService::Terminate(const std::vector<ID> &task_ids,
                              int timeout_ms) {
  return manager_.Terminate(task_ids, timeout_ms);
}

/**
 * @brief Terminate one task by identifier.
 */
TransferAppService::ECM
TransferAppService::Terminate(const ID &task_id, int timeout_ms) {
  return manager_.Terminate(task_id, timeout_ms);
}

/**
 * @brief Pause tasks by ids.
 */
TransferAppService::ECM
TransferAppService::Pause(const std::vector<ID> &task_ids) {
  return manager_.Pause(task_ids);
}

/**
 * @brief Pause one task by identifier.
 */
TransferAppService::ECM TransferAppService::Pause(const ID &task_id) {
  return manager_.Pause(task_id);
}

/**
 * @brief Resume tasks by ids.
 */
TransferAppService::ECM
TransferAppService::Resume(const std::vector<ID> &task_ids) {
  return manager_.Resume(task_ids);
}

/**
 * @brief Resume one task by identifier.
 */
TransferAppService::ECM TransferAppService::Resume(const ID &task_id) {
  return manager_.Resume(task_id);
}

/**
 * @brief Retry one finished task.
 */
TransferAppService::ECM
TransferAppService::Retry(const ID &task_id, bool is_async, bool quiet,
                          const std::vector<int> &indices) {
  return manager_.retry(task_id, is_async, quiet, indices);
}

/**
 * @brief Add one transfer set into the cached job list.
 */
size_t TransferAppService::AddCachedTransferSet(
    const UserTransferSet &transfer_set) {
  return manager_.SubmitTransferSet(transfer_set);
}

/**
 * @brief Remove cached transfer sets by indices.
 */
size_t TransferAppService::RemoveCachedTransferSets(
    const std::vector<size_t> &set_indices) {
  return manager_.DeleteTransferSets(set_indices);
}

/**
 * @brief Clear all cached transfer sets.
 */
void TransferAppService::ClearCachedTransferSets() {
  manager_.ClearCachedTransferSets();
}

/**
 * @brief Submit cached transfer sets.
 */
TransferAppService::ECM
TransferAppService::SubmitCachedTransferSets(bool quiet, amf interrupt_flag,
                                             bool is_async) {
  return manager_.SubmitCachedTransferSets(quiet, interrupt_flag, is_async);
}

/**
 * @brief Query one cached transfer set.
 */
TransferAppService::ECM
TransferAppService::QueryCachedTransferSet(size_t set_index) const {
  return manager_.QueryCachedUserSet(set_index);
}

/**
 * @brief List cached transfer-set identifiers.
 */
std::vector<size_t> TransferAppService::ListCachedTransferSetIds() const {
  return manager_.ListTransferSetIds();
}
} // namespace AMApplication::TransferWorkflow
