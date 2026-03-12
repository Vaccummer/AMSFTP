#include "application/transfer/runtime/AMWorkManager.hpp"

#include "application/transfer/runtime/TaskPlanner.hpp"
#include "TaskSchedulerCore.hpp"

#include <memory>
#include <utility>

/**
 * @brief Construct one application-owned work manager facade.
 */
AMWorkManager::AMWorkManager()
    : scheduler_(
          std::make_unique<AMApplication::TransferRuntime::TaskSchedulerCore>()) {
}

/**
 * @brief Destroy one application-owned work manager facade.
 */
AMWorkManager::~AMWorkManager() = default;

/**
 * @brief Move-construct one work manager facade.
 */
AMWorkManager::AMWorkManager(AMWorkManager &&) noexcept = default;

/**
 * @brief Move-assign one work manager facade.
 */
AMWorkManager &AMWorkManager::operator=(AMWorkManager &&) noexcept = default;

/**
 * @brief Gracefully terminate pending/conducting tasks and stop workers.
 */
AMWorkManager::ECM AMWorkManager::GracefulTerminate(int timeout_ms) {
  return scheduler_->GracefulTerminate(timeout_ms);
}

/**
 * @brief Get or set the chunk size used by transit transfers.
 */
size_t AMWorkManager::ChunkSize(int64_t size) {
  return scheduler_->ChunkSize(size);
}

/**
 * @brief Get or set the desired worker thread count.
 */
size_t AMWorkManager::ThreadCount(size_t new_count) {
  return scheduler_->ThreadCount(new_count);
}

/**
 * @brief Snapshot occupied and idle worker thread ids.
 */
std::pair<std::vector<size_t>, std::vector<size_t>>
AMWorkManager::GetThreadIds() const {
  return scheduler_->GetThreadIds();
}

/**
 * @brief Submit one prepared task info object.
 */
AMWorkManager::ECM AMWorkManager::Submit(std::shared_ptr<TaskInfo> task_info) {
  return scheduler_->Submit(std::move(task_info));
}

/**
 * @brief Create one task info object bound to a transfer client pool.
 */
std::shared_ptr<TaskInfo> AMWorkManager::CreateTaskInfo(
    std::shared_ptr<TASKS> tasks,
    const std::shared_ptr<AMApplication::client::ClientPublicPool> &pool,
    TransferCallback callback, ssize_t buffer_size, bool quiet, int thread_id) {
  return scheduler_->CreateTaskInfo(std::move(tasks), pool, std::move(callback),
                                    buffer_size, quiet, thread_id);
}

/**
 * @brief Query task status by id.
 */
std::optional<TaskStatus> AMWorkManager::GetStatus(const TaskId &id) const {
  return scheduler_->GetStatus(id);
}

/**
 * @brief Query one cached task result.
 */
std::shared_ptr<TaskInfo> AMWorkManager::GetResult(const TaskId &id,
                                                   bool remove) {
  return scheduler_->GetResult(id, remove);
}

/**
 * @brief Query one active task from the registry.
 */
std::pair<std::shared_ptr<TaskInfo>, bool>
AMWorkManager::GetTask(const TaskId &id) const {
  return scheduler_->GetTask(id);
}

/**
 * @brief Pause one task by id.
 */
AMWorkManager::ECM AMWorkManager::Pause(const TaskId &id, int timeout_ms) {
  return scheduler_->Pause(id, timeout_ms);
}

/**
 * @brief Resume one task by id.
 */
AMWorkManager::ECM AMWorkManager::Resume(const TaskId &id, int timeout_ms) {
  return scheduler_->Resume(id, timeout_ms);
}

/**
 * @brief Terminate one task by id.
 */
std::pair<std::shared_ptr<TaskInfo>, AMWorkManager::ECM>
AMWorkManager::Terminate(const TaskId &id, int timeout_ms) {
  return scheduler_->Terminate(id, timeout_ms);
}

/**
 * @brief Return the total number of pending tasks.
 */
size_t AMWorkManager::PendingCount() const { return scheduler_->PendingCount(); }

/**
 * @brief Return whether any task is currently conducting.
 */
bool AMWorkManager::IsConducting() const { return scheduler_->IsConducting(); }

/**
 * @brief Snapshot currently conducting task ids.
 */
std::unordered_set<AMWorkManager::TaskId> AMWorkManager::GetConductingIds() const {
  return scheduler_->GetConductingIds();
}

/**
 * @brief Clear all cached finished task results.
 */
void AMWorkManager::ClearResults() { scheduler_->ClearResults(); }

/**
 * @brief Remove one cached finished task result.
 */
bool AMWorkManager::RemoveResult(const TaskId &id) {
  return scheduler_->RemoveResult(id);
}

/**
 * @brief Snapshot all cached result ids.
 */
std::vector<std::string> AMWorkManager::GetResultIds() const {
  return scheduler_->GetResultIds();
}

/**
 * @brief Snapshot the task registry.
 */
std::unordered_map<std::string, std::shared_ptr<TaskInfo>>
AMWorkManager::GetRegistryCopy() const {
  return scheduler_->GetRegistryCopy();
}

/**
 * @brief Snapshot all pending tasks.
 */
std::vector<std::shared_ptr<TaskInfo>> AMWorkManager::GetPendingTasks() const {
  return scheduler_->GetPendingTasks();
}

/**
 * @brief Snapshot all conducting tasks.
 */
std::vector<std::shared_ptr<TaskInfo>>
AMWorkManager::GetConductingTasks() const {
  return scheduler_->GetConductingTasks();
}

/**
 * @brief Plan transfer tasks through the extracted application planner.
 */
std::pair<AMWorkManager::ECM, TASKS>
AMWorkManager::LoadTasks(const std::string &src, const std::string &dst,
                         AMDomain::client::IClientRuntimePort &runtime_port,
                         AMDomain::client::IClientLifecyclePort &lifecycle_port,
                         const std::string &src_host,
                         const std::string &dst_host, bool clone,
                         bool overwrite, bool mkdir,
                         bool ignore_sepcial_file, bool resume,
                         std::shared_ptr<TaskControlToken> control_token,
                         int timeout_ms, int64_t start_time) {
  return AMApplication::TransferRuntime::TaskPlanner::LoadTasks(
      src, dst, runtime_port, lifecycle_port, src_host, dst_host, clone,
      overwrite, mkdir, ignore_sepcial_file, resume, std::move(control_token),
      timeout_ms, start_time);
}
