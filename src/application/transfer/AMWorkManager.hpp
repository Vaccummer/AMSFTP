#pragma once

#include "foundation/DataClass.hpp"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace AMApplication::TransferRuntime {
class TaskSchedulerCore;
class ITransferClientPoolPort;
class AMWorkManager {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using TaskId = std::string;

  /**
   * @brief Construct a work manager backed by the application scheduler core.
   */
  AMWorkManager();

  /**
   * @brief Destroy the work manager and stop all workers.
   */
  ~AMWorkManager();

  AMWorkManager(const AMWorkManager &) = delete;
  AMWorkManager &operator=(const AMWorkManager &) = delete;
  AMWorkManager(AMWorkManager &&) noexcept;
  AMWorkManager &operator=(AMWorkManager &&) noexcept;

  /**
   * @brief Gracefully terminate pending/conducting tasks and stop workers.
   */
  ECM GracefulTerminate(int timeout_ms = 5000);

  /**
   * @brief Get or set the chunk size used by transit transfers.
   */
  size_t ChunkSize(int64_t size = -1);

  /**
   * @brief Get or set the desired worker thread count.
   */
  size_t ThreadCount(size_t new_count = 0);

  /**
   * @brief Snapshot occupied and idle worker thread ids.
   */
  std::pair<std::vector<size_t>, std::vector<size_t>> GetThreadIds() const;

  /**
   * @brief Submit one prepared task info object.
   */
  ECM Submit(std::shared_ptr<TaskInfo> task_info);

  /**
   * @brief Create one task info object bound to a transfer client pool.
   */
  std::shared_ptr<TaskInfo>
  CreateTaskInfo(std::shared_ptr<TASKS> tasks,
                 const std::shared_ptr<ITransferClientPoolPort> &pool,
                 TransferCallback callback = TransferCallback(),
                 ssize_t buffer_size = -1, bool quiet = false,
                 int thread_id = -1);

  /**
   * @brief Query task status by id.
   */
  [[nodiscard]] std::optional<TaskStatus> GetStatus(const TaskId &id) const;

  /**
   * @brief Query one cached task result.
   */
  std::shared_ptr<TaskInfo> GetResult(const TaskId &id, bool remove = true);

  /**
   * @brief Query one active task from the registry.
   */
  [[nodiscard]] std::pair<std::shared_ptr<TaskInfo>, bool>
  GetTask(const TaskId &id) const;

  /**
   * @brief Pause one task by id.
   */
  ECM Pause(const TaskId &id, int timeout_ms = 5000);

  /**
   * @brief Resume one task by id.
   */
  ECM Resume(const TaskId &id, int timeout_ms = 5000);

  /**
   * @brief Terminate one task by id.
   */
  std::pair<std::shared_ptr<TaskInfo>, ECM> Terminate(const TaskId &id,
                                                      int timeout_ms = 5000);

  /**
   * @brief Return the total number of pending tasks.
   */
  [[nodiscard]] size_t PendingCount() const;

  /**
   * @brief Return whether any task is currently conducting.
   */
  [[nodiscard]] bool IsConducting() const;

  /**
   * @brief Snapshot currently conducting task ids.
   */
  [[nodiscard]] std::unordered_set<TaskId> GetConductingIds() const;

  /**
   * @brief Clear all cached finished task results.
   */
  void ClearResults();

  /**
   * @brief Remove one cached finished task result.
   */
  bool RemoveResult(const TaskId &id);

  /**
   * @brief Snapshot all cached result ids.
   */
  [[nodiscard]] std::vector<TaskId> GetResultIds() const;

  /**
   * @brief Snapshot the task registry.
   */
  [[nodiscard]] std::unordered_map<TaskId, std::shared_ptr<TaskInfo>>
  GetRegistryCopy() const;

  /**
   * @brief Snapshot all pending tasks.
   */
  [[nodiscard]] std::vector<std::shared_ptr<TaskInfo>> GetPendingTasks() const;

  /**
   * @brief Snapshot all conducting tasks.
   */
  [[nodiscard]] std::vector<std::shared_ptr<TaskInfo>>
  GetConductingTasks() const;

private:
  std::unique_ptr<TaskSchedulerCore> scheduler_;
};
} // namespace AMApplication::TransferRuntime
