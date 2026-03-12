#pragma once

#include "application/client/runtime/ClientPublicPool.hpp"
#include "foundation/DataClass.hpp"

#include <atomic>
#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace AMInfra::ClientRuntime {
class TransferExecutionEngine;
}

namespace AMApplication::TransferRuntime {

class TaskSchedulerCore {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using EC = ErrorCode;
  using TaskId = std::string;
  using ClientHandle = AMDomain::client::ClientHandle;
  using ClientProtocol = AMDomain::client::ClientProtocol;

  /**
   * @brief Construct a scheduler core with one default worker thread.
   */
  TaskSchedulerCore();

  /**
   * @brief Stop all workers and release scheduler-owned runtime resources.
   */
  ~TaskSchedulerCore();

  TaskSchedulerCore(const TaskSchedulerCore &) = delete;
  TaskSchedulerCore &operator=(const TaskSchedulerCore &) = delete;
  TaskSchedulerCore(TaskSchedulerCore &&) = delete;
  TaskSchedulerCore &operator=(TaskSchedulerCore &&) = delete;

  /**
   * @brief Gracefully terminate pending/conducting tasks and stop workers.
   */
  ECM GracefulTerminate(int timeout_ms = 5000);

  /**
   * @brief Set or get the chunk size used by transit transfers.
   */
  size_t ChunkSize(int64_t size = -1);

  /**
   * @brief Adjust or query the worker thread count.
   */
  size_t ThreadCount(size_t new_count = 0);

  /**
   * @brief Snapshot occupied and idle worker thread ids.
   */
  std::pair<std::vector<size_t>, std::vector<size_t>> GetThreadIds() const;

  /**
   * @brief Submit an already-constructed TaskInfo object.
   */
  ECM Submit(std::shared_ptr<TaskInfo> task_info);

  /**
   * @brief Build one TaskInfo from transfer tasks and public pool.
   */
  std::shared_ptr<TaskInfo>
  CreateTaskInfo(std::shared_ptr<TASKS> tasks,
                 const std::shared_ptr<AMApplication::client::ClientPublicPool>
                     &pool,
                 TransferCallback callback = TransferCallback(),
                 ssize_t buffer_size = -1, bool quiet = false,
                 int thread_id = -1);

  /**
   * @brief Query task status by ID.
   */
  std::optional<TaskStatus> GetStatus(const TaskId &id) const;

  /**
   * @brief Query task result and optionally remove it from the cache.
   */
  std::shared_ptr<TaskInfo> GetResult(const TaskId &id, bool remove = true);

  /**
   * @brief Get task info from the active registry.
   */
  std::pair<std::shared_ptr<TaskInfo>, bool> GetTask(const TaskId &id) const;

  /**
   * @brief Pause a task by ID and wait for paused status.
   */
  ECM Pause(const TaskId &id, int timeout_ms = 5000);

  /**
   * @brief Resume a task by ID and wait for in-flight pause to complete.
   */
  ECM Resume(const TaskId &id, int timeout_ms = 5000);

  /**
   * @brief Terminate a task by ID and optionally wait for completion.
   */
  std::pair<std::shared_ptr<TaskInfo>, ECM> Terminate(const TaskId &id,
                                                      int timeout_ms = 5000);

  /**
   * @brief Get the total number of pending tasks across all queues.
   */
  size_t PendingCount() const;

  /**
   * @brief Check whether any task is currently conducting.
   */
  bool IsConducting() const;

  /**
   * @brief Get a copy of currently conducting task IDs.
   */
  std::unordered_set<TaskId> GetConductingIds() const;

  /**
   * @brief Clear all finished results from the cache.
   */
  void ClearResults();

  /**
   * @brief Remove a specific result from the cache.
   */
  bool RemoveResult(const TaskId &id);

  /**
   * @brief Get all result IDs currently cached.
   */
  std::vector<std::string> GetResultIds() const;

  /**
   * @brief Snapshot the task registry map.
   */
  std::unordered_map<std::string, std::shared_ptr<TaskInfo>>
  GetRegistryCopy() const;

  /**
   * @brief Snapshot all pending tasks that have not started yet.
   */
  std::vector<std::shared_ptr<TaskInfo>> GetPendingTasks() const;

  /**
   * @brief Snapshot all currently conducting tasks.
   */
  std::vector<std::shared_ptr<TaskInfo>> GetConductingTasks() const;

private:
  /**
   * @brief Clamp requested worker count into a supported range.
   */
  static size_t ClampThreadCount(size_t count);

  /**
   * @brief Check whether a thread ID is valid for affinity scheduling.
   */
  bool IsValidThreadId(int thread_id) const;

  /**
   * @brief Check whether a task id is already in use.
   */
  bool IsTaskIdUsed_(const TaskId &task_id) const;

  /**
   * @brief Generate a simple numeric task id that does not duplicate.
   */
  TaskId GenerateTaskId_() const;

  /**
   * @brief Determine whether any pending tasks exist while queue lock is held.
   */
  bool HasPendingTasksLocked() const;

  /**
   * @brief Bind one task id to a transfer pool instance.
   */
  void SetTaskPool_(const TaskId &task_id,
                    const std::shared_ptr<AMApplication::client::ClientPublicPool>
                        &pool);

  /**
   * @brief Get transfer pool snapshot for one task id.
   */
  std::shared_ptr<AMApplication::client::ClientPublicPool>
  GetTaskPool_(const TaskId &task_id) const;

  /**
   * @brief Remove and return transfer pool binding for one task id.
   */
  std::shared_ptr<AMApplication::client::ClientPublicPool>
  TakeTaskPool_(const TaskId &task_id);

  /**
   * @brief Release one task's pooled client leases and pool binding.
   */
  void ReleaseTaskResources_(const TaskId &task_id);

  /**
   * @brief Cancel all pending tasks during shutdown.
   */
  void CancelPendingTasksOnExit_(
      const std::string &reason = "Task canceled while shutting down");

  /**
   * @brief Ensure progress data and inner callback are prepared.
   */
  void EnsureProgressData(const std::shared_ptr<TaskInfo> &task_info);

  /**
   * @brief Register a task and enqueue it into the appropriate queue.
   */
  void RegisterTask(const std::shared_ptr<TaskInfo> &task_info,
                    TaskAssignType assign_type, int affinity_thread);

  /**
   * @brief Dequeue a task for a specific worker thread.
   */
  std::optional<std::pair<TaskId, std::shared_ptr<TaskInfo>>>
  DequeueTask(size_t thread_index);

  /**
   * @brief Store a completed task or invoke its result callback.
   */
  void HandleCompletedTask(const std::shared_ptr<TaskInfo> &task_info);

  /**
   * @brief Mark a task as currently conducting on a worker thread.
   */
  void SetConducting(size_t thread_index, const TaskId &task_id,
                     const std::shared_ptr<TaskInfo> &task_info);

  /**
   * @brief Clear conducting state for a worker thread.
   */
  void ClearConducting(size_t thread_index);

  /**
   * @brief Dispatch the internal progress callback wrapper.
   */
  void InnerCallback(std::shared_ptr<TaskInfo> task_info, WkProgressData &pd,
                     bool force = false);

  /**
   * @brief Check whether a task should be skipped before conducting.
   */
  bool ShouldSkipTask(std::shared_ptr<TaskInfo> task_info);

  /**
   * @brief Resolve one transfer-buffer hint from request config.
   */
  static ssize_t ResolveBufferHint_(const ClientHandle &client);

  /**
   * @brief Calculate one transfer buffer size from clients and overrides.
   */
  ssize_t CalculateBufferSize(const ClientHandle &src_client,
                              const ClientHandle &dst_client,
                              ssize_t provided_size);

  /**
   * @brief Normalize one task nickname to canonical transfer-pool key.
   */
  static std::string CanonicalTaskNickname_(const std::string &nickname);

  /**
   * @brief Collect distinct client nicknames required by one task.
   */
  std::vector<std::string>
  CollectTaskNicknames_(const std::shared_ptr<TaskInfo> &task_info) const;

  /**
   * @brief Acquire the pooled clients required by one task execution pass.
   */
  std::pair<ECM, std::unordered_map<std::string, ClientHandle>>
  AcquireTaskClients_(const std::shared_ptr<TaskInfo> &task_info,
                      const std::shared_ptr<AMApplication::client::ClientPublicPool>
                          &pool);

  /**
   * @brief Resolve one client handle from the acquired task client map.
   */
  ClientHandle ResolveTaskClient_(
      const std::unordered_map<std::string, ClientHandle> &clients,
      const std::string &nickname) const;

  /**
   * @brief Run one worker loop for the assigned thread index.
   */
  void WorkerLoop(size_t thread_index);

  /**
   * @brief Execute all file entries inside one TaskInfo.
   */
  void ExecuteTask(std::shared_ptr<TaskInfo> task_info);

  std::atomic<bool> running_{true};
  std::atomic<size_t> desired_thread_count_{1};

  std::vector<std::thread> worker_threads_;

  mutable std::mutex queue_mtx_;
  std::condition_variable queue_cv_;
  std::vector<std::list<TaskId>> affinity_queues_;
  std::list<TaskId> public_queue_;

  /**
   * @brief Lock order policy: queue -> registry -> task_pool -> result ->
   * conducting.
   */
  mutable std::mutex registry_mtx_;
  std::unordered_map<TaskId, std::shared_ptr<TaskInfo>> task_registry_;
  mutable std::mutex task_pool_mtx_;
  std::unordered_map<TaskId, std::shared_ptr<AMApplication::client::ClientPublicPool>>
      task_pools_;

  mutable std::mutex result_mtx_;
  std::unordered_map<TaskId, std::shared_ptr<TaskInfo>> results_;

  mutable std::mutex conducting_mtx_;
  std::condition_variable conducting_cv_;
  std::unordered_set<TaskId> conducting_tasks_;
  std::vector<TaskId> conducting_by_thread_;
  std::vector<std::shared_ptr<TaskInfo>> conducting_infos_;
  size_t chunk_size_ = 256 * AMKB;
  std::atomic<bool> is_deconstruct{false};
  std::unique_ptr<AMInfra::ClientRuntime::TransferExecutionEngine>
      execution_engine_;
};

} // namespace AMApplication::TransferRuntime
