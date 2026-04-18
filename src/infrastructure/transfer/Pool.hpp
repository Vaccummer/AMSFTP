#pragma once

#include "infrastructure/transfer/Engine.hpp"

namespace AMInfra::transfer {
class TransferExecutionPool final
    : public AMDomain::transfer::ITransferPoolPort,
      NonCopyableNonMovable {
public:
  explicit TransferExecutionPool(
      const AMDomain::transfer::TransferManagerArg &arg = {});
  ~TransferExecutionPool() override;

  ECM Shutdown(int timeout_ms = 5000) override;
  size_t ThreadCount(size_t new_count = 0) override;
  size_t MaxThreadCount(size_t new_max = 0) override;

  [[nodiscard]] std::unordered_map<size_t, bool>
  GetThreadIDs() const override;

  ECM Submit(TaskHandle task_info) override;

  [[nodiscard]] std::optional<TaskStatus>
  GetStatus(const TaskID &id) const override;

  [[nodiscard]] TaskHandle GetActiveTask(const TaskID &id) const override;

  [[nodiscard]] std::unordered_map<TaskID, TaskHandle>
  GetAllActiveTasks() const override;

  [[nodiscard]] std::unordered_map<TaskID, TaskHandle>
  GetPendingTasks() const override;

  [[nodiscard]] std::unordered_map<TaskID, TaskHandle>
  GetConductingTasks() const override;

  std::pair<TaskHandle, ECM>
  StopActive(const TaskID &id, AMDomain::transfer::ActiveStopReason reason,
             int timeout_ms = 5000, int grace_period_ms = 1500) override;

  std::pair<TaskHandle, ECM> Terminate(const TaskID &id, int timeout_ms = 5000,
                                       int grace_period_ms = 1500) override;

private:
  void CancelPendingTasksOnExit_(
      const std::string &reason = "Task canceled while shutting down");
  void RegisterTask(const TaskHandle &task_info, TaskAssignType assign_type,
                    int affinity_thread);
  [[nodiscard]] std::optional<std::pair<TaskID, TaskHandle>>
  DequeueTask(std::stop_token stop_token, size_t thread_index);
  void HandleCompletedTask(const TaskHandle &task_info);
  void SetConducting(size_t thread_index, const TaskID &task_id,
                     const TaskHandle &task_info);
  void ClearConducting(size_t thread_index);
  void WorkerLoop(std::stop_token stop_token, size_t thread_index);
  [[nodiscard]] size_t ClampMaxThreads_(size_t value) const;
  [[nodiscard]] size_t ComputeDesiredThreadCount_() const;
  void EnsureWorkerCapacity_(size_t worker_count);
  void RecomputeDesiredThreadCount_();
  [[nodiscard]] bool HasPendingTasksUnsafe_() const;
  void StartHeartbeat_();
  void StopHeartbeat_();
  void HeartbeatLoop_(std::stop_token stop_token);
  void HeartbeatTick_();
  [[nodiscard]] std::unordered_map<TaskID, TaskHandle> GetRegistryCopy() const;

private:
  std::atomic<bool> running_{true};
  std::atomic<size_t> desired_thread_count_{0};
  std::atomic<size_t> max_thread_count_{1};
  std::vector<std::jthread> worker_threads_ = {};
  mutable std::mutex worker_mtx_ = {};
  std::jthread heartbeat_thread_ = {};
  std::atomic<bool> heartbeat_running_{false};
  std::atomic<int> heartbeat_interval_s_{0};
  std::atomic<int> heartbeat_timeout_ms_{100};
  mutable std::mutex heartbeat_wait_mtx_ = {};
  std::condition_variable heartbeat_cv_ = {};
  mutable std::mutex queue_mtx_ = {};
  std::condition_variable queue_cv_ = {};
  std::vector<std::list<TaskID>> affinity_queues_ = {};
  std::list<TaskID> public_queue_ = {};
  mutable TaskRegistry task_registry_ = {};
  mutable std::mutex conducting_mtx_ = {};
  std::condition_variable conducting_cv_ = {};
  std::unordered_set<TaskID> conducting_tasks_ = {};
  std::vector<TaskID> conducting_by_thread_ = {};
  std::vector<TaskHandle> conducting_infos_ = {};
  AMDomain::transfer::TransferManagerArg manager_arg_ = {};
  std::vector<std::unique_ptr<TransferExecutionEngine>> engines_ = {};
  std::atomic<bool> is_deconstruct{false};
};
} // namespace AMInfra::transfer
