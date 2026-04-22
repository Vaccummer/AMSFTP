#pragma once
#include "domain/transfer/TransferPort.hpp"
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

  [[nodiscard]] std::unordered_map<size_t, bool> GetThreadIDs() const override;

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
  struct PoolControlState_ {
    std::atomic<bool> running{true};
    std::atomic<bool> is_deconstruct{false};
    std::atomic<size_t> desired_thread_count{0};
    std::atomic<size_t> max_thread_count{1};
  };

  struct WorkerRuntime_ {
    std::vector<std::jthread> threads = {};
    mutable std::mutex mtx = {};
    std::vector<std::unique_ptr<TransferExecutionEngine>> engines = {};
  };

  struct QueueRuntime_ {
    mutable std::mutex mtx = {};
    std::condition_variable cv = {};
    std::vector<std::list<TaskID>> affinity = {};
    std::list<TaskID> public_queue = {};
    mutable TaskRegistry registry = {};
  };

  struct ConductingRuntime_ {
    mutable std::mutex mtx = {};
    std::condition_variable cv = {};
    std::unordered_set<TaskID> tasks = {};
    std::vector<TaskID> by_thread = {};
    std::vector<TaskHandle> infos = {};
  };

  struct PoolConfig_ {
    AMDomain::transfer::TransferManagerArg manager_arg = {};
  };

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
  [[nodiscard]] std::unordered_map<TaskID, TaskHandle> GetRegistryCopy() const;

private:
  PoolControlState_ control_ = {};
  WorkerRuntime_ workers_ = {};
  QueueRuntime_ queue_ = {};
  ConductingRuntime_ conducting_ = {};
  PoolConfig_ config_ = {};
};
} // namespace AMInfra::transfer
