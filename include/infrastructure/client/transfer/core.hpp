#pragma once
#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/DataClass.hpp"
#include <algorithm>
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

namespace AMInfra::transfer {
using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;

using TaskHandle = std::shared_ptr<AMDomain::transfer::TaskInfo>;
using TaskStatus = AMDomain::transfer::TaskStatus;
using TaskInfo = AMDomain::transfer::TaskInfo;
using TaskId = TaskInfo::ID;
using TaskAssignType = ::TaskAssignType;
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TransferTask = AMDomain::transfer::TransferTask;

class StreamRingBuffer {
private:
  /**
   * @brief Backing storage for the ring buffer.
   *
   * This uses std::array to replace the raw char[] buffer. The effective
   * capacity is clamped to the requested size at construction time.
   */
  std::vector<char> buffer_{};
  size_t capacity_ = 0;
  std::atomic<size_t> head_{0}; // Consumer read position
  std::atomic<size_t> tail_{0}; // Producer write position

public:
  /**
   * @brief Construct a ring buffer with a requested capacity.
   *
   * @param size Requested buffer size in bytes. The actual capacity is clamped
   *             to the maximum std::array size.
   */
  explicit StreamRingBuffer(size_t size)
      : capacity_(std::max<size_t>(size, 1)) {
    this->buffer_.resize(capacity_);
  }

  /**
   * @brief Get the amount of readable data in the buffer.
   */
  size_t available() const {
    return tail_.load(std::memory_order_acquire) -
           head_.load(std::memory_order_relaxed);
  }

  /**
   * @brief Get the amount of writable space remaining in the buffer.
   */
  size_t writable() const { return capacity_ - available(); }

  /**
   * @brief Get the write pointer and maximum contiguous writable length.
   */
  std::pair<char *, size_t> get_write_ptr() {
    size_t t = tail_.load(std::memory_order_relaxed);
    size_t h = head_.load(std::memory_order_acquire);
    size_t pos = t % capacity_;
    size_t used = t - h;
    size_t free_space = capacity_ - used;
    // Contiguous writable = min(distance to end, free space)
    size_t contig = capacity_ - pos > free_space ? free_space : capacity_ - pos;
    return {buffer_.data() + pos, contig};
  }

  /**
   * @brief Commit a number of bytes as written to the buffer.
   */
  void commit_write(size_t len) {
    tail_.fetch_add(len, std::memory_order_release);
  }

  /**
   * @brief Get the read pointer and maximum contiguous readable length.
   */
  std::pair<char *, size_t> get_read_ptr() {
    size_t h = head_.load(std::memory_order_relaxed);
    size_t t = tail_.load(std::memory_order_acquire);
    size_t pos = h % capacity_;
    size_t avail = t - h;
    // Contiguous readable = min(distance to end, available data)
    size_t contig = capacity_ - pos > avail ? avail : capacity_ - pos;
    return {buffer_.data() + pos, contig};
  }

  /**
   * @brief Commit a number of bytes as consumed from the buffer.
   */
  void commit_read(size_t len) {
    head_.fetch_add(len, std::memory_order_release);
  }

  /**
   * @brief Check whether the buffer has no readable data.
   */
  bool empty() const { return available() == 0; }

  /**
   * @brief Check whether the buffer has no writable space.
   */
  bool full() const { return writable() == 0; }

  /**
   * @brief Get the effective capacity of the buffer.
   */
  size_t get_capacity() const { return capacity_; }
};

struct TransferRuntimeProgress {
  TaskHandle task_info = nullptr;
  std::shared_ptr<StreamRingBuffer> ring_buffer = nullptr;
  double cb_time = 0.0;

  explicit TransferRuntimeProgress(TaskHandle task_info = nullptr);

  void CallInnerCallback(bool force = false);
  void UpdateSize(size_t delta) const;
  [[nodiscard]] AMDomain::transfer::TransferTask *GetCurrentTask() const;
};

class TransferExecutionEngine final : NonCopyableNonMovable {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ClientHandle = AMInfra::transfer::ClientHandle;

  explicit TransferExecutionEngine();
  ~TransferExecutionEngine() override;

  ECM TransferSignleFile(ClientHandle src_client, ClientHandle dst_client,
                         TransferRuntimeProgress &runtime_progress) const;
};

class TransferExecutionPool final
    : public AMDomain::transfer::ITransferPoolPort,
      NonCopyableNonMovable {
public:
  using TaskHandle = AMInfra::transfer::TaskHandle;
  using TaskStatus = AMInfra::transfer::TaskStatus;
  using TaskInfo = AMInfra::transfer::TaskInfo;
  using TaskId = AMInfra::transfer::TaskId;
  using TaskAssignType = AMInfra::transfer::TaskAssignType;
  using ClientHandle = AMInfra::transfer::ClientHandle;
  using TransferClientContainer = AMInfra::transfer::TransferClientContainer;

  explicit TransferExecutionPool();
  ~TransferExecutionPool() override;

  ECM Shutdown(int timeout_ms = 5000) override;
  size_t ThreadCount(size_t new_count = 0) override;

  std::unordered_map<size_t, bool> GetThreadIDs() const override;

  ECM Submit(TaskHandle task_info, TransferClientContainer clients) override;

  [[nodiscard]] std::optional<TaskStatus>
  GetStatus(const TaskId &id) const override;

  TaskHandle GetResultTask(const TaskId &id, bool remove = true) override;

  [[nodiscard]] TaskHandle GetActiveTask(const TaskId &id) const override;

  [[nodiscard]] std::unordered_map<TaskId, TaskHandle>
  GetAllActiveTasks() const override;

  [[nodiscard]] std::unordered_map<TaskId, TaskHandle>
  GetPendingTasks() const override;

  [[nodiscard]] std::unordered_map<TaskId, TaskHandle>
  GetConductingTasks() const override;

  [[nodiscard]] std::unordered_map<TaskId, TaskHandle>
  GetAllHistoryTasks() const override;

  void ClearResults() override;
  bool RemoveResult(const TaskId &id) override;

  ECM Pause(const TaskId &id, int timeout_ms = 5000) override;
  ECM Resume(const TaskId &id, int timeout_ms = 5000) override;

  std::pair<TaskHandle, ECM> Terminate(const TaskId &id,
                                       int timeout_ms = 5000) override;

private:
  void CancelPendingTasksOnExit_(
      const std::string &reason = "Task canceled while shutting down");

  void RegisterTask(const TaskHandle &task_info, TaskAssignType assign_type,
                    int affinity_thread);

  std::optional<std::pair<TaskId, TaskHandle>> DequeueTask(size_t thread_index);

  void HandleCompletedTask(const TaskHandle &task_info);

  void SetConducting(size_t thread_index, const TaskId &task_id,
                     const TaskHandle &task_info);

  void ClearConducting(size_t thread_index);

  void WorkerLoop(size_t thread_index);

  void ExecuteTask(const TaskHandle &task_info);

  std::unordered_map<TaskId, TaskHandle> GetRegistryCopy() const;

  std::atomic<bool> running_{true};
  std::atomic<size_t> desired_thread_count_{1};

  std::vector<std::thread> worker_threads_;

  mutable std::mutex queue_mtx_;
  std::condition_variable queue_cv_;
  std::vector<std::list<TaskId>> affinity_queues_;
  std::list<TaskId> public_queue_;

  mutable AMAtomic<std::unordered_map<TaskId, TaskHandle>> task_registry_;

  mutable AMAtomic<std::unordered_map<TaskId, TaskHandle>> results_;

  mutable std::mutex conducting_mtx_;
  std::condition_variable conducting_cv_;
  std::unordered_set<TaskId> conducting_tasks_;
  std::vector<TaskId> conducting_by_thread_;
  std::vector<TaskHandle> conducting_infos_;
  TransferExecutionEngine transfer_engine_ = TransferExecutionEngine();
  std::atomic<bool> is_deconstruct{false};
};
} // namespace AMInfra::transfer
