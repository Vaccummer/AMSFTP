#pragma once
#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/core/DataClass.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace AMInfra::transfer {
using EC = ErrorCode;
using ProgressCBInfo = AMDomain::transfer::ProgressCBInfo;
using ErrorCBInfo = AMDomain::transfer::ErrorCBInfo;
using TaskHandle = std::shared_ptr<AMDomain::transfer::TaskInfo>;
using TaskStatus = AMDomain::transfer::TaskStatus;
using TaskInfo = AMDomain::transfer::TaskInfo;
using TaskId = TaskInfo::ID;
using TaskAssignType = ::TaskAssignType;
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TransferTask = AMDomain::transfer::TransferTask;

struct TransferBufferPolicy {
  size_t default_buffer_size =
      AMDomain::client::ClientService::AMDefaultRemoteBufferSize;
  size_t min_buffer_size = AMDomain::client::ClientService::AMMinBufferSize;
  size_t max_buffer_size = AMDomain::client::ClientService::AMMaxBufferSize;
};

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
  mutable std::mutex wait_mtx_;
  mutable std::condition_variable wait_cv_;

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
   * @brief Get the writable contiguous region.
   */
  std::span<char> get_write_span() {
    size_t t = tail_.load(std::memory_order_relaxed);
    size_t h = head_.load(std::memory_order_acquire);
    size_t pos = t % capacity_;
    size_t used = t - h;
    size_t free_space = capacity_ - used;
    size_t contig = capacity_ - pos > free_space ? free_space : capacity_ - pos;
    return std::span<char>(buffer_.data() + pos, contig);
  }

  /**
   * @brief Backward-compatible writable pointer view.
   */
  std::pair<char *, size_t> get_write_ptr() {
    auto span = get_write_span();
    return {span.data(), span.size()};
  }

  /**
   * @brief Commit a number of bytes as written to the buffer.
   */
  void commit_write(size_t len) {
    tail_.fetch_add(len, std::memory_order_release);
    wait_cv_.notify_all();
  }

  /**
   * @brief Get the readable contiguous region.
   */
  std::span<char> get_read_span() {
    size_t h = head_.load(std::memory_order_relaxed);
    size_t t = tail_.load(std::memory_order_acquire);
    size_t pos = h % capacity_;
    size_t avail = t - h;
    size_t contig = capacity_ - pos > avail ? avail : capacity_ - pos;
    return std::span<char>(buffer_.data() + pos, contig);
  }

  /**
   * @brief Backward-compatible readable pointer view.
   */
  std::pair<char *, size_t> get_read_ptr() {
    auto span = get_read_span();
    return {span.data(), span.size()};
  }

  /**
   * @brief Commit a number of bytes as consumed from the buffer.
   */
  void commit_read(size_t len) {
    head_.fetch_add(len, std::memory_order_release);
    wait_cv_.notify_all();
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

  void Reset() {
    head_.store(0, std::memory_order_relaxed);
    tail_.store(0, std::memory_order_relaxed);
    NotifyAll();
  }

  void NotifyAll() const { wait_cv_.notify_all(); }

  bool WaitWritable(const std::function<bool()> &should_stop = {},
                    int wait_ms = 50) const {
    if (writable() > 0) {
      return true;
    }
    std::unique_lock<std::mutex> lock(wait_mtx_);
    wait_cv_.wait_for(lock, std::chrono::milliseconds(std::max(1, wait_ms)),
                      [&]() { return writable() > 0 || (should_stop && should_stop()); });
    return writable() > 0;
  }

  bool WaitReadable(const std::function<bool()> &should_stop = {},
                    int wait_ms = 50) const {
    if (available() > 0) {
      return true;
    }
    std::unique_lock<std::mutex> lock(wait_mtx_);
    wait_cv_.wait_for(lock, std::chrono::milliseconds(std::max(1, wait_ms)),
                      [&]() { return available() > 0 || (should_stop && should_stop()); });
    return available() > 0;
  }
};

struct TransferRuntimeProgress {
  TaskHandle task_info = nullptr;
  std::shared_ptr<StreamRingBuffer> ring_buffer = nullptr;
  std::atomic<bool> io_abort{false};
  double cb_time = 0.0;
  explicit TransferRuntimeProgress(TaskHandle task_info = nullptr);
  void CallInnerCallback(bool force = false);
  void UpdateSize(size_t delta) const;
  [[nodiscard]] AMDomain::transfer::TransferTask *GetCurrentTask() const;
};

class TransferExecutionEngine final : NonCopyableNonMovable {
public:
  using ClientHandle = AMInfra::transfer::ClientHandle;

  explicit TransferExecutionEngine(
      const TransferBufferPolicy &buffer_policy = {});
  ~TransferExecutionEngine() override;

  void ExecuteTask(const TaskHandle &task_info);

  ECM TransferSignleFile(ClientHandle src_client, ClientHandle dst_client,
                         TransferRuntimeProgress &runtime_progress);

private:
  struct ReadJob {
    ClientHandle src_client = nullptr;
    TaskHandle task_info = nullptr;
    TransferRuntimeProgress *runtime_progress = nullptr;
    std::promise<ECM> promise = {};
  };

  void ReadLoop_(std::stop_token stop_token);
  std::future<ECM> EnqueueReadJob_(ClientHandle src_client,
                                   const TaskHandle &task_info,
                                   TransferRuntimeProgress *runtime_progress);
  [[nodiscard]] size_t ResolveTaskBufferSize_(
      const TaskHandle &task_info) const;

private:
  TransferBufferPolicy buffer_policy_ = {};
  mutable std::mutex read_queue_mtx_ = {};
  std::condition_variable read_queue_cv_ = {};
  std::deque<ReadJob> read_queue_ = {};
  std::jthread read_thread_ = {};
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

  explicit TransferExecutionPool(
      const AMDomain::transfer::TransferManagerArg &arg = {});
  ~TransferExecutionPool() override;

  ECM Shutdown(int timeout_ms = 5000) override;
  size_t ThreadCount(size_t new_count = 0) override;
  size_t MaxThreadCount(size_t new_max = 0) override;

  std::unordered_map<size_t, bool> GetThreadIDs() const override;

  ECM Submit(TaskHandle task_info) override;

  [[nodiscard]] std::optional<TaskStatus>
  GetStatus(const TaskId &id) const override;

  [[nodiscard]] TaskHandle GetActiveTask(const TaskId &id) const override;

  [[nodiscard]] std::unordered_map<TaskId, TaskHandle>
  GetAllActiveTasks() const override;

  [[nodiscard]] std::unordered_map<TaskId, TaskHandle>
  GetPendingTasks() const override;

  [[nodiscard]] std::unordered_map<TaskId, TaskHandle>
  GetConductingTasks() const override;

  std::pair<TaskHandle, ECM> StopActive(
      const TaskId &id, AMDomain::transfer::ActiveStopReason reason,
      int timeout_ms = 5000) override;

  std::pair<TaskHandle, ECM> Terminate(const TaskId &id,
                                       int timeout_ms = 5000) override;

private:
  void CancelPendingTasksOnExit_(
      const std::string &reason = "Task canceled while shutting down");

  void RegisterTask(const TaskHandle &task_info, TaskAssignType assign_type,
                    int affinity_thread);

  std::optional<std::pair<TaskId, TaskHandle>>
  DequeueTask(std::stop_token stop_token, size_t thread_index);

  void HandleCompletedTask(const TaskHandle &task_info);

  void SetConducting(size_t thread_index, const TaskId &task_id,
                     const TaskHandle &task_info);

  void ClearConducting(size_t thread_index);

  void WorkerLoop(std::stop_token stop_token, size_t thread_index);

  size_t ClampMaxThreads_(size_t value) const;
  size_t ComputeDesiredThreadCount_() const;
  void EnsureWorkerCapacity_(size_t worker_count);
  void RecomputeDesiredThreadCount_();
  bool HasPendingTasksUnsafe_() const;

  void StartHeartbeat_();
  void StopHeartbeat_();
  void HeartbeatLoop_(std::stop_token stop_token);
  void HeartbeatTick_();

  std::unordered_map<TaskId, TaskHandle> GetRegistryCopy() const;

  std::atomic<bool> running_{true};
  std::atomic<size_t> desired_thread_count_{0};
  std::atomic<size_t> max_thread_count_{1};

  std::vector<std::jthread> worker_threads_;
  mutable std::mutex worker_mtx_ = {};
  std::jthread heartbeat_thread_ = {};
  std::atomic<bool> heartbeat_running_{false};
  std::atomic<int> heartbeat_interval_s_{0};
  std::atomic<int> heartbeat_timeout_ms_{100};
  mutable std::mutex heartbeat_wait_mtx_ = {};
  std::condition_variable heartbeat_cv_ = {};

  mutable std::mutex queue_mtx_;
  std::condition_variable queue_cv_;
  std::vector<std::list<TaskId>> affinity_queues_;
  std::list<TaskId> public_queue_;

  mutable AMAtomic<std::unordered_map<TaskId, TaskHandle>> task_registry_;

  mutable std::mutex conducting_mtx_;
  std::condition_variable conducting_cv_;
  std::unordered_set<TaskId> conducting_tasks_;
  std::vector<TaskId> conducting_by_thread_;
  std::vector<TaskHandle> conducting_infos_;
  AMDomain::transfer::TransferManagerArg manager_arg_ = {};
  std::vector<std::unique_ptr<TransferExecutionEngine>> engines_ = {};
  std::atomic<bool> is_deconstruct{false};
};
} // namespace AMInfra::transfer


