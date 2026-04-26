#pragma once

#include "infrastructure/transfer/Common.hpp"
#include "infrastructure/transfer/RuntimeProgress.hpp"

#include <deque>
#include <future>
#include <semaphore>

namespace AMInfra::transfer {
class TransferExecutionEngine final : NonCopyableNonMovable {
public:
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

  void ReadLoop_();
  std::future<ECM> EnqueueReadJob_(ClientHandle src_client,
                                   const TaskHandle &task_info,
                                   TransferRuntimeProgress *runtime_progress);
  [[nodiscard]] size_t
  ResolveTaskBufferSize_(const TaskHandle &task_info) const;

private:
  TransferBufferPolicy buffer_policy_ = {};
  mutable std::mutex read_queue_mtx_ = {};
  std::deque<ReadJob> read_queue_ = {};
  std::counting_semaphore<> read_queue_ready_{0};
  std::atomic<bool> stop_requested_{false};
  std::thread read_thread_ = {};
};
} // namespace AMInfra::transfer
