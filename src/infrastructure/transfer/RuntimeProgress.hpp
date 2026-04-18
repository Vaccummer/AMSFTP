#pragma once

#include "infrastructure/transfer/Common.hpp"
#include "infrastructure/transfer/StreamRingBuffer.hpp"

namespace AMInfra::transfer {
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
} // namespace AMInfra::transfer
