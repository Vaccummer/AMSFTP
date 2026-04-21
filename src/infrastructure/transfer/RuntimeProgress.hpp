#pragma once

#include "infrastructure/transfer/Common.hpp"
#include "infrastructure/transfer/StreamRingBuffer.hpp"

#include <cstddef>

namespace AMInfra::transfer {
struct SftpWriteTuning {
  size_t bucket_index = 6; // 1MB
  size_t consecutive_eagain = 0;
  size_t consecutive_good = 0;
  size_t consecutive_short = 0;

  void Reset() {
    bucket_index = 6; // 1MB
    consecutive_eagain = 0;
    consecutive_good = 0;
    consecutive_short = 0;
  }
};

struct TransferRuntimeProgress {
  TaskHandle task_info = nullptr;
  std::shared_ptr<StreamRingBuffer> ring_buffer = nullptr;
  std::shared_ptr<SftpWriteTuning> sftp_write_tuning = nullptr;
  std::atomic<bool> io_abort{false};
  double cb_time = 0.0;

  explicit TransferRuntimeProgress(TaskHandle task_info = nullptr);
  void CallInnerCallback(bool force = false);
  void UpdateSize(size_t delta) const;
  [[nodiscard]] AMDomain::transfer::TransferTask *GetCurrentTask() const;
};
} // namespace AMInfra::transfer
