#pragma once

#include "infrastructure/transfer/Common.hpp"
#include "infrastructure/transfer/StreamRingBuffer.hpp"

#include <cstdint>

namespace AMInfra::transfer {
struct SftpWriteStats {
  uint64_t write_requests = 0;
  uint64_t libssh2_calls = 0;
  uint64_t success_calls = 0;
  uint64_t short_writes = 0;
  uint64_t zero_writes = 0;
  uint64_t eagain_retries = 0;
  uint64_t fatal_errors = 0;
  uint64_t logical_requested_bytes = 0;
  uint64_t attempted_bytes = 0;
  uint64_t written_bytes = 0;
  uint64_t max_request_bytes = 0;
  uint64_t max_written_bytes = 0;
  double first_call_time = 0.0;
  double last_call_time = 0.0;

  void Reset() { *this = {}; }
};

struct TransferRuntimeProgress {
  TaskHandle task_info = nullptr;
  std::shared_ptr<StreamRingBuffer> ring_buffer = nullptr;
  std::shared_ptr<SftpWriteStats> sftp_write_stats = nullptr;
  std::atomic<bool> io_abort{false};
  double cb_time = 0.0;

  explicit TransferRuntimeProgress(TaskHandle task_info = nullptr);
  void CallInnerCallback(bool force = false);
  void UpdateSize(size_t delta) const;
  [[nodiscard]] AMDomain::transfer::TransferTask *GetCurrentTask() const;
};
} // namespace AMInfra::transfer
