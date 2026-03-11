#pragma once

#include "domain/client/ClientPort.hpp"
#include "foundation/DataClass.hpp"

#include <functional>
#include <memory>

namespace AMInfra::ClientRuntime {

class TransferExecutionEngine {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
  using ProgressCallback = std::function<void(const std::shared_ptr<TaskInfo> &,
                                              WkProgressData &, bool force)>;

  /**
   * @brief Construct a transfer execution engine with chunk size and progress
   * callback.
   */
  TransferExecutionEngine(size_t chunk_size = 256 * AMKB,
                          ProgressCallback progress_callback = {});

  /**
   * @brief Destroy the execution engine implementation.
   */
  ~TransferExecutionEngine();

  TransferExecutionEngine(const TransferExecutionEngine &) = delete;
  TransferExecutionEngine &operator=(const TransferExecutionEngine &) = delete;
  TransferExecutionEngine(TransferExecutionEngine &&) noexcept;
  TransferExecutionEngine &operator=(TransferExecutionEngine &&) noexcept;

  /**
   * @brief Set the transfer chunk size.
   */
  void SetChunkSize(size_t chunk_size);

  /**
   * @brief Get the current transfer chunk size.
   */
  size_t GetChunkSize() const;

  /**
   * @brief Execute one prepared single-file transfer.
   */
  ECM ExecuteSingleFileTransfer(
      const ClientHandle &src_client, const ClientHandle &dst_client,
      const std::shared_ptr<TaskInfo> &task_info) const;

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace AMInfra::ClientRuntime
