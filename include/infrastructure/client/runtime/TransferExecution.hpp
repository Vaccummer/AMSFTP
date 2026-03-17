#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/DataClass.hpp"

#include <functional>
#include <memory>

namespace AMInfra::ClientRuntime {

class TransferExecutionEngine final
    : public AMDomain::transfer::ITransferExecutionPort,
      NonCopyableNonMovable {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
  using ProgressCallback = std::function<void(std::shared_ptr<TaskInfo>,
                                              WkProgressData &, bool force)>;

  /**
   * @brief Construct a transfer execution engine with progress callback.
   */
  explicit TransferExecutionEngine(ProgressCallback progress_callback = {});

  /**
   * @brief Destroy the execution engine implementation.
   */
  ~TransferExecutionEngine() override;

  /**
   * @brief Execute one prepared single-file transfer.
   */
  ECM TransferSignleFile(ClientHandle src_client, ClientHandle dst_client,
                         std::shared_ptr<TaskInfo> task_info) const override;

private:
  ProgressCallback progress_callback_ = {};
};

} // namespace AMInfra::ClientRuntime
