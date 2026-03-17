#pragma once

#include "foundation/DataClass.hpp"
#include <functional>
#include <memory>
#include <utility>

namespace AMDomain::client {
class IClientPort;
}

namespace AMDomain::transfer {
/**
 * @brief Domain-level runtime abstraction for single-file transfer execution.
 */
class ITransferExecutionPort {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
  using ProgressCallback =
      std::function<void(std::shared_ptr<TaskInfo>, WkProgressData &, bool)>;

  virtual ~ITransferExecutionPort() = default;

  /**
   * @brief Execute one single-file transfer item.
   */
  [[nodiscard]] virtual ECM
  TransferSignleFile(ClientHandle src_client, ClientHandle dst_client,
                     std::shared_ptr<TaskInfo> task_info) const = 0;
};

/**
 * @brief Create default transfer execution port backed by infrastructure.
 */
std::unique_ptr<ITransferExecutionPort> CreateDefaultTransferExecutionPort(
    ITransferExecutionPort::ProgressCallback callback);
} // namespace AMDomain::transfer
