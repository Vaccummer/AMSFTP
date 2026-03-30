#pragma once

#include "domain/transfer/TransferPort.hpp"
#include "foundation/core/DataClass.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace AMDomain::client {
class IClientPort;
}

namespace AMApplication::TransferRuntime {
using ITransferExecutionPort = AMDomain::transfer::ITransferExecutionPort;

/**
 * @brief Application runtime abstraction for transfer client pool leasing.
 */
class ITransferClientPoolPort
    : public AMDomain::transfer::ITransferClientPoolPort {
public:
  virtual ~ITransferClientPoolPort() = default;
};
} // namespace AMApplication::TransferRuntime
