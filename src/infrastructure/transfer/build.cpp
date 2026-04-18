#include "infrastructure/transfer/Pool.hpp"

// Port Implemention
namespace AMDomain::transfer {
/**
 * @brief Create default infra-backed transfer pool adapter.
 */
std::unique_ptr<ITransferPoolPort>
CreateTransferPoolPort(const TransferManagerArg &arg) {
  return std::make_unique<AMInfra::transfer::TransferExecutionPool>(arg);
}
} // namespace AMDomain::transfer
