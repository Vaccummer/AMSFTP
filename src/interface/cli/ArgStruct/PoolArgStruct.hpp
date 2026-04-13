#pragma once

#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"

namespace AMInterface::cli {

/**
 * @brief CLI argument container for pool ls.
 */
struct PoolLsArgs : BaseArgStruct {
  AMInterface::client::ListPoolClientsRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->PoolLs(request);
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for pool check.
 */
struct PoolCheckArgs : BaseArgStruct {
  AMInterface::client::CheckPoolClientsRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->PoolCheck(request);
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for pool rm.
 */
struct PoolRemoveArgs : BaseArgStruct {
  AMInterface::client::RemovePoolClientsRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->PoolRm(request);
  }
  void reset() override { request = {}; }
};

} // namespace AMInterface::cli
