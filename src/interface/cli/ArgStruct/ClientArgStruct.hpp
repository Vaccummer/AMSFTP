#pragma once

#include "foundation/tools/string.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include "interface/cli/ArgStruct/CommonHelpers.hpp"
#include <string>

namespace AMInterface::cli {

/**
 * @brief CLI argument container for clients.
 */
struct ClientsArgs : BaseArgStruct {
  AMInterface::client::ListClientsRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto req = request;
    req.check = false;
    return managers.interfaces.client_interface_service->ListClients(req);
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for check.
 */
struct CheckArgs : BaseArgStruct {
  AMInterface::client::CheckClientsRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->CheckClients(request);
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for ch.
 */
struct ChangeClientArgs : BaseArgStruct {
  AMInterface::client::ChangeClientRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    auto req = request;
    if (AMStr::Strip(req.nickname).empty()) {
      req.nickname = "local";
    }
    ECM rcm = managers.interfaces.client_interface_service->ChangeClient(req);
    argstruct_common::SetEnterInteractive(ctx, (rcm));
    return rcm;
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for disconnect.
 */
struct DisconnectArgs : BaseArgStruct {
  AMInterface::client::RemoveClientsRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->RemoveClients(request);
  }
  void reset() override { request = {}; }
};

} // namespace AMInterface::cli


