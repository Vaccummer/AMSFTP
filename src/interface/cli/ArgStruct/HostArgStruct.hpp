#pragma once

#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include <string>
#include <vector>

namespace AMInterface::cli {

/**
 * @brief CLI argument container for host ls.
 */
struct HostLsArgs : BaseArgStruct {
  bool detail = false;
  std::vector<std::string> nicknames = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->ListHosts(nicknames,
                                                                    detail);
  }
  void reset() override {
    detail = false;
    nicknames.clear();
  }
};

/**
 * @brief CLI argument container for host get.
 */
struct HostGetArgs : BaseArgStruct {
  std::vector<std::string> nicknames = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->ListHosts(nicknames,
                                                                    true);
  }
  void reset() override { nicknames.clear(); }
};

/**
 * @brief CLI argument container for host add.
 */
struct HostAddArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->AddHost(nickname);
  }
  void reset() override { nickname.clear(); }
};

/**
 * @brief CLI argument container for host edit.
 */
struct HostEditArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->ModifyHost(nickname);
  }
  void reset() override { nickname.clear(); }
};

/**
 * @brief CLI argument container for host rename.
 */
struct HostRenameArgs : BaseArgStruct {
  std::string old_name = {};
  std::string new_name = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->RenameHost(old_name,
                                                                    new_name);
  }
  void reset() override {
    old_name.clear();
    new_name.clear();
  }
};

/**
 * @brief CLI argument container for host remove.
 */
struct HostRemoveArgs : BaseArgStruct {
  std::vector<std::string> names = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->RemoveHosts(names);
  }
  void reset() override { names.clear(); }
};

/**
 * @brief CLI argument container for host set.
 */
struct HostSetArgs : BaseArgStruct {
  AMInterface::client::SetHostValueRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->SetHostValue(request);
  }
  void reset() override { request = {}; }
};

} // namespace AMInterface::cli

