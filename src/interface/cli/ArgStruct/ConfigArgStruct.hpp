#pragma once

#include "domain/host/HostModel.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include <string>
#include <vector>

namespace AMInterface::cli {

/**
 * @brief CLI argument container for config ls.
 */
struct ConfigLsArgs : BaseArgStruct {
  bool detail = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->ListHosts(detail);
  }
  void reset() override { detail = false; }
};

/**
 * @brief CLI argument container for config keys.
 */
struct ConfigKeysArgs : BaseArgStruct {
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    std::string header = {};
    for (const auto key : AMDomain::host::ConRequest::FieldNames) {
      header += AMStr::ToString(key) + "\t";
    }
    for (const auto key : AMDomain::host::ClientMetaData::FieldNames) {
      header += AMStr::ToString(key) + "\t";
    }
    managers.interfaces.prompt_io_manager->Print(header);
    return OK;
  }
  void reset() override {}
};

/**
 * @brief CLI argument container for config data.
 */
struct ConfigDataArgs : BaseArgStruct {
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.config_interface_service->PrintPaths();
  }
  void reset() override {}
};

/**
 * @brief CLI argument container for config get.
 */
struct ConfigGetArgs : BaseArgStruct {
  AMInterface::client::ListClientsRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->ListHosts(request.nicknames, true);
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for config add.
 */
struct ConfigAddArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->AddHost(nickname);
  }
  void reset() override { nickname.clear(); }
};

/**
 * @brief CLI argument container for config edit.
 */
struct ConfigEditArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->ModifyHost(nickname);
  }
  void reset() override { nickname.clear(); }
};

/**
 * @brief CLI argument container for config rename.
 */
struct ConfigRenameArgs : BaseArgStruct {
  std::string old_name = {};
  std::string new_name = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->RenameHost(old_name, new_name);
  }
  void reset() override {
    old_name.clear();
    new_name.clear();
  }
};

/**
 * @brief CLI argument container for config remove.
 */
struct ConfigRemoveArgs : BaseArgStruct {
  std::vector<std::string> names = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->RemoveHosts(names);
  }
  void reset() override { names.clear(); }
};

/**
 * @brief CLI argument container for config set.
 */
struct ConfigSetArgs : BaseArgStruct {
  AMInterface::client::SetHostValueRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->SetHostValue(request);
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for config save.
 */
struct ConfigSaveArgs : BaseArgStruct {
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.config_interface_service->SaveAll();
  }
  void reset() override {}
};

/**
 * @brief CLI argument container for config backup.
 */
struct ConfigBackupArgs : BaseArgStruct {
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.config_interface_service->BackupAll();
  }
  void reset() override {}
};

/**
 * @brief CLI argument container for config profile set.
 */
struct ConfigProfileSetArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::client::ChangeClientRequest request = {};
    request.nickname = AMStr::Strip(nickname).empty() ? "local" : nickname;
    request.quiet = false;
    return managers.interfaces.client_interface_service->ChangeClient(request);
  }
  void reset() override { nickname.clear(); }
};

} // namespace AMInterface::cli


