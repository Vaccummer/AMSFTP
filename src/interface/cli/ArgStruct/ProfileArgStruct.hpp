#pragma once

#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include <string>
#include <unordered_set>
#include <vector>

namespace AMInterface::cli {

/**
 * @brief CLI argument container for profile edit.
 */
struct ProfileEditArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    const std::string literal = AMStr::Strip(nickname);
    if (literal.empty()) {
      const ECM rcm =
          Err(EC::InvalidArg, __func__, "", "empty profile nickname");
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
      return rcm;
    }
    if (!AMDomain::host::HostService::ValidateNickname(literal)) {
      const ECM rcm = Err(EC::InvalidArg, __func__, literal,
                          "invalid profile nickname literal");
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
      return rcm;
    }
    const std::string target = AMDomain::host::HostService::NormalizeNickname(
        literal);
    const auto host_query = managers.application.host_service->GetClientConfig(
        target, true);
    if (!(host_query)) {
      const ECM rcm =
          Err(EC::HostConfigNotFound, __func__, target, "Host not found");
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
      return rcm;
    }
    const ECM rcm = managers.interfaces.config_interface_service->EditProfile(
        target);
    if (!(rcm)) {
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
    }
    return rcm;
  }
  void reset() override { nickname.clear(); }
};

/**
 * @brief CLI argument container for profile get.
 */
struct ProfileGetArgs : BaseArgStruct {
  std::vector<std::string> nicknames = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    if (nicknames.empty()) {
      const ECM rcm = Err(EC::InvalidArg, __func__, "",
                          "profile get requires at least one nickname");
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
      return rcm;
    }

    std::vector<std::string> targets = {};
    std::unordered_set<std::string> seen = {};
    targets.reserve(nicknames.size());
    for (const auto &nickname : nicknames) {
      const std::string literal = AMStr::Strip(nickname);
      if (literal.empty()) {
        const ECM rcm =
            Err(EC::InvalidArg, __func__, "", "empty profile nickname");
        managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
        return rcm;
      }
      if (!AMDomain::host::HostService::ValidateNickname(literal)) {
        const ECM rcm = Err(EC::InvalidArg, __func__, literal,
                            "invalid profile nickname literal");
        managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
        return rcm;
      }

      const std::string target =
          AMDomain::host::HostService::NormalizeNickname(literal);
      const auto host_query = managers.application.host_service->GetClientConfig(
          target, true);
      if (!(host_query)) {
        const ECM rcm =
            Err(EC::HostConfigNotFound, __func__, target, "Host not found");
        managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
        return rcm;
      }
      if (seen.insert(target).second) {
        targets.push_back(target);
      }
    }

    const ECM rcm = managers.interfaces.config_interface_service->GetProfile(
        targets);
    if (!(rcm)) {
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
    }
    return rcm;
  }
  void reset() override { nicknames.clear(); }
};

} // namespace AMInterface::cli


