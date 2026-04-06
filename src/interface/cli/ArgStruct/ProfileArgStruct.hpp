#pragma once

#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include <string>
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
    return managers.interfaces.prompt_io_manager->Edit(nickname);
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
    return managers.interfaces.prompt_io_manager->Get(nicknames);
  }
  void reset() override { nicknames.clear(); }
};

} // namespace AMInterface::cli


