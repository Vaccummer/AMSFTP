#pragma once

#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include <string>
#include <vector>

namespace AMInterface::cli {

/**
 * @brief CLI argument container for `var get`.
 */
struct VarGetArgs : BaseArgStruct {
  std::string varname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.var_interface_service->QueryAndPrintVar(varname);
  }
  void reset() override { varname.clear(); }
};

/**
 * @brief CLI argument container for `var def`.
 */
struct VarDefArgs : BaseArgStruct {
  bool global = false;
  std::string varname = {};
  std::string value = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.var_interface_service->DefineVar(global, varname, value);
  }
  void reset() override {
    global = false;
    varname.clear();
    value.clear();
  }
};

/**
 * @brief CLI argument container for `var del`.
 */
struct VarDelArgs : BaseArgStruct {
  bool all = false;
  std::vector<std::string> tokens = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.var_interface_service->DeleteVar(all, tokens);
  }
  void reset() override {
    all = false;
    tokens.clear();
  }
};

/**
 * @brief CLI argument container for `var ls`.
 */
struct VarLsArgs : BaseArgStruct {
  std::vector<std::string> sections = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.var_interface_service->ListVars(sections);
  }
  void reset() override { sections.clear(); }
};

} // namespace AMInterface::cli


