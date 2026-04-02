#pragma once

#include "CLI/App.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/cli/CLIArg.hpp"
#include "interface/parser/CommandTree.hpp"
#include <filesystem>
#include <memory>
#include <string>

namespace AMBootstrap {
namespace fs = std::filesystem;
using AMDomain::config::ConfigStoreInitArg;

ConfigStoreInitArg BuildConfigInitArg(const fs::path &root_dir);
void PrintBootstrapWarn(const std::string &msg);

struct BootstrapServices final : public NonCopyableNonMovable {
  BootstrapServices() = default;

  std::string app_name = {};
  fs::path root_dir = {};
  std::unique_ptr<CLI::App> cli_app = nullptr;
  AMInterface::parser::CommandNode command_tree = {};
  AMInterface::cli::CliArgsPool cli_args_pool = {};
  AMInterface::cli::CliCommands cli_commands = {};

  AMInterface::cli::CLIServices managers = {};
  AMInterface::cli::CliRunContext run_ctx = {};
};

ECMData<std::unique_ptr<BootstrapServices>>
BuildBootstrapServices(const std::string &app_name, const fs::path &root_dir);
} // namespace AMBootstrap
