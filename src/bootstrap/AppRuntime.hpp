#pragma once

#include "CLI/App.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/cli/CLIArg.hpp"
#include "interface/parser/CommandTree.hpp"

#include <filesystem>
#include <memory>
#include <string>

namespace AMBootstrap {
namespace fs = std::filesystem;

struct AppRuntime final : public NonCopyableNonMovable {
  AppRuntime() = default;
  ~AppRuntime() override;

  [[nodiscard]] ECM Build(const std::string &app_name,
                          const std::string &app_description,
                          const std::string &app_version,
                          const fs::path &root_dir);
  [[nodiscard]] ECM Shutdown();

  std::string app_name = {};
  std::string app_description = {};
  std::string version = {};
  fs::path root_dir = {};
  std::unique_ptr<CLI::App> cli_app = nullptr;

  AMInterface::parser::CommandNode command_tree = {};

  AMInterface::cli::CliArgsPool cli_args_pool = {};
  AMInterface::cli::CliCommands cli_commands = {};

  AMInterface::cli::CLIServices managers = {};
  AMInterface::cli::CliRunContext run_ctx = {};

private:
  void ShutdownNoThrow() noexcept;

  bool is_shutdown_ = true;
};

} // namespace AMBootstrap
