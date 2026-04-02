#pragma once

#include "CLI/CLI.hpp"
#include "bootstrap/BootstrapServices.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/cli/InteractiveLoop.hpp"
#include "interface/parser/CommandTree.hpp"
#include <atomic>
#include <iostream>

namespace AMBootstrap {
inline bool HasParsedCommand(const CLI::App &app) {
  for (const auto *sub : app.get_subcommands()) {
    if (sub && sub->parsed()) {
      return true;
    }
  }
  return false;
}

inline int RunCLI(BootstrapServices &runtime, int argc, char **argv) {
  runtime.cli_app = std::make_unique<CLI::App>("AMSFTP CLI", runtime.app_name);
  runtime.cli_app->set_version_flag("-v,--version", "Show version information");
  runtime.command_tree = {};
  runtime.cli_args_pool = {};
  runtime.cli_commands = AMInterface::cli::BindCliOptions(
      *runtime.cli_app, runtime.cli_args_pool, runtime.command_tree);

  try {
    runtime.cli_app->parse(argc, argv);
  } catch (const CLI::CallForHelp &e) {
    std::cout << runtime.cli_app->help() << std::endl;
    return e.get_exit_code();
  } catch (const CLI::CallForAllHelp &e) {
    std::cout << runtime.cli_app->help("", CLI::AppFormatMode::All)
              << std::endl;
    return e.get_exit_code();
  } catch (const CLI::CallForVersion &e) {
    std::cout << runtime.cli_app->version() << std::endl;
    return e.get_exit_code();
  } catch (const CLI::ParseError &e) {
    return runtime.cli_app->exit(e);
  }
  if (!HasParsedCommand(*runtime.cli_app)) {
    std::cout << runtime.cli_app->help("", CLI::AppFormatMode::All)
              << std::endl;
    return static_cast<int>(EC::InvalidArg);
  }
  runtime.run_ctx.async = false;
  runtime.run_ctx.enforce_interactive = false;
  AMInterface::cli::DispatchCliCommands(runtime.cli_commands, runtime.managers,
                                        runtime.run_ctx);

  if (runtime.run_ctx.enter_interactive) {
    AMInterface::cli::RunInteractiveLoop(*runtime.cli_app, runtime.cli_commands,
                                         runtime.command_tree, runtime.managers,
                                         runtime.run_ctx);
  }

  return runtime.run_ctx.exit_code
             ? runtime.run_ctx.exit_code->load(std::memory_order_relaxed)
             : static_cast<int>(runtime.run_ctx.rcm.code);
}

} // namespace AMBootstrap
