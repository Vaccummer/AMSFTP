#pragma once

#include "CLI/CLI.hpp"
#include "bootstrap/BootstrapServices.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/cli/CliParseFlow.hpp"
#include "interface/cli/InteractiveLoop.hpp"
#include "interface/cli/MainHelpFormatter.hpp"
#include "interface/prompt/Prompt.hpp"
#include <atomic>

namespace AMBootstrap {
inline int RunCLI(BootstrapServices &runtime, int argc, char **argv) {
  runtime.cli_app = std::make_unique<CLI::App>("AMSFTP CLI", runtime.app_name);
  runtime.cli_app->set_version_flag("--version", "Show version information");
  runtime.cli_app->allow_windows_style_options(false);
  runtime.command_tree = {};
  runtime.cli_args_pool = {};
  runtime.cli_commands = AMInterface::cli::BindCliOptions(
      *runtime.cli_app, runtime.cli_args_pool, runtime.command_tree);

  const AMInterface::style::AMStyleService *style_service = nullptr;
  if (runtime.managers.interfaces.style_service.IsReady()) {
    style_service = &runtime.managers.interfaces.style_service.Get();
    AMInterface::cli::InstallMainHelpFormatter(*runtime.cli_app, *style_service,
                                               &runtime.command_tree);
  }

  const auto parse_outcome = AMInterface::cli::ParseCliArgv(
      {
          .app = runtime.cli_app.get(),
          .command_tree = &runtime.command_tree,
          .style_service = style_service,
          .validate_unknown_command = (style_service != nullptr),
          .require_command = true,
          .show_all_help_when_no_command = true,
      },
      argc, argv);

  if (!parse_outcome.ShouldDispatch()) {
    if (!parse_outcome.message.empty()) {
      AMInterface::prompt::PromptIOManager::StaticPrint(parse_outcome.message);
    }
    return parse_outcome.exit_code != 0
               ? parse_outcome.exit_code
               : static_cast<int>(parse_outcome.rcm.code);
  }

  runtime.run_ctx.async = false;
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
