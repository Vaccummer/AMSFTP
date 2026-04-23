#pragma once

#include "bootstrap/AppRuntime.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/cli/CliParseFlow.hpp"
#include "interface/cli/InteractiveLoop.hpp"
#include "interface/prompt/Prompt.hpp"
#include <atomic>

namespace AMBootstrap {
inline int RunCLI(AppRuntime &runtime, int argc, char **argv) {
  if (!runtime.cli_app || !runtime.cli_commands.app || !runtime.cli_commands.args) {
    return static_cast<int>(EC::InvalidHandle);
  }

  const AMInterface::style::AMStyleService *style_service = nullptr;
  if (runtime.managers.interfaces.style_service.IsReady()) {
    style_service = &runtime.managers.interfaces.style_service.Get();
  }

  const auto parse_outcome = AMInterface::cli::ParseCliArgv(
      {
          .app = runtime.cli_app.get(),
          .command_tree = &runtime.command_tree,
          .style_service = style_service,
          .validate_unknown_command = (style_service != nullptr),
          .require_command = true,
          .show_all_help_when_no_command = false,
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
