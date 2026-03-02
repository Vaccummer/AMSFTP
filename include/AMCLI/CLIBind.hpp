#pragma once
#include "AMCLI/CLIArg.hpp"
#include "AMCLI/CommandTree.hpp"

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args);

/**
 * @brief Set the exit code and return.
 */
void SetCliExitCode(int code);

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
DispatchResult DispatchCliCommands(const CliCommands &cli_commands,
                                   const CliManagers &managers,
                                   CliRunContext &ctx,
                                   bool async = false,
                                   bool enforce_interactive = false);
