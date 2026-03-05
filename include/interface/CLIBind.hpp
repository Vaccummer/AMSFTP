#pragma once
#include "interface/CLIArg.hpp"

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args);

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
void DispatchCliCommands(const CliCommands &cli_commands,
                         const CliManagers &managers, CliRunContext &ctx,
                         bool async = false,
                         bool enforce_interactive = false);
