#pragma once
#include "interface/cli/CLIArg.hpp"
#include "interface/parser/CommandTree.hpp"

namespace AMInterface::cli {

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args,
                           AMInterface::parser::CommandNode &command_tree);

/**
 * @brief Bind the completion generation command.
 */
void BindCompletionCommands(AMInterface::parser::CommandNode *root,
                            CliArgsPool &args);

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
void DispatchCliCommands(const CliCommands &cli_commands,
                         const CLIServices &managers, CliRunContext &ctx);

} // namespace AMInterface::cli

