#pragma once
#include "CLI/CLI.hpp"
#include "interface/cli/CLIArg.hpp"
#include "interface/parser/CommandTree.hpp"

namespace AMInterface::cli {

/**
 * @brief Run the core interactive loop until the user exits.
 *
 * @param app Parsed CLI app instance reused for interactive parsing.
 * @param cli_commands Bound CLI handles associated with @p app.
 * @param command_tree Bound command tree for completion and token analysis.
 * @param managers Shared manager references for command dispatch.
 * @return Exit code to use when terminating the program.
 */
int RunInteractiveLoop(CLI::App &app, const CliCommands &cli_commands,
                       AMInterface::parser::CommandNode &command_tree,
                       const CLIServices &managers, CliRunContext &ctx);

} // namespace AMInterface::cli
