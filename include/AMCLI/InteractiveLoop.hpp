#pragma once
#include "AMBase/DataClass.hpp"
#include "AMCLI/CLIBind.hpp"
#include <string>
#include <vector>

/**
 * @brief Run the core interactive loop until the user exits.
 *
 * @param app_name CLI application name used for CLI11 parsing.
 * @param managers Shared manager references for command dispatch.
 * @return Exit code to use when terminating the program.
 */
int RunInteractiveLoop(const std::string &app_name,
                       const CliManagers &managers);

namespace AMInputPreprocess {
/**
 * @brief Detect `!` shell prefix from one interactive command line.
 *
 * @param input Raw interactive input text.
 * @param shell_command Output shell command without heading `!`.
 * @param is_shell Output flag indicating shell dispatch.
 * @return Success when parsing completes; invalid arg when `!` is empty.
 */
ECM ParseShellPrefix(const std::string &input, std::string *shell_command,
                     bool *is_shell);

/**
 * @brief Split interactive command text into CLI11 argument tokens.
 *
 * Quote wrappers are removed, and backtick escapes are restored for every
 * escaped character except `$` (`` `$`` is preserved for post-parse var
 * substitution).
 */
std::vector<std::string> SplitCliTokens(const std::string &input);

/**
 * @brief Expand variable shorthand tokens into `var get/def` CLI tokens.
 *
 * Supported shorthands:
 * - `$varname`
 * - `$varname=value`
 * - `$varname = value`
 * - `$varname= value`
 * - `$varname =value`
 *
 * Escaped dollars (`` `$``) are preserved as plain text and are not expanded.
 *
 * @param tokens Input/output CLI tokens.
 * @return True if tokens were recognized as shorthand and rewritten.
 */
bool ExpandVarShortcutTokens(std::vector<std::string> *tokens);
} // namespace AMInputPreprocess
