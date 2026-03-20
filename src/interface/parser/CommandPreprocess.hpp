#pragma once
#include "foundation/core/DataClass.hpp"
#include <string>
#include <vector>

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
 * @brief Expand variable shorthand tokens into `var get/def/ls` CLI tokens.
 *
 * Supported shorthands:
 * - `$`
 * - `$zone:`
 * - `$:`
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
