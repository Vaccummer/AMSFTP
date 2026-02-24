#pragma once
#include "AMBase/DataClass.hpp"
// #include "AMCLI/CLIBind.hpp"
#include "AMCLI/CLIArg.hpp"
#include <functional>
#include <mutex>
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

namespace AMInteractiveLoop {
/**
 * @brief Registry for interactive-loop lifecycle clear callbacks.
 *
 * Two callback groups are supported:
 * - callbacks executed whenever PromptCore returns
 * - callbacks executed once when RunInteractiveLoop exits
 *
 * Callback pointers must remain valid while they are registered.
 */
class EventRegistry : public NonCopyableNonMovable {
public:
  /**
   * @brief Return singleton registry instance.
   */
  static EventRegistry &Instance();

  /**
   * @brief Register callback invoked after each PromptCore return.
   *
   * Duplicate callback pointers are ignored.
   *
   * @param clear_fn Pointer to `std::function<void()>`.
   */
  void RegisterOnCorePromptReturn(std::function<void()> *clear_fn);

  /**
   * @brief Register callback invoked when interactive loop exits.
   *
   * Duplicate callback pointers are ignored.
   *
   * @param clear_fn Pointer to `std::function<void()>`.
   */
  void RegisterOnInteractiveLoopExit(std::function<void()> *clear_fn);

  /**
   * @brief Execute all callbacks for PromptCore-return phase.
   */
  void RunOnCorePromptReturn();

  /**
   * @brief Execute all callbacks for interactive-loop-exit phase.
   */
  void RunOnInteractiveLoopExit();

private:
  /**
   * @brief Construct empty registry.
   */
  EventRegistry() = default;

  /**
   * @brief Register callback into one callback vector.
   */
  void RegisterCallback_(std::vector<std::function<void()> *> *callbacks,
                         std::function<void()> *clear_fn);

  /**
   * @brief Execute callbacks from one callback vector.
   */
  void RunCallbacks_(const std::vector<std::function<void()> *> &callbacks);

  std::mutex mutex_;
  std::vector<std::function<void()> *> core_prompt_return_callbacks_;
  std::vector<std::function<void()> *> interactive_loop_exit_callbacks_;
};
} // namespace AMInteractiveLoop

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
