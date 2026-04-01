#pragma once
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/enum_related.hpp"
#include <memory>

class AMCompleteEngine;
struct ic_completion_env_s;
namespace AMInterface::cli {
class AMInteractiveEventRegistry;
}
namespace AMInterface::completion {
class ICompletionRuntime;
}
namespace AMInterface::parser {
class CommandNode;
class TokenTypeAnalyzer;
} // namespace AMInterface::parser

/**
 * @brief Completion coordinator for interactive input.
 */
class AMCompleter : public NonCopyableNonMovable {
public:
  /**
   * @brief Construct completer facade.
   */
  AMCompleter(AMInterface::parser::CommandNode *command_tree,
              AMInterface::parser::TokenTypeAnalyzer *token_type_analyzer,
              std::shared_ptr<AMInterface::completion::ICompletionRuntime>
                  runtime,
              AMInterface::cli::AMInteractiveEventRegistry
                  *interactive_event_registry = nullptr);

  /**
   * @brief Stop the async worker and release resources.
   */
  ~AMCompleter() override;

  /**
   * @brief Initialize completer state.
   */
  ECM Init() {
    Install();
    return Ok();
  }

  /**
   * @brief Install completer callback and apply configuration.
   */
  void Install();

  /**
   * @brief Clear any cached completion results.
   */
  void ClearCache();

  /**
   * @brief Return the currently active completer instance.
   */
  static AMCompleter *Active();

  /**
   * @brief Set the active completer instance.
   *
   * @param instance Completer instance or nullptr to clear.
   */
  static void SetActive(AMCompleter *instance);

  static void IsoclineCompleter(ic_completion_env_s *cenv, const char *prefix);

private:
  std::unique_ptr<AMCompleteEngine> engine_;
};
