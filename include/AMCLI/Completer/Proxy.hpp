#pragma once
#include "foundation/DataClass.hpp"
#include "foundation/tools/enum_related.hpp"

class AMCompleteEngine;
struct ic_completion_env_s;

/**
 * @brief Completion coordinator for interactive input.
 */
class AMCompleter : public NonCopyableNonMovable {
public:
  /**
   * @brief Construct completer facade.
   */
  AMCompleter();

  /**
   * @brief Stop the async worker and release resources.
   */
  ~AMCompleter() override;

  /**
   * @brief Initialize completer state.
   */
  ECM Init() override {
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
