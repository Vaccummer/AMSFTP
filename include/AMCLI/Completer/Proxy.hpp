#pragma once
#include "AMBase/DataClass.hpp"
#include "AMCLI/Completer/Engine.hpp"

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
  void Init() override;

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

  static void IsoclineCompleter(ic_completion_env_t *cenv, const char *prefix);

private:
  AMCompleteEngine engine_{};
};


