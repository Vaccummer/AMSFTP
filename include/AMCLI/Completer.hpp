#pragma once
#include "AMBase/DataClass.hpp"
#include <memory>
#include <string>

struct ic_completion_env_s;
using ic_completion_env_t = ic_completion_env_s;

/**
 * @brief Base implementation storage and operations for AMCompleter.
 */
class AMCompleterImpl {
public:
  /**
   * @brief Initialize completer runtime state.
   */
  AMCompleterImpl();

  /**
   * @brief Stop async worker and release runtime state.
   */
  virtual ~AMCompleterImpl();

  /**
   * @brief Read all completion settings and cache them for the current install.
   */
  void LoadConfig();

  /**
   * @brief Install isocline completion callback and apply configuration.
   *
   * @param completion_arg Callback context argument passed to isocline.
   */
  void Install(void *completion_arg);

  /**
   * @brief Clear path completion caches.
   */
  void ClearCache();

  /**
   * @brief Handle one completion request.
   */
  void HandleCompletion(ic_completion_env_t *cenv, const std::string &input,
                        size_t cursor);

protected:
  /**
   * @brief Runtime state holder for completion internals.
   */
  struct State;
  std::unique_ptr<State> state_;

  int complete_max_items_ = -1;
  long complete_max_rows_ = 9;
  bool complete_number_pick_ = true;
  bool complete_auto_fill_ = true;
  std::string complete_select_sign_;
  int complete_delay_ms_ = 100;
  size_t cache_min_items_ = 100;
  size_t cache_max_entries_ = 64;
  std::string input_tag_command_;
  std::string input_tag_module_;
};

/**
 * @brief Completion coordinator for interactive input.
 */
class AMCompleter : public NonCopyableNonMovable, AMCompleterImpl {
public:
  using Impl = AMCompleterImpl;

  /**
   * @brief Construct completer facade.
   */
  AMCompleter() { SetActive(this); }

  /**
   * @brief Stop the async worker and release resources.
   */
  ~AMCompleter() override { SetActive(nullptr); }

  /**
   * @brief Initialize completer state.
   */
  void Init() override {
    Install(this);
    LoadConfig();
  }

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

public:
  /**
   * @brief Isocline callback entrypoint for completion.
   *
   * @param cenv Completion environment provided by isocline.
   * @param prefix Raw input prefix before the cursor.
   */
  static void IsoclineCompleter(ic_completion_env_t *cenv, const char *prefix);
};
