#include "AMCLI/Completer.hpp"
#include "Isocline/isocline.h"
#include <atomic>
#include <string>

namespace {
/**
 * @brief Active completer singleton.
 */
std::atomic<AMCompleter *> g_active_completer{nullptr};
} // namespace

/**
 * @brief Construct completer facade.
 */
AMCompleter::AMCompleter() { SetActive(this); }

/**
 * @brief Stop the async worker and release resources.
 */
AMCompleter::~AMCompleter() { SetActive(nullptr); }

/**
 * @brief Initialize completer state.
 */
void AMCompleter::Init() { Install(); }

/**
 * @brief Install completer callback and apply configuration.
 */
void AMCompleter::Install() {
  engine_.Install(this);
  engine_.LoadConfig();
}

/**
 * @brief Clear any cached completion results.
 */
void AMCompleter::ClearCache() { engine_.ClearCache(); }

/**
 * @brief Return the currently active completer instance.
 */
AMCompleter *AMCompleter::Active() {
  return g_active_completer.load(std::memory_order_relaxed);
}

/**
 * @brief Set the active completer instance.
 */
void AMCompleter::SetActive(AMCompleter *instance) {
  g_active_completer.store(instance, std::memory_order_relaxed);
}

/**
 * @brief Isocline callback entrypoint for completion.
 */
void AMCompleter::IsoclineCompleter(ic_completion_env_t *cenv,
                                    const char *prefix) {
  (void)prefix;
  if (!cenv) {
    return;
  }
  auto *self = static_cast<AMCompleter *>(ic_completion_arg(cenv));
  if (!self) {
    return;
  }
  long cursor = 0;
  const char *input = ic_completion_input(cenv, &cursor);
  if (!input || cursor < 0) {
    return;
  }
  self->engine_.HandleCompletion(cenv, std::string(input),
                                 static_cast<size_t>(cursor));
}
