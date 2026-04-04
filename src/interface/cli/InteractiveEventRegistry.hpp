#pragma once

#include "foundation/core/DataClass.hpp"
#include <functional>
#include <mutex>
#include <vector>

namespace AMInterface::cli {

class AMInteractiveEventRegistry : public NonCopyableNonMovable {
public:
  AMInteractiveEventRegistry() = default;
  ~AMInteractiveEventRegistry() override = default;

  void RegisterOnCorePromptReturn(std::function<void()> *clear_fn);
  void RegisterOnInteractiveLoopExit(std::function<void()> *clear_fn);
  void RunOnCorePromptReturn();
  void RunOnInteractiveLoopExit();

private:
  void RegisterCallback_(std::vector<std::function<void()> *> *callbacks,
                         std::function<void()> *clear_fn);
  void RunCallbacks_(const std::vector<std::function<void()> *> &callbacks);

  std::mutex mutex_ = {};
  std::vector<std::function<void()> *> core_prompt_return_callbacks_ = {};
  std::vector<std::function<void()> *> interactive_loop_exit_callbacks_ = {};
};

} // namespace AMInterface::cli
