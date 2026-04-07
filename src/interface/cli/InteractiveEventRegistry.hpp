#pragma once

#include "foundation/core/DataClass.hpp"
#include <functional>
#include <unordered_map>
#include <vector>

namespace AMInterface::cli {
enum class InteractiveEventCategory {
  CorePromptReturn = 0,
  InteractiveLoopExit = 1,
};

class InteractiveEventRegistry : public NonCopyableNonMovable {
public:
  InteractiveEventRegistry() = default;
  ~InteractiveEventRegistry() override = default;

  bool Register(InteractiveEventCategory category, int id,
                std::function<void()> fn);
  bool Unregister(InteractiveEventCategory category, int id);
  void Run(InteractiveEventCategory category);

private:
  struct CallbackEntry {
    int id = 0;
    std::function<void()> fn = {};
  };

  using RegistryMap =
      std::unordered_map<InteractiveEventCategory, std::vector<CallbackEntry>>;
  mutable AMAtomic<RegistryMap> registry_ = AMAtomic<RegistryMap>();
};

} // namespace AMInterface::cli
