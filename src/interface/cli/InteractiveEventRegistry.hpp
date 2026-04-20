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
  using RegistrationId = size_t;

  InteractiveEventRegistry() = default;
  ~InteractiveEventRegistry() override = default;

  InteractiveEventRegistry::RegistrationId
  Register(InteractiveEventCategory category, std::function<void()> fn) {
    if (!fn) {
      return 0;
    }

    const RegistrationId id =
        next_registration_id_.fetch_add(1, std::memory_order_relaxed);
    auto guard = registry_.lock();
    auto &callbacks = (*guard)[category];
    callbacks.emplace_back(id, std::move(fn));
    return id;
  }

  bool Unregister(InteractiveEventCategory category, RegistrationId id) {
    if (id <= 0) {
      return false;
    }

    auto guard = registry_.lock();
    if (!guard->contains(category)) {
      return false;
    }
    auto map_it = guard->find(category);

    auto &callbacks = map_it->second;
    const auto old_size = callbacks.size();
    const auto erased = std::erase_if(
        callbacks, [id](const CallbackEntry &entry) { return entry.id == id; });
    if (old_size == callbacks.size() || erased == 0) {
      return false;
    }
    return true;
  }

  void Run(InteractiveEventCategory category) {
    // Run against a snapshot copy to avoid holding lock during callback
    // execution.
    RegistryMap snapshot = {};
    {
      auto guard = registry_.lock();
      snapshot = *guard;
    }

    if (!snapshot.contains(category)) {
      return;
    }
    auto map_it = snapshot.find(category);

    for (auto &entry : map_it->second) {
      auto &fn = entry.fn;
      if (!fn) {
        continue;
      }
      try {
        fn();
      } catch (...) {
      }
    }
  }

private:
  struct CallbackEntry {
    RegistrationId id = 0;
    std::function<void()> fn = {};
  };

  using RegistryMap =
      std::unordered_map<InteractiveEventCategory, std::vector<CallbackEntry>>;
  mutable AMAtomic<RegistryMap> registry_ = AMAtomic<RegistryMap>();
  std::atomic<RegistrationId> next_registration_id_{1};
};

} // namespace AMInterface::cli
