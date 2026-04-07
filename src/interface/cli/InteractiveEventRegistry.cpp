#include "interface/cli/InteractiveEventRegistry.hpp"

#include <algorithm>

namespace AMInterface::cli {

bool InteractiveEventRegistry::Register(InteractiveEventCategory category,
                                        int id,
                                        std::function<void()> fn) {
  if (id <= 0 || !fn) {
    return false;
  }

  auto guard = registry_.lock();
  auto &callbacks = (*guard)[category];
  const auto dup_it =
      std::find_if(callbacks.begin(), callbacks.end(),
                   [id](const CallbackEntry &entry) { return entry.id == id; });
  if (dup_it != callbacks.end()) {
    return false;
  }

  callbacks.push_back({id, std::move(fn)});
  return true;
}

bool InteractiveEventRegistry::Unregister(InteractiveEventCategory category,
                                          int id) {
  if (id <= 0) {
    return false;
  }

  auto guard = registry_.lock();
  auto map_it = guard->find(category);
  if (map_it == guard->end()) {
    return false;
  }

  auto &callbacks = map_it->second;
  const auto old_size = callbacks.size();
  callbacks.erase(std::remove_if(callbacks.begin(), callbacks.end(),
                                 [id](const CallbackEntry &entry) {
                                   return entry.id == id;
                                 }),
                  callbacks.end());
  if (callbacks.size() == old_size) {
    return false;
  }
  return true;
}

void InteractiveEventRegistry::Run(InteractiveEventCategory category) {
  // Run against a snapshot copy to avoid holding lock during callback execution.
  RegistryMap snapshot = {};
  {
    auto guard = registry_.lock();
    snapshot = *guard;
  }

  auto map_it = snapshot.find(category);
  if (map_it == snapshot.end()) {
    return;
  }

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

} // namespace AMInterface::cli
