#pragma once

#include "domain/config/ConfigStorePort.hpp"
#include "foundation/core/DataClass.hpp"

#include <atomic>
#include <typeindex>

namespace AMDomain::config {
/**
 * @brief Base port for services that flush typed config snapshots.
 */
class IConfigSyncPort : public NonCopyableNonMovable {
public:
  explicit IConfigSyncPort(std::type_index config_arg_type)
      : config_arg_type_(config_arg_type) {}
  ~IConfigSyncPort() override = default;

  [[nodiscard]] bool IsConfigDirty() const {
    return config_dirty_.load(std::memory_order_acquire);
  }

  void MarkConfigDirty() {
    config_dirty_.store(true, std::memory_order_release);
  }

  void ClearConfigDirty() {
    config_dirty_.store(false, std::memory_order_release);
  }

  [[nodiscard]] std::type_index GetConfigArgTypeIndex() const {
    return config_arg_type_;
  }

  virtual ECM FlushTo(IConfigStorePort *store) = 0;

protected:
  const std::type_index config_arg_type_;
  std::atomic<bool> config_dirty_{false};
};
} // namespace AMDomain::config
