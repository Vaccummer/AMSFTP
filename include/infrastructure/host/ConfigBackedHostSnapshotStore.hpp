#pragma once

#include "application/config/ConfigAppService.hpp"
#include "domain/host/HostPorts.hpp"
#include "foundation/DataClass.hpp"

namespace AMInfra::host {
/**
 * @brief Config-service-backed snapshot store for host configuration data.
 */
class ConfigBackedHostConfigSnapshotStore final
    : public AMDomain::host::IHostConfigSnapshotStore,
      public NonCopyableNonMovable {
public:
  /**
   * @brief Construct one store with an optional bound config service.
   */
  explicit ConfigBackedHostConfigSnapshotStore(
      AMApplication::config::AMConfigAppService *config_service = nullptr);

  /**
   * @brief Bind the config application service used for persistence.
   */
  void Bind(AMApplication::config::AMConfigAppService *config_service);

  [[nodiscard]] std::pair<ECM, AMDomain::host::HostConfigArg>
  LoadSnapshot() const override;

  ECM SaveSnapshot(const AMDomain::host::HostConfigArg &snapshot,
                   bool dump_async = true) override;

private:
  AMApplication::config::AMConfigAppService *config_service_ = nullptr;
};

/**
 * @brief Config-service-backed snapshot store for known-host data.
 */
class ConfigBackedKnownHostSnapshotStore final
    : public AMDomain::host::IKnownHostSnapshotStore,
      public NonCopyableNonMovable {
public:
  /**
   * @brief Construct one store with an optional bound config service.
   */
  explicit ConfigBackedKnownHostSnapshotStore(
      AMApplication::config::AMConfigAppService *config_service = nullptr);

  /**
   * @brief Bind the config application service used for persistence.
   */
  void Bind(AMApplication::config::AMConfigAppService *config_service);

  [[nodiscard]] std::pair<ECM, AMDomain::host::KnownHostEntryArg>
  LoadSnapshot() const override;

  ECM SaveSnapshot(const AMDomain::host::KnownHostEntryArg &snapshot,
                   bool dump_async = true) override;

private:
  AMApplication::config::AMConfigAppService *config_service_ = nullptr;
};
} // namespace AMInfra::host
