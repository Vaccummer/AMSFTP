#pragma once

#include "bootstrap/ConfigAssembly.hpp"
#include "infrastructure/host/ConfigBackedHostSnapshotStore.hpp"
#include "interface/CLIArg.hpp"

namespace AMBootstrap {
/**
 * @brief Process-lifetime composition root for CLI manager wiring.
 */
struct AppHandle : NonCopyableNonMovable {
  /**
   * @brief Construct app handle from explicit manager references.
   */
  AppHandle(AMSignalMonitorPort &signal_monitor,
            AMPromptManager &prompt_manager,
            AMDomain::host::AMHostConfigManager &host_config_manager,
            AMDomain::host::AMKnownHostsManager &known_hosts_manager,
            AMDomain::var::VarCLISet &var_manager,
            AMLoggerManagerPort &log_manager,
            AMApplication::client::ClientAppService &client_service,
            AMDomain::transfer::AMTransferManager &transfer_manager,
            AMDomain::filesystem::AMFileSystem &filesystem);

  /**
   * @brief Initialize process-lifetime services and bind runtime adapters.
   */
  ECM Init(const amf &task_control_token);

  /**
   * @brief Clear process-lifetime runtime adapter bindings.
   */
  void ResetRuntimeBindings();

private:
  ConfigAssembly config_;
  AMInfra::host::ConfigBackedHostConfigSnapshotStore host_config_store_;
  AMInfra::host::ConfigBackedKnownHostSnapshotStore known_host_store_;

public:
  CliManagers managers;
};
} // namespace AMBootstrap
