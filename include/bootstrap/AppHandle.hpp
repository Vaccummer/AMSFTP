#pragma once

#include "bootstrap/ConfigAssembly.hpp"
#include "infrastructure/host/ConfigBackedHostSnapshotStore.hpp"
#include "interface/adapters/ApplicationAdapters.hpp"
#include "interface/cli/CLIArg.hpp"

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
            AMLoggerManagerPort &log_manager,
            AMApplication::client::ClientAppService &client_service,
            AMApplication::TransferWorkflow::TransferAppService
                &transfer_service);

  /**
   * @brief Initialize process-lifetime services and bind runtime adapters.
   */
  ECM Init(amf task_control_token);

  /**
   * @brief Clear process-lifetime runtime adapter bindings.
   */
  void ResetRuntimeBindings();

private:
  ConfigAssembly config_;
  AMInfra::host::ConfigBackedHostConfigSnapshotStore host_config_store_;
  AMInfra::host::ConfigBackedKnownHostSnapshotStore known_host_store_;
  AMInterface::ApplicationAdapters::ConfigBackedVarRepository var_repository_;
  AMInterface::ApplicationAdapters::CurrentVarDomainProvider
      current_var_domain_provider_;

public:
  AMApplication::VarWorkflow::VarAppService var_service;
  CliManagers managers;
};
} // namespace AMBootstrap



