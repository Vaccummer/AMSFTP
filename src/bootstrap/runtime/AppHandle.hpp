#pragma once

#include "bootstrap/runtime/ConfigAssembly.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/var/VarAppService.hpp"
#include "application/var/VarWorkflows.hpp"
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
            AMApplication::host::AMHostAppService &host_service,
            AMApplication::host::AMKnownHostsAppService &known_hosts_service,
            AMInterface::prompt::IsoclineProfileManager &prompt_profile_history_manager,
            AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
            AMDomain::host::AMHostConfigManager &host_config_manager,
            AMDomain::host::AMKnownHostsManager &known_hosts_manager,
            AMLoggerManagerPort &log_manager,
            AMApplication::client::ClientAppService &client_service,
            AMApplication::filesystem::FilesystemAppService &filesystem_service,
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
  AMApplication::host::AMHostAppService &host_service_;
  AMApplication::host::AMKnownHostsAppService &known_hosts_service_;
  ConfigAssembly config_;
  AMInfra::host::ConfigBackedHostConfigSnapshotStore host_config_store_;
  AMInfra::host::ConfigBackedKnownHostSnapshotStore known_host_store_;
  AMInterface::ApplicationAdapters::ConfigBackedVarRepository
      runtime_var_repository_;
  AMInterface::ApplicationAdapters::CurrentVarDomainProvider
      runtime_var_domain_provider_;
  AMApplication::VarWorkflow::VarAppService runtime_var_service_;

public:
  AMApplication::var::VarAppService var_service;
  CliManagers managers;
};
} // namespace AMBootstrap





