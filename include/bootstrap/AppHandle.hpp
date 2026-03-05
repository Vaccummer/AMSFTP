#pragma once

#include "foundation//tools/enum_related.hpp"
#include "interface/ApplicationAdapters.hpp"
#include "interface/CLIArg.hpp"

namespace AMBootstrap {
/**
 * @brief Process-lifetime composition root for CLI manager wiring.
 */
struct AppHandle : NonCopyableNonMovable {
  /**
   * @brief Construct app handle from explicit manager references.
   */
  AppHandle(AMInfraCliSignalMonitor &signal_monitor,
            AMInfraConfigManager &config_manager,
            AMPromptManager &prompt_manager, AMDomain::host::AMHostManager &host_manager,
            AMDomain::var::VarCLISet &var_manager, AMInfraLogManager &log_manager,
            AMDomain::client::AMClientManager &client_manager,
            AMDomain::transfer::AMTransferManager &transfer_manager, AMDomain::filesystem::AMFileSystem &filesystem)
      : managers(signal_monitor, config_manager, prompt_manager, host_manager,
                 var_manager, log_manager, client_manager, transfer_manager,
                 filesystem) {}

  /**
   * @brief Initialize process-lifetime services and bind runtime adapters.
   */
  ECM Init(const amf &task_control_token) {
    AMInterface::ApplicationAdapters::Runtime::RuntimeBindings bindings{};
    bindings.host_manager = &managers.host_manager;
    bindings.client_manager = &managers.client_manager;
    bindings.transfer_manager = &managers.transfer_manager;
    bindings.var_manager = &managers.var_manager;
    bindings.signal_monitor = &managers.signal_monitor;
    bindings.prompt_manager = &managers.prompt_manager;
    bindings.config_manager = &managers.config_manager;
    bindings.filesystem = &managers.filesystem;
    AMInterface::ApplicationAdapters::Runtime::Bind(bindings);
    ECM rcm = managers.Init(task_control_token);
    if (!isok(rcm)) {
      AMInterface::ApplicationAdapters::Runtime::Reset();
      return rcm;
    }
    return Ok();
  }

  /**
   * @brief Clear process-lifetime runtime adapter bindings.
   */
  void ResetRuntimeBindings() {
    AMInterface::ApplicationAdapters::Runtime::Reset();
  }

  CliManagers managers;
};
} // namespace AMBootstrap
