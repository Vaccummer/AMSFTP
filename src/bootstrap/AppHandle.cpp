#include "bootstrap/AppHandle.hpp"

#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "interface/ApplicationAdapters.hpp"

namespace AMBootstrap {
/**
 * @brief Construct app handle from explicit manager references.
 */
AppHandle::AppHandle(AMSignalMonitorPort &signal_monitor,
                     AMPromptManager &prompt_manager,
                     AMDomain::host::AMHostConfigManager &host_config_manager,
                     AMDomain::host::AMKnownHostsManager &known_hosts_manager,
                     AMDomain::var::VarCLISet &var_manager,
                     AMLoggerManagerPort &log_manager,
                     AMApplication::client::ClientAppService &client_service,
                     AMDomain::transfer::AMTransferManager &transfer_manager,
                     AMDomain::filesystem::AMFileSystem &filesystem)
    : config_(), host_config_store_(), known_host_store_(),
      managers(signal_monitor, config_.ConfigService(), config_.StyleService(),
               prompt_manager, host_config_manager, known_hosts_manager,
               var_manager, log_manager, client_service, transfer_manager,
               filesystem) {}

/**
 * @brief Initialize process-lifetime services and bind runtime adapters.
 */
ECM AppHandle::Init(const amf &task_control_token) {
  std::string root_dir;
  if (!AMStr::GetEnv("AMSFTP_ROOT", &root_dir)) {
    return Err(EC::ProgrammInitializeFailed,
               "Failed to get $AMSFTP_ROOT environment variable");
  }

  ECM rcm = config_.Init(std::filesystem::path(root_dir));
  if (!isok(rcm)) {
    return rcm;
  }

  host_config_store_.Bind(&config_.ConfigService());
  known_host_store_.Bind(&config_.ConfigService());
  managers.host_config_manager.BindSnapshotStore(&host_config_store_);
  managers.known_hosts_manager.BindSnapshotStore(&known_host_store_);

  AMInterface::ApplicationAdapters::Runtime::RuntimeBindings bindings{};
  bindings.host_config_manager = &managers.host_config_manager;
  bindings.known_hosts_manager = &managers.known_hosts_manager;
  bindings.client_service = &managers.client_service;
  bindings.transfer_manager = &managers.transfer_manager;
  bindings.var_manager = &managers.var_manager;
  bindings.signal_monitor = &managers.signal_monitor;
  bindings.prompt_manager = &managers.prompt_manager;
  bindings.config_service = &config_.ConfigService();
  bindings.style_service = &config_.StyleService();
  bindings.filesystem = &managers.filesystem;
  AMInterface::ApplicationAdapters::Runtime::Bind(bindings);

  rcm = managers.Init(task_control_token);
  if (!isok(rcm)) {
    AMInterface::ApplicationAdapters::Runtime::Reset();
    config_.Close();
    return rcm;
  }
  return Ok();
}

/**
 * @brief Clear process-lifetime runtime adapter bindings.
 */
void AppHandle::ResetRuntimeBindings() {
  AMInterface::ApplicationAdapters::Runtime::Reset();
}
} // namespace AMBootstrap
