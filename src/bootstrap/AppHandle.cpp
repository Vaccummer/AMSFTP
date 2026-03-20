#include "bootstrap/AppHandle.hpp"

#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "domain/host/HostManager.hpp"
#include "interface/adapters/ApplicationAdapters.hpp"

namespace AMBootstrap {
/**
 * @brief Construct app handle from explicit manager references.
 */
AppHandle::AppHandle(AMSignalMonitorPort &signal_monitor,
                     AMPromptManager &prompt_manager,
                     AMDomain::host::AMHostConfigManager &host_config_manager,
                     AMDomain::host::AMKnownHostsManager &known_hosts_manager,
                     AMLoggerManagerPort &log_manager,
                     AMApplication::client::ClientAppService &client_service,
                     AMApplication::TransferWorkflow::TransferAppService
                         &transfer_service)
    : config_(), host_config_store_(), known_host_store_(),
      var_repository_(config_.ConfigService()),
      current_var_domain_provider_(client_service),
      var_service(var_repository_, current_var_domain_provider_),
      managers(signal_monitor, config_.ConfigService(), config_.StyleService(),
               prompt_manager, host_config_manager, known_hosts_manager,
               var_service, log_manager, client_service, transfer_service) {}

/**
 * @brief Initialize process-lifetime services and bind runtime adapters.
 */
ECM AppHandle::Init(amf task_control_token) {
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
  bindings.transfer_service = &managers.transfer_service;
  bindings.var_query = &var_service;
  bindings.var_substitution = &var_service;
  bindings.signal_monitor = &managers.signal_monitor;
  bindings.prompt_manager = &managers.prompt_manager;
  bindings.config_service = &config_.ConfigService();
  bindings.style_service = &config_.StyleService();
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




