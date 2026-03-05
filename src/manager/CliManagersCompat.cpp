#include "interface/CLIArg.hpp"
#include "domain/client/ClientManager.hpp"
#include "domain/filesystem/FileSystemManager.hpp"
#include "domain/host/HostManager.hpp"
#include "domain/transfer/TransferManager.hpp"
#include "domain/var/VarManager.hpp"
#include "foundation/tools/enum_related.hpp"
#include "infrastructure/Config.hpp"
#include "infrastructure/Logger.hpp"
#include "infrastructure/SignalMonitor.hpp"

/**
 * @brief Bind manager references for CLI dispatch.
 */
CliManagers::CliManagers(AMInfraCliSignalMonitor &signal_monitor_ref,
                         AMInfraConfigManager &config_manager_ref,
                         AMPromptManager &prompt_manager_ref,
                         AMDomain::host::AMHostManager &host_manager_ref,
                         AMDomain::var::VarCLISet &var_manager_ref,
                         AMInfraLogManager &log_manager_ref,
                         AMDomain::client::AMClientManager &client_manager_ref,
                         AMDomain::transfer::AMTransferManager &transfer_manager_ref,
                         AMDomain::filesystem::AMFileSystem &filesystem_ref)
    : signal_monitor(signal_monitor_ref), config_manager(config_manager_ref),
      prompt_manager(prompt_manager_ref), host_manager(host_manager_ref),
      var_manager(var_manager_ref), log_manager(log_manager_ref),
      client_manager(client_manager_ref),
      transfer_manager(transfer_manager_ref), filesystem(filesystem_ref) {}

/**
 * @brief Initialize all bound managers in dependency-safe order.
 */
ECM CliManagers::Init(const amf &task_control_token) {
  if (!task_control_token) {
    return Err(EC::InvalidArg, "CliManagers::Init requires task control token");
  }
  signal_monitor.BindTaskControlToken(task_control_token);
  ECM rcm = signal_monitor.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = config_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = prompt_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = host_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = var_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  log_manager.BindConfigManager(&config_manager);
  rcm = log_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = client_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = transfer_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  return filesystem.Init();
}



