#include "interface/CLIArg.hpp"
#include "domain/client/ClientManager.hpp"
#include "domain/filesystem/FileSystemManager.hpp"
#include "domain/host/HostManager.hpp"
#include "domain/signal/SignalMonitorPort.hpp"
#include "domain/transfer/TransferManager.hpp"
#include "domain/var/VarManager.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/json.hpp"
#include "infrastructure/Config.hpp"
#include "infrastructure/Logger.hpp"
#include <csignal>

namespace {
/**
 * @brief Convert JSON scalar into string form.
 */
std::string ToStringScalar_(const Json &value) {
  if (value.is_string()) {
    return value.get<std::string>();
  }
  if (value.is_boolean()) {
    return value.get<bool>() ? "true" : "false";
  }
  if (value.is_number_integer()) {
    return std::to_string(value.get<int64_t>());
  }
  if (value.is_number_unsigned()) {
    return std::to_string(value.get<size_t>());
  }
  if (value.is_number_float()) {
    return AMStr::fmt("{}", value.get<double>());
  }
  if (value.is_null()) {
    return "";
  }
  return value.dump();
}

/**
 * @brief Parse settings `UserVars` JSON into manager domain dictionary.
 */
AMDomain::var::AMVarManager::DomainDict ParseUserVarsDict_(
    const Json &user_vars) {
  using DomainDict = AMDomain::var::AMVarManager::DomainDict;
  using DomainVars = AMDomain::var::AMVarManager::DomainVars;
  DomainDict parsed;
  parsed.reserve(user_vars.size() + 1);
  parsed[varsetkn::kPublic] = DomainVars{};

  for (auto it = user_vars.begin(); it != user_vars.end(); ++it) {
    if (it.value().is_object()) {
      if (it.key() != varsetkn::kPublic &&
          !varsetkn::IsValidZoneName(it.key())) {
        continue;
      }
      DomainVars &vars = parsed[it.key()];
      for (auto vit = it.value().begin(); vit != it.value().end(); ++vit) {
        if (!varsetkn::IsValidVarname(vit.key())) {
          continue;
        }
        vars[vit.key()] = ToStringScalar_(vit.value());
      }
      continue;
    }

    if (!varsetkn::IsValidVarname(it.key())) {
      continue;
    }
    parsed[varsetkn::kPublic][it.key()] = ToStringScalar_(it.value());
  }
  return parsed;
}
/**
 * @brief Hook name used to bridge process signals into session token state.
 */
constexpr const char *kSessionControlHook = "SESSION_CONTROL_TOKEN";

/**
 * @brief Build hook callback that updates the bound session token status.
 */
AMSignalMonitorPort::SignalHook BuildSessionControlHook_(
    const amf &task_control_token) {
  AMSignalMonitorPort::SignalHook hook;
  hook.callback = [token_weak = std::weak_ptr<TaskControlToken>(task_control_token)](
                      int signum) {
    const std::shared_ptr<TaskControlToken> token = token_weak.lock();
    if (!token) {
      return;
    }
    if (signum == SIGINT) {
      (void)token->SetStatus(ControlSignal::Interrupt);
      return;
    }
#ifdef SIGTERM
    if (signum == SIGTERM) {
      (void)token->SetStatus(ControlSignal::Kill);
    }
#endif
  };
  hook.is_silenced = false;
  hook.priority = 500;
  hook.consume = false;
  return hook;
}
} // namespace

/**
 * @brief Bind manager references for CLI dispatch.
 */
CliManagers::CliManagers(AMSignalMonitorPort &signal_monitor_ref,
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
  (void)signal_monitor.UnregisterHook(kSessionControlHook);
  (void)signal_monitor.RegisterHook(kSessionControlHook,
                                    BuildSessionControlHook_(task_control_token));
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
  Json user_vars = config_manager.ResolveArg<Json>(DocumentKind::Settings,
                                                   {varsetkn::kRoot},
                                                   Json::object(), {});
  if (!user_vars.is_object()) {
    user_vars = Json::object();
  }
  rcm = var_manager.Init(ParseUserVarsDict_(user_vars));
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



