#include "interface/cli/CLIArg.hpp"
#include "application/client/ClientAppService.hpp"
#include "application/config/ConfigAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/transfer/TransferAppService.hpp"
#include "application/var/VarAppService.hpp"
#include "application/config/ConfigPayloads.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostManager.hpp"
#include "domain/var/VarModel.hpp"
#include "domain/log/LoggerPorts.hpp"
#include "domain/signal/SignalMonitorPort.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/log/FileLoggerWriter.hpp"
#include "infrastructure/writer/WriteDispatcher.hpp"
#include "interface/prompt/Prompt.hpp"
#include <csignal>
#include <filesystem>
#include <memory>

namespace {
/**
 * @brief Clamp configured client heartbeat timeout into a safe range.
 */
int ResolveClientHeartbeatTimeoutMs_(
    AMApplication::config::AMConfigAppService &config_service) {
  AMApplication::config::SettingsOptionsSnapshot options = {};
  if (!config_service.Read(&options)) {
    return 100;
  }
  int value = options.client_manager.heartbeat_timeout_ms;
  if (value < 10) {
    return 10;
  }
  if (value > 10000) {
    return 10000;
  }
  return value;
}

/**
 * @brief Resolve configured client heartbeat interval in seconds.
 *
 * Value `<= 0` means heartbeat disabled.
 */
int ResolveClientHeartbeatIntervalS_(
    AMApplication::config::AMConfigAppService &config_service) {
  AMApplication::config::SettingsOptionsSnapshot options = {};
  if (!config_service.Read(&options)) {
    return 60;
  }
  return options.client_manager.heartbeat_interval_s;
}

/**
 * @brief Resolve initial transfer worker thread count from config snapshot.
 */
int ResolveTransferInitThreadCount_(
    AMApplication::config::AMConfigAppService &config_service) {
  AMApplication::config::SettingsOptionsSnapshot options = {};
  if (!config_service.Read(&options)) {
    return 1;
  }
  int value = options.transfer_manager.init_thread_num;
  if (value < 1) {
    value = 1;
  }
  if (value > 128) {
    value = 128;
  }
  return value;
}

/**
 * @brief Configure domain logger with infrastructure file writers.
 */
ECM ConfigureLogger_(
    AMLoggerManagerPort &log_manager,
    AMApplication::config::AMConfigAppService &config_service) {
  if (auto scheduler = log_manager.Scheduler()) {
    scheduler->Stop();
  }

  AMApplication::config::SettingsOptionsSnapshot options = {};
  (void)config_service.Read(&options);

  const std::filesystem::path base =
      config_service.ProjectRoot().empty()
          ? std::filesystem::path(".")
          : config_service.ProjectRoot();

  auto scheduler = std::make_shared<AMInfraAsyncWriter>();
  scheduler->Start();

  auto client_writer = std::make_shared<AMInfraFileLoggerWriter>(
      base / "log" / "Client.log");
  ECM rcm = client_writer->LastError();
  if (!isok(rcm)) {
    scheduler->Stop();
    return rcm;
  }

  auto program_writer = std::make_shared<AMInfraFileLoggerWriter>(
      base / "log" / "Program.log");
  rcm = program_writer->LastError();
  if (!isok(rcm)) {
    scheduler->Stop();
    return rcm;
  }

  log_manager.ClearLoggers();
  log_manager.SetScheduler(scheduler);
  if (!log_manager.SetLogger(AMDomain::log::LoggerType::Client,
                             client_writer)) {
    scheduler->Stop();
    return Err(EC::ProgrammInitializeFailed,
               "Failed to bind client logger writer");
  }
  if (!log_manager.SetLogger(AMDomain::log::LoggerType::Program,
                             program_writer)) {
    scheduler->Stop();
    return Err(EC::ProgrammInitializeFailed,
               "Failed to bind program logger writer");
  }

  log_manager.SetTraceLevel(AMDomain::log::LoggerType::Client,
                            options.log_manager.client_trace_level);
  log_manager.SetTraceLevel(AMDomain::log::LoggerType::Program,
                            options.log_manager.program_trace_level);
  return Ok();
}

/**
 * @brief Hook name used to bridge process signals into session token state.
 */
constexpr const char *kSessionControlHook = "SESSION_CONTROL_TOKEN";

/**
 * @brief Build hook callback that updates the bound session token status.
 */
AMDomain::signal::SignalHook BuildSessionControlHook_(
    amf task_control_token) {
  AMDomain::signal::SignalHook hook;
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
                         AMApplication::config::AMConfigAppService &config_service_ref,
                         AMInterface::style::AMStyleService &style_service_ref,
                         AMInterface::prompt::IsoclineProfileManager &prompt_profile_history_manager_ref,
                         AMInterface::prompt::AMPromptIOManager &prompt_io_manager_ref,
                         AMApplication::host::AMHostAppService &host_service_ref,
                         AMApplication::host::AMKnownHostsAppService &known_hosts_service_ref,
                         AMDomain::host::AMHostConfigManager &host_config_manager_ref,
                         AMDomain::host::AMKnownHostsManager &known_hosts_manager_ref,
                         AMApplication::var::VarAppService &var_service_ref,
                         AMLoggerManagerPort &log_manager_ref,
                         AMApplication::client::ClientAppService &client_service_ref,
                         AMApplication::filesystem::FilesystemAppService &filesystem_service_ref,
                         AMApplication::TransferWorkflow::TransferAppService
                             &transfer_service_ref)
    : signal_monitor(signal_monitor_ref), config_service(config_service_ref),
      style_service(style_service_ref),
      prompt_profile_history_manager(prompt_profile_history_manager_ref),
      prompt_io_manager(prompt_io_manager_ref),
      host_service(host_service_ref),
      known_hosts_service(known_hosts_service_ref),
      host_config_manager(host_config_manager_ref),
      known_hosts_manager(known_hosts_manager_ref),
      var_service(var_service_ref), log_manager(log_manager_ref),
      client_service(client_service_ref),
      filesystem_service(filesystem_service_ref),
      transfer_service(transfer_service_ref) {}

/**
 * @brief Initialize all bound managers in dependency-safe order.
 */
ECM CliManagers::Init(amf task_control_token) {
  if (!task_control_token) {
    return Err(EC::InvalidArg, "CliManagers::Init requires task control token");
  }
  client_service.BindHostConfigManager(&host_service);
  client_service.RegisterControlComponent(task_control_token);
  (void)signal_monitor.UnregisterHook(kSessionControlHook);
  (void)signal_monitor.RegisterHook(kSessionControlHook,
                                    BuildSessionControlHook_(task_control_token));
  ECM rcm = signal_monitor.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = prompt_profile_history_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = prompt_io_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  auto [local_rcm, _local_cfg] = host_config_manager.GetLocalConfig();
  if (!isok(local_rcm)) {
    return local_rcm;
  }
  client_service.SetPrivateKeys(host_config_manager.PrivateKeys());
  rcm = known_hosts_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  AMDomain::var::VarSetArg var_snapshot = {};
  (void)config_service.Read(&var_snapshot);
  rcm = var_service.LoadFromSnapshot(var_snapshot);
  if (!isok(rcm)) {
    return rcm;
  }
  auto sync_rcm =
      config_service.RegisterSyncParticipant<AMDomain::var::VarSetArg>(
          [this]() { return var_service.IsConfigDirty(); },
          [this]() { return var_service.ExportConfigSnapshot(); },
          [this]() { var_service.ClearConfigDirty(); });
  if (!isok(sync_rcm.rcm)) {
    return sync_rcm.rcm;
  }
  rcm = ConfigureLogger_(log_manager, config_service);
  if (!isok(rcm)) {
    return rcm;
  }
  client_service.SetHeartbeatIntervalS(
      ResolveClientHeartbeatIntervalS_(config_service));
  client_service.SetHeartbeatTimeoutMs(
      ResolveClientHeartbeatTimeoutMs_(config_service));
  client_service.SetInteractiveFlag(
      std::make_shared<std::atomic<bool>>(false));
  client_service.SetKnownHostCallback(
      [this](const AMDomain::client::KnownHostQuery &query) -> ECM {
        if (!isok(AMDomain::host::KnownHostRules::ValidateKnownHostQuery(query))) {
          return Err(EC::InvalidArg, "invalid known host query");
        }
        auto stored = query;
        ECM find_rcm = known_hosts_manager.FindKnownHost(stored);
        if (!isok(find_rcm)) {
          bool canceled = false;
          bool accepted = true;
          auto interactive_flag = client_service.GetInteractiveFlag();
          const bool is_interactive =
              interactive_flag &&
              interactive_flag->load(std::memory_order_relaxed);
          if (is_interactive) {
            prompt_io_manager.FmtPrint(
                "Unknown host: {}:{}  User: {} Protocol: [!se][{}][/se]",
                query.hostname, query.port, query.username, query.protocol);
            prompt_io_manager.FmtPrint("Fingerprint: {}",
                                    AMStr::Strip(query.GetFingerprint()));
            accepted =
                prompt_io_manager.PromptYesNo("Trust this host key? (y/N): ",
                                           &canceled);
          }
          if (canceled || !accepted) {
            return Err(EC::ConfigCanceled,
                       "Known host fingerprint add canceled");
          }
          return known_hosts_manager.UpsertKnownHost(query, true);
        }
        const std::string expected = AMStr::Strip(stored.GetFingerprint());
        const std::string actual = AMStr::Strip(query.GetFingerprint());
        if (expected != actual) {
          return Err(EC::HostFingerprintMismatch,
                     AMStr::fmt("{}:{} {} fingerprint mismatches",
                                query.hostname, query.port, query.protocol));
        }
        return Ok();
      });
  client_service.SetAuthCallback(
      [this](const AMDomain::client::AuthCBInfo &info)
          -> std::optional<std::string> {
        const std::string client_name =
            info.request.nickname.empty() ? "unknown" : info.request.nickname;
        if (info.NeedPassword) {
          std::string password;
          if (!prompt_io_manager.SecurePrompt(
                  AMStr::fmt("Password required [{}]: ", client_name),
                  &password)) {
            return std::string();
          }
          return password;
        }
        if (!info.iscorrect) {
          if (info.password_n.empty()) {
            return std::nullopt;
          }
          prompt_io_manager.FmtPrint("Wrong password [{}]", client_name);
          return std::nullopt;
        }
        auto cfg = host_config_manager.GetClientConfig(client_name);
        if (cfg.first.first == EC::Success) {
          cfg.second.request.password = info.password_n;
          (void)host_config_manager.AddHost(cfg.second, true);
        }
        return std::nullopt;
      });
  client_service.SetDisconnectCallback(
      [this](const AMDomain::client::ClientHandle &client,
             const ECM &ecm) {
        if (!client || isok(ecm)) {
          return;
        }
        prompt_io_manager.ErrorFormat(
            ECM{ecm.first,
                AMStr::fmt("Client disconnected [{}]: {}",
                           client->ConfigPort().GetNickname(),
                           ecm.second.empty()
                               ? std::string(AMStr::ToString(ecm.first))
                               : ecm.second)});
      });
  rcm = client_service.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = transfer_service.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  const int transfer_threads = ResolveTransferInitThreadCount_(config_service);
  rcm = transfer_service.SetWorkerThreadCount(
      static_cast<size_t>(transfer_threads));
  if (!isok(rcm)) {
    return rcm;
  }
  return Ok();
}







