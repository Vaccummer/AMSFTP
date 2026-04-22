#include "bootstrap/AppRuntime.hpp"

#include "application/client/ClientAppService.hpp"
#include "application/completion/CompleterAppService.hpp"
#include "application/config/ConfigAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/log/LoggerAppService.hpp"
#include "application/prompt/PromptHistoryManager.hpp"
#include "application/prompt/PromptProfileManager.hpp"
#include "application/terminal/TermAppService.hpp"
#include "application/transfer/TransferAppService.hpp"
#include "application/var/VarAppService.hpp"
#include "domain/config/ConfigStorePort.hpp"
#include "domain/log/LoggerModel.hpp"
#include "domain/log/LoggerPorts.hpp"
#include "domain/signal/SignalMonitorPort.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/adapters/config/ConfigInterfaceService.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "interface/adapters/terminal/TerminalInterfaceService.hpp"
#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/cli/MainHelpFormatter.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"

#include <atomic>
#include <csignal>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace AMBootstrap {
namespace {

struct ConfigSnapshots final {
  AMDomain::host::HostConfigArg host_config_arg = {};
  AMDomain::host::KnownHostEntryArg known_hosts_arg = {};
  AMDomain::client::ClientServiceArg client_service_arg = {};
  AMDomain::filesystem::FilesystemArg filesystem_arg = {};
  AMDomain::var::VarSetArg var_arg = {};
  AMDomain::completion::CompleterArg completer_arg = {};
  AMDomain::prompt::PromptProfileArg prompt_profile_arg = {};
  AMDomain::prompt::PromptHistoryArg prompt_history_arg = {};
  AMDomain::style::StyleConfigArg style_arg = {};
  AMDomain::transfer::TransferManagerArg transfer_manager_arg = {};
  AMDomain::log::LogManagerArg log_manager_arg = {};
};

struct DomainAssemblyState final {
  std::unique_ptr<AMDomain::signal::SignalMonitor> signal_monitor = nullptr;
  std::unique_ptr<AMDomain::transfer::ITransferPoolPort> transfer_pool =
      nullptr;
};

struct ApplicationAssemblyState final {
  std::unique_ptr<AMApplication::config::ConfigAppService> config_service =
      nullptr;
  std::unique_ptr<AMApplication::host::HostAppService> host_service = nullptr;
  std::unique_ptr<AMApplication::host::KnownHostsAppService>
      known_hosts_service = nullptr;
  std::unique_ptr<AMApplication::client::ClientAppService> client_service =
      nullptr;
  std::unique_ptr<AMApplication::terminal::TermAppService> terminal_service =
      nullptr;
  std::unique_ptr<AMApplication::filesystem::FilesystemAppService>
      filesystem_service = nullptr;
  std::unique_ptr<AMApplication::var::VarAppService> var_service = nullptr;
  std::unique_ptr<AMApplication::completion::CompleterConfigManager>
      completer_config_manager = nullptr;
  std::unique_ptr<AMApplication::prompt::PromptProfileManager>
      prompt_profile_manager = nullptr;
  std::unique_ptr<AMApplication::prompt::PromptHistoryManager>
      prompt_history_manager = nullptr;
  std::unique_ptr<AMApplication::log::LoggerAppService> log_manager = nullptr;
  std::unique_ptr<AMApplication::transfer::TransferAppService>
      transfer_service = nullptr;
  AMDomain::transfer::TransferManagerArg transfer_manager_arg = {};
  AMDomain::log::LogManagerArg log_manager_arg = {};
};

struct InterfaceAssemblyState final {
  std::unique_ptr<AMInterface::style::AMStyleService> style_service = nullptr;
  std::unique_ptr<AMInterface::prompt::IsoclineProfileManager>
      prompt_profile_history_manager = nullptr;
  std::unique_ptr<AMInterface::prompt::PromptIOManager> prompt_io_manager =
      nullptr;
  std::unique_ptr<AMInterface::config::ConfigInterfaceService>
      config_interface_service = nullptr;
  std::unique_ptr<AMInterface::client::ClientInterfaceService>
      client_interface_service = nullptr;
  std::unique_ptr<AMInterface::filesystem::FilesystemInterfaceSerivce>
      filesystem_interface_service = nullptr;
  std::unique_ptr<AMInterface::terminal::TerminalInterfaceService>
      terminal_interface_service = nullptr;
  std::unique_ptr<AMInterface::var::VarInterfaceService> var_interface_service =
      nullptr;
  std::unique_ptr<AMInterface::transfer::TransferInterfaceService>
      transfer_service = nullptr;
};

struct ApplicationAssemblyBundle final {
  ConfigSnapshots snapshots = {};
  ApplicationAssemblyState services = {};
};

void ResetCliRuntimeState_(AppRuntime *runtime, const std::string &app_name,
                           const std::string &app_description,
                           const std::string &app_version,
                           const fs::path &root_dir) {
  runtime->app_name = app_name;
  runtime->app_description = app_description;
  runtime->version = app_version;
  runtime->root_dir = root_dir;
  runtime->cli_app.reset();
  runtime->command_tree = {};
  runtime->cli_args_pool = {};
  runtime->cli_commands = {};
}

ECM BuildRunContext_(AMInterface::cli::CliRunContext *run_ctx) {
  run_ctx->task_control_token = std::make_shared<InterruptControl>();
  if (!run_ctx->task_control_token) {
    return {EC::InvalidHandle, "", "", "failed to create task control token"};
  }
  run_ctx->exit_code = std::make_shared<std::atomic<int>>(0);
  run_ctx->is_interactive = std::make_shared<std::atomic<bool>>(false);
  return OK;
}

ECM InitAndLoadConfigService_(AMApplication::config::ConfigAppService *service,
                              const fs::path &root_dir) {
  if (service == nullptr) {
    return {EC::InvalidHandle, "runtime build config", root_dir.string(),
            "config service is null"};
  }
  service->SetInitArg(
      AMDomain::config::BuildDefaultConfigStoreInitArg(root_dir));
  ECM rcm = service->Init();
  if (!rcm) {
    return {rcm.code, "runtime init config", root_dir.string(),
            rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                              : rcm.error};
  }
  rcm = service->Load(std::nullopt, true);
  if (!rcm) {
    return {rcm.code, "runtime load config", root_dir.string(),
            rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                              : rcm.error};
  }
  return OK;
}

ConfigSnapshots
ReadConfigSnapshots_(AMApplication::config::ConfigAppService *service) {
  ConfigSnapshots snapshots = {};
  (void)service->Read(&snapshots.host_config_arg);
  (void)service->Read(&snapshots.known_hosts_arg);
  (void)service->Read(&snapshots.client_service_arg);
  (void)service->Read(&snapshots.filesystem_arg);
  (void)service->Read(&snapshots.var_arg);
  (void)service->Read(&snapshots.completer_arg);
  (void)service->Read(&snapshots.prompt_profile_arg);
  (void)service->Read(&snapshots.prompt_history_arg);
  (void)service->Read(&snapshots.style_arg);
  (void)service->Read(&snapshots.transfer_manager_arg);
  (void)service->Read(&snapshots.log_manager_arg);
  return snapshots;
}

ECM BuildCoreApplicationServices_(const ConfigSnapshots &snapshots,
                                  ApplicationAssemblyState *state) {
  if (state == nullptr) {
    return {EC::InvalidArg, "runtime build application core", "<state>",
            "state is null"};
  }

  state->transfer_manager_arg = snapshots.transfer_manager_arg;
  state->transfer_manager_arg.heartbeat_interval_s =
      snapshots.client_service_arg.heartbeat_interval_s;
  state->transfer_manager_arg.heartbeat_timeout_ms =
      snapshots.client_service_arg.heartbeat_timeout_ms;
  state->log_manager_arg = snapshots.log_manager_arg;

  state->log_manager = std::make_unique<AMApplication::log::LoggerAppService>();
  state->host_service = std::make_unique<AMApplication::host::HostAppService>();
  {
    const ECM rcm = state->host_service->Init(snapshots.host_config_arg);
    if (!rcm) {
      return {rcm.code, "runtime init host service", "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  state->known_hosts_service =
      std::make_unique<AMApplication::host::KnownHostsAppService>();
  {
    const ECM rcm =
        state->known_hosts_service->Init(snapshots.known_hosts_arg.entries);
    if (!rcm) {
      return {rcm.code, "runtime init known hosts service", "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  state->client_service =
      std::make_unique<AMApplication::client::ClientAppService>(
          state->host_service.get(), snapshots.client_service_arg);
  state->client_service->SetPrivateKeys(snapshots.host_config_arg.private_keys);

  state->terminal_service =
      std::make_unique<AMApplication::terminal::TermAppService>(
          AMDomain::terminal::BufferExceedCallback{},
          state->log_manager.get());

  state->filesystem_service =
      std::make_unique<AMApplication::filesystem::FilesystemAppService>(
          snapshots.filesystem_arg, state->client_service.get());

  state->var_service =
      std::make_unique<AMApplication::var::VarAppService>(snapshots.var_arg);
  {
    const ECM rcm = state->var_service->Init();
    if (!rcm) {
      return {rcm.code, "runtime init var service", "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  return OK;
}

ECM BuildPromptApplicationServices_(const ConfigSnapshots &snapshots,
                                    ApplicationAssemblyState *state) {
  if (state == nullptr) {
    return {EC::InvalidArg, "runtime build prompt application", "<state>",
            "state is null"};
  }

  state->completer_config_manager =
      std::make_unique<AMApplication::completion::CompleterConfigManager>(
          snapshots.completer_arg);
  {
    const ECM rcm = state->completer_config_manager->Init();
    if (!rcm) {
      return {rcm.code, "runtime init completer config", "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  state->prompt_profile_manager =
      std::make_unique<AMApplication::prompt::PromptProfileManager>(
          snapshots.prompt_profile_arg);
  {
    const ECM rcm = state->prompt_profile_manager->Init();
    if (!rcm) {
      return {rcm.code, "runtime init prompt profile", "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  state->prompt_history_manager =
      std::make_unique<AMApplication::prompt::PromptHistoryManager>(
          snapshots.prompt_history_arg);
  {
    const ECM rcm = state->prompt_history_manager->Init();
    if (!rcm) {
      return {rcm.code, "runtime init prompt history", "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  return OK;
}

ECM RegisterConfigSyncPorts_(ApplicationAssemblyState *state) {
  if (state == nullptr || state->config_service == nullptr) {
    return {EC::InvalidHandle, "runtime register config sync ports", "<state>",
            "state or config service is null"};
  }

  auto register_port = [&](AMDomain::config::IConfigSyncPort *port,
                           const std::string &name) -> ECM {
    if (port == nullptr) {
      return {EC::InvalidHandle, "runtime register sync port", name,
              "sync port is null"};
    }
    auto result = state->config_service->RegisterSyncPort(port);
    if (!result.rcm) {
      return {result.rcm.code, "runtime register sync port", name,
              result.rcm.error.empty()
                  ? std::string(AMStr::ToString(result.rcm.code))
                  : result.rcm.error};
    }
    return OK;
  };

  ECM rcm = register_port(state->host_service.get(), "HostAppService");
  if (!rcm) {
    return rcm;
  }
  rcm = register_port(state->known_hosts_service.get(), "KnownHostsAppService");
  if (!rcm) {
    return rcm;
  }
  rcm = register_port(state->client_service.get(), "ClientAppService");
  if (!rcm) {
    return rcm;
  }
  rcm = register_port(state->filesystem_service.get(), "FilesystemAppService");
  if (!rcm) {
    return rcm;
  }
  rcm = register_port(state->var_service.get(), "VarAppService");
  if (!rcm) {
    return rcm;
  }
  rcm = register_port(state->completer_config_manager.get(),
                      "CompleterConfigManager");
  if (!rcm) {
    return rcm;
  }
  rcm = register_port(state->prompt_profile_manager.get(),
                      "PromptProfileManager");
  if (!rcm) {
    return rcm;
  }
  rcm = register_port(state->prompt_history_manager.get(),
                      "PromptHistoryManager");
  if (!rcm) {
    return rcm;
  }
  return OK;
}

ECM RegisterInterfaceSyncPorts_(ApplicationAssemblyState *app_state,
                                InterfaceAssemblyState *ui_state) {
  if (app_state == nullptr || ui_state == nullptr ||
      app_state->config_service == nullptr ||
      ui_state->style_service == nullptr) {
    return {EC::InvalidHandle, "runtime register interface sync ports",
            "<dependencies>", "required dependency is null"};
  }

  auto result =
      app_state->config_service->RegisterSyncPort(ui_state->style_service.get());
  if (!result.rcm) {
    return {result.rcm.code, "runtime register sync port", "StyleConfigManager",
            result.rcm.error.empty()
                ? std::string(AMStr::ToString(result.rcm.code))
                : result.rcm.error};
  }
  return OK;
}

ECMData<ApplicationAssemblyBundle>
BuildApplicationAssembly_(const fs::path &root_dir) {
  ApplicationAssemblyBundle bundle = {};
  bundle.services.config_service =
      std::make_unique<AMApplication::config::ConfigAppService>();

  ECM rcm = InitAndLoadConfigService_(bundle.services.config_service.get(),
                                      root_dir);
  if (!rcm) {
    return {ApplicationAssemblyBundle{}, rcm};
  }

  bundle.snapshots = ReadConfigSnapshots_(bundle.services.config_service.get());

  rcm = BuildCoreApplicationServices_(bundle.snapshots, &bundle.services);
  if (!rcm) {
    return {ApplicationAssemblyBundle{}, rcm};
  }
  rcm = BuildPromptApplicationServices_(bundle.snapshots, &bundle.services);
  if (!rcm) {
    return {ApplicationAssemblyBundle{}, rcm};
  }
  rcm = RegisterConfigSyncPorts_(&bundle.services);
  if (!rcm) {
    return {ApplicationAssemblyBundle{}, rcm};
  }
  return {std::move(bundle), OK};
}

ECM BuildDomainAssembly_(const ApplicationAssemblyState &app_state,
                         DomainAssemblyState *state) {
  if (state == nullptr) {
    return {EC::InvalidArg, "runtime build domain assembly", "<state>",
            "state is null"};
  }

  state->signal_monitor = AMDomain::signal::BuildSignalMonitorPort();
  if (!state->signal_monitor) {
    return {EC::InvalidHandle, "runtime build signal monitor",
            "<signal-monitor>", "failed to build signal monitor"};
  }

  state->transfer_pool = AMDomain::transfer::CreateTransferPoolPort(
      app_state.transfer_manager_arg);
  if (!state->transfer_pool) {
    return {EC::InvalidHandle, "runtime build transfer pool",
            "<transfer-pool>", "failed to create transfer pool"};
  }

  return OK;
}

ECM BuildInterfaceAssembly_(const ConfigSnapshots &snapshots,
                            const amf &task_control_token,
                            DomainAssemblyState *domain_state,
                            ApplicationAssemblyState *app_state,
                            InterfaceAssemblyState *state) {
  if (domain_state == nullptr || app_state == nullptr || state == nullptr ||
      app_state->config_service == nullptr ||
      app_state->host_service == nullptr ||
      app_state->known_hosts_service == nullptr ||
      app_state->client_service == nullptr ||
      app_state->terminal_service == nullptr ||
      app_state->filesystem_service == nullptr ||
      app_state->var_service == nullptr ||
      app_state->prompt_profile_manager == nullptr ||
      app_state->prompt_history_manager == nullptr ||
      domain_state->transfer_pool == nullptr) {
    return {EC::InvalidHandle, "runtime build interface assembly",
            "<dependencies>", "required dependency is null"};
  }

  state->style_service =
      std::make_unique<AMInterface::style::AMStyleService>(snapshots.style_arg);
  {
    const ECM rcm = state->style_service->Init();
    if (!rcm) {
      return {rcm.code, "runtime init style service", "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  state->prompt_profile_history_manager =
      std::make_unique<AMInterface::prompt::IsoclineProfileManager>(
          *app_state->prompt_profile_manager,
          *app_state->prompt_history_manager, *state->style_service);
  {
    const ECM rcm = state->prompt_profile_history_manager->Init();
    if (!rcm) {
      return {rcm.code, "runtime init isocline profile manager",
              "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  state->prompt_io_manager =
      std::make_unique<AMInterface::prompt::PromptIOManager>(
          *state->prompt_profile_history_manager);
  {
    const ECM rcm = state->prompt_io_manager->Init();
    if (!rcm) {
      return {rcm.code, "runtime init prompt io manager", "<bootstrap>",
              rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                : rcm.error};
    }
  }

  state->config_interface_service =
      std::make_unique<AMInterface::config::ConfigInterfaceService>(
          *app_state->config_service, *app_state->host_service,
          *state->prompt_io_manager, *app_state->prompt_profile_manager,
          *state->prompt_profile_history_manager);

  state->client_interface_service =
      std::make_unique<AMInterface::client::ClientInterfaceService>(
          *app_state->client_service, *app_state->terminal_service,
          *app_state->filesystem_service, *app_state->host_service,
          *app_state->known_hosts_service, *state->prompt_io_manager,
          *state->style_service);
  state->client_interface_service->SetDefaultControlToken(task_control_token);
  state->client_interface_service->BindInteractionCallbacks();

  state->filesystem_interface_service =
      std::make_unique<AMInterface::filesystem::FilesystemInterfaceSerivce>(
          *app_state->client_service, *app_state->host_service,
          *app_state->filesystem_service, *state->style_service,
          *state->prompt_io_manager);
  state->filesystem_interface_service->SetDefaultControlToken(
      task_control_token);

  state->terminal_interface_service =
      std::make_unique<AMInterface::terminal::TerminalInterfaceService>(
          *app_state->client_service, *app_state->terminal_service,
          *app_state->filesystem_service, *state->style_service,
          *state->prompt_io_manager);
  state->terminal_interface_service->SetDefaultControlToken(task_control_token);

  state->var_interface_service =
      std::make_unique<AMInterface::var::VarInterfaceService>(
          *app_state->var_service, *app_state->client_service,
          *state->prompt_io_manager, *state->style_service);

  app_state->transfer_service =
      std::make_unique<AMApplication::transfer::TransferAppService>(
          *domain_state->transfer_pool, *app_state->client_service,
          *app_state->filesystem_service);

  state->transfer_service =
      std::make_unique<AMInterface::transfer::TransferInterfaceService>(
          *app_state->filesystem_service, *app_state->transfer_service,
          *state->prompt_io_manager,
          [](AMDomain::client::amf token) { return ControlComponent(token); },
          state->style_service.get(),
          app_state->transfer_manager_arg.bar_refresh_interval_ms);
  state->transfer_service->SetDefaultControlToken(task_control_token);

  return OK;
}

void BindAssembliesToRuntime_(AppRuntime *runtime, DomainAssemblyState *domain,
                              ApplicationAssemblyState *app,
                              InterfaceAssemblyState *ui) {
  runtime->managers.domain.signal_monitor.SetInstance(
      std::move(domain->signal_monitor));
  runtime->managers.domain.transfer_pool.SetInstance(
      std::move(domain->transfer_pool));

  runtime->managers.application.config_service.SetInstance(
      std::move(app->config_service));
  runtime->managers.application.host_service.SetInstance(
      std::move(app->host_service));
  runtime->managers.application.known_hosts_service.SetInstance(
      std::move(app->known_hosts_service));
  runtime->managers.application.client_service.SetInstance(
      std::move(app->client_service));
  runtime->managers.application.terminal_service.SetInstance(
      std::move(app->terminal_service));
  runtime->managers.application.filesystem_service.SetInstance(
      std::move(app->filesystem_service));
  runtime->managers.application.var_service.SetInstance(
      std::move(app->var_service));
  runtime->managers.application.completer_config_manager.SetInstance(
      std::move(app->completer_config_manager));
  runtime->managers.application.prompt_profile_manager.SetInstance(
      std::move(app->prompt_profile_manager));
  runtime->managers.application.prompt_history_manager.SetInstance(
      std::move(app->prompt_history_manager));
  runtime->managers.application.log_manager.SetInstance(
      std::move(app->log_manager));
  runtime->managers.application.transfer_service.SetInstance(
      std::move(app->transfer_service));

  runtime->managers.interfaces.style_service.SetInstance(
      std::move(ui->style_service));
  runtime->managers.interfaces.prompt_profile_history_manager.SetInstance(
      std::move(ui->prompt_profile_history_manager));
  runtime->managers.interfaces.prompt_io_manager.SetInstance(
      std::move(ui->prompt_io_manager));
  runtime->managers.interfaces.config_interface_service.SetInstance(
      std::move(ui->config_interface_service));
  runtime->managers.interfaces.client_interface_service.SetInstance(
      std::move(ui->client_interface_service));
  runtime->managers.interfaces.filesystem_interface_service.SetInstance(
      std::move(ui->filesystem_interface_service));
  runtime->managers.interfaces.terminal_interface_service.SetInstance(
      std::move(ui->terminal_interface_service));
  runtime->managers.interfaces.var_interface_service.SetInstance(
      std::move(ui->var_interface_service));
  runtime->managers.interfaces.transfer_service.SetInstance(
      std::move(ui->transfer_service));
}

ECM BuildRuntime_(AppRuntime &runtime, const std::string &app_name,
                  const std::string &app_description,
                  const std::string &app_version,
                  const fs::path &root_dir) {
  ResetCliRuntimeState_(&runtime, app_name, app_description, app_version,
                        root_dir);
  {
    const ECM rcm = BuildRunContext_(&runtime.run_ctx);
    if (!rcm) {
      return rcm;
    }
  }

  auto app_bundle_result = BuildApplicationAssembly_(runtime.root_dir);
  if (!app_bundle_result.rcm) {
    return app_bundle_result.rcm;
  }

  ApplicationAssemblyBundle app_bundle = std::move(app_bundle_result.data);
  DomainAssemblyState domain_state = {};
  {
    const ECM rcm = BuildDomainAssembly_(app_bundle.services, &domain_state);
    if (!rcm) {
      return rcm;
    }
  }

  InterfaceAssemblyState interface_state = {};
  {
    const ECM rcm = BuildInterfaceAssembly_(
        app_bundle.snapshots, runtime.run_ctx.task_control_token,
        &domain_state, &app_bundle.services, &interface_state);
    if (!rcm) {
      return rcm;
    }
  }
  {
    const ECM rcm =
        RegisterInterfaceSyncPorts_(&app_bundle.services, &interface_state);
    if (!rcm) {
      return rcm;
    }
  }

  BindAssembliesToRuntime_(&runtime, &domain_state, &app_bundle.services,
                           &interface_state);
  return OK;
}

ECM ValidateRuntime_(const AppRuntime &runtime) {
  if (!runtime.run_ctx.task_control_token) {
    return {EC::InvalidArg, "session init", "<context>",
            "task control token is not initialized"};
  }
  if (!runtime.managers.domain.signal_monitor.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "signal monitor is not initialized"};
  }
  if (!runtime.managers.domain.transfer_pool.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "transfer pool is not initialized"};
  }
  if (!runtime.managers.application.config_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "config service is not initialized"};
  }
  if (!runtime.managers.application.host_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "host service is not initialized"};
  }
  if (!runtime.managers.application.client_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "client service is not initialized"};
  }
  if (!runtime.managers.application.terminal_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "terminal service is not initialized"};
  }
  if (!runtime.managers.application.filesystem_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "filesystem service is not initialized"};
  }
  if (!runtime.managers.application.completer_config_manager.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "completer config manager is not initialized"};
  }
  if (!runtime.managers.application.log_manager.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "log manager is not initialized"};
  }
  if (!runtime.managers.interfaces.style_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "style service is not initialized"};
  }
  if (!runtime.managers.interfaces.prompt_io_manager.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "prompt io manager is not initialized"};
  }
  if (!runtime.managers.interfaces.client_interface_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "client interface service is not initialized"};
  }
  if (!runtime.managers.interfaces.config_interface_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "config interface service is not initialized"};
  }
  if (!runtime.managers.interfaces.filesystem_interface_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "filesystem interface service is not initialized"};
  }
  if (!runtime.managers.interfaces.terminal_interface_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "terminal interface service is not initialized"};
  }
  if (!runtime.managers.interfaces.var_interface_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "var interface service is not initialized"};
  }
  if (!runtime.managers.interfaces.transfer_service.IsReady()) {
    return {EC::InvalidHandle, "session init", "<context>",
            "transfer interface service is not initialized"};
  }
  return OK;
}

std::filesystem::path ResolveLogPath_(const fs::path &project_root,
                                      const std::string &configured_path,
                                      const fs::path &default_relative_path) {
  std::string raw_path = configured_path;
  AMStr::VStrip(raw_path);
  const fs::path resolved =
      raw_path.empty() ? default_relative_path : fs::path(raw_path);
  if (resolved.is_absolute()) {
    return resolved.lexically_normal();
  }
  return (project_root / resolved).lexically_normal();
}

ECM ConfigureLogManager_(AppRuntime &runtime) {
  auto &app = runtime.managers.application;
  auto &client_service = app.client_service.Get();
  auto &log_manager = app.log_manager.Get();

  auto client_writer_owned = AMDomain::log::BuildLoggerWritePort();
  auto program_writer_owned = AMDomain::log::BuildLoggerWritePort();
  if (!client_writer_owned || !program_writer_owned) {
    return {EC::InvalidHandle, "session init log manager", "<writer>",
            "failed to build logger writer"};
  }

  auto client_writer = std::shared_ptr<AMDomain::log::ILoggerWritePort>(
      std::move(client_writer_owned));
  auto program_writer = std::shared_ptr<AMDomain::log::ILoggerWritePort>(
      std::move(program_writer_owned));

  AMDomain::log::LogManagerArg log_manager_arg = {};
  (void)runtime.managers.application.config_service->Read(&log_manager_arg);

  const fs::path client_path =
      ResolveLogPath_(runtime.root_dir, log_manager_arg.client_log_path,
                      fs::path("config/log/Client.log"));
  const fs::path program_path =
      ResolveLogPath_(runtime.root_dir, log_manager_arg.program_log_path,
                      fs::path("config/log/Program.log"));

  const ECM client_path_rcm = client_writer->SetPath(client_path);
  if (!client_path_rcm) {
    return {client_path_rcm.code, "session init log manager",
            client_path.string(),
            client_path_rcm.error.empty()
                ? std::string(AMStr::ToString(client_path_rcm.code))
                : client_path_rcm.error};
  }

  const ECM program_path_rcm = program_writer->SetPath(program_path);
  if (!program_path_rcm) {
    return {program_path_rcm.code, "session init log manager",
            program_path.string(),
            program_path_rcm.error.empty()
                ? std::string(AMStr::ToString(program_path_rcm.code))
                : program_path_rcm.error};
  }

  if (!log_manager.SetLogger(AMDomain::log::LoggerType::Client,
                             client_writer)) {
    return {EC::CommonFailure, "session init log manager", client_path.string(),
            "failed to register client logger writer"};
  }
  if (!log_manager.SetLogger(AMDomain::log::LoggerType::Program,
                             program_writer)) {
    return {EC::CommonFailure, "session init log manager",
            program_path.string(), "failed to register program logger writer"};
  }

  (void)log_manager.SetTraceLevel(AMDomain::log::LoggerType::Client,
                                  log_manager_arg.client_trace_level);
  (void)log_manager.SetTraceLevel(AMDomain::log::LoggerType::Program,
                                  log_manager_arg.program_trace_level);

  const AMDomain::client::TraceCallback trace_callback =
      log_manager.TraceCallbackFunc(AMDomain::log::LoggerType::Client);
  client_service.RegisterMaintainerCallbacks(
      std::nullopt, trace_callback, std::nullopt, std::nullopt, std::nullopt);
  client_service.RegisterPublicCallbacks(
      std::nullopt, trace_callback, std::nullopt, std::nullopt, std::nullopt);
  return OK;
}

ECM InitSignalMonitor_(AppRuntime &runtime) {
  auto &signal_monitor = runtime.managers.domain.signal_monitor.Get();
  AMDomain::signal::SignalHook hook = {};
  hook.callback = [task_control_token =
                       runtime.run_ctx.task_control_token](int signal_num) {
    if (signal_num != SIGINT && signal_num != SIGTERM) {
      return;
    }
    if (task_control_token) {
      task_control_token->RequestInterrupt(signal_num == SIGTERM ? 0 : 1000);
    }
    if (signal_num == SIGINT && ic_is_editline_active()) {
      (void)ic_async_stop();
    }
  };
  hook.priority = 500;
  hook.consume = false;
  (void)signal_monitor.RegisterHook("session-control", hook);

  const ECM rcm = signal_monitor.Init();
  if (!rcm) {
    return {rcm.code, "session init signal monitor", "<bootstrap>",
            rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                              : rcm.error};
  }
  return OK;
}

ECM BootstrapLocalClient_(AppRuntime &runtime) {
  auto &app = runtime.managers.application;
  auto local_cfg_result = app.host_service->GetLocalConfig();
  if (!local_cfg_result.rcm) {
    return {local_cfg_result.rcm.code, "session init local client", "local",
            local_cfg_result.rcm.error.empty()
                ? std::string(AMStr::ToString(local_cfg_result.rcm.code))
                : local_cfg_result.rcm.error};
  }

  const auto control = ControlComponent(runtime.run_ctx.task_control_token);
  auto local_client_result =
      app.client_service->CreateClient(local_cfg_result.data, control, true);
  if (!local_client_result.rcm) {
    return {local_client_result.rcm.code, "session create local client",
            "local",
            local_client_result.rcm.error.empty()
                ? std::string(AMStr::ToString(local_client_result.rcm.code))
                : local_client_result.rcm.error};
  }
  if (!local_client_result.data) {
    return {EC::InvalidHandle, "session create local client", "local",
            "local client handle is null"};
  }

  ECM rcm = app.client_service->Init(local_client_result.data);
  if (!rcm) {
    return {rcm.code, "session init local client", "local",
            rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                              : rcm.error};
  }

  rcm = app.filesystem_service->EnsureClientWorkdir(local_client_result.data,
                                                    control);
  if (!rcm) {
    return {rcm.code, "session ensure local workdir", "local",
            rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                              : rcm.error};
  }
  return OK;
}

ECM InitializeSession_(AppRuntime &runtime) {
  ECM rcm = ValidateRuntime_(runtime);
  if (!rcm) {
    return rcm;
  }

  rcm = ConfigureLogManager_(runtime);
  if (!rcm) {
    return rcm;
  }

  rcm = InitSignalMonitor_(runtime);
  if (!rcm) {
    return rcm;
  }

  rcm = BootstrapLocalClient_(runtime);
  if (!rcm) {
    return rcm;
  }

  return OK;
}

ECM AssembleCli_(AppRuntime &runtime) {
  runtime.cli_app = std::make_unique<CLI::App>(runtime.app_description,
                                               runtime.app_name);
  if (!runtime.cli_app) {
    return {EC::InvalidHandle, "cli assembly", "<cli-app>",
            "failed to create CLI::App"};
  }

  runtime.cli_app->set_version_flag("--version", runtime.version);
  runtime.cli_app->allow_windows_style_options(false);

  runtime.command_tree = {};
  runtime.cli_args_pool = {};
  runtime.cli_commands = AMInterface::cli::BindCliOptions(
      *runtime.cli_app, runtime.cli_args_pool, runtime.command_tree);

  if (!runtime.cli_commands.app || !runtime.cli_commands.args) {
    return {EC::InvalidHandle, "cli assembly", "<cli-bind>",
            "failed to bind CLI commands"};
  }

  if (runtime.managers.interfaces.style_service.IsReady()) {
    auto &style_service = runtime.managers.interfaces.style_service.Get();
    AMInterface::cli::InstallMainHelpFormatter(*runtime.cli_app, style_service,
                                               &runtime.command_tree);
  }

  return OK;
}

ECM RecordCleanupError_(const ECM &candidate, ECM *first_error,
                        const std::string &step) {
  if (first_error == nullptr || candidate) {
    return candidate;
  }
  if (*first_error) {
    *first_error =
        Err(candidate.code, "bootstrap shutdown", step, candidate.msg());
  }
  return candidate;
}

ECM SaveRuntimeConfig_(AppRuntime &runtime) {
  if (runtime.managers.interfaces.config_interface_service.IsReady()) {
    return runtime.managers.interfaces.config_interface_service->SaveAll();
  }

  if (!runtime.managers.application.config_service.IsReady()) {
    return OK;
  }

  if (runtime.managers.interfaces.prompt_io_manager.IsReady()) {
    runtime.managers.interfaces.prompt_io_manager->SyncCurrentHistory();
  }

  auto &config_service = runtime.managers.application.config_service.Get();
  ECM first_error = config_service.FlushDirtyParticipants();
  for (const auto &doc : config_service.ListDocuments()) {
    const ECM dump_rcm = config_service.Dump(doc.kind, "", false);
    if (!dump_rcm && first_error) {
      first_error = dump_rcm;
    }
  }
  return first_error;
}

ECM ShutdownRuntime_(AppRuntime &runtime) {
  ECM first_error = OK;

  if (runtime.run_ctx.task_control_token) {
    runtime.run_ctx.task_control_token->RequestInterrupt();
  }

  if (runtime.managers.interfaces.prompt_profile_history_manager.IsReady()) {
    runtime.managers.interfaces.prompt_profile_history_manager
        ->SetDefaultCompleter(nullptr, nullptr);
    runtime.managers.interfaces.prompt_profile_history_manager
        ->SetDefaultHighlighter(nullptr, nullptr);
  }

  if (runtime.managers.runtime.interactive_loop_runtime.IsReady()) {
    runtime.managers.runtime.interactive_loop_runtime.SetInstance(nullptr);
  }

  (void)RecordCleanupError_(SaveRuntimeConfig_(runtime), &first_error,
                            "save runtime config");

  if (runtime.managers.interfaces.terminal_interface_service.IsReady()) {
    runtime.managers.interfaces.terminal_interface_service.SetInstance(nullptr);
  }

  if (runtime.managers.domain.transfer_pool.IsReady()) {
    (void)RecordCleanupError_(
        runtime.managers.domain.transfer_pool->Shutdown(3000), &first_error,
        "shutdown transfer pool");
    runtime.managers.domain.transfer_pool.SetInstance(nullptr);
  }

  if (runtime.managers.domain.signal_monitor.IsReady()) {
    runtime.managers.domain.signal_monitor->Stop();
    runtime.managers.domain.signal_monitor.SetInstance(nullptr);
  }

  if (runtime.managers.application.terminal_service.IsReady()) {
    runtime.managers.application.terminal_service.SetInstance(nullptr);
  }
  if (runtime.managers.application.transfer_service.IsReady()) {
    runtime.managers.application.transfer_service.SetInstance(nullptr);
  }
  if (runtime.managers.application.log_manager.IsReady()) {
    runtime.managers.application.log_manager->ClearLoggers();
    runtime.managers.application.log_manager.SetInstance(nullptr);
  }
  if (runtime.managers.application.config_service.IsReady()) {
    runtime.managers.application.config_service->CloseHandles();
    runtime.managers.application.config_service.SetInstance(nullptr);
  }

  runtime.managers.interfaces.client_interface_service.SetInstance(nullptr);
  runtime.managers.interfaces.config_interface_service.SetInstance(nullptr);
  runtime.managers.interfaces.filesystem_interface_service.SetInstance(nullptr);
  runtime.managers.interfaces.var_interface_service.SetInstance(nullptr);
  runtime.managers.interfaces.transfer_service.SetInstance(nullptr);
  runtime.managers.interfaces.prompt_io_manager.SetInstance(nullptr);
  runtime.managers.interfaces.prompt_profile_history_manager.SetInstance(
      nullptr);
  runtime.managers.interfaces.style_service.SetInstance(nullptr);

  runtime.managers.application.host_service.SetInstance(nullptr);
  runtime.managers.application.known_hosts_service.SetInstance(nullptr);
  runtime.managers.application.client_service.SetInstance(nullptr);
  runtime.managers.application.filesystem_service.SetInstance(nullptr);
  runtime.managers.application.var_service.SetInstance(nullptr);
  runtime.managers.application.completer_config_manager.SetInstance(nullptr);
  runtime.managers.application.prompt_profile_manager.SetInstance(nullptr);
  runtime.managers.application.prompt_history_manager.SetInstance(nullptr);

  runtime.cli_app.reset();
  runtime.command_tree = {};
  runtime.cli_args_pool = {};
  runtime.cli_commands = {};

  return first_error;
}

} // namespace

AppRuntime::~AppRuntime() { ShutdownNoThrow(); }

ECM AppRuntime::Build(const std::string &app_name_arg,
                      const std::string &app_description_arg,
                      const std::string &app_version_arg,
                      const fs::path &root_dir_arg) {
  ShutdownNoThrow();

  ECM rcm = BuildRuntime_(*this, app_name_arg, app_description_arg,
                          app_version_arg, root_dir_arg);
  if (!rcm) {
    ShutdownNoThrow();
    return rcm;
  }
  is_shutdown_ = false;

  rcm = InitializeSession_(*this);
  if (!rcm) {
    ShutdownNoThrow();
    return rcm;
  }

  rcm = AssembleCli_(*this);
  if (!rcm) {
    ShutdownNoThrow();
    return rcm;
  }

  return OK;
}

ECM AppRuntime::Shutdown() {
  if (is_shutdown_) {
    return OK;
  }

  const ECM rcm = ShutdownRuntime_(*this);
  is_shutdown_ = true;
  return rcm;
}

void AppRuntime::ShutdownNoThrow() noexcept {
  try {
    (void)Shutdown();
  } catch (...) {
  }
}

} // namespace AMBootstrap
