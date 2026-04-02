#include "bootstrap/BootstrapServices.hpp"

#include "application/client/ClientAppService.hpp"
#include "application/config/ConfigAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/log/LoggerAppService.hpp"
#include "application/prompt/PromptHistoryManager.hpp"
#include "application/prompt/PromptProfileManager.hpp"
#include "application/var/VarAppService.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"

#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace AMBootstrap {
namespace {
using AMDomain::config::DocumentKind;

struct ConfigSnapshots final {
  AMDomain::host::HostConfigArg host_config_arg = {};
  AMDomain::host::KnownHostEntryArg known_hosts_arg = {};
  AMDomain::client::ClientServiceArg client_service_arg = {};
  AMDomain::filesystem::FilesystemArg filesystem_arg = {};
  AMDomain::var::VarSetArg var_arg = {};
  AMDomain::prompt::PromptProfileArg prompt_profile_arg = {};
  AMDomain::prompt::PromptHistoryArg prompt_history_arg = {};
  AMDomain::style::StyleConfigArg style_arg = {};
  AMDomain::transfer::TransferManagerArg transfer_manager_arg = {};
};

struct AppServiceBuildState final {
  std::unique_ptr<AMApplication::config::ConfigAppService> config_service =
      nullptr;
  std::unique_ptr<AMApplication::host::HostAppService> host_service =
      nullptr;
  std::unique_ptr<AMApplication::host::KnownHostsAppService>
      known_hosts_service = nullptr;
  std::unique_ptr<AMApplication::client::ClientAppService> client_service =
      nullptr;
  std::unique_ptr<AMApplication::filesystem::FilesystemAppService>
      filesystem_service = nullptr;
  std::unique_ptr<AMApplication::var::VarAppService> var_service = nullptr;
  std::unique_ptr<AMApplication::prompt::PromptProfileManager>
      prompt_profile_manager = nullptr;
  std::unique_ptr<AMApplication::prompt::PromptHistoryManager>
      prompt_history_manager = nullptr;
  std::unique_ptr<AMInterface::style::AMStyleService> style_service = nullptr;
  std::unique_ptr<AMInterface::prompt::IsoclineProfileManager>
      prompt_profile_history_manager = nullptr;
  std::unique_ptr<AMInterface::prompt::AMPromptIOManager> prompt_io_manager =
      nullptr;
  AMDomain::transfer::TransferManagerArg transfer_manager_arg = {};
};

struct InterfaceServiceBuildState final {
  std::unique_ptr<AMInterface::client::ClientInterfaceService>
      client_interface_service = nullptr;
  std::unique_ptr<AMInterface::filesystem::FilesystemInterfaceSerivce>
      filesystem_interface_service = nullptr;
  std::unique_ptr<AMInterface::var::VarInterfaceService> var_interface_service =
      nullptr;
  std::unique_ptr<AMDomain::transfer::ITransferPoolPort> transfer_pool =
      nullptr;
  std::unique_ptr<AMInterface::transfer::TransferInterfaceService>
      transfer_service = nullptr;
  std::unique_ptr<AMDomain::signal::SignalMonitor> signal_monitor = nullptr;
};

void BuildCliRuntimeState_(BootstrapServices *runtime,
                           const std::string &app_name,
                           const fs::path &root_dir) {
  runtime->app_name = app_name;
  runtime->root_dir = root_dir;
  runtime->cli_app.reset();
  runtime->command_tree = {};
  runtime->cli_args_pool = {};
  runtime->cli_commands = {};
}

ECM BuildRunContext_(AMInterface::cli::CliRunContext *run_ctx) {
  run_ctx->task_control_token = AMDomain::client::CreateClientControlToken();
  if (!run_ctx->task_control_token) {
    return Err(EC::InvalidHandle, "", "", "failed to create task control token");
  }
  run_ctx->exit_code = std::make_shared<std::atomic<int>>(0);
  run_ctx->is_interactive = std::make_shared<std::atomic<bool>>(false);
  return OK;
}

void InitAndLoadConfigService_(AMApplication::config::ConfigAppService *service,
                               const fs::path &root_dir) {
  service->SetInitArg(BuildConfigInitArg(root_dir));
  ECM rcm = service->Init();
  if (!(rcm)) {
    PrintBootstrapWarn(AMStr::fmt("config init failed: {}", rcm.msg()));
    return;
  }
  rcm = service->Load(std::nullopt, true);
  if (!(rcm)) {
    PrintBootstrapWarn(AMStr::fmt("config load failed: {}", rcm.msg()));
  }
}

ConfigSnapshots ReadConfigSnapshots_(
    AMApplication::config::ConfigAppService *service) {
  ConfigSnapshots snapshots = {};
  (void)service->Read(&snapshots.host_config_arg);
  (void)service->Read(&snapshots.known_hosts_arg);
  (void)service->Read(&snapshots.client_service_arg);
  (void)service->Read(&snapshots.filesystem_arg);
  (void)service->Read(&snapshots.var_arg);
  (void)service->Read(&snapshots.prompt_profile_arg);
  (void)service->Read(&snapshots.prompt_history_arg);
  (void)service->Read(&snapshots.style_arg);
  (void)service->Read(&snapshots.transfer_manager_arg);
  return snapshots;
}

void BuildCoreApplicationServices_(const ConfigSnapshots &snapshots,
                                   AppServiceBuildState *state) {
  state->transfer_manager_arg = snapshots.transfer_manager_arg;
  state->host_service = std::make_unique<AMApplication::host::HostAppService>();
  {
    const ECM rcm = state->host_service->Init(snapshots.host_config_arg);
    if (!(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("host init failed: {}", rcm.msg()));
    }
  }

  state->known_hosts_service =
      std::make_unique<AMApplication::host::KnownHostsAppService>();
  {
    const ECM rcm =
        state->known_hosts_service->Init(snapshots.known_hosts_arg.entries);
    if (!(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("known-hosts init failed: {}", rcm.msg()));
    }
  }

  state->client_service =
      std::make_unique<AMApplication::client::ClientAppService>(
          snapshots.client_service_arg);
  state->client_service->BindHostConfigManager(state->host_service.get());

  state->filesystem_service =
      std::make_unique<AMApplication::filesystem::FilesystemAppService>(
          snapshots.filesystem_arg, state->host_service.get(),
          state->client_service.get());

  state->var_service =
      std::make_unique<AMApplication::var::VarAppService>(snapshots.var_arg);
  {
    const ECM rcm = state->var_service->Init();
    if (!(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("var init failed: {}", rcm.msg()));
    }
  }
}

void BuildPromptAndStyleServices_(const ConfigSnapshots &snapshots,
                                  AppServiceBuildState *state) {
  state->prompt_profile_manager =
      std::make_unique<AMApplication::prompt::PromptProfileManager>(
          snapshots.prompt_profile_arg);
  {
    const ECM rcm = state->prompt_profile_manager->Init();
    if (!(rcm)) {
      PrintBootstrapWarn(
          AMStr::fmt("prompt profile init failed: {}", rcm.msg()));
    }
  }

  state->prompt_history_manager =
      std::make_unique<AMApplication::prompt::PromptHistoryManager>(
          snapshots.prompt_history_arg);
  {
    const ECM rcm = state->prompt_history_manager->Init();
    if (!(rcm)) {
      PrintBootstrapWarn(
          AMStr::fmt("prompt history init failed: {}", rcm.msg()));
    }
  }

  state->style_service =
      std::make_unique<AMInterface::style::AMStyleService>(snapshots.style_arg);
  {
    const ECM rcm = state->style_service->Init();
    if (!(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("style init failed: {}", rcm.msg()));
    }
  }

  state->prompt_profile_history_manager =
      std::make_unique<AMInterface::prompt::IsoclineProfileManager>(
          *state->prompt_profile_manager, *state->prompt_history_manager,
          *state->style_service);
  {
    const ECM rcm = state->prompt_profile_history_manager->Init();
    if (!(rcm)) {
      PrintBootstrapWarn(
          AMStr::fmt("isocline profile init failed: {}", rcm.msg()));
    }
  }

  state->prompt_io_manager =
      std::make_unique<AMInterface::prompt::AMPromptIOManager>(
          *state->prompt_profile_history_manager);
  {
    const ECM rcm = state->prompt_io_manager->Init();
    if (!(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("prompt io init failed: {}", rcm.msg()));
    }
  }
}

void RegisterConfigSyncPorts_(AppServiceBuildState *state) {
  if (state == nullptr || state->config_service == nullptr) {
    return;
  }

  auto register_port = [&](AMApplication::config::IConfigSyncPort *port,
                           const std::string &name) {
    if (port == nullptr) {
      PrintBootstrapWarn(AMStr::fmt("skip registering sync port: {}", name));
      return;
    }
    auto result = state->config_service->RegisterSyncPort(port);
    if (!(result.rcm)) {
      PrintBootstrapWarn(
          AMStr::fmt("register sync port {} failed: {}", name, result.rcm.msg()));
    }
  };

  register_port(state->host_service.get(), "HostAppService");
  register_port(state->known_hosts_service.get(), "KnownHostsAppService");
  register_port(state->client_service.get(), "ClientAppService");
  register_port(state->filesystem_service.get(), "FilesystemAppService");
  register_port(state->var_service.get(), "VarAppService");
  register_port(state->prompt_profile_manager.get(), "PromptProfileManager");
  register_port(state->prompt_history_manager.get(), "PromptHistoryManager");
  register_port(state->style_service.get(), "StyleConfigManager");
}

AppServiceBuildState BuildApplicationServices_(const fs::path &root_dir) {
  AppServiceBuildState state = {};
  state.config_service =
      std::make_unique<AMApplication::config::ConfigAppService>();
  InitAndLoadConfigService_(state.config_service.get(), root_dir);
  const ConfigSnapshots snapshots = ReadConfigSnapshots_(state.config_service.get());
  BuildCoreApplicationServices_(snapshots, &state);
  BuildPromptAndStyleServices_(snapshots, &state);
  RegisterConfigSyncPorts_(&state);
  return state;
}

void BuildClientInterfaceServices_(
    const AMInterface::cli::amf &task_control_token,
    const AppServiceBuildState &app_state, InterfaceServiceBuildState *state) {
  state->client_interface_service =
      std::make_unique<AMInterface::client::ClientInterfaceService>(
          *app_state.client_service, *app_state.filesystem_service,
          *app_state.host_service, *app_state.known_hosts_service,
          *app_state.prompt_io_manager, *app_state.style_service);
  state->client_interface_service->SetDefaultControlToken(task_control_token);
  state->client_interface_service->BindInteractionCallbacks();

  state->filesystem_interface_service =
      std::make_unique<AMInterface::filesystem::FilesystemInterfaceSerivce>(
          *app_state.client_service, *app_state.filesystem_service,
          *app_state.style_service, *app_state.prompt_io_manager);
  state->filesystem_interface_service->SetDefaultControlToken(
      task_control_token);

  state->var_interface_service =
      std::make_unique<AMInterface::var::VarInterfaceService>(
          *app_state.var_service, *app_state.client_service,
          *app_state.prompt_io_manager);
}

ECM BuildTransferInterfaceService_(
    const AMInterface::cli::amf &task_control_token,
    const AppServiceBuildState &app_state, InterfaceServiceBuildState *state) {
  state->transfer_pool =
      AMDomain::transfer::CreateTransferPoolPort(app_state.transfer_manager_arg);
  if (!state->transfer_pool) {
    return Err(EC::InvalidHandle, "", "", "failed to create transfer pool");
  }

  state->transfer_service =
      std::make_unique<AMInterface::transfer::TransferInterfaceService>(
          *app_state.filesystem_service, *app_state.prompt_io_manager,
          *state->transfer_pool,
          [](AMDomain::client::amf token) {
            return AMDomain::client::ClientControlComponent(token, -1);
          },
          app_state.style_service.get());
  state->transfer_service->SetDefaultControlToken(task_control_token);
  return OK;
}

void BootstrapLocalClient_(const AMInterface::cli::amf &task_control_token,
                           const AppServiceBuildState &app_state) {
  auto local_cfg_result = app_state.host_service->GetLocalConfig();
  if ((local_cfg_result.rcm)) {
    const auto control =
        AMDomain::client::ClientControlComponent(task_control_token, -1);
    auto local_client_result = app_state.client_service->CreateClient(
        local_cfg_result.data, control, true);
    if ((local_client_result.rcm) && local_client_result.data) {
      ECM rcm = app_state.client_service->Init(local_client_result.data);
      if (!(rcm)) {
        PrintBootstrapWarn(AMStr::fmt("client init failed: {}", rcm.msg()));
      } else {
        const ECM ensure_rcm = app_state.filesystem_service->EnsureClientWorkdir(
            local_client_result.data, control);
        if (!(ensure_rcm)) {
          PrintBootstrapWarn(
              AMStr::fmt("ensure local workdir failed: {}", ensure_rcm.msg()));
        }
      }
    } else if (!(local_client_result.rcm)) {
      PrintBootstrapWarn(AMStr::fmt("local client create failed: {}",
                                    local_client_result.rcm.msg()));
    }
    return;
  }
  PrintBootstrapWarn(AMStr::fmt("resolve local host config failed: {}",
                                local_cfg_result.rcm.msg()));
}

void BuildAndInitSignalMonitor_(
    const AMInterface::cli::amf &task_control_token,
    InterfaceServiceBuildState *state) {
  state->signal_monitor = AMDomain::signal::BuildSignalMonitorPort();
  if (!state->signal_monitor) {
    throw std::runtime_error("failed to build signal monitor");
  }

  AMDomain::signal::SignalHook hook = {};
  hook.is_silenced = false;
  hook.is_silenced = false;
  hook.callback = [task_control_token](int signal_num) {
    if (signal_num == SIGINT) {
      if (task_control_token) {
        task_control_token->RequestInterrupt();
      }
      return;
    }
    if (signal_num == SIGTERM) {
      if (task_control_token) {
        task_control_token->RequestInterrupt();
      }
    }
  };

  state->signal_monitor->RegisterHook("ControlToken", hook);
  const ECM rcm = state->signal_monitor->Init();
  if (!rcm) {
    PrintBootstrapWarn(AMStr::fmt("signal monitor init failed: {}", rcm.msg()));
    throw std::runtime_error("failed to initialize signal monitor");
  }
}

void BindServicesToCliManagers_(BootstrapServices *runtime,
                                AppServiceBuildState *app_state,
                                InterfaceServiceBuildState *interface_state) {
  runtime->managers.signal_monitor.SetInstance(std::move(interface_state->signal_monitor));

  runtime->managers.config_service.SetInstance(std::move(app_state->config_service));
  runtime->managers.host_service.SetInstance(std::move(app_state->host_service));
  runtime->managers.known_hosts_service.SetInstance(
      std::move(app_state->known_hosts_service));
  runtime->managers.client_service.SetInstance(std::move(app_state->client_service));
  runtime->managers.filesystem_service.SetInstance(
      std::move(app_state->filesystem_service));
  runtime->managers.var_service.SetInstance(std::move(app_state->var_service));

  runtime->managers.client_interface_service.SetInstance(
      std::move(interface_state->client_interface_service));
  runtime->managers.filesystem_interface_service.SetInstance(
      std::move(interface_state->filesystem_interface_service));
  runtime->managers.var_interface_service.SetInstance(
      std::move(interface_state->var_interface_service));
  runtime->managers.transfer_pool.SetInstance(std::move(interface_state->transfer_pool));
  runtime->managers.transfer_service.SetInstance(
      std::move(interface_state->transfer_service));

  runtime->managers.SetPromptProfileManager(
      std::move(app_state->prompt_profile_manager));
  runtime->managers.SetPromptHistoryManager(
      std::move(app_state->prompt_history_manager));
  runtime->managers.style_service.SetInstance(std::move(app_state->style_service));
  runtime->managers.prompt_profile_history_manager.SetInstance(
      std::move(app_state->prompt_profile_history_manager));
  runtime->managers.prompt_io_manager.SetInstance(
      std::move(app_state->prompt_io_manager));
  runtime->managers.log_manager.SetInstance(
      std::make_unique<AMApplication::log::LoggerAppService>());
}

} // namespace

ConfigStoreInitArg BuildConfigInitArg(const fs::path &root_dir) {
  ConfigStoreInitArg arg = {};
  arg.root_dir = root_dir;
  arg.layout = {
      {DocumentKind::Config,
       {DocumentKind::Config, root_dir / "config" / "config.toml", "{}"}},
      {DocumentKind::Settings,
       {DocumentKind::Settings, root_dir / "config" / "settings.toml", "{}"}},
      {DocumentKind::KnownHosts,
       {DocumentKind::KnownHosts, root_dir / "config" / "known_hosts.toml",
        "{}"}},
      {DocumentKind::History,
       {DocumentKind::History, root_dir / "config" / "history.toml", "{}"}}};
  return arg;
}

void PrintBootstrapWarn(const std::string &msg) {
  std::cerr << "[bootstrap] " << msg << std::endl;
}

ECMData<std::unique_ptr<BootstrapServices>>
BuildBootstrapServices(const std::string &app_name, const fs::path &root_dir) {
  auto runtime = std::make_unique<BootstrapServices>();

  BuildCliRuntimeState_(runtime.get(), app_name, root_dir);

  {
    const ECM rcm = BuildRunContext_(&runtime->run_ctx);
    if (!(rcm)) {
      return {nullptr, rcm};
    }
  }

  AppServiceBuildState app_state = BuildApplicationServices_(runtime->root_dir);

  InterfaceServiceBuildState interface_state = {};
  BuildClientInterfaceServices_(runtime->run_ctx.task_control_token, app_state,
                                &interface_state);
  {
    const ECM rcm = BuildTransferInterfaceService_(
        runtime->run_ctx.task_control_token, app_state, &interface_state);
    if (!(rcm)) {
      return {nullptr, rcm};
    }
  }
  BootstrapLocalClient_(runtime->run_ctx.task_control_token, app_state);
  BuildAndInitSignalMonitor_(runtime->run_ctx.task_control_token,
                             &interface_state);

  BindServicesToCliManagers_(runtime.get(), &app_state, &interface_state);

  {
    const ECM rcm = runtime->managers.Init(runtime->run_ctx.task_control_token);
    if (!(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("cli manager init failed: {}", rcm.msg()));
    }
  }

  return {std::move(runtime), OK};
}

} // namespace AMBootstrap

