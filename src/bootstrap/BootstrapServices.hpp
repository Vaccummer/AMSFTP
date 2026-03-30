#pragma once

#include "CLI/CLI.hpp"
#include "application/client/ClientAppService.hpp"
#include "application/config/ConfigAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/prompt/PromptHistoryManager.hpp"
#include "application/prompt/PromptProfileManager.hpp"
#include "application/var/VarAppService.hpp"
#include "domain/config/ConfigModel.hpp"
#include "domain/log/LoggerManager.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/signal_monitor/SignalMonitor.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/cli/CLIArg.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"
#include <atomic>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

namespace AMBootstrap {
namespace fs = std::filesystem;
using AMDomain::config::ConfigStoreInitArg;
using AMDomain::config::DocumentKind;

inline ConfigStoreInitArg BuildConfigInitArg(const fs::path &root_dir) {
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

inline void PrintBootstrapWarn(const std::string &msg) {
  std::cerr << "[bootstrap] " << msg << std::endl;
}

struct BootstrapServices final : public NonCopyableNonMovable {
  BootstrapServices() = default;

  std::string app_name = {};
  fs::path root_dir = {};
  std::unique_ptr<CLI::App> cli_app = nullptr;
  AMInterface::parser::CommandNode command_tree = {};
  AMInterface::cli::CliArgsPool cli_args_pool = {};
  AMInterface::cli::CliCommands cli_commands = {};

  AMInterface::cli::CLIServices managers = {};
  AMInterface::cli::CliRunContext run_ctx = {};
};

inline ECMData<std::unique_ptr<BootstrapServices>>
BuildBootstrapServices(const std::string &app_name, const fs::path &root_dir) {
  auto runtime = std::make_unique<BootstrapServices>();
  runtime->app_name = app_name;
  runtime->root_dir = root_dir;

  auto config_service =
      std::make_unique<AMApplication::config::AMConfigAppService>();
  config_service->SetInitArg(BuildConfigInitArg(root_dir));
  {
    ECM rcm = config_service->Init();
    if (!isok(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("config init failed: {}", rcm.second));
    } else {
      rcm = config_service->Load(std::nullopt, true);
      if (!isok(rcm)) {
        PrintBootstrapWarn(AMStr::fmt("config load failed: {}", rcm.second));
      }
    }
  }

  AMDomain::host::HostConfigArg host_config_arg = {};
  AMDomain::host::KnownHostEntryArg known_hosts_arg = {};
  AMDomain::client::ClientServiceArg client_service_arg = {};
  AMDomain::filesystem::FilesystemArg filesystem_arg = {};
  AMDomain::var::VarSetArg var_arg = {};
  AMDomain::prompt::PromptProfileArg prompt_profile_arg = {};
  AMDomain::prompt::PromptHistoryArg prompt_history_arg = {};
  AMDomain::style::StyleConfigArg style_arg = {};

  (void)config_service->Read(&host_config_arg);
  (void)config_service->Read(&known_hosts_arg);
  (void)config_service->Read(&client_service_arg);
  (void)config_service->Read(&filesystem_arg);
  (void)config_service->Read(&var_arg);
  (void)config_service->Read(&prompt_profile_arg);
  (void)config_service->Read(&prompt_history_arg);
  (void)config_service->Read(&style_arg);

  auto host_service = std::make_unique<AMApplication::host::AMHostAppService>();
  {
    const ECM rcm = host_service->Init(host_config_arg);
    if (!isok(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("host init failed: {}", rcm.second));
    }
  }

  auto known_hosts_service =
      std::make_unique<AMApplication::host::AMKnownHostsAppService>();
  {
    const ECM rcm = known_hosts_service->Init(known_hosts_arg.entries);
    if (!isok(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("known-hosts init failed: {}", rcm.second));
    }
  }

  auto client_service =
      std::make_unique<AMApplication::client::ClientAppService>(client_service_arg);
  client_service->BindHostConfigManager(host_service.get());

  auto filesystem_service =
      std::make_unique<AMApplication::filesystem::FilesystemAppService>(
          filesystem_arg, host_service.get(), client_service.get());

  auto var_service =
      std::make_unique<AMApplication::var::VarAppService>(var_arg);
  {
    const ECM rcm = var_service->Init();
    if (!isok(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("var init failed: {}", rcm.second));
    }
  }

  auto prompt_profile_manager =
      std::make_unique<AMApplication::prompt::PromptProfileManager>(
          prompt_profile_arg);
  {
    const ECM rcm = prompt_profile_manager->Init();
    if (!isok(rcm)) {
      PrintBootstrapWarn(
          AMStr::fmt("prompt profile init failed: {}", rcm.second));
    }
  }
  auto prompt_history_manager =
      std::make_unique<AMApplication::prompt::PromptHistoryManager>(
          prompt_history_arg);
  {
    const ECM rcm = prompt_history_manager->Init();
    if (!isok(rcm)) {
      PrintBootstrapWarn(
          AMStr::fmt("prompt history init failed: {}", rcm.second));
    }
  }

  auto style_service =
      std::make_unique<AMInterface::style::AMStyleService>(style_arg);
  {
    const ECM rcm = style_service->Init();
    if (!isok(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("style init failed: {}", rcm.second));
    }
  }

  auto prompt_profile_history_manager =
      std::make_unique<AMInterface::prompt::IsoclineProfileManager>(
          *prompt_profile_manager, *prompt_history_manager, *style_service);
  {
    const ECM rcm = prompt_profile_history_manager->Init();
    if (!isok(rcm)) {
      PrintBootstrapWarn(
          AMStr::fmt("isocline profile init failed: {}", rcm.second));
    }
  }

  auto prompt_io_manager = std::make_unique<AMInterface::prompt::AMPromptIOManager>(
      *prompt_profile_history_manager);
  {
    const ECM rcm = prompt_io_manager->Init();
    if (!isok(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("prompt io init failed: {}", rcm.second));
    }
  }

  runtime->run_ctx.task_control_token = AMDomain::client::CreateClientControlToken();
  if (!runtime->run_ctx.task_control_token) {
    return {nullptr,
            Err(EC::InvalidHandle, "failed to create task control token")};
  }

  auto client_interface_service =
      std::make_unique<AMInterface::client::ClientInterfaceService>(
          *client_service, *host_service, *known_hosts_service,
          *prompt_io_manager);
  client_interface_service->SetDefaultControlToken(runtime->run_ctx.task_control_token);
  client_interface_service->BindInteractionCallbacks();

  auto filesystem_interface_service =
      std::make_unique<AMInterface::filesystem::FilesystemInterfaceSerivce>(
          *client_service, *filesystem_service, *style_service,
          *prompt_io_manager, runtime->run_ctx.task_control_token);

  auto var_interface_service =
      std::make_unique<AMInterface::var::VarInterfaceService>(
          *var_service, *client_service, *prompt_io_manager);

  auto transfer_pool = AMDomain::transfer::CreateTransferPoolPort();
  if (!transfer_pool) {
    return {nullptr, Err(EC::InvalidHandle, "failed to create transfer pool")};
  }

  auto transfer_service =
      std::make_unique<AMInterface::transfer::TransferInterfaceService>(
          *filesystem_service, *prompt_io_manager, *transfer_pool,
          [](AMDomain::client::amf token) {
            return AMDomain::client::MakeClientControlComponent(token, -1);
          },
          style_service.get());

  {
    auto local_cfg_result = host_service->GetLocalConfig();
    if (isok(local_cfg_result.first)) {
      auto local_client_result = client_service->CreateClient(
          local_cfg_result.second,
          AMDomain::client::MakeClientControlComponent(runtime->run_ctx.task_control_token,
                                                       -1),
          true);
      if (isok(local_client_result.rcm) && local_client_result.data) {
        ECM rcm = client_service->Init(local_client_result.data);
        if (!isok(rcm)) {
          PrintBootstrapWarn(AMStr::fmt("client init failed: {}", rcm.second));
        }
      } else if (!isok(local_client_result.rcm)) {
        PrintBootstrapWarn(AMStr::fmt("local client create failed: {}",
                                      local_client_result.rcm.second));
      }
    } else {
      PrintBootstrapWarn(AMStr::fmt("resolve local host config failed: {}",
                                    local_cfg_result.first.second));
    }
  }

  runtime->managers.signal_monitor.SetInstance(
      std::make_unique<AMInfraCliSignalMonitor>());
  runtime->managers.config_service.SetInstance(std::move(config_service));
  runtime->managers.host_service.SetInstance(std::move(host_service));
  runtime->managers.known_hosts_service.SetInstance(std::move(known_hosts_service));
  runtime->managers.client_service.SetInstance(std::move(client_service));
  runtime->managers.filesystem_service.SetInstance(std::move(filesystem_service));
  runtime->managers.var_service.SetInstance(std::move(var_service));
  runtime->managers.client_interface_service.SetInstance(
      std::move(client_interface_service));
  runtime->managers.filesystem_interface_service.SetInstance(
      std::move(filesystem_interface_service));
  runtime->managers.var_interface_service.SetInstance(
      std::move(var_interface_service));
  runtime->managers.SetPromptProfileManager(std::move(prompt_profile_manager));
  runtime->managers.SetPromptHistoryManager(std::move(prompt_history_manager));
  runtime->managers.style_service.SetInstance(std::move(style_service));
  runtime->managers.prompt_profile_history_manager.SetInstance(
      std::move(prompt_profile_history_manager));
  runtime->managers.prompt_io_manager.SetInstance(std::move(prompt_io_manager));
  runtime->managers.transfer_pool.SetInstance(std::move(transfer_pool));
  runtime->managers.transfer_service.SetInstance(std::move(transfer_service));
  runtime->managers.log_manager.SetInstance(std::make_unique<AMLoggerManager>());

  {
    const ECM rcm = runtime->managers.Init(runtime->run_ctx.task_control_token);
    if (!isok(rcm)) {
      PrintBootstrapWarn(AMStr::fmt("cli manager init failed: {}", rcm.second));
    }
  }

  runtime->run_ctx.exit_code = std::make_shared<std::atomic<int>>(0);
  runtime->run_ctx.is_interactive = std::make_shared<std::atomic<bool>>(false);
  return {std::move(runtime), Ok()};
}
} // namespace AMBootstrap

