#include "bootstrap/BootstrapServices.hpp"

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
#include "domain/config/ConfigSchema.hpp"
#include "domain/log/LoggerModel.hpp"
#include "domain/log/LoggerPorts.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/adapters/config/ConfigInterfaceService.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "interface/adapters/terminal/TerminalInterfaceService.hpp"
#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"

#include <atomic>
#include <csignal>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace AMBootstrap {
namespace {
using AMDomain::config::DocumentKind;
using AMDomain::config::schema::GetSchemaJson;

constexpr const char *kRootEnvKey = "AMSFTP_ROOT";

struct ManagedTarget final {
  std::filesystem::path relative_path = {};
  std::string content = {};
};

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

struct AppServiceBuildState final {
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
  std::unique_ptr<AMInterface::style::AMStyleService> style_service = nullptr;
  std::unique_ptr<AMInterface::prompt::IsoclineProfileManager>
      prompt_profile_history_manager = nullptr;
  std::unique_ptr<AMInterface::prompt::AMPromptIOManager> prompt_io_manager =
      nullptr;
  std::unique_ptr<AMApplication::log::LoggerAppService> log_manager = nullptr;
  AMDomain::transfer::TransferManagerArg transfer_manager_arg = {};
  AMDomain::log::LogManagerArg log_manager_arg = {};
};

struct InterfaceServiceBuildState final {
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
  std::unique_ptr<AMDomain::transfer::ITransferPoolPort> transfer_pool =
      nullptr;
  std::unique_ptr<AMApplication::transfer::TransferAppService>
      transfer_app_service = nullptr;
  std::unique_ptr<AMInterface::transfer::TransferInterfaceService>
      transfer_service = nullptr;
  std::unique_ptr<AMDomain::signal::SignalMonitor> signal_monitor = nullptr;
};

std::filesystem::path NormalizeRootPath_(std::string value) {
  AMStr::VStrip(value);
  if (value.empty()) {
    return {};
  }
  std::error_code ec;
  std::filesystem::path p(value);
  p = p.lexically_normal();
  const auto abs = std::filesystem::absolute(p, ec);
  if (ec) {
    return p;
  }
  return abs.lexically_normal();
}

std::vector<ManagedTarget> BuildManagedTargets_() {
  std::vector<ManagedTarget> out = {};
  out.reserve(8);
  auto toml_marker = [](const std::string &schema_name) {
    return AMStr::fmt("# :schema ./schema/{}\n", schema_name);
  };
  out.push_back({std::filesystem::path("config/config.toml"),
                 toml_marker("config.schema.json")});
  out.push_back({std::filesystem::path("config/settings.toml"),
                 toml_marker("settings.schema.json")});
  out.push_back({std::filesystem::path("config/known_hosts.toml"),
                 toml_marker("known_hosts.schema.json")});
  out.push_back({std::filesystem::path("config/history.toml"),
                 toml_marker("history.schema.json")});
  out.push_back({std::filesystem::path("config/schema/config.schema.json"),
                 std::string(GetSchemaJson(DocumentKind::Config)) + "\n"});
  out.push_back({std::filesystem::path("config/schema/settings.schema.json"),
                 std::string(GetSchemaJson(DocumentKind::Settings)) + "\n"});
  out.push_back({std::filesystem::path("config/schema/known_hosts.schema.json"),
                 std::string(GetSchemaJson(DocumentKind::KnownHosts)) + "\n"});
  out.push_back({std::filesystem::path("config/schema/history.schema.json"),
                 std::string(GetSchemaJson(DocumentKind::History)) + "\n"});
  return out;
}

ECM WriteTextFile_(const std::filesystem::path &file_path,
                   const std::string &content) {
  std::error_code ec;
  const auto parent = file_path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      return Err(EC::ConfigDumpFailed, "bootstrap init root",
                 file_path.string(), ec.message());
    }
  }
  if (std::filesystem::exists(file_path, ec) && !ec &&
      std::filesystem::is_directory(file_path, ec)) {
    return Err(EC::ConfigDumpFailed, "bootstrap init root", file_path.string(),
               "target path is a directory");
  }
  std::ofstream out(file_path,
                    std::ios::out | std::ios::trunc | std::ios::binary);
  if (!out.is_open()) {
    return Err(EC::ConfigDumpFailed, "bootstrap init root", file_path.string(),
               "failed to open file for writing");
  }
  out << content;
  if (!out.good()) {
    return Err(EC::ConfigDumpFailed, "bootstrap init root", file_path.string(),
               "failed to write file");
  }
  return OK;
}

ECM EnsureRootLayout_(const std::filesystem::path &root_dir) {
  std::error_code ec;
  std::filesystem::create_directories(root_dir / "config", ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed, "bootstrap init root", root_dir.string(),
               ec.message());
  }
  std::filesystem::create_directories(root_dir / "config" / "schema", ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed, "bootstrap init root", root_dir.string(),
               ec.message());
  }
  std::filesystem::create_directories(root_dir / "config" / "bak", ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed, "bootstrap init root", root_dir.string(),
               ec.message());
  }
  return OK;
}

ECM InitProjectRoot_(const std::filesystem::path &root_dir) {
  std::error_code ec;
  if (std::filesystem::exists(root_dir, ec) && !ec &&
      !std::filesystem::is_directory(root_dir, ec)) {
    return Err(EC::InvalidArg, "bootstrap init root", root_dir.string(),
               "root path exists but is not a directory");
  }
  ec.clear();
  std::filesystem::create_directories(root_dir, ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed, "bootstrap init root", root_dir.string(),
               ec.message());
  }

  ECM rcm = EnsureRootLayout_(root_dir);
  if (!rcm) {
    return rcm;
  }

  for (const auto &target : BuildManagedTargets_()) {
    const auto abs_path = root_dir / target.relative_path;
    ec.clear();
    if (std::filesystem::exists(abs_path, ec) && !ec) {
      continue;
    }
    if (ec) {
      return Err(EC::ConfigDumpFailed, "bootstrap init root", abs_path.string(),
                 ec.message());
    }
    rcm = WriteTextFile_(abs_path, target.content);
    if (!rcm) {
      return rcm;
    }
  }
  return OK;
}

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
  run_ctx->task_control_token = std::make_shared<InterruptControl>();
  if (!run_ctx->task_control_token) {
    return Err(EC::InvalidHandle, "", "",
               "failed to create task control token");
  }
  run_ctx->exit_code = std::make_shared<std::atomic<int>>(0);
  run_ctx->is_interactive = std::make_shared<std::atomic<bool>>(false);
  return OK;
}

ECM InitAndLoadConfigService_(AMApplication::config::ConfigAppService *service,
                              const fs::path &root_dir) {
  if (service == nullptr) {
    return Err(EC::InvalidHandle, "bootstrap init config", root_dir.string(),
               "config service is null");
  }
  service->SetInitArg(BuildConfigInitArg(root_dir));
  ECM rcm = service->Init();
  if (!rcm) {
    return Err(rcm.code, "bootstrap init config", root_dir.string(),
               rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                 : rcm.error);
  }
  rcm = service->Load(std::nullopt, true);
  if (!rcm) {
    return Err(rcm.code, "bootstrap load config", root_dir.string(),
               rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                 : rcm.error);
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
                                  AppServiceBuildState *state) {
  if (state == nullptr) {
    return Err(EC::InvalidArg, "bootstrap build core services", "<state>",
               "state is null");
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
      return Err(rcm.code, "bootstrap init host service", "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
  }

  state->known_hosts_service =
      std::make_unique<AMApplication::host::KnownHostsAppService>();
  {
    const ECM rcm =
        state->known_hosts_service->Init(snapshots.known_hosts_arg.entries);
    if (!(rcm)) {
      return Err(rcm.code, "bootstrap init known hosts service", "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
  }

  state->client_service =
      std::make_unique<AMApplication::client::ClientAppService>(
          state->host_service.get(), snapshots.client_service_arg);
  state->client_service->SetPrivateKeys(snapshots.host_config_arg.private_keys);

  state->terminal_service =
      std::make_unique<AMApplication::terminal::TermAppService>();

  state->filesystem_service =
      std::make_unique<AMApplication::filesystem::FilesystemAppService>(
          snapshots.filesystem_arg, state->client_service.get());

  state->var_service =
      std::make_unique<AMApplication::var::VarAppService>(snapshots.var_arg);
  {
    const ECM rcm = state->var_service->Init();
    if (!(rcm)) {
      return Err(rcm.code, "bootstrap init var service", "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
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

ECM BuildLogManager_(const fs::path &project_root,
                     AppServiceBuildState *state) {
  if (state == nullptr || state->client_service == nullptr ||
      state->log_manager == nullptr) {
    return Err(EC::InvalidHandle, "bootstrap build log manager",
               "<dependencies>", "required service dependency is null");
  }

  auto client_writer_owned = AMDomain::log::BuildLoggerWritePort();
  auto program_writer_owned = AMDomain::log::BuildLoggerWritePort();
  if (!client_writer_owned || !program_writer_owned) {
    return Err(EC::InvalidHandle, "bootstrap build log manager", "<writer>",
               "failed to build logger writer");
  }

  auto client_writer = std::shared_ptr<AMDomain::log::ILoggerWritePort>(
      std::move(client_writer_owned));
  auto program_writer = std::shared_ptr<AMDomain::log::ILoggerWritePort>(
      std::move(program_writer_owned));

  const fs::path client_path =
      ResolveLogPath_(project_root, state->log_manager_arg.client_log_path,
                      fs::path("config/log/Client.log"));
  const fs::path program_path =
      ResolveLogPath_(project_root, state->log_manager_arg.program_log_path,
                      fs::path("config/log/Program.log"));

  const ECM client_path_rcm = client_writer->SetPath(client_path);
  if (!client_path_rcm) {
    return Err(client_path_rcm.code, "bootstrap build log manager",
               client_path.string(),
               client_path_rcm.error.empty()
                   ? std::string(AMStr::ToString(client_path_rcm.code))
                   : client_path_rcm.error);
  }

  const ECM program_path_rcm = program_writer->SetPath(program_path);
  if (!program_path_rcm) {
    return Err(program_path_rcm.code, "bootstrap build log manager",
               program_path.string(),
               program_path_rcm.error.empty()
                   ? std::string(AMStr::ToString(program_path_rcm.code))
                   : program_path_rcm.error);
  }

  if (!state->log_manager->SetLogger(AMDomain::log::LoggerType::Client,
                                     client_writer)) {
    return Err(EC::CommonFailure, "bootstrap build log manager",
               client_path.string(), "failed to register client logger writer");
  }
  if (!state->log_manager->SetLogger(AMDomain::log::LoggerType::Program,
                                     program_writer)) {
    return Err(EC::CommonFailure, "bootstrap build log manager",
               program_path.string(),
               "failed to register program logger writer");
  }

  (void)state->log_manager->SetTraceLevel(
      AMDomain::log::LoggerType::Client,
      state->log_manager_arg.client_trace_level);
  (void)state->log_manager->SetTraceLevel(
      AMDomain::log::LoggerType::Program,
      state->log_manager_arg.program_trace_level);

  const AMDomain::client::TraceCallback trace_callback =
      state->log_manager->TraceCallbackFunc(AMDomain::log::LoggerType::Client);
  state->client_service->RegisterMaintainerCallbacks(
      std::nullopt, trace_callback, std::nullopt, std::nullopt, std::nullopt);
  state->client_service->RegisterPublicCallbacks(
      std::nullopt, trace_callback, std::nullopt, std::nullopt, std::nullopt);
  return OK;
}

ECM BuildPromptAndStyleServices_(const ConfigSnapshots &snapshots,
                                 AppServiceBuildState *state) {
  if (state == nullptr) {
    return Err(EC::InvalidArg, "bootstrap build prompt/style services",
               "<state>", "state is null");
  }
  state->completer_config_manager =
      std::make_unique<AMApplication::completion::CompleterConfigManager>(
          snapshots.completer_arg);
  {
    const ECM rcm = state->completer_config_manager->Init();
    if (!(rcm)) {
      return Err(rcm.code, "bootstrap init completer config", "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
  }

  state->prompt_profile_manager =
      std::make_unique<AMApplication::prompt::PromptProfileManager>(
          snapshots.prompt_profile_arg);
  {
    const ECM rcm = state->prompt_profile_manager->Init();
    if (!(rcm)) {
      return Err(rcm.code, "bootstrap init prompt profile", "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
  }

  state->prompt_history_manager =
      std::make_unique<AMApplication::prompt::PromptHistoryManager>(
          snapshots.prompt_history_arg);
  {
    const ECM rcm = state->prompt_history_manager->Init();
    if (!(rcm)) {
      return Err(rcm.code, "bootstrap init prompt history", "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
  }

  state->style_service =
      std::make_unique<AMInterface::style::AMStyleService>(snapshots.style_arg);
  {
    const ECM rcm = state->style_service->Init();
    if (!(rcm)) {
      return Err(rcm.code, "bootstrap init style service", "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
  }

  state->prompt_profile_history_manager =
      std::make_unique<AMInterface::prompt::IsoclineProfileManager>(
          *state->prompt_profile_manager, *state->prompt_history_manager,
          *state->style_service);
  {
    const ECM rcm = state->prompt_profile_history_manager->Init();
    if (!(rcm)) {
      return Err(rcm.code, "bootstrap init isocline profile manager",
                 "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
  }

  state->prompt_io_manager =
      std::make_unique<AMInterface::prompt::AMPromptIOManager>(
          *state->prompt_profile_history_manager);
  {
    const ECM rcm = state->prompt_io_manager->Init();
    if (!(rcm)) {
      return Err(rcm.code, "bootstrap init prompt io manager", "<bootstrap>",
                 rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                   : rcm.error);
    }
  }
  return OK;
}

ECM RegisterConfigSyncPorts_(AppServiceBuildState *state) {
  if (state == nullptr || state->config_service == nullptr) {
    return Err(EC::InvalidHandle, "bootstrap register config sync ports",
               "<state>", "state or config service is null");
  }

  auto register_port = [&](AMDomain::config::IConfigSyncPort *port,
                           const std::string &name) -> ECM {
    if (port == nullptr) {
      return Err(EC::InvalidHandle, "bootstrap register sync port", name,
                 "sync port is null");
    }
    auto result = state->config_service->RegisterSyncPort(port);
    if (!(result.rcm)) {
      return Err(result.rcm.code, "bootstrap register sync port", name,
                 result.rcm.error.empty()
                     ? std::string(AMStr::ToString(result.rcm.code))
                     : result.rcm.error);
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
  rcm = register_port(state->style_service.get(), "StyleConfigManager");
  if (!rcm) {
    return rcm;
  }
  return OK;
}

ECMData<AppServiceBuildState>
BuildApplicationServices_(const fs::path &root_dir) {
  AppServiceBuildState state = {};
  state.config_service =
      std::make_unique<AMApplication::config::ConfigAppService>();
  ECM rcm = InitAndLoadConfigService_(state.config_service.get(), root_dir);
  if (!rcm) {
    return {AppServiceBuildState{}, rcm};
  }
  const ConfigSnapshots snapshots =
      ReadConfigSnapshots_(state.config_service.get());
  rcm = BuildCoreApplicationServices_(snapshots, &state);
  if (!rcm) {
    return {AppServiceBuildState{}, rcm};
  }
  rcm = BuildPromptAndStyleServices_(snapshots, &state);
  if (!rcm) {
    return {AppServiceBuildState{}, rcm};
  }
  rcm = RegisterConfigSyncPorts_(&state);
  if (!rcm) {
    return {AppServiceBuildState{}, rcm};
  }
  return {std::move(state), OK};
}

ECM BuildClientInterfaceServices_(const amf &task_control_token,
                                  const AppServiceBuildState &app_state,
                                  InterfaceServiceBuildState *state) {
  if (state == nullptr || app_state.config_service == nullptr ||
      app_state.client_service == nullptr ||
      app_state.terminal_service == nullptr ||
      app_state.filesystem_service == nullptr ||
      app_state.host_service == nullptr ||
      app_state.known_hosts_service == nullptr ||
      app_state.prompt_io_manager == nullptr ||
      app_state.style_service == nullptr || app_state.var_service == nullptr) {
    return Err(EC::InvalidHandle, "bootstrap build interface services",
               "<dependencies>", "required service dependency is null");
  }
  state->config_interface_service =
      std::make_unique<AMInterface::config::ConfigInterfaceService>(
          *app_state.config_service, *app_state.host_service,
          *app_state.prompt_io_manager);

  state->client_interface_service =
      std::make_unique<AMInterface::client::ClientInterfaceService>(
          *app_state.client_service, *app_state.terminal_service,
          *app_state.filesystem_service, *app_state.host_service,
          *app_state.known_hosts_service, *app_state.prompt_io_manager,
          *app_state.style_service);
  state->client_interface_service->SetDefaultControlToken(task_control_token);
  state->client_interface_service->BindInteractionCallbacks();

  state->filesystem_interface_service =
      std::make_unique<AMInterface::filesystem::FilesystemInterfaceSerivce>(
          *app_state.client_service, *app_state.host_service,
          *app_state.filesystem_service, *app_state.style_service,
          *app_state.prompt_io_manager);
  state->filesystem_interface_service->SetDefaultControlToken(
      task_control_token);

  state->terminal_interface_service =
      std::make_unique<AMInterface::terminal::TerminalInterfaceService>(
          *app_state.client_service, *app_state.terminal_service,
          *app_state.filesystem_service, *app_state.style_service,
          *app_state.prompt_io_manager);
  state->terminal_interface_service->SetDefaultControlToken(task_control_token);

  state->var_interface_service =
      std::make_unique<AMInterface::var::VarInterfaceService>(
          *app_state.var_service, *app_state.client_service,
          *app_state.prompt_io_manager);
  return OK;
}

ECM BuildTransferInterfaceService_(const amf &task_control_token,
                                   const AppServiceBuildState &app_state,
                                   InterfaceServiceBuildState *state) {
  if (state == nullptr || app_state.filesystem_service == nullptr ||
      app_state.prompt_io_manager == nullptr ||
      app_state.style_service == nullptr) {
    return Err(EC::InvalidHandle, "bootstrap build transfer interface",
               "<dependencies>", "required service dependency is null");
  }
  state->transfer_pool = AMDomain::transfer::CreateTransferPoolPort(
      app_state.transfer_manager_arg);
  if (!state->transfer_pool) {
    return Err(EC::InvalidHandle, "", "", "failed to create transfer pool");
  }

  state->transfer_app_service =
      std::make_unique<AMApplication::transfer::TransferAppService>(
          *state->transfer_pool, *app_state.client_service,
          *app_state.filesystem_service);

  state->transfer_service =
      std::make_unique<AMInterface::transfer::TransferInterfaceService>(
          *app_state.filesystem_service, *state->transfer_app_service,
          *app_state.prompt_io_manager,
          [](AMDomain::client::amf token) { return ControlComponent(token); },
          app_state.style_service.get(),
          app_state.transfer_manager_arg.bar_refresh_interval_ms);
  state->transfer_service->SetDefaultControlToken(task_control_token);
  return OK;
}

ECM BootstrapLocalClient_(const amf &task_control_token,
                          const AppServiceBuildState &app_state) {
  if (app_state.host_service == nullptr ||
      app_state.client_service == nullptr ||
      app_state.filesystem_service == nullptr) {
    return Err(EC::InvalidHandle, "bootstrap local client", "<dependencies>",
               "required service dependency is null");
  }
  auto local_cfg_result = app_state.host_service->GetLocalConfig();
  if ((local_cfg_result.rcm)) {
    const auto control = ControlComponent(task_control_token);
    auto local_client_result = app_state.client_service->CreateClient(
        local_cfg_result.data, control, true);
    if ((local_client_result.rcm) && local_client_result.data) {
      ECM rcm = app_state.client_service->Init(local_client_result.data);
      if (!(rcm)) {
        return Err(rcm.code, "bootstrap init local client", "local",
                   rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                     : rcm.error);
      } else {
        const ECM ensure_rcm =
            app_state.filesystem_service->EnsureClientWorkdir(
                local_client_result.data, control);
        if (!ensure_rcm) {
          return Err(ensure_rcm.code, "bootstrap ensure local workdir", "local",
                     ensure_rcm.error.empty()
                         ? std::string(AMStr::ToString(ensure_rcm.code))
                         : ensure_rcm.error);
        }
      }
    } else if (!(local_client_result.rcm)) {
      return Err(
          local_client_result.rcm.code, "bootstrap create local client",
          "local",
          local_client_result.rcm.error.empty()
              ? std::string(AMStr::ToString(local_client_result.rcm.code))
              : local_client_result.rcm.error);
    }
    return OK;
  }
  return Err(local_cfg_result.rcm.code, "bootstrap resolve local config",
             "local",
             local_cfg_result.rcm.error.empty()
                 ? std::string(AMStr::ToString(local_cfg_result.rcm.code))
                 : local_cfg_result.rcm.error);
}

ECM BuildAndInitSignalMonitor_(const amf &task_control_token,
                               InterfaceServiceBuildState *state) {
  if (state == nullptr) {
    return Err(EC::InvalidArg, "bootstrap init signal monitor", "<state>",
               "state is null");
  }
  state->signal_monitor = AMDomain::signal::BuildSignalMonitorPort();
  if (!state->signal_monitor) {
    return Err(EC::InvalidHandle, "bootstrap init signal monitor",
               "<signal-monitor>", "failed to build signal monitor");
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
    return Err(rcm.code, "bootstrap init signal monitor", "<bootstrap>",
               rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                 : rcm.error);
  }
  return OK;
}

void BindServicesToCliManagers_(BootstrapServices *runtime,
                                AppServiceBuildState *app_state,
                                InterfaceServiceBuildState *interface_state) {
  runtime->managers.domain.signal_monitor.SetInstance(
      std::move(interface_state->signal_monitor));

  runtime->managers.application.config_service.SetInstance(
      std::move(app_state->config_service));
  runtime->managers.application.host_service.SetInstance(
      std::move(app_state->host_service));
  runtime->managers.application.known_hosts_service.SetInstance(
      std::move(app_state->known_hosts_service));
  runtime->managers.application.client_service.SetInstance(
      std::move(app_state->client_service));
  runtime->managers.application.terminal_service.SetInstance(
      std::move(app_state->terminal_service));
  runtime->managers.application.filesystem_service.SetInstance(
      std::move(app_state->filesystem_service));
  runtime->managers.application.transfer_service.SetInstance(
      std::move(interface_state->transfer_app_service));
  runtime->managers.application.var_service.SetInstance(
      std::move(app_state->var_service));
  runtime->managers.application.completer_config_manager.SetInstance(
      std::move(app_state->completer_config_manager));

  runtime->managers.interfaces.client_interface_service.SetInstance(
      std::move(interface_state->client_interface_service));
  runtime->managers.interfaces.config_interface_service.SetInstance(
      std::move(interface_state->config_interface_service));
  runtime->managers.interfaces.filesystem_interface_service.SetInstance(
      std::move(interface_state->filesystem_interface_service));
  runtime->managers.interfaces.terminal_interface_service.SetInstance(
      std::move(interface_state->terminal_interface_service));
  runtime->managers.interfaces.var_interface_service.SetInstance(
      std::move(interface_state->var_interface_service));
  runtime->managers.domain.transfer_pool.SetInstance(
      std::move(interface_state->transfer_pool));
  runtime->managers.interfaces.transfer_service.SetInstance(
      std::move(interface_state->transfer_service));

  runtime->managers.application.prompt_profile_manager.SetInstance(
      std::move(app_state->prompt_profile_manager));
  runtime->managers.application.prompt_history_manager.SetInstance(
      std::move(app_state->prompt_history_manager));
  runtime->managers.interfaces.style_service.SetInstance(
      std::move(app_state->style_service));
  runtime->managers.interfaces.prompt_profile_history_manager.SetInstance(
      std::move(app_state->prompt_profile_history_manager));
  runtime->managers.interfaces.prompt_io_manager.SetInstance(
      std::move(app_state->prompt_io_manager));
  runtime->managers.application.log_manager.SetInstance(
      std::move(app_state->log_manager));
}

} // namespace

ConfigStoreInitArg BuildConfigInitArg(const fs::path &root_dir) {
  ConfigStoreInitArg arg = {};
  arg.root_dir = root_dir;
  arg.layout = {
      {DocumentKind::Config,
       {DocumentKind::Config, root_dir / "config" / "config.toml",
        AMDomain::config::schema::GetSchemaJson(DocumentKind::Config)}},
      {DocumentKind::Settings,
       {DocumentKind::Settings, root_dir / "config" / "settings.toml",
        AMDomain::config::schema::GetSchemaJson(DocumentKind::Settings)}},
      {DocumentKind::KnownHosts,
       {DocumentKind::KnownHosts, root_dir / "config" / "known_hosts.toml",
        AMDomain::config::schema::GetSchemaJson(DocumentKind::KnownHosts)}},
      {DocumentKind::History,
       {DocumentKind::History, root_dir / "config" / "history.toml",
        AMDomain::config::schema::GetSchemaJson(DocumentKind::History)}}};
  return arg;
}

ECMData<fs::path> ResolveRootDir() {
  std::string env_root = {};
  if (!AMStr::GetEnv(kRootEnvKey, &env_root)) {
    return {fs::path{},
            Err(EC::ConfigNotInitialized, "bootstrap resolve root",
                "$AMSFTP_ROOT", "env variable $AMSFTP_ROOT is not set")};
  }
  AMStr::VStrip(env_root);
  if (env_root.empty()) {
    return {fs::path{}, Err(EC::ConfigNotInitialized, "bootstrap resolve root",
                            "$AMSFTP_ROOT", "AMSFTP_ROOT is empty")};
  }

  fs::path root_dir = NormalizeRootPath_(env_root);
  if (root_dir.empty()) {
    return {fs::path{}, Err(EC::InvalidArg, "bootstrap resolve root", env_root,
                            "resolved root directory is empty")};
  }
  std::error_code ec;
  if (std::filesystem::exists(root_dir, ec) && !ec &&
      !std::filesystem::is_directory(root_dir, ec)) {
    return {fs::path{},
            Err(EC::InvalidArg, "bootstrap resolve root", root_dir.string(),
                "AMSFTP_ROOT exists but is not a directory")};
  }
  if (ec) {
    return {fs::path{}, Err(EC::ConfigLoadFailed, "bootstrap resolve root",
                            root_dir.string(), ec.message())};
  }
  const ECM init_rcm = InitProjectRoot_(root_dir);
  if (!init_rcm) {
    return {fs::path{}, init_rcm};
  }
  return {root_dir, OK};
}

void PrintBootstrapWarn(const std::string &msg) {
  std::string rendered = msg;
  const std::string env_token = "$AMSFTP_ROOT";
  const std::string colored_env = "\x1b[38;2;204;168;233m$AMSFTP_ROOT\x1b[0m";
  AMStr::vreplace_all(rendered, env_token, colored_env);
  std::cerr << "❌ [bootstrap] " << rendered << std::endl;
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

  auto app_state_result = BuildApplicationServices_(runtime->root_dir);
  if (!(app_state_result.rcm)) {
    return {nullptr, app_state_result.rcm};
  }
  AppServiceBuildState app_state = std::move(app_state_result.data);

  {
    const ECM rcm = BuildLogManager_(runtime->root_dir, &app_state);
    if (!(rcm)) {
      return {nullptr, rcm};
    }
  }
  InterfaceServiceBuildState interface_state = {};
  {
    const ECM rcm = BuildClientInterfaceServices_(
        runtime->run_ctx.task_control_token, app_state, &interface_state);
    if (!(rcm)) {
      return {nullptr, rcm};
    }
  }
  {
    const ECM rcm = BuildTransferInterfaceService_(
        runtime->run_ctx.task_control_token, app_state, &interface_state);
    if (!(rcm)) {
      return {nullptr, rcm};
    }
  }
  {
    const ECM rcm =
        BootstrapLocalClient_(runtime->run_ctx.task_control_token, app_state);
    if (!(rcm)) {
      return {nullptr, rcm};
    }
  }
  {
    const ECM rcm = BuildAndInitSignalMonitor_(
        runtime->run_ctx.task_control_token, &interface_state);
    if (!(rcm)) {
      return {nullptr, rcm};
    }
  }

  BindServicesToCliManagers_(runtime.get(), &app_state, &interface_state);

  {
    const ECM rcm = runtime->managers.Init(runtime->run_ctx.task_control_token);
    if (!(rcm)) {
      return {nullptr,
              Err(rcm.code, "bootstrap init cli managers", "<bootstrap>",
                  rcm.error.empty() ? std::string(AMStr::ToString(rcm.code))
                                    : rcm.error)};
    }
  }

  return {std::move(runtime), OK};
}

} // namespace AMBootstrap
