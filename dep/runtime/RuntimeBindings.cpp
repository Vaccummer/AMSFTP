#include "interface/adapters/ApplicationAdapters.hpp"
#include "interface/prompt/Prompt.hpp"
#include "application/client/ClientAppService.hpp"
#include "application/config/StyleSettings.hpp"
#include "infrastructure/controller/ClientControlTokenAdapter.hpp"
#include "application/config/ConfigPayloads.hpp"
#include "domain/host/HostManager.hpp"
#include "domain/signal/SignalMonitorPort.hpp"
#include "application/transfer/TransferAppService.hpp"
#include "domain/var/VarPorts.hpp"
#include "foundation/tools/string.hpp"
#include "interface/style/StyleManager.hpp"
#include <atomic>
#include <stdexcept>

namespace AMInterface::ApplicationAdapters {
namespace {
/**
 * @brief Legacy settings key kept for config-schema compatibility.
 */
constexpr const char *kTransferOptionsKey = "TransferManager";

/**
 * @brief Runtime dependency slots bound once from startup wiring.
 */
struct RuntimeBindingState {
  std::atomic<AMDomain::host::AMHostConfigManager *> host_config_manager{nullptr};
  std::atomic<AMDomain::host::AMKnownHostsManager *> known_hosts_manager{nullptr};
  std::atomic<AMApplication::client::ClientAppService *> client_service{nullptr};
  std::atomic<AMApplication::TransferWorkflow::TransferAppService *> transfer_service{nullptr};
  std::atomic<const AMDomain::var::IVarQueryPort *> var_query{nullptr};
  std::atomic<const AMDomain::var::IVarSubstitutionPort *> var_substitution{nullptr};
  std::atomic<AMSignalMonitorPort *> signal_monitor{nullptr};
  std::atomic<AMInterface::prompt::IsoclineProfileManager *> prompt_profile_history_manager{
      nullptr};
  std::atomic<AMInterface::prompt::AMPromptIOManager *> prompt_io_manager{nullptr};
  std::atomic<AMApplication::config::AMConfigAppService *> config_service{
      nullptr};
  std::atomic<AMInterface::style::AMStyleService *> style_service{nullptr};
};

/**
 * @brief Return process-wide runtime binding storage.
 */
RuntimeBindingState &RuntimeBindingState_() {
  static RuntimeBindingState state;
  return state;
}

bool TryParseInt_(const std::string &text, int *out) {
  if (!out) {
    return false;
  }
  const std::string trimmed = AMStr::Strip(text);
  if (trimmed.empty()) {
    return false;
  }
  try {
    size_t parsed_size = 0;
    const int value = std::stoi(trimmed, &parsed_size, 10);
    if (parsed_size != trimmed.size()) {
      return false;
    }
    *out = value;
    return true;
  } catch (...) {
    return false;
  }
}
} // namespace

/**
 * @brief Bind runtime dependencies explicitly.
 */
void Runtime::Bind(const RuntimeBindings &bindings) {
  auto &state = RuntimeBindingState_();
  state.host_config_manager.store(bindings.host_config_manager, std::memory_order_release);
  state.known_hosts_manager.store(bindings.known_hosts_manager,
                                  std::memory_order_release);
  state.client_service.store(bindings.client_service, std::memory_order_release);
  state.transfer_service.store(bindings.transfer_service,
                               std::memory_order_release);
  state.var_query.store(bindings.var_query, std::memory_order_release);
  state.var_substitution.store(bindings.var_substitution,
                               std::memory_order_release);
  state.signal_monitor.store(bindings.signal_monitor, std::memory_order_release);
  state.prompt_profile_history_manager.store(
      bindings.prompt_profile_history_manager, std::memory_order_release);
  state.prompt_io_manager.store(bindings.prompt_io_manager,
                                std::memory_order_release);
  state.config_service.store(bindings.config_service, std::memory_order_release);
  state.style_service.store(bindings.style_service, std::memory_order_release);
}

/**
 * @brief Clear runtime dependency bindings.
 */
void Runtime::Reset() {
  auto &state = RuntimeBindingState_();
  state.host_config_manager.store(nullptr, std::memory_order_release);
  state.known_hosts_manager.store(nullptr, std::memory_order_release);
  state.client_service.store(nullptr, std::memory_order_release);
  state.transfer_service.store(nullptr, std::memory_order_release);
  state.var_query.store(nullptr, std::memory_order_release);
  state.var_substitution.store(nullptr, std::memory_order_release);
  state.signal_monitor.store(nullptr, std::memory_order_release);
  state.prompt_profile_history_manager.store(nullptr, std::memory_order_release);
  state.prompt_io_manager.store(nullptr, std::memory_order_release);
  state.config_service.store(nullptr, std::memory_order_release);
  state.style_service.store(nullptr, std::memory_order_release);
}

/**
 * @brief Return whether all runtime dependencies are bound.
 */
bool Runtime::IsBound() {
  auto &state = RuntimeBindingState_();
  return state.host_config_manager.load(std::memory_order_acquire) &&
         state.known_hosts_manager.load(std::memory_order_acquire) &&
         state.client_service.load(std::memory_order_acquire) &&
         state.transfer_service.load(std::memory_order_acquire) &&
         state.var_query.load(std::memory_order_acquire) &&
         state.var_substitution.load(std::memory_order_acquire) &&
         state.signal_monitor.load(std::memory_order_acquire) &&
         state.prompt_profile_history_manager.load(std::memory_order_acquire) &&
         state.prompt_io_manager.load(std::memory_order_acquire) &&
         state.config_service.load(std::memory_order_acquire) &&
         state.style_service.load(std::memory_order_acquire);
}

/**
 * @brief Return bound config service reference or throw when unbound.
 */
AMApplication::config::AMConfigAppService &Runtime::ConfigServiceOrThrow() {
  AMApplication::config::AMConfigAppService *config_service =
      RuntimeBindingState_().config_service.load(std::memory_order_acquire);
  if (!config_service) {
    throw std::runtime_error("Runtime config app service is not bound");
  }
  return *config_service;
}

/**
 * @brief Return bound style service reference or throw when unbound.
 */
AMInterface::style::AMStyleService &Runtime::StyleServiceOrThrow() {
  AMInterface::style::AMStyleService *style_service =
      RuntimeBindingState_().style_service.load(std::memory_order_acquire);
  if (!style_service) {
    throw std::runtime_error("Runtime style service is not bound");
  }
  return *style_service;
}

/**
 * @brief Return true when a configured host nickname exists.
 */
AMDomain::host::AMHostConfigManager &Runtime::HostConfigManagerOrThrow() {
  AMDomain::host::AMHostConfigManager *host_config_manager =
      RuntimeBindingState_().host_config_manager.load(std::memory_order_acquire);
  if (!host_config_manager) {
    throw std::runtime_error("Runtime host config manager is not bound");
  }
  return *host_config_manager;
}

AMDomain::host::AMKnownHostsManager &Runtime::KnownHostsManagerOrThrow() {
  AMDomain::host::AMKnownHostsManager *known_hosts_manager =
      RuntimeBindingState_().known_hosts_manager.load(std::memory_order_acquire);
  if (!known_hosts_manager) {
    throw std::runtime_error("Runtime known hosts manager is not bound");
  }
  return *known_hosts_manager;
}

AMApplication::client::ClientAppService &Runtime::ClientServiceOrThrow() {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  if (!client_service) {
    throw std::runtime_error("Runtime client app service is not bound");
  }
  return *client_service;
}

AMDomain::client::IClientRuntimePort &Runtime::ClientRuntimePortOrThrow() {
  return ClientServiceOrThrow();
}

AMDomain::client::IClientLifecyclePort &Runtime::ClientLifecyclePortOrThrow() {
  return ClientServiceOrThrow();
}

AMDomain::client::IClientPathPort &Runtime::ClientPathPortOrThrow() {
  return ClientServiceOrThrow();
}

/**
 * @brief Return true when a configured host nickname exists.
 */
bool Runtime::HostExists(const std::string &nickname) {
  AMDomain::host::AMHostConfigManager *host_config_manager =
      RuntimeBindingState_().host_config_manager.load(std::memory_order_acquire);
  return host_config_manager ? host_config_manager->HostExists(nickname) : false;
}

/**
 * @brief Return configured host nicknames.
 */
std::vector<std::string> Runtime::ListHostNames() {
  AMDomain::host::AMHostConfigManager *host_config_manager =
      RuntimeBindingState_().host_config_manager.load(std::memory_order_acquire);
  return host_config_manager ? host_config_manager->ListNames()
                             : std::vector<std::string>{};
}

/**
 * @brief Return created/connected client nicknames.
 */
std::vector<std::string> Runtime::ListClientNames() {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  return client_service ? client_service->GetClientNames()
                        : std::vector<std::string>{};
}

/**
 * @brief Return tracked transfer task IDs.
 */
std::vector<std::string> Runtime::ListTaskIds() {
  AMApplication::TransferWorkflow::TransferAppService *transfer_service =
      RuntimeBindingState_().transfer_service.load(std::memory_order_acquire);
  return transfer_service ? transfer_service->ListTaskIds()
                          : std::vector<std::string>{};
}

/**
 * @brief Resolve one client by nickname.
 */
Runtime::ClientHandle Runtime::GetClient(const std::string &nickname) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  if (!client_service) {
    return nullptr;
  }
  auto client = client_service->GetClient(nickname, true);
  return isok(client.rcm) ? client.data : nullptr;
}

/**
 * @brief Resolve one host client from client-maintainer by nickname.
 */
Runtime::ClientHandle Runtime::GetHostClient(const std::string &nickname) {
  return GetClient(nickname);
}

/**
 * @brief Return local client instance.
 */
Runtime::ClientHandle Runtime::LocalClient() {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  return client_service ? client_service->GetLocalClient() : nullptr;
}

/**
 * @brief Return current active client.
 */
Runtime::ClientHandle Runtime::CurrentClient() {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  return client_service ? client_service->GetCurrentClient() : nullptr;
}

/**
 * @brief Return current active client nickname.
 */
std::string Runtime::CurrentNickname() {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  return client_service ? client_service->CurrentNickname() : std::string{};
}

/**
 * @brief Parse one raw path token through bound client path service.
 */
AMDomain::client::ParsedClientPath Runtime::ParsePath(const std::string &input,
                                                      amf interrupt_flag) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  if (!client_service) {
    return {"", "", nullptr, Err(EC::InvalidHandle, "Runtime client app service is not bound")};
  }
  return client_service->ParseScopedPath(
      input, AMInfra::controller::AdaptClientInterruptFlag(interrupt_flag));
}

/**
 * @brief Return client workdir, initializing when absent.
 */
std::string Runtime::GetOrInitWorkdir(const ClientHandle &client) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  return client_service ? client_service->GetOrInitWorkdir(client) : std::string{};
}

/**
 * @brief Update one client workdir in application session state.
 */
ECM Runtime::SetClientWorkdir(const ClientHandle &client,
                              const std::string &path) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  if (!client_service || !client) {
    return Err(EC::InvalidHandle, "Runtime client app service is not bound");
  }
  auto state = client_service->GetWorkdirState(client->ConfigPort().GetNickname());
  state.cwd = client_service->BuildAbsolutePath(client, path);
  return client_service->SetWorkdirState(client->ConfigPort().GetNickname(), state);
}

/**
 * @brief Set current active client instance.
 */
void Runtime::SetCurrentClient(const ClientHandle &client) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  if (client_service) {
    client_service->SetCurrentClient(client);
  }
}

/**
 * @brief Connect one configured nickname through bound lifecycle port.
 */
std::pair<ECM, Runtime::ClientHandle>
Runtime::ConnectNickname(const std::string &nickname, bool force,
                         bool register_to_manager, amf interrupt_flag) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  if (!client_service) {
    return {Err(EC::InvalidHandle, "Runtime client app service is not bound"), nullptr};
  }
  AMDomain::client::ClientConnectOptions options{};
  options.force = force;
  options.quiet = true;
  options.register_to_manager = register_to_manager;
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(
          AMInfra::controller::AdaptClientInterruptFlag(interrupt_flag));
  return client_service->ConnectNickname(
      nickname, options, {}, control);
}

/**
 * @brief Connect one explicit request through bound lifecycle port.
 */
std::pair<ECM, Runtime::ClientHandle>
Runtime::ConnectRequest(const AMDomain::client::ClientConnectContext &context,
                        amf interrupt_flag) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  if (!client_service) {
    return {Err(EC::InvalidHandle, "Runtime client app service is not bound"), nullptr};
  }
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(
          AMInfra::controller::AdaptClientInterruptFlag(interrupt_flag));
  return client_service->ConnectRequest(
      context, {}, control);
}

/**
 * @brief Remove one client through bound lifecycle port.
 */
ECM Runtime::RemoveClient(const std::string &nickname) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  return client_service ? client_service->RemoveClient(nickname)
                        : Err(EC::InvalidHandle, "Runtime client app service is not bound");
}

/**
 * @brief Build absolute path from client + raw path.
 */
std::string Runtime::BuildPath(const Runtime::ClientHandle &client,
                               const std::string &path) {
  AMApplication::client::ClientAppService *client_service =
      RuntimeBindingState_().client_service.load(std::memory_order_acquire);
  return client_service ? client_service->BuildAbsolutePath(client, path) : path;
}

/**
 * @brief Substitute path-like variable segments in one raw token.
 */
std::string Runtime::SubstitutePathLike(const std::string &raw) {
  const AMDomain::var::IVarSubstitutionPort *var_substitution =
      RuntimeBindingState_().var_substitution.load(std::memory_order_acquire);
  return var_substitution ? var_substitution->SubstitutePathLike(raw) : raw;
}

/**
 * @brief Return true when one variable domain exists.
 */
bool Runtime::HasVarDomain(const std::string &domain) {
  const AMDomain::var::IVarQueryPort *var_query =
      RuntimeBindingState_().var_query.load(std::memory_order_acquire);
  return var_query ? var_query->HasDomain(domain) : false;
}

/**
 * @brief Return all available variable domains.
 */
std::vector<std::string> Runtime::ListVarDomains() {
  const AMDomain::var::IVarQueryPort *var_query =
      RuntimeBindingState_().var_query.load(std::memory_order_acquire);
  return var_query ? var_query->ListDomains() : std::vector<std::string>{};
}

/**
 * @brief Return variables in one domain.
 */
std::vector<AMDomain::var::VarInfo>
Runtime::ListVarsByDomain(const std::string &domain) {
  const AMDomain::var::IVarQueryPort *var_query =
      RuntimeBindingState_().var_query.load(std::memory_order_acquire);
  return var_query ? var_query->ListByDomain(domain)
                   : std::vector<AMDomain::var::VarInfo>{};
}

/**
 * @brief Return current variable domain.
 */
std::string Runtime::CurrentVarDomain() {
  const AMDomain::var::IVarQueryPort *var_query =
      RuntimeBindingState_().var_query.load(std::memory_order_acquire);
  return var_query ? var_query->CurrentDomain() : "";
}

/**
 * @brief Query one variable value by domain/name.
 */
AMDomain::var::VarInfo Runtime::GetVar(const std::string &domain,
                                         const std::string &name) {
  const AMDomain::var::IVarQueryPort *var_query =
      RuntimeBindingState_().var_query.load(std::memory_order_acquire);
  return var_query ? var_query->GetVar(domain, name)
                   : AMDomain::var::VarInfo{};
}

/**
 * @brief Resolve prompt-path options for one nickname profile.
 */
PromptPathOptions
Runtime::ResolvePromptPathOptions(const std::string &nickname) {
  AMApplication::config::AMConfigAppService *config_service =
      RuntimeBindingState_().config_service.load(std::memory_order_acquire);
  if (!config_service) {
    return {};
  }

  AMApplication::config::PromptProfileDocument profile_document = {};
  if (!config_service->Read(&profile_document)) {
    return {};
  }

  const AMApplication::config::PromptProfileSettings *resolved = nullptr;
  auto direct = profile_document.profiles.find(nickname);
  if (direct != profile_document.profiles.end()) {
    resolved = &direct->second;
  } else {
    auto fallback = profile_document.profiles.find("*");
    if (fallback != profile_document.profiles.end()) {
      resolved = &fallback->second;
    }
  }
  if (!resolved) {
    static const AMApplication::config::PromptProfileSettings defaults = {};
    resolved = &defaults;
  }

  PromptPathOptions out{};
  out.inline_hint_enable = resolved->inline_hint.path.enable;
  out.inline_hint_timeout_ms = resolved->inline_hint.path.timeout_ms;
  out.complete_use_async = resolved->complete.path.use_async;
  out.complete_timeout_ms = resolved->complete.path.timeout_ms;
  out.highlight_enable = resolved->highlight.path.enable;
  out.highlight_timeout_ms = resolved->highlight.path.timeout_ms;
  return out;
}

/**
 * @brief Resolve one settings string with fallback.
 */
std::string Runtime::ResolveSettingString(const std::vector<std::string> &path,
                                          const std::string &fallback) {
  AMApplication::config::AMConfigAppService *config_service =
      RuntimeBindingState_().config_service.load(std::memory_order_acquire);

  if (path.size() >= 2 && path[0] == "Style" && config_service) {
    AMApplication::config::AMStyleSnapshot snapshot = {};
    if (config_service->Read(&snapshot)) {
      if (path[1] == "CompleteMenu" && path.size() == 3) {
        const std::string &field = path[2];
        if (field == "item_select_sign") {
          return snapshot.complete_menu.item_select_sign;
        }
        if (field == "order_num_style") {
          return snapshot.complete_menu.order_num_style;
        }
        if (field == "help_style") {
          return snapshot.complete_menu.help_style;
        }
        if (field == "number_pick") {
          return snapshot.complete_menu.number_pick ? "true" : "false";
        }
        if (field == "auto_fillin") {
          return snapshot.complete_menu.auto_fillin ? "true" : "false";
        }
      }
      if (path[1] == "CLIPrompt") {
        if (path.size() == 3) {
          const std::string &field = path[2];
          if (field == "format") {
            return snapshot.cli_prompt.prompt_template.core_prompt;
          }
          auto it = snapshot.cli_prompt.named_styles.find(field);
          if (it != snapshot.cli_prompt.named_styles.end()) {
            return it->second;
          }
        }
        if (path.size() == 4 && (path[2] == "template" || path[2] == "templete")) {
          if (path[3] == "core_prompt") {
            return snapshot.cli_prompt.prompt_template.core_prompt;
          }
          if (path[3] == "history_search_prompt") {
            return snapshot.cli_prompt.prompt_template.history_search_prompt;
          }
        }
        if (path.size() == 4 && path[2] == "shortcut") {
          auto it = snapshot.cli_prompt.shortcut.find(path[3]);
          if (it != snapshot.cli_prompt.shortcut.end()) {
            return it->second;
          }
        }
        if (path.size() == 4 && path[2] == "icons") {
          auto it = snapshot.cli_prompt.icons.find(path[3]);
          if (it != snapshot.cli_prompt.icons.end()) {
            return it->second;
          }
        }
      }
      if (path.size() == 3 && path[1] == "InputHighlight") {
        auto it = snapshot.input_highlight.find(path[2]);
        if (it != snapshot.input_highlight.end()) {
          return it->second;
        }
      }
      if (path.size() == 3 && path[1] == "ValueQueryHighlight") {
        auto it = snapshot.value_query_highlight.find(path[2]);
        if (it != snapshot.value_query_highlight.end()) {
          return it->second;
        }
      }
      if (path.size() == 3 && path[1] == "InternalStyle") {
        auto it = snapshot.internal_style.find(path[2]);
        if (it != snapshot.internal_style.end()) {
          return it->second;
        }
        if (path[2] == "default_prompt") {
          it = snapshot.internal_style.find("default_prompt_style");
          if (it != snapshot.internal_style.end()) {
            return it->second;
          }
        } else if (path[2] == "default_prompt_style") {
          it = snapshot.internal_style.find("default_prompt");
          if (it != snapshot.internal_style.end()) {
            return it->second;
          }
        }
      }
      if (path.size() == 3 && path[1] == "Path") {
        auto it = snapshot.path.find(path[2]);
        if (it != snapshot.path.end()) {
          return it->second;
        }
      }
      if (path.size() == 3 && path[1] == "SystemInfo") {
        auto it = snapshot.system_info.find(path[2]);
        if (it != snapshot.system_info.end()) {
          return it->second;
        }
      }
    }
  }

  if (path.size() >= 2 && path[0] == "Options" && config_service) {
    AMApplication::config::SettingsOptionsSnapshot options = {};
    if (config_service->Read(&options)) {
      if (path.size() == 3 && path[1] == "ClientManager" && path[2] == "heartbeat_timeout_ms") {
        return std::to_string(options.client_manager.heartbeat_timeout_ms);
      }
      if (path.size() == 3 && path[1] == "ClientManager" && path[2] == "heartbeat_interval_s") {
        return std::to_string(options.client_manager.heartbeat_interval_s);
      }
      if (path.size() == 3 && path[1] == kTransferOptionsKey) {
        if (path[2] == "init_thread_num") {
          return std::to_string(options.transfer_manager.init_thread_num);
        }
        if (path[2] == "max_thread_num") {
          return std::to_string(options.transfer_manager.max_thread_num);
        }
      }
      if (path.size() == 3 && path[1] == "FileSystem" && path[2] == "max_cd_history") {
        return std::to_string(options.filesystem.max_cd_history);
      }
      if (path.size() == 3 && path[1] == "LogManager") {
        if (path[2] == "client_trace_level") {
          return std::to_string(options.log_manager.client_trace_level);
        }
        if (path[2] == "program_trace_level") {
          return std::to_string(options.log_manager.program_trace_level);
        }
      }
      if (path.size() == 3 && path[1] == "AutoConfigBackup") {
        if (path[2] == "enabled") {
          return options.auto_config_backup.enabled ? "true" : "false";
        }
        if (path[2] == "interval_s") {
          return std::to_string(options.auto_config_backup.interval_s);
        }
        if (path[2] == "max_backup_count") {
          return std::to_string(options.auto_config_backup.max_backup_count);
        }
        if (path[2] == "last_backup_time_s") {
          return std::to_string(options.auto_config_backup.last_backup_time_s);
        }
      }
    }
  }

  return fallback;
}

/**
 * @brief Resolve one settings integer with fallback.
 */
int Runtime::ResolveSettingInt(const std::vector<std::string> &path,
                               int fallback) {
  const std::string raw = ResolveSettingString(path, "");
  if (raw.empty()) {
    return fallback;
  }
  int value = fallback;
  if (!TryParseInt_(raw, &value)) {
    return fallback;
  }
  return value;
}

/**
 * @brief Execute config backup when pending writes exceed threshold.
 */
ECM Runtime::BackupConfigIfNeeded() {
  AMApplication::config::AMConfigAppService *config_service =
      RuntimeBindingState_().config_service.load(std::memory_order_acquire);
  return config_service ? config_service->BackupIfNeeded() : Ok();
}

/**
 * @brief Resolve one config document storage path.
 */
bool Runtime::GetConfigDataPath(AMDomain::config::DocumentKind kind,
                                std::filesystem::path *out_path) {
  AMApplication::config::AMConfigAppService *config_service =
      RuntimeBindingState_().config_service.load(std::memory_order_acquire);
  return config_service ? config_service->GetDataPath(kind, out_path) : false;
}

/**
 * @brief Return whether one config document has unsaved mutations.
 */
bool Runtime::IsConfigDirty(AMDomain::config::DocumentKind kind) {
  AMApplication::config::AMConfigAppService *config_service =
      RuntimeBindingState_().config_service.load(std::memory_order_acquire);
  return config_service ? config_service->IsDirty(kind) : false;
}

/**
 * @brief Load one config document from storage.
 */
ECM Runtime::LoadConfig(AMDomain::config::DocumentKind kind, bool strict) {
  AMApplication::config::AMConfigAppService *config_service =
      RuntimeBindingState_().config_service.load(std::memory_order_acquire);
  return config_service ? config_service->Load(kind, strict) : Ok();
}

/**
 * @brief Format text through interface style service.
 */
std::string Runtime::Format(const std::string &text,
                            AMInterface::style::StyleIndex style_index,
                            const PathInfo *path_info) {
  AMInterface::style::AMStyleService *style_service =
      RuntimeBindingState_().style_service.load(std::memory_order_acquire);
  return style_service ? style_service->Format(text, style_index, path_info)
                       : text;
}

/**
 * @brief Create one progress bar using style configuration.
 */
AMProgressBar Runtime::CreateProgressBar(int64_t total_size,
                                         const std::string &prefix) {
  AMInterface::style::AMStyleService *style_service =
      RuntimeBindingState_().style_service.load(std::memory_order_acquire);
  if (style_service) {
    return style_service->CreateProgressBar(total_size, prefix);
  }
  return AMProgressBar(total_size, prefix);
}

/**
 * @brief Format one UTF-8 table using configured style defaults.
 */
std::string
Runtime::FormatUtf8Table(const std::vector<std::string> &keys,
                         const std::vector<std::vector<std::string>> &rows) {
  AMInterface::style::AMStyleService *style_service =
      RuntimeBindingState_().style_service.load(std::memory_order_acquire);
  if (!style_service) {
    return AMStr::FormatUtf8Table(keys, rows, "#00adb5");
  }
  return style_service->FormatUtf8Table(keys, rows);
}

/**
 * @brief Register one named signal hook.
 */
bool Runtime::RegisterSignalHook(
    const std::string &name, const AMDomain::signal::SignalHook &hook) {
  AMSignalMonitorPort *signal_monitor =
      RuntimeBindingState_().signal_monitor.load(std::memory_order_acquire);
  return signal_monitor ? signal_monitor->RegisterHook(name, hook) : false;
}

/**
 * @brief Unregister one named signal hook.
 */
bool Runtime::UnregisterSignalHook(const std::string &name) {
  AMSignalMonitorPort *signal_monitor =
      RuntimeBindingState_().signal_monitor.load(std::memory_order_acquire);
  return signal_monitor ? signal_monitor->UnregisterHook(name) : false;
}

/**
 * @brief Set signal-hook priority.
 */
bool Runtime::SetSignalHookPriority(const std::string &name, int priority) {
  AMSignalMonitorPort *signal_monitor =
      RuntimeBindingState_().signal_monitor.load(std::memory_order_acquire);
  return signal_monitor ? signal_monitor->SetHookPriority(name, priority)
                        : false;
}

/**
 * @brief Silence one registered CLI signal hook.
 */
void Runtime::SilenceSignalHook(const std::string &name) {
  AMSignalMonitorPort *signal_monitor =
      RuntimeBindingState_().signal_monitor.load(std::memory_order_acquire);
  if (signal_monitor) {
    signal_monitor->SilenceHook(name);
  }
}

/**
 * @brief Resume one registered CLI signal hook.
 */
void Runtime::ResumeSignalHook(const std::string &name) {
  AMSignalMonitorPort *signal_monitor =
      RuntimeBindingState_().signal_monitor.load(std::memory_order_acquire);
  if (signal_monitor) {
    signal_monitor->ResumeHook(name);
  }
}

/**
 * @brief Style one filesystem path display item.
 */
std::string Runtime::StylePath(const PathInfo &info, const std::string &name) {
  return Runtime::Format(name, AMInterface::style::StyleIndex::None, &info);
}
} // namespace AMInterface::ApplicationAdapters



