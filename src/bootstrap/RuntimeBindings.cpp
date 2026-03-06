#include "interface/ApplicationAdapters.hpp"
#include "interface/Prompt.hpp"
#include "domain/client/ClientManager.hpp"
#include "domain/filesystem/FileSystemManager.hpp"
#include "domain/host/HostManager.hpp"
#include "domain/signal/SignalMonitorPort.hpp"
#include "domain/transfer/TransferManager.hpp"
#include "domain/var/VarManager.hpp"
#include "infrastructure/Config.hpp"
#include <atomic>
#include <stdexcept>

namespace AMInterface::ApplicationAdapters {
namespace {
/**
 * @brief Runtime dependency slots bound once from startup wiring.
 */
struct RuntimeBindingState {
  std::atomic<AMDomain::host::AMHostManager *> host_manager{nullptr};
  std::atomic<AMDomain::client::AMClientManager *> client_manager{nullptr};
  std::atomic<AMDomain::transfer::AMTransferManager *> transfer_manager{nullptr};
  std::atomic<AMDomain::var::VarCLISet *> var_manager{nullptr};
  std::atomic<AMSignalMonitorPort *> signal_monitor{nullptr};
  std::atomic<AMPromptManager *> prompt_manager{nullptr};
  std::atomic<AMInfraConfigManager *> config_manager{nullptr};
  std::atomic<AMDomain::filesystem::AMFileSystem *> filesystem{nullptr};
};

/**
 * @brief Return process-wide runtime binding storage.
 */
RuntimeBindingState &RuntimeBindingState_() {
  static RuntimeBindingState state;
  return state;
}
} // namespace

/**
 * @brief Bind runtime dependencies explicitly.
 */
void Runtime::Bind(const RuntimeBindings &bindings) {
  auto &state = RuntimeBindingState_();
  state.host_manager.store(bindings.host_manager, std::memory_order_release);
  state.client_manager.store(bindings.client_manager, std::memory_order_release);
  state.transfer_manager.store(bindings.transfer_manager,
                               std::memory_order_release);
  state.var_manager.store(bindings.var_manager, std::memory_order_release);
  state.signal_monitor.store(bindings.signal_monitor, std::memory_order_release);
  state.prompt_manager.store(bindings.prompt_manager, std::memory_order_release);
  state.config_manager.store(bindings.config_manager, std::memory_order_release);
  state.filesystem.store(bindings.filesystem, std::memory_order_release);
}

/**
 * @brief Clear runtime dependency bindings.
 */
void Runtime::Reset() {
  auto &state = RuntimeBindingState_();
  state.host_manager.store(nullptr, std::memory_order_release);
  state.client_manager.store(nullptr, std::memory_order_release);
  state.transfer_manager.store(nullptr, std::memory_order_release);
  state.var_manager.store(nullptr, std::memory_order_release);
  state.signal_monitor.store(nullptr, std::memory_order_release);
  state.prompt_manager.store(nullptr, std::memory_order_release);
  state.config_manager.store(nullptr, std::memory_order_release);
  state.filesystem.store(nullptr, std::memory_order_release);
}

/**
 * @brief Return whether all runtime dependencies are bound.
 */
bool Runtime::IsBound() {
  auto &state = RuntimeBindingState_();
  return state.host_manager.load(std::memory_order_acquire) &&
         state.client_manager.load(std::memory_order_acquire) &&
         state.transfer_manager.load(std::memory_order_acquire) &&
         state.var_manager.load(std::memory_order_acquire) &&
         state.signal_monitor.load(std::memory_order_acquire) &&
         state.prompt_manager.load(std::memory_order_acquire) &&
         state.config_manager.load(std::memory_order_acquire) &&
         state.filesystem.load(std::memory_order_acquire);
}

/**
 * @brief Return bound config manager reference or throw when unbound.
 */
AMInfraConfigManager &Runtime::ConfigManagerOrThrow() {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  if (!config_manager) {
    throw std::runtime_error("Runtime config manager is not bound");
  }
  return *config_manager;
}

/**
 * @brief Return true when a configured host nickname exists.
 */
bool Runtime::HostExists(const std::string &nickname) {
  AMDomain::host::AMHostManager *host_manager =
      RuntimeBindingState_().host_manager.load(std::memory_order_acquire);
  return host_manager ? host_manager->HostExists(nickname) : false;
}

/**
 * @brief Return configured host nicknames.
 */
std::vector<std::string> Runtime::ListHostNames() {
  AMDomain::host::AMHostManager *host_manager =
      RuntimeBindingState_().host_manager.load(std::memory_order_acquire);
  return host_manager ? host_manager->ListNames() : std::vector<std::string>{};
}

/**
 * @brief Return created/connected client nicknames.
 */
std::vector<std::string> Runtime::ListClientNames() {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->GetClientNames()
                        : std::vector<std::string>{};
}

/**
 * @brief Return tracked transfer task IDs.
 */
std::vector<std::string> Runtime::ListTaskIds() {
  AMDomain::transfer::AMTransferManager *transfer_manager =
      RuntimeBindingState_().transfer_manager.load(std::memory_order_acquire);
  return transfer_manager ? transfer_manager->ListTaskIds()
                          : std::vector<std::string>{};
}

/**
 * @brief Resolve one client by nickname.
 */
Runtime::ClientHandle Runtime::GetClient(const std::string &nickname) {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->GetClient(nickname) : nullptr;
}

/**
 * @brief Resolve one host client from client-maintainer by nickname.
 */
Runtime::ClientHandle Runtime::GetHostClient(const std::string &nickname) {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->Clients().GetHost(nickname) : nullptr;
}

/**
 * @brief Return local client instance.
 */
Runtime::ClientHandle Runtime::LocalClient() {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->LocalClient() : nullptr;
}

/**
 * @brief Return current active client.
 */
Runtime::ClientHandle Runtime::CurrentClient() {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->CurrentClient() : nullptr;
}

/**
 * @brief Build absolute path from client + raw path.
 */
std::string Runtime::BuildPath(const Runtime::ClientHandle &client,
                               const std::string &path) {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->BuildPath(client, path) : path;
}

/**
 * @brief Substitute path-like variable segments in one raw token.
 */
std::string Runtime::SubstitutePathLike(const std::string &raw) {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->SubstitutePathLike(raw) : raw;
}

/**
 * @brief Return true when one variable domain exists.
 */
bool Runtime::HasVarDomain(const std::string &domain) {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->HasDomain(domain) : false;
}

/**
 * @brief Return all available variable domains.
 */
std::vector<std::string> Runtime::ListVarDomains() {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->ListDomains() : std::vector<std::string>{};
}

/**
 * @brief Return variables in one domain.
 */
std::vector<VarInfo> Runtime::ListVarsByDomain(const std::string &domain) {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->ListByDomain(domain) : std::vector<VarInfo>{};
}

/**
 * @brief Return current variable domain.
 */
std::string Runtime::CurrentVarDomain() {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->CurrentDomain() : "";
}

/**
 * @brief Query one variable value by domain/name.
 */
VarInfo Runtime::GetVar(const std::string &domain, const std::string &name) {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->GetVar(domain, name) : VarInfo{};
}

/**
 * @brief Resolve prompt-path options for one nickname profile.
 */
PromptPathOptions
Runtime::ResolvePromptPathOptions(const std::string &nickname) {
  AMPromptManager *prompt_manager =
      RuntimeBindingState_().prompt_manager.load(std::memory_order_acquire);
  if (!prompt_manager) {
    return {};
  }
  const AMPromptProfileArgs &profile =
      prompt_manager->ResolvePromptProfileArgs(nickname);
  PromptPathOptions out{};
  out.inline_hint_enable = profile.inline_hint.path.enable;
  out.inline_hint_timeout_ms = profile.inline_hint.path.timeout_ms;
  out.complete_use_async = profile.complete.path.use_async;
  out.complete_timeout_ms = profile.complete.path.timeout_ms;
  out.highlight_enable = profile.highlight.path.enable;
  out.highlight_timeout_ms = profile.highlight.path.timeout_ms;
  return out;
}

/**
 * @brief Resolve one settings string with fallback.
 */
std::string Runtime::ResolveSettingString(const std::vector<std::string> &path,
                                          const std::string &fallback) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->ResolveArg<std::string>(
                              DocumentKind::Settings, path, fallback, {})
                        : fallback;
}

/**
 * @brief Resolve one settings integer with fallback.
 */
int Runtime::ResolveSettingInt(const std::vector<std::string> &path,
                               int fallback) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->ResolveArg<int>(
                              DocumentKind::Settings, path, fallback, {})
                        : fallback;
}

/**
 * @brief Execute config backup when pending writes exceed threshold.
 */
ECM Runtime::BackupConfigIfNeeded() {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->BackupIfNeeded() : Ok();
}

/**
 * @brief Resolve one config document storage path.
 */
bool Runtime::GetConfigDataPath(DocumentKind kind,
                                std::filesystem::path *out_path) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->GetDataPath(kind, out_path) : false;
}

/**
 * @brief Return whether one config document has unsaved mutations.
 */
bool Runtime::IsConfigDirty(DocumentKind kind) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->IsDirty(kind) : false;
}

/**
 * @brief Load one config document from storage.
 */
ECM Runtime::LoadConfig(DocumentKind kind, bool strict) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->Load(kind, strict) : Ok();
}

/**
 * @brief Format text through ConfigManager style formatter.
 */
std::string Runtime::Format(const std::string &text,
                            const std::string &style_key,
                            const PathInfo *path_info) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->Format(text, style_key, path_info)
                        : text;
}

/**
 * @brief Register one named signal hook.
 */
bool Runtime::RegisterSignalHook(
    const std::string &name, const AMSignalMonitorPort::SignalHook &hook) {
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
  AMDomain::filesystem::AMFileSystem *filesystem =
      RuntimeBindingState_().filesystem.load(std::memory_order_acquire);
  return filesystem ? filesystem->StylePath(info, name) : name;
}
} // namespace AMInterface::ApplicationAdapters



