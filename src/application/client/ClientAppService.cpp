#include "application/client/ClientAppService.hpp"

#include "domain/client/ClientDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostManager.hpp"
#include "foundation/Path.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/string.hpp"
#include <filesystem>
#include <mutex>
#include <unordered_map>

namespace AMApplication::client {
namespace {
using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;
using ClientHandle = AMDomain::client::ClientHandle;
using ClientWorkdirState = AMDomain::client::ClientWorkdirState;
using ClientConnectContext = AMDomain::client::ClientConnectContext;
using ClientConnectOptions = AMDomain::client::ClientConnectOptions;
using ClientProtocol = AMDomain::client::ClientProtocol;
using KnownHostCallback = AMDomain::client::KnownHostCallback;
using AuthCallback = AMDomain::client::AuthCallback;
using TraceCallback = AMDomain::client::TraceCallback;
using DisconnectCallback =
    std::function<void(const ClientHandle &, const ECM &)>;
using HostConfig = AMDomain::host::HostConfig;
using ConRequest = AMDomain::client::ConRequest;

/**
 * @brief Normalize one nickname to canonical runtime form.
 */
std::string NormalizeNickname_(const std::string &nickname) {
  return AMDomain::client::ClientDomainService::NormalizeNickname(nickname);
}

/**
 * @brief Return true when one nickname targets the local profile.
 */
bool IsLocalNickname_(const std::string &nickname) {
  return AMDomain::host::HostManagerService::IsLocalNickname(nickname);
}

/**
 * @brief Normalize one nickname to application runtime key form.
 */
std::string NormalizeRuntimeNickname_(const std::string &nickname) {
  return IsLocalNickname_(nickname) ? std::string("local")
                                    : NormalizeNickname_(nickname);
}

/**
 * @brief Return true when one task-control flag is already interrupted.
 */
bool IsInterrupted_(const amf &interrupt_flag) {
  return interrupt_flag && !interrupt_flag->IsRunning();
}

/**
 * @brief Build one interrupted result pair.
 */
std::pair<ECM, ClientHandle> InterruptedResult_() {
  return {Err(EC::Terminate, "Interrupted by user"), nullptr};
}

/**
 * @brief Build one interrupted status.
 */
ECM InterruptedStatus_() { return Err(EC::Terminate, "Interrupted by user"); }

/**
 * @brief Return current epoch milliseconds when caller omitted start time.
 */
int64_t ResolveStartTime_(int64_t start_time) {
  return start_time >= 0 ? start_time : AMTime::miliseconds();
}

/**
 * @brief Normalize one stored workdir state to canonical separators.
 */
ClientWorkdirState NormalizeWorkdirState_(ClientWorkdirState state) {
  state.home_dir = AMPathStr::UnifyPathSep(state.home_dir, "/");
  state.login_dir = AMPathStr::UnifyPathSep(state.login_dir, "/");
  state.cwd = AMPathStr::UnifyPathSep(state.cwd, "/");
  return state;
}

/**
 * @brief Build workdir state from persisted host config.
 */
ClientWorkdirState WorkdirStateFromHostConfig_(const HostConfig &config) {
  ClientWorkdirState state{};
  state.home_dir = "";
  state.login_dir = config.metadata.login_dir;
  state.cwd = config.metadata.cwd;
  return NormalizeWorkdirState_(std::move(state));
}
} // namespace

/**
 * @brief Private implementation for client application service.
 */
class ClientAppService::Impl {
public:
  /**
   * @brief Construct implementation from host config manager and client factory.
   */
  Impl(AMDomain::host::AMHostConfigManager &host_config_manager,
       AMDomain::client::IClientFactoryPort &client_factory)
      : host_config_manager_(host_config_manager),
        client_factory_(client_factory),
        public_pool_(std::make_shared<ClientPublicPool>(
            [this](const std::string &nickname, int timeout_ms,
                   int64_t start_time) {
              return CreateTransferClient_(nickname, timeout_ms, start_time);
            })) {}

  /**
   * @brief Initialize local runtime state and maintainer registry.
   */
  ECM Init() {
    auto [cfg_rcm, local_cfg] = host_config_manager_.GetLocalConfig();
    if (!isok(cfg_rcm)) {
      return cfg_rcm;
    }

    auto [create_rcm, local_client] = CreateClient_(local_cfg.request);
    if (!isok(create_rcm) || !local_client) {
      return create_rcm;
    }

    ECM connect_rcm = local_client->IOPort().Connect(false);
    if (!isok(connect_rcm)) {
      return connect_rcm;
    }

    {
      std::lock_guard<std::mutex> lock(session_mtx_);
      local_client_ = local_client;
      current_client_ = local_client;
      workdir_states_[NormalizeRuntimeNickname_(local_cfg.request.nickname)] =
          WorkdirStateFromHostConfig_(local_cfg);
    }

    const int timeout_ms =
        AMDomain::client::ClientDomainService::ClampHeartbeatTimeoutMs(
            heartbeat_timeout_ms_);
    maintainer_ = std::make_unique<ClientMaintainer>(
        60, timeout_ms, SnapshotDisconnectCallback_());

    (void)GetOrInitWorkdir(local_client);
    return Ok();
  }

  /**
   * @brief Set heartbeat timeout for application-owned maintainer.
   */
  void SetHeartbeatTimeoutMs(int timeout_ms) {
    heartbeat_timeout_ms_ =
        AMDomain::client::ClientDomainService::ClampHeartbeatTimeoutMs(
            timeout_ms);
  }

  /**
   * @brief Return heartbeat timeout.
   */
  [[nodiscard]] int HeartbeatTimeoutMs() const { return heartbeat_timeout_ms_; }

  /**
   * @brief Set known-host callback provider.
   */
  void SetKnownHostCallback(KnownHostCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    known_host_cb_ = std::move(cb);
  }

  /**
   * @brief Set auth callback provider.
   */
  void SetAuthCallback(AuthCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    auth_cb_ = std::move(cb);
  }

  /**
   * @brief Set disconnect callback provider.
   */
  void SetDisconnectCallback(DisconnectCallback cb) {
    {
      std::lock_guard<std::mutex> lock(callback_mtx_);
      disconnect_cb_ = std::move(cb);
    }
    if (maintainer_) {
      maintainer_->SetDisconnectCallback(SnapshotDisconnectCallback_());
    }
  }

  /**
   * @brief Bind shared interactive-state flag.
   */
  void SetInteractiveFlag(const std::shared_ptr<std::atomic<bool>> &flag) {
    if (!flag) {
      return;
    }
    std::lock_guard<std::mutex> lock(session_mtx_);
    interactive_flag_ = flag;
  }

  /**
   * @brief Return bound interactive-state flag.
   */
  [[nodiscard]] std::shared_ptr<std::atomic<bool>> GetInteractiveFlag() const {
    std::lock_guard<std::mutex> lock(session_mtx_);
    return interactive_flag_;
  }

  /**
   * @brief Return maintainer reference.
   */
  [[nodiscard]] ClientMaintainer &Maintainer() { return *maintainer_; }

  /**
   * @brief Return maintainer reference.
   */
  [[nodiscard]] const ClientMaintainer &Maintainer() const {
    return *maintainer_;
  }

  /**
   * @brief Return shared transfer client pool.
   */
  [[nodiscard]] std::shared_ptr<ClientPublicPool> PublicPool() const {
    return public_pool_;
  }

  /**
   * @brief Create one transfer-only client instance by nickname.
   */
  std::pair<ECM, ClientHandle> CreateTransferClient(const std::string &nickname,
                                                    int timeout_ms,
                                                    int64_t start_time) {
    return CreateTransferClient_(nickname, timeout_ms, start_time);
  }

  /**
   * @brief Return one client by nickname.
   */
  [[nodiscard]] ClientHandle GetClient(const std::string &nickname) const {
    const std::string key = NormalizeRuntimeNickname_(nickname);
    if (IsLocalNickname_(key)) {
      return GetLocalClient();
    }
    return maintainer_ ? maintainer_->GetClient(key) : nullptr;
  }

  /**
   * @brief Return local client instance.
   */
  [[nodiscard]] ClientHandle GetLocalClient() const {
    std::lock_guard<std::mutex> lock(session_mtx_);
    return local_client_;
  }

  /**
   * @brief Return current active client instance.
   */
  [[nodiscard]] ClientHandle GetCurrentClient() const {
    std::lock_guard<std::mutex> lock(session_mtx_);
    return current_client_ ? current_client_ : local_client_;
  }

  /**
   * @brief Return current active nickname.
   */
  [[nodiscard]] std::string CurrentNickname() const {
    ClientHandle client = GetCurrentClient();
    return client ? NormalizeRuntimeNickname_(client->ConfigPort().GetNickname())
                  : std::string("local");
  }

  /**
   * @brief Set current active client instance.
   */
  void SetCurrentClient(const ClientHandle &client) {
    std::lock_guard<std::mutex> lock(session_mtx_);
    current_client_ = client ? client : local_client_;
  }

  /**
   * @brief Return all client nicknames.
   */
  [[nodiscard]] std::vector<std::string> GetClientNames() const {
    std::vector<std::string> names = {};
    if (GetLocalClient()) {
      names.emplace_back("local");
    }
    if (!maintainer_) {
      return names;
    }
    auto registered = maintainer_->GetNicknames();
    for (const auto &name : registered) {
      if (!IsLocalNickname_(name)) {
        names.push_back(name);
      }
    }
    return names;
  }

  /**
   * @brief Return all client handles.
   */
  [[nodiscard]] std::vector<ClientHandle> GetClients() const {
    std::vector<ClientHandle> clients = {};
    if (auto local = GetLocalClient()) {
      clients.push_back(local);
    }
    if (!maintainer_) {
      return clients;
    }
    auto registered = maintainer_->GetClients();
    for (const auto &client : registered) {
      if (client && !IsLocalNickname_(client->ConfigPort().GetNickname())) {
        clients.push_back(client);
      }
    }
    return clients;
  }

  /**
   * @brief Connect one configured nickname.
   */
  std::pair<ECM, ClientHandle>
  ConnectNickname(const std::string &nickname,
                  const ClientConnectOptions &options,
                  TraceCallback trace_cb, amf interrupt_flag) {
    if (IsInterrupted_(interrupt_flag)) {
      return InterruptedResult_();
    }

    const std::string key = NormalizeRuntimeNickname_(nickname);
    if (IsLocalNickname_(key)) {
      return {Ok(), GetLocalClient()};
    }

    auto [cfg_rcm, host_cfg] = host_config_manager_.GetClientConfig(key);
    if (!isok(cfg_rcm)) {
      return {cfg_rcm, nullptr};
    }

    auto [create_rcm, client] =
        CreateClient_(host_cfg.request, std::move(trace_cb));
    if (!isok(create_rcm) || !client) {
      return {create_rcm, nullptr};
    }

    ECM connect_rcm = client->IOPort().Connect(
        options.force,
        options.timeout_seconds > 0 ? options.timeout_seconds * 1000 : -1,
        ResolveStartTime_(-1));
    if (!isok(connect_rcm)) {
      return {connect_rcm, client};
    }

    ECM state_rcm = ApplyInitialState_(key, client, host_cfg.metadata);
    if (!isok(state_rcm)) {
      return {state_rcm, client};
    }

    if (options.register_to_manager && maintainer_) {
      ECM add_rcm = maintainer_->AddClient(client, true);
      if (!isok(add_rcm)) {
        return {add_rcm, client};
      }
    }
    return {Ok(), client};
  }

  /**
   * @brief Connect one explicit request payload.
   */
  std::pair<ECM, ClientHandle>
  ConnectRequest(const ClientConnectContext &context, TraceCallback trace_cb,
                 amf interrupt_flag) {
    if (IsInterrupted_(interrupt_flag)) {
      return InterruptedResult_();
    }

    ConRequest request = context.request;
    request.nickname = NormalizeRuntimeNickname_(request.nickname);
    if (request.keyfile.empty() && !context.private_keys.empty()) {
      request.keyfile = context.private_keys.front();
    }
    if (!request.password.empty() && !AMAuth::IsEncrypted(request.password)) {
      request.password = AMAuth::EncryptPassword(request.password);
    }

    ECM validate_rcm =
        AMDomain::client::ClientDomainService::ValidateConnectRequest(
            request, true);
    if (!isok(validate_rcm)) {
      return {validate_rcm, nullptr};
    }

    auto [create_rcm, client] = CreateClient_(request, std::move(trace_cb));
    if (!isok(create_rcm) || !client) {
      return {create_rcm, nullptr};
    }

    ECM connect_rcm = client->IOPort().Connect(
        context.options.force,
        context.options.timeout_seconds > 0 ? context.options.timeout_seconds * 1000
                                            : -1,
        ResolveStartTime_(-1));
    if (!isok(connect_rcm)) {
      return {connect_rcm, client};
    }

    HostConfig entry{};
    entry.request = request;
    auto [state_rcm, state] = ResolveInitialState_(client, entry.metadata);
    if (!isok(state_rcm)) {
      return {state_rcm, client};
    }
    {
      std::lock_guard<std::mutex> lock(session_mtx_);
      workdir_states_[request.nickname] = state;
    }

    entry.metadata = PersistedMetadataForState_(state);
    ECM save_rcm = host_config_manager_.AddHost(entry, true);
    if (!isok(save_rcm)) {
      return {save_rcm, client};
    }

    if (IsLocalNickname_(request.nickname)) {
      std::lock_guard<std::mutex> lock(session_mtx_);
      const bool current_is_local =
          !current_client_ || IsLocalNickname_(current_client_->ConfigPort().GetNickname());
      local_client_ = client;
      if (current_is_local) {
        current_client_ = client;
      }
    } else if (context.options.register_to_manager && maintainer_) {
      ECM add_rcm = maintainer_->AddClient(client, true);
      if (!isok(add_rcm)) {
        return {add_rcm, client};
      }
    }
    return {Ok(), client};
  }

  /**
   * @brief Ensure one client exists and is connected.
   */
  std::pair<ECM, ClientHandle>
  EnsureClient(const std::string &nickname, amf interrupt_flag) {
    if (IsInterrupted_(interrupt_flag)) {
      return InterruptedResult_();
    }

    const std::string key = NormalizeRuntimeNickname_(nickname);
    if (IsLocalNickname_(key)) {
      return {Ok(), GetLocalClient()};
    }

    ClientHandle existing = GetClient(key);
    if (!existing) {
      ClientConnectOptions options{};
      options.force = false;
      options.quiet = true;
      options.register_to_manager = true;
      return ConnectNickname(key, options, {}, interrupt_flag);
    }

    ECM connect_rcm = existing->IOPort().Connect(false);
    if (!isok(connect_rcm)) {
      return {connect_rcm, existing};
    }
    return {Ok(), existing};
  }

  /**
   * @brief Check one client by nickname.
   */
  std::pair<ECM, ClientHandle>
  CheckClient(const std::string &nickname, bool update, amf interrupt_flag,
              int timeout_ms, int64_t start_time) {
    if (IsInterrupted_(interrupt_flag)) {
      return InterruptedResult_();
    }

    ClientHandle client = GetClient(nickname);
    if (!client) {
      const std::string display = NormalizeRuntimeNickname_(nickname);
      return {Err(EC::ClientNotFound,
                  AMStr::fmt("Client not found: {}", display.empty() ? "local" : display)),
              nullptr};
    }

    if (!update) {
      const auto state = client->ConfigPort().GetState();
      if (state.first == AMDomain::client::ClientStatus::OK) {
        return {Ok(), client};
      }
    }

    ECM check_rcm = client->IOPort().Check(timeout_ms, ResolveStartTime_(start_time));
    return {check_rcm, client};
  }

  /**
   * @brief Remove one client from runtime registry.
   */
  ECM RemoveClient(const std::string &nickname) {
    const std::string key = NormalizeRuntimeNickname_(nickname);
    if (IsLocalNickname_(key)) {
      return Err(EC::InvalidArg, "Local client cannot be removed");
    }
    if (!maintainer_) {
      return Err(EC::InvalidHandle, "Client maintainer is not initialized");
    }
    ECM remove_rcm = maintainer_->RemoveClient(key);
    if (!isok(remove_rcm)) {
      return remove_rcm;
    }
    std::lock_guard<std::mutex> lock(session_mtx_);
    workdir_states_.erase(key);
    if (current_client_ && current_client_->ConfigPort().GetNickname() == key) {
      current_client_ = local_client_;
    }
    return Ok();
  }

  /**
   * @brief Parse one raw path token into nickname/path/client form.
   */
  [[nodiscard]] AMDomain::client::ParsedClientPath
  ParseScopedPath(const std::string &input, amf interrupt_flag) {
    if (IsInterrupted_(interrupt_flag)) {
      return {"", "", nullptr, InterruptedStatus_()};
    }

    const std::string current_nickname = CurrentNickname();
    const auto scoped = AMDomain::client::ClientDomainService::ParseScopedPath(
        input, current_nickname);
    ECM validate_rcm =
        AMDomain::client::ClientDomainService::ValidateScopedPath(scoped);
    if (!isok(validate_rcm)) {
      return {scoped.nickname, scoped.path, nullptr, validate_rcm};
    }

    if (IsLocalNickname_(scoped.nickname)) {
      return {"local", scoped.path, GetLocalClient(), Ok()};
    }

    ClientHandle client = GetClient(scoped.nickname);
    if (!client) {
      if (!host_config_manager_.HostExists(scoped.nickname)) {
        return {scoped.nickname, scoped.path, nullptr,
                Err(EC::HostConfigNotFound,
                    AMStr::fmt("Host config not found: {}", scoped.nickname))};
      }
      return {scoped.nickname, scoped.path, nullptr,
              Err(EC::ClientNotFound,
                  AMStr::fmt("Client not created: {}", scoped.nickname))};
    }
    return {scoped.nickname, scoped.path, client, Ok()};
  }

  /**
   * @brief Resolve one raw path against a client into absolute path.
   */
  [[nodiscard]] std::string
  ResolveClientPath(const std::string &path,
                    const ClientHandle &client) const {
    ClientHandle resolved_client = client ? client : GetCurrentClient();
    return BuildAbsolutePath(resolved_client, path);
  }

  /**
   * @brief Return stored workdir state for one nickname.
   */
  [[nodiscard]] ClientWorkdirState
  GetWorkdirState(const std::string &nickname) const {
    const std::string key = NormalizeRuntimeNickname_(nickname.empty() ? CurrentNickname()
                                                                       : nickname);
    {
      std::lock_guard<std::mutex> lock(session_mtx_);
      const auto it = workdir_states_.find(key);
      if (it != workdir_states_.end()) {
        return it->second;
      }
    }

    ClientWorkdirState state = LoadPersistedState_(key);
    std::lock_guard<std::mutex> lock(session_mtx_);
    workdir_states_[key] = state;
    return state;
  }

  /**
   * @brief Store workdir state for one nickname.
   */
  ECM SetWorkdirState(const std::string &nickname,
                      const ClientWorkdirState &state) {
    const std::string key = NormalizeRuntimeNickname_(nickname.empty() ? CurrentNickname()
                                                                       : nickname);
    const ClientWorkdirState normalized = NormalizeWorkdirState_(state);
    {
      std::lock_guard<std::mutex> lock(session_mtx_);
      workdir_states_[key] = normalized;
    }
    return PersistWorkdirState_(key, normalized);
  }

  /**
   * @brief Return current workdir, initializing when absent.
   */
  [[nodiscard]] std::string GetOrInitWorkdir(const ClientHandle &client) {
    if (!client) {
      return {};
    }

    const std::string nickname = NormalizeRuntimeNickname_(client->ConfigPort().GetNickname());
    ClientWorkdirState state = GetWorkdirState(nickname);
    state.home_dir = AMPathStr::UnifyPathSep(client->ConfigPort().GetHomeDir(), "/");
    if (state.home_dir.empty()) {
      state.home_dir = AMPathStr::UnifyPathSep(client->IOPort().UpdateHomeDir(), "/");
    }
    if (state.login_dir.empty()) {
      state.login_dir = state.home_dir;
    }
    if (!state.login_dir.empty() && !PathIsDir_(client, state.login_dir)) {
      state.login_dir = state.home_dir;
    }
    if (state.cwd.empty()) {
      state.cwd = state.login_dir;
    }
    state.cwd = AMDomain::client::ClientDomainService::ResolveAbsolutePath(
        state.cwd, state, "/");
    if (state.login_dir.empty()) {
      state.login_dir = state.cwd;
    }
    if (!state.login_dir.empty() && !AMPathStr::IsAbs(state.login_dir, "/")) {
      state.login_dir = AMDomain::client::ClientDomainService::ResolveAbsolutePath(
          state.login_dir, state, "/");
    }
    (void)SetWorkdirState(nickname, state);
    return state.cwd;
  }

  /**
   * @brief Build absolute path from client workdir/home context.
   */
  [[nodiscard]] std::string BuildAbsolutePath(const ClientHandle &client,
                                              const std::string &path) const {
    if (!client) {
      return path;
    }
    ClientWorkdirState state = GetWorkdirState(client->ConfigPort().GetNickname());
    state.home_dir = AMPathStr::UnifyPathSep(client->ConfigPort().GetHomeDir(), "/");
    if (state.home_dir.empty()) {
      state.home_dir = state.login_dir;
    }
    if (state.cwd.empty()) {
      state.cwd = AMDomain::client::ClientDomainService::ResolveWorkdir(state, "/");
    }
    return AMDomain::client::ClientDomainService::ResolveAbsolutePath(path, state,
                                                                      "/");
  }

private:
  /**
   * @brief Return one snapshot of known-host callback.
   */
  [[nodiscard]] KnownHostCallback SnapshotKnownHostCallback_() const {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    return known_host_cb_;
  }

  /**
   * @brief Return one snapshot of auth callback.
   */
  [[nodiscard]] AuthCallback SnapshotAuthCallback_() const {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    return auth_cb_;
  }

  /**
   * @brief Return one snapshot of disconnect callback.
   */
  [[nodiscard]] DisconnectCallback SnapshotDisconnectCallback_() const {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    return disconnect_cb_;
  }

  /**
   * @brief Create one concrete client and register current runtime callbacks.
   */
  std::pair<ECM, ClientHandle> CreateClient_(const ConRequest &request,
                                             TraceCallback trace_cb = {}) {
    auto [create_rcm, client] = client_factory_.CreateClient(request);
    if (!isok(create_rcm) || !client) {
      return {create_rcm, nullptr};
    }
    if (trace_cb) {
      client->IOPort().RegisterTraceCallback(std::move(trace_cb));
    }
    if (auto auth_cb = SnapshotAuthCallback_()) {
      client->IOPort().RegisterAuthCallback(std::move(auth_cb));
    }
    if (auto known_host_cb = SnapshotKnownHostCallback_()) {
      client->IOPort().RegisterKnownHostCallback(std::move(known_host_cb));
    }
    return {Ok(), client};
  }

  /**
   * @brief Create and connect one transfer-only pooled client by nickname.
   */
  std::pair<ECM, ClientHandle>
  CreateTransferClient_(const std::string &nickname, int timeout_ms,
                        int64_t start_time) {
    const std::string key = NormalizeRuntimeNickname_(nickname);
    auto load_cfg = [&]() -> std::pair<ECM, HostConfig> {
      if (IsLocalNickname_(key)) {
        return host_config_manager_.GetLocalConfig();
      }
      return host_config_manager_.GetClientConfig(key);
    };

    auto [cfg_rcm, host_cfg] = load_cfg();
    if (!isok(cfg_rcm)) {
      return {cfg_rcm, nullptr};
    }

    auto [create_rcm, client] = CreateClient_(host_cfg.request);
    if (!isok(create_rcm) || !client) {
      return {create_rcm, nullptr};
    }

    ECM connect_rcm = client->IOPort().Connect(false, timeout_ms,
                                               ResolveStartTime_(start_time));
    if (!isok(connect_rcm)) {
      return {connect_rcm, client};
    }
    return {Ok(), client};
  }

  /**
   * @brief Load persisted workdir state from host config.
   */
  [[nodiscard]] ClientWorkdirState
  LoadPersistedState_(const std::string &nickname) const {
    if (IsLocalNickname_(nickname)) {
      auto [rcm, cfg] = host_config_manager_.GetLocalConfig();
      return isok(rcm) ? WorkdirStateFromHostConfig_(cfg) : ClientWorkdirState{};
    }
    auto [rcm, cfg] = host_config_manager_.GetClientConfig(nickname);
    return isok(rcm) ? WorkdirStateFromHostConfig_(cfg) : ClientWorkdirState{};
  }

  /**
   * @brief Persist one workdir state snapshot back into host config.
   */
  ECM PersistWorkdirState_(const std::string &nickname,
                           const ClientWorkdirState &state) {
    auto load_cfg = [&]() -> std::pair<ECM, HostConfig> {
      if (IsLocalNickname_(nickname)) {
        return host_config_manager_.GetLocalConfig();
      }
      return host_config_manager_.GetClientConfig(nickname);
    };

    auto [cfg_rcm, cfg] = load_cfg();
    if (!isok(cfg_rcm)) {
      return cfg_rcm;
    }
    cfg.metadata.login_dir = state.login_dir;
    cfg.metadata.cwd = state.cwd;
    return host_config_manager_.AddHost(cfg, true);
  }

  /**
   * @brief Return persisted metadata snapshot for one nickname.
   */
  [[nodiscard]] AMDomain::host::ClientMetaData
  PersistedMetadataForState_(const ClientWorkdirState &state) const {
    AMDomain::host::ClientMetaData metadata{};
    metadata.login_dir = state.login_dir;
    metadata.cwd = state.cwd;
    return metadata;
  }

  /**
   * @brief Return true when one path currently exists as a directory.
   */
  [[nodiscard]] bool PathIsDir_(const ClientHandle &client,
                                const std::string &path) const {
    if (!client || path.empty()) {
      return false;
    }
    if (client->ConfigPort().GetProtocol() == ClientProtocol::LOCAL) {
      std::error_code ec;
      return std::filesystem::exists(path, ec) &&
             std::filesystem::is_directory(path, ec);
    }
    auto [rcm, info] = client->IOPort().stat(path, false);
    return isok(rcm) && info.type == PathType::DIR;
  }

  /**
   * @brief Apply initial persisted login/cwd state after connect.
   */
  ECM ApplyInitialState_(const std::string &nickname, const ClientHandle &client,
                         const AMDomain::host::ClientMetaData &metadata) {
    auto [state_rcm, state] = ResolveInitialState_(client, metadata);
    if (!isok(state_rcm)) {
      return state_rcm;
    }
    return SetWorkdirState(nickname, state);
  }

  /**
   * @brief Resolve initial runtime workdir state from client + metadata.
   */
  std::pair<ECM, ClientWorkdirState>
  ResolveInitialState_(const ClientHandle &client,
                       const AMDomain::host::ClientMetaData &metadata) {
    if (!client) {
      return {Err(EC::InvalidHandle, "null client handle"), {}};
    }
    ClientWorkdirState state = NormalizeWorkdirState_(
        {client->ConfigPort().GetHomeDir(), metadata.login_dir, metadata.cwd});
    if (state.home_dir.empty()) {
      state.home_dir = AMPathStr::UnifyPathSep(client->IOPort().UpdateHomeDir(), "/");
    }
    if (state.login_dir.empty()) {
      state.login_dir = state.home_dir;
    }
    if (!state.login_dir.empty() && !PathIsDir_(client, state.login_dir)) {
      state.login_dir = state.home_dir;
    }
    if (state.cwd.empty()) {
      state.cwd = state.login_dir;
    }
    state.cwd = AMDomain::client::ClientDomainService::ResolveAbsolutePath(
        state.cwd, state, "/");
    if (!state.login_dir.empty() && !AMPathStr::IsAbs(state.login_dir, "/")) {
      state.login_dir = AMDomain::client::ClientDomainService::ResolveAbsolutePath(
          state.login_dir, state, "/");
    }
    return {Ok(), state};
  }

private:
  AMDomain::host::AMHostConfigManager &host_config_manager_;
  AMDomain::client::IClientFactoryPort &client_factory_;
  mutable std::mutex callback_mtx_;
  KnownHostCallback known_host_cb_ = {};
  AuthCallback auth_cb_ = {};
  DisconnectCallback disconnect_cb_ = {};
  mutable std::mutex session_mtx_;
  std::shared_ptr<std::atomic<bool>> interactive_flag_ =
      std::make_shared<std::atomic<bool>>(false);
  ClientHandle local_client_ = nullptr;
  ClientHandle current_client_ = nullptr;
  mutable std::unordered_map<std::string, ClientWorkdirState> workdir_states_;
  int heartbeat_timeout_ms_ = 100;
  std::unique_ptr<ClientMaintainer> maintainer_;
  std::shared_ptr<ClientPublicPool> public_pool_;
};

/**
 * @brief Construct app service from host config manager and client factory.
 */
ClientAppService::ClientAppService(
    AMDomain::host::AMHostConfigManager &host_config_manager,
    AMDomain::client::IClientFactoryPort &client_factory)
    : impl_(std::make_unique<Impl>(host_config_manager, client_factory)) {}

/**
 * @brief Destroy app service.
 */
ClientAppService::~ClientAppService() = default;

/**
 * @brief Initialize local/current client state and maintainer registry.
 */
ECM ClientAppService::Init() { return impl_->Init(); }

/**
 * @brief Set heartbeat timeout for application-owned maintainer.
 */
void ClientAppService::SetHeartbeatTimeoutMs(int timeout_ms) {
  impl_->SetHeartbeatTimeoutMs(timeout_ms);
}

/**
 * @brief Return current heartbeat timeout.
 */
int ClientAppService::HeartbeatTimeoutMs() const {
  return impl_->HeartbeatTimeoutMs();
}

/**
 * @brief Set known-host callback provider.
 */
void ClientAppService::SetKnownHostCallback(KnownHostCallback cb) {
  impl_->SetKnownHostCallback(std::move(cb));
}

/**
 * @brief Set auth callback provider.
 */
void ClientAppService::SetAuthCallback(AuthCallback cb) {
  impl_->SetAuthCallback(std::move(cb));
}

/**
 * @brief Set disconnect callback provider.
 */
void ClientAppService::SetDisconnectCallback(DisconnectCallback cb) {
  impl_->SetDisconnectCallback(std::move(cb));
}

/**
 * @brief Bind shared interactive-state flag.
 */
void ClientAppService::SetInteractiveFlag(
    const std::shared_ptr<std::atomic<bool>> &flag) {
  impl_->SetInteractiveFlag(flag);
}

/**
 * @brief Return bound interactive-state flag.
 */
std::shared_ptr<std::atomic<bool>> ClientAppService::GetInteractiveFlag() const {
  return impl_->GetInteractiveFlag();
}

/**
 * @brief Return current maintainer reference.
 */
ClientMaintainer &ClientAppService::Maintainer() { return impl_->Maintainer(); }

/**
 * @brief Return current maintainer reference.
 */
const ClientMaintainer &ClientAppService::Maintainer() const {
  return impl_->Maintainer();
}

/**
 * @brief Return shared transfer client pool.
 */
std::shared_ptr<ClientPublicPool> ClientAppService::PublicPool() const {
  return impl_->PublicPool();
}

/**
 * @brief Create one transfer-only client instance by nickname.
 */
std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::CreateTransferClient(const std::string &nickname,
                                       int timeout_ms,
                                       int64_t start_time) {
  return impl_->CreateTransferClient(nickname, timeout_ms, start_time);
}

/**
 * @brief Return one client by nickname.
 */
ClientAppService::ClientHandle
ClientAppService::GetClient(const std::string &nickname) const {
  return impl_->GetClient(nickname);
}

/**
 * @brief Return local client instance.
 */
ClientAppService::ClientHandle ClientAppService::GetLocalClient() const {
  return impl_->GetLocalClient();
}

/**
 * @brief Return current active client instance.
 */
ClientAppService::ClientHandle ClientAppService::GetCurrentClient() const {
  return impl_->GetCurrentClient();
}

/**
 * @brief Return current active nickname.
 */
std::string ClientAppService::CurrentNickname() const {
  return impl_->CurrentNickname();
}

/**
 * @brief Set current active client instance.
 */
void ClientAppService::SetCurrentClient(const ClientHandle &client) {
  impl_->SetCurrentClient(client);
}

/**
 * @brief Return all client nicknames.
 */
std::vector<std::string> ClientAppService::GetClientNames() const {
  return impl_->GetClientNames();
}

/**
 * @brief Return all client handles.
 */
std::vector<ClientAppService::ClientHandle> ClientAppService::GetClients() const {
  return impl_->GetClients();
}

/**
 * @brief Connect one configured nickname.
 */
std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::ConnectNickname(const std::string &nickname,
                                  const ClientConnectOptions &options,
                                  TraceCallback trace_cb,
                                  amf interrupt_flag) {
  return impl_->ConnectNickname(nickname, options, std::move(trace_cb),
                                interrupt_flag);
}

/**
 * @brief Connect one explicit request payload.
 */
std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::ConnectRequest(const ClientConnectContext &context,
                                 TraceCallback trace_cb,
                                 amf interrupt_flag) {
  return impl_->ConnectRequest(context, std::move(trace_cb), interrupt_flag);
}

/**
 * @brief Ensure one client exists and is connected.
 */
std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::EnsureClient(const std::string &nickname,
                               amf interrupt_flag) {
  return impl_->EnsureClient(nickname, interrupt_flag);
}

/**
 * @brief Check one client by nickname.
 */
std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::CheckClient(const std::string &nickname, bool update,
                              amf interrupt_flag, int timeout_ms,
                              int64_t start_time) {
  return impl_->CheckClient(nickname, update, interrupt_flag, timeout_ms,
                            start_time);
}

/**
 * @brief Remove one client from runtime registry.
 */
ClientAppService::ECM ClientAppService::RemoveClient(
    const std::string &nickname) {
  return impl_->RemoveClient(nickname);
}

/**
 * @brief Parse one raw path token into nickname/path/client form.
 */
ClientAppService::ParsedClientPath
ClientAppService::ParseScopedPath(const std::string &input,
                                  amf interrupt_flag) {
  return impl_->ParseScopedPath(input, interrupt_flag);
}

/**
 * @brief Resolve one raw path into absolute path.
 */
std::string ClientAppService::ResolveClientPath(
    const std::string &path, const ClientHandle &client) const {
  return impl_->ResolveClientPath(path, client);
}

/**
 * @brief Return stored workdir state for one nickname.
 */
ClientAppService::ClientWorkdirState ClientAppService::GetWorkdirState(
    const std::string &nickname) const {
  return impl_->GetWorkdirState(nickname);
}

/**
 * @brief Store workdir state for one nickname.
 */
ClientAppService::ECM ClientAppService::SetWorkdirState(
    const std::string &nickname, const ClientWorkdirState &state) {
  return impl_->SetWorkdirState(nickname, state);
}

/**
 * @brief Return current workdir, initializing when absent.
 */
std::string ClientAppService::GetOrInitWorkdir(const ClientHandle &client) {
  return impl_->GetOrInitWorkdir(client);
}

/**
 * @brief Build absolute path from client workdir/home context.
 */
std::string ClientAppService::BuildAbsolutePath(const ClientHandle &client,
                                                const std::string &path) const {
  return impl_->BuildAbsolutePath(client, path);
}
} // namespace AMApplication::client
