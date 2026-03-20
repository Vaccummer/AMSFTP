#include "application/client/ClientAppService.hpp"

#include "ClientPublicPool.hpp"

#include "foundation/core/Path.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"

namespace AMApplication::client {
namespace {
using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;
using ClientHandle = AMDomain::client::ClientHandle;
using ClientState = AMDomain::client::ClientState;
using ClientStatus = AMDomain::client::ClientStatus;
using ClientWorkdirState = AMDomain::client::ClientWorkdirState;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using HostConfig = AMDomain::host::HostConfig;
using ConRequest = AMDomain::host::ConRequest;
using ClientProtocol = AMDomain::host::ClientProtocol;

bool IsInterrupted(const AMDomain::client::amf &interrupt_flag) {
  return interrupt_flag && interrupt_flag->IsInterrupted();
}
} // namespace

ClientAppService::ClientAppService() : ClientAppService(ClientServiceArg{}) {}

ClientAppService::ClientAppService(ClientServiceArg arg)
    : init_arg_(std::move(arg)),
      disconnect_cb_(init_arg_.disconnect_callback),
      trace_cb_(init_arg_.trace_callback), auth_cb_(init_arg_.auth_callback),
      known_host_cb_(init_arg_.known_host_callback) {
  maintainer_ = AMDomain::client::CreateClientMaintainer(
      init_arg_.heartbeat_interval_s, init_arg_.heartbeat_timeout_ms,
      disconnect_cb_, {});
  if (maintainer_) {
    maintainer_->SetCheckTimeout(init_arg_.heartbeat_timeout_ms);
    if (init_arg_.heartbeat_interval_s > 0) {
      maintainer_->SetHeartbeatInterval(init_arg_.heartbeat_interval_s);
      maintainer_->StartHeartbeat();
    }
  }

  transfer_pool_ = std::make_shared<ClientPublicPool>(
      [this](const std::string &nickname, int timeout_ms, int64_t start_time) {
        return CreateTransferClient(nickname, timeout_ms, start_time);
      });
}

ClientAppService::~ClientAppService() = default;

ClientAppService::ECM ClientAppService::Init() {
  auto *host_config_manager = init_arg_.host_config_manager;
  if (!host_config_manager) {
    return {EC::Success, ""};
  }

  auto [cfg_rcm, local_cfg] = host_config_manager->GetLocalConfig();
  if (!isok(cfg_rcm)) {
    return cfg_rcm;
  }

  auto [create_rcm, local_client] = CreateClient(local_cfg);
  if (!isok(create_rcm) || !local_client) {
    return create_rcm;
  }

  const auto connect = local_client->IOPort().Connect(
      AMDomain::filesystem::ConnectArgs{false}, BuildControl_());
  if (!isok(connect.rcm)) {
    return connect.rcm;
  }

  ECM add_rcm = AddClient(local_client, true);
  if (!isok(add_rcm)) {
    return add_rcm;
  }

  SetWorkdirState("local", NormalizeWorkdirState_(
                                {local_client->ConfigPort().GetHomeDir(),
                                 local_cfg.metadata.login_dir,
                                 local_cfg.metadata.cwd}));
  return {EC::Success, ""};
}

ClientAppService::ClientServiceArg ClientAppService::GetInitArg() const {
  std::lock_guard<std::mutex> callback_lock(callback_mtx_);
  std::lock_guard<std::mutex> registry_lock(registry_mtx_);
  ClientServiceArg arg = init_arg_;
  arg.disconnect_callback = disconnect_cb_;
  arg.trace_callback = trace_cb_;
  arg.auth_callback = auth_cb_;
  arg.known_host_callback = known_host_cb_;
  return arg;
}

ClientAppService::ClientHandle
ClientAppService::GetClient(const std::string &nickname) const {
  const std::string key = NormalizeNickname_(nickname);
  if (IsLocalNickname_(key)) {
    return GetLocalClient();
  }
  if (!maintainer_) {
    return nullptr;
  }
  return maintainer_->GetClient(key);
}

ClientAppService::ClientHandle ClientAppService::GetLocalClient() const {
  std::lock_guard<std::mutex> lock(registry_mtx_);
  return local_client_;
}

ClientAppService::ClientHandle ClientAppService::GetCurrentClient() const {
  std::lock_guard<std::mutex> lock(registry_mtx_);
  return current_client_ ? current_client_ : local_client_;
}

std::string ClientAppService::GetCurrentNickname() const {
  ClientHandle current = GetCurrentClient();
  if (!current) {
    return "local";
  }
  return NormalizeNickname_(current->ConfigPort().GetNickname());
}

std::string ClientAppService::CurrentNickname() const {
  return GetCurrentNickname();
}

std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::CreateClient(const HostConfig &config) {
  KnownHostCallback known_host_cb = {};
  TraceCallback trace_cb = {};
  AuthCallback auth_cb = {};
  std::vector<std::string> private_keys;
  {
    std::lock_guard<std::mutex> callback_lock(callback_mtx_);
    std::lock_guard<std::mutex> registry_lock(registry_mtx_);
    known_host_cb = known_host_cb_;
    trace_cb = trace_cb_;
    auth_cb = auth_cb_;
    private_keys = init_arg_.private_keys;
  }

  auto [create_rcm, client] =
      AMDomain::client::CreateClient(config.request, known_host_cb, trace_cb,
                                     auth_cb, private_keys);
  if (!isok(create_rcm) || !client) {
    return {create_rcm, nullptr};
  }
  ApplyCallbacksToClient_(client);
  return {create_rcm, client};
}

ClientAppService::ECM ClientAppService::AddClient(ClientHandle client,
                                                  bool overwrite) {
  if (!client) {
    return {EC::InvalidHandle, "Client handle is null"};
  }

  ApplyCallbacksToClient_(client);
  const std::string nickname =
      NormalizeNickname_(client->ConfigPort().GetNickname());
  if (nickname.empty()) {
    return {EC::InvalidArg, "Client nickname is empty"};
  }

  if (IsLocalNickname_(nickname)) {
    std::lock_guard<std::mutex> lock(registry_mtx_);
    if (!local_client_ || overwrite) {
      local_client_ = client;
    }
    if (!current_client_ || IsLocalNickname_(current_client_->ConfigPort().GetNickname()) ||
        overwrite) {
      current_client_ = local_client_;
    }
    return {EC::Success, ""};
  }

  if (!maintainer_) {
    return {EC::InvalidHandle, "Client maintainer is not initialized"};
  }
  const bool added = maintainer_->AddClient(client, overwrite);
  if (!added) {
    return {EC::TargetAlreadyExists,
            AMStr::fmt("Client already exists: {}", nickname)};
  }

  std::lock_guard<std::mutex> lock(registry_mtx_);
  if (!current_client_) {
    current_client_ = client;
  }
  return {EC::Success, ""};
}

ClientAppService::ClientState
ClientAppService::CheckClient(const std::string &nickname, bool reconnect,
                              bool update) {
  ClientHandle client = GetClient(nickname);
  if (!client) {
    return {ClientStatus::NotInitialized,
            {EC::ClientNotFound,
             AMStr::fmt("Client not found: {}", NormalizeNickname_(nickname))}};
  }
  return CheckClientInternal_(client, reconnect, update, BuildControl_());
}

std::map<std::string, ClientAppService::ClientHandle>
ClientAppService::GetClients() const {
  std::map<std::string, ClientHandle> clients = {};
  if (maintainer_) {
    clients = maintainer_->GetAllClients();
  }

  const ClientHandle local = GetLocalClient();
  if (local) {
    clients["local"] = local;
  }
  return clients;
}

ClientAppService::ECM ClientAppService::RemoveClient(
    const std::string &nickname) {
  const std::string key = NormalizeNickname_(nickname);
  if (IsLocalNickname_(key)) {
    return {EC::InvalidArg, "Local client cannot be removed"};
  }

  if (!maintainer_) {
    return {EC::InvalidHandle, "Client maintainer is not initialized"};
  }
  if (!maintainer_->RemoveClient(key)) {
    return {EC::ClientNotFound, AMStr::fmt("Client not found: {}", key)};
  }

  std::lock_guard<std::mutex> lock(registry_mtx_);
  public_clients_.erase(key);
  if (current_client_ &&
      NormalizeNickname_(current_client_->ConfigPort().GetNickname()) == key) {
    current_client_ = local_client_;
  }
  return {EC::Success, ""};
}

std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::GetPublicClient(const std::string &nickname) {
  const std::string key = NormalizeNickname_(nickname);

  while (true) {
    ClientID candidate_id;
    ClientHandle candidate = nullptr;
    {
      std::lock_guard<std::mutex> lock(registry_mtx_);
      auto bucket_it = public_clients_.find(key);
      if (bucket_it == public_clients_.end() || bucket_it->second.empty()) {
        return {{EC::ClientNotFound,
                 AMStr::fmt("No public client found for {}", key)},
                nullptr};
      }
      auto it = bucket_it->second.begin();
      candidate_id = it->first;
      candidate = it->second;
    }

    if (!candidate) {
      std::lock_guard<std::mutex> lock(registry_mtx_);
      auto bucket_it = public_clients_.find(key);
      if (bucket_it != public_clients_.end()) {
        bucket_it->second.erase(candidate_id);
        if (bucket_it->second.empty()) {
          public_clients_.erase(bucket_it);
        }
      }
      continue;
    }

    const ClientState state =
        CheckClientInternal_(candidate, false, true, BuildControl_());
    if (state.status == ClientStatus::OK && isok(state.rcm)) {
      return {state.rcm, candidate};
    }

    std::lock_guard<std::mutex> lock(registry_mtx_);
    auto bucket_it = public_clients_.find(key);
    if (bucket_it != public_clients_.end()) {
      bucket_it->second.erase(candidate_id);
      if (bucket_it->second.empty()) {
        public_clients_.erase(bucket_it);
      }
    }
  }
}

ClientAppService::ECM
ClientAppService::AddPublicClient(const ClientHandle &client) {
  if (!client) {
    return {EC::InvalidHandle, "Client handle is null"};
  }
  const std::string nickname =
      NormalizeNickname_(client->ConfigPort().GetNickname());
  const ClientID id = client->GetUID();
  if (nickname.empty()) {
    return {EC::InvalidArg, "Client nickname is empty"};
  }
  if (id.empty()) {
    return {EC::InvalidArg, "Client UID is empty"};
  }

  ApplyCallbacksToClient_(client);

  std::lock_guard<std::mutex> lock(registry_mtx_);
  public_clients_[nickname][id] = client;
  return {EC::Success, ""};
}

void ClientAppService::SetPublicClientCallback(
    std::optional<DisconnectCallback> disconnect_cb,
    std::optional<TraceCallback> trace_cb,
    std::optional<KnownHostCallback> known_host_cb,
    std::optional<AuthCallback> auth_cb) {
  {
    std::lock_guard<std::mutex> callback_lock(callback_mtx_);
    std::lock_guard<std::mutex> registry_lock(registry_mtx_);
    if (disconnect_cb.has_value()) {
      disconnect_cb_ = std::move(*disconnect_cb);
      init_arg_.disconnect_callback = disconnect_cb_;
    }
    if (trace_cb.has_value()) {
      trace_cb_ = std::move(*trace_cb);
      init_arg_.trace_callback = trace_cb_;
    }
    if (known_host_cb.has_value()) {
      known_host_cb_ = std::move(*known_host_cb);
      init_arg_.known_host_callback = known_host_cb_;
    }
    if (auth_cb.has_value()) {
      auth_cb_ = std::move(*auth_cb);
      init_arg_.auth_callback = auth_cb_;
    }
  }

  if (maintainer_ && disconnect_cb.has_value()) {
    maintainer_->SetDisconnectCallback(disconnect_cb_);
  }
}

void ClientAppService::SetHeartbeatTimeoutMs(int timeout_ms) {
  const int clamped = static_cast<int>(
      AMDomain::client::MaintainerService::ClampHeartbeatTimeoutMs(timeout_ms));
  {
    std::lock_guard<std::mutex> lock(registry_mtx_);
    init_arg_.heartbeat_timeout_ms = clamped;
  }
  if (maintainer_) {
    maintainer_->SetCheckTimeout(clamped);
  }
}

int ClientAppService::HeartbeatTimeoutMs() const {
  std::lock_guard<std::mutex> lock(registry_mtx_);
  return init_arg_.heartbeat_timeout_ms;
}

void ClientAppService::SetHeartbeatIntervalS(int interval_s) {
  {
    std::lock_guard<std::mutex> lock(registry_mtx_);
    init_arg_.heartbeat_interval_s = interval_s;
  }

  if (!maintainer_) {
    return;
  }
  if (interval_s <= 0) {
    maintainer_->PauseHeartbeat();
    return;
  }

  const int clamped = static_cast<int>(
      AMDomain::client::MaintainerService::ClampHeartbeatIntervalS(interval_s));
  maintainer_->SetHeartbeatInterval(clamped);
  maintainer_->StartHeartbeat();
}

int ClientAppService::HeartbeatIntervalS() const {
  std::lock_guard<std::mutex> lock(registry_mtx_);
  return init_arg_.heartbeat_interval_s;
}

void ClientAppService::SetKnownHostCallback(KnownHostCallback cb) {
  SetPublicClientCallback(std::nullopt, std::nullopt,
                          std::optional<KnownHostCallback>(std::move(cb)),
                          std::nullopt);
}

void ClientAppService::SetAuthCallback(AuthCallback cb) {
  SetPublicClientCallback(std::nullopt, std::nullopt, std::nullopt,
                          std::optional<AuthCallback>(std::move(cb)));
}

void ClientAppService::SetDisconnectCallback(DisconnectCallback cb) {
  SetPublicClientCallback(std::optional<DisconnectCallback>(std::move(cb)),
                          std::nullopt, std::nullopt, std::nullopt);
}

void ClientAppService::SetTraceCallback(TraceCallback cb) {
  SetPublicClientCallback(std::nullopt,
                          std::optional<TraceCallback>(std::move(cb)),
                          std::nullopt, std::nullopt);
}

void ClientAppService::SetInteractiveFlag(
    const std::shared_ptr<std::atomic<bool>> &flag) {
  if (!flag) {
    return;
  }
  std::lock_guard<std::mutex> lock(registry_mtx_);
  interactive_flag_ = flag;
}

std::shared_ptr<std::atomic<bool>> ClientAppService::GetInteractiveFlag() const {
  std::lock_guard<std::mutex> lock(registry_mtx_);
  return interactive_flag_;
}

std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
ClientAppService::PublicPool() const {
  return transfer_pool_;
}

std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::CreateTransferClient(const std::string &nickname,
                                       int timeout_ms,
                                       int64_t start_time) {
  auto [public_rcm, public_client] = GetPublicClient(nickname);
  if (isok(public_rcm) && public_client) {
    return {public_rcm, public_client};
  }

  const std::string key = NormalizeNickname_(nickname);
  if (auto existing = GetClient(key)) {
    const ClientState state = CheckClientInternal_(
        existing, false, true, BuildControl_(nullptr, timeout_ms, start_time));
    if (isok(state.rcm)) {
      (void)AddPublicClient(existing);
      return {state.rcm, existing};
    }
  }

  auto *host_config_manager = init_arg_.host_config_manager;
  if (!host_config_manager) {
    return {public_rcm, nullptr};
  }

  std::pair<ECM, HostConfig> cfg =
      IsLocalNickname_(key) ? host_config_manager->GetLocalConfig()
                            : host_config_manager->GetClientConfig(key);
  if (!isok(cfg.first)) {
    return {cfg.first, nullptr};
  }

  auto [create_rcm, client] = CreateClient(cfg.second);
  if (!isok(create_rcm) || !client) {
    return {create_rcm, nullptr};
  }

  auto connect_res = client->IOPort().Connect(
      AMDomain::filesystem::ConnectArgs{false},
      BuildControl_(nullptr, timeout_ms, start_time));
  if (!isok(connect_res.rcm)) {
    return {connect_res.rcm, client};
  }

  ECM add_public_rcm = AddPublicClient(client);
  if (!isok(add_public_rcm)) {
    return {add_public_rcm, client};
  }
  return {ECM{EC::Success, ""}, client};
}

void ClientAppService::SetCurrentClient(const ClientHandle &client) {
  std::lock_guard<std::mutex> lock(registry_mtx_);
  current_client_ = client ? client : local_client_;
}

std::vector<std::string> ClientAppService::GetClientNames() const {
  std::vector<std::string> names = {};
  auto clients = GetClients();
  names.reserve(clients.size());
  for (const auto &entry : clients) {
    names.push_back(entry.first);
  }
  return names;
}

std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::ConnectNickname(const std::string &nickname,
                                  const ClientConnectOptions &options,
                                  TraceCallback trace_cb,
                                  amf interrupt_flag) {
  if (IsInterrupted(interrupt_flag)) {
    return {{EC::Terminate, "Interrupted by user"}, nullptr};
  }

  const std::string key = NormalizeNickname_(nickname);
  if (!options.force) {
    if (auto existing = GetClient(key)) {
      const ClientState state = CheckClientInternal_(
          existing, false, false,
          BuildControl_(interrupt_flag,
                        options.timeout_seconds > 0
                            ? options.timeout_seconds * 1000
                            : -1,
                        AMTime::miliseconds()));
      if (isok(state.rcm)) {
        return {state.rcm, existing};
      }
    }
  }

  auto *host_config_manager = init_arg_.host_config_manager;
  if (!host_config_manager) {
    return {{EC::InvalidHandle, "Host config manager is not bound"}, nullptr};
  }

  auto cfg = IsLocalNickname_(key) ? host_config_manager->GetLocalConfig()
                                   : host_config_manager->GetClientConfig(key);
  if (!isok(cfg.first)) {
    return {cfg.first, nullptr};
  }

  auto [create_rcm, client] = CreateClient(cfg.second);
  if (!isok(create_rcm) || !client) {
    return {create_rcm, nullptr};
  }
  if (trace_cb) {
    client->IOPort().RegisterTraceCallback(std::move(trace_cb));
  }

  auto connect_res = client->IOPort().Connect(
      AMDomain::filesystem::ConnectArgs{options.force},
      BuildControl_(interrupt_flag,
                    options.timeout_seconds > 0 ? options.timeout_seconds * 1000
                                                : -1,
                    AMTime::miliseconds()));
  if (!isok(connect_res.rcm)) {
    return {connect_res.rcm, client};
  }

  if (options.register_to_manager) {
    ECM add_rcm = AddClient(client, true);
    if (!isok(add_rcm)) {
      return {add_rcm, client};
    }
  }

  const ClientWorkdirState init_state =
      NormalizeWorkdirState_({client->ConfigPort().GetHomeDir(),
                              cfg.second.metadata.login_dir,
                              cfg.second.metadata.cwd});
  (void)SetWorkdirState(key, init_state);
  return {{EC::Success, ""}, client};
}

std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::ConnectRequest(const ClientConnectContext &context,
                                 TraceCallback trace_cb,
                                 amf interrupt_flag) {
  if (IsInterrupted(interrupt_flag)) {
    return {{EC::Terminate, "Interrupted by user"}, nullptr};
  }

  HostConfig cfg = {};
  cfg.request = context.request;
  cfg.request.nickname = NormalizeNickname_(cfg.request.nickname);
  if (cfg.request.nickname.empty()) {
    cfg.request.nickname = "local";
  }
  if (cfg.request.keyfile.empty() && !context.private_keys.empty()) {
    cfg.request.keyfile = context.private_keys.front();
  }
  if (!cfg.request.password.empty() &&
      !AMAuth::IsEncrypted(cfg.request.password)) {
    cfg.request.password = AMAuth::EncryptPassword(cfg.request.password);
  }

  auto [create_rcm, client] = CreateClient(cfg);
  if (!isok(create_rcm) || !client) {
    return {create_rcm, nullptr};
  }
  if (trace_cb) {
    client->IOPort().RegisterTraceCallback(std::move(trace_cb));
  }

  auto connect_res = client->IOPort().Connect(
      AMDomain::filesystem::ConnectArgs{context.options.force},
      BuildControl_(interrupt_flag,
                    context.options.timeout_seconds > 0
                        ? context.options.timeout_seconds * 1000
                        : -1,
                    AMTime::miliseconds()));
  if (!isok(connect_res.rcm)) {
    return {connect_res.rcm, client};
  }

  if (context.options.register_to_manager) {
    ECM add_rcm = AddClient(client, true);
    if (!isok(add_rcm)) {
      return {add_rcm, client};
    }
  }

  return {{EC::Success, ""}, client};
}

std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::EnsureClient(const std::string &nickname,
                               amf interrupt_flag) {
  if (IsInterrupted(interrupt_flag)) {
    return {{EC::Terminate, "Interrupted by user"}, nullptr};
  }

  const std::string key = NormalizeNickname_(nickname);
  if (auto client = GetClient(key)) {
    const ClientState state =
        CheckClientInternal_(client, true, false, BuildControl_(interrupt_flag));
    return {state.rcm, client};
  }

  ClientConnectOptions options = {};
  options.force = false;
  options.quiet = true;
  options.register_to_manager = true;
  return ConnectNickname(key, options, {}, interrupt_flag);
}

std::pair<ClientAppService::ECM, ClientAppService::ClientHandle>
ClientAppService::CheckClient(const std::string &nickname, bool update,
                              amf interrupt_flag, int timeout_ms,
                              int64_t start_time) {
  if (IsInterrupted(interrupt_flag)) {
    return {{EC::Terminate, "Interrupted by user"}, nullptr};
  }

  ClientHandle client = GetClient(nickname);
  if (!client) {
    return {{EC::ClientNotFound,
             AMStr::fmt("Client not found: {}", NormalizeNickname_(nickname))},
            nullptr};
  }

  const ClientState state = CheckClientInternal_(
      client, false, update,
      BuildControl_(interrupt_flag, timeout_ms, start_time));
  return {state.rcm, client};
}

ClientAppService::ParsedClientPath
ClientAppService::ParseScopedPath(const std::string &input,
                                  amf interrupt_flag) {
  if (IsInterrupted(interrupt_flag)) {
    return {"", "", nullptr, {EC::Terminate, "Interrupted by user"}};
  }

  std::string nickname;
  std::string path;
  if (!input.empty() && input.front() == '@') {
    nickname = "local";
    path = input.substr(1);
  } else {
    const size_t at_pos = input.find('@');
    if (at_pos == std::string::npos) {
      nickname = GetCurrentNickname();
      path = input;
    } else {
      nickname = NormalizeNickname_(input.substr(0, at_pos));
      path = input.substr(at_pos + 1);
    }
  }

  if (nickname.empty()) {
    nickname = "local";
  }

  ClientHandle client = GetClient(nickname);
  if (client) {
    return {nickname, path, client, {EC::Success, ""}};
  }

  auto *host_config_manager = init_arg_.host_config_manager;
  if (!IsLocalNickname_(nickname) && host_config_manager &&
      !host_config_manager->HostExists(nickname)) {
    return {nickname, path, nullptr,
            {EC::HostConfigNotFound,
             AMStr::fmt("Host config not found: {}", nickname)}};
  }

  return {nickname, path, nullptr,
          {EC::ClientNotFound,
           AMStr::fmt("Client not created: {}", nickname)}};
}

std::string ClientAppService::ResolveClientPath(const std::string &path,
                                                const ClientHandle &client) const {
  return BuildAbsolutePath(client ? client : GetCurrentClient(), path);
}

ClientAppService::ClientWorkdirState
ClientAppService::GetWorkdirState(const std::string &nickname) const {
  const std::string key =
      NormalizeNickname_(nickname.empty() ? GetCurrentNickname() : nickname);
  std::lock_guard<std::mutex> lock(workdir_mtx_);
  auto it = workdir_states_.find(key);
  if (it == workdir_states_.end()) {
    return {};
  }
  return it->second;
}

ClientAppService::ECM
ClientAppService::SetWorkdirState(const std::string &nickname,
                                  const ClientWorkdirState &state) {
  const std::string key =
      NormalizeNickname_(nickname.empty() ? GetCurrentNickname() : nickname);
  std::lock_guard<std::mutex> lock(workdir_mtx_);
  workdir_states_[key] = NormalizeWorkdirState_(state);
  return {EC::Success, ""};
}

std::string ClientAppService::GetOrInitWorkdir(const ClientHandle &client) {
  if (!client) {
    return "";
  }

  const std::string key = NormalizeNickname_(client->ConfigPort().GetNickname());
  ClientWorkdirState state = GetWorkdirState(key);
  state.home_dir = AMPathStr::UnifyPathSep(client->ConfigPort().GetHomeDir(), "/");
  if (state.home_dir.empty()) {
    state.home_dir = state.login_dir;
  }
  if (state.login_dir.empty()) {
    state.login_dir = state.home_dir;
  }
  if (state.cwd.empty()) {
    state.cwd = state.login_dir;
  }
  state = NormalizeWorkdirState_(state);
  (void)SetWorkdirState(key, state);
  return state.cwd;
}

std::string ClientAppService::BuildAbsolutePath(const ClientHandle &client,
                                                const std::string &path) const {
  if (!client) {
    return path;
  }

  ClientWorkdirState state = GetWorkdirState(client->ConfigPort().GetNickname());
  state.home_dir = AMPathStr::UnifyPathSep(client->ConfigPort().GetHomeDir(), "/");
  if (state.home_dir.empty()) {
    state.home_dir = state.login_dir;
  }
  if (state.login_dir.empty()) {
    state.login_dir = state.home_dir;
  }
  if (state.cwd.empty()) {
    state.cwd = state.login_dir;
  }

  if (path.empty()) {
    return state.cwd;
  }
  return AMFS::abspath(path, true, state.home_dir, state.cwd, "/");
}

std::string ClientAppService::NormalizeNickname_(const std::string &nickname) {
  const std::string stripped = AMStr::Strip(nickname);
  if (IsLocalNickname_(stripped)) {
    return "local";
  }
  return stripped;
}

bool ClientAppService::IsLocalNickname_(const std::string &nickname) {
  return AMDomain::host::HostManagerService::IsLocalNickname(nickname);
}

ClientAppService::ClientStatus
ClientAppService::StatusFromEcm_(const ECM &rcm) {
  if (isok(rcm)) {
    return ClientStatus::OK;
  }
  if (rcm.first == EC::NotInitialized) {
    return ClientStatus::NotInitialized;
  }
  if (rcm.first == EC::NoConnection) {
    return ClientStatus::NoConnection;
  }
  return ClientStatus::ConnectionBroken;
}

ClientAppService::ClientWorkdirState
ClientAppService::NormalizeWorkdirState_(ClientWorkdirState state) {
  state.home_dir = AMPathStr::UnifyPathSep(state.home_dir, "/");
  state.login_dir = AMPathStr::UnifyPathSep(state.login_dir, "/");
  state.cwd = AMPathStr::UnifyPathSep(state.cwd, "/");
  return state;
}

ClientControlComponent
ClientAppService::BuildControl_(amf interrupt_flag, int timeout_ms,
                                int64_t start_time) const {
  AMDomain::client::amf token = interrupt_flag;
  {
    std::lock_guard<std::mutex> lock(registry_mtx_);
    if (!token) {
      token = init_arg_.control_token_port;
    }
  }
  return AMDomain::client::MakeClientControlComponent(std::move(token),
                                                       timeout_ms, start_time);
}

void ClientAppService::ApplyCallbacksToClient_(const ClientHandle &client,
                                               TraceCallback trace_override) {
  if (!client) {
    return;
  }

  TraceCallback trace = trace_override;
  AuthCallback auth = {};
  KnownHostCallback known_host = {};

  {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    if (!trace) {
      trace = trace_cb_;
    }
    auth = auth_cb_;
    known_host = known_host_cb_;
  }

  if (trace) {
    client->IOPort().RegisterTraceCallback(std::move(trace));
  }
  if (auth) {
    client->IOPort().RegisterAuthCallback(std::move(auth));
  }
  if (known_host) {
    client->IOPort().RegisterKnownHostCallback(std::move(known_host));
  }
}

ClientState ClientAppService::CheckClientInternal_(
    const ClientHandle &client, bool reconnect, bool update,
    const ClientControlComponent &control) const {
  if (!client) {
    return {ClientStatus::NotInitialized,
            {EC::InvalidHandle, "Client handle is null"}};
  }

  const auto persist_state = [&client](const ClientState &state) {
    client->ConfigPort().SetState(state);
    return state;
  };

  if (control.IsInterrupted()) {
    return persist_state(
        {StatusFromEcm_({EC::Terminate, "Interrupted by user"}),
         {EC::Terminate, "Interrupted by user"}});
  }
  if (control.IsTimeout()) {
    return persist_state(
        {StatusFromEcm_({EC::OperationTimeout, "Operation timed out"}),
         {EC::OperationTimeout, "Operation timed out"}});
  }

  if (!update) {
    const ClientState cached = client->ConfigPort().GetState();
    if (cached.status == ClientStatus::OK && isok(cached.rcm)) {
      return cached;
    }
    if (!reconnect) {
      return cached;
    }
  } else {
    const auto update_os = client->IOPort().UpdateOSType({}, control);
    ClientState state = {StatusFromEcm_(update_os.rcm), update_os.rcm};
    if (isok(state.rcm) || !reconnect) {
      return persist_state(state);
    }
  }

  const auto connect =
      client->IOPort().Connect(AMDomain::filesystem::ConnectArgs{true}, control);
  if (!isok(connect.rcm)) {
    return persist_state({StatusFromEcm_(connect.rcm), connect.rcm});
  }

  const auto refresh = client->IOPort().UpdateOSType({}, control);
  return persist_state({StatusFromEcm_(refresh.rcm), refresh.rcm});
}

} // namespace AMApplication::client
