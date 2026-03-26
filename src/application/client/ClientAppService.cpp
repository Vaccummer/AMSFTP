#include "application/client/ClientAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/string.hpp"
#include <optional>

namespace AMApplication::client {
namespace {
using ClientStatus = AMDomain::client::ClientStatus;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using HostConfig = AMDomain::host::HostConfig;
using HostConfigManager = AMApplication::host::AMHostAppService;
using AMDomain::host::HostService::IsLocalNickname;

std::string JoinCandidates_(const std::vector<std::string> &candidates) {
  std::string out = {};
  for (size_t i = 0; i < candidates.size(); ++i) {
    if (i > 0) {
      out += ", ";
    }
    out += candidates[i];
  }
  return out;
}

ECMData<HostConfig>
ResolveHostConfig_(HostConfigManager *host_config_manager,
                   const std::string &nickname, bool case_sensitive) {
  if (!host_config_manager) {
    return {HostConfig{},
            Err(EC::InvalidHandle, "Host config manager is not bound")};
  }

  auto [cfg_rcm, cfg] = host_config_manager->GetClientConfig(nickname);
  if (isok(cfg_rcm) || case_sensitive) {
    return {cfg, cfg_rcm};
  }

  const std::string lowered = AMStr::lowercase(AMStr::Strip(nickname));
  std::vector<std::string> matched_names = {};
  for (const auto &name : host_config_manager->ListNames()) {
    if (AMStr::lowercase(AMStr::Strip(name)) == lowered) {
      matched_names.push_back(name);
    }
  }
  if (matched_names.empty()) {
    return {HostConfig{},
            Err(EC::ClientNotFound,
                AMStr::fmt("Host config not found: {}", nickname))};
  }
  if (matched_names.size() > 1) {
    return {HostConfig{},
            Err(EC::ClientNotFound,
                AMStr::fmt("Ambiguous host config nickname [{}], candidates: {}",
                           nickname, JoinCandidates_(matched_names)))};
  }
  auto [matched_rcm, matched_cfg] =
      host_config_manager->GetClientConfig(matched_names.front());
  return {matched_cfg, matched_rcm};
}
} // namespace

ClientAppService::ScopedConnectHooksGuard::ScopedConnectHooksGuard(
    ClientAppService *service, ConnectHooks hooks)
    : service_(service), previous_hooks_({}), active_(false) {
  if (!service_) {
    return;
  }
  std::lock_guard<std::mutex> lock(service_->connect_hooks_mutex_);
  previous_hooks_ = service_->connect_hooks_;
  service_->connect_hooks_ = std::move(hooks);
  active_ = true;
}

ClientAppService::ScopedConnectHooksGuard::ScopedConnectHooksGuard(
    ScopedConnectHooksGuard &&other) noexcept
    : service_(other.service_),
      previous_hooks_(std::move(other.previous_hooks_)),
      active_(other.active_) {
  other.service_ = nullptr;
  other.active_ = false;
}

ClientAppService::ScopedConnectHooksGuard &
ClientAppService::ScopedConnectHooksGuard::operator=(
    ScopedConnectHooksGuard &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  reset();
  service_ = other.service_;
  previous_hooks_ = std::move(other.previous_hooks_);
  active_ = other.active_;
  other.service_ = nullptr;
  other.active_ = false;
  return *this;
}

ClientAppService::ScopedConnectHooksGuard::~ScopedConnectHooksGuard() {
  reset();
}

void ClientAppService::ScopedConnectHooksGuard::reset() {
  if (!active_ || !service_) {
    return;
  }
  std::lock_guard<std::mutex> lock(service_->connect_hooks_mutex_);
  service_->connect_hooks_ = previous_hooks_;
  active_ = false;
  service_ = nullptr;
}

ClientAppService::ClientAppService() : ClientAppService(ClientServiceArg{}) {}

ClientAppService::ClientAppService(ClientServiceArg arg)
    : ClientAppServiceBase(std::move(arg)) {}

ClientAppService::~ClientAppService() = default;

ECM ClientAppService::Init(ClientHandle local_client) {
  const ClientServiceArg init_arg = GetInitArg();
  const ClientCallbacks public_callbacks = GetPublicCallbacks();
  this->maintainer_ = CreateClientMaintainer(init_arg.heartbeat_interval_s,
                                             init_arg.heartbeat_timeout_ms,
                                             public_callbacks.disconnect, {});
  if (local_client) {
    ECM add_local_rcm = AddClient(local_client, true);
    if (!add_local_rcm) {
      return add_local_rcm;
    }
    return {EC::Success, ""};
  }
  return {EC::InvalidArg, "Client handle is null"};
}

ECMData<ClientHandle> ClientAppService::GetClient(const std::string &nickname,
                                                  bool case_sensitive) const {
  if (IsLocalNickname(nickname)) {
    ClientHandle local = GetLocalClient();
    if (!local) {
      return {nullptr, Err(EC::ClientNotFound, "Local client not found")};
    }
    return {local, Ok()};
  }
  if (!maintainer_) {
    return {nullptr,
            Err(EC::InvalidHandle, "Client maintainer is not initialized")};
  }
  ClientHandle client = maintainer_->GetClient(nickname);
  if (client) {
    return {client, Ok()};
  }
  if (!case_sensitive) {
    const std::string lowered = AMStr::lowercase(AMStr::Strip(nickname));
    std::vector<std::string> matched_names = {};
    ClientHandle matched_client = nullptr;
    for (const auto &entry : maintainer_->GetAllClients()) {
      if (AMStr::lowercase(entry.first) != lowered) {
        continue;
      }
      matched_names.push_back(entry.first);
      matched_client = entry.second;
    }
    if (matched_names.size() == 1 && matched_client) {
      return {matched_client, Ok()};
    }
    if (matched_names.size() > 1) {
      return {nullptr,
              Err(EC::ClientNotFound,
                  AMStr::fmt("Ambiguous client nickname [{}], candidates: {}",
                             nickname, JoinCandidates_(matched_names)))};
    }
  }
  return {nullptr, Err(EC::ClientNotFound,
                       AMStr::fmt("Client not found: {}", nickname))};
}

ClientHandle ClientAppService::GetLocalClient() const {
  return runtime_clients_.lock()->local;
}

ClientHandle ClientAppService::GetCurrentClient() const {
  return runtime_clients_.lock()->current;
}

std::string ClientAppService::GetCurrentNickname() const {
  ClientHandle current = GetCurrentClient();
  if (!current) {
    return "";
  }
  return current->ConfigPort().GetNickname();
}

std::string ClientAppService::CurrentNickname() const {
  return GetCurrentNickname();
}

void ClientAppService::BindHostConfigManager(
    HostConfigManager *host_config_manager) {
  host_config_manager_ = host_config_manager;
}

ECMData<ClientHandle>
ClientAppService::CreateClient(const HostConfig &config,
                               const ClientControlComponent &control,
                               bool silent) {
  auto [callbacks, private_keys] = SnapshotCreateContext_(false);

  auto [create_rcm, client] = AMDomain::client::CreateClient(
      config.request, callbacks.known_host, callbacks.trace, callbacks.auth,
      private_keys);
  if (!isok(create_rcm) || !client) {
    return {nullptr, create_rcm};
  }
  ApplyCallbacksToClient_(client, callbacks);

  const ConnectHooks hooks = SnapshotConnectHooks_();
  if (hooks.before_connect) {
    (void)CallCallbackSafe(hooks.before_connect, config, client, silent);
  }
  auto connect_result =
      client->IOPort().Connect(AMDomain::filesystem::ConnectArgs{}, control);
  if (hooks.after_connect) {
    (void)CallCallbackSafe(hooks.after_connect, config, client, silent,
                           connect_result.rcm);
  }
  if (!isok(connect_result.rcm)) {
    return {nullptr, connect_result.rcm};
  }
  return {client, connect_result.rcm};
}

ECMData<ClientHandle>
ClientAppService::EnsureClient(const std::string &nickname, bool case_sensitive,
                               bool silent) {
  const ClientControlComponent control =
      GetControlComponent(std::nullopt, -1);
  return EnsureClient(nickname, control, case_sensitive, silent);
}

ECMData<ClientHandle> ClientAppService::EnsureClient(
    const std::string &nickname, const ClientControlComponent &control,
    bool case_sensitive, bool silent) {
  auto client_result = GetClient(nickname, case_sensitive);
  if (isok(client_result.rcm) && client_result.data) {
    return client_result;
  }
  if (client_result.rcm.first != EC::ClientNotFound) {
    return client_result;
  }

  auto config_result =
      ResolveHostConfig_(host_config_manager_, nickname, case_sensitive);
  if (!isok(config_result.rcm)) {
    return {nullptr, config_result.rcm};
  }

  auto create_result = CreateClient(config_result.data, control, silent);
  if (!isok(create_result.rcm) || !create_result.data) {
    return create_result;
  }

  ECM add_rcm = AddClient(create_result.data, false);
  if (isok(add_rcm)) {
    return {create_result.data, Ok()};
  }
  if (add_rcm.first == EC::TargetAlreadyExists) {
    auto existing =
        GetClient(create_result.data->ConfigPort().GetNickname(), true);
    if (isok(existing.rcm) && existing.data) {
      return existing;
    }
  }
  return {create_result.data, add_rcm};
}

ECMData<ClientHandle>
ClientAppService::ChangeClient(const std::string &nickname,
                               const ClientControlComponent &control,
                               bool silent) {
  const std::string current_nickname = GetCurrentNickname();
  if (!current_nickname.empty() && current_nickname == nickname) {
    ClientHandle current = GetCurrentClient();
    if (current) {
      return {current, Ok()};
    }
  }

  auto client_result = EnsureClient(nickname, control, false, silent);
  if (!isok(client_result.rcm) || !client_result.data) {
    return client_result;
  }
  SetCurrentClient(client_result.data);
  return {client_result.data, Ok()};
}

ECM ClientAppService::AddClient(ClientHandle client, bool overwrite) {
  if (!client) {
    return {EC::InvalidHandle, "Client handle is null"};
  }

  ApplyCallbacksToClient_(client, GetMaintainerCallbacks());
  const std::string nickname = client->ConfigPort().GetNickname();
  if (nickname.empty()) {
    return {EC::InvalidArg, "Client nickname is empty"};
  }

  if (IsLocalNickname(nickname)) {
    auto runtime_clients = runtime_clients_.lock();
    auto cache = runtime_clients.load();
    if (!cache.local || overwrite) {
      cache.local = client;
    }
    if (!cache.current ||
        IsLocalNickname(cache.current->ConfigPort().GetNickname()) ||
        overwrite) {
      cache.current = cache.local;
    }
    runtime_clients.store(cache);
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

  auto runtime_clients = runtime_clients_.lock();
  auto cache = runtime_clients.load();
  if (!cache.current) {
    cache.current = client;
    runtime_clients.store(cache);
  }
  return {EC::Success, ""};
}

std::optional<CheckResult> ClientAppService::CheckClient(
    const std::string &nickname, bool reconnect, bool update,
    const std::optional<ClientControlComponent> &control_component,
    int timeout_ms) {
  auto client_result = GetClient(nickname);
  if (!isok(client_result.rcm) || !client_result.data) {
    return std::nullopt;
  }
  const ClientControlComponent resolved_control =
      control_component ? *control_component
                        : GetControlComponent(std::nullopt, timeout_ms);
  return CheckClientInternal_(client_result.data, reconnect, update,
                              resolved_control);
}

std::map<std::string, ClientHandle> ClientAppService::GetClients() const {
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

ECM ClientAppService::RemoveClient(const std::string &nickname) {
  const std::string key = nickname;

  if (!maintainer_) {
    return {EC::InvalidHandle, "Client maintainer is not initialized"};
  }
  if (!maintainer_->RemoveClient(key)) {
    return {EC::ClientNotFound, AMStr::fmt("Client not found: {}", key)};
  }

  {
    auto public_clients = public_clients_.lock();
    public_clients->erase(key);
  }
  {
    auto runtime_clients = runtime_clients_.lock();
    auto cache = runtime_clients.load();
    if (cache.current && cache.current->ConfigPort().GetNickname() == key) {
      cache.current = cache.local;
      runtime_clients.store(cache);
    }
  }
  return {EC::Success, ""};
}

ECMData<ClientHandle>
ClientAppService::GetPublicClient(const std::string &nickname) {
  while (true) {
    ClientID candidate_id;
    ClientHandle candidate = nullptr;
    {
      auto public_clients = public_clients_.lock();
      auto bucket_it = public_clients->find(nickname);
      if (bucket_it == public_clients->end() || bucket_it->second.empty()) {
        return {nullptr,
                {EC::ClientNotFound,
                 AMStr::fmt("No public client found for {}", nickname)}};
      }
      auto it = bucket_it->second.begin();
      candidate_id = it->first;
      candidate = it->second;
    }

    if (!candidate) {
      auto public_clients = public_clients_.lock();
      auto bucket_it = public_clients->find(nickname);
      if (bucket_it != public_clients->end()) {
        bucket_it->second.erase(candidate_id);
        if (bucket_it->second.empty()) {
          public_clients->erase(bucket_it);
        }
      }
      continue;
    }

    auto state = candidate->ConfigPort().GetState();
    if (state.status == ClientStatus::OK && isok(state.rcm)) {
      return {candidate, state.rcm};
    }

    auto public_clients = public_clients_.lock();
    auto bucket_it = public_clients->find(nickname);
    if (bucket_it != public_clients->end()) {
      bucket_it->second.erase(candidate_id);
      if (bucket_it->second.empty()) {
        public_clients->erase(bucket_it);
      }
    }
  }
}

ECM ClientAppService::AddPublicClient(const ClientHandle &client) {
  if (!client) {
    return {EC::InvalidHandle, "Client handle is null"};
  }
  const std::string nickname = client->ConfigPort().GetNickname();
  const ClientID id = client->GetUID();
  if (nickname.empty()) {
    return {EC::InvalidArg, "Client nickname is empty"};
  }
  if (id.empty()) {
    return {EC::InvalidArg, "Client UID is empty"};
  }

  ApplyCallbacksToClient_(client, GetPublicCallbacks());

  auto public_clients = public_clients_.lock();
  (*public_clients)[nickname][id] = client;
  return {EC::Success, ""};
}

ClientAppService::ScopedConnectHooksGuard
ClientAppService::UseScopedConnectHooks(ConnectHooks hooks) {
  return {this, std::move(hooks)};
}

void ClientAppService::SetCurrentClient(const ClientHandle &client) {
  runtime_clients_.lock()->current = client;
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

void ClientAppService::ApplyCallbacksToClient_(const ClientHandle &client,
                                               const ClientCallbacks &callbacks,
                                               TraceCallback trace_override) {
  if (!client) {
    return;
  }

  TraceCallback trace =
      trace_override ? std::move(trace_override) : callbacks.trace;
  AuthCallback auth = callbacks.auth;
  KnownHostCallback known_host = callbacks.known_host;

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

std::pair<ClientAppService::ClientCallbacks, std::vector<std::string>>
ClientAppService::SnapshotCreateContext_(bool for_public_pool) const {
  ClientCallbacks callbacks =
      for_public_pool ? GetPublicCallbacks() : GetMaintainerCallbacks();
  std::vector<std::string> private_keys = GetPrivateKeys();
  return {std::move(callbacks), std::move(private_keys)};
}

ClientAppService::ConnectHooks ClientAppService::SnapshotConnectHooks_() const {
  std::lock_guard<std::mutex> lock(connect_hooks_mutex_);
  return connect_hooks_;
}

CheckResult ClientAppService::CheckClientInternal_(
    const ClientHandle &client, bool reconnect, bool update,
    const ClientControlComponent &control) const {
  CheckResult result;
  if (!client) {
    result.status = ClientStatus::NullHandle;
    result.rcm = {EC::InvalidHandle, "Client handle is null"};
    return result;
  }
  if (!update) {
    const CheckResult cached = client->ConfigPort().GetState();
    if (cached.status == ClientStatus::OK && isok(cached.rcm)) {
      return cached;
    }
    if (!reconnect) {
      return cached;
    }
  } else {
    auto state = client->IOPort().Check({}, control);
    if (isok(state.rcm) || !reconnect) {
      return state;
    }
  }

  client->IOPort().Connect(AMDomain::filesystem::ConnectArgs{true}, control);
  return client->ConfigPort().GetState();
}

} // namespace AMApplication::client
