#include "application/client/ClientAppServiceBase.hpp"

#include "foundation/tools/string.hpp"

namespace AMApplication::client {
ClientAppServiceBase::ClientAppServiceBase(ClientServiceArg arg)
    : AMApplication::config::IConfigSyncPort(typeid(ClientServiceArg)),
      init_arg_(std::move(arg)), control_token_(nullptr),
      private_keys_(std::vector<std::string>{}),
      maintainer_callbacks_(ClientCallbacks{}),
      public_callbacks_(ClientCallbacks{}), runtime_clients_(RuntimeClientCache{}),
      public_clients_(ClientContainer{}) {}

ClientServiceArg ClientAppServiceBase::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM ClientAppServiceBase::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (config_service == nullptr) {
    return {EC::InvalidArg, "", "", "config service is null"};
  }
  if (!config_service->Write<ClientServiceArg>(GetInitArg())) {
    return {EC::ConfigDumpFailed, "", "", "failed to flush client config"};
  }
  return OK;
}

void ClientAppServiceBase::SetHeartbeatTimeoutMs(int timeout_ms) {
  auto init_arg = init_arg_.lock();
  auto value = init_arg.load();
  value.heartbeat_timeout_ms = timeout_ms;
  init_arg.store(value);
  MarkConfigDirty();
}

int ClientAppServiceBase::HeartbeatTimeoutMs() const {
  return init_arg_.lock().load().heartbeat_timeout_ms;
}

void ClientAppServiceBase::SetHeartbeatIntervalS(int interval_s) {
  auto init_arg = init_arg_.lock();
  auto value = init_arg.load();
  value.heartbeat_interval_s = interval_s;
  init_arg.store(value);
  MarkConfigDirty();
}

int ClientAppServiceBase::HeartbeatIntervalS() const {
  return init_arg_.lock().load().heartbeat_interval_s;
}

void ClientAppServiceBase::RegisterControlComponent(amf control_token) {
  control_token_.lock().store(std::move(control_token));
}

ControlComponent
ClientAppServiceBase::GetControlComponent(std::optional<amf> control_token,
                                          int timeout_ms) const {
  amf token = control_token ? *control_token : control_token_.lock().load();
  if (timeout_ms > 0) {
    return {token, timeout_ms};
  }
  return {token, 0};
}

void ClientAppServiceBase::SetPrivateKeys(
    std::vector<std::string> private_keys) {
  private_keys_.lock().store(std::move(private_keys));
}

std::vector<std::string> ClientAppServiceBase::GetPrivateKeys() const {
  return private_keys_.lock().load();
}

void ClientAppServiceBase::RegisterMaintainerCallbacks(
    std::optional<DisconnectCallback> disconnect_cb,
    std::optional<TraceCallback> trace_cb,
    std::optional<ConnectStateCallback> connect_state_cb,
    std::optional<KnownHostCallback> known_host_cb,
    std::optional<AuthCallback> auth_cb) {
  auto callbacks = maintainer_callbacks_.lock();
  auto value = callbacks.load();
  if (disconnect_cb.has_value()) {
    value.disconnect = std::move(*disconnect_cb);
  }
  if (trace_cb.has_value()) {
    value.trace = std::move(*trace_cb);
  }
  if (connect_state_cb.has_value()) {
    value.connect_state = std::move(*connect_state_cb);
  }
  if (known_host_cb.has_value()) {
    value.known_host = std::move(*known_host_cb);
  }
  if (auth_cb.has_value()) {
    value.auth = std::move(*auth_cb);
  }
  callbacks.store(std::move(value));
}

void ClientAppServiceBase::RegisterPublicCallbacks(
    std::optional<DisconnectCallback> disconnect_cb,
    std::optional<TraceCallback> trace_cb,
    std::optional<ConnectStateCallback> connect_state_cb,
    std::optional<KnownHostCallback> known_host_cb,
    std::optional<AuthCallback> auth_cb) {
  auto callbacks = public_callbacks_.lock();
  auto value = callbacks.load();
  if (disconnect_cb.has_value()) {
    value.disconnect = std::move(*disconnect_cb);
  }
  if (trace_cb.has_value()) {
    value.trace = std::move(*trace_cb);
  }
  if (connect_state_cb.has_value()) {
    value.connect_state = std::move(*connect_state_cb);
  }
  if (known_host_cb.has_value()) {
    value.known_host = std::move(*known_host_cb);
  }
  if (auth_cb.has_value()) {
    value.auth = std::move(*auth_cb);
  }
  callbacks.store(std::move(value));
}

ClientAppServiceBase::ClientCallbacks
ClientAppServiceBase::GetMaintainerCallbacks() const {
  return maintainer_callbacks_.lock().load();
}

ClientAppServiceBase::ClientCallbacks
ClientAppServiceBase::GetPublicCallbacks() const {
  return public_callbacks_.lock().load();
}

ClientHandle ClientAppServiceBase::GetLocalClient() const {
  return runtime_clients_.lock()->local;
}

ClientHandle ClientAppServiceBase::GetCurrentClient() const {
  return runtime_clients_.lock()->current;
}

std::string ClientAppServiceBase::GetCurrentNickname() const {
  ClientHandle current = GetCurrentClient();
  if (!current) {
    ClientHandle local = GetLocalClient();
    if (!local) {
      return "local";
    }
    const std::string local_nickname =
        AMStr::Strip(local->ConfigPort().GetNickname());
    return local_nickname.empty() ? std::string("local") : local_nickname;
  }
  const std::string current_nickname =
      AMStr::Strip(current->ConfigPort().GetNickname());
  if (!current_nickname.empty()) {
    return current_nickname;
  }
  ClientHandle local = GetLocalClient();
  if (!local) {
    return "local";
  }
  const std::string local_nickname =
      AMStr::Strip(local->ConfigPort().GetNickname());
  return local_nickname.empty() ? std::string("local") : local_nickname;
}

std::string ClientAppServiceBase::CurrentNickname() const {
  return GetCurrentNickname();
}

void ClientAppServiceBase::SetCurrentClient(const ClientHandle &client) {
  runtime_clients_.lock()->current = client;
}

std::vector<ClientAppServiceBase::PublicClientInstance>
ClientAppServiceBase::ListPublicClients(
    const std::vector<std::string> &nicknames, bool case_sensitive) const {
  std::vector<PublicClientInstance> out = {};
  std::vector<std::string> filters = {};
  filters.reserve(nicknames.size());
  for (const auto &nickname : nicknames) {
    const std::string stripped = AMStr::Strip(nickname);
    if (!stripped.empty()) {
      filters.push_back(stripped);
    }
  }

  auto public_clients = public_clients_.lock();
  for (const auto &bucket : *public_clients) {
    bool selected = filters.empty();
    for (const auto &target : filters) {
      if (AMStr::Equals(bucket.first, target, case_sensitive)) {
        selected = true;
        break;
      }
    }
    if (!selected) {
      continue;
    }
    for (const auto &entry : bucket.second) {
      out.push_back(PublicClientInstance{bucket.first, entry.first,
                                         entry.second});
    }
  }
  return out;
}

std::vector<std::string> ClientAppServiceBase::GetPublicClientNames() const {
  std::vector<std::string> out = {};
  auto public_clients = public_clients_.lock();
  out.reserve(public_clients->size());
  for (const auto &entry : *public_clients) {
    out.push_back(entry.first);
  }
  return out;
}

void ClientAppServiceBase::SetLocalClient_(const ClientHandle &client,
                                           bool update_current) {
  auto runtime_clients = runtime_clients_.lock();
  auto cache = runtime_clients.load();
  cache.local = client;
  if (update_current) {
    cache.current = client;
  }
  runtime_clients.store(cache);
}

bool ClientAppServiceBase::SetCurrentClientIfEmpty_(const ClientHandle &client) {
  auto runtime_clients = runtime_clients_.lock();
  auto cache = runtime_clients.load();
  if (cache.current) {
    return false;
  }
  cache.current = client;
  runtime_clients.store(cache);
  return true;
}

std::optional<std::string>
ClientAppServiceBase::ResolvePublicBucketKey_(const std::string &nickname,
                                              bool case_sensitive) const {
  const std::string target = AMStr::Strip(nickname);
  if (target.empty()) {
    return std::nullopt;
  }

  auto public_clients = public_clients_.lock();
  auto direct_it = public_clients->find(target);
  if (direct_it != public_clients->end()) {
    return direct_it->first;
  }
  if (case_sensitive) {
    return std::nullopt;
  }
  for (const auto &entry : *public_clients) {
    if (AMStr::Equals(entry.first, target, false)) {
      return entry.first;
    }
  }
  return std::nullopt;
}

std::vector<std::pair<ClientID, ClientHandle>>
ClientAppServiceBase::SnapshotPublicBucket_(const std::string &nickname) const {
  std::vector<std::pair<ClientID, ClientHandle>> out = {};
  auto public_clients = public_clients_.lock();
  auto bucket_it = public_clients->find(nickname);
  if (bucket_it == public_clients->end()) {
    return out;
  }
  out.reserve(bucket_it->second.size());
  for (const auto &entry : bucket_it->second) {
    out.push_back(entry);
  }
  return out;
}

void ClientAppServiceBase::UpsertPublicClient_(const std::string &nickname,
                                               const ClientID &id,
                                               const ClientHandle &client) {
  auto public_clients = public_clients_.lock();
  (*public_clients)[nickname][id] = client;
}

bool ClientAppServiceBase::ErasePublicClient_(const std::string &nickname,
                                              const ClientID &id) {
  auto public_clients = public_clients_.lock();
  auto bucket_it = public_clients->find(nickname);
  if (bucket_it == public_clients->end()) {
    return false;
  }
  if (bucket_it->second.erase(id) == 0) {
    return false;
  }
  if (bucket_it->second.empty()) {
    public_clients->erase(bucket_it);
  }
  return true;
}

void ClientAppServiceBase::ErasePublicBucket_(const std::string &nickname) {
  auto public_clients = public_clients_.lock();
  public_clients->erase(nickname);
}
} // namespace AMApplication::client
