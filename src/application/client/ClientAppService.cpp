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
using AMDomain::host::HostService::IsLocalNickname;

} // namespace

ClientAppService::ClientAppService() : ClientAppService(ClientServiceArg{}) {}

ClientAppService::ClientAppService(ClientServiceArg arg)
    : ClientAppServiceBase(std::move(arg)) {}

ClientAppService::~ClientAppService() = default;

ECM ClientAppService::Init(ClientHandle local_client) {
  const ClientServiceArg init_arg = GetInitArg();
  const ClientCallbacks public_callbacks = GetPublicCallbacks();
  this->maintainer_ =
      CreateClientMaintainer(init_arg.heartbeat_interval_s,
                             init_arg.heartbeat_timeout_ms,
                             public_callbacks.disconnect, {});
  if (local_client) {
    ECM add_local_rcm = AddClient(local_client, true);
    if (!isok(add_local_rcm)) {
      return add_local_rcm;
    }
    return {EC::Success, ""};
  }
  return {EC::InvalidArg, "Client handle is null"};
}

ClientHandle ClientAppService::GetClient(const std::string &nickname) const {
  if (!maintainer_) {
    return nullptr;
  }
  return maintainer_->GetClient(nickname);
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

std::pair<ECM, ClientHandle>
ClientAppService::CreateClient(const HostConfig &config) {
  auto [callbacks, private_keys] = SnapshotCreateContext_(false);

  auto [create_rcm, client] = AMDomain::client::CreateClient(
      config.request, callbacks.known_host, callbacks.trace, callbacks.auth,
      private_keys);
  if (!isok(create_rcm) || !client) {
    return {create_rcm, nullptr};
  }
  ApplyCallbacksToClient_(client, callbacks);
  return {create_rcm, client};
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
  ClientHandle client = GetClient(nickname);
  if (!client) {
    return std::nullopt;
  }
  return CheckClientInternal_(client, reconnect, update,
                              ResolveControl(control_component, timeout_ms));
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

std::pair<ECM, ClientHandle>
ClientAppService::GetPublicClient(const std::string &nickname) {
  const std::string key = nickname;

  while (true) {
    ClientID candidate_id;
    ClientHandle candidate = nullptr;
    {
      auto public_clients = public_clients_.lock();
      auto bucket_it = public_clients->find(key);
      if (bucket_it == public_clients->end() || bucket_it->second.empty()) {
        return {{EC::ClientNotFound,
                 AMStr::fmt("No public client found for {}", key)},
                nullptr};
      }
      auto it = bucket_it->second.begin();
      candidate_id = it->first;
      candidate = it->second;
    }

    if (!candidate) {
      auto public_clients = public_clients_.lock();
      auto bucket_it = public_clients->find(key);
      if (bucket_it != public_clients->end()) {
        bucket_it->second.erase(candidate_id);
        if (bucket_it->second.empty()) {
          public_clients->erase(bucket_it);
        }
      }
      continue;
    }

    auto state = CheckClientInternal_(candidate, false, true,
                                      ResolveControl(std::nullopt));
    if (state.status == ClientStatus::OK && isok(state.rcm)) {
      return {state.rcm, candidate};
    }

    auto public_clients = public_clients_.lock();
    auto bucket_it = public_clients->find(key);
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

void ClientAppService::SetCurrentClient(const ClientHandle &client) {
  auto runtime_clients = runtime_clients_.lock();
  auto cache = runtime_clients.load();
  cache.current = client ? client : cache.local;
  runtime_clients.store(cache);
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
