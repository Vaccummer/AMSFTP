#include "application/client/ClientAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include <optional>

namespace AMApplication::client {
namespace {
using ClientStatus = AMDomain::client::ClientStatus;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using HostConfig = AMDomain::host::HostConfig;
using HostConfigManager = AMApplication::host::HostAppService;
using AMDomain::host::HostService::IsLocalNickname;
constexpr const char *kTransferLeaseKey = "transfer.lease";
constexpr const char *kTerminalLeaseKey = "terminal.lease";

[[nodiscard]] ECM QueryLeaseFlag_(const ClientHandle &client, const char *key,
                                  bool *value) {
  if (!client) {
    return Err(EC::InvalidHandle, "query_client_lease", "<client>",
               "Client handle is null");
  }
  if (value == nullptr) {
    return Err(EC::InvalidArg, "query_client_lease", "<client>",
               "Lease output is null");
  }

  bool found = false;
  bool type_mismatch = false;
  bool current = false;
  client->MetaDataPort().MutateNamedValue<bool>(
      key, [&](bool *stored, bool name_found, bool type_match) {
        if (!name_found) {
          return;
        }
        found = true;
        if (!type_match || !stored) {
          type_mismatch = true;
          return;
        }
        current = *stored;
      });
  if (type_mismatch) {
    return Err(EC::CommonFailure, "query_client_lease", key,
               AMStr::fmt("{} metadata type is invalid", key));
  }
  *value = found ? current : false;
  return OK;
}

[[nodiscard]] ECM StoreLeaseFlag_(const ClientHandle &client, const char *key,
                                  bool value, const char *operation) {
  if (!client) {
    return Err(EC::InvalidHandle, operation, "<client>",
               "Client handle is null");
  }
  if (client->MetaDataPort().StoreNamedData(key, std::any(value), true)) {
    return OK;
  }
  return Err(EC::CommonFailure, operation, "<client>",
             AMStr::fmt("{} metadata type is invalid", key));
}

[[nodiscard]] ECM ReconcileTerminalLease_(const ClientHandle &client) {
  if (!client) {
    return Err(EC::InvalidHandle, "reconcile_terminal_lease", "<client>",
               "Client handle is null");
  }

  bool active = false;
  const ECM query_rcm = QueryLeaseFlag_(client, kTerminalLeaseKey, &active);
  if (!(query_rcm) || !active) {
    return query_rcm;
  }

  const auto state = client->ConfigPort().GetState();
  if (state.data.status == ClientStatus::OK) {
    return OK;
  }
  return StoreLeaseFlag_(client, kTerminalLeaseKey, false,
                         "reconcile_terminal_lease");
}

ECMData<HostConfig> ResolveHostConfig_(HostConfigManager *host_config_manager,
                                       const std::string &nickname,
                                       bool case_sensitive) {
  if (!host_config_manager) {
    return {HostConfig{},
            Err(EC::InvalidHandle, "resolve_host_config", "<host_service>",
                "Host config manager is not bound")};
  }

  auto cfg_result =
      host_config_manager->GetClientConfig(nickname, case_sensitive);
  if (cfg_result) {
    return cfg_result;
  }
  return {HostConfig{}, Err(EC::ClientNotFound, "resolve_host_config", nickname,
                            "Host config not found")};
}

ECM AcquireTransferLease_(const ClientHandle &client) {
  if (!client) {
    return Err(EC::InvalidHandle, "acquire_transfer_lease", "<client>",
               "Client handle is null");
  }

  const ECM reconcile_rcm = ReconcileTerminalLease_(client);
  if (!(reconcile_rcm)) {
    return reconcile_rcm;
  }
  bool terminal_active = false;
  const ECM terminal_query_rcm =
      QueryLeaseFlag_(client, kTerminalLeaseKey, &terminal_active);
  if (!(terminal_query_rcm)) {
    return terminal_query_rcm;
  }
  if (terminal_active) {
    return Err(EC::PathUsingByOthers, "acquire_transfer_lease", "<client>",
               "Client terminal is active");
  }

  auto &meta = client->MetaDataPort();
  bool lease_acquired = false;
  bool lease_missing = false;
  bool type_mismatch = false;

  meta.MutateNamedValue<bool>(
      kTransferLeaseKey, [&](bool *leased, bool name_found, bool type_match) {
        if (!name_found) {
          lease_missing = true;
          return;
        }
        if (!type_match || !leased) {
          type_mismatch = true;
          return;
        }
        if (!*leased) {
          *leased = true;
          lease_acquired = true;
        }
      });

  if (type_mismatch) {
    if (meta.StoreNamedData(kTransferLeaseKey, std::any(true), true)) {
      return OK;
    }
    return Err(EC::CommonFailure, "acquire_transfer_lease", "<client>",
               "transfer.lease metadata type is invalid");
  }
  if (lease_acquired) {
    return OK;
  }

  if (lease_missing) {
    if (meta.StoreNamedData(kTransferLeaseKey, std::any(true), false)) {
      return OK;
    }
    bool retry_acquired = false;
    bool retry_type_mismatch = false;
    meta.MutateNamedValue<bool>(
        kTransferLeaseKey, [&](bool *leased, bool name_found, bool type_match) {
          if (!name_found) {
            return;
          }
          if (!type_match || !leased) {
            retry_type_mismatch = true;
            return;
          }
          if (!*leased) {
            *leased = true;
            retry_acquired = true;
          }
        });
    if (retry_type_mismatch) {
      return Err(EC::CommonFailure, "acquire_transfer_lease", "<client>",
                 "transfer.lease metadata type is invalid");
    }
    if (retry_acquired) {
      return OK;
    }
  }

  return Err(EC::PathUsingByOthers, "acquire_transfer_lease", "<client>",
             "Client is already leased");
}

ECM AcquireTerminalLease_(const ClientHandle &client) {
  if (!client) {
    return Err(EC::InvalidHandle, "acquire_terminal_lease", "<client>",
               "Client handle is null");
  }

  auto &meta = client->MetaDataPort();
  const ECM reconcile_rcm = ReconcileTerminalLease_(client);
  if (!(reconcile_rcm)) {
    return reconcile_rcm;
  }

  bool transfer_active = false;
  const ECM transfer_query_rcm =
      QueryLeaseFlag_(client, kTransferLeaseKey, &transfer_active);
  if (!(transfer_query_rcm)) {
    return transfer_query_rcm;
  }
  if (transfer_active) {
    return Err(EC::PathUsingByOthers, "acquire_terminal_lease", "<client>",
               "Client is already leased");
  }

  bool terminal_acquired = false;
  bool lease_missing = false;
  bool type_mismatch = false;
  meta.MutateNamedValue<bool>(
      kTerminalLeaseKey, [&](bool *leased, bool name_found, bool type_match) {
        if (!name_found) {
          lease_missing = true;
          return;
        }
        if (!type_match || !leased) {
          type_mismatch = true;
          return;
        }
        if (!*leased) {
          *leased = true;
        }
        terminal_acquired = true;
      });

  if (type_mismatch) {
    return StoreLeaseFlag_(client, kTerminalLeaseKey, true,
                           "acquire_terminal_lease");
  }
  if (terminal_acquired) {
    return OK;
  }

  if (lease_missing) {
    if (meta.StoreNamedData(kTerminalLeaseKey, std::any(true), false)) {
      return OK;
    }
    bool retry_type_mismatch = false;
    bool retry_acquired = false;
    meta.MutateNamedValue<bool>(kTerminalLeaseKey,
                                [&](bool *leased, bool name_found,
                                    bool type_match) {
                                  if (!name_found) {
                                    return;
                                  }
                                  if (!type_match || !leased) {
                                    retry_type_mismatch = true;
                                    return;
                                  }
                                  if (!*leased) {
                                    *leased = true;
                                  }
                                  retry_acquired = true;
                                });
    if (retry_type_mismatch) {
      return Err(EC::CommonFailure, "acquire_terminal_lease", "<client>",
                 "terminal.lease metadata type is invalid");
    }
    if (retry_acquired) {
      return OK;
    }
  }

  return OK;
}
} // namespace

ClientAppService::ClientAppService(ClientServiceArg arg)
    : ClientAppServiceBase(std::move(arg)) {}

ClientAppService::~ClientAppService() = default;

ECM ClientAppService::Init(ClientHandle local_client) {
  const ClientServiceArg init_arg = GetInitArg();
  const ClientCallbacks public_callbacks = GetPublicCallbacks();
  this->maintainer_ = CreateClientMaintainer(init_arg.heartbeat_interval_s,
                                             init_arg.heartbeat_timeout_ms,
                                             public_callbacks.disconnect, {});
  if (!maintainer_) {
    return {EC::InvalidHandle, "ClientAppService::Init", "maintainer",
            "Client maintainer is nullptr"};
  }
  this->maintainer_->StartHeartbeat();
  if (local_client) {
    ECM add_local_rcm = AddClient(local_client, true);
    if (!add_local_rcm) {
      return add_local_rcm;
    }
    return OK;
  }
  return {EC::InvalidArg, "ClientAppService::Init", "local_client",
          "Local Client handle is null"};
}

ECMData<ClientHandle> ClientAppService::GetClient(const std::string &nickname,
                                                  bool case_sensitive) const {
  if (IsLocalNickname(nickname)) {
    ClientHandle local = GetLocalClient();
    if (!local) {
      return {nullptr, Err(EC::ClientNotFound, "get_client", "local",
                           "Local client not found")};
    }
    return {local, OK};
  }
  if (!maintainer_) {
    return {nullptr, Err(EC::InvalidHandle, "get_client", nickname,
                         "Client maintainer is not initialized")};
  }
  ClientHandle client = maintainer_->GetClient(nickname);
  if (client) {
    return {client, OK};
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
      return {matched_client, OK};
    }
    if (matched_names.size() > 1) {
      return {nullptr, Err(EC::ClientNotFound, "get_client", nickname,
                           AMStr::fmt("Ambiguous nickname, candidates: {}",
                                      AMStr::join(matched_names, ", ")))};
    }
  }
  return {nullptr,
          Err(EC::ClientNotFound, "get_client", nickname, "Client not found")};
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

std::string ClientAppService::CurrentNickname() const {
  return GetCurrentNickname();
}

void ClientAppService::RegisterMaintainerCallbacks(
    std::optional<DisconnectCallback> disconnect_cb,
    std::optional<TraceCallback> trace_cb,
    std::optional<ConnectStateCallback> connect_state_cb,
    std::optional<KnownHostCallback> known_host_cb,
    std::optional<AuthCallback> auth_cb) {
  ClientAppServiceBase::RegisterMaintainerCallbacks(disconnect_cb, trace_cb,
                                                    connect_state_cb,
                                                    known_host_cb, auth_cb);
  if (maintainer_ && disconnect_cb.has_value()) {
    maintainer_->SetDisconnectCallback(*disconnect_cb);
  }
}

void ClientAppService::RegisterPublicCallbacks(
    std::optional<DisconnectCallback> disconnect_cb,
    std::optional<TraceCallback> trace_cb,
    std::optional<ConnectStateCallback> connect_state_cb,
    std::optional<KnownHostCallback> known_host_cb,
    std::optional<AuthCallback> auth_cb) {
  ClientAppServiceBase::RegisterPublicCallbacks(disconnect_cb, trace_cb,
                                                connect_state_cb,
                                                known_host_cb, auth_cb);
  if (maintainer_ && disconnect_cb.has_value()) {
    maintainer_->SetDisconnectCallback(*disconnect_cb);
  }
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
  if (!(create_rcm)) {
    return {nullptr, create_rcm};
  }
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, __func__, "",
                         "CreateClient returned null client")};
  }
  ApplyCallbacksToClient_(client, callbacks);

  (void)client->MetaDataPort().StoreTypedValue(config.metadata, true);

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
  if (!connect_result.rcm) {
    return {nullptr, connect_result.rcm};
  }

  return {client, connect_result.rcm};
}

ECMData<ClientHandle>
ClientAppService::EnsureClient(const std::string &nickname, bool case_sensitive,
                               bool silent) {
  const ClientControlComponent control = GetControlComponent(std::nullopt, -1);
  return EnsureClient(nickname, control, case_sensitive, silent);
}

ECMData<ClientHandle>
ClientAppService::EnsureClient(const std::string &nickname,
                               const ClientControlComponent &control,
                               bool case_sensitive, bool silent) {
  auto client_result = GetClient(nickname, case_sensitive);
  if ((client_result.rcm) && client_result.data) {
    return client_result;
  }
  if (client_result.rcm.code != EC::ClientNotFound) {
    return client_result;
  }

  auto config_result =
      ResolveHostConfig_(host_config_manager_, nickname, case_sensitive);
  if (!(config_result.rcm)) {
    return {nullptr, config_result.rcm};
  }

  auto create_result = CreateClient(config_result.data, control, silent);
  if (!(create_result.rcm) || !create_result.data) {
    return create_result;
  }

  ECM add_rcm = AddClient(create_result.data, false);
  if ((add_rcm)) {
    return {create_result.data, OK};
  }
  if (add_rcm.code == EC::TargetAlreadyExists) {
    auto existing =
        GetClient(create_result.data->ConfigPort().GetNickname(), true);
    if ((existing.rcm) && existing.data) {
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
      return {current, OK};
    }
  }

  auto client_result = EnsureClient(nickname, control, false, silent);
  if (!(client_result.rcm) || !client_result.data) {
    return client_result;
  }
  SetCurrentClient(client_result.data);
  return {client_result.data, OK};
}

ECM ClientAppService::AddClient(ClientHandle client, bool overwrite) {
  if (!client) {
    return {EC::InvalidHandle, "add_client", "<client>",
            "Client handle is null"};
  }

  ApplyCallbacksToClient_(client, GetMaintainerCallbacks());
  const std::string nickname = client->ConfigPort().GetNickname();
  if (nickname.empty()) {
    return {EC::InvalidArg, "add_client", "<empty>",
            "Client nickname is empty"};
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
    return OK;
  }

  if (!maintainer_) {
    return {EC::InvalidHandle, "add_client", nickname,
            "Client maintainer is not initialized"};
  }
  const bool added = maintainer_->AddClient(client, overwrite);
  if (!added) {
    return {EC::TargetAlreadyExists, "add_client", nickname,
            "Client already exists"};
  }

  auto runtime_clients = runtime_clients_.lock();
  auto cache = runtime_clients.load();
  if (!cache.current) {
    cache.current = client;
    runtime_clients.store(cache);
  }
  return OK;
}

std::optional<ECMData<CheckResult>> ClientAppService::CheckClient(
    const std::string &nickname, bool reconnect, bool update,
    const std::optional<ClientControlComponent> &control_component,
    int timeout_ms) {
  auto client_result = GetClient(nickname);
  if (!(client_result.rcm) || !client_result.data) {
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
    return {EC::InvalidHandle, "remove_client", key,
            "Client maintainer is not initialized"};
  }
  if (!maintainer_->RemoveClient(key)) {
    return {EC::ClientNotFound, "remove_client", key, "Client not found"};
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
  return OK;
}

ECMData<ClientHandle>
ClientAppService::GetPublicClient(const std::string &nickname) {
  std::vector<std::pair<ClientID, ClientHandle>> candidates = {};
  {
    auto public_clients = public_clients_.lock();
    auto bucket_it = public_clients->find(nickname);
    if (bucket_it == public_clients->end() || bucket_it->second.empty()) {
      return {nullptr,
              {EC::ClientNotFound, "get_public_client", nickname,
               "No public client found"}};
    }
    candidates.reserve(bucket_it->second.size());
    for (const auto &entry : bucket_it->second) {
      candidates.push_back(entry);
    }
  }

  std::vector<ClientID> stale_ids = {};
  bool has_leased_client = false;
  ECM status = OK;
  for (const auto &[candidate_id, candidate] : candidates) {
    if (!candidate) {
      stale_ids.push_back(candidate_id);
      continue;
    }

    const ECM lease_rcm = AcquireTransferLease_(candidate);
    if ((lease_rcm)) {
      candidate->TaskControlPort().ClearInterrupt();
      auto check_result =
          candidate->IOPort().Check({}, ClientControlComponent(nullptr, 2000));
      if (!(check_result.rcm)) {
        (void)TryReturnClient(candidate);
        stale_ids.push_back(candidate_id);
        status = check_result.rcm;
        continue;
      }
      auto managed_result = GetClient(nickname, true);
      if ((managed_result.rcm) && managed_result.data &&
          managed_result.data != candidate) {
        auto metadata_opt = GetClientMetadata(managed_result.data);
        if (metadata_opt.has_value()) {
          const ECM sync_rcm = SetClientMetadata(candidate, *metadata_opt);
          if (!(sync_rcm)) {
            (void)TryReturnClient(candidate);
            return {nullptr, sync_rcm};
          }
        }
      }
      return {candidate, OK};
    }
    if (lease_rcm.code == EC::PathUsingByOthers) {
      has_leased_client = true;
      if ((status)) {
        status = lease_rcm;
      }
      continue;
    }
    status = lease_rcm;
  }

  if (!stale_ids.empty()) {
    auto public_clients = public_clients_.lock();
    auto bucket_it = public_clients->find(nickname);
    if (bucket_it != public_clients->end()) {
      for (const auto &id : stale_ids) {
        bucket_it->second.erase(id);
      }
      if (bucket_it->second.empty()) {
        public_clients->erase(bucket_it);
      }
    }
  }

  if (has_leased_client) {
    if (!(status)) {
      return {nullptr, status};
    }
    return {nullptr, Err(EC::PathUsingByOthers, "get_public_client", nickname,
                         "All public clients are leased")};
  }
  if (!(status)) {
    return {nullptr, status};
  }
  return {nullptr, Err(EC::ClientNotFound, "get_public_client", nickname,
                       "No public client found")};
}

ECM ClientAppService::AddPublicClient(const ClientHandle &client) {
  if (!client) {
    return {EC::InvalidHandle, "add_public_client", "<client>",
            "Client handle is null"};
  }
  const std::string nickname = client->ConfigPort().GetNickname();
  const ClientID id = client->GetUID();
  if (nickname.empty()) {
    return {EC::InvalidArg, "add_public_client", "<empty>",
            "Client nickname is empty"};
  }
  if (id.empty()) {
    return {EC::InvalidArg, "add_public_client", nickname,
            "Client UID is empty"};
  }

  auto managed_result = GetClient(nickname, true);
  if ((managed_result.rcm) && managed_result.data &&
      managed_result.data != client) {
    auto metadata_opt = GetClientMetadata(managed_result.data);
    if (metadata_opt.has_value()) {
      const ECM sync_rcm = SetClientMetadata(client, *metadata_opt);
      if (!(sync_rcm)) {
        return sync_rcm;
      }
    }
  }

  ApplyCallbacksToClient_(client, GetPublicCallbacks());

  auto public_clients = public_clients_.lock();
  (*public_clients)[nickname][id] = client;
  return OK;
}

void ClientAppService::SetConnectHooks(ConnectHooks hooks) {
  std::lock_guard<std::mutex> lock(connect_hooks_mutex_);
  connect_hooks_ = std::move(hooks);
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

std::optional<ClientMetaData>
ClientAppService::GetClientMetadata(const ClientHandle &client) {
  if (!client) {
    return std::nullopt;
  }
  return client->MetaDataPort().QueryTypedValue<ClientMetaData>();
}

ECM ClientAppService::SetClientMetadata(const ClientHandle &client,
                                        const ClientMetaData &metadata) {
  if (!client) {
    return {EC::InvalidHandle, "set_client_metadata", "<client>",
            "Client handle is null"};
  }
  const bool ok = client->MetaDataPort().StoreTypedValue(metadata, true);
  if (!ok) {
    return {EC::CommonFailure, "set_client_metadata", "<client>",
            "Failed to store client metadata"};
  }
  return OK;
}

ECMData<std::string>
ClientAppService::GetClientCwd(const ClientHandle &client) {
  if (!client) {
    return {"",
            {EC::InvalidHandle, "get_client_cwd", "<client>",
             "Client handle is null"}};
  }
  auto meta_opt = GetClientMetadata(client);
  if (!meta_opt.has_value()) {
    return {"", Err(EC::CommonFailure, "get_client_cwd", "<client>",
                    "Client metadata not found")};
  }
  return {meta_opt->cwd, OK};
}

ECM ClientAppService::SetClientCwd(const ClientHandle &client,
                                   const std::string &cwd) {
  if (!client) {
    return Err(EC::InvalidHandle, "set_client_cwd", "<client>",
               "Client handle is null");
  }
  bool updated = false;
  client->MetaDataPort().MutateTypeValue<ClientMetaData>(
      [&](ClientMetaData *meta) {
        if (!meta) {
          return;
        }
        meta->cwd = cwd;
        updated = true;
      });
  if (updated) {
    return OK;
  }

  ClientMetaData meta = {};
  meta.cwd = cwd;
  return SetClientMetadata(client, meta);
}

ECM ClientAppService::TryLeaseClient(const ClientHandle &client) {
  return AcquireTransferLease_(client);
}

ECM ClientAppService::TryReturnClient(const ClientHandle &client) {
  if (!client) {
    return Err(EC::InvalidHandle, "release_transfer_lease", "<client>",
               "Client handle is null");
  }
  auto &meta = client->MetaDataPort();
  bool released = false;
  bool lease_missing = false;
  bool type_mismatch = false;

  meta.MutateNamedValue<bool>(
      kTransferLeaseKey, [&](bool *leased, bool name_found, bool type_match) {
        if (!name_found) {
          lease_missing = true;
          return;
        }
        if (!type_match || !leased) {
          type_mismatch = true;
          return;
        }
        *leased = false;
        released = true;
      });

  if (type_mismatch) {
    if (meta.StoreNamedData(kTransferLeaseKey, std::any(false), true)) {
      return OK;
    }
    return Err(EC::CommonFailure, "release_transfer_lease", "<client>",
               "transfer.lease metadata type is invalid");
  }
  if (released || lease_missing) {
    return OK;
  }
  return OK;
}

ECM ClientAppService::TryActivateTerminal(const ClientHandle &client) {
  return AcquireTerminalLease_(client);
}

ECM ClientAppService::TryDeactivateTerminal(const ClientHandle &client) {
  return StoreLeaseFlag_(client, kTerminalLeaseKey, false,
                         "release_terminal_lease");
}

ECM ClientAppService::EnsureTerminalInactive(const ClientHandle &client,
                                             const std::string &operation) {
  if (!client) {
    return Err(EC::InvalidHandle,
               operation.empty() ? "terminal_guard" : operation, "<client>",
               "Client handle is null");
  }

  const ECM reconcile_rcm = ReconcileTerminalLease_(client);
  if (!(reconcile_rcm)) {
    return reconcile_rcm;
  }

  bool active = false;
  const ECM query_rcm = QueryLeaseFlag_(client, kTerminalLeaseKey, &active);
  if (!(query_rcm)) {
    return query_rcm;
  }
  if (!active) {
    return OK;
  }

  const std::string target = AMStr::Strip(client->ConfigPort().GetNickname());
  return Err(EC::PathUsingByOthers,
             operation.empty() ? "terminal_guard" : operation,
             target.empty() ? std::string("<client>") : target,
             "Client terminal is active");
}

void ClientAppService::ApplyCallbacksToClient_(const ClientHandle &client,
                                               const ClientCallbacks &callbacks,
                                               TraceCallback trace_override) {
  if (!client) {
    return;
  }

  TraceCallback trace =
      trace_override ? std::move(trace_override) : callbacks.trace;
  ConnectStateCallback connect_state = callbacks.connect_state;
  AuthCallback auth = callbacks.auth;
  KnownHostCallback known_host = callbacks.known_host;

  if (trace) {
    client->IOPort().RegisterTraceCallback(trace);
  }
  if (connect_state) {
    client->IOPort().RegisterConnectStateCallback(connect_state);
  }
  if (auth) {
    client->IOPort().RegisterAuthCallback(auth);
  }
  if (known_host) {
    client->IOPort().RegisterKnownHostCallback(known_host);
  }

  auto *terminal_port = client->TerminalPort();
  if (!terminal_port) {
    return;
  }
  if (trace) {
    terminal_port->RegisterTraceCallback(trace);
  }
  if (connect_state) {
    terminal_port->RegisterConnectStateCallback(connect_state);
  }
  if (auth) {
    terminal_port->RegisterAuthCallback(auth);
  }
  if (known_host) {
    terminal_port->RegisterKnownHostCallback(known_host);
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

ECMData<CheckResult> ClientAppService::CheckClientInternal_(
    const ClientHandle &client, bool reconnect, bool update,
    const ClientControlComponent &control) const {
  ECMData<CheckResult> result = {};
  if (!client) {
    result.data.status = ClientStatus::NullHandle;
    result.rcm = {EC::InvalidHandle, "check_client", "<client>",
                  "Client handle is null"};
    return result;
  }
  if (!update) {
    const auto cached = client->ConfigPort().GetState();
    if (cached.data.status == ClientStatus::OK && (cached.rcm)) {
      return cached;
    }
    if (!reconnect) {
      return cached;
    }
  } else {
    auto state = client->IOPort().Check({}, control);
    if ((state.rcm) || !reconnect) {
      return state;
    }
  }

  client->IOPort().Connect(AMDomain::filesystem::ConnectArgs{true}, control);
  return client->ConfigPort().GetState();
}

} // namespace AMApplication::client
