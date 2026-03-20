#include "ClientPublicPool.hpp"

#include "domain/client/ClientDomainService.hpp"
#include "domain/host/HostDomainService.hpp"

#include <algorithm>
#include <shared_mutex>
#include <unordered_set>
#include <utility>

namespace AMApplication::client {
namespace {
using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;
using ClientHandle = AMDomain::client::ClientHandle;
}

/**
 * @brief Construct pool with optional client creation callback.
 */
ClientPublicPool::ClientPublicPool(CreateClientFn create_client)
    : create_client_(std::move(create_client)) {}

/**
 * @brief Replace the client creation callback used for pool misses.
 */
void ClientPublicPool::SetCreateClientFn(CreateClientFn create_client) {
  std::lock_guard<std::mutex> lock(mutex_);
  create_client_ = std::move(create_client);
}

/**
 * @brief Normalize one nickname to the canonical pool key.
 */
std::string ClientPublicPool::CanonicalNickname_(const std::string &nickname) {
  if (AMDomain::host::HostManagerService::IsLocalNickname(nickname)) {
    return "local";
  }
  return AMDomain::client::ClientDomainService::NormalizeNickname(nickname);
}

/**
 * @brief Read current lease state from one client metadata store.
 */
ClientPublicPool::ClientLeaseState ClientPublicPool::ReadLeaseStateLocked_(
    const AMDomain::client::IClientMetaDataPort &metadata) {
  bool exists = false;
  const std::any *payload = metadata.QueryNamedData(kLeaseDataName_, exists);
  if (!exists || !payload) {
    return {};
  }
  const auto *state = std::any_cast<ClientLeaseState>(payload);
  return state ? *state : ClientLeaseState{};
}

/**
 * @brief Write lease state into one client metadata store.
 */
void ClientPublicPool::WriteLeaseStateLocked_(
    AMDomain::client::IClientMetaDataPort &metadata,
    const ClientLeaseState &state) {
  bool exists = false;
  std::any *payload = metadata.QueryNamedData(kLeaseDataName_, exists);
  if (exists && payload) {
    if (auto *stored = std::any_cast<ClientLeaseState>(payload)) {
      *stored = state;
      return;
    }
  }
  (void)metadata.StoreNamedData(kLeaseDataName_, std::any(state), true);
}

/**
 * @brief Append one client into the task lease table when missing.
 */
void ClientPublicPool::TrackTaskLeaseLocked_(const std::string &task_id,
                                             const ClientHandle &client) {
  if (task_id.empty() || !client) {
    return;
  }
  auto &leases = task_leases_[task_id];
  if (std::find(leases.begin(), leases.end(), client) == leases.end()) {
    leases.push_back(client);
  }
}

/**
 * @brief Remove one client from the task lease table when present.
 */
void ClientPublicPool::EraseTaskLeaseLocked_(const std::string &task_id,
                                             const ClientHandle &client) {
  if (task_id.empty() || !client) {
    return;
  }
  auto it = task_leases_.find(task_id);
  if (it == task_leases_.end()) {
    return;
  }
  auto &leases = it->second;
  leases.erase(std::remove(leases.begin(), leases.end(), client), leases.end());
  if (leases.empty()) {
    task_leases_.erase(it);
  }
}

/**
 * @brief Remove one client instance from the nickname bucket.
 */
void ClientPublicPool::RemoveClientLocked_(const std::string &nickname,
                                           const ClientHandle &client) {
  auto bucket_it = clients_.find(nickname);
  if (bucket_it == clients_.end()) {
    return;
  }
  auto &bucket = bucket_it->second;
  bucket.remove(client);
  if (bucket.empty()) {
    clients_.erase(bucket_it);
  }
}

/**
 * @brief Try to reuse one pooled client from an existing nickname bucket.
 */
std::pair<ECM, ClientHandle> ClientPublicPool::TryAcquireExistingLocked_(
    const std::string &task_id, const std::string &nickname, int timeout_ms,
    int64_t start_time) {
  auto bucket_it = clients_.find(nickname);
  if (bucket_it == clients_.end()) {
    return {ECM{EC::Success, ""}, nullptr};
  }

  auto &bucket = bucket_it->second;
  for (auto it = bucket.begin(); it != bucket.end();) {
    const ClientHandle client = *it;
    if (!client) {
      it = bucket.erase(it);
      continue;
    }

    auto &metadata = client->MetaDataPort();
    std::unique_lock<std::shared_mutex> metadata_lock(metadata.Mutex());
    ClientLeaseState lease = ReadLeaseStateLocked_(metadata);
    if (lease.in_use && lease.owner_task_id != task_id) {
      ++it;
      continue;
    }
    lease.in_use = true;
    lease.owner_task_id = task_id;
    WriteLeaseStateLocked_(metadata, lease);
    metadata_lock.unlock();

    ECM check_rcm = client->IOPort().Check(
        {AMDomain::client::MakeClientIOControlArgs(nullptr, timeout_ms,
                                                   start_time)});
    if (check_rcm.first == EC::Success) {
      TrackTaskLeaseLocked_(task_id, client);
      return {ECM{EC::Success, ""}, client};
    }

    metadata_lock.lock();
    WriteLeaseStateLocked_(metadata, ClientLeaseState{});
    metadata_lock.unlock();
    EraseTaskLeaseLocked_(task_id, client);
    it = bucket.erase(it);
  }

  if (bucket.empty()) {
    clients_.erase(bucket_it);
  }
  return {ECM{EC::Success, ""}, nullptr};
}

/**
 * @brief Acquire one transfer client for a task and nickname.
 */
std::pair<ECM, ClientHandle> ClientPublicPool::AcquireClient(
    const std::string &task_id, const std::string &nickname, int timeout_ms,
    int64_t start_time, bool force_new_instance) {
  if (task_id.empty()) {
    return {ECM{EC::InvalidArg, "Task id is empty"}, nullptr};
  }
  const std::string key = CanonicalNickname_(nickname);
  if (key.empty()) {
    return {ECM{EC::InvalidArg, "Client nickname is empty"}, nullptr};
  }

  if (!force_new_instance) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto [reuse_rcm, reused] =
        TryAcquireExistingLocked_(task_id, key, timeout_ms, start_time);
    if (reuse_rcm.first != EC::Success || reused) {
      return {reuse_rcm, reused};
    }
  }

  CreateClientFn create_client;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    create_client = create_client_;
  }
  if (!create_client) {
    return {ECM{EC::InvalidHandle, "Transfer client create callback is not set"},
            nullptr};
  }

  auto [create_rcm, created] = create_client(key, timeout_ms, start_time);
  if (create_rcm.first != EC::Success || !created) {
    return {create_rcm, nullptr};
  }

  ECM check_rcm = created->IOPort().Check(
      {AMDomain::client::MakeClientIOControlArgs(nullptr, timeout_ms,
                                                 start_time)});
  if (check_rcm.first != EC::Success) {
    return {check_rcm, nullptr};
  }

  std::lock_guard<std::mutex> lock(mutex_);
  clients_[key].push_back(created);
  auto &metadata = created->MetaDataPort();
  std::unique_lock<std::shared_mutex> metadata_lock(metadata.Mutex());
  WriteLeaseStateLocked_(metadata,
                         ClientLeaseState{true, task_id});
  metadata_lock.unlock();
  TrackTaskLeaseLocked_(task_id, created);
  return {ECM{EC::Success, ""}, created};
}

/**
 * @brief Acquire all distinct clients required by one task.
 */
std::pair<ECM, std::unordered_map<std::string, ClientHandle>>
ClientPublicPool::AcquireClients(const std::string &task_id,
                                 const std::vector<std::string> &nicknames,
                                 int timeout_ms, int64_t start_time) {
  std::unordered_map<std::string, ClientHandle> result;
  std::unordered_set<std::string> seen;
  for (const auto &nickname : nicknames) {
    const std::string key = CanonicalNickname_(nickname);
    if (key.empty() || !seen.insert(key).second) {
      continue;
    }
    auto [rcm, client] = AcquireClient(task_id, key, timeout_ms, start_time);
    if (rcm.first != EC::Success || !client) {
      ReleaseTask(task_id);
      return {rcm, {}};
    }
    result.emplace(key, client);
  }
  return {ECM{EC::Success, ""}, result};
}

/**
 * @brief Release all leased clients owned by one task.
 */
void ClientPublicPool::ReleaseTask(const std::string &task_id) {
  if (task_id.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto it = task_leases_.find(task_id);
  if (it == task_leases_.end()) {
    return;
  }
  std::vector<ClientHandle> leases = std::move(it->second);
  task_leases_.erase(it);

  for (const auto &client : leases) {
    if (!client) {
      continue;
    }
    auto &metadata = client->MetaDataPort();
    std::unique_lock<std::shared_mutex> metadata_lock(metadata.Mutex());
    ClientLeaseState lease = ReadLeaseStateLocked_(metadata);
    if (lease.owner_task_id == task_id) {
      WriteLeaseStateLocked_(metadata, ClientLeaseState{});
    }
    metadata_lock.unlock();
  }
}
} // namespace AMApplication::client
