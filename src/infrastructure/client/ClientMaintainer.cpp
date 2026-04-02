#include "infrastructure/client/maintainer/ClientMaintainer.hpp"
#include "domain/client/ClientDomainService.hpp"
#include "foundation/tools/string.hpp"

#include <chrono>
#include <string>
#include <utility>
#include <vector>

namespace AMInfra::client::maintainer {
namespace {
using ClientHandle = AMDomain::client::ClientHandle;
using ClientName = AMDomain::client::ClientName;
using DisconnectCallback = AMDomain::client::DisconnectCallback;

[[nodiscard]] ClientName NormalizeClientName(const ClientName &name) {
  const std::string normalized = AMStr::Strip(name);
  const std::string lower = AMStr::lowercase(normalized);
  return (lower.empty() || lower == "local") ? "local" : normalized;
}

[[nodiscard]] int ClampHeartbeatInterval(int interval_s) {
  return static_cast<int>(
      AMDomain::client::MaintainerService::ClampHeartbeatIntervalS(interval_s));
}

[[nodiscard]] int ClampCheckTimeout(int timeout_ms) {
  return static_cast<int>(
      AMDomain::client::MaintainerService::ClampHeartbeatTimeoutMs(timeout_ms));
}

[[nodiscard]] std::map<ClientName, ClientHandle>
SnapshotClients(AMAtomic<std::map<ClientName, ClientHandle>> &clients) {
  auto lock = clients.lock();
  return lock.load();
}

[[nodiscard]] DisconnectCallback
SnapshotDisconnectCallback(AMAtomic<DisconnectCallback> &disconnect_cb) {
  auto lock = disconnect_cb.lock();
  return lock.load();
}

[[nodiscard]] ECM CheckClientNow(const ClientHandle &client, int timeout_ms) {
  if (!client) {
    return {EC::InvalidHandle, "Client handle is null"};
  }
  return client->IOPort()
      .Check({}, AMDomain::client::ClientControlComponent(nullptr, timeout_ms))
      .rcm;
}
} // namespace

ClientMaintainer::ClientMaintainer(int heartbeat_interval_s,
                                   int check_timeout_ms,
                                   DisconnectCallback disconnect_callback,
                                   std::vector<ClientHandle> init_clients)
    : clients_(std::map<ClientName, ClientHandle>{}),
      disconnect_cb_(std::move(disconnect_callback)),
      heartbeat_interval_s_(ClampHeartbeatInterval(heartbeat_interval_s)),
      check_timeout_ms_(ClampCheckTimeout(check_timeout_ms)) {
  (void)AddClients(init_clients, true);
}

ClientMaintainer::~ClientMaintainer() { TerminateHeartbeat(); }

ClientMaintainer::ClientHandle
ClientMaintainer::GetClient(const ClientName &name) {
  const ClientName normalized = NormalizeClientName(name);
  auto clients = clients_.lock();
  auto it = clients->find(normalized);
  return it == clients->end() ? nullptr : it->second;
}

ECM ClientMaintainer::CheckClient(const ClientName &name) {
  const ClientName normalized = NormalizeClientName(name);
  auto client = GetClient(normalized);
  if (!client) {
    return {EC::ClientNotFound, "Client not found: " + normalized};
  }
  return CheckClientNow(client,
                        check_timeout_ms_.load(std::memory_order_acquire));
}

std::map<ClientMaintainer::ClientName, ClientMaintainer::ClientHandle>
ClientMaintainer::GetAllClients() {
  return SnapshotClients(clients_);
}

bool ClientMaintainer::RemoveClient(const ClientName &name) {
  const ClientName normalized = NormalizeClientName(name);
  auto clients = clients_.lock();
  return clients->erase(normalized) > 0;
}

void ClientMaintainer::RemoveDisconnectedClients() {
  const auto clients_snapshot = SnapshotClients(clients_);
  const auto callback = SnapshotDisconnectCallback(disconnect_cb_);
  const int timeout_ms = check_timeout_ms_.load(std::memory_order_acquire);
  std::vector<ClientName> to_remove = {};
  to_remove.reserve(clients_snapshot.size());

  for (const auto &entry : clients_snapshot) {
    const ECM check_rcm = CheckClientNow(entry.second, timeout_ms);
    if (check_rcm.code == EC::Success) {
      continue;
    }
    to_remove.push_back(entry.first);
    if (callback) {
      (void)CallCallbackSafe(callback, entry.second, check_rcm);
    }
  }

  if (to_remove.empty()) {
    return;
  }

  auto clients = clients_.lock();
  for (const auto &name : to_remove) {
    clients->erase(name);
  }
}

void ClientMaintainer::RemoveAllClients() {
  auto clients = clients_.lock();
  clients->clear();
}

bool ClientMaintainer::AddClient(ClientHandle client, bool overwrite) {
  if (!client) {
    return false;
  }
  const std::string raw_name = AMStr::Strip(client->ConfigPort().GetNickname());
  if (raw_name.empty()) {
    return false;
  }
  const ClientName normalized = NormalizeClientName(raw_name);

  auto clients = clients_.lock();
  auto it = clients->find(normalized);
  if (it != clients->end() && !overwrite) {
    return false;
  }
  (*clients)[normalized] = std::move(client);
  return true;
}

std::vector<bool>
ClientMaintainer::AddClients(const std::vector<ClientHandle> &clients,
                             bool overwrite) {
  std::vector<bool> result = {};
  result.reserve(clients.size());
  for (const auto &client : clients) {
    result.push_back(AddClient(client, overwrite));
  }
  return result;
}

void ClientMaintainer::SetHeartbeatInterval(int interval_s) {
  heartbeat_interval_s_.store(ClampHeartbeatInterval(interval_s),
                              std::memory_order_release);
  heartbeat_cv_.notify_all();
}

void ClientMaintainer::SetCheckTimeout(int timeout_ms) {
  check_timeout_ms_.store(ClampCheckTimeout(timeout_ms),
                          std::memory_order_release);
}

void ClientMaintainer::SetDisconnectCallback(DisconnectCallback callback) {
  auto cb = disconnect_cb_.lock();
  cb.store(std::move(callback));
}

bool ClientMaintainer::IsHeartbeatRunning() const {
  return heartbeat_state_.load(std::memory_order_acquire) ==
         HeartbeatState::Running;
}

void ClientMaintainer::TerminateHeartbeat() {
  std::lock_guard<std::mutex> thread_lock(heartbeat_thread_mtx_);
  heartbeat_state_.store(HeartbeatState::Terminated, std::memory_order_release);
  heartbeat_cv_.notify_all();
  if (heartbeat_thread_.joinable()) {
    heartbeat_thread_.join();
  }
}

void ClientMaintainer::PauseHeartbeat() {
  HeartbeatState expected = HeartbeatState::Running;
  (void)heartbeat_state_.compare_exchange_strong(
      expected, HeartbeatState::Paused, std::memory_order_acq_rel);
  heartbeat_cv_.notify_all();
}

void ClientMaintainer::StartHeartbeat() {
  std::lock_guard<std::mutex> thread_lock(heartbeat_thread_mtx_);
  const HeartbeatState state = heartbeat_state_.load(std::memory_order_acquire);
  if (state == HeartbeatState::Running) {
    return;
  }
  if (state == HeartbeatState::Paused) {
    heartbeat_state_.store(HeartbeatState::Running, std::memory_order_release);
    heartbeat_cv_.notify_all();
    return;
  }
  if (heartbeat_thread_.joinable()) {
    heartbeat_thread_.join();
  }
  heartbeat_state_.store(HeartbeatState::Running, std::memory_order_release);
  heartbeat_thread_ = std::thread([this]() { HeartbeatLoop_(); });
}

void ClientMaintainer::HeartbeatLoop_() {
  while (true) {
    const HeartbeatState state =
        heartbeat_state_.load(std::memory_order_acquire);
    if (state == HeartbeatState::Terminated) {
      return;
    }
    if (state == HeartbeatState::Paused) {
      std::unique_lock<std::mutex> wait_lock(heartbeat_wait_mtx_);
      (void)heartbeat_cv_.wait(wait_lock, [this]() {
        const HeartbeatState s =
            heartbeat_state_.load(std::memory_order_acquire);
        return s != HeartbeatState::Paused;
      });
      continue;
    }
    if (state != HeartbeatState::Running) {
      return;
    }

    const auto clients_snapshot = SnapshotClients(clients_);
    const auto callback = SnapshotDisconnectCallback(disconnect_cb_);
    const int timeout_ms = check_timeout_ms_.load(std::memory_order_acquire);
    for (const auto &entry : clients_snapshot) {
      if (heartbeat_state_.load(std::memory_order_acquire) !=
          HeartbeatState::Running) {
        break;
      }
      const ECM check_rcm = CheckClientNow(entry.second, timeout_ms);
      if (check_rcm.code != EC::Success && callback) {
        (void)CallCallbackSafe(callback, entry.second, check_rcm);
      }
    }

    const int interval_s = ClampHeartbeatInterval(
        heartbeat_interval_s_.load(std::memory_order_acquire));
    std::unique_lock<std::mutex> wait_lock(heartbeat_wait_mtx_);
    (void)heartbeat_cv_.wait_for(
        wait_lock, std::chrono::seconds(interval_s), [this]() {
          return heartbeat_state_.load(std::memory_order_acquire) !=
                 HeartbeatState::Running;
        });
  }
}
} // namespace AMInfra::client::maintainer

namespace AMDomain::client {
std::unique_ptr<IClientMaintainerPort>
CreateClientMaintainer(int heartbeat_interval_s, int check_timeout_ms,
                       DisconnectCallback disconnect_callback,
                       std::vector<ClientHandle> init_clients) {
  return std::make_unique<AMInfra::client::maintainer::ClientMaintainer>(
      heartbeat_interval_s, check_timeout_ms, std::move(disconnect_callback),
      std::move(init_clients));
}
} // namespace AMDomain::client
