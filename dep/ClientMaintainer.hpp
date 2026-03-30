#pragma once

#include "domain/client/ClientPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/time.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace AMApplication::client {
class ClientMaintainer {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using EC = ErrorCode;
  using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
  using DisconnectCallback =
      std::function<void(const ClientHandle &, const ECM &)>;

private:
  std::atomic<bool> running_ = false;
  std::thread heartbeat_thread_;
  mutable std::mutex mutex_;
  std::mutex heartbeat_wait_mutex_;
  std::condition_variable heartbeat_cv_;

  std::unordered_map<std::string, ClientHandle> hosts_;
  DisconnectCallback disconnect_cb_;

  /**
   * @brief Clamp heartbeat timeout to valid range in milliseconds.
   */
  static int ClampHeartbeatTimeoutMs_(int value) {
    if (value < 10) {
      return 10;
    }
    if (value > 10000) {
      return 10000;
    }
    return value;
  }

  /**
   * @brief Copy current hosts map under lock for lock-free checks.
   */
  std::unordered_map<std::string, ClientHandle> SnapshotHosts_() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return hosts_;
  }

  /**
   * @brief Return current disconnect callback snapshot under lock.
   */
  DisconnectCallback SnapshotDisconnectCallback_() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return disconnect_cb_;
  }

  /**
   * @brief Run periodic heartbeat checks until stop is requested.
   */
  void HeartbeatLoop_(int interval_s, int heartbeat_timeout_ms) {
    const auto wait_interval =
        std::chrono::milliseconds((std::max)(1, interval_s) * 1000);

    while (running_.load(std::memory_order_acquire)) {
      auto hosts = SnapshotHosts_();
      auto callback = SnapshotDisconnectCallback_();

      for (const auto &entry : hosts) {
        const auto &client = entry.second;
        if (!client) {
          continue;
        }
        ECM rcm = client->IOPort().Check({AMDomain::client::MakeClientIOControlArgs(
            nullptr, heartbeat_timeout_ms, AMTime::miliseconds())});
        if (rcm.first != EC::Success && callback) {
          (void)CallCallbackSafe(callback, client, rcm);
        }
      }

      std::unique_lock<std::mutex> wait_lock(heartbeat_wait_mutex_);
      if (heartbeat_cv_.wait_for(wait_lock, wait_interval, [this]() {
            return !running_.load(std::memory_order_acquire);
          })) {
        return;
      }
    }
  }

  /**
   * @brief Start heartbeat thread when interval is enabled.
   */
  void StartHeartbeat_(int heartbeat_interval_s, int heartbeat_timeout_ms) {
    if (heartbeat_interval_s < 0) {
      running_.store(false, std::memory_order_release);
      return;
    }

    running_.store(true, std::memory_order_release);
    heartbeat_thread_ =
        std::thread([this, heartbeat_interval_s, heartbeat_timeout_ms]() {
          HeartbeatLoop_(heartbeat_interval_s, heartbeat_timeout_ms);
        });
  }

  /**
   * @brief Stop heartbeat thread and wait for completion.
   */
  void StopHeartbeat_() {
    running_.store(false, std::memory_order_release);
    heartbeat_cv_.notify_all();
    if (heartbeat_thread_.joinable()) {
      heartbeat_thread_.join();
    }
  }

public:
  /**
   * @brief Construct maintainer with optional heartbeat and initial clients.
   */
  ClientMaintainer(int heartbeat_interval_s = 60,
                   int heartbeat_timeout_ms = 100,
                   DisconnectCallback disconnect_callback = {},
                   std::vector<ClientHandle> init_hosts = {}) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto &host : init_hosts) {
        if (host) {
          hosts_[host->ConfigPort().GetNickname()] = std::move(host);
        }
      }
      disconnect_cb_ = std::move(disconnect_callback);
    }

    const int clamped_timeout = ClampHeartbeatTimeoutMs_(heartbeat_timeout_ms);
    StartHeartbeat_(heartbeat_interval_s, clamped_timeout);
  }

  /**
   * @brief Destroy maintainer and stop heartbeat worker deterministically.
   */
  ~ClientMaintainer() { StopHeartbeat_(); }

  /**
   * @brief Get current host nicknames snapshot.
   */
  std::vector<std::string> GetNicknames() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> host_list;
    host_list.reserve(hosts_.size());
    for (const auto &entry : hosts_) {
      host_list.push_back(entry.first);
    }
    return host_list;
  }

  /**
   * @brief Get full hosts map snapshot.
   */
  std::unordered_map<std::string, ClientHandle> GetHostsSnapshot() const {
    return SnapshotHosts_();
  }

  /**
   * @brief Get one client by nickname.
   */
  ClientHandle GetClient(const std::string &nickname) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = hosts_.find(nickname);
    if (it == hosts_.end()) {
      return nullptr;
    }
    return it->second;
  }

  /**
   * @brief Get all clients when nickname filter is empty, otherwise return
   * matched clients.
   */
  std::vector<ClientHandle>
  GetClients(const std::vector<std::string> &nicknames = {}) const {
    std::vector<ClientHandle> result;
    std::lock_guard<std::mutex> lock(mutex_);

    if (nicknames.empty()) {
      result.reserve(hosts_.size());
      for (const auto &entry : hosts_) {
        if (entry.second) {
          result.push_back(entry.second);
        }
      }
      return result;
    }

    result.reserve(nicknames.size());
    for (const auto &nickname : nicknames) {
      const auto it = hosts_.find(nickname);
      if (it != hosts_.end() && it->second) {
        result.push_back(it->second);
      }
    }
    return result;
  }

  /**
   * @brief Add or overwrite one client by its configured nickname.
   */
  ECM AddClient(ClientHandle client, bool overwrite = false) {
    if (!client) {
      return {EC::InvalidHandle, "Client handle is null"};
    }

    const std::string nickname = client->ConfigPort().GetNickname();
    if (nickname.empty()) {
      return {EC::InvalidArg, "Client nickname is empty"};
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = hosts_.find(nickname);
    if (it != hosts_.end() && !overwrite) {
      return {EC::TargetAlreadyExists,
              "Client with this nickname already exists"};
    }
    hosts_[nickname] = std::move(client);
    return {EC::Success, ""};
  }

  /**
   * @brief Remove one client by nickname.
   */
  ECM RemoveClient(const std::string &nickname) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (hosts_.erase(nickname) == 0) {
      return {EC::ClientNotFound, "Client with this nickname not found"};
    }
    return {EC::Success, ""};
  }

  /**
   * @brief Set disconnect callback used by heartbeat failure events.
   */
  void SetDisconnectCallback(DisconnectCallback callback = {}) {
    std::lock_guard<std::mutex> lock(mutex_);
    disconnect_cb_ = std::move(callback);
  }
};
} // namespace AMApplication::client
