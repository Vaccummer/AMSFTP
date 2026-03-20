#pragma once

#include "domain/client/ClientPort.hpp"
#include "foundation/core/DataClass.hpp"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

namespace AMInfra::client::maintainer {
class ClientMaintainer final : public AMDomain::client::IClientMaintainerPort,
                               private NonCopyableNonMovable {
public:
  using ClientHandle = AMDomain::client::ClientHandle;
  using ClientName = AMDomain::client::ClientName;
  using ECM = AMDomain::client::ECM;
  using EC = AMDomain::client::EC;
  using DisconnectCallback =
      std::function<void(const ClientHandle &, const ECM &)>;

private:
  enum class HeartbeatState : int {
    Stopped = 0,
    Running = 1,
    Paused = 2,
    Terminated = 3,
  };

  AMAtomic<std::map<ClientName, ClientHandle>> clients_;
  AMAtomic<DisconnectCallback> disconnect_cb_;

  std::mutex heartbeat_wait_mtx_;
  std::condition_variable heartbeat_cv_;

  std::mutex heartbeat_thread_mtx_;
  std::thread heartbeat_thread_;

  std::atomic<HeartbeatState> heartbeat_state_{HeartbeatState::Stopped};
  std::atomic<int> heartbeat_interval_s_{60};
  std::atomic<int> check_timeout_ms_{100};

  void HeartbeatLoop_();

public:
  ClientMaintainer(int heartbeat_interval_s = 60, int check_timeout_ms = 100,
                   DisconnectCallback disconnect_callback = {},
                   std::vector<ClientHandle> init_clients = {});

  ~ClientMaintainer() override;

  ClientHandle GetClient(const ClientName &name) override;

  ECM CheckClient(const ClientName &name) override;

  std::map<ClientName, ClientHandle> GetAllClients() override;

  bool RemoveClient(const ClientName &name) override;

  void RemoveDisconnectedClients() override;

  void RemoveAllClients() override;

  bool AddClient(ClientHandle client, bool overwrite) override;

  std::vector<bool> AddClients(const std::vector<ClientHandle> &clients,
                               bool overwrite) override;

  void SetHeartbeatInterval(int interval_s) override;

  void SetCheckTimeout(int timeout_ms) override;

  void SetDisconnectCallback(DisconnectCallback callback) override;

  [[nodiscard]] bool IsHeartbeatRunning() const override;

  void TerminateHeartbeat() override;

  void PauseHeartbeat() override;

  void StartHeartbeat() override;
};
} // namespace AMInfra::client::maintainer
