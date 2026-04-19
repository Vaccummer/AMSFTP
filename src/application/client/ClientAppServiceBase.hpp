#pragma once

#include "application/config/ConfigAppService.hpp"
#include "domain/client/ClientPort.hpp"

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace AMApplication::client {
using ClientServiceArg = AMDomain::client::ClientServiceArg;
using amf = AMDomain::client::amf;
using TraceCallback = AMDomain::client::TraceCallback;
using ConnectStateCallback = AMDomain::client::ConnectStateCallback;
using AuthCallback = AMDomain::client::AuthCallback;
using KnownHostCallback = AMDomain::client::KnownHostCallback;
using ClientHandle = AMDomain::client::ClientHandle;
using ClientID = AMDomain::client::ClientID;
using DisconnectCallback =
    std::function<void(const AMDomain::client::ClientHandle &, const ECM &)>;
using PublicClientBucket = std::map<ClientID, ClientHandle>;
using ClientContainer = std::map<std::string, PublicClientBucket>;

class ClientAppServiceBase : public AMApplication::config::IConfigSyncPort {
public:
  struct RuntimeClientCache {
    ClientHandle local = nullptr;
    ClientHandle current = nullptr;
  };

  struct PublicClientInstance {
    std::string nickname = {};
    ClientID id = {};
    ClientHandle client = nullptr;
  };

  struct ClientCallbacks {
    DisconnectCallback disconnect = {};
    TraceCallback trace = {};
    ConnectStateCallback connect_state = {};
    AuthCallback auth = {};
    KnownHostCallback known_host = {};
  };

  explicit ClientAppServiceBase(ClientServiceArg arg = {});
  ~ClientAppServiceBase() override = default;

  [[nodiscard]] ClientServiceArg GetInitArg() const;
  ECM FlushTo(AMApplication::config::ConfigAppService *config_service) override;

  virtual void SetHeartbeatTimeoutMs(int timeout_ms);
  [[nodiscard]] virtual int HeartbeatTimeoutMs() const;
  virtual void SetHeartbeatIntervalS(int interval_s);
  [[nodiscard]] virtual int HeartbeatIntervalS() const;

  void RegisterControlComponent(amf control_token);
  [[nodiscard]] ControlComponent
  GetControlComponent(std::optional<amf> control_token = std::nullopt,
                      int timeout_ms = 0) const;

  void SetPrivateKeys(std::vector<std::string> private_keys);
  [[nodiscard]] std::vector<std::string> GetPrivateKeys() const;

  void RegisterMaintainerCallbacks(
      std::optional<DisconnectCallback> disconnect_cb = std::nullopt,
      std::optional<TraceCallback> trace_cb = std::nullopt,
      std::optional<ConnectStateCallback> connect_state_cb = std::nullopt,
      std::optional<KnownHostCallback> known_host_cb = std::nullopt,
      std::optional<AuthCallback> auth_cb = std::nullopt);
  void RegisterPublicCallbacks(
      std::optional<DisconnectCallback> disconnect_cb = std::nullopt,
      std::optional<TraceCallback> trace_cb = std::nullopt,
      std::optional<ConnectStateCallback> connect_state_cb = std::nullopt,
      std::optional<KnownHostCallback> known_host_cb = std::nullopt,
      std::optional<AuthCallback> auth_cb = std::nullopt);

  [[nodiscard]] ClientCallbacks GetMaintainerCallbacks() const;
  [[nodiscard]] ClientCallbacks GetPublicCallbacks() const;

  [[nodiscard]] ClientHandle GetLocalClient() const;
  [[nodiscard]] ClientHandle GetCurrentClient() const;
  [[nodiscard]] std::string GetCurrentNickname() const;
  [[nodiscard]] std::string CurrentNickname() const;
  void SetCurrentClient(const ClientHandle &client);

  [[nodiscard]] std::vector<PublicClientInstance>
  ListPublicClients(const std::vector<std::string> &nicknames = {},
                    bool case_sensitive = false) const;
  [[nodiscard]] std::vector<std::string> GetPublicClientNames() const;

protected:
  void SetLocalClient_(const ClientHandle &client, bool update_current);
  bool SetCurrentClientIfEmpty_(const ClientHandle &client);
  [[nodiscard]] std::optional<std::string>
  ResolvePublicBucketKey_(const std::string &nickname,
                          bool case_sensitive) const;
  [[nodiscard]] std::vector<std::pair<ClientID, ClientHandle>>
  SnapshotPublicBucket_(const std::string &nickname) const;
  void UpsertPublicClient_(const std::string &nickname, const ClientID &id,
                           const ClientHandle &client);
  bool ErasePublicClient_(const std::string &nickname, const ClientID &id);
  void ErasePublicBucket_(const std::string &nickname);

  mutable AMAtomic<ClientServiceArg> init_arg_ = {};
  mutable AMAtomic<amf> control_token_ = {};
  mutable AMAtomic<std::vector<std::string>> private_keys_ = {};
  mutable AMAtomic<ClientCallbacks> maintainer_callbacks_ = {};
  mutable AMAtomic<ClientCallbacks> public_callbacks_ = {};
  mutable AMAtomic<RuntimeClientCache> runtime_clients_ = {};
  mutable AMAtomic<ClientContainer> public_clients_ = {};
};
} // namespace AMApplication::client
