#pragma once

#include "domain/client/ClientPort.hpp"
#include "application/config/ConfigAppService.hpp"

#include <functional>
#include <atomic>
#include <optional>
#include <string>
#include <vector>

namespace AMApplication::client {
using ClientServiceArg = AMDomain::client::ClientServiceArg;
using amf = AMDomain::client::amf;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using TraceCallback = AMDomain::client::TraceCallback;
using ConnectStateCallback = AMDomain::client::ConnectStateCallback;
using AuthCallback = AMDomain::client::AuthCallback;
using KnownHostCallback = AMDomain::client::KnownHostCallback;
using DisconnectCallback =
    std::function<void(const AMDomain::client::ClientHandle &, const ECM &)>;

class ClientAppServiceBase : public AMApplication::config::IConfigSyncPort {
public:
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
  [[nodiscard]] ClientControlComponent
  GetControlComponent(std::optional<amf> control_token = std::nullopt,
                      int timeout_ms = -1) const;

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

protected:
  mutable AMAtomic<ClientServiceArg> init_arg_ = {};
  mutable AMAtomic<amf> control_token_ = {};
  mutable AMAtomic<std::vector<std::string>> private_keys_ = {};
  mutable AMAtomic<ClientCallbacks> maintainer_callbacks_ = {};
  mutable AMAtomic<ClientCallbacks> public_callbacks_ = {};
};
} // namespace AMApplication::client
