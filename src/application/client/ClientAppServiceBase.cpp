#include "application/client/ClientAppServiceBase.hpp"

namespace AMApplication::client {
ClientAppServiceBase::ClientAppServiceBase(ClientServiceArg arg)
    : init_arg_(std::move(arg)), control_token_(nullptr),
      private_keys_(std::vector<std::string>{}),
      maintainer_callbacks_(ClientCallbacks{}),
      public_callbacks_(ClientCallbacks{}) {}

ClientServiceArg ClientAppServiceBase::GetInitArg() const {
  return init_arg_.lock().load();
}

bool ClientAppServiceBase::IsConfigDirty() const {
  return config_dirty_.load(std::memory_order_acquire);
}

void ClientAppServiceBase::ClearConfigDirty() {
  config_dirty_.store(false, std::memory_order_release);
}

void ClientAppServiceBase::SetHeartbeatTimeoutMs(int timeout_ms) {
  auto init_arg = init_arg_.lock();
  auto value = init_arg.load();
  value.heartbeat_timeout_ms = timeout_ms;
  init_arg.store(value);
  config_dirty_.store(true, std::memory_order_release);
}

int ClientAppServiceBase::HeartbeatTimeoutMs() const {
  return init_arg_.lock().load().heartbeat_timeout_ms;
}

void ClientAppServiceBase::SetHeartbeatIntervalS(int interval_s) {
  auto init_arg = init_arg_.lock();
  auto value = init_arg.load();
  value.heartbeat_interval_s = interval_s;
  init_arg.store(value);
  config_dirty_.store(true, std::memory_order_release);
}

int ClientAppServiceBase::HeartbeatIntervalS() const {
  return init_arg_.lock().load().heartbeat_interval_s;
}

void ClientAppServiceBase::RegisterControlComponent(amf control_token) {
  control_token_.lock().store(std::move(control_token));
}

ClientControlComponent
ClientAppServiceBase::GetControlComponent(std::optional<amf> control_token,
                                          int timeout_ms) const {
  amf token = control_token ? *control_token : control_token_.lock().load();
  return {std::move(token), timeout_ms};
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
} // namespace AMApplication::client
