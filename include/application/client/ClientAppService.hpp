#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/host/HostManager.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace AMApplication::TransferRuntime {
class ITransferClientPoolPort;
}

namespace AMApplication::client {
class ClientAppService {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using EC = ErrorCode;
  using ClientHandle = AMDomain::client::ClientHandle;
  using ClientState = AMDomain::client::ClientState;
  using ClientStatus = AMDomain::client::ClientStatus;
  using ClientID = AMDomain::client::ClientID;
  using TraceCallback = AMDomain::client::TraceCallback;
  using AuthCallback = AMDomain::client::AuthCallback;
  using KnownHostCallback = AMDomain::client::KnownHostCallback;
  using DisconnectCallback =
      std::function<void(const ClientHandle &, const ECM &)>;
  using ClientConnectOptions = AMDomain::client::ClientConnectOptions;
  using ClientConnectContext = AMDomain::client::ClientConnectContext;
  using ClientWorkdirState = AMDomain::client::ClientWorkdirState;
  using ParsedClientPath = AMDomain::client::ParsedClientPath;
  using amf = AMDomain::client::amf;
  using ClientContainer =
      std::map<std::string, std::map<ClientID, ClientHandle>>;

  struct ClientServiceArg {
    int heartbeat_interval_s = 60;
    int heartbeat_timeout_ms = 100;
    amf control_token_port = nullptr;
    DisconnectCallback disconnect_callback = {};
    TraceCallback trace_callback = {};
    AuthCallback auth_callback = {};
    KnownHostCallback known_host_callback = {};
    std::vector<std::string> private_keys = {};
  };

  ClientAppService();
  explicit ClientAppService(ClientServiceArg arg);
  ~ClientAppService();

  ClientAppService(const ClientAppService &) = delete;
  ClientAppService &operator=(const ClientAppService &) = delete;
  ClientAppService(ClientAppService &&) = delete;
  ClientAppService &operator=(ClientAppService &&) = delete;

  ECM Init();

  [[nodiscard]] ClientServiceArg GetInitArg() const;

  [[nodiscard]] ClientHandle GetClient(const std::string &nickname) const;
  [[nodiscard]] ClientHandle GetLocalClient() const;
  [[nodiscard]] ClientHandle GetCurrentClient() const;
  [[nodiscard]] std::string GetCurrentNickname() const;
  [[nodiscard]] std::string CurrentNickname() const;

  std::pair<ECM, ClientHandle>
  CreateClient(const AMDomain::host::HostConfig &config);
  ECM AddClient(ClientHandle client, bool overwrite);
  [[nodiscard]] ClientState CheckClient(const std::string &nickname,
                                        bool reconnect, bool update);
  [[nodiscard]] std::map<std::string, ClientHandle> GetClients() const;
  ECM RemoveClient(const std::string &nickname);

  std::pair<ECM, ClientHandle> GetPublicClient(const std::string &nickname);
  ECM AddPublicClient(const ClientHandle &client);
  void SetPublicClientCallback(
      std::optional<DisconnectCallback> disconnect_cb = std::nullopt,
      std::optional<TraceCallback> trace_cb = std::nullopt,
      std::optional<KnownHostCallback> known_host_cb = std::nullopt,
      std::optional<AuthCallback> auth_cb = std::nullopt);

  void SetHeartbeatTimeoutMs(int timeout_ms);
  [[nodiscard]] int HeartbeatTimeoutMs() const;
  void SetHeartbeatIntervalS(int interval_s);
  [[nodiscard]] int HeartbeatIntervalS() const;

  void SetKnownHostCallback(KnownHostCallback cb = {});
  void SetAuthCallback(AuthCallback cb = {});
  void SetDisconnectCallback(DisconnectCallback cb = {});
  void SetTraceCallback(TraceCallback cb = {});

  void SetInteractiveFlag(const std::shared_ptr<std::atomic<bool>> &flag);
  [[nodiscard]] std::shared_ptr<std::atomic<bool>> GetInteractiveFlag() const;

  [[nodiscard]] std::shared_ptr<
      AMApplication::TransferRuntime::ITransferClientPoolPort>
  PublicPool() const;
  std::pair<ECM, ClientHandle> CreateTransferClient(const std::string &nickname,
                                                    int timeout_ms = -1,
                                                    int64_t start_time = -1);

  void SetCurrentClient(const ClientHandle &client);
  [[nodiscard]] std::vector<std::string> GetClientNames() const;

  std::pair<ECM, ClientHandle>
  ConnectNickname(const std::string &nickname,
                  const ClientConnectOptions &options = {},
                  TraceCallback trace_cb = {}, amf interrupt_flag = nullptr);
  std::pair<ECM, ClientHandle>
  ConnectRequest(const ClientConnectContext &context,
                 TraceCallback trace_cb = {}, amf interrupt_flag = nullptr);
  std::pair<ECM, ClientHandle> EnsureClient(const std::string &nickname,
                                            amf interrupt_flag = nullptr);
  std::pair<ECM, ClientHandle> CheckClient(const std::string &nickname,
                                           bool update = false,
                                           amf interrupt_flag = nullptr,
                                           int timeout_ms = -1,
                                           int64_t start_time = -1);

  [[nodiscard]] ParsedClientPath ParseScopedPath(const std::string &input,
                                                 amf interrupt_flag = nullptr);
  [[nodiscard]] std::string
  ResolveClientPath(const std::string &path,
                    const ClientHandle &client = nullptr) const;
  [[nodiscard]] ClientWorkdirState
  GetWorkdirState(const std::string &nickname) const;
  ECM SetWorkdirState(const std::string &nickname,
                      const ClientWorkdirState &state);
  [[nodiscard]] std::string GetOrInitWorkdir(const ClientHandle &client);
  [[nodiscard]] std::string BuildAbsolutePath(const ClientHandle &client,
                                              const std::string &path) const;

private:
  [[nodiscard]] static std::string
  NormalizeNickname_(const std::string &nickname);
  [[nodiscard]] static bool IsLocalNickname_(const std::string &nickname);
  [[nodiscard]] static ClientStatus StatusFromEcm_(const ECM &rcm);
  [[nodiscard]] static ClientWorkdirState
  NormalizeWorkdirState_(ClientWorkdirState state);

  [[nodiscard]] AMDomain::client::ClientControlComponent
  BuildControl_(amf interrupt_flag = nullptr, int timeout_ms = -1,
                int64_t start_time = -1) const;

  void ApplyCallbacksToClient_(const ClientHandle &client,
                               TraceCallback trace_override = {});
  [[nodiscard]] ClientState CheckClientInternal_(
      const ClientHandle &client, bool reconnect, bool update,
      const AMDomain::client::ClientControlComponent &control) const;

private:
  mutable std::mutex callback_mtx_;
  mutable std::mutex registry_mtx_;
  mutable std::mutex workdir_mtx_;

  ClientServiceArg init_arg_ = {};
  std::unique_ptr<AMDomain::client::IClientMaintainerPort> maintainer_ =
      nullptr;
  ClientContainer public_clients_ = {};

  ClientHandle local_client_ = nullptr;
  ClientHandle current_client_ = nullptr;

  DisconnectCallback disconnect_cb_ = {};
  TraceCallback trace_cb_ = {};
  AuthCallback auth_cb_ = {};
  KnownHostCallback known_host_cb_ = {};

  std::map<std::string, ClientWorkdirState> workdir_states_ = {};
  std::shared_ptr<std::atomic<bool>> interactive_flag_ =
      std::make_shared<std::atomic<bool>>(false);

  std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
      transfer_pool_ = nullptr;
};
} // namespace AMApplication::client
