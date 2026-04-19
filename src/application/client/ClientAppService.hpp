#pragma once

#include "application/client/ClientAppServiceBase.hpp"
#include "application/host/HostAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace AMApplication::client {
using AMApplication::host::HostAppService;
using AMDomain::client::ClientHandle;
using AMDomain::client::ClientID;
using AMDomain::filesystem::CheckResult;
using AMDomain::host::ClientMetaData;
using AMDomain::host::ClientNickname;
using AMDomain::host::HostConfig;
using BeforeConnectCallback =
    std::function<void(const HostConfig &, const ClientHandle &, bool)>;
using AfterConnectCallback = std::function<void(
    const HostConfig &, const ClientHandle &, bool, const ECM &)>;
constexpr const char *kTransferLeaseKey = "transfer.lease";
constexpr const char *kTerminalLeaseKey = "terminal.lease";

class ClientAppService : public ClientAppServiceBase {
public:
  using PublicClientInstance = ClientAppServiceBase::PublicClientInstance;

  struct ConnectHooks {
    BeforeConnectCallback before_connect = {};
    AfterConnectCallback after_connect = {};
  };

  explicit ClientAppService(HostAppService *host_config_manager,
                            ClientServiceArg arg = ClientServiceArg());
  ~ClientAppService() override;

  ECM Init(ClientHandle local_client);

  [[nodiscard]] ECMData<ClientHandle>
  GetClient(const std::string &nickname, bool case_sensitive = true) const;

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

  ECMData<ClientHandle> CreateClient(const AMDomain::host::HostConfig &config,
                                     const ControlComponent &control,
                                     bool silent = false);

  ECMData<ClientHandle> CreateClient(const std::string &nickname,
                                     const ControlComponent &control,
                                     bool case_sensitive = true,
                                     bool silent = false);

  [[nodiscard]] ECMData<ClientHandle> EnsureClient(const std::string &nickname,
                                                   bool case_sensitive = true,
                                                   bool silent = false);

  [[nodiscard]] ECMData<ClientHandle>
  EnsureClient(const std::string &nickname, const ControlComponent &control,
               bool case_sensitive = true, bool silent = false);

  ECM AddClient(ClientHandle client, bool overwrite);

  [[nodiscard]] std::optional<ECMData<CheckResult>> CheckClient(
      const std::string &nickname, bool reconnect, bool update,
      const std::optional<ControlComponent> &control_component = std::nullopt,
      int timeout_ms = 0);
  [[nodiscard]] ECMData<CheckResult> CheckClientHandle(
      const ClientHandle &client, bool reconnect, bool update,
      const std::optional<ControlComponent> &control_component = std::nullopt,
      int timeout_ms = 0) const;

  [[nodiscard]] std::map<std::string, ClientHandle> GetClients() const;

  ECM RemoveClient(const std::string &nickname);
  ECM RemovePublicClient(const std::string &nickname, const ClientID &id);
  ECM RemovePublicClients(
      const std::vector<std::pair<std::string, ClientID>> &targets);

  ECMData<ClientHandle> GetPublicClient(const std::string &nickname);

  ECM AddPublicClient(const ClientHandle &client);

  void SetConnectHooks(ConnectHooks hooks);

  ECMData<ClientHandle> ChangeClient(const std::string &nickname,
                                     const ControlComponent &control,
                                     bool silent = false);
  [[nodiscard]] std::vector<std::string> GetClientNames() const;

  [[nodiscard]] static std::optional<ClientMetaData>
  GetClientMetadata(const ClientHandle &client);
  static ECM SetClientMetadata(const ClientHandle &client,
                               const ClientMetaData &metadata);
  [[nodiscard]] static ECMData<std::string>
  GetClientCwd(const ClientHandle &client);
  static ECM SetClientCwd(const ClientHandle &client, const std::string &cwd);
  [[nodiscard]] static ECMData<bool>
  IsTransferLeased(const ClientHandle &client);
  [[nodiscard]] static ECM TryLeaseClient(const ClientHandle &client);
  [[nodiscard]] static ECM TryReturnClient(const ClientHandle &client);
  [[nodiscard]] static ECM TryActivateTerminal(const ClientHandle &client);
  [[nodiscard]] static ECM TryDeactivateTerminal(const ClientHandle &client);
  [[nodiscard]] static ECM
  EnsureTerminalInactive(const ClientHandle &client,
                         const std::string &operation = {});

private:
  void ApplyCallbacksToClient_(const ClientHandle &client,
                               const ClientCallbacks &callbacks,
                               TraceCallback trace_override = {});
  [[nodiscard]] ECMData<CheckResult>
  CheckClientInternal_(const ClientHandle &client, bool reconnect, bool update,
                       const ControlComponent &control) const;
  [[nodiscard]] std::pair<ClientCallbacks, std::vector<std::string>>
  SnapshotCreateContext_(bool for_public_pool) const;
  [[nodiscard]] ConnectHooks SnapshotConnectHooks_() const;
  [[nodiscard]] ControlComponent BuildCheckControl_(int timeout_ms = 0) const;

private:
  std::unique_ptr<AMDomain::client::IClientMaintainerPort> maintainer_ =
      nullptr;
  HostAppService *host_config_manager_ = nullptr;
  mutable std::mutex connect_hooks_mutex_ = {};
  ConnectHooks connect_hooks_ = {};
};
} // namespace AMApplication::client
