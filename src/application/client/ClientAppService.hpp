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
using ClientHandle = AMDomain::client::ClientHandle;
using CheckResult = AMDomain::filesystem::CheckResult;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using HostConfig = AMDomain::host::HostConfig;
using ClientMetaData = AMDomain::host::ClientMetaData;
using HostConfigManager = AMApplication::host::HostAppService;
using ClientID = AMDomain::client::ClientID;
using ClientNickname = AMDomain::host::ConRequest::ClientNickname;
using ClientContainer = std::map<std::string, std::map<ClientID, ClientHandle>>;
using BeforeConnectCallback =
    std::function<void(const HostConfig &, const ClientHandle &, bool)>;
using AfterConnectCallback = std::function<void(
    const HostConfig &, const ClientHandle &, bool, const ECM &)>;
struct ClientHanleCache {
  ClientHandle local = nullptr;
  ClientHandle current = nullptr;
};

class ClientAppService : public ClientAppServiceBase {
public:
  struct ConnectHooks {
    BeforeConnectCallback before_connect = {};
    AfterConnectCallback after_connect = {};
  };

  explicit ClientAppService(ClientServiceArg arg = ClientServiceArg());
  ~ClientAppService() override;

  ECM Init(ClientHandle local_client);
  [[nodiscard]] ECMData<ClientHandle>

  GetClient(const std::string &nickname, bool case_sensitive = true) const;

  [[nodiscard]] ClientHandle GetLocalClient() const;

  [[nodiscard]] ClientHandle GetCurrentClient() const;

  [[nodiscard]] std::string GetCurrentNickname() const;

  [[nodiscard]] std::string CurrentNickname() const;

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

  void BindHostConfigManager(HostConfigManager *host_config_manager);
  ECMData<ClientHandle> CreateClient(const AMDomain::host::HostConfig &config,
                                     const ClientControlComponent &control,
                                     bool silent = false);

  [[nodiscard]] ECMData<ClientHandle> EnsureClient(const std::string &nickname,
                                                   bool case_sensitive = true,
                                                   bool silent = false);

  [[nodiscard]] ECMData<ClientHandle>
  EnsureClient(const std::string &nickname,
               const ClientControlComponent &control,
               bool case_sensitive = true, bool silent = false);

  ECM AddClient(ClientHandle client, bool overwrite);

  [[nodiscard]] std::optional<ECMData<CheckResult>>
  CheckClient(const std::string &nickname, bool reconnect, bool update,
              const std::optional<ClientControlComponent> &control_component =
                  std::nullopt,
              int timeout_ms = 0);

  [[nodiscard]] std::map<std::string, ClientHandle> GetClients() const;

  ECM RemoveClient(const std::string &nickname);

  ECMData<ClientHandle> GetPublicClient(const std::string &nickname);

  ECM AddPublicClient(const ClientHandle &client);

  void SetConnectHooks(ConnectHooks hooks);

  ECMData<ClientHandle> ChangeClient(const std::string &nickname,
                                     const ClientControlComponent &control,
                                     bool silent = false);

  void SetCurrentClient(const ClientHandle &client);
  [[nodiscard]] std::vector<std::string> GetClientNames() const;

  [[nodiscard]] static std::optional<ClientMetaData>
  GetClientMetadata(const ClientHandle &client);
  static ECM SetClientMetadata(const ClientHandle &client,
                               const ClientMetaData &metadata);
  [[nodiscard]] static ECMData<std::string>
  GetClientCwd(const ClientHandle &client);
  static ECM SetClientCwd(const ClientHandle &client, const std::string &cwd);
  [[nodiscard]] static ECM TryLeaseClient(const ClientHandle &client);
  [[nodiscard]] static ECM TryReturnClient(const ClientHandle &client);

private:
  void ApplyCallbacksToClient_(const ClientHandle &client,
                               const ClientCallbacks &callbacks,
                               TraceCallback trace_override = {});
  [[nodiscard]] ECMData<CheckResult> CheckClientInternal_(
      const ClientHandle &client, bool reconnect, bool update,
      const AMDomain::client::ClientControlComponent &control) const;
  [[nodiscard]] std::pair<ClientCallbacks, std::vector<std::string>>
  SnapshotCreateContext_(bool for_public_pool) const;
  [[nodiscard]] ConnectHooks SnapshotConnectHooks_() const;

private:
  mutable AMAtomic<ClientHanleCache> runtime_clients_ = {};
  std::unique_ptr<AMDomain::client::IClientMaintainerPort> maintainer_ =
      nullptr;
  mutable AMAtomic<ClientContainer> public_clients_ = {};
  HostConfigManager *host_config_manager_ = nullptr;
  mutable std::mutex connect_hooks_mutex_ = {};
  ConnectHooks connect_hooks_ = {};
};
} // namespace AMApplication::client
