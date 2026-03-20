#pragma once

#include "application/client/ClientAppServiceBase.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace AMApplication::TransferRuntime {
class ITransferClientPoolPort;
}

namespace AMApplication::client {
using ClientHandle = AMDomain::client::ClientHandle;
using CheckResult = AMDomain::filesystem::CheckResult;
using ClientConnectOptions = AMDomain::client::ClientConnectOptions;
using ClientConnectContext = AMDomain::client::ClientConnectContext;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using HostConfig = AMDomain::host::HostConfig;
using ClientID = AMDomain::client::ClientID;
using ClientNickname = AMDomain::host::ConRequest::ClientNickname;
using ClientContainer = std::map<std::string, std::map<ClientID, ClientHandle>>;

struct ClientHanleCache {
  ClientHandle local = nullptr;
  ClientHandle current = nullptr;
};

class ClientAppService : public ClientAppServiceBase {
public:
  ClientAppService();
  explicit ClientAppService(ClientServiceArg arg);
  ~ClientAppService() override;

  ECM Init(ClientHandle local_client);
  [[nodiscard]] ClientHandle GetClient(const std::string &nickname) const;
  [[nodiscard]] ClientHandle GetLocalClient() const;
  [[nodiscard]] ClientHandle GetCurrentClient() const;
  [[nodiscard]] std::string GetCurrentNickname() const;
  [[nodiscard]] std::string CurrentNickname() const;

  std::pair<ECM, ClientHandle>
  CreateClient(const AMDomain::host::HostConfig &config);
  ECM AddClient(ClientHandle client, bool overwrite);
  [[nodiscard]] std::optional<CheckResult>
  CheckClient(const std::string &nickname, bool reconnect, bool update,
              const std::optional<ClientControlComponent> &control_component =
                  std::nullopt,
              int timeout_ms = 0);
  [[nodiscard]] std::map<std::string, ClientHandle> GetClients() const;
  ECM RemoveClient(const std::string &nickname);

  std::pair<ECM, ClientHandle> GetPublicClient(const std::string &nickname);
  ECM AddPublicClient(const ClientHandle &client);

  [[nodiscard]] std::shared_ptr<
      AMApplication::TransferRuntime::ITransferClientPoolPort>
  PublicPool() const;

  void SetCurrentClient(const ClientHandle &client);
  [[nodiscard]] std::vector<std::string> GetClientNames() const;

private:
  void ApplyCallbacksToClient_(const ClientHandle &client,
                               const ClientCallbacks &callbacks,
                               TraceCallback trace_override = {});
  [[nodiscard]] CheckResult CheckClientInternal_(
      const ClientHandle &client, bool reconnect, bool update,
      const AMDomain::client::ClientControlComponent &control) const;
  [[nodiscard]] std::pair<ClientCallbacks, std::vector<std::string>>
  SnapshotCreateContext_(bool for_public_pool) const;

private:
  mutable AMAtomic<ClientHanleCache> runtime_clients_ = {};
  std::unique_ptr<AMDomain::client::IClientMaintainerPort> maintainer_ =
      nullptr;
  mutable AMAtomic<ClientContainer> public_clients_ = {};
};
} // namespace AMApplication::client
