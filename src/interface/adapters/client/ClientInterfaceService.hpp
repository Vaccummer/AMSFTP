#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::client {
using ClientAppService = AMApplication::client::ClientAppService;
using FilesystemAppService = AMApplication::filesystem::FilesystemAppService;
using AMHostConfigManager = AMApplication::host::HostAppService;
using AMKnownHostsManager = AMApplication::host::KnownHostsAppService;
using AMPromptIOManager = AMInterface::prompt::AMPromptIOManager;
using AMStyleService = AMInterface::style::AMStyleService;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using amf = AMDomain::client::amf;
using ClientHandle = AMDomain::client::ClientHandle;
using HostConfig = AMDomain::host::HostConfig;

struct ConnectRequest {
  std::vector<std::string> nicknames = {};
  bool force = false;
};

struct ChangeClientRequest {
  std::string nickname = "";
  bool quiet = false;
};

struct ProtocolConnectRequest {
  std::string nickname = "";
  std::string user_at_host = "";
  int64_t port = 0;
  std::string password = "";
  std::string keyfile = "";
};

struct RemoveClientsRequest {
  std::vector<std::string> nicknames = {};
};

struct ListClientsRequest {
  std::vector<std::string> nicknames = {};
  bool check = false;
  bool detail = false;
};

struct CheckClientsRequest {
  std::vector<std::string> nicknames = {};
  bool detail = false;
};

struct SetHostValueRequest {
  std::string nickname = {};
  std::string attrname = {};
  std::string value = {};
};

class ClientConnectSpinner;

class ClientInterfaceService final : public NonCopyableNonMovable {
public:
  ClientInterfaceService(ClientAppService &client_service,
                         FilesystemAppService &filesystem_service,
                         AMHostConfigManager &host_config_manager,
                         AMKnownHostsManager &known_hosts_manager,
                         AMPromptIOManager &prompt_io_manager,
                         AMStyleService &style_service);
  ~ClientInterfaceService() override;

  void SetDefaultControlToken(const amf &token);
  [[nodiscard]] amf GetDefaultControlToken() const;
  void BindInteractionCallbacks();

  ECM Connect(
      const ConnectRequest &request,
      const std::optional<ClientControlComponent> &component = std::nullopt);
  ECM ChangeClient(
      const ChangeClientRequest &request,
      const std::optional<ClientControlComponent> &component = std::nullopt);
  ECM ConnectSftp(
      const ProtocolConnectRequest &request,
      const std::optional<ClientControlComponent> &component = std::nullopt);
  ECM ConnectFtp(
      const ProtocolConnectRequest &request,
      const std::optional<ClientControlComponent> &component = std::nullopt);
  ECM RemoveClients(
      const RemoveClientsRequest &request,
      const std::optional<ClientControlComponent> &component = std::nullopt);
  ECM ListClients(
      const ListClientsRequest &request,
      const std::optional<ClientControlComponent> &component = std::nullopt);
  ECM CheckClients(
      const CheckClientsRequest &request,
      const std::optional<ClientControlComponent> &component = std::nullopt);
  ECM ListPrivateKeys(bool detail);
  ECM AddHost(const std::string &nickname);
  ECM ModifyHost(const std::string &nickname);
  ECM RenameHost(const std::string &old_nickname,
                 const std::string &new_nickname);
  ECM RemoveHosts(const std::vector<std::string> &nicknames);
  ECM SetHostValue(const SetHostValueRequest &request);
  ECM ListHosts(bool detail);

private:
  [[nodiscard]] ClientControlComponent
  ResolveControl_(const std::optional<ClientControlComponent> &component) const;
  [[nodiscard]] ECM
  ConnectProtocol_(const ProtocolConnectRequest &request,
                   AMDomain::host::ClientProtocol protocol,
                   const std::optional<ClientControlComponent> &component);

  ClientAppService &client_service_;
  FilesystemAppService &filesystem_service_;
  AMHostConfigManager &host_config_manager_;
  AMKnownHostsManager &known_hosts_manager_;
  AMPromptIOManager &prompt_io_manager_;
  AMStyleService &style_service_;
  std::unique_ptr<ClientConnectSpinner> spinner_ = nullptr;
  amf default_control_token_ = nullptr;
};
} // namespace AMInterface::client

