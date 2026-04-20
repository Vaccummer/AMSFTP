#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/terminal/TermAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/adapters/client/ClientInterfaceDTO.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::client {
using ClientAppService = AMApplication::client::ClientAppService;
using TermAppService = AMApplication::terminal::TermAppService;
using FilesystemAppService = AMApplication::filesystem::FilesystemAppService;
using AMHostConfigManager = AMApplication::host::HostAppService;
using AMKnownHostsManager = AMApplication::host::KnownHostsAppService;
using AMPromptIOManager = AMInterface::prompt::AMPromptIOManager;
using AMStyleService = AMInterface::style::AMStyleService;
using amf = AMDomain::client::amf;
using ClientHandle = AMDomain::client::ClientHandle;
using HostConfig = AMDomain::host::HostConfig;

class ClientConnectSpinner;

class ClientInterfaceService final : public NonCopyableNonMovable {
public:
  ClientInterfaceService(ClientAppService &client_service,
                         TermAppService &terminal_service,
                         FilesystemAppService &filesystem_service,
                         AMHostConfigManager &host_config_manager,
                         AMKnownHostsManager &known_hosts_manager,
                         AMPromptIOManager &prompt_io_manager,
                         AMStyleService &style_service);
  ~ClientInterfaceService() override;

  void SetDefaultControlToken(const amf &token);
  [[nodiscard]] amf GetDefaultControlToken() const;
  void BindInteractionCallbacks();

  ECM Connect(const ConnectRequest &request,
              const std::optional<ControlComponent> &component = std::nullopt);
  ECM ChangeClient(
      const ChangeClientRequest &request,
      const std::optional<ControlComponent> &component = std::nullopt);
  ECM ConnectSftp(
      const ProtocolConnectRequest &request,
      const std::optional<ControlComponent> &component = std::nullopt);
  ECM ConnectFtp(
      const ProtocolConnectRequest &request,
      const std::optional<ControlComponent> &component = std::nullopt);
  ECM ConnectLocal(
      const ProtocolConnectRequest &request,
      const std::optional<ControlComponent> &component = std::nullopt);
  ECM RemoveClients(
      const RemoveClientsRequest &request,
      const std::optional<ControlComponent> &component = std::nullopt);
  ECM ListClients(
      const ListClientsRequest &request,
      const std::optional<ControlComponent> &component = std::nullopt);
  ECM CheckClients(
      const CheckClientsRequest &request,
      const std::optional<ControlComponent> &component = std::nullopt);
  ECM PoolLs(const ListPoolClientsRequest &request,
             const std::optional<ControlComponent> &component = std::nullopt);
  ECM PoolCheck(
      const CheckPoolClientsRequest &request,
      const std::optional<ControlComponent> &component = std::nullopt);
  ECM PoolRm(const RemovePoolClientsRequest &request,
             const std::optional<ControlComponent> &component = std::nullopt);
  ECM ListPrivateKeys();
  ECM AddHost(const std::string &nickname);
  ECM ModifyHost(const std::string &nickname);
  ECM RenameHost(const std::string &old_nickname,
                 const std::string &new_nickname);
  ECM RemoveHosts(const std::vector<std::string> &nicknames);
  ECM SetHostValue(const SetHostValueRequest &request);
  ECM ListHosts(bool detail, bool list = false);
  ECM ListHosts(const std::vector<std::string> &nicknames, bool detail,
                bool list = false);

private:
  [[nodiscard]] ControlComponent
  ResolveControl_(const std::optional<ControlComponent> &component) const;
  [[nodiscard]] ECM
  ConnectProtocol_(const ProtocolConnectRequest &request,
                   AMDomain::host::ClientProtocol protocol,
                   const std::optional<ControlComponent> &component);

  ClientAppService &client_service_;
  TermAppService &terminal_service_;
  FilesystemAppService &filesystem_service_;
  AMHostConfigManager &host_config_manager_;
  AMKnownHostsManager &known_hosts_manager_;
  AMPromptIOManager &prompt_io_manager_;
  AMStyleService &style_service_;
  std::unique_ptr<ClientConnectSpinner> spinner_ = nullptr;
  amf default_control_token_ = nullptr;
};
} // namespace AMInterface::client
