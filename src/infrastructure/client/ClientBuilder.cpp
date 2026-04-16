#include "domain/client/ClientDomainService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "infrastructure/client/common/Base.hpp"
#include "infrastructure/client/ftp/FTP.hpp"
#include "infrastructure/client/local/Local.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"
#include "infrastructure/terminal/local/Terminal.hpp"
#include "infrastructure/terminal/sftp/Terminal.hpp"
#include <memory>
#include <utility>
#include <vector>

namespace AMDomain::client {

/**
 * @brief Build one concrete client instance from protocol request data.
 *
 * This runtime factory assembles split metadata/config/control/io parts and
 * returns an aggregate IClientPort implementation.
 */
std::pair<ECM, std::shared_ptr<AMDomain::client::IClientPort>>
CreateClient(const ConRequest &request,
             AMDomain::client::KnownHostCallback known_host_cb,
             TraceCallback trace_cb, AuthCallback auth_cb,
             const std::vector<std::string> &private_keys) {
  ConRequest normalized = request;
  normalized.buffer_size = ClientService::ClampBufferSize(
      normalized.buffer_size, normalized.protocol == ClientProtocol::LOCAL);

  auto metadata_port = std::make_unique<AMInfra::client::ClientMetaDataStore>();
  auto config_port =
      std::make_unique<AMInfra::client::ClientConfigStore>(normalized);
  auto control_port = std::make_unique<AMInfra::client::ClientControlToken>();
  std::unique_ptr<AMDomain::client::IClientIOPort> io_port;
  ClientID UID;

  switch (normalized.protocol) {
  case ClientProtocol::SFTP:
    io_port = std::make_unique<AMInfra::client::SFTP::AMSFTPIOCore>(
        config_port.get(), control_port.get(), private_keys,
        std::move(trace_cb), std::move(auth_cb), std::move(known_host_cb));
    UID = ClientService::GenerateID(ClientProtocol::SFTP);
    break;
  case ClientProtocol::FTP:
    io_port = std::make_unique<AMInfra::client::FTP::AMFTPIOCore>(
        config_port.get(), control_port.get(), std::move(trace_cb),
        std::move(auth_cb));
    UID = ClientService::GenerateID(ClientProtocol::FTP);
    break;
  case ClientProtocol::LOCAL:
    io_port = std::make_unique<AMInfra::client::LOCAL::AMLocalIOCore>(
        config_port.get(), control_port.get(), std::move(trace_cb),
        std::move(auth_cb));
    UID = ClientService::GenerateID(ClientProtocol::LOCAL);
    break;
  default:
    return {{EC::InvalidArg, "", "", "Unsupported client protocol"},
            nullptr};
  }

  return {OK, std::make_shared<AMInfra::client::BaseClient>(
                  std::move(metadata_port), std::move(config_port),
                  std::move(control_port), std::move(io_port), UID)};
}

} // namespace AMDomain::client

namespace AMDomain::terminal {

ECMData<TerminalHandle> CreateTerminalPort(const ClientHandle &client) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "CreateTerminalPort", "<client>",
                         "Client handle is null")};
  }
  const ConRequest request = client->ConfigPort().GetRequest();
  switch (request.protocol) {
  case AMDomain::host::ClientProtocol::SFTP: {
    auto *sftp_core =
        dynamic_cast<AMInfra::client::SFTP::AMSFTPIOCore *>(&client->IOPort());
    if (sftp_core == nullptr) {
      return {nullptr, Err(EC::OperationUnsupported, "CreateTerminalPort",
                           request.nickname,
                           "Client IO port cannot provide SFTP session reuse")};
    }
    if (sftp_core->session == nullptr) {
      return {nullptr,
              Err(EC::NoConnection, "CreateTerminalPort", request.nickname,
                  "Client session is not connected")};
    }

    auto terminal = std::make_shared<AMInfra::terminal::SFTP::SSHTerminalPort>(
        client, request, sftp_core);
    if (!terminal) {
      return {nullptr,
              Err(EC::InvalidHandle, "CreateTerminalPort", request.nickname,
                  "Failed to create terminal handle")};
    }
    return {std::move(terminal), OK};
  }
  case AMDomain::host::ClientProtocol::LOCAL: {
    auto *local_core = dynamic_cast<AMInfra::client::LOCAL::AMLocalIOCore *>(
        &client->IOPort());
    if (local_core == nullptr) {
      return {nullptr,
              Err(EC::OperationUnsupported, "CreateTerminalPort",
                  request.nickname,
                  "Client IO port cannot provide local terminal runtime")};
    }
    auto terminal =
        std::make_shared<AMInfra::client::LOCAL::terminal::LocalTerminalPort>(
            client, request, local_core);
    if (!terminal) {
      return {nullptr,
              Err(EC::InvalidHandle, "CreateTerminalPort", request.nickname,
                  "Failed to create terminal handle")};
    }
    return {std::move(terminal), OK};
  }
  default:
    return {nullptr,
            Err(EC::OperationUnsupported, "CreateTerminalPort",
                request.nickname,
                "Current client protocol does not support terminal mode")};
  }
}

} // namespace AMDomain::terminal

