#include "domain/client/ClientDomainService.hpp"
#include "domain/client/ClientPort.hpp"

#include "infrastructure/client/common/Base.hpp"
#include "infrastructure/client/ftp/FTP.hpp"
#include "infrastructure/client/http/HTTP.hpp"
#include "infrastructure/client/local/Local.hpp"
#include "infrastructure/client/maintainer/ClientMaintainer.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"

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
  normalized.buffer_size =
      ClientService::ClampBufferSize(normalized.buffer_size);

  auto metadata_port = std::make_unique<AMInfra::client::ClientMetaDataStore>();
  auto config_port =
      std::make_unique<AMInfra::client::ClientConfigStore>(normalized);
  auto control_port = std::make_unique<InterruptControl>();
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
    return {{EC::InvalidArg, "", "", "Unsupported client protocol"}, nullptr};
  }

  return {OK, std::make_shared<AMInfra::client::BaseClient>(
                  std::move(metadata_port), std::move(config_port),
                  std::move(control_port), std::move(io_port), UID)};
}

std::unique_ptr<IClientMaintainerPort>
CreateClientMaintainer(int heartbeat_interval_s, int check_timeout_ms,
                       DisconnectCallback disconnect_callback,
                       std::vector<ClientHandle> init_clients) {
  return std::make_unique<AMInfra::client::maintainer::ClientMaintainer>(
      heartbeat_interval_s, check_timeout_ms, std::move(disconnect_callback),
      std::move(init_clients));
}

inline std::pair<ECM, AMDomain::client::ClientHandle>
CreateTransientHttpSourceClient(const std::string &url,
                                const std::string &proxy = "",
                                const std::string &bear_token = "",
                                const std::string &username = "",
                                int redirect_times = 0) {
  auto [rcm, client] = AMInfra::client::HTTP::BuildTransientHttpSourceClient(
      url, "", username, bear_token);
  if (!(rcm) || !client) {
    return {rcm, nullptr};
  }
  auto *http_io =
      dynamic_cast<AMInfra::client::HTTP::AMHTTPIOCore *>(&client->IOPort());
  if (http_io != nullptr) {
    http_io->SetProxy(proxy);
    http_io->SetMaxRedirectTimes(redirect_times);
    http_io->SetBearerToken(bear_token);
  }
  return {rcm, client};
}
} // namespace AMDomain::client
