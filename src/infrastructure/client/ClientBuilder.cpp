#pragma once
#include "domain/client/ClientPort.hpp"
#include "infrastructure/client/common/Base.hpp"
#include "infrastructure/client/ftp/FTP.hpp"
#include "infrastructure/client/local/Local.hpp"
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
  if (normalized.buffer_size <= 0) {
    normalized.buffer_size = (normalized.protocol == ClientProtocol::LOCAL)
                                 ? AMDefaultLocalBufferSize
                                 : AMDefaultRemoteBufferSize;
  }

  auto metadata_port = std::make_unique<AMInfra::client::ClientMetaDataStore>();
  auto config_port =
      std::make_unique<AMInfra::client::ClientConfigStore>(normalized);
  auto control_port = std::make_unique<AMInfra::client::ClientControl>();
  std::unique_ptr<AMDomain::client::IClientIOPort> io_port;
  static std::atomic<size_t> client_counter{0};
  std::string UID;

  switch (normalized.protocol) {
  case ClientProtocol::SFTP:
    io_port = std::make_unique<AMInfra::client::SFTP::AMSFTPIOCore>(
        config_port.get(), control_port.get(), private_keys, std::move(trace_cb),
        std::move(auth_cb), std::move(known_host_cb));
    UID = AMStr::fmt("SFTP-{}",
                     client_counter.fetch_add(1, std::memory_order_relaxed));
    break;
  case ClientProtocol::FTP:
    io_port = std::make_unique<AMInfra::client::FTP::AMFTPIOCore>(
        config_port.get(), control_port.get(), std::move(trace_cb),
        std::move(auth_cb));
    UID = AMStr::fmt("FTP-{}",
                     client_counter.fetch_add(1, std::memory_order_relaxed));
    break;
  case ClientProtocol::LOCAL:
    io_port = std::make_unique<AMInfra::client::LOCAL::AMLocalIOCore>(
        config_port.get(), control_port.get(), std::move(trace_cb),
        std::move(auth_cb));
    UID = AMStr::fmt("LOCAL-{}",
                     client_counter.fetch_add(1, std::memory_order_relaxed));
    break;
  default:
    return {{EC::InvalidArg, "Unsupported client protocol"}, nullptr};
  }

  return {{EC::Success, ""},
          std::make_shared<AMInfra::client::BaseClient>(
              std::move(metadata_port), std::move(config_port),
              std::move(control_port), std::move(io_port), UID)};
}

} // namespace AMDomain::client
