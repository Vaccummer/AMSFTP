#pragma once

#include "infrastructure/client/common/Base.hpp"
#include "infrastructure/client/ftp/FTP.hpp"
#include "infrastructure/client/local/Local.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"
#include <memory>
#include <utility>
#include <vector>

namespace AMBootstrap {
/**
 * @brief Build one concrete client instance from protocol request data.
 *
 * This is a composition-root helper and should be used by bootstrap/wiring
 * paths instead of legacy global helpers.
 */
inline std::shared_ptr<BaseClient>
CreateClient(const ConRequest &request, ssize_t trace_num = 10,
             TraceCallback trace_cb = {}, std::vector<std::string> keys = {},
             AuthCallback auth_cb = {}) {
  const ClientProtocol protocol = request.protocol;
  const ssize_t buffer_size = request.buffer_size > 0
                                  ? request.buffer_size
                                  : static_cast<ssize_t>(8 * AMMB);
  if (protocol == ClientProtocol::SFTP) {
    auto client = std::make_shared<AMSFTPClient>(
        request, keys, trace_num, std::move(trace_cb), std::move(auth_cb));
    client->TransferRingBufferSize(buffer_size);
    return std::dynamic_pointer_cast<BaseClient>(client);
  }
  if (protocol == ClientProtocol::FTP) {
    auto client = std::make_shared<AMFTPClient>(
        request, trace_num, std::move(trace_cb), std::move(auth_cb));
    client->TransferRingBufferSize(buffer_size);
    return std::dynamic_pointer_cast<BaseClient>(client);
  }
  if (protocol == ClientProtocol::LOCAL) {
    auto client =
        std::make_shared<AMLocalClient>(request, trace_num, std::move(trace_cb));
    client->TransferRingBufferSize(buffer_size);
    return std::dynamic_pointer_cast<BaseClient>(client);
  }
  return nullptr;
}
} // namespace AMBootstrap
