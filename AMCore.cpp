#include "AMCore.hpp"
using AMCilent =
    std::variant<std::shared_ptr<AMSFTPClient>, std::shared_ptr<AMFTPClient>>;
std::atomic<bool> is_wsa_initialized(false);
void cleanup_wsa() {
  if (is_wsa_initialized) {
    WSACleanup();
    is_wsa_initialized = false;
  }
}
std::optional<AMCilent> CreateClient(const ConRequst &requeset,
                                     ClientProtocol protocol, ssize_t trace_num,
                                     py::object trace_cb, ssize_t buffer_size,
                                     std::vector<std::string> keys,
                                     py::object auth_cb) {
  if (protocol == ClientProtocol::SFTP) {
    auto client = std::make_shared<AMSFTPClient>(requeset, keys, trace_num,
                                                 trace_cb, auth_cb);
    client->TransferRingBufferSize(buffer_size);
    return client;
  } else if (protocol == ClientProtocol::FTP) {
    auto client = std::make_shared<AMFTPClient>(requeset, trace_num, trace_cb);
    client->TransferRingBufferSize(buffer_size);
    return client;
  } else {
    return std::nullopt;
  }
}