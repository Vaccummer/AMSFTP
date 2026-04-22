#include "domain/terminal/TerminalPort.hpp"
#include "infrastructure/terminal/local/LocalTerminal.hpp"
#include "infrastructure/terminal/sftp/SSHTerminal.hpp"

namespace AMDomain::terminal {
ECMData<TerminalHandle>
CreateTerminalPort(const ClientHandle &client,
                   BufferExceedCallback buffer_exceed_callback,
                   const TerminalManagerArg &terminal_manager_arg) {
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
    if (sftp_core->Session() == nullptr) {
      return {nullptr,
              Err(EC::NoConnection, "CreateTerminalPort", request.nickname,
                  "Client session is not connected")};
    }

    auto terminal =
        std::make_shared<AMInfra::terminal::SFTP::SSHTerminalPort>(
            client, buffer_exceed_callback, terminal_manager_arg);
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
            client, buffer_exceed_callback, terminal_manager_arg);
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
