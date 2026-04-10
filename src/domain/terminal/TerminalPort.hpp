#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/terminal/TerminalModel.hpp"
#include <cstdint>
#include <memory>

namespace AMDomain::terminal {
using ClientHandle = AMDomain::client::ClientHandle;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using ConRequest = AMDomain::host::ConRequest;

class ITerminalPort {
public:
  virtual ~ITerminalPort() = default;

  [[nodiscard]] virtual ConRequest GetRequest() const = 0;

  virtual ECMData<ChannelOpenResult>
  OpenChannel(const ChannelOpenArgs &open_args,
              const ClientControlComponent &control = {}) = 0;

  virtual ECMData<ChannelActiveResult>
  ActiveChannel(const ChannelActiveArgs &active_args,
                const ClientControlComponent &control = {}) = 0;

  virtual ECMData<ChannelReadResult>
  ReadChannel(const ChannelReadArgs &read_args,
              const ClientControlComponent &control = {}) = 0;

  virtual ECMData<ChannelWriteResult>
  WriteChannel(const ChannelWriteArgs &write_args,
               const ClientControlComponent &control = {}) = 0;

  virtual ECMData<ChannelResizeResult>
  ResizeChannel(const ChannelResizeArgs &resize_args,
                const ClientControlComponent &control = {}) = 0;

  virtual ECMData<ChannelCloseResult>
  CloseChannel(const ChannelCloseArgs &close_args,
               const ClientControlComponent &control = {}) = 0;

  virtual ECMData<ChannelRenameResult>
  RenameChannel(const ChannelRenameArgs &rename_args,
                const ClientControlComponent &control = {}) = 0;

  virtual ECMData<ChannelListResult>
  ListChannels(const ChannelListArgs &list_args,
               const ClientControlComponent &control = {}) = 0;

  virtual ECMData<CheckSessionResult>
  CheckSession(const CheckSessionArgs &check_args,
               const ClientControlComponent &control = {}) = 0;

  virtual ECMData<ChannelCheckResult>
  CheckChannel(const ChannelCheckArgs &check_args,
               const ClientControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ClientStatus GetSessionState() const = 0;

  [[nodiscard]] virtual ECMData<std::intptr_t>
  GetRemoteSocketHandle() const = 0;
};

using TerminalHandle = std::shared_ptr<ITerminalPort>;

[[nodiscard]] ECMData<TerminalHandle>
CreateTerminalPort(const ClientHandle &client);

} // namespace AMDomain::terminal
