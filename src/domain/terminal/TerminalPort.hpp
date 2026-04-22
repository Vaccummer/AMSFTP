#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"
#include "domain/terminal/ChannelPort.hpp"
#include "domain/terminal/TerminalModel.hpp"
#include <memory>
#include <optional>
#include <string>

namespace AMDomain::terminal {
class ITerminalPort;
using AMDomain::client::ClientHandle;
using AMDomain::host::ConRequest;
using TerminalHandle = std::shared_ptr<ITerminalPort>;

class ITerminalPort {
public:
  virtual ~ITerminalPort() = default;

  [[nodiscard]] virtual ConRequest GetRequest() const = 0;

  virtual ECMData<ChannelOpenResult>
  OpenChannel(const ChannelOpenArgs &open_args,
              const ControlComponent &control = {}) = 0;

  virtual ECMData<ChannelActiveResult>
  ActiveChannel(const ChannelActiveArgs &active_args,
                const ControlComponent &control = {}) = 0;

  virtual ECMData<ChannelPortHandle>
  GetChannelPort(const std::optional<std::string> &channel_name = std::nullopt,
                 const ControlComponent &control = {}) = 0;

  virtual ECMData<ChannelCloseResult>
  CloseChannel(const ChannelCloseArgs &close_args,
               const ControlComponent &control = {}) = 0;

  virtual ECMData<ChannelRenameResult>
  RenameChannel(const ChannelRenameArgs &rename_args,
                const ControlComponent &control = {}) = 0;

  virtual ECMData<ChannelListResult>
  ListChannels(const ChannelListArgs &list_args,
               const ControlComponent &control = {}) = 0;

  virtual ECMData<CheckSessionResult>
  CheckSession(const CheckSessionArgs &check_args,
               const ControlComponent &control = {}) = 0;

  [[nodiscard]] virtual AMDomain::filesystem::CheckResult
  GetSessionState() const = 0;
};

[[nodiscard]] ECMData<TerminalHandle>
CreateTerminalPort(const ClientHandle &client,
                   BufferExceedCallback buffer_exceed_callback = {},
                   const TerminalManagerArg &terminal_manager_arg = {});

} // namespace AMDomain::terminal
