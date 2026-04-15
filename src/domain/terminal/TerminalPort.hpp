#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"
#include "domain/terminal/ChannelPort.hpp"
#include "domain/terminal/TerminalModel.hpp"
#include <memory>
#include <optional>
#include <string>
#include <vector>

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

  virtual ECMData<ChannelPortHandle>
  GetChannelPort(const std::optional<std::string> &channel_name = std::nullopt,
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

  [[nodiscard]] virtual AMDomain::filesystem::CheckResult
  GetSessionState() const = 0;

  [[nodiscard]] virtual std::optional<ECM>
  GetChannelState(const std::string &channel_name) const = 0;

  [[nodiscard]] virtual std::vector<std::string>
  GetCachedChannelNames() const = 0;
};

using TerminalHandle = std::shared_ptr<ITerminalPort>;

[[nodiscard]] ECMData<TerminalHandle>
CreateTerminalPort(const ClientHandle &client);

} // namespace AMDomain::terminal
