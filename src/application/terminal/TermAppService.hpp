#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/core/DataClass.hpp"
#include <map>
#include <mutex>
#include <string>

namespace AMApplication::terminal {
using ClientHandle = AMDomain::client::ClientHandle;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using TerminalHandle = AMDomain::terminal::TerminalHandle;

class TermAppService final : public NonCopyableNonMovable {
public:
  TermAppService() = default;
  ~TermAppService() override = default;

  [[nodiscard]] ECMData<TerminalHandle>
  EnsureTerminal(const ClientHandle &client);

  [[nodiscard]] ECMData<TerminalHandle>
  GetTerminalByNickname(const std::string &nickname) const;

  ECM RemoveTerminal(const std::string &nickname,
                     const ClientControlComponent &control = {});

  ECMData<AMDomain::terminal::ChannelOpenResult>
  OpenChannel(const ClientHandle &client,
              const AMDomain::terminal::ChannelOpenArgs &open_args,
              const ClientControlComponent &control = {});

  ECMData<AMDomain::terminal::ChannelActiveResult>
  ActiveChannel(const ClientHandle &client,
                const AMDomain::terminal::ChannelActiveArgs &active_args,
                const ClientControlComponent &control = {});

  ECMData<AMDomain::terminal::ChannelReadResult>
  ReadChannel(const ClientHandle &client,
              const AMDomain::terminal::ChannelReadArgs &read_args,
              const ClientControlComponent &control = {});

  ECMData<AMDomain::terminal::ChannelWriteResult>
  WriteChannel(const ClientHandle &client,
               const AMDomain::terminal::ChannelWriteArgs &write_args,
               const ClientControlComponent &control = {});

  ECMData<AMDomain::terminal::ChannelResizeResult>
  ResizeChannel(const ClientHandle &client,
                const AMDomain::terminal::ChannelResizeArgs &resize_args,
                const ClientControlComponent &control = {});

  ECMData<AMDomain::terminal::ChannelCloseResult>
  CloseChannel(const ClientHandle &client,
               const AMDomain::terminal::ChannelCloseArgs &close_args,
               const ClientControlComponent &control = {});

  ECMData<AMDomain::terminal::ChannelListResult>
  ListChannels(const ClientHandle &client,
               const AMDomain::terminal::ChannelListArgs &list_args = {},
               const ClientControlComponent &control = {});

  ECMData<AMDomain::terminal::TerminalStatusResult>
  Status(const ClientHandle &client,
         const AMDomain::terminal::TerminalStatusArgs &status_args = {},
         const ClientControlComponent &control = {});

private:
  [[nodiscard]] static std::string
  BuildTerminalKey_(const ClientHandle &client, const char *action);

  [[nodiscard]] ECMData<TerminalHandle>
  QueryTerminal_(const std::string &terminal_key) const;

private:
  mutable std::mutex mutex_ = {};
  std::map<std::string, TerminalHandle> terminals_ = {};
};

} // namespace AMApplication::terminal
