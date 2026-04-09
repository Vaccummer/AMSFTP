#include "application/terminal/TermAppService.hpp"

#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::terminal {
namespace {
using EC = ErrorCode;
}

std::string TermAppService::BuildTerminalKey_(const ClientHandle &client,
                                              const char *action) {
  if (!client) {
    return "";
  }
  const std::string raw =
      AMStr::Strip(client->ConfigPort().GetNickname().empty()
                       ? client->ConfigPort().GetRequest().nickname
                       : client->ConfigPort().GetNickname());
  if (raw.empty()) {
    return "";
  }
  (void)action;
  return AMDomain::host::HostService::NormalizeNickname(raw);
}

ECMData<TerminalHandle>
TermAppService::QueryTerminal_(const std::string &terminal_key) const {
  if (terminal_key.empty()) {
    return {nullptr,
            Err(EC::InvalidArg, "terminal.query", "terminal_key",
                "Terminal key is empty")};
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto it = terminals_.find(terminal_key);
  if (it == terminals_.end() || !it->second) {
    return {nullptr,
            Err(EC::ClientNotFound, "terminal.query", terminal_key,
                "Terminal not found")};
  }
  return {it->second, OK};
}

ECMData<TerminalHandle> TermAppService::EnsureTerminal(const ClientHandle &client) {
  if (!client) {
    return {nullptr,
            Err(EC::InvalidHandle, "terminal.ensure", "<client>",
                "Client handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.ensure");
  if (terminal_key.empty()) {
    return {nullptr,
            Err(EC::InvalidArg, "terminal.ensure", "terminal_key",
                "Failed to resolve terminal key from client")};
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it != terminals_.end() && it->second) {
      return {it->second, OK};
    }
  }

  auto create_result = AMDomain::terminal::CreateTerminalPort(client);
  if (!(create_result.rcm) || !create_result.data) {
    return create_result;
  }
  TerminalHandle created = std::move(create_result.data);

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto [it, inserted] = terminals_.emplace(terminal_key, created);
    if (!inserted && !it->second) {
      it->second = std::move(created);
    }
    return {it->second, OK};
  }
}

ECMData<TerminalHandle>
TermAppService::GetTerminalByNickname(const std::string &nickname) const {
  const std::string terminal_key =
      AMDomain::host::HostService::NormalizeNickname(AMStr::Strip(nickname));
  if (terminal_key.empty()) {
    return {nullptr,
            Err(EC::InvalidArg, "terminal.get", nickname,
                "Terminal nickname is empty")};
  }
  return QueryTerminal_(terminal_key);
}

ECM TermAppService::RemoveTerminal(const std::string &nickname,
                                   const ClientControlComponent &control) {
  const std::string key =
      AMDomain::host::HostService::NormalizeNickname(AMStr::Strip(nickname));
  if (key.empty()) {
    return Err(EC::InvalidArg, "terminal.remove", nickname,
               "Terminal nickname is empty");
  }

  TerminalHandle target = nullptr;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(key);
    if (it == terminals_.end()) {
      return OK;
    }
    target = it->second;
    terminals_.erase(it);
  }

  if (!target) {
    return OK;
  }

  auto list_result = target->ListChannels({}, control);
  if (!(list_result.rcm)) {
    return list_result.rcm;
  }
  ECM status = OK;
  for (const auto &name : list_result.data.channel_names) {
    auto close_result = target->CloseChannel({name, true}, control);
    if (!(close_result.rcm)) {
      status = close_result.rcm;
    }
  }
  return status;
}

ECMData<AMDomain::terminal::ChannelOpenResult>
TermAppService::OpenChannel(const ClientHandle &client,
                            const AMDomain::terminal::ChannelOpenArgs &open_args,
                            const ClientControlComponent &control) {
  auto terminal_result = EnsureTerminal(client);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {{}, terminal_result.rcm};
  }
  return terminal_result.data->OpenChannel(open_args, control);
}

ECMData<AMDomain::terminal::ChannelActiveResult>
TermAppService::ActiveChannel(
    const ClientHandle &client,
    const AMDomain::terminal::ChannelActiveArgs &active_args,
    const ClientControlComponent &control) {
  auto terminal_result = EnsureTerminal(client);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {{}, terminal_result.rcm};
  }
  return terminal_result.data->ActiveChannel(active_args, control);
}

ECMData<AMDomain::terminal::ChannelReadResult>
TermAppService::ReadChannel(const ClientHandle &client,
                            const AMDomain::terminal::ChannelReadArgs &read_args,
                            const ClientControlComponent &control) {
  auto terminal_result = EnsureTerminal(client);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {{}, terminal_result.rcm};
  }
  return terminal_result.data->ReadChannel(read_args, control);
}

ECMData<AMDomain::terminal::ChannelWriteResult>
TermAppService::WriteChannel(
    const ClientHandle &client,
    const AMDomain::terminal::ChannelWriteArgs &write_args,
    const ClientControlComponent &control) {
  auto terminal_result = EnsureTerminal(client);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {{}, terminal_result.rcm};
  }
  return terminal_result.data->WriteChannel(write_args, control);
}

ECMData<AMDomain::terminal::ChannelResizeResult>
TermAppService::ResizeChannel(
    const ClientHandle &client,
    const AMDomain::terminal::ChannelResizeArgs &resize_args,
    const ClientControlComponent &control) {
  auto terminal_result = EnsureTerminal(client);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {{}, terminal_result.rcm};
  }
  return terminal_result.data->ResizeChannel(resize_args, control);
}

ECMData<AMDomain::terminal::ChannelCloseResult>
TermAppService::CloseChannel(
    const ClientHandle &client,
    const AMDomain::terminal::ChannelCloseArgs &close_args,
    const ClientControlComponent &control) {
  auto terminal_result = EnsureTerminal(client);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {{}, terminal_result.rcm};
  }
  return terminal_result.data->CloseChannel(close_args, control);
}

ECMData<AMDomain::terminal::ChannelListResult>
TermAppService::ListChannels(
    const ClientHandle &client,
    const AMDomain::terminal::ChannelListArgs &list_args,
    const ClientControlComponent &control) {
  auto terminal_result = EnsureTerminal(client);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {{}, terminal_result.rcm};
  }
  return terminal_result.data->ListChannels(list_args, control);
}

ECMData<AMDomain::terminal::TerminalStatusResult>
TermAppService::Status(const ClientHandle &client,
                       const AMDomain::terminal::TerminalStatusArgs &status_args,
                       const ClientControlComponent &control) {
  auto terminal_result = EnsureTerminal(client);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {{}, terminal_result.rcm};
  }
  return terminal_result.data->Status(status_args, control);
}

} // namespace AMApplication::terminal
