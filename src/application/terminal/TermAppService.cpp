#include "application/terminal/TermAppService.hpp"

#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalModel.hpp"
#include "foundation/tools/string.hpp"

#include <mutex>
#include <optional>
#include <utility>

namespace AMApplication::terminal {
namespace {
using EC = ErrorCode;
using AMDomain::host::HostService::IsLocalNickname;
using AMDomain::host::HostService::NormalizeNickname;
using AMDomain::terminal::kDefaultTerminalChannelName;
using AMDomain::terminal::kTerminalRemoveCloseTimeoutMs;

[[nodiscard]] bool IsConnectionBroken_(ErrorCode code) {
  return code == EC::NoConnection || code == EC::ConnectionLost ||
         code == EC::NoSession || code == EC::ClientNotFound;
}

} // namespace

TermAppService::~TermAppService() {
  std::vector<std::string> keys = {};
  {
    std::lock_guard<std::mutex> lock(mutex_);
    keys.reserve(terminals_.size());
    for (const auto &entry : terminals_) {
      if (entry.second) {
        keys.push_back(entry.first);
      }
    }
  }
  for (const auto &key : keys) {
    DropAllTerminalChannelPortsByKey_(key, {});
  }
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

std::string TermAppService::NormalizeTerminalKey_(const std::string &nickname) {
  std::string key = NormalizeNickname(AMStr::Strip(nickname));
  if (IsLocalNickname(key)) {
    key = "local";
  }
  return key;
}

ECMData<TerminalHandle>
TermAppService::QueryTerminal_(const std::string &terminal_key) const {
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.query", "terminal_key",
                         "Terminal key is empty")};
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto it = terminals_.find(terminal_key);
  if (it == terminals_.end() || !it->second) {
    return {nullptr, Err(EC::ClientNotFound, "terminal.query", terminal_key,
                         "Terminal not found")};
  }
  return {it->second, OK};
}

ECMData<TerminalHandle>
TermAppService::CreateTerminal(const ClientHandle &client, bool detach) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.create", "<client>",
                         "Client handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.create");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.create", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  if (!detach) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it != terminals_.end() && it->second) {
      return {it->second, OK};
    }
  }

  auto create_result =
      AMDomain::terminal::CreateTerminalPort(client, buffer_exceed_callback_);
  if (!(create_result.rcm) || !create_result.data) {
    return create_result;
  }
  TerminalHandle created = create_result.data;

  auto open_result = created->OpenChannel({kDefaultTerminalChannelName}, {});
  if (!(open_result.rcm) && open_result.rcm.code != EC::TargetAlreadyExists) {
    return {nullptr, open_result.rcm};
  }

  auto active_result =
      created->ActiveChannel({kDefaultTerminalChannelName}, {});
  if (!(active_result.rcm) || !active_result.data.activated) {
    return {nullptr, active_result.rcm
                         ? Err(EC::CommonFailure,
                               "terminal.create.active_default", terminal_key,
                               "Failed to activate default terminal channel")
                         : active_result.rcm};
  }

  if (detach) {
    return {created, OK};
  }
  return AddTerminal(client, created, false);
}

ECMData<TerminalHandle>
TermAppService::AddTerminal(const ClientHandle &client,
                            const TerminalHandle &terminal, bool force) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.add", "<client>",
                         "Client handle is null")};
  }
  if (!terminal) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.add", "<terminal>",
                         "Terminal handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.add");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.add", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  TerminalHandle out = nullptr;
  bool replaced_terminal = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it == terminals_.end()) {
      terminals_.emplace(terminal_key, terminal);
      out = terminal;
    } else {
      if (force || !it->second) {
        replaced_terminal =
            (it->second != nullptr && it->second.get() != terminal.get());
        it->second = terminal;
      }
      out = it->second;
    }
  }

  if (replaced_terminal) {
    DropAllTerminalChannelPortsByKey_(terminal_key, {});
  }
  return {out, OK};
}

ECMData<TerminalHandle>
TermAppService::EnsureTerminal(const ClientHandle &client) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.ensure", "<client>",
                         "Client handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.ensure");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.ensure", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it != terminals_.end() && it->second) {
      return {it->second, OK};
    }
  }

  return CreateTerminal(client, false);
}

ECMData<TerminalHandle>
TermAppService::GetTerminalByNickname(const std::string &nickname,
                                      bool case_sensitive) const {
  const std::string key = NormalizeTerminalKey_(nickname);
  if (key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.get", nickname,
                         "Terminal nickname is empty")};
  }

  if (case_sensitive) {
    return QueryTerminal_(key);
  }

  const std::string lowered = AMStr::lowercase(key);
  std::vector<std::string> matched_names = {};
  TerminalHandle matched_terminal = nullptr;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &entry : terminals_) {
      if (!entry.second) {
        continue;
      }
      if (AMStr::lowercase(entry.first) != lowered) {
        continue;
      }
      matched_names.push_back(entry.first);
      matched_terminal = entry.second;
    }
  }

  if (matched_names.size() == 1 && matched_terminal) {
    return {matched_terminal, OK};
  }

  if (matched_names.size() > 1) {
    return {nullptr, Err(EC::ClientNotFound, "terminal.get", nickname,
                         AMStr::fmt("Ambiguous nickname, candidates: {}",
                                    AMStr::join(matched_names, ", ")))};
  }
  return {nullptr, Err(EC::ClientNotFound, "terminal.get", nickname,
                       "Terminal not found")};
}

std::vector<std::string> TermAppService::ListTerminalNames() const {
  std::vector<std::string> names = {};
  std::lock_guard<std::mutex> lock(mutex_);
  names.reserve(terminals_.size());
  for (const auto &entry : terminals_) {
    if (entry.second) {
      names.push_back(entry.first);
    }
  }
  return names;
}

ECMData<ChannelPortHandle>
TermAppService::EnsureChannelPort(const std::string &terminal_nickname,
                                  const std::string &channel_name,
                                  const ControlComponent &control) {
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.channel.ensure", "terminal",
                         "Terminal nickname is empty")};
  }
  if (channel.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.channel.ensure", "channel",
                         "Channel name is empty")};
  }

  auto terminal_result = QueryTerminal_(terminal_key);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return {nullptr, terminal_result.rcm};
  }
  return terminal_result.data->GetChannelPort(
      std::optional<std::string>(channel), control);
}

ECM TermAppService::DropChannelPort(const std::string &terminal_nickname,
                                    const std::string &channel_name,
                                    const ControlComponent &control) {
  auto channel_result =
      EnsureChannelPort(terminal_nickname, channel_name, control);
  if (!(channel_result.rcm)) {
    if (channel_result.rcm.code == EC::ClientNotFound) {
      return OK;
    }
    return channel_result.rcm;
  }
  if (!channel_result.data) {
    return OK;
  }
  return channel_result.data->UnbindForeground();
}

void TermAppService::DropAllTerminalChannelPortsByKey_(
    const std::string &terminal_key, const ControlComponent &control) {
  if (terminal_key.empty()) {
    return;
  }
  auto terminal_result = QueryTerminal_(terminal_key);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    return;
  }

  auto list_result = terminal_result.data->ListChannels({}, control);
  if (!(list_result.rcm)) {
    return;
  }

  for (const auto &[name, channel_port] : list_result.data.channels) {
    (void)name;
    if (!channel_port) {
      continue;
    }
    (void)channel_port->UnbindForeground();
  }
}

ECM TermAppService::DropTerminalChannelPorts(
    const std::string &terminal_nickname, const ControlComponent &control) {
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  if (terminal_key.empty()) {
    return {EC::InvalidArg, "terminal.channel.drop_all", "terminal",
            "Terminal nickname is empty"};
  }
  DropAllTerminalChannelPortsByKey_(terminal_key, control);
  return OK;
}

ECM TermAppService::RemoveTerminal(const std::string &nickname,
                                   const ControlComponent &control) {
  const std::string key = NormalizeTerminalKey_(nickname);
  if (key.empty()) {
    return {EC::InvalidArg, "terminal.remove", nickname,
            "Terminal nickname is empty"};
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

  auto list_for_detach = target->ListChannels({}, control);
  if (list_for_detach.rcm) {
    for (const auto &[name, channel_port] : list_for_detach.data.channels) {
      (void)name;
      if (!channel_port) {
        continue;
      }
      (void)channel_port->UnbindForeground();
    }
  }

  const auto session_state = target->GetSessionState();
  if (session_state.status != AMDomain::client::ClientStatus::OK) {
    return OK;
  }

  auto list_result = target->ListChannels({}, control);
  if (!(list_result.rcm)) {
    if (IsConnectionBroken_(list_result.rcm.code)) {
      return OK;
    }
    return list_result.rcm;
  }

  const ControlComponent close_control =
      control.RemainingTimeMs().has_value()
          ? control
          : ControlComponent(control.ControlToken(),
                             kTerminalRemoveCloseTimeoutMs);

  ECM status = OK;
  for (const auto &[name, channel_port] : list_result.data.channels) {
    (void)channel_port;
    auto close_result = target->CloseChannel({name, true}, close_control);
    if (!(close_result.rcm)) {
      if (IsConnectionBroken_(close_result.rcm.code)) {
        continue;
      }
      status = close_result.rcm;
    }
  }

  return status;
}

} // namespace AMApplication::terminal
