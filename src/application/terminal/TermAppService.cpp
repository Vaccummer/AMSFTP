#include "application/terminal/TermAppService.hpp"

#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/string.hpp"
#include <vector>

namespace AMApplication::terminal {
namespace {
using EC = ErrorCode;
constexpr const char *kDefaultTerminalChannelName = "default";
constexpr int kTerminalRemoveCloseTimeoutMs = 1500;
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

  auto create_result = AMDomain::terminal::CreateTerminalPort(client);
  if (!(create_result.rcm) || !create_result.data) {
    return create_result;
  }
  TerminalHandle created = create_result.data;

  auto open_result = created->OpenChannel({kDefaultTerminalChannelName}, {});
  if (!(open_result.rcm) && open_result.rcm.code != EC::TargetAlreadyExists) {
    return {nullptr, open_result.rcm};
  }

  auto active_result = created->ActiveChannel({kDefaultTerminalChannelName}, {});
  if (!(active_result.rcm) || !active_result.data.activated) {
    return {
        nullptr,
        active_result.rcm
            ? Err(EC::CommonFailure, "terminal.create.active_default",
                  terminal_key, "Failed to activate default terminal channel")
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

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it == terminals_.end()) {
      terminals_.emplace(terminal_key, terminal);
      return {terminal, OK};
    }
    if (force || !it->second) {
      it->second = terminal;
    }
    return {it->second, OK};
  }
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
  const std::string key =
      AMDomain::host::HostService::NormalizeNickname(AMStr::Strip(nickname));
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

  const auto session_state = target->GetSessionState();
  if (session_state != AMDomain::client::ClientStatus::OK) {
    // Disconnected sessions can fail or block during graceful channel close.
    // Terminal map entry is already removed, so best-effort cleanup stops here.
    return OK;
  }

  auto list_result = target->ListChannels({}, control);
  if (!(list_result.rcm)) {
    if (list_result.rcm.code == EC::NoConnection ||
        list_result.rcm.code == EC::ConnectionLost ||
        list_result.rcm.code == EC::NoSession) {
      return OK;
    }
    return list_result.rcm;
  }
  const AMDomain::client::ClientControlComponent close_control =
      control.RemainingTimeMs().has_value()
          ? control
          : AMDomain::client::ClientControlComponent(
                control.ControlToken(), kTerminalRemoveCloseTimeoutMs);
  ECM status = OK;
  for (const auto &name : list_result.data.channel_names) {
    auto close_result = target->CloseChannel({name, true}, close_control);
    if (!(close_result.rcm)) {
      if (close_result.rcm.code == EC::NoConnection ||
          close_result.rcm.code == EC::ConnectionLost ||
          close_result.rcm.code == EC::NoSession ||
          close_result.rcm.code == EC::ClientNotFound) {
        continue;
      }
      status = close_result.rcm;
    }
  }
  return status;
}

} // namespace AMApplication::terminal
