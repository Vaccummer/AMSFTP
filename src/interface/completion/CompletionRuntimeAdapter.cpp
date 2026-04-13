#include "interface/completion/CompletionRuntimeAdapter.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace AMInterface::completion {
namespace {
constexpr auto kTerminalSnapshotTtl = std::chrono::milliseconds(300);

std::string NormalizePath_(const std::string &path) {
  return AMDomain::filesystem::services::NormalizePath(AMStr::Strip(path));
}

std::string ResolveWorkdir_(const AMDomain::host::ClientMetaData &metadata,
                            const std::string &home_dir) {
  const std::string cwd = NormalizePath_(metadata.cwd);
  if (!cwd.empty()) {
    return cwd;
  }
  const std::string login_dir = NormalizePath_(metadata.login_dir);
  if (!login_dir.empty()) {
    return login_dir;
  }
  const std::string home = NormalizePath_(home_dir);
  if (!home.empty()) {
    return home;
  }
  return ".";
}

std::string NormalizeNicknameOrDefault_(const std::string &nickname,
                                        const std::string &fallback) {
  std::string key = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(nickname));
  if (key.empty()) {
    key = AMDomain::host::HostService::NormalizeNickname(AMStr::Strip(fallback));
  }
  if (key.empty()) {
    key = "local";
  }
  return key;
}

} // namespace

AMDomain::client::ClientHandle CompletionRuntimeAdapter::CurrentClient() const {
  return client_service_.GetCurrentClient();
}

std::string CompletionRuntimeAdapter::CurrentNickname() const {
  std::string nickname = AMStr::Strip(client_service_.CurrentNickname());
  if (nickname.empty()) {
    nickname = "local";
  }
  return nickname;
}

AMDomain::client::ClientHandle CompletionRuntimeAdapter::LocalClient() const {
  return client_service_.GetLocalClient();
}

AMDomain::client::ClientHandle
CompletionRuntimeAdapter::GetClient(const std::string &nickname) const {
  auto client = client_service_.GetClient(nickname, true);
  if (!(client.rcm)) {
    return nullptr;
  }
  return client.data;
}

std::vector<std::string> CompletionRuntimeAdapter::ListClientNames() const {
  return client_service_.GetClientNames();
}

std::vector<std::string> CompletionRuntimeAdapter::ListHostNames() const {
  return host_service_.ListNames();
}

std::vector<std::string> CompletionRuntimeAdapter::ListPoolNames() const {
  return client_service_.GetPublicClientNames();
}

std::vector<std::string> CompletionRuntimeAdapter::ListTerminalNames() const {
  return terminal_service_.ListTerminalNames();
}

std::vector<std::string> CompletionRuntimeAdapter::ListChannelNames(
    const std::string &terminal_nickname) const {
  std::vector<std::string> out = {};
  const auto snapshot = ResolveTerminalSnapshot_(terminal_nickname);
  if (!snapshot.found) {
    return out;
  }
  out.reserve(snapshot.channel_ok.size());
  for (const auto &entry : snapshot.channel_ok) {
    out.push_back(entry.first);
  }
  std::sort(out.begin(), out.end());
  return out;
}

bool CompletionRuntimeAdapter::HostExists(const std::string &nickname) const {
  return host_service_.HostExists(nickname);
}

bool CompletionRuntimeAdapter::TerminalExists(const std::string &nickname) const {
  auto terminal = terminal_service_.GetTerminalByNickname(nickname, false);
  return (terminal.rcm) && terminal.data;
}

ICompletionRuntime::TerminalNameState
CompletionRuntimeAdapter::QueryTerminalNameState(
    const std::string &nickname) const {
  const std::string key = NormalizeNicknameOrDefault_(nickname, CurrentNickname());
  const auto snapshot = ResolveTerminalSnapshot_(key);
  if (!snapshot.found) {
    if (host_service_.HostExists(key)) {
      return TerminalNameState::Unestablished;
    }
    return TerminalNameState::Nonexistent;
  }

  if (snapshot.status == AMDomain::client::ClientStatus::OK) {
    return TerminalNameState::OK;
  }
  return TerminalNameState::Disconnected;
}

ICompletionRuntime::ChannelNameState
CompletionRuntimeAdapter::QueryChannelNameState(
    const std::string &terminal_nickname, const std::string &channel_name,
    bool allow_new) const {
  const std::string key =
      NormalizeNicknameOrDefault_(terminal_nickname, CurrentNickname());
  const std::string channel = AMStr::Strip(channel_name);
  const bool valid_literal = AMDomain::host::HostService::ValidateNickname(channel);
  if (channel.empty()) {
    return allow_new ? ChannelNameState::InvalidNew : ChannelNameState::Nonexistent;
  }

  const auto snapshot = ResolveTerminalSnapshot_(key);
  if (!snapshot.found) {
    if (!allow_new) {
      return ChannelNameState::Nonexistent;
    }
    if (!valid_literal || QueryTerminalNameState(key) == TerminalNameState::Nonexistent) {
      return ChannelNameState::InvalidNew;
    }
    return ChannelNameState::ValidNew;
  }

  auto channel_it = snapshot.channel_ok.find(channel);
  if (channel_it != snapshot.channel_ok.end()) {
    return channel_it->second ? ChannelNameState::OK
                              : ChannelNameState::Disconnected;
  }

  if (!allow_new) {
    return ChannelNameState::Nonexistent;
  }
  return valid_literal ? ChannelNameState::ValidNew
                       : ChannelNameState::InvalidNew;
}

CompletionRuntimeAdapter::TerminalSnapshot_
CompletionRuntimeAdapter::ResolveTerminalSnapshot_(
    const std::string &terminal_nickname) const {
  const std::string key =
      NormalizeNicknameOrDefault_(terminal_nickname, CurrentNickname());
  if (key.empty()) {
    return {};
  }

  const auto now = std::chrono::steady_clock::now();
  {
    std::lock_guard<std::mutex> lock(terminal_snapshot_mutex_);
    auto it = terminal_snapshots_.find(key);
    if (it != terminal_snapshots_.end() &&
        (now - it->second.updated_at) <= kTerminalSnapshotTtl) {
      return it->second;
    }
  }

  TerminalSnapshot_ snapshot = {};
  auto terminal_result = terminal_service_.GetTerminalByNickname(key, false);
  if ((terminal_result.rcm) && terminal_result.data) {
    snapshot.found = true;
    snapshot.status = terminal_result.data->GetSessionState().status;
    const auto channels = terminal_result.data->GetCachedChannelNames();
    for (const auto &channel : channels) {
      auto state_opt = terminal_result.data->GetChannelState(channel);
      const bool is_ok = !state_opt.has_value() ||
                         state_opt->code == ErrorCode::Success;
      snapshot.channel_ok[channel] = is_ok;
    }
  }
  snapshot.updated_at = now;

  {
    std::lock_guard<std::mutex> lock(terminal_snapshot_mutex_);
    terminal_snapshots_[key] = snapshot;
  }
  return snapshot;
}

std::vector<std::string> CompletionRuntimeAdapter::ListVarDomains() const {
  std::vector<std::string> out = {};
  auto all_vars = var_service_.GetAllVar();
  if (!(all_vars.rcm)) {
    return out;
  }
  out.reserve(all_vars.data.size());
  for (const auto &[domain, vars] : all_vars.data) {
    (void)vars;
    out.push_back(domain);
  }
  return out;
}

bool CompletionRuntimeAdapter::HasVarDomain(const std::string &zone) const {
  auto all_vars = var_service_.GetAllVar();
  if (!(all_vars.rcm)) {
    return false;
  }
  return all_vars.data.find(zone) != all_vars.data.end();
}

std::string CompletionRuntimeAdapter::CurrentVarDomain() const {
  std::string current = AMStr::Strip(client_service_.CurrentNickname());
  if (current.empty()) {
    current = "local";
  }
  return current;
}

std::vector<AMDomain::var::VarInfo>
CompletionRuntimeAdapter::ListVarsByDomain(const std::string &domain) const {
  std::vector<AMDomain::var::VarInfo> out = {};
  auto zone = var_service_.EnumerateZone(domain);
  if (!(zone.rcm)) {
    return out;
  }
  out.reserve(zone.data.size());
  for (const auto &[name, info] : zone.data) {
    (void)name;
    out.push_back(info);
  }
  std::sort(out.begin(), out.end(), [](const auto &lhs, const auto &rhs) {
    return lhs.varname < rhs.varname;
  });
  return out;
}

std::vector<TASKID> CompletionRuntimeAdapter::ListTaskIds() const {
  std::vector<TASKID> out = {};
  std::unordered_set<TASKID> seen = {};
  const auto add_ids = [&out, &seen](const auto &tasks) {
    for (const auto &[id, task] : tasks) {
      if (!task) {
        continue;
      }
      if (seen.insert(id).second) {
        out.push_back(id);
      }
    }
  };

  add_ids(transfer_service_.GetPendingTasks());
  add_ids(transfer_service_.GetConductingTasks());
  add_ids(transfer_service_.GetPausedTasks());
  add_ids(transfer_service_.GetFinishedTasks());
  std::sort(out.begin(), out.end());
  return out;
}

ICompletionRuntime::PromptPathOptions
CompletionRuntimeAdapter::ResolvePromptPathOptions(
    const std::string &nickname) const {
  auto query = prompt_profile_manager_.GetZoneProfile(nickname);
  PromptPathOptions out = {};
  out.inline_hint.enable =
      query.profile.inline_hint.enable && query.profile.inline_hint.path.enable;
  out.inline_hint.use_async = query.profile.inline_hint.path.use_async;
  out.inline_hint.timeout_ms = query.profile.inline_hint.path.timeout_ms;
  out.inline_hint.delay_ms = query.profile.inline_hint.search_delay_ms;
  out.complete.enable = true;
  out.complete.use_async = query.profile.complete.path.use_async;
  out.complete.timeout_ms = query.profile.complete.path.timeout_ms;
  out.complete.delay_ms = 0;
  return out;
}

std::string
CompletionRuntimeAdapter::SubstitutePathLike(const std::string &raw) const {
  return var_interface_service_.SubstitutePathLike(raw);
}

std::string
CompletionRuntimeAdapter::BuildPath(AMDomain::client::ClientHandle client,
                                    const std::string &raw_path) const {
  if (!client) {
    return NormalizePath_(raw_path);
  }

  const std::string input = raw_path.empty() ? "." : raw_path;
  const std::string home_dir = client->ConfigPort().GetHomeDir();
  AMDomain::host::ClientMetaData metadata = {};
  auto metadata_opt =
      client->MetaDataPort().QueryTypedValue<AMDomain::host::ClientMetaData>();
  if (metadata_opt.has_value()) {
    metadata = *metadata_opt;
  }
  const std::string cwd = ResolveWorkdir_(metadata, home_dir);
  return AMPath::abspath(input, true, home_dir, cwd);
}

std::string CompletionRuntimeAdapter::Format(
    const std::string &text, AMInterface::style::StyleIndex style_index) const {
  return style_service_.Format(text, style_index);
}

std::string
CompletionRuntimeAdapter::FormatPath(const std::string &segment,
                                     const PathInfo *path_info) const {
  return style_service_.Format(
      segment, AMInterface::style::StyleIndex::PathLike, path_info);
}

} // namespace AMInterface::completion

