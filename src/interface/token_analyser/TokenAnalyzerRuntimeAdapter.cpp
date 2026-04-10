#include "interface/token_analyser/TokenAnalyzerRuntimeAdapter.hpp"

#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include <optional>

namespace AMInterface::parser {
namespace {

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

AMDomain::client::ClientHandle
TokenAnalyzerRuntimeAdapter::CurrentClient() const {
  return client_service_.GetCurrentClient();
}

AMDomain::client::ClientHandle TokenAnalyzerRuntimeAdapter::LocalClient() const {
  return client_service_.GetLocalClient();
}

AMDomain::client::ClientHandle
TokenAnalyzerRuntimeAdapter::GetClient(const std::string &nickname) const {
  auto client = client_service_.GetClient(nickname, true);
  if (!(client.rcm)) {
    return nullptr;
  }
  return client.data;
}

std::string TokenAnalyzerRuntimeAdapter::CurrentNickname() const {
  std::string nickname = AMStr::Strip(client_service_.CurrentNickname());
  if (nickname.empty()) {
    nickname = "local";
  }
  return AMDomain::host::HostService::NormalizeNickname(nickname);
}

bool TokenAnalyzerRuntimeAdapter::HostExists(const std::string &nickname) const {
  return host_service_.HostExists(nickname);
}

bool TokenAnalyzerRuntimeAdapter::TerminalExists(
    const std::string &nickname) const {
  auto terminal =
      terminal_service_.GetTerminalByNickname(nickname, false);
  return (terminal.rcm) && terminal.data;
}

ITokenAnalyzerRuntime::TerminalNameState
TokenAnalyzerRuntimeAdapter::QueryTerminalNameState(
    const std::string &nickname) const {
  const std::string key = NormalizeNicknameOrDefault_(nickname, CurrentNickname());
  auto terminal_result = terminal_service_.GetTerminalByNickname(key, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    if (host_service_.HostExists(key)) {
      return TerminalNameState::Unestablished;
    }
    return TerminalNameState::Nonexistent;
  }

  auto check_result = terminal_result.data->CheckSession({}, {});
  if ((check_result.rcm) &&
      check_result.data.status == AMDomain::client::ClientStatus::OK) {
    return TerminalNameState::OK;
  }
  return TerminalNameState::Disconnected;
}

ITokenAnalyzerRuntime::ChannelNameState
TokenAnalyzerRuntimeAdapter::QueryChannelNameState(const std::string &nickname,
                                                   const std::string &channel_name,
                                                   bool allow_new) const {
  const std::string key = NormalizeNicknameOrDefault_(nickname, CurrentNickname());
  const std::string channel = AMStr::Strip(channel_name);
  const bool valid_literal = AMDomain::host::HostService::ValidateNickname(channel);
  if (channel.empty()) {
    return allow_new ? ChannelNameState::InvalidNew : ChannelNameState::Nonexistent;
  }

  auto terminal_result = terminal_service_.GetTerminalByNickname(key, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    if (!allow_new) {
      return ChannelNameState::Nonexistent;
    }
    if (!valid_literal || QueryTerminalNameState(key) == TerminalNameState::Nonexistent) {
      return ChannelNameState::InvalidNew;
    }
    return ChannelNameState::ValidNew;
  }

  auto check_result =
      terminal_result.data->CheckChannel({std::optional<std::string>(channel)}, {});
  if ((check_result.rcm) && check_result.data.exists) {
    return check_result.data.is_open ? ChannelNameState::OK
                                     : ChannelNameState::Disconnected;
  }

  if (!allow_new) {
    return ChannelNameState::Nonexistent;
  }
  return valid_literal ? ChannelNameState::ValidNew
                       : ChannelNameState::InvalidNew;
}

bool TokenAnalyzerRuntimeAdapter::HasVarDomain(const std::string &zone) const {
  auto all_vars = var_service_.GetAllVar();
  if (!(all_vars.rcm)) {
    return false;
  }
  return all_vars.data.find(zone) != all_vars.data.end();
}

std::string TokenAnalyzerRuntimeAdapter::CurrentVarDomain() const {
  std::string current = AMStr::Strip(client_service_.CurrentNickname());
  if (current.empty()) {
    current = "local";
  }
  return current;
}

ECMData<AMDomain::var::VarInfo>
TokenAnalyzerRuntimeAdapter::GetVar(const std::string &zone,
                                    const std::string &varname) const {
  return var_service_.GetVar(zone, varname);
}

ITokenAnalyzerRuntime::PromptPathOptions
TokenAnalyzerRuntimeAdapter::ResolvePromptPathOptions(
    const std::string &nickname) const {
  auto query = prompt_profile_manager_.GetZoneProfile(nickname);
  PromptPathOptions out = {};
  out.highlight_enable = query.profile.highlight.path.enable;
  out.highlight_timeout_ms = query.profile.highlight.path.timeout_ms;
  return out;
}

std::string
TokenAnalyzerRuntimeAdapter::SubstitutePathLike(const std::string &raw) const {
  return var_interface_service_.SubstitutePathLike(raw);
}

std::string TokenAnalyzerRuntimeAdapter::BuildPath(
    AMDomain::client::ClientHandle client, const std::string &raw_path) const {
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

ECMData<PathInfo> TokenAnalyzerRuntimeAdapter::StatPath(
    AMDomain::client::ClientHandle client, const std::string &abs_path,
    int timeout_ms) const {
  if (!client) {
    return {PathInfo{}, Err(EC::InvalidHandle, __func__, "", "client is null")};
  }
  auto control =
      AMDomain::client::ClientControlComponent(nullptr, timeout_ms);
  auto stat_result = client->IOPort().stat({abs_path, false}, control);
  return {stat_result.data.info, stat_result.rcm};
}

std::string TokenAnalyzerRuntimeAdapter::FormatPath(
    const std::string &segment, const PathInfo *path_info) const {
  return style_service_.Format(segment, AMInterface::style::StyleIndex::PathLike,
                               path_info);
}

std::string TokenAnalyzerRuntimeAdapter::ResolveInputHighlightStyle(
    AMTokenType type, const std::string &default_value) const {
  const auto style_cfg = style_service_.GetInitArg().style;
  switch (type) {
  case AMTokenType::Module:
    return style_cfg.common.module;
  case AMTokenType::Command:
    return style_cfg.common.command;
  case AMTokenType::VarName:
    return style_cfg.common.public_varname;
  case AMTokenType::VarNameMissing:
    return style_cfg.common.nonexistent_varname;
  case AMTokenType::VarValue:
    return style_cfg.common.varvalue;
  case AMTokenType::Nickname:
    return style_cfg.common.nickname;
  case AMTokenType::DisconnectedNickname:
    return style_cfg.common.disconnected_nickname;
  case AMTokenType::UnestablishedNickname:
    return style_cfg.common.unestablished_nickname;
  case AMTokenType::NonexistentNickname:
    return style_cfg.common.nonexistent_nickname;
  case AMTokenType::BuiltinArg:
    return style_cfg.common.builtin_arg;
  case AMTokenType::NonexistentBuiltinArg:
    return style_cfg.common.nonexistent_builtin_arg;
  case AMTokenType::ValidValue:
    return style_cfg.value_query_highlight.valid_value;
  case AMTokenType::InvalidValue:
    return style_cfg.value_query_highlight.invalid_value;
  case AMTokenType::ValidNewNickname:
    return style_cfg.common.valid_new_nickname;
  case AMTokenType::InvalidNewNickname:
    return style_cfg.common.invalid_new_nickname;
  case AMTokenType::TerminalName:
    return style_cfg.common.termname;
  case AMTokenType::DisconnectedTerminalName:
    return style_cfg.common.disconnected_termname;
  case AMTokenType::UnestablishedTerminalName:
    return style_cfg.common.unestablished_termname;
  case AMTokenType::NonexistentTerminalName:
    return style_cfg.common.nonexistent_termname;
  case AMTokenType::ChannelName:
    return style_cfg.common.channelname;
  case AMTokenType::DisconnectedChannelName:
    return style_cfg.common.disconnected_channelname;
  case AMTokenType::NonexistentChannelName:
    return style_cfg.common.nonexistent_channelname;
  case AMTokenType::ValidNewChannelName:
    return style_cfg.common.valid_new_channelname;
  case AMTokenType::InvalidNewChannelName:
    return style_cfg.common.invalid_new_channelname;
  case AMTokenType::String:
    return style_cfg.common.string;
  case AMTokenType::Option:
    return style_cfg.common.option;
  case AMTokenType::AtSign:
    return style_cfg.common.atsign;
  case AMTokenType::DollarSign:
    return style_cfg.common.dollarsign;
  case AMTokenType::EqualSign:
    return style_cfg.common.equalsign;
  case AMTokenType::EscapeSign:
    return style_cfg.common.escapedsign;
  case AMTokenType::Path:
    return style_cfg.common.path_like;
  case AMTokenType::BangSign:
    return style_cfg.common.bangsign;
  case AMTokenType::ShellCmd:
    return style_cfg.common.shell_cmd;
  case AMTokenType::IllegalCommand:
    return style_cfg.common.illegal_command;
  case AMTokenType::Common:
    return style_cfg.common.common;
  default:
    return default_value;
  }
}

std::string TokenAnalyzerRuntimeAdapter::ResolvePathHighlightStyle(
    AMTokenType type, const std::string &default_value) const {
  const auto style_cfg = style_service_.GetInitArg().style;
  switch (type) {
  case AMTokenType::File:
    return style_cfg.path.regular;
  case AMTokenType::Dir:
    return style_cfg.path.dir;
  case AMTokenType::Symlink:
    return style_cfg.path.symlink;
  case AMTokenType::Special:
    return style_cfg.path.otherspecial;
  case AMTokenType::Nonexistentpath:
    return style_cfg.path.nonexistent;
  default:
    return default_value;
  }
}

} // namespace AMInterface::parser

