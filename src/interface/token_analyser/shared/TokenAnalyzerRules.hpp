#pragma once

#include "domain/host/HostDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntime.hpp"

#include <memory>
#include <string>

namespace AMInterface::parser::shared {

[[nodiscard]] inline bool ParseVarTokenAt(const std::string &input, size_t pos,
                                          size_t limit, size_t *out_end) {
  size_t parsed_end = 0;
  AMDomain::var::VarRef ref = {};
  if (!AMDomain::var::ParseVarRefAt(input, pos, limit, true, true, &parsed_end,
                                    &ref) ||
      !ref.valid) {
    return false;
  }
  if (out_end) {
    *out_end = parsed_end;
  }
  return true;
}

[[nodiscard]] inline bool ParseVarTokenText(const std::string &token,
                                            std::string *out_name = nullptr) {
  AMDomain::var::VarRef ref = {};
  if (!AMDomain::var::ParseVarToken(token, &ref) || !ref.valid ||
      ref.varname.empty()) {
    return false;
  }
  if (out_name) {
    *out_name = ref.varname;
  }
  return true;
}

[[nodiscard]] inline AMTokenType
VarNameTypeFor(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
               const std::string &name) {
  if (!runtime) {
    return AMTokenType::VarNameMissing;
  }
  const std::string domain = runtime->CurrentVarDomain();
  auto scoped = runtime->GetVar(domain, name);
  if ((scoped.rcm)) {
    return AMTokenType::VarName;
  }
  auto pub = runtime->GetVar(AMDomain::var::kPublic, name);
  return (pub.rcm) ? AMTokenType::VarName : AMTokenType::VarNameMissing;
}

[[nodiscard]] inline bool IsValidOptionToken(const std::string &token,
                                             const CommandNode *node) {
  if (!node || token.size() < 2 || token[0] != '-') {
    return false;
  }
  if (token.starts_with("--")) {
    std::string name = token;
    const size_t eq = token.find('=');
    if (eq != std::string::npos) {
      name = token.substr(0, eq);
    }
    return node->long_options.contains(name);
  }
  if (token.size() < 2) {
    return false;
  }
  for (size_t i = 1; i < token.size(); ++i) {
    if (!node->short_options.contains(token[i])) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] inline AMTokenType
ClassifyNicknameTokenType(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                          const std::string &nickname_raw) {
  const std::string nickname = AMStr::Strip(nickname_raw);
  if (AMDomain::host::HostService::IsLocalNickname(nickname)) {
    return AMTokenType::Nickname;
  }
  if (!runtime) {
    return AMTokenType::NonexistentNickname;
  }
  if (auto client = runtime->GetClient(nickname); client) {
    const auto state = client->ConfigPort().GetState();
    if (state.data.status == AMDomain::client::ClientStatus::OK) {
      return AMTokenType::Nickname;
    }
    return AMTokenType::DisconnectedNickname;
  }
  if (runtime->HostExists(nickname)) {
    return AMTokenType::UnestablishedNickname;
  }
  return AMTokenType::NonexistentNickname;
}

[[nodiscard]] inline AMTokenType
ClassifyVarZoneTokenType(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                         const std::string &zone_raw) {
  const std::string zone = AMStr::Strip(zone_raw);
  if (zone.empty()) {
    return AMTokenType::NonexistentNickname;
  }
  if (zone == AMDomain::var::kPublic) {
    return AMTokenType::Nickname;
  }
  if (!runtime) {
    return AMTokenType::NonexistentNickname;
  }
  if (runtime->HasVarDomain(zone)) {
    return AMTokenType::Nickname;
  }
  if (runtime->HostExists(zone)) {
    return AMTokenType::UnestablishedNickname;
  }
  return AMTokenType::NonexistentNickname;
}

[[nodiscard]] inline AMTokenType TerminalTokenTypeFromState(
    ITokenAnalyzerRuntime::TerminalNameState state) {
  switch (state) {
  case ITokenAnalyzerRuntime::TerminalNameState::OK:
    return AMTokenType::TerminalName;
  case ITokenAnalyzerRuntime::TerminalNameState::Disconnected:
    return AMTokenType::DisconnectedTerminalName;
  case ITokenAnalyzerRuntime::TerminalNameState::Unestablished:
    return AMTokenType::UnestablishedTerminalName;
  case ITokenAnalyzerRuntime::TerminalNameState::Nonexistent:
  default:
    return AMTokenType::NonexistentTerminalName;
  }
}

[[nodiscard]] inline AMTokenType ChannelTokenTypeFromState(
    ITokenAnalyzerRuntime::ChannelNameState state) {
  switch (state) {
  case ITokenAnalyzerRuntime::ChannelNameState::OK:
    return AMTokenType::ChannelName;
  case ITokenAnalyzerRuntime::ChannelNameState::Disconnected:
    return AMTokenType::DisconnectedChannelName;
  case ITokenAnalyzerRuntime::ChannelNameState::Nonexistent:
    return AMTokenType::NonexistentChannelName;
  case ITokenAnalyzerRuntime::ChannelNameState::ValidNew:
    return AMTokenType::ValidNewChannelName;
  case ITokenAnalyzerRuntime::ChannelNameState::InvalidNew:
  default:
    return AMTokenType::InvalidNewChannelName;
  }
}

} // namespace AMInterface::parser::shared
