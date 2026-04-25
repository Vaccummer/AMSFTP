#include "interface/highlight/InputHighlighter.hpp"

#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/input_analysis/rules/InputTextRules.hpp"
#include "interface/style/StyleManager.hpp"

#include <optional>

namespace AMInterface::highlight {
namespace {

using AMInterface::input::AnalyzedToken;
using AMInterface::input::InputAnalysis;
using AMInterface::input::PathKind;
using AMInterface::input::TokenRole;
using AMInterface::input::TokenState;
using AMInterface::style::StyleIndex;
using AMInterface::input::rules::FindUnescapedChar;
using AMInterface::input::rules::UnescapeBackticks;

std::string EscapeBbcode_(const std::string &text) {
  return AMStr::BBCEscape(text);
}

std::optional<StyleIndex> ResolveStyleIndex_(TokenRole role, TokenState state) {
  switch (role) {
  case TokenRole::Module:
    return StyleIndex::Module;
  case TokenRole::Command:
    return StyleIndex::Command;
  case TokenRole::Option:
    return StyleIndex::Option;
  case TokenRole::IllegalCommand:
    return StyleIndex::IllegalCommand;
  case TokenRole::StringLiteral:
    return StyleIndex::String;
  case TokenRole::ShellCommand:
    return StyleIndex::ShellCmd;
  case TokenRole::Nickname:
    switch (state) {
    case TokenState::Valid:
      return StyleIndex::Nickname;
    case TokenState::Disconnected:
      return StyleIndex::DisconnectedNickname;
    case TokenState::Unestablished:
      return StyleIndex::UnestablishedNickname;
    case TokenState::Nonexistent:
      return StyleIndex::NonexistentNickname;
    case TokenState::NewValid:
      return StyleIndex::ValidNewNickname;
    case TokenState::NewInvalid:
    case TokenState::Invalid:
      return StyleIndex::InvalidNewNickname;
    default:
      return StyleIndex::Nickname;
    }
  case TokenRole::TerminalName:
    switch (state) {
    case TokenState::Valid:
      return StyleIndex::TerminalName;
    case TokenState::Disconnected:
      return StyleIndex::DisconnectedTerminalName;
    case TokenState::Nonexistent:
      return StyleIndex::NonexistentTerminalName;
    case TokenState::NewValid:
      return StyleIndex::ValidNewTerminalName;
    case TokenState::NewInvalid:
    case TokenState::Invalid:
      return StyleIndex::InvalidNewTerminalName;
    default:
      return StyleIndex::TerminalName;
    }
  case TokenRole::BuiltinArg:
    return state == TokenState::Invalid ? StyleIndex::NonexistentBuiltinArg
                                        : StyleIndex::BuiltinArg;
  case TokenRole::ValidatedValue:
    return state == TokenState::Invalid ? StyleIndex::IllegalCommand
                                        : StyleIndex::BuiltinArg;
  case TokenRole::VariableReference:
  case TokenRole::VariableName:
    return state == TokenState::Missing ? StyleIndex::NonexistentVarname
                                        : StyleIndex::PublicVarname;
  case TokenRole::VariableZone:
    return StyleIndex::VarnameZone;
  case TokenRole::VariableValue:
    return StyleIndex::VarValue;
  case TokenRole::FindPattern:
    return StyleIndex::FindPattern;
  case TokenRole::AtSign:
    return StyleIndex::AtSign;
  case TokenRole::DollarSign:
    return StyleIndex::DollarSign;
  case TokenRole::EqualSign:
    return StyleIndex::EqualSign;
  case TokenRole::LeftBrace:
    return StyleIndex::LeftBraceSign;
  case TokenRole::RightBrace:
    return StyleIndex::RightBraceSign;
  case TokenRole::ColonSign:
    return StyleIndex::ColonSign;
  case TokenRole::EscapeSign:
    return StyleIndex::EscapedSign;
  case TokenRole::BangSign:
    return StyleIndex::BangSign;
  default:
    return std::nullopt;
  }
}

PathInfo BuildPathInfo_(PathKind kind) {
  PathInfo info = {};
  switch (kind) {
  case PathKind::File:
    info.path = ".";
    info.type = PathType::FILE;
    break;
  case PathKind::Directory:
    info.path = ".";
    info.type = PathType::DIR;
    break;
  case PathKind::Symlink:
    info.path = ".";
    info.type = PathType::SYMLINK;
    break;
  case PathKind::Nonexistent:
    info.path.clear();
    info.type = PathType::FILE;
    break;
  case PathKind::Special:
    info.path = ".";
    info.type = PathType::Unknown;
    break;
  case PathKind::None:
  default:
    info.path = ".";
    info.type = PathType::FILE;
    break;
  }
  return info;
}

void AppendStyledRange_(const AMInterface::style::AMStyleService *style_service,
                        std::string *out, const std::string &text,
                        TokenRole role, TokenState state,
                        PathKind path_kind = PathKind::None) {
  if (!out) {
    return;
  }
  if (text.empty()) {
    return;
  }
  if (!style_service) {
    out->append(EscapeBbcode_(text));
    return;
  }
  if (role == TokenRole::Path) {
    const PathInfo info = BuildPathInfo_(path_kind);
    out->append(style_service->Format(text, StyleIndex::PathLike, &info));
    return;
  }
  const auto style_index = ResolveStyleIndex_(role, state);
  if (!style_index.has_value()) {
    out->append(EscapeBbcode_(text));
    return;
  }
  out->append(style_service->Format(text, *style_index));
}

void RenderVarTokenText_(const AMInterface::style::AMStyleService *style_service,
                         const std::string &raw, TokenState state,
                         TokenRole fallback_role, std::string *out) {
  if (raw.empty() || raw.front() != '$') {
    AppendStyledRange_(style_service, out, raw, fallback_role, state);
    return;
  }

  AppendStyledRange_(style_service, out, "$",
                     TokenRole::DollarSign, TokenState::Neutral);
  const bool braced = raw.size() >= 2 && raw[1] == '{';
  if (braced) {
    AppendStyledRange_(style_service, out, "{",
                       TokenRole::LeftBrace, TokenState::Neutral);
  }

  const size_t body_begin = braced ? 2 : 1;
  if (body_begin >= raw.size()) {
    return;
  }

  size_t body_end = raw.size();
  const bool closed = braced && raw.back() == '}';
  if (closed) {
    --body_end;
  }
  if (body_end < body_begin) {
    body_end = body_begin;
  }

  const std::string body = raw.substr(body_begin, body_end - body_begin);
  const size_t colon = body.find(':');
  if (colon == std::string::npos) {
    AppendStyledRange_(style_service, out, body, TokenRole::VariableName,
                       state);
  } else {
    const std::string zone = body.substr(0, colon);
    AppendStyledRange_(style_service, out, zone, TokenRole::VariableZone,
                       state == TokenState::Missing
                           ? TokenState::Nonexistent
                           : TokenState::Valid);
    AppendStyledRange_(style_service, out, ":", TokenRole::ColonSign,
                       TokenState::Neutral);
    AppendStyledRange_(style_service, out, body.substr(colon + 1),
                       TokenRole::VariableName, state);
  }

  if (closed) {
    AppendStyledRange_(style_service, out, "}", TokenRole::RightBrace,
                       TokenState::Neutral);
  }
}

void RenderVarReference_(const AMInterface::style::AMStyleService *style_service,
                         const std::string &input, const AnalyzedToken &token,
                         std::string *out) {
  const std::string raw = input.substr(token.raw.start, token.raw.end - token.raw.start);
  const size_t eq = raw.find('=');
  if (eq != std::string::npos) {
    const std::string lhs = raw.substr(0, eq);
    if (AMDomain::var::ParseVarToken(lhs)) {
      RenderVarTokenText_(style_service, lhs, token.state, token.role, out);
      AppendStyledRange_(style_service, out, "=", TokenRole::EqualSign,
                         TokenState::Neutral);
      AppendStyledRange_(style_service, out, raw.substr(eq + 1),
                         TokenRole::VariableValue, TokenState::Neutral);
      return;
    }
  }
  RenderVarTokenText_(style_service, raw, token.state, token.role, out);
}

void RenderPath_(const AMInterface::style::AMStyleService *style_service,
                 const std::string &input, const AnalyzedToken &token,
                 std::string *out) {
  const std::string raw = input.substr(token.raw.start, token.raw.end - token.raw.start);
  const size_t at_pos = FindUnescapedChar(raw, '@');
  if (at_pos == std::string::npos) {
    AppendStyledRange_(style_service, out, raw, TokenRole::Path, token.state,
                       token.path_kind);
    return;
  }

  if (at_pos == 0) {
    AppendStyledRange_(style_service, out, "@", TokenRole::AtSign,
                       TokenState::Neutral);
    AppendStyledRange_(style_service, out, raw.substr(1), TokenRole::Path,
                       token.state, token.path_kind);
    return;
  }

  const size_t first_sep = raw.find_first_of("/\\");
  if (first_sep != std::string::npos && at_pos > first_sep) {
    AppendStyledRange_(style_service, out, raw, TokenRole::Path, token.state,
                       token.path_kind);
    return;
  }

  const std::string prefix = UnescapeBackticks(raw.substr(0, at_pos), true);
  TokenState nick_state = TokenState::Nonexistent;
  if (!prefix.empty()) {
    nick_state = token.state == TokenState::Valid ? TokenState::Valid
                                                  : TokenState::Neutral;
  }
  AppendStyledRange_(style_service, out, raw.substr(0, at_pos),
                     TokenRole::Nickname, nick_state);
  AppendStyledRange_(style_service, out, "@", TokenRole::AtSign,
                     TokenState::Neutral);
  AppendStyledRange_(style_service, out, raw.substr(at_pos + 1), TokenRole::Path,
                     token.state, token.path_kind);
}

void RenderTermTarget_(const AMInterface::style::AMStyleService *style_service,
                       const std::string &input, const AnalyzedToken &token,
                       std::string *out) {
  const std::string raw = input.substr(token.raw.start, token.raw.end - token.raw.start);
  const size_t at_pos = FindUnescapedChar(raw, '@');
  if (at_pos == std::string::npos) {
    AppendStyledRange_(style_service, out, raw, TokenRole::TerminalName,
                       token.state);
    return;
  }
  if (at_pos > 0) {
    AppendStyledRange_(style_service, out, raw.substr(0, at_pos),
                       TokenRole::Nickname, token.qualifier_state);
  }
  if (style_service) {
    out->append(style_service->Format("@", StyleIndex::TermnameAtSign));
  } else {
    out->append(EscapeBbcode_("@"));
  }
  AppendStyledRange_(style_service, out, raw.substr(at_pos + 1),
                     TokenRole::TerminalName, token.state);
}

bool ShellModeHead_(const std::string &input, size_t *head) {
  if (!head) {
    return false;
  }
  *head = 0;
  while (*head < input.size() && AMStr::IsWhitespace(input[*head])) {
    ++(*head);
  }
  return *head < input.size() && input[*head] == '!';
}

} // namespace

void InputHighlighter::RenderFormatted(const std::string &input,
                                       std::string *formatted) const {
  if (!formatted) {
    return;
  }
  formatted->clear();
  if (!analyzer_) {
    return;
  }

  size_t shell_head = 0;
  if (ShellModeHead_(input, &shell_head)) {
    formatted->append(EscapeBbcode_(input.substr(0, shell_head)));
    AppendStyledRange_(style_service_, formatted, "!", TokenRole::BangSign,
                       TokenState::Neutral);
    if (shell_head + 1 < input.size()) {
      AppendStyledRange_(style_service_, formatted, input.substr(shell_head + 1),
                         TokenRole::ShellCommand, TokenState::Neutral);
    }
    return;
  }

  const InputAnalysis analysis = analyzer_->Analyze(input);
  size_t cursor = 0;
  for (const auto &token : analysis.tokens) {
    if (token.raw.start > cursor) {
      formatted->append(EscapeBbcode_(
          input.substr(cursor, token.raw.start - cursor)));
    }

    if (token.role == TokenRole::VariableReference ||
        token.role == TokenRole::VariableName) {
      RenderVarReference_(style_service_, input, token, formatted);
    } else if (token.role == TokenRole::Path) {
      RenderPath_(style_service_, input, token, formatted);
    } else if (token.role == TokenRole::TerminalName) {
      RenderTermTarget_(style_service_, input, token, formatted);
    } else {
      AppendStyledRange_(style_service_, formatted,
                         input.substr(token.raw.start, token.raw.end - token.raw.start),
                         token.role, token.state, token.path_kind);
    }
    cursor = token.raw.end;
  }
  if (cursor < input.size()) {
    formatted->append(EscapeBbcode_(input.substr(cursor)));
  }
}

void InputHighlighter::IsoclineHighlightCallback(ic_highlight_env_t *henv,
                                                 const char *input, void *arg) {
  if (!henv || !input || !arg) {
    return;
  }
  auto *highlighter = static_cast<InputHighlighter *>(arg);
  if (!highlighter) {
    return;
  }
  std::string formatted = {};
  highlighter->RenderFormatted(input, &formatted);
  if (formatted.empty()) {
    return;
  }
  ic_highlight_formatted(henv, input, formatted.c_str());
}

} // namespace AMInterface::highlight
