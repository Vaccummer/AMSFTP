#include "interface/token_analyser/highlight/HighlightFormatter.hpp"

#include "domain/host/HostDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntime.hpp"
#include "interface/token_analyser/shared/InputTextRules.hpp"
#include "interface/token_analyser/shared/TokenAnalyzerRules.hpp"
#include <algorithm>
#include <array>
#include <optional>

namespace AMInterface::parser::highlight {
namespace {

using shared::ClassifyNicknameTokenType;
using shared::ClassifyVarZoneTokenType;
using shared::FindUnescapedChar;
using shared::IsQuotedChar;
using shared::ParseVarTokenAt;
using shared::TerminalTokenTypeFromState;
using shared::UnescapeBackticks;
using shared::VarNameTypeFor;

bool IsChannelTokenType_(AMTokenType type) {
  switch (type) {
  case AMTokenType::ChannelName:
  case AMTokenType::DisconnectedChannelName:
  case AMTokenType::NonexistentChannelName:
  case AMTokenType::ValidNewChannelName:
  case AMTokenType::InvalidNewChannelName:
    return true;
  default:
    return false;
  }
}

std::string NormalizeStyleTag_(const std::string &raw) {
  std::string trimmed = AMStr::Strip(raw);
  if (trimmed.empty()) {
    return "";
  }
  if (trimmed.find("[/") != std::string::npos) {
    return "";
  }
  if (trimmed.front() != '[') {
    trimmed.insert(trimmed.begin(), '[');
  }
  if (trimmed.back() != ']') {
    trimmed.push_back(']');
  }
  return trimmed;
}

void AppendEscapedBbcodeChar_(std::string &out, char c) {
  if (c == '\\') {
    out.append("\\\\");
  } else if (c == '[') {
    out.append("\\[");
  } else {
    out.push_back(c);
  }
}

std::string ResolveStyleTagForType_(
    std::shared_ptr<ITokenAnalyzerRuntime> runtime, AMTokenType type) {
  if (!runtime) {
    return "";
  }
  const std::string from_input =
      NormalizeStyleTag_(runtime->ResolveInputHighlightStyle(type, ""));
  if (!from_input.empty()) {
    return from_input;
  }

  return NormalizeStyleTag_(runtime->ResolvePathHighlightStyle(type, ""));
}

bool IsPathRenderType_(AMTokenType type) {
  switch (type) {
  case AMTokenType::Path:
  case AMTokenType::Nonexistentpath:
  case AMTokenType::File:
  case AMTokenType::Dir:
  case AMTokenType::Symlink:
  case AMTokenType::Special:
    return true;
  default:
    return false;
  }
}

PathInfo BuildPathInfoForTokenType_(AMTokenType type) {
  PathInfo info = {};
  info.path = ".";
  switch (type) {
  case AMTokenType::File:
    info.type = PathType::FILE;
    break;
  case AMTokenType::Dir:
    info.type = PathType::DIR;
    break;
  case AMTokenType::Symlink:
    info.type = PathType::SYMLINK;
    break;
  case AMTokenType::Special:
    info.type = PathType::Unknown;
    break;
  case AMTokenType::Nonexistentpath:
    info.type = PathType::FILE;
    info.path.clear();
    break;
  default:
    info.type = PathType::FILE;
    break;
  }
  return info;
}

std::string FormatPathSegment_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                               const std::string &segment, AMTokenType type) {
  if (segment.empty()) {
    return segment;
  }
  if (!runtime) {
    return AMStr::BBCEscape(segment);
  }
  if (type == AMTokenType::Path) {
    return runtime->FormatPath(segment, nullptr);
  }
  PathInfo info = BuildPathInfoForTokenType_(type);
  return runtime->FormatPath(segment, &info);
}

constexpr size_t kTokenTypeCount_ =
    static_cast<size_t>(AMTokenType::InvalidNewChannelName) + 1;

struct HighlightBuffer_ {
  std::vector<AMTokenType> types = {};
  std::vector<int> priorities = {};
};

struct HighlightContext_ {
  const std::string *input = nullptr;
  const std::vector<AMInterface::parser::model::RawToken> *tokens = nullptr;
  const CommandNode *command_tree = nullptr;
  std::shared_ptr<ITokenAnalyzerRuntime> runtime = nullptr;
};

struct ParsedVarHighlight_ {
  AMDomain::var::VarRef ref = {};
  size_t local_end = 0;
  bool has_closing_brace = false;
  std::string zone_token = {};
};

struct VarShortcutDefine_ {
  size_t equal_pos = 0;
  size_t value_begin = 0;
  bool valid = false;
};

HighlightBuffer_ InitializeHighlightBuffer_(size_t size) {
  HighlightBuffer_ buffer = {};
  buffer.types.assign(size, AMTokenType::Common);
  buffer.priorities.assign(size, 0);
  return buffer;
}

void ApplyRange_(HighlightBuffer_ &buffer, size_t start, size_t end,
                 AMTokenType type) {
  const size_t size = buffer.types.size();
  if (start >= end || start >= size) {
    return;
  }
  if (end > size) {
    end = size;
  }

  const int priority = static_cast<int>(type);
  for (size_t i = start; i < end; ++i) {
    if (priority >= buffer.priorities[i]) {
      buffer.priorities[i] = priority;
      buffer.types[i] = type;
    }
  }
}

bool ShouldApplySemanticTokenType_(AMTokenType type) {
  switch (type) {
  case AMTokenType::IllegalCommand:
  case AMTokenType::Nickname:
  case AMTokenType::DisconnectedNickname:
  case AMTokenType::UnestablishedNickname:
  case AMTokenType::NonexistentNickname:
  case AMTokenType::BuiltinArg:
  case AMTokenType::NonexistentBuiltinArg:
  case AMTokenType::ValidValue:
  case AMTokenType::InvalidValue:
  case AMTokenType::ValidNewNickname:
  case AMTokenType::InvalidNewNickname:
  case AMTokenType::TerminalName:
  case AMTokenType::DisconnectedTerminalName:
  case AMTokenType::UnestablishedTerminalName:
  case AMTokenType::NonexistentTerminalName:
  case AMTokenType::ChannelName:
  case AMTokenType::DisconnectedChannelName:
  case AMTokenType::NonexistentChannelName:
  case AMTokenType::ValidNewChannelName:
  case AMTokenType::InvalidNewChannelName:
  case AMTokenType::Path:
  case AMTokenType::Nonexistentpath:
  case AMTokenType::File:
  case AMTokenType::Dir:
  case AMTokenType::Symlink:
  case AMTokenType::Special:
    return true;
  default:
    return false;
  }
}

std::array<std::string, kTokenTypeCount_>
BuildStyleTags_(std::shared_ptr<ITokenAnalyzerRuntime> runtime) {
  std::array<std::string, kTokenTypeCount_> style_tags = {};
  for (size_t i = 0; i < kTokenTypeCount_; ++i) {
    style_tags[i] = ResolveStyleTagForType_(runtime, static_cast<AMTokenType>(i));
  }
  return style_tags;
}

void RenderFormattedOutput_(const std::string &input,
                            const HighlightBuffer_ &buffer,
                            std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                            std::string *formatted) {
  if (!formatted) {
    return;
  }

  const auto style_tags = BuildStyleTags_(runtime);
  formatted->reserve(input.size() + 16);
  std::string current_tag = {};
  for (size_t i = 0; i < input.size(); ++i) {
    const AMTokenType cur_type = buffer.types[i];
    if (IsPathRenderType_(cur_type)) {
      size_t end = i + 1;
      while (end < input.size() && buffer.types[end] == cur_type) {
        ++end;
      }
      if (!current_tag.empty()) {
        formatted->append("[/]");
        current_tag.clear();
      }
      formatted->append(
          FormatPathSegment_(runtime, input.substr(i, end - i), cur_type));
      i = end - 1;
      continue;
    }

    const std::string &tag = style_tags[static_cast<size_t>(cur_type)];
    if (tag != current_tag) {
      if (!current_tag.empty()) {
        formatted->append("[/]");
      }
      if (!tag.empty()) {
        formatted->append(tag);
      }
      current_tag = tag;
    }
    AppendEscapedBbcodeChar_(*formatted, input[i]);
  }
  if (!current_tag.empty()) {
    formatted->append("[/]");
  }
}

void HighlightEscapeSigns_(const HighlightContext_ &context,
                           HighlightBuffer_ &buffer) {
  if (!context.input || context.input->empty()) {
    return;
  }

  const std::string &input = *context.input;
  for (size_t i = 0; i + 1 < input.size(); ++i) {
    if (input[i] != '`') {
      continue;
    }
    const char next = input[i + 1];
    if (next != '$' && next != '@' && next != '"' && next != '\'' &&
        next != '`') {
      continue;
    }
    ApplyRange_(buffer, i, i + 2, AMTokenType::EscapeSign);
    ++i;
  }
}

void HighlightQuotedTokens_(const HighlightContext_ &context,
                            HighlightBuffer_ &buffer) {
  if (!context.tokens) {
    return;
  }

  for (const auto &token : *context.tokens) {
    if (token.quoted) {
      ApplyRange_(buffer, token.start, token.end, AMTokenType::String);
    }
  }
}

void HighlightSemanticTokenRanges_(const HighlightContext_ &context,
                                   HighlightBuffer_ &buffer) {
  if (!context.tokens) {
    return;
  }

  for (const auto &token : *context.tokens) {
    if (token.quoted || !ShouldApplySemanticTokenType_(token.type)) {
      continue;
    }
    ApplyRange_(buffer, token.start, token.end, token.type);
  }
}

void HighlightCommandsAndOptions_(const HighlightContext_ &context,
                                  HighlightBuffer_ &buffer) {
  if (!context.tokens) {
    return;
  }

  for (const auto &token : *context.tokens) {
    if (token.quoted) {
      continue;
    }
    if (token.type == AMTokenType::Module || token.type == AMTokenType::Command ||
        token.type == AMTokenType::Option) {
      ApplyRange_(buffer, token.start, token.end, token.type);
    }
  }
}

void HighlightNicknameAtSigns_(const HighlightContext_ &context,
                               HighlightBuffer_ &buffer) {
  if (!context.tokens || !context.input) {
    return;
  }

  const std::string &input = *context.input;
  for (const auto &token : *context.tokens) {
    if (token.start >= input.size()) {
      continue;
    }

    const std::string text = input.substr(token.start, token.end - token.start);
    size_t prefix_offset = 0;
    if (token.start < token.end && IsQuotedChar(input[token.start])) {
      prefix_offset = 1;
    }
    if (prefix_offset >= text.size()) {
      continue;
    }

    const std::string scan = text.substr(prefix_offset);
    const size_t at_pos_local = FindUnescapedChar(scan, '@');
    if (at_pos_local == std::string::npos) {
      continue;
    }
    if (at_pos_local == 0) {
      if (IsChannelTokenType_(token.type)) {
        ApplyRange_(buffer, token.start + prefix_offset,
                    token.start + prefix_offset + 1, AMTokenType::AtSign);
      }
      continue;
    }

    const size_t at_pos = prefix_offset + at_pos_local;
    const std::string prefix =
        UnescapeBackticks(scan.substr(0, at_pos_local), true);
    if (prefix.empty()) {
      continue;
    }

    const size_t nick_start = token.start + prefix_offset;
    const size_t nick_end = token.start + at_pos;
    const size_t at_index = nick_end;
    AMTokenType nick_type = ClassifyNicknameTokenType(context.runtime, prefix);
    if (context.runtime && IsChannelTokenType_(token.type)) {
      nick_type = TerminalTokenTypeFromState(
          context.runtime->QueryTerminalNameState(prefix));
    }
    ApplyRange_(buffer, nick_start, nick_end, nick_type);
    ApplyRange_(buffer, at_index, at_index + 1, AMTokenType::AtSign);
  }
}

std::optional<ParsedVarHighlight_> ParseVarHighlight_(
    const std::string &token) {
  size_t parsed_end = 0;
  ParsedVarHighlight_ parsed = {};
  if (!AMDomain::var::ParseVarRefAt(token, 0, token.size(), true, true,
                                    &parsed_end, &parsed.ref) ||
      !parsed.ref.valid || parsed_end == 0) {
    return std::nullopt;
  }

  parsed.local_end = std::min(parsed_end, token.size());
  parsed.has_closing_brace = parsed.ref.braced && parsed.local_end > 0 &&
                             token[parsed.local_end - 1] == '}';
  if (!parsed.ref.explicit_domain) {
    return parsed;
  }

  size_t body_begin = parsed.ref.braced ? 2 : 1;
  size_t body_end = parsed.local_end;
  if (parsed.has_closing_brace && body_end > 0) {
    --body_end;
  }
  if (body_end <= body_begin || body_begin >= token.size()) {
    return parsed;
  }

  const std::string body = token.substr(body_begin, body_end - body_begin);
  const size_t colon = body.find(':');
  if (colon != std::string::npos) {
    parsed.zone_token = body.substr(0, colon);
  }
  return parsed;
}

void HighlightSingleVarToken_(const HighlightContext_ &context,
                              HighlightBuffer_ &buffer, size_t token_start,
                              size_t token_end) {
  if (!context.input || token_end <= token_start ||
      token_start >= context.input->size()) {
    return;
  }

  const size_t bounded_end = std::min(token_end, context.input->size());
  const std::string token = context.input->substr(token_start,
                                                  bounded_end - token_start);
  const auto parsed = ParseVarHighlight_(token);
  if (!parsed.has_value()) {
    return;
  }

  ApplyRange_(buffer, token_start, token_start + 1, AMTokenType::DollarSign);
  size_t cursor = token_start + 1;
  if (parsed->ref.braced && cursor < token_start + parsed->local_end) {
    ApplyRange_(buffer, cursor, cursor + 1, AMTokenType::LeftBraceSign);
    ++cursor;
  }

  if (parsed->ref.explicit_domain) {
    const size_t zone_begin = cursor;
    const size_t zone_end =
        std::min(zone_begin + parsed->zone_token.size(), token_start + parsed->local_end);
    if (zone_end > zone_begin) {
      const AMTokenType zone_type =
          ClassifyVarZoneTokenType(context.runtime, parsed->zone_token);
      ApplyRange_(buffer, zone_begin, zone_end, zone_type);
    }
    cursor = zone_end;
    if (cursor < token_start + parsed->local_end) {
      ApplyRange_(buffer, cursor, cursor + 1, AMTokenType::ColonSign);
      ++cursor;
    }
  }

  const AMTokenType var_type = [&]() {
    if (parsed->ref.varname.empty()) {
      return AMTokenType::VarNameMissing;
    }
    if (parsed->ref.explicit_domain && context.runtime) {
      auto scoped = context.runtime->GetVar(parsed->ref.domain, parsed->ref.varname);
      return (scoped.rcm) ? AMTokenType::VarName : AMTokenType::VarNameMissing;
    }
    return VarNameTypeFor(context.runtime, parsed->ref.varname);
  }();

  const size_t var_end = std::min(cursor + parsed->ref.varname.size(),
                                  token_start + parsed->local_end);
  if (var_end > cursor) {
    ApplyRange_(buffer, cursor, var_end, var_type);
  }

  if (parsed->ref.braced && parsed->has_closing_brace &&
      token_start + parsed->local_end > token_start) {
    const size_t close_pos = token_start + parsed->local_end - 1;
    if (close_pos >= token_start + 1) {
      ApplyRange_(buffer, close_pos, close_pos + 1,
                  AMTokenType::RightBraceSign);
    }
  }
}

void HighlightVarReferences_(const HighlightContext_ &context,
                             HighlightBuffer_ &buffer) {
  if (!context.input || context.input->empty()) {
    return;
  }

  const std::string &input = *context.input;
  for (size_t i = 0; i < input.size(); ++i) {
    if (input[i] == '`' && i + 1 < input.size() && input[i + 1] == '$') {
      ++i;
      continue;
    }
    if (input[i] != '$') {
      continue;
    }

    size_t end = 0;
    if (!ParseVarTokenAt(input, i, input.size(), &end)) {
      continue;
    }
    HighlightSingleVarToken_(context, buffer, i, end);
    i = end - 1;
  }
}

std::optional<VarShortcutDefine_>
FindVarShortcutDefine_(const HighlightContext_ &context) {
  if (!context.tokens || !context.input || context.tokens->empty()) {
    return std::nullopt;
  }

  const std::string &input = *context.input;
  const size_t size = input.size();
  const auto &tokens = *context.tokens;
  const auto &first = tokens.front();
  if (first.quoted || first.content_start >= size ||
      first.content_end <= first.content_start || first.content_end > size) {
    return std::nullopt;
  }

  size_t var_end = 0;
  if (!ParseVarTokenAt(input, first.content_start, first.content_end, &var_end)) {
    return std::nullopt;
  }

  VarShortcutDefine_ define = {};
  if (var_end < first.content_end && input[var_end] == '=') {
    define.equal_pos = var_end;
    define.value_begin = var_end + 1;
    define.valid = true;
    return define;
  }
  if (tokens.size() < 2) {
    return std::nullopt;
  }

  const auto &second = tokens[1];
  if (second.quoted || second.content_start >= size ||
      second.content_end <= second.content_start || second.content_end > size) {
    return std::nullopt;
  }

  const std::string second_text =
      input.substr(second.content_start, second.content_end - second.content_start);
  if (second_text == "=") {
    define.equal_pos = second.content_start;
    define.value_begin = size;
    if (tokens.size() >= 3 && tokens[2].content_start < size) {
      define.value_begin = tokens[2].content_start;
    }
    define.valid = true;
    return define;
  }
  if (!second_text.empty() && second_text.front() == '=') {
    define.equal_pos = second.content_start;
    define.value_begin = second.content_start + 1;
    define.valid = true;
    return define;
  }

  return std::nullopt;
}

void ApplyVarShortcutDefine_(HighlightBuffer_ &buffer,
                             const VarShortcutDefine_ &define) {
  if (!define.valid) {
    return;
  }

  ApplyRange_(buffer, define.equal_pos, define.equal_pos + 1,
              AMTokenType::EqualSign);
  ApplyRange_(buffer, define.value_begin, buffer.types.size(),
              AMTokenType::VarValue);
}

void HighlightVars_(const HighlightContext_ &context, HighlightBuffer_ &buffer) {
  HighlightVarReferences_(context, buffer);
  const auto define = FindVarShortcutDefine_(context);
  if (define.has_value()) {
    ApplyVarShortcutDefine_(buffer, *define);
  }
}

void HighlightShellMode_(const HighlightContext_ &context,
                         HighlightBuffer_ &buffer) {
  if (!context.input) {
    return;
  }

  const std::string &input = *context.input;
  size_t shell_head = 0;
  while (shell_head < input.size() && AMStr::IsWhitespace(input[shell_head])) {
    ++shell_head;
  }

  if (shell_head >= input.size() || input[shell_head] != '!') {
    return;
  }

  ApplyRange_(buffer, shell_head, shell_head + 1, AMTokenType::BangSign);
  if (shell_head + 1 < input.size()) {
    ApplyRange_(buffer, shell_head + 1, input.size(), AMTokenType::ShellCmd);
  }
}

class TokenHighlightFormatter final {
public:
  TokenHighlightFormatter(const CommandNode *command_tree,
                          std::shared_ptr<ITokenAnalyzerRuntime> runtime)
      : command_tree_(command_tree), runtime_(std::move(runtime)) {}

  void Format(const std::string &input,
              const std::vector<AMInterface::parser::model::RawToken> &tokens,
              std::string *formatted) const {
    if (!formatted) {
      return;
    }
    formatted->clear();
    const size_t size = input.size();
    if (size == 0) {
      return;
    }

    HighlightContext_ context = {};
    context.input = &input;
    context.tokens = &tokens;
    context.command_tree = command_tree_;
    context.runtime = runtime_;

    HighlightBuffer_ buffer = InitializeHighlightBuffer_(size);
    HighlightEscapeSigns_(context, buffer);
    HighlightQuotedTokens_(context, buffer);
    HighlightSemanticTokenRanges_(context, buffer);
    HighlightCommandsAndOptions_(context, buffer);
    HighlightNicknameAtSigns_(context, buffer);
    HighlightVars_(context, buffer);
    HighlightShellMode_(context, buffer);

    RenderFormattedOutput_(input, buffer, runtime_, formatted);
  }

private:
  const CommandNode *command_tree_ = nullptr;
  std::shared_ptr<ITokenAnalyzerRuntime> runtime_ = nullptr;
};

} // namespace

void FormatHighlightedInput(
    const std::string &input,
    const std::vector<AMInterface::parser::model::RawToken> &tokens,
    const AMInterface::parser::CommandNode *command_tree,
    std::shared_ptr<AMInterface::parser::ITokenAnalyzerRuntime> runtime,
    std::string *formatted) {
  TokenHighlightFormatter formatter(command_tree, std::move(runtime));
  formatter.Format(input, tokens, formatted);
}

} // namespace AMInterface::parser::highlight


