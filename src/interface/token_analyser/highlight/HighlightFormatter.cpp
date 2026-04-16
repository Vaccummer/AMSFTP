#include "interface/token_analyser/highlight/HighlightFormatter.hpp"

#include "domain/host/HostDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntime.hpp"
#include "interface/token_analyser/shared/InputTextRules.hpp"
#include <algorithm>
#include <array>

namespace AMInterface::parser::highlight {
namespace {

bool IsLocalNickname_(const std::string &nickname) {
  return AMDomain::host::HostService::IsLocalNickname(nickname);
}

size_t FindUnescapedChar_(const std::string &text, char target) {
  return shared::FindUnescapedChar(text, target);
}

std::string UnescapeBackticks_(const std::string &text) {
  return shared::UnescapeBackticks(text, true);
}

inline bool IsQuoted(char c) { return shared::IsQuotedChar(c); }

AMTokenType
ClassifyNicknameTokenType_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                           const std::string &nickname_raw) {
  const std::string nickname = AMStr::Strip(nickname_raw);
  if (IsLocalNickname_(nickname)) {
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

AMTokenType ClassifyVarZoneTokenType_(
    std::shared_ptr<ITokenAnalyzerRuntime> runtime,
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

AMTokenType TerminalTokenTypeFromState_(
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

bool ParseVarTokenAt_(const std::string &input, size_t pos, size_t limit,
                      size_t *out_end) {
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

int PriorityForType_(AMTokenType type) {
  switch (type) {
  case AMTokenType::IllegalCommand:
    return 200;
  case AMTokenType::EscapeSign:
    return 100;
  case AMTokenType::BangSign:
    return 99;
  case AMTokenType::ShellCmd:
    return 98;
  case AMTokenType::EqualSign:
    return 95;
  case AMTokenType::VarValue:
    return 90;
  case AMTokenType::VarName:
  case AMTokenType::VarNameMissing:
  case AMTokenType::ValidValue:
  case AMTokenType::InvalidValue:
  case AMTokenType::ValidNewNickname:
  case AMTokenType::InvalidNewNickname:
  case AMTokenType::DollarSign:
  case AMTokenType::LeftBraceSign:
  case AMTokenType::RightBraceSign:
  case AMTokenType::ColonSign:
    return 80;
  case AMTokenType::AtSign:
  case AMTokenType::Nickname:
  case AMTokenType::DisconnectedNickname:
  case AMTokenType::UnestablishedNickname:
  case AMTokenType::NonexistentNickname:
  case AMTokenType::TerminalName:
  case AMTokenType::DisconnectedTerminalName:
  case AMTokenType::UnestablishedTerminalName:
  case AMTokenType::NonexistentTerminalName:
  case AMTokenType::ChannelName:
  case AMTokenType::DisconnectedChannelName:
  case AMTokenType::NonexistentChannelName:
  case AMTokenType::ValidNewChannelName:
  case AMTokenType::InvalidNewChannelName:
    return 70;
  case AMTokenType::BuiltinArg:
  case AMTokenType::NonexistentBuiltinArg:
    return 65;
  case AMTokenType::Option:
    return 60;
  case AMTokenType::Module:
  case AMTokenType::Command:
    return 50;
  case AMTokenType::Path:
  case AMTokenType::Nonexistentpath:
  case AMTokenType::File:
  case AMTokenType::Dir:
  case AMTokenType::Symlink:
  case AMTokenType::Special:
    return 40;
  case AMTokenType::String:
    return 20;
  case AMTokenType::Common:
  default:
    return 0;
  }
}

AMTokenType VarNameTypeFor_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
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

bool IsValidOptionToken_(const std::string &token, const CommandNode *node) {
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

    std::vector<AMTokenType> types(size, AMTokenType::Common);
    std::vector<int> priorities(size, 0);

    auto apply_range = [&](size_t start, size_t end, AMTokenType type) {
      if (start >= end || start >= size) {
        return;
      }
      if (end > size) {
        end = size;
      }
      const int priority = PriorityForType_(type);
      for (size_t i = start; i < end; ++i) {
        if (priority >= priorities[i]) {
          priorities[i] = priority;
          types[i] = type;
        }
      }
    };

    auto highlight_var_token = [&](size_t token_start, size_t token_end) {
      if (token_end <= token_start || token_start >= input.size()) {
        return;
      }
      if (token_end > input.size()) {
        token_end = input.size();
      }
      const std::string token =
          input.substr(token_start, token_end - token_start);
      size_t parsed_end = 0;
      AMDomain::var::VarRef ref = {};
      if (!AMDomain::var::ParseVarRefAt(token, 0, token.size(), true, true,
                                        &parsed_end, &ref) ||
          !ref.valid || parsed_end == 0) {
        return;
      }

      const size_t local_end = std::min(parsed_end, token.size());
      const bool braced = ref.braced;
      const bool explicit_domain = ref.explicit_domain;
      const std::string varname = ref.varname;
      const bool has_closing_brace =
          braced && local_end > 0 && token[local_end - 1] == '}';
      std::string zone_token = {};
      if (explicit_domain) {
        size_t body_begin = braced ? 2 : 1;
        size_t body_end = local_end;
        if (has_closing_brace && body_end > 0) {
          --body_end;
        }
        if (body_end > body_begin && body_begin < token.size()) {
          const std::string body =
              token.substr(body_begin, body_end - body_begin);
          const size_t colon = body.find(':');
          if (colon != std::string::npos) {
            zone_token = body.substr(0, colon);
          }
        }
      }

      apply_range(token_start, token_start + 1, AMTokenType::DollarSign);
      size_t cursor = token_start + 1;

      if (braced && cursor < token_start + local_end) {
        apply_range(cursor, cursor + 1, AMTokenType::LeftBraceSign);
        ++cursor;
      }

      if (explicit_domain) {
        const size_t zone_begin = cursor;
        const size_t zone_end =
            std::min(zone_begin + zone_token.size(), token_start + local_end);
        if (zone_end > zone_begin) {
          const AMTokenType zone_type =
              ClassifyVarZoneTokenType_(runtime_, zone_token);
          apply_range(zone_begin, zone_end, zone_type);
        }
        cursor = zone_end;
        if (cursor < token_start + local_end) {
          apply_range(cursor, cursor + 1, AMTokenType::ColonSign);
          ++cursor;
        }
      }

      const AMTokenType var_type = [&]() {
        if (varname.empty()) {
          return AMTokenType::VarNameMissing;
        }
        if (explicit_domain && runtime_) {
          auto scoped = runtime_->GetVar(ref.domain, varname);
          return (scoped.rcm) ? AMTokenType::VarName
                              : AMTokenType::VarNameMissing;
        }
        return VarNameTypeFor_(runtime_, varname);
      }();

      const size_t var_end =
          std::min(cursor + varname.size(), token_start + local_end);
      if (var_end > cursor) {
        apply_range(cursor, var_end, var_type);
        cursor = var_end;
      }

      if (braced && has_closing_brace && token_start + local_end > token_start) {
        const size_t close_pos = token_start + local_end - 1;
        if (close_pos >= token_start + 1) {
          apply_range(close_pos, close_pos + 1, AMTokenType::RightBraceSign);
        }
      }
    };

    auto highlight_var_references = [&]() {
      if (input.empty()) {
        return;
      }
      for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '`' && i + 1 < input.size() && input[i + 1] == '$') {
          ++i;
          continue;
        }
        if (input[i] != '$') {
          continue;
        }
        size_t end = 0;
        if (!ParseVarTokenAt_(input, i, input.size(), &end)) {
          continue;
        }
        highlight_var_token(i, end);
        i = end - 1;
      }
    };

    auto highlight_var_shortcut_define = [&]() {
      if (tokens.empty()) {
        return;
      }
      const auto &first = tokens.front();
      if (first.quoted || first.content_start >= size ||
          first.content_end <= first.content_start || first.content_end > size) {
        return;
      }
      size_t var_end = 0;
      if (!ParseVarTokenAt_(input, first.content_start, first.content_end,
                            &var_end)) {
        return;
      }

      auto apply_define_tail = [&](size_t eq_pos, size_t value_begin) {
        if (eq_pos < size) {
          apply_range(eq_pos, eq_pos + 1, AMTokenType::EqualSign);
        }
        if (value_begin < size) {
          apply_range(value_begin, size, AMTokenType::VarValue);
        }
      };

      if (var_end < first.content_end && input[var_end] == '=') {
        apply_define_tail(var_end, var_end + 1);
        return;
      }
      if (tokens.size() < 2) {
        return;
      }

      const auto &second = tokens[1];
      if (second.quoted || second.content_start >= size ||
          second.content_end <= second.content_start ||
          second.content_end > size) {
        return;
      }
      const std::string second_text = input.substr(
          second.content_start, second.content_end - second.content_start);
      if (second_text == "=") {
        size_t value_begin = size;
        if (tokens.size() >= 3) {
          const auto &value_token = tokens[2];
          if (value_token.content_start < size) {
            value_begin = value_token.content_start;
          }
        }
        apply_define_tail(second.content_start, value_begin);
        return;
      }
      if (!second_text.empty() && second_text.front() == '=') {
        apply_define_tail(second.content_start, second.content_start + 1);
      }
    };

    auto highlight_escape_signs = [&]() {
      if (input.empty()) {
        return;
      }
      for (size_t i = 0; i + 1 < input.size(); ++i) {
        if (input[i] != '`') {
          continue;
        }
        const char next = input[i + 1];
        if (next != '$' && next != '@' && next != '"' && next != '\'' &&
            next != '`') {
          continue;
        }
        apply_range(i, i + 2, AMTokenType::EscapeSign);
        ++i;
      }
    };

    auto highlight_nickname_at_sign = [&]() {
      for (const auto &token : tokens) {
        if (token.start >= input.size()) {
          continue;
        }
        const std::string text = input.substr(token.start, token.end - token.start);
        size_t prefix_offset = 0;
        if (token.start < token.end && IsQuoted(input[token.start])) {
          prefix_offset = 1;
        }
        if (prefix_offset >= text.size()) {
          continue;
        }
        const std::string scan = text.substr(prefix_offset);
        const size_t at_pos_local = FindUnescapedChar_(scan, '@');
        if (at_pos_local == std::string::npos) {
          continue;
        }
        if (at_pos_local == 0) {
          if (IsChannelTokenType_(token.type)) {
            apply_range(token.start + prefix_offset, token.start + prefix_offset + 1,
                        AMTokenType::AtSign);
          }
          continue;
        }
        const size_t at_pos = prefix_offset + at_pos_local;
        const std::string prefix = UnescapeBackticks_(scan.substr(0, at_pos_local));
        if (prefix.empty()) {
          continue;
        }
        const size_t nick_start = token.start + prefix_offset;
        const size_t nick_end = token.start + at_pos;
        const size_t at_index = nick_end;
        AMTokenType nick_type = ClassifyNicknameTokenType_(runtime_, prefix);
        if (runtime_ && IsChannelTokenType_(token.type)) {
          nick_type = TerminalTokenTypeFromState_(
              runtime_->QueryTerminalNameState(prefix));
        }
        apply_range(nick_start, nick_end, nick_type);
        apply_range(at_index, at_index + 1, AMTokenType::AtSign);
      }
    };

    auto highlight_commands_and_options = [&]() {
      const CommandNode *node = nullptr;
      std::string path = {};
      if (!command_tree_) {
        return;
      }
      for (const auto &token : tokens) {
        if (token.quoted) {
          continue;
        }
        const std::string text = input.substr(token.start, token.end - token.start);
        if (text.empty()) {
          continue;
        }
        if (path.empty()) {
          if (command_tree_->IsModule(text)) {
            apply_range(token.start, token.end, AMTokenType::Module);
            path = text;
            node = command_tree_->FindNode(path);
            continue;
          }
          if (command_tree_->IsTopCommand(text)) {
            apply_range(token.start, token.end, AMTokenType::Command);
            path = text;
            node = command_tree_->FindNode(path);
            continue;
          }
          continue;
        }
        if (node && node->subcommands.contains(text)) {
          apply_range(token.start, token.end, AMTokenType::Command);
          path += " " + text;
          node = command_tree_->FindNode(path);
        }
      }

      if (!node) {
        return;
      }
      for (const auto &token : tokens) {
        if (token.quoted) {
          continue;
        }
        const std::string text = input.substr(token.start, token.end - token.start);
        if (IsValidOptionToken_(text, node)) {
          apply_range(token.start, token.end, AMTokenType::Option);
        }
      }
    };

    highlight_escape_signs();
    for (const auto &token : tokens) {
      if (token.quoted) {
        apply_range(token.start, token.end, AMTokenType::String);
      }
    }
    for (const auto &token : tokens) {
      if (token.quoted) {
        continue;
      }
      switch (token.type) {
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
        apply_range(token.start, token.end, token.type);
        break;
      default:
        break;
      }
    }

    highlight_commands_and_options();
    highlight_nickname_at_sign();
    highlight_var_references();
    highlight_var_shortcut_define();

    size_t shell_head = 0;
    while (shell_head < size && AMStr::IsWhitespace(input[shell_head])) {
      ++shell_head;
    }
    const bool shell_mode = shell_head < size && input[shell_head] == '!';
    if (shell_mode) {
      apply_range(shell_head, shell_head + 1, AMTokenType::BangSign);
      if (shell_head + 1 < size) {
        apply_range(shell_head + 1, size, AMTokenType::ShellCmd);
      }
    }

    constexpr size_t kTokenTypeCount =
        static_cast<size_t>(AMTokenType::InvalidNewChannelName) + 1;
    std::array<std::string, kTokenTypeCount> style_tags = {};
    for (size_t i = 0; i < kTokenTypeCount; ++i) {
      style_tags[i] =
          ResolveStyleTagForType_(runtime_, static_cast<AMTokenType>(i));
    }

    formatted->reserve(input.size() + 16);
    std::string current_tag = {};
    for (size_t i = 0; i < size; ++i) {
      const AMTokenType cur_type = types[i];
      if (IsPathRenderType_(cur_type)) {
        size_t end = i + 1;
        while (end < size && types[end] == cur_type) {
          ++end;
        }
        if (!current_tag.empty()) {
          formatted->append("[/]");
          current_tag.clear();
        }
        formatted->append(
            FormatPathSegment_(runtime_, input.substr(i, end - i), cur_type));
        i = end - 1;
        continue;
      }

      const std::string &tag = style_tags[static_cast<size_t>(types[i])];
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


