#include "interface/parser/TokenTypeAnalyzer.hpp"

#include "domain/host/HostDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/cli/InteractiveEventRegistry.hpp"
#include "interface/parser/CommandTree.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <unordered_map>

namespace AMInterface::parser {
namespace {

using AMDomain::var::VarInfo;
using TokenCacheValue = std::vector<TokenTypeAnalyzer::AMToken>;
std::unordered_map<std::string, TokenCacheValue> g_split_token_cache = {};

/** Return true when nickname resolves to local-client scope. */
bool IsLocalNickname_(const std::string &nickname) {
  return AMDomain::host::HostService::IsLocalNickname(nickname);
}

/** Find first unescaped character in text. */
size_t FindUnescapedChar_(const std::string &text, char target) {
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '`' && i + 1 < text.size()) {
      ++i;
      continue;
    }
    if (text[i] == target) {
      return i;
    }
  }
  return std::string::npos;
}

/** Remove backtick escapes for special characters used by tokenizer. */
std::string UnescapeBackticks_(const std::string &text) {
  if (text.empty()) {
    return text;
  }
  std::string out = {};
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '`' && i + 1 < text.size()) {
      const char next = text[i + 1];
      if (next == '$' || next == '@' || next == '"' || next == '\'' ||
          next == '`') {
        out.push_back(next);
        ++i;
        continue;
      }
    }
    out.push_back(text[i]);
  }
  return out;
}

/** Return true when text looks like path input. */
bool IsPathLikeText_(const std::string &text) {
  if (text.empty()) {
    return false;
  }
  if (text[0] == '/' || text[0] == '\\' || text[0] == '~' || text[0] == '.') {
    return true;
  }
  if (text.size() >= 2 && std::isalpha(static_cast<unsigned char>(text[0])) &&
      text[1] == ':') {
    return true;
  }
  return text.find('/') != std::string::npos ||
         text.find('\\') != std::string::npos;
}

/** Return true when input contains a clear user-intended path sign. */
bool HasClearPathSign_(const std::string &text) {
  if (text.empty()) {
    return false;
  }
  if (text[0] == '@' || text[0] == '~' || text[0] == '/' || text[0] == '\\' ||
      text[0] == '.') {
    return true;
  }
  if (text.size() >= 2 && std::isalpha(static_cast<unsigned char>(text[0])) &&
      text[1] == ':') {
    return true;
  }
  return text.find('/') != std::string::npos ||
         text.find('\\') != std::string::npos;
}

/** Return true if string begins with "--". */
bool StartsWithLongOption_(const std::string &text) {
  return text.size() >= 2 && text[0] == '-' && text[1] == '-';
}

/** Return true if string begins with "-" but not "--". */
bool StartsWithShortOption_(const std::string &text) {
  return text.size() >= 1 && text[0] == '-' &&
         !(text.size() >= 2 && text[1] == '-');
}

/** Return true when semantic value indicates a path token. */
bool IsPathSemantic_(AMCommandArgSemantic semantic) {
  return semantic == AMCommandArgSemantic::Path;
}

/** Convert nickname classification into token highlight type. */
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
  if (runtime->GetClient(nickname)) {
    return AMTokenType::Nickname;
  }
  if (runtime->HostExists(nickname)) {
    return AMTokenType::UnestablishedNickname;
  }
  return AMTokenType::NonexistentNickname;
}

/** Convert new-host-nickname token to valid/invalid highlight type. */
AMTokenType
ClassifyNewHostNicknameTokenType_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                                  const std::string &nickname_raw) {
  const std::string nickname = AMStr::Strip(nickname_raw);
  ECM validate_rcm = AMDomain::host::HostService::ValidateFieldValue(
      AMDomain::host::ConRequest::Attr::nickname, nickname);
  if (!isok(validate_rcm)) {
    return AMTokenType::InvalidValue;
  }
  if (AMDomain::host::HostService::IsLocalNickname(nickname)) {
    return AMTokenType::InvalidValue;
  }
  if (runtime && runtime->HostExists(nickname)) {
    return AMTokenType::InvalidValue;
  }
  return AMTokenType::ValidValue;
}

/** Convert var-zone token to highlight type. */
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

/** Return true when token text is `$var=...` or `${var}=...` shorthand. */
bool IsVarShortcutDefineToken_(const std::string &raw_text) {
  if (raw_text.size() >= 2 && raw_text[0] == '`' && raw_text[1] == '$') {
    return false;
  }
  const std::string text = UnescapeBackticks_(raw_text);
  if (text.size() < 3 || text.front() != '$') {
    return false;
  }
  const size_t eq = text.find('=');
  if (eq == std::string::npos || eq <= 1) {
    return false;
  }
  const std::string lhs = text.substr(0, eq);
  return AMDomain::var::ParseVarToken(lhs);
}

/** Convert concrete filesystem type to path token variants. */
AMTokenType ToPathTokenType_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return AMTokenType::File;
  case PathType::DIR:
    return AMTokenType::Dir;
  case PathType::SYMLINK:
    return AMTokenType::Symlink;
  default:
    return AMTokenType::Special;
  }
}

/** Convert timeout value to int for client API calls. */
int ToClientTimeoutMs_(size_t timeout_ms, int fallback_ms) {
  if (timeout_ms == 0) {
    return fallback_ms;
  }
  constexpr size_t kIntMax =
      static_cast<size_t>(std::numeric_limits<int>::max());
  if (timeout_ms > kIntMax) {
    return std::numeric_limits<int>::max();
  }
  return static_cast<int>(timeout_ms);
}

/** Return true when the character begins or ends a quoted string token. */
inline bool IsQuoted(char c) { return c == '"' || c == '\''; }

/** Normalize configured style to bbcode opening tag. */
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

/** Append one character escaped for bbcode parsing. */
void AppendEscapedBbcodeChar_(std::string &out, char c) {
  if (c == '\\') {
    out.append("\\\\");
  } else if (c == '[') {
    out.append("\\[");
  } else {
    out.push_back(c);
  }
}

/** Resolve style key by token type. */
std::string StyleKeyForType_(AMTokenType type) {
  switch (type) {
  case AMTokenType::Module:
    return "module";
  case AMTokenType::Command:
    return "command";
  case AMTokenType::VarName:
    return "public_varname";
  case AMTokenType::VarNameMissing:
    return "nonexistent_varname";
  case AMTokenType::VarValue:
    return "varvalue";
  case AMTokenType::Nickname:
    return "nickname";
  case AMTokenType::UnestablishedNickname:
    return "unestablished_nickname";
  case AMTokenType::NonexistentNickname:
    return "nonexistent_nickname";
  case AMTokenType::BuiltinArg:
    return "builtin_arg";
  case AMTokenType::ValidValue:
    return "valid_new_nickname";
  case AMTokenType::InvalidValue:
    return "invalid_new_nickname";
  case AMTokenType::String:
    return "string";
  case AMTokenType::Option:
    return "option";
  case AMTokenType::AtSign:
    return "atsign";
  case AMTokenType::DollarSign:
    return "dollarsign";
  case AMTokenType::LeftBraceSign:
    return "leftbrace";
  case AMTokenType::RightBraceSign:
    return "rightbrace";
  case AMTokenType::ColonSign:
    return "colonsign";
  case AMTokenType::EqualSign:
    return "equalsign";
  case AMTokenType::EscapeSign:
    return "escapedsign";
  case AMTokenType::Path:
    return "path_like";
  case AMTokenType::Nonexistentpath:
    return "nonexistentpath";
  case AMTokenType::File:
    return "file";
  case AMTokenType::Dir:
    return "dir";
  case AMTokenType::Symlink:
    return "symlink";
  case AMTokenType::Special:
    return "special";
  case AMTokenType::BangSign:
    return "bangsign";
  case AMTokenType::ShellCmd:
    return "shell_cmd";
  case AMTokenType::IllegalCommand:
    return "illegal_command";
  case AMTokenType::Common:
  default:
    return "common";
  }
}

/** Resolve style tag for a token type with path-style fallback. */
std::string ResolveStyleTagForType_(
    std::shared_ptr<ITokenAnalyzerRuntime> runtime, AMTokenType type) {
  if (!runtime) {
    return "";
  }
  auto resolve_tag = [&](const std::vector<std::string> &path) {
    return NormalizeStyleTag_(runtime->ResolveSettingString(path, ""));
  };
  const std::string from_input =
      resolve_tag({"Style", "InputHighlight", StyleKeyForType_(type)});
  if (!from_input.empty()) {
    return from_input;
  }

  switch (type) {
  case AMTokenType::File:
    return resolve_tag({"Style", "Path", "regular"});
  case AMTokenType::Dir:
    return resolve_tag({"Style", "Path", "dir"});
  case AMTokenType::Symlink:
    return resolve_tag({"Style", "Path", "symlink"});
  case AMTokenType::Special:
    return resolve_tag({"Style", "Path", "otherspecial"});
  case AMTokenType::Nonexistentpath:
    return resolve_tag({"Style", "Path", "nonexistent"});
  default:
    return "";
  }
}

/** Return true if token type should be rendered using path formatter. */
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

/** Build path info used by path formatter for path token rendering. */
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

/** Render one path-like token segment through style formatter hook. */
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

/** Parse a variable token at one position within one limit. */
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

/** Validate full token as variable reference and optionally extract varname. */
bool ParseVarTokenText_(const std::string &token, std::string *out_name) {
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

/** Assign overlap resolution priority per token type. */
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
  case AMTokenType::DollarSign:
  case AMTokenType::LeftBraceSign:
  case AMTokenType::RightBraceSign:
  case AMTokenType::ColonSign:
    return 80;
  case AMTokenType::AtSign:
  case AMTokenType::Nickname:
  case AMTokenType::UnestablishedNickname:
  case AMTokenType::NonexistentNickname:
    return 70;
  case AMTokenType::BuiltinArg:
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

/** Resolve variable-name highlight type with current/public-domain fallback. */
AMTokenType VarNameTypeFor_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                            const std::string &name) {
  if (!runtime) {
    return AMTokenType::VarNameMissing;
  }
  const std::string domain = runtime->CurrentVarDomain();
  auto scoped = runtime->GetVar(domain, name);
  if (isok(scoped.rcm)) {
    return AMTokenType::VarName;
  }
  auto pub = runtime->GetVar(AMDomain::var::kPublic, name);
  return isok(pub.rcm) ? AMTokenType::VarName : AMTokenType::VarNameMissing;
}

/** Validate token against option set for one command node. */
bool IsValidOptionToken_(const std::string &token, const CommandNode *node) {
  if (!node || token.size() < 2 || token[0] != '-') {
    return false;
  }
  if (token.rfind("--", 0) == 0) {
    std::string name = token;
    const size_t eq = token.find('=');
    if (eq != std::string::npos) {
      name = token.substr(0, eq);
    }
    return node->long_options.find(name) != node->long_options.end();
  }
  if (token.size() < 2) {
    return false;
  }
  for (size_t i = 1; i < token.size(); ++i) {
    if (node->short_options.find(token[i]) == node->short_options.end()) {
      return false;
    }
  }
  return true;
}

/** Token split stage engine (whitespace + quote + backtick rules). */
class TokenSplitEngine final {
public:
  static std::vector<TokenTypeAnalyzer::AMToken>
  Split(const std::string &input) {
    std::vector<TokenTypeAnalyzer::AMToken> tokens = {};
    size_t i = 0;
    while (i < input.size()) {
      while (i < input.size() && AMStr::IsWhitespace(input[i])) {
        ++i;
      }
      if (i >= input.size()) {
        break;
      }

      TokenTypeAnalyzer::AMToken token = {};
      token.start = i;
      token.content_start = i;
      token.content_end = i;
      token.end = i;
      token.quoted = false;
      token.type = AMTokenType::Unset;

      char active_quote = 0;
      bool saw_quote = false;
      while (i < input.size()) {
        const char c = input[i];
        if (c == '`' && i + 1 < input.size()) {
          i += 2;
          continue;
        }
        if (active_quote != 0) {
          if (c == active_quote) {
            active_quote = 0;
            saw_quote = true;
          }
          ++i;
          continue;
        }
        if (IsQuoted(c)) {
          active_quote = c;
          saw_quote = true;
          ++i;
          continue;
        }
        if (AMStr::IsWhitespace(c)) {
          break;
        }
        ++i;
      }
      token.end = i;
      token.content_start = token.start;
      token.content_end = token.end;
      token.quoted = saw_quote;

      if (token.start < token.end && IsQuoted(input[token.start])) {
        const char outer_quote = input[token.start];
        size_t close = token.start + 1;
        bool found_close = false;
        while (close < token.end) {
          if (input[close] == '`' && close + 1 < token.end) {
            close += 2;
            continue;
          }
          if (input[close] == outer_quote) {
            found_close = true;
            break;
          }
          ++close;
        }

        token.quoted = true;
        if (found_close && close + 1 == token.end) {
          token.content_start = token.start + 1;
          token.content_end = close;
        } else if (!found_close) {
          token.content_start = std::min(token.start + 1, token.end);
          token.content_end = token.end;
        }
      }

      tokens.push_back(token);
    }
    return tokens;
  }
};

/** Semantic token classifier stage (command/options/nickname/path/var). */
class TokenSemanticClassifier final {
public:
  TokenSemanticClassifier(const CommandNode *command_tree,
                          std::shared_ptr<ITokenAnalyzerRuntime> runtime)
      : command_tree_(command_tree), runtime_(std::move(runtime)) {}

  std::vector<TokenTypeAnalyzer::AMToken>
  Classify(const std::string &input,
           const std::vector<TokenTypeAnalyzer::AMToken> &split_tokens) const {
    std::vector<TokenTypeAnalyzer::AMToken> tokens = split_tokens;
    std::vector<std::string> texts = {};
    texts.reserve(tokens.size());
    for (const auto &token : tokens) {
      texts.push_back(input.substr(token.content_start,
                                   token.content_end - token.content_start));
    }

    for (auto &token : tokens) {
      token.type = token.quoted ? AMTokenType::String : AMTokenType::Common;
    }

    const CommandNode *node = nullptr;
    std::string command_path = {};
    size_t command_tokens = 0;
    if (command_tree_) {
      bool parsing = true;
      for (size_t idx = 0; idx < tokens.size(); ++idx) {
        auto &token = tokens[idx];
        if (token.quoted) {
          continue;
        }
        const std::string &text = texts[idx];
        if (text.empty()) {
          continue;
        }
        if (!parsing) {
          continue;
        }

        if (command_path.empty()) {
          if (command_tree_->IsModule(text)) {
            token.type = AMTokenType::Module;
            command_path = text;
            node = command_tree_->FindNode(command_path);
            command_tokens = idx + 1;
            continue;
          }
          if (command_tree_->IsTopCommand(text)) {
            token.type = AMTokenType::Command;
            command_path = text;
            node = command_tree_->FindNode(command_path);
            command_tokens = idx + 1;
            if (!node || node->subcommands.empty()) {
              parsing = false;
            }
            continue;
          }
          parsing = false;
          continue;
        }

        if (node && node->subcommands.find(text) != node->subcommands.end()) {
          token.type = AMTokenType::Command;
          command_path += " " + text;
          node = command_tree_->FindNode(command_path);
          command_tokens = idx + 1;
          if (!node || node->subcommands.empty()) {
            parsing = false;
          }
          continue;
        }
        parsing = false;
      }
    }

    if (command_tree_) {
      std::vector<size_t> legal_indexes = {};
      legal_indexes.reserve(tokens.size());
      const CommandNode *scan_node = nullptr;
      std::string scan_path = {};

      for (size_t idx = 0; idx < tokens.size(); ++idx) {
        if (tokens[idx].quoted) {
          continue;
        }
        const std::string &text = texts[idx];
        if (text.empty()) {
          continue;
        }

        if (scan_path.empty()) {
          if (command_tree_->IsModule(text)) {
            legal_indexes.push_back(idx);
            scan_path = text;
            scan_node = command_tree_->FindNode(scan_path);
            continue;
          }
          if (command_tree_->IsTopCommand(text)) {
            legal_indexes.push_back(idx);
            scan_path = text;
            scan_node = command_tree_->FindNode(scan_path);
            continue;
          }
          continue;
        }

        if (scan_node &&
            scan_node->subcommands.find(text) != scan_node->subcommands.end()) {
          legal_indexes.push_back(idx);
          scan_path += " " + text;
          scan_node = command_tree_->FindNode(scan_path);
        }
      }

      if (!legal_indexes.empty()) {
        size_t segment_begin = 0;
        for (size_t legal_index : legal_indexes) {
          for (size_t idx = segment_begin; idx < legal_index; ++idx) {
            if (tokens[idx].quoted || tokens[idx].type != AMTokenType::Common) {
              continue;
            }
            if (IsVarShortcutDefineToken_(texts[idx])) {
              continue;
            }
            tokens[idx].type = AMTokenType::IllegalCommand;
          }
          segment_begin = legal_index + 1;
        }
      }
    }

    if (node) {
      for (size_t idx = 0; idx < tokens.size(); ++idx) {
        auto &token = tokens[idx];
        if (token.quoted || token.type != AMTokenType::Common) {
          continue;
        }
        if (IsValidOptionToken_(texts[idx], node)) {
          token.type = AMTokenType::Option;
        }
      }
    }

    AMDomain::client::ClientHandle current_client =
        runtime_ ? runtime_->CurrentClient() : nullptr;
    std::string current_nickname = "local";
    if (current_client) {
      current_nickname = current_client->ConfigPort().GetNickname();
      if (current_nickname.empty()) {
        current_nickname = "local";
      }
    }

    std::optional<CommandNode::OptionValueRule> pending_value_rule = std::nullopt;
    size_t pending_value_index = 0;
    auto consume_option_value = [&]() -> std::optional<AMCommandArgSemantic> {
      if (!pending_value_rule.has_value()) {
        return std::nullopt;
      }
      const AMCommandArgSemantic semantic = pending_value_rule->semantic;
      ++pending_value_index;
      if (!pending_value_rule->repeat_tail &&
          pending_value_index >= pending_value_rule->value_count) {
        pending_value_rule.reset();
        pending_value_index = 0;
      }
      return semantic;
    };
    auto set_pending_option_value = [&](const CommandNode::OptionValueRule &rule,
                                        size_t consumed) {
      if (!rule.repeat_tail && consumed >= rule.value_count) {
        pending_value_rule.reset();
        pending_value_index = 0;
        return;
      }
      pending_value_rule = rule;
      pending_value_index = consumed;
    };

    size_t arg_index = 0;
    for (size_t idx = 0; idx < tokens.size(); ++idx) {
      auto &token = tokens[idx];
      if (idx < command_tokens) {
        continue;
      }

      const std::string &raw_text = texts[idx];
      if (raw_text.empty()) {
        continue;
      }

      bool positional_consumed = false;
      bool option_definition = false;
      const bool option_value_token = pending_value_rule.has_value();
      std::optional<AMCommandArgSemantic> semantic_hint = consume_option_value();

      if (!semantic_hint.has_value() && command_tree_ && !command_path.empty() &&
          !token.quoted) {
        if (StartsWithLongOption_(raw_text)) {
          option_definition = true;
          const size_t eq_pos = raw_text.find('=');
          const std::string option_name =
              eq_pos == std::string::npos ? raw_text : raw_text.substr(0, eq_pos);
          const auto rule = command_tree_->ResolveOptionValueRule(
              command_path, option_name, '\0', 0);
          if (rule.has_value()) {
            if (eq_pos == std::string::npos) {
              set_pending_option_value(*rule, 0);
            } else if (eq_pos + 1 < raw_text.size()) {
              set_pending_option_value(*rule, 1);
            } else {
              set_pending_option_value(*rule, 0);
            }
          }
        } else if (StartsWithShortOption_(raw_text)) {
          option_definition = true;
          const std::string body = raw_text.substr(1);
          for (size_t cidx = 0; cidx < body.size(); ++cidx) {
            const auto rule = command_tree_->ResolveOptionValueRule(
                command_path, "", body[cidx], 0);
            if (!rule.has_value()) {
              continue;
            }
            if (cidx + 1 < body.size()) {
              set_pending_option_value(*rule, 1);
            } else {
              set_pending_option_value(*rule, 0);
            }
            break;
          }
        }
      }

      if (!option_value_token && !semantic_hint.has_value() && !option_definition &&
          command_tree_ && !command_path.empty()) {
        semantic_hint =
            command_tree_->ResolvePositionalSemantic(command_path, arg_index);
        positional_consumed = true;
      } else if (!option_definition && !option_value_token) {
        positional_consumed = true;
      }

      if (token.quoted) {
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      if ((token.type == AMTokenType::Option || option_definition) &&
          !semantic_hint.has_value()) {
        continue;
      }

      const std::string unescaped_text = UnescapeBackticks_(raw_text);
      if (token.type == AMTokenType::Common && semantic_hint.has_value()) {
        if (*semantic_hint == AMCommandArgSemantic::HostNicknameNew) {
          const bool is_sftp_or_ftp =
              (command_path == "sftp" || command_path == "ftp");
          const bool is_user_at_host =
              FindUnescapedChar_(raw_text, '@') != std::string::npos;
          if (is_sftp_or_ftp && is_user_at_host) {
            if (positional_consumed) {
              ++arg_index;
            }
            continue;
          }
          token.type = ClassifyNewHostNicknameTokenType_(runtime_, unescaped_text);
          if (positional_consumed) {
            ++arg_index;
          }
          continue;
        }

        if (*semantic_hint == AMCommandArgSemantic::HostAttr ||
            *semantic_hint == AMCommandArgSemantic::TaskId) {
          token.type = AMTokenType::BuiltinArg;
          if (positional_consumed) {
            ++arg_index;
          }
          continue;
        }

        if (*semantic_hint == AMCommandArgSemantic::HostNickname ||
            *semantic_hint == AMCommandArgSemantic::ClientName) {
          token.type = ClassifyNicknameTokenType_(runtime_, unescaped_text);
          if (positional_consumed) {
            ++arg_index;
          }
          continue;
        }

        if (*semantic_hint == AMCommandArgSemantic::VarZone) {
          token.type = ClassifyVarZoneTokenType_(runtime_, unescaped_text);
          if (positional_consumed) {
            ++arg_index;
          }
          continue;
        }

        if (*semantic_hint == AMCommandArgSemantic::ShellCmd) {
          token.type = AMTokenType::ShellCmd;
          if (positional_consumed) {
            ++arg_index;
          }
          continue;
        }
      }

      AMDomain::var::VarRef ref = {};
      if (token.type == AMTokenType::Common &&
          AMDomain::var::ParseVarToken(raw_text, &ref) && ref.valid &&
          !ref.varname.empty()) {
        if (ref.explicit_domain && runtime_) {
          auto scoped = runtime_->GetVar(ref.domain, ref.varname);
          token.type = isok(scoped.rcm) ? AMTokenType::VarName
                                        : AMTokenType::VarNameMissing;
        } else {
          token.type = VarNameTypeFor_(runtime_, ref.varname);
        }
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      const size_t at_pos = FindUnescapedChar_(raw_text, '@');
      const bool has_unescaped_at = at_pos != std::string::npos;
      const bool force_path =
          semantic_hint.has_value() && IsPathSemantic_(*semantic_hint);
      const bool has_clear_path_sign =
          has_unescaped_at || HasClearPathSign_(unescaped_text);

      if (token.type == AMTokenType::Common && force_path &&
          !has_clear_path_sign) {
        const AMTokenType nick_type =
            ClassifyNicknameTokenType_(runtime_, unescaped_text);
        if (nick_type == AMTokenType::Nickname ||
            nick_type == AMTokenType::UnestablishedNickname) {
          token.type = nick_type;
          if (positional_consumed) {
            ++arg_index;
          }
          continue;
        }
      }

      const bool treat_as_path =
          force_path || has_clear_path_sign || IsPathLikeText_(unescaped_text);
      if (!treat_as_path) {
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      std::string nickname_for_cfg = current_nickname;
      std::string nickname_for_lookup = current_nickname;
      std::string path_part_raw = raw_text;
      bool explicit_target = false;
      bool explicit_local = false;

      if (!raw_text.empty() && raw_text.front() == '@') {
        explicit_target = true;
        explicit_local = true;
        nickname_for_cfg = "local";
        nickname_for_lookup = "local";
        path_part_raw = raw_text.substr(1);
      } else if (has_unescaped_at) {
        explicit_target = true;
        const std::string prefix_raw = raw_text.substr(0, at_pos);
        const std::string prefix = AMStr::Strip(UnescapeBackticks_(prefix_raw));
        path_part_raw = raw_text.substr(at_pos + 1);
        if (IsLocalNickname_(prefix)) {
          explicit_local = true;
          nickname_for_cfg = "local";
          nickname_for_lookup = "local";
        } else if (!prefix.empty()) {
          nickname_for_cfg = prefix;
          nickname_for_lookup = prefix;
        }
      } else if (IsLocalNickname_(current_nickname)) {
        nickname_for_cfg = "local";
        nickname_for_lookup = "local";
      }

      ITokenAnalyzerRuntime::PromptPathOptions profile = {};
      if (runtime_) {
        profile = runtime_->ResolvePromptPathOptions(nickname_for_cfg);
      }
      if (!profile.highlight_enable) {
        token.type = AMTokenType::Path;
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      AMDomain::client::ClientHandle path_client = nullptr;
      if (runtime_) {
        if (explicit_target) {
          if (explicit_local) {
            path_client = runtime_->LocalClient();
          } else {
            path_client = runtime_->GetClient(nickname_for_lookup);
          }
        } else {
          path_client = current_client ? current_client : runtime_->LocalClient();
        }
      }

      if (!runtime_ || !path_client) {
        token.type = AMTokenType::Nonexistentpath;
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      const std::string path_part_unescaped = UnescapeBackticks_(path_part_raw);
      const std::string path_part_resolved =
          runtime_->SubstitutePathLike(path_part_unescaped);
      const std::string abs_path = runtime_->BuildPath(path_client, path_part_resolved);
      const int timeout_ms =
          ToClientTimeoutMs_(profile.highlight_timeout_ms, 1000);

      auto stat_result = runtime_->StatPath(path_client, abs_path, timeout_ms);
      if (isok(stat_result.rcm)) {
        token.type = ToPathTokenType_(stat_result.data.type);
      } else if (stat_result.rcm.first == EC::FileNotExist ||
                 stat_result.rcm.first == EC::PathNotExist) {
        token.type = AMTokenType::Nonexistentpath;
      } else {
        token.type = AMTokenType::Special;
      }

      if (positional_consumed) {
        ++arg_index;
      }
    }

    return tokens;
  }

private:
  const CommandNode *command_tree_ = nullptr;
  std::shared_ptr<ITokenAnalyzerRuntime> runtime_ = nullptr;
};

/** Final formatter stage: span overlays + bbcode emission. */
class TokenHighlightFormatter final {
public:
  TokenHighlightFormatter(const CommandNode *command_tree,
                          std::shared_ptr<ITokenAnalyzerRuntime> runtime)
      : command_tree_(command_tree), runtime_(std::move(runtime)) {}

  void Format(const std::string &input,
              const std::vector<TokenTypeAnalyzer::AMToken> &tokens,
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
        size_t body_begin = braced ? 2 : 1; // "$" or "${"
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
          return isok(scoped.rcm) ? AMTokenType::VarName
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
        if (at_pos_local == std::string::npos || at_pos_local == 0) {
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
        const AMTokenType nick_type = ClassifyNicknameTokenType_(runtime_, prefix);
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
        if (node && node->subcommands.find(text) != node->subcommands.end()) {
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
      case AMTokenType::UnestablishedNickname:
      case AMTokenType::NonexistentNickname:
      case AMTokenType::BuiltinArg:
      case AMTokenType::ValidValue:
      case AMTokenType::InvalidValue:
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
        static_cast<size_t>(AMTokenType::InvalidValue) + 1;
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

void TokenTypeAnalyzer::BindInteractiveEventRegistry(
    AMInterface::cli::AMInteractiveEventRegistry *registry) {
  if (!registry || token_cache_hook_registered_) {
    return;
  }
  token_cache_clear_callback_ = []() { TokenTypeAnalyzer::ClearTokenCache(); };
  registry->RegisterOnCorePromptReturn(&token_cache_clear_callback_);
  token_cache_hook_registered_ = true;
}

void TokenTypeAnalyzer::RefreshNicknameCache() {}

void TokenTypeAnalyzer::PromptHighlighter_(ic_highlight_env_t *henv,
                                           const char *input, void *arg) {
  if (!henv || !input) {
    return;
  }
  auto *analyzer = static_cast<TokenTypeAnalyzer *>(arg);
  if (!analyzer) {
    return;
  }
  std::string formatted = {};
  analyzer->HighlightFormatted(input, &formatted);
  if (formatted.empty()) {
    return;
  }
  ic_highlight_formatted(henv, input, formatted.c_str());
}

void TokenTypeAnalyzer::ClearTokenCache() { g_split_token_cache.clear(); }

std::vector<TokenTypeAnalyzer::AMToken>
TokenTypeAnalyzer::SplitToken(const std::string &input) const {
  auto cache_it = g_split_token_cache.find(input);
  if (cache_it != g_split_token_cache.end()) {
    return cache_it->second;
  }
  std::vector<AMToken> tokens = TokenSplitEngine::Split(input);
  g_split_token_cache[input] = tokens;
  return tokens;
}

std::vector<TokenTypeAnalyzer::AMToken>
TokenTypeAnalyzer::TokenizeStyle(const std::string &input) {
  TokenSemanticClassifier classifier(command_tree_, runtime_);
  return classifier.Classify(input, SplitToken(input));
}

bool TokenTypeAnalyzer::ParseVarTokenAt(const std::string &input, size_t pos,
                                        size_t limit, size_t *out_end) const {
  return ParseVarTokenAt_(input, pos, limit, out_end);
}

bool TokenTypeAnalyzer::ParseVarTokenText(const std::string &token,
                                          std::string *out_name) const {
  return ParseVarTokenText_(token, out_name);
}

AMTokenType TokenTypeAnalyzer::VarNameTypeFor(const std::string &name) const {
  return VarNameTypeFor_(runtime_, name);
}

bool TokenTypeAnalyzer::IsValidOptionToken(const std::string &token,
                                           const CommandNode *node) const {
  return IsValidOptionToken_(token, node);
}

int TokenTypeAnalyzer::PriorityForType(AMTokenType type) const {
  return PriorityForType_(type);
}

void TokenTypeAnalyzer::HighlightFormatted(const std::string &input,
                                           std::string *formatted) {
  TokenSemanticClassifier classifier(command_tree_, runtime_);
  TokenHighlightFormatter formatter(command_tree_, runtime_);
  auto classified_tokens = classifier.Classify(input, SplitToken(input));
  formatter.Format(input, classified_tokens, formatted);
}

} // namespace AMInterface::parser
