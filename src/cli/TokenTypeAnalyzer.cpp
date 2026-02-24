#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMCLI/InteractiveLoop.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Var.hpp"
#include <array>
#include <cctype>
#include <functional>
#include <limits>
#include <mutex>
#include <string_view>

namespace {
using TokenCacheValue = std::vector<AMTokenTypeAnalyzer::AMToken>;
std::unordered_map<std::string, TokenCacheValue> g_split_token_cache;
std::once_flag g_token_cache_hook_once;
std::function<void()> g_token_cache_clear_callback = []() {
  AMTokenTypeAnalyzer::ClearTokenCache();
};

/** Register token-cache clear callback for each PromptCore return. */
void EnsureTokenCacheClearHookRegistered_() {
  std::call_once(g_token_cache_hook_once, []() {
    auto &registry = AMInteractiveLoop::EventRegistry::Instance();
    registry.RegisterOnCorePromptReturn(&g_token_cache_clear_callback);
  });
}

/** Return true when the character is allowed in variable names. */
inline bool IsVarNameChar(char c) {
  const char token[1] = {c};
  return varsetkn::IsValidVarname(std::string_view(token, 1));
}

/** Validate a full variable name string using the allowed character set. */
bool IsValidVarName(const std::string &name) {
  return varsetkn::IsValidVarname(name);
}

/** Return true when the nickname resolves to local-client scope. */
inline bool IsLocalNickname_(const std::string &nickname) {
  const std::string lowered = AMStr::lowercase(AMStr::Strip(nickname));
  return lowered.empty() || lowered == "local";
}

/** Find first unescaped char in text. */
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

/** Remove backtick escapes for selected special characters. */
std::string UnescapeBackticks_(const std::string &text) {
  if (text.empty()) {
    return text;
  }
  std::string out;
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
AMTokenType ClassifyNicknameTokenType_(const std::string &nickname_raw,
                                       AMHostManager &host_manager,
                                       AMClientManager &client_manager) {
  const std::string nickname = AMStr::Strip(nickname_raw);
  if (IsLocalNickname_(nickname)) {
    return AMTokenType::Nickname;
  }

  const bool client_exists = static_cast<bool>(client_manager.GetClient(nickname));
  if (client_exists) {
    return AMTokenType::Nickname;
  }
  if (host_manager.HostExists(nickname)) {
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
  if (text[1] == '{') {
    const size_t close = text.find('}', 2);
    if (close == std::string::npos || close + 1 != eq) {
      return false;
    }
    const std::string name = AMStr::Strip(text.substr(2, close - 2));
    return !name.empty() && varsetkn::IsValidVarname(name);
  }
  const std::string name = text.substr(1, eq - 1);
  return !name.empty() && varsetkn::IsValidVarname(name);
}

/** Convert concrete filesystem type to AMTokenType path variants. */
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

/**
 * @brief Convert timeout value to int for client API calls.
 */
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

/**
 * @brief Normalize a configured style into a bbcode opening tag.
 *
 * @param raw Raw style string from settings.
 * @return Opening bbcode tag, or empty if the input is unusable.
 */
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

/**
 * @brief Append a character escaped for bbcode parsing.
 *
 * @param out Output string to append to.
 * @param c Character to append with escaping if needed.
 */
void AppendEscapedBbcodeChar_(std::string &out, char c) {
  if (c == '\\') {
    out.append("\\\\");
  } else if (c == '[') {
    out.append("\\[");
  } else {
    out.push_back(c);
  }
}

const std::string StyleKeyForType(AMTokenType type) {
  switch (type) {
  case AMTokenType::Module:
    return "module";
  case AMTokenType::Command:
    return "command";
  case AMTokenType::VarName:
    return "public_varname";
  case AMTokenType::VarNameMissing:
    return "nonexist_varname";
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
  case AMTokenType::String:
    return "string";
  case AMTokenType::Option:
    return "option";
  case AMTokenType::AtSign:
    return "atsign";
  case AMTokenType::DollarSign:
    return "dollarsign";
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

/**
 * @brief Resolve style tag for a token type with path-style fallback.
 */
std::string ResolveStyleTagForType_(AMConfigManager &config_manager,
                                    AMTokenType type) {
  auto resolve_tag = [&](const std::vector<std::string> &path) -> std::string {
    return NormalizeStyleTag_(config_manager.ResolveArg<std::string>(
        DocumentKind::Settings, path, "", {}));
  };

  const std::string from_input =
      resolve_tag({"Style", "InputHighlight", StyleKeyForType(type)});
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

/** Build path info used by AMConfigManager::Format for path token rendering. */
PathInfo BuildPathInfoForTokenType_(AMTokenType type) {
  PathInfo info;
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

/** Render a path-like token segment through config formatter. */
std::string FormatPathSegment_(AMConfigManager &config_manager,
                               const std::string &segment, AMTokenType type) {
  if (segment.empty()) {
    return segment;
  }
  if (type == AMTokenType::Path) {
    return config_manager.Format(segment, "path_like", nullptr);
  }
  PathInfo info = BuildPathInfoForTokenType_(type);
  return config_manager.Format(segment, "path_like", &info);
}

} // namespace

/** Realtime nickname checks are used; no cache to refresh. */
void AMTokenTypeAnalyzer::RefreshNicknameCache() {
  // no-op
}

void AMTokenTypeAnalyzer::PromptHighlighter_(ic_highlight_env_t *henv,
                                             const char *input, void *arg) {
  (void)arg;
  if (!henv || !input) {
    return;
  }
  static AMTokenTypeAnalyzer &analyzer = AMTokenTypeAnalyzer::Instance();
  std::string formatted;
  analyzer.HighlightFormatted(input, &formatted);
  if (formatted.empty()) {
    return;
  }
  ic_highlight_formatted(henv, input, formatted.c_str());
}

void AMTokenTypeAnalyzer::ClearTokenCache() {
  g_split_token_cache.clear();
}

/**
 * @brief Split input into shell-level tokens without semantic typing.
 */
std::vector<AMTokenTypeAnalyzer::AMToken>
AMTokenTypeAnalyzer::SplitToken(const std::string &input) {
  auto cache_it = g_split_token_cache.find(input);
  if (cache_it != g_split_token_cache.end()) {
    return cache_it->second;
  }

  std::vector<AMToken> tokens;
  size_t i = 0;
  while (i < input.size()) {
    while (i < input.size() && AMStr::IsWhitespace(input[i])) {
      ++i;
    }
    if (i >= input.size()) {
      break;
    }

    AMToken token;
    token.start = i;
    token.content_start = i;
    token.content_end = i;
    token.end = i;
    token.quoted = false;
    token.type = AMTokenType::Unset;

    if (IsQuoted(input[i])) {
      token.quoted = true;
      const char quote = input[i];
      ++i;
      token.content_start = i;

      while (i < input.size()) {
        if (input[i] == '`' && i + 1 < input.size() &&
            (input[i + 1] == '"' || input[i + 1] == '\'')) {
          i += 2;
          continue;
        }
        if (input[i] == quote) {
          break;
        }
        ++i;
      }
      token.content_end = i;
      if (i < input.size() && input[i] == quote) {
        ++i;
      }
      token.end = i;
      tokens.push_back(token);
      continue;
    }

    while (i < input.size() && !AMStr::IsWhitespace(input[i])) {
      ++i;
    }
    token.end = i;
    token.content_start = token.start;
    token.content_end = token.end;
    tokens.push_back(token);
  }
  g_split_token_cache[input] = tokens;
  return tokens;
}

/**
 * @brief Analyze split tokens into style-level token types.
 */
std::vector<AMTokenTypeAnalyzer::AMToken>
AMTokenTypeAnalyzer::TokenizeStyle(const std::string &input) {
  std::vector<AMToken> tokens = SplitToken(input);
  std::vector<std::string> texts;
  texts.reserve(tokens.size());
  for (const auto &token : tokens) {
    texts.push_back(input.substr(token.content_start,
                                 token.content_end - token.content_start));
  }

  for (auto &token : tokens) {
    token.type = token.quoted ? AMTokenType::String : AMTokenType::Common;
  }

  const CommandNode *node = nullptr;
  std::string command_path;
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
    std::vector<size_t> legal_indexes;
    legal_indexes.reserve(tokens.size());
    const CommandNode *scan_node = nullptr;
    std::string scan_path;

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
      for (const size_t legal_index : legal_indexes) {
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
      if (IsValidOptionToken(texts[idx], node)) {
        token.type = AMTokenType::Option;
      }
    }
  }

  std::shared_ptr<BaseClient> current_client = client_manager_.CurrentClient();
  std::string current_nickname = "local";
  if (current_client) {
    current_nickname = current_client->GetNickname();
    if (current_nickname.empty()) {
      current_nickname = "local";
    }
  }

  std::optional<CommandNode::OptionValueRule> pending_value_rule;
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

    if (!semantic_hint.has_value() && !option_definition && command_tree_ &&
        !command_path.empty()) {
      semantic_hint =
          command_tree_->ResolvePositionalSemantic(command_path, arg_index);
      positional_consumed = true;
    } else if (!option_definition) {
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
        token.type = ClassifyNicknameTokenType_(unescaped_text, host_manager_,
                                                client_manager_);
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }
    }

    std::string name;
    if (token.type == AMTokenType::Common &&
        ParseVarTokenText(raw_text, &name)) {
      token.type = VarNameTypeFor(name);
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

    // Path semantic without clear path sign: prefer nickname classification.
    if (token.type == AMTokenType::Common && force_path && !has_clear_path_sign) {
      const AMTokenType nick_type =
          ClassifyNicknameTokenType_(unescaped_text, host_manager_,
                                     client_manager_);
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
      std::string prefix_raw = raw_text.substr(0, at_pos);
      std::string prefix = AMStr::Strip(UnescapeBackticks_(prefix_raw));
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

    const AMPromptProfileArgs &profile =
        prompt_manager_.ResolvePromptProfileArgs(nickname_for_cfg);
    if (!profile.highlight.path.enable) {
      token.type = AMTokenType::Path;
      if (positional_consumed) {
        ++arg_index;
      }
      continue;
    }

    std::shared_ptr<BaseClient> path_client;
    if (explicit_target) {
      if (explicit_local) {
        path_client = client_manager_.LocalClient();
      } else {
        path_client = client_manager_.GetClient(nickname_for_lookup);
      }
    } else {
      path_client =
          current_client ? current_client : client_manager_.LocalClient();
    }

    if (!path_client) {
      token.type = AMTokenType::Nonexistentpath;
      if (positional_consumed) {
        ++arg_index;
      }
      continue;
    }

    const std::string path_part = UnescapeBackticks_(path_part_raw);
    const std::string abs_path =
        client_manager_.BuildPath(path_client, path_part);
    const int timeout_ms =
        ToClientTimeoutMs_(profile.highlight.path.timeout_ms, 1000);

    auto [rcm, info] =
        path_client->stat(abs_path, false, nullptr, timeout_ms, am_ms());
    if (rcm.first == EC::Success) {
      token.type = ToPathTokenType_(info.type);
    } else if (rcm.first == EC::FileNotExist || rcm.first == EC::PathNotExist) {
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

/** Parse a variable token at a given position within a limit. */
bool AMTokenTypeAnalyzer::ParseVarTokenAt(const std::string &input, size_t pos,
                                          size_t limit, size_t *out_end) const {
  if (pos >= input.size() || input[pos] != '$') {
    return false;
  }
  if (pos + 1 >= input.size()) {
    return false;
  }
  if (input[pos + 1] == '{') {
    size_t close = input.find('}', pos + 2);
    if (close == std::string::npos || close >= limit) {
      return false;
    }
    std::string inner = AMStr::Strip(input.substr(pos + 2, close - pos - 2));
    if (!IsValidVarName(inner)) {
      return false;
    }
    if (out_end) {
      *out_end = close + 1;
    }
    return true;
  }

  size_t cur = pos + 1;
  while (cur < input.size() && IsVarNameChar(input[cur])) {
    ++cur;
  }
  if (cur == pos + 1 || cur > limit) {
    return false;
  }
  if (out_end) {
    *out_end = cur;
  }
  return true;
}

/** Validate whether a complete token is a variable reference and extract. */
bool AMTokenTypeAnalyzer::ParseVarTokenText(const std::string &token,
                                            std::string *out_name) const {
  if (token.empty() || token[0] != '$') {
    return false;
  }
  if (token.size() < 2) {
    return false;
  }
  if (token[1] == '{') {
    if (token.back() != '}') {
      return false;
    }
    std::string inner = AMStr::Strip(token.substr(2, token.size() - 3));
    if (!IsValidVarName(inner)) {
      return false;
    }
    if (out_name) {
      *out_name = inner;
    }
    return true;
  }
  std::string inner = token.substr(1);
  if (!IsValidVarName(inner)) {
    return false;
  }
  if (out_name) {
    *out_name = inner;
  }
  return true;
}

/** Assign a priority for overlap resolution between token types. */
int AMTokenTypeAnalyzer::PriorityForType(AMTokenType type) const {
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
  case AMTokenType::DollarSign:
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

AMTokenType AMTokenTypeAnalyzer::VarNameTypeFor(const std::string &name) const {
  VarInfo scoped = var_manager_.GetVar(var_manager_.CurrentDomain(), name);
  if (scoped.IsValid().first == EC::Success) {
    return AMTokenType::VarName;
  }
  VarInfo pub = var_manager_.GetVar(varsetkn::kPublic, name);
  return pub.IsValid().first == EC::Success ? AMTokenType::VarName
                                            : AMTokenType::VarNameMissing;
}

/** Validate a token against the option set for a command node. */
bool AMTokenTypeAnalyzer::IsValidOptionToken(const std::string &token,
                                             const CommandNode *node) const {
  if (!node || token.size() < 2 || token[0] != '-') {
    return false;
  }
  if (token.rfind("--", 0) == 0) {
    std::string name = token;
    size_t eq = token.find('=');
    if (eq != std::string::npos) {
      name = token.substr(0, eq);
    }
    return node->long_options.find(name) != node->long_options.end();
  }
  if (token.size() < 2) {
    return false;
  }
  for (size_t i = 1; i < token.size(); ++i) {
    char c = token[i];
    if (node->short_options.find(c) == node->short_options.end()) {
      return false;
    }
  }
  return true;
}

/** Main highlighter entrypoint for isocline bbcode formatting. */
void AMTokenTypeAnalyzer::HighlightFormatted(const std::string &input,
                                             std::string *formatted) {
  if (!formatted) {
    return;
  }
  EnsureTokenCacheClearHookRegistered_();
  formatted->clear();
  const size_t size = input.size();
  if (size == 0) {
    return;
  }

  std::vector<AMTokenType> types(size, AMTokenType::Common);
  std::vector<int> priorities(size, 0);

  std::vector<AMToken> tokens = TokenizeStyle(input);

  auto apply_range = [&](size_t start, size_t end, AMTokenType type) {
    if (start >= end || start >= size) {
      return;
    }
    if (end > size) {
      end = size;
    }
    int priority = PriorityForType(type);
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
    apply_range(token_start, token_start + 1, AMTokenType::DollarSign);
    std::string name;
    std::string token = input.substr(token_start, token_end - token_start);
    if (!ParseVarTokenText(token, &name)) {
      return;
    }
    apply_range(token_start + 1, token_end, VarNameTypeFor(name));
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
      if (!ParseVarTokenAt(input, i, input.size(), &end)) {
        continue;
      }
      highlight_var_token(i, end);
      i = end - 1;
    }
  };

  /**
   * @brief Highlight `$var=...` / `$var = ...` shortcut assignment segments.
   */
  auto highlight_var_shortcut_define = [&]() {
    if (tokens.empty()) {
      return;
    }
    const AMToken &first = tokens.front();
    if (first.quoted || first.content_start >= size ||
        first.content_end <= first.content_start || first.content_end > size) {
      return;
    }

    size_t var_end = 0;
    if (!ParseVarTokenAt(input, first.content_start, first.content_end,
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

    const AMToken &second = tokens[1];
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
        const AMToken &value_token = tokens[2];
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
      if (token.quoted) {
        continue;
      }
      std::string text = input.substr(token.start, token.end - token.start);
      size_t at_pos = FindUnescapedChar_(text, '@');
      if (at_pos == std::string::npos || at_pos == 0) {
        continue;
      }
      std::string prefix = UnescapeBackticks_(text.substr(0, at_pos));
      if (prefix.empty()) {
        continue;
      }
      size_t nick_start = token.start;
      size_t nick_end = token.start + at_pos;
      size_t at_index = nick_end;
      const AMTokenType nick_type =
          ClassifyNicknameTokenType_(prefix, host_manager_, client_manager_);
      apply_range(nick_start, nick_end, nick_type);
      apply_range(at_index, at_index + 1, AMTokenType::AtSign);
    }
  };

  auto highlight_commands_and_options = [&](const CommandNode **out_node,
                                            size_t *out_command_tokens) {
    const CommandNode *node = nullptr;
    size_t consumed = 0;
    std::string path;

    if (!command_tree_) {
      if (out_node) {
        *out_node = nullptr;
      }
      if (out_command_tokens) {
        *out_command_tokens = 0;
      }
      return;
    }

    for (size_t i = 0; i < tokens.size(); ++i) {
      const auto &token = tokens[i];
      if (token.quoted) {
        continue;
      }
      std::string text = input.substr(token.start, token.end - token.start);
      if (text.empty()) {
        continue;
      }

      if (path.empty()) {
        if (command_tree_->IsModule(text)) {
          apply_range(token.start, token.end, AMTokenType::Module);
          path = text;
          node = command_tree_->FindNode(path);
          consumed = i + 1;
          continue;
        }
        if (command_tree_->IsTopCommand(text)) {
          apply_range(token.start, token.end, AMTokenType::Command);
          path = text;
          node = command_tree_->FindNode(path);
          consumed = i + 1;
          continue;
        }
        continue;
      }

      if (node && node->subcommands.find(text) != node->subcommands.end()) {
        apply_range(token.start, token.end, AMTokenType::Command);
        path += " " + text;
        node = command_tree_->FindNode(path);
        consumed = i + 1;
      }
    }

    if (out_node) {
      *out_node = node;
    }
    if (out_command_tokens) {
      *out_command_tokens = consumed;
    }

    if (!node) {
      return;
    }
    for (const auto &token : tokens) {
      if (token.quoted) {
        continue;
      }
      std::string text = input.substr(token.start, token.end - token.start);
      if (IsValidOptionToken(text, node)) {
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
      apply_range(token.start, token.end, token.type);
      break;
    case AMTokenType::Nickname:
    case AMTokenType::UnestablishedNickname:
    case AMTokenType::NonexistentNickname:
    case AMTokenType::BuiltinArg:
      apply_range(token.start, token.end, token.type);
      break;
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

  highlight_commands_and_options(nullptr, nullptr);
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
      static_cast<size_t>(AMTokenType::BuiltinArg) + 1;
  std::array<std::string, kTokenTypeCount> style_tags;
  for (size_t i = 0; i < kTokenTypeCount; ++i) {
    style_tags[i] =
        ResolveStyleTagForType_(config_manager_, static_cast<AMTokenType>(i));
  }

  formatted->reserve(input.size() + 16);
  std::string current_tag;
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
      formatted->append(FormatPathSegment_(config_manager_,
                                           input.substr(i, end - i), cur_type));
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

