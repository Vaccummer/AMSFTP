#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Set.hpp"
#include "AMManager/Var.hpp"
#include <array>
#include <cctype>
#include <limits>

namespace {
using TokenCacheValue = std::vector<AMTokenTypeAnalyzer::AMToken>;
std::unordered_map<std::string, TokenCacheValue> g_split_token_cache;
std::unordered_map<std::string, TokenCacheValue> g_style_token_cache;
/** Return true when the character is allowed in variable names. */
inline bool IsVarNameChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}

/** Validate a full variable name string using the allowed character set. */
bool IsValidVarName(const std::string &name) {
  if (name.empty()) {
    return false;
  }
  for (char c : name) {
    if (!IsVarNameChar(c)) {
      return false;
    }
  }
  return true;
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

/** Return true if command path expects a path argument at arg index. */
bool IsPathArgumentCommand_(const std::string &command_path, size_t arg_index) {
  if (command_path == "cd" || command_path == "ls" ||
      command_path == "realpath") {
    return arg_index == 0;
  }
  if (command_path == "find" || command_path == "walk" ||
      command_path == "tree") {
    return arg_index == 0;
  }
  if (command_path == "stat" || command_path == "size" ||
      command_path == "mkdir" || command_path == "rm" || command_path == "cp") {
    return true;
  }
  return false;
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

AMTokenTypeAnalyzer::PathEngineConfig
ToPathEngineConfig_(const AMHostSetPathConfig &src) {
  AMTokenTypeAnalyzer::PathEngineConfig out;
  out.use_async = src.use_async;
  out.use_cache = src.use_cache;
  out.cache_items_threshold = src.cache_items_threshold;
  out.cache_max_entries = src.cache_max_entries;
  out.timeout_ms = src.timeout_ms;
  out.highlight_use_check = src.highlight_use_check;
  out.highlight_timeout_ms = src.highlight_timeout_ms;
  return out;
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

/** Find the first '=' outside of quotes starting from a position. */
size_t FindEqualOutsideQuotes(const std::string &input, size_t start) {
  bool in_single = false;
  bool in_double = false;
  for (size_t i = start; i < input.size(); ++i) {
    char c = input[i];
    if (!in_double && c == '\'') {
      in_single = !in_single;
      continue;
    }
    if (!in_single && c == '"') {
      in_double = !in_double;
      continue;
    }
    if (!in_single && !in_double && c == '=') {
      return i;
    }
  }
  return std::string::npos;
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

/** Reload nickname cache from host manager. */
void AMTokenTypeAnalyzer::RefreshNicknameCache() {
  nicknames_.clear();
  for (const auto &name : host_manager_.ListNames()) {
    nicknames_.insert(name);
  }
}

void AMTokenTypeAnalyzer::RefreshHostSet() {
  (void)set_manager_.Reload();
  ClearTokenCache();
}

AMTokenTypeAnalyzer::PathEngineConfig
AMTokenTypeAnalyzer::ResolvePathEngineConfig(const std::string &nickname) {
  const AMHostSetAttrResult result = set_manager_.ResolvePathSet(nickname);
  return ToPathEngineConfig_(result.value);
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
  g_style_token_cache.clear();
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
  auto cache_it = g_style_token_cache.find(input);
  if (cache_it != g_style_token_cache.end()) {
    return cache_it->second;
  }

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

  size_t arg_index = 0;
  for (size_t idx = 0; idx < tokens.size(); ++idx) {
    auto &token = tokens[idx];
    if (idx < command_tokens) {
      continue;
    }
    if (token.quoted) {
      ++arg_index;
      continue;
    }

    const std::string &raw_text = texts[idx];
    if (raw_text.empty()) {
      continue;
    }
    if (token.type == AMTokenType::Option) {
      continue;
    }

    std::string name;
    if (token.type == AMTokenType::Common &&
        ParseVarTokenText(raw_text, &name)) {
      token.type = VarNameTypeFor(name);
      ++arg_index;
      continue;
    }

    const size_t at_pos = FindUnescapedChar_(raw_text, '@');
    const bool has_unescaped_at = at_pos != std::string::npos;

    if (token.type == AMTokenType::Common && has_unescaped_at && at_pos > 0) {
      const std::string prefix = UnescapeBackticks_(raw_text.substr(0, at_pos));
      if (nicknames_.find(prefix) != nicknames_.end()) {
        token.type = AMTokenType::Nickname;
      }
    }

    const std::string unescaped_text = UnescapeBackticks_(raw_text);
    const bool force_path = IsPathArgumentCommand_(command_path, arg_index);
    const bool treat_as_path =
        force_path || has_unescaped_at || IsPathLikeText_(unescaped_text);
    if (!treat_as_path) {
      ++arg_index;
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

    const AMHostSetAttrResult path_result =
        set_manager_.ResolvePathSet(nickname_for_cfg);
    const AMHostSetPathConfig &path_cfg = path_result.value;
    if (!path_cfg.highlight_use_check) {
      token.type = AMTokenType::Path;
      ++arg_index;
      continue;
    }

    std::shared_ptr<BaseClient> path_client;
    if (explicit_target) {
      if (explicit_local) {
        path_client = client_manager_.LocalClient();
      } else {
        path_client = client_manager_.Clients().GetHost(nickname_for_lookup);
      }
    } else {
      path_client =
          current_client ? current_client : client_manager_.LocalClient();
    }

    if (!path_client) {
      token.type = AMTokenType::Nonexistentpath;
      ++arg_index;
      continue;
    }

    const std::string path_part = UnescapeBackticks_(path_part_raw);
    const std::string abs_path =
        client_manager_.BuildPath(path_client, path_part);
    const int timeout_ms =
        ToClientTimeoutMs_(path_cfg.highlight_timeout_ms, 1000);

    auto [rcm, info] =
        path_client->stat(abs_path, false, nullptr, timeout_ms, am_ms());
    if (rcm.first == EC::Success) {
      token.type = ToPathTokenType_(info.type);
    } else if (rcm.first == EC::FileNotExist || rcm.first == EC::PathNotExist) {
      token.type = AMTokenType::Nonexistentpath;
    } else {
      token.type = AMTokenType::Special;
    }

    ++arg_index;
  }

  g_style_token_cache[input] = tokens;
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
  case AMTokenType::EscapeSign:
    return 100;
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
    return 70;
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
  formatted->clear();
  const size_t size = input.size();
  if (size == 0) {
    return;
  }

  std::vector<AMTokenType> types(size, AMTokenType::Common);
  std::vector<int> priorities(size, 0);

  RefreshNicknameCache();

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
      if (nicknames_.find(prefix) == nicknames_.end()) {
        continue;
      }
      size_t nick_start = token.start;
      size_t nick_end = token.start + at_pos;
      size_t at_index = nick_end;
      apply_range(nick_start, nick_end, AMTokenType::Nickname);
      apply_range(at_index, at_index + 1, AMTokenType::AtSign);
    }
  };

  auto highlight_commands_and_options = [&](const CommandNode **out_node,
                                            size_t *out_command_tokens) {
    const CommandNode *node = nullptr;
    size_t consumed = 0;
    std::string path;
    bool parsing = true;

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
      if (parsing) {
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
            if (!node || node->subcommands.empty()) {
              parsing = false;
            }
            continue;
          }
          parsing = false;
        } else if (node &&
                   node->subcommands.find(text) != node->subcommands.end()) {
          apply_range(token.start, token.end, AMTokenType::Command);
          path += " " + text;
          node = command_tree_->FindNode(path);
          consumed = i + 1;
          if (!node || node->subcommands.empty()) {
            parsing = false;
          }
          continue;
        } else {
          parsing = false;
        }
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

  auto highlight_var_command = [&](bool *handled) {
    if (handled) {
      *handled = false;
    }
    size_t first_index = 0;
    while (first_index < tokens.size() && tokens[first_index].quoted) {
      ++first_index;
    }
    if (first_index >= tokens.size()) {
      return;
    }
    const auto &first = tokens[first_index];
    std::string first_text = input.substr(first.start, first.end - first.start);
    if (first_text != "var" && first_text != "del") {
      return;
    }
    if (handled) {
      *handled = true;
    }
    apply_range(first.start, first.end, AMTokenType::Command);

    size_t remainder_start = first.end;
    size_t eq_pos = FindEqualOutsideQuotes(input, remainder_start);
    if (first_text == "var" && eq_pos != std::string::npos) {
      apply_range(eq_pos, eq_pos + 1, AMTokenType::EqualSign);
      apply_range(eq_pos + 1, input.size(), AMTokenType::VarValue);

      size_t dollar = remainder_start;
      while (true) {
        dollar = input.find('$', dollar);
        if (dollar == std::string::npos || dollar >= eq_pos) {
          break;
        }
        if (dollar > 0 && input[dollar - 1] == '`') {
          ++dollar;
          continue;
        }
        size_t end = 0;
        if (ParseVarTokenAt(input, dollar, eq_pos, &end)) {
          highlight_var_token(dollar, end);
        }
        break;
      }
      return;
    }

    for (size_t i = first_index + 1; i < tokens.size(); ++i) {
      const auto &token = tokens[i];
      if (token.quoted) {
        continue;
      }
      std::string text = input.substr(token.start, token.end - token.start);
      if (!ParseVarTokenText(text)) {
        continue;
      }
      highlight_var_token(token.start, token.end);
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

  bool handled = false;
  highlight_var_command(&handled);
  if (handled) {
    highlight_var_references();
  } else {
    std::string trimmed = AMStr::Strip(input);
    if (!trimmed.empty() && trimmed.front() == '$') {
      size_t offset = input.find('$');
      size_t eq_pos = FindEqualOutsideQuotes(input, offset);
      if (eq_pos != std::string::npos) {
        apply_range(eq_pos, eq_pos + 1, AMTokenType::EqualSign);
        apply_range(eq_pos + 1, input.size(), AMTokenType::VarValue);
        size_t end = 0;
        if (ParseVarTokenAt(input, offset, eq_pos, &end)) {
          highlight_var_token(offset, end);
        }
        highlight_var_references();
      } else {
        const CommandNode *node = nullptr;
        size_t consumed = 0;
        highlight_commands_and_options(&node, &consumed);
        highlight_nickname_at_sign();
        highlight_var_references();
      }
    } else {
      const CommandNode *node = nullptr;
      size_t consumed = 0;
      highlight_commands_and_options(&node, &consumed);
      highlight_nickname_at_sign();
      highlight_var_references();
    }
  }

  constexpr size_t kTokenTypeCount =
      static_cast<size_t>(AMTokenType::Special) + 1;
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
