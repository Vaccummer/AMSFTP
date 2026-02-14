#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Var.hpp"
#include <array>

namespace {
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
    return "exist_varname";
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
  case AMTokenType::Common:
  default:
    return "common";
  }
}

} // namespace

/** Reload nickname cache from host manager. */
void AMTokenTypeAnalyzer::RefreshNicknameCache() {
  nicknames_.clear();
  auto names = AMHostManager::Instance().ListNames();
  for (const auto &name : names) {
    nicknames_.insert(name);
  }
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

/** Split input into whitespace-delimited tokens while keeping quoted strings.
 */
std::vector<AMTokenTypeAnalyzer::Token>
AMTokenTypeAnalyzer::Tokenize(const std::string &input) const {
  std::vector<Token> tokens;
  size_t i = 0;
  while (i < input.size()) {
    while (i < input.size() && AMStr::IsWhitespace(input[i])) {
      ++i;
    }
    if (i >= input.size()) {
      break;
    }
    size_t start = i;
    bool quoted = false;
    if (IsQuoted(input[i])) {
      quoted = true;
      char quote = input[i];
      ++i;
      while (i < input.size()) {
        if (input[i] == '`' && i + 1 < input.size() &&
            (input[i + 1] == '"' || input[i + 1] == '\'')) {
          i += 2;
          continue;
        }
        if (input[i] == quote) {
          ++i;
          break;
        }
        ++i;
      }
    } else {
      while (i < input.size() && !AMStr::IsWhitespace(input[i])) {
        ++i;
      }
    }
    tokens.push_back({start, i, quoted});
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

/** Validate whether a complete token is a variable reference. */
bool AMTokenTypeAnalyzer::ParseVarTokenText(const std::string &token) const {
  return ParseVarTokenText(token, nullptr);
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
  case AMTokenType::String:
    return 20;
  case AMTokenType::Common:
  default:
    return 0;
  }
}

AMTokenType AMTokenTypeAnalyzer::VarNameTypeFor(const std::string &name) const {
  return var_manager_.Resolve(name) ? AMTokenType::VarName
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

  std::vector<Token> tokens = Tokenize(input);

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
    std::vector<bool> quoted_mask(input.size(), false);
    for (const auto &token : tokens) {
      if (token.quoted) {
        for (size_t i = token.start; i < token.end && i < input.size(); ++i) {
          quoted_mask[i] = true;
        }
      }
    }

    for (size_t i = 0; i < input.size(); ++i) {
      if (quoted_mask[i]) {
        continue;
      }
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
      if (next != '$' && next != '"' && next != '\'') {
        continue;
      }
      apply_range(i, i + 1, AMTokenType::EscapeSign);
    }
  };

  auto highlight_nickname_at_sign = [&]() {
    for (const auto &token : tokens) {
      if (token.quoted) {
        continue;
      }
      std::string text = input.substr(token.start, token.end - token.start);
      size_t at_pos = text.find('@');
      if (at_pos == std::string::npos || at_pos == 0) {
        continue;
      }
      std::string prefix = text.substr(0, at_pos);
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
      static_cast<size_t>(AMTokenType::EscapeSign) + 1;
  std::array<std::string, kTokenTypeCount> style_tags;
  for (size_t i = 0; i < kTokenTypeCount; ++i) {
    style_tags[i] = NormalizeStyleTag_(config_manager_.ResolveArg<std::string>(
        DocumentKind::Settings,
        {"style", "InputHighlight",
         StyleKeyForType(static_cast<AMTokenType>(i))},
        "", {}));
  }

  formatted->reserve(input.size() + 16);
  std::string current_tag;
  for (size_t i = 0; i < size; ++i) {
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
