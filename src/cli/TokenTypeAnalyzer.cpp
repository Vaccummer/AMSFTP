#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMCLI/CLIBind.hpp"
#include <algorithm>

namespace {
/** Return true when the character is allowed in variable names. */
bool IsVarNameChar(char c) {
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
bool IsQuoted(char c) { return c == '"' || c == '\''; }

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

} // namespace

/** Construct the analyzer and prime CLI definition cache. */
AMTokenTypeAnalyzer::AMTokenTypeAnalyzer(AMConfigManager &config_manager)
    : config_manager_(config_manager) {
  EnsureCliCache();
}

/** Ensure the CLI cache is built once. */
void AMTokenTypeAnalyzer::EnsureCliCache() {
  if (cli_cache_ready_) {
    return;
  }
  BuildCliCache();
  cli_cache_ready_ = true;
}

/** Build the CLI cache from CLI11 command definitions. */
void AMTokenTypeAnalyzer::BuildCliCache() {
  CLI::App app{"AMSFTP CLI", "amsftp"};
  CliArgsPool args_pool;
  (void)BindCliOptions(app, args_pool);

  auto subs = app.get_subcommands([](CLI::App *) { return true; });
  for (auto *sub : subs) {
    top_commands_.insert(sub->get_name());
  }
  for (auto *sub : subs) {
    auto nested = sub->get_subcommands([](CLI::App *) { return true; });
    if (!nested.empty()) {
      modules_.insert(sub->get_name());
    }
  }

  BuildCliNode(&app, "", true);
}

/** Build a command node entry for a CLI11 app path. */
void AMTokenTypeAnalyzer::BuildCliNode(CLI::App *app, const std::string &path,
                                       bool is_root) {
  CommandNode node;
  auto options = app->get_options();
  for (auto *opt : options) {
    for (const auto &lname : opt->get_lnames()) {
      if (!lname.empty()) {
        node.long_options.insert("--" + lname);
      }
    }
    for (const auto &sname : opt->get_snames()) {
      if (!sname.empty()) {
        node.short_options.insert(sname[0]);
      }
    }
  }

  auto subs = app->get_subcommands([](CLI::App *) { return true; });
  for (auto *sub : subs) {
    node.subcommands.insert(sub->get_name());
  }

  if (!is_root) {
    command_nodes_[path] = node;
  }

  for (auto *sub : subs) {
    std::string next = path.empty() ? sub->get_name() : path + " " + sub->get_name();
    BuildCliNode(sub, next, false);
  }
}

/** Find a cached node by command path. */
const AMTokenTypeAnalyzer::CommandNode *
AMTokenTypeAnalyzer::FindNode(const std::string &path) const {
  auto it = command_nodes_.find(path);
  if (it == command_nodes_.end()) {
    return nullptr;
  }
  return &it->second;
}

/** Reload nickname cache from configuration. */
void AMTokenTypeAnalyzer::RefreshNicknameCache() {
  nicknames_.clear();
  auto names = config_manager_.ListHostnames();
  for (const auto &name : names) {
    nicknames_.insert(name);
  }
}

/** Split input into whitespace-delimited tokens while keeping quoted strings. */
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
                                          size_t limit,
                                          size_t *out_end) const {
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
    std::string inner =
        AMStr::TrimWhitespaceCopy(input.substr(pos + 2, close - pos - 2));
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
    std::string inner =
        AMStr::TrimWhitespaceCopy(token.substr(2, token.size() - 3));
    return IsValidVarName(inner);
  }
  std::string inner = token.substr(1);
  return IsValidVarName(inner);
}

/** Map token types to replxx colors. */
ReplxxColor AMTokenTypeAnalyzer::ColorForType(AMTokenType type) const {
  switch (type) {
  case AMTokenType::Module:
    return replxx_color_bold(REPLXX_COLOR_BRIGHTMAGENTA);
  case AMTokenType::Command:
    return replxx_color_bold(REPLXX_COLOR_BRIGHTGREEN);
  case AMTokenType::VarName:
    return replxx_color_bold(REPLXX_COLOR_BRIGHTBLUE);
  case AMTokenType::VarValue:
    return REPLXX_COLOR_YELLOW;
  case AMTokenType::Nickname:
    return REPLXX_COLOR_BRIGHTCYAN;
  case AMTokenType::String:
    return REPLXX_COLOR_BROWN;
  case AMTokenType::Option:
    return replxx_color_bold(REPLXX_COLOR_BRIGHTCYAN);
  case AMTokenType::AtSign:
    return replxx_color_bold(REPLXX_COLOR_BRIGHTMAGENTA);
  case AMTokenType::DollarSign:
    return replxx_color_bold(REPLXX_COLOR_BRIGHTMAGENTA);
  case AMTokenType::EqualSign:
    return REPLXX_COLOR_BRIGHTRED;
  case AMTokenType::Common:
  default:
    return REPLXX_COLOR_DEFAULT;
  }
}

/** Assign a priority for overlap resolution between token types. */
int AMTokenTypeAnalyzer::PriorityForType(AMTokenType type) const {
  switch (type) {
  case AMTokenType::String:
    return 100;
  case AMTokenType::EqualSign:
    return 95;
  case AMTokenType::VarValue:
    return 90;
  case AMTokenType::VarName:
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
  case AMTokenType::Common:
  default:
    return 0;
  }
}

/** Apply a pre-built token span to the color buffer. */
void AMTokenTypeAnalyzer::ApplyColor(const AMTokenSpan &span,
                                     ReplxxColor *colors,
                                     std::vector<int> &priorities,
                                     int size) const {
  ApplyRange(span.start, span.end, span.type, colors, priorities, size);
}

/** Apply a token type to a specific range with priority checks. */
void AMTokenTypeAnalyzer::ApplyRange(size_t start, size_t end,
                                     AMTokenType type, ReplxxColor *colors,
                                     std::vector<int> &priorities,
                                     int size) const {
  if (!colors || size <= 0) {
    return;
  }
  if (start >= end) {
    return;
  }
  if (start >= static_cast<size_t>(size)) {
    return;
  }
  if (end > static_cast<size_t>(size)) {
    end = static_cast<size_t>(size);
  }
  int priority = PriorityForType(type);
  ReplxxColor color = ColorForType(type);
  for (size_t i = start; i < end; ++i) {
    if (priority >= priorities[i]) {
      priorities[i] = priority;
      colors[i] = color;
    }
  }
}

/** Highlight a variable token by separating $ and the name. */
void AMTokenTypeAnalyzer::HighlightVarToken(size_t token_start,
                                            size_t token_end,
                                            ReplxxColor *colors,
                                            std::vector<int> &priorities,
                                            int size) const {
  if (token_end <= token_start) {
    return;
  }
  ApplyRange(token_start, token_start + 1, AMTokenType::DollarSign, colors,
             priorities, size);
  ApplyRange(token_start + 1, token_end, AMTokenType::VarName, colors,
             priorities, size);
}

/** Highlight variable references outside of quoted strings. */
void AMTokenTypeAnalyzer::HighlightVarReferences(
    const std::string &input, const std::vector<Token> &tokens,
    ReplxxColor *colors, std::vector<int> &priorities, int size) const {
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
    HighlightVarToken(i, end, colors, priorities, size);
    i = end - 1;
  }
}

/** Highlight nickname and @ when the nickname exists in cache. */
void AMTokenTypeAnalyzer::HighlightNicknameAtSign(
    const std::string &input, const std::vector<Token> &tokens,
    ReplxxColor *colors, std::vector<int> &priorities, int size) const {
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
    ApplyRange(nick_start, nick_end, AMTokenType::Nickname, colors, priorities,
               size);
    ApplyRange(at_index, at_index + 1, AMTokenType::AtSign, colors, priorities,
               size);
  }
}

/** Validate a token against the option set for a command node. */
bool AMTokenTypeAnalyzer::IsValidOptionToken(
    const std::string &token, const CommandNode *node) const {
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

/** Highlight command/module tokens and valid options for the command path. */
void AMTokenTypeAnalyzer::HighlightCommandsAndOptions(
    const std::string &input, const std::vector<Token> &tokens,
    ReplxxColor *colors, std::vector<int> &priorities, int size,
    const CommandNode **out_node, size_t *out_command_tokens) const {
  const CommandNode *node = nullptr;
  size_t consumed = 0;
  std::string path;
  bool parsing = true;

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
        if (modules_.find(text) != modules_.end()) {
          ApplyRange(token.start, token.end, AMTokenType::Module, colors,
                     priorities, size);
          path = text;
          node = FindNode(path);
          consumed = i + 1;
          continue;
        }
        if (top_commands_.find(text) != top_commands_.end()) {
          ApplyRange(token.start, token.end, AMTokenType::Command, colors,
                     priorities, size);
          path = text;
          node = FindNode(path);
          consumed = i + 1;
          if (!node || node->subcommands.empty()) {
            parsing = false;
          }
          continue;
        }
        parsing = false;
      } else if (node && node->subcommands.find(text) != node->subcommands.end()) {
        ApplyRange(token.start, token.end, AMTokenType::Command, colors,
                   priorities, size);
        path += " " + text;
        node = FindNode(path);
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
      ApplyRange(token.start, token.end, AMTokenType::Option, colors,
                 priorities, size);
    }
  }
}

/** Highlight var/del commands and handle assignment/value spans. */
void AMTokenTypeAnalyzer::HighlightVarCommand(
    const std::string &input, const std::vector<Token> &tokens,
    ReplxxColor *colors, std::vector<int> &priorities, int size,
    bool *handled) const {
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
  ApplyRange(first.start, first.end, AMTokenType::Command, colors, priorities,
             size);

  size_t remainder_start = first.end;
  size_t eq_pos = FindEqualOutsideQuotes(input, remainder_start);
  if (first_text == "var" && eq_pos != std::string::npos) {
    ApplyRange(eq_pos, eq_pos + 1, AMTokenType::EqualSign, colors, priorities,
               size);
    ApplyRange(eq_pos + 1, input.size(), AMTokenType::VarValue, colors,
               priorities, size);

    size_t dollar = input.find('$', remainder_start);
    if (dollar != std::string::npos && dollar < eq_pos) {
      size_t end = 0;
      if (ParseVarTokenAt(input, dollar, eq_pos, &end)) {
        HighlightVarToken(dollar, end, colors, priorities, size);
      }
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
    HighlightVarToken(token.start, token.end, colors, priorities, size);
  }
}

/** Main highlighter entrypoint for replxx. */
void AMTokenTypeAnalyzer::Highlight(const std::string &input,
                                    ReplxxColor *colors, int size) {
  if (!colors || size <= 0) {
    return;
  }
  for (int i = 0; i < size; ++i) {
    colors[i] = REPLXX_COLOR_DEFAULT;
  }
  std::vector<int> priorities(static_cast<size_t>(size), 0);

  RefreshNicknameCache();
  EnsureCliCache();

  std::vector<Token> tokens = Tokenize(input);

  for (const auto &token : tokens) {
    if (token.quoted) {
      ApplyRange(token.start, token.end, AMTokenType::String, colors,
                 priorities, size);
    }
  }

  bool handled = false;
  HighlightVarCommand(input, tokens, colors, priorities, size, &handled);
  if (handled) {
    HighlightVarReferences(input, tokens, colors, priorities, size);
    return;
  }

  std::string trimmed = AMStr::TrimWhitespaceCopy(input);
  if (!trimmed.empty() && trimmed.front() == '$') {
    size_t offset = input.find('$');
    size_t eq_pos = FindEqualOutsideQuotes(input, offset);
    if (eq_pos != std::string::npos) {
      ApplyRange(eq_pos, eq_pos + 1, AMTokenType::EqualSign, colors, priorities,
                 size);
      ApplyRange(eq_pos + 1, input.size(), AMTokenType::VarValue, colors,
                 priorities, size);
      size_t end = 0;
      if (ParseVarTokenAt(input, offset, eq_pos, &end)) {
        HighlightVarToken(offset, end, colors, priorities, size);
      }
      HighlightVarReferences(input, tokens, colors, priorities, size);
      return;
    }
  }

  const CommandNode *node = nullptr;
  size_t consumed = 0;
  HighlightCommandsAndOptions(input, tokens, colors, priorities, size, &node,
                              &consumed);

  HighlightNicknameAtSign(input, tokens, colors, priorities, size);
  HighlightVarReferences(input, tokens, colors, priorities, size);
}
