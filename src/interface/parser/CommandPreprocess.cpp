#include "interface/parser/CommandPreprocess.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/parser/CommandTree.hpp"

#include <optional>

namespace AMInterface::parser {
namespace {

struct CliTokenWithMeta_ {
  std::string text = {};
  bool quoted = false;
};

constexpr char kQuotedDashShellCmdSentinel_ = '\x1D';

/**
 * @brief Restore backtick escapes and strip syntactic quote delimiters.
 *
 * In preprocess tokenization, only quote escapes are restored (`"` / `\'`).
 * Other backtick escapes are kept as literal text for downstream resolvers.
 */
std::string UnescapeCliToken_(const std::string &token) {
  if (token.empty()) {
    return token;
  }
  std::string out;
  out.reserve(token.size());
  char active_quote = 0;
  for (size_t i = 0; i < token.size(); ++i) {
    const char c = token[i];
    if (c == '`' && i + 1 < token.size()) {
      const char next = token[i + 1];
      if (next == '"' || next == '\'') {
        out.push_back(next);
        ++i;
        continue;
      }
      out.push_back(c);
      continue;
    }
    if (c == '"' || c == '\'') {
      if (active_quote == 0) {
        active_quote = c;
        continue;
      }
      if (active_quote == c) {
        active_quote = 0;
        continue;
      }
    }
    out.push_back(c);
  }
  return out;
}

ResolvedStringMeta ResolveStringMetaImpl_(const std::string &text) {
  ResolvedStringMeta out = {};
  out.value.reserve(text.size());
  out.chars.reserve(text.size());

  for (size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (c == '`' && i + 1 < text.size()) {
      const char next = text[i + 1];
      if (next == '$' || next == '@' || next == '`' || next == '"' ||
          next == '\'') {
        out.value.push_back(next);
        out.chars.push_back(ResolvedCharMeta{true, next});
        ++i;
        continue;
      }
      out.value.push_back(c);
      out.chars.push_back(ResolvedCharMeta{false, '\0'});
      continue;
    }
    out.value.push_back(c);
    out.chars.push_back(ResolvedCharMeta{false, '\0'});
  }
  return out;
}

size_t FindFirstUnescapedChar_(const std::string &text, char target) {
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

bool StartsWithLongOption_(const std::string &text) {
  return text.size() > 2 && text[0] == '-' && text[1] == '-';
}

bool StartsWithShortOption_(const std::string &text) {
  return text.size() >= 2 && text[0] == '-' && text[1] != '-';
}

bool StartsWithDashLiteral_(const std::string &text) {
  return text.size() >= 2 && text[0] == '-';
}

std::vector<CliTokenWithMeta_>
SplitCliTokensWithMeta_(const std::string &input,
                        const AMInterface::input::InputAnalyzer &analyzer) {
  std::vector<CliTokenWithMeta_> out = {};
  const auto split = analyzer.SplitTokens(input);
  out.reserve(split.size());
  for (const auto &token : split) {
    if (token.content_end < token.content_start ||
        token.content_end > input.size()) {
      continue;
    }
    const std::string raw = input.substr(
        token.content_start, token.content_end - token.content_start);
    const std::string normalized = UnescapeCliToken_(raw);
    if (normalized.empty()) {
      continue;
    }
    out.push_back({normalized, token.quoted});
  }
  return out;
}

void ConsumePendingOptionValue_(
    std::optional<CommandNode::OptionValueRule> *rule, size_t *value_index) {
  if (!rule || !value_index || !rule->has_value()) {
    return;
  }
  ++(*value_index);
  if (!rule->value().repeat_tail && *value_index >= rule->value().value_count) {
    rule->reset();
    *value_index = 0;
  }
}

void SetPendingOptionValueByToken_(
    const std::string &token, const std::string &command_path,
    const CommandNode *command_tree,
    std::optional<CommandNode::OptionValueRule> *pending_rule,
    size_t *pending_value_index) {
  if (!command_tree || !pending_rule || !pending_value_index ||
      command_path.empty()) {
    return;
  }

  if (StartsWithLongOption_(token)) {
    const size_t eq_pos = token.find('=');
    const std::string option_name =
        (eq_pos == std::string::npos) ? token : token.substr(0, eq_pos);
    const auto rule = command_tree->ResolveOptionValueRule(
        command_path, option_name, '\0', 0);
    if (!rule.has_value()) {
      return;
    }
    if (eq_pos == std::string::npos || eq_pos + 1 >= token.size()) {
      *pending_rule = rule;
      *pending_value_index = 0;
      return;
    }
    if (rule->repeat_tail || rule->value_count > 1) {
      *pending_rule = rule;
      *pending_value_index = 1;
      if (!pending_rule->value().repeat_tail &&
          *pending_value_index >= pending_rule->value().value_count) {
        pending_rule->reset();
        *pending_value_index = 0;
      }
    }
    return;
  }

  if (!StartsWithShortOption_(token)) {
    return;
  }

  const std::string body = token.substr(1);
  for (size_t cidx = 0; cidx < body.size(); ++cidx) {
    const auto rule =
        command_tree->ResolveOptionValueRule(command_path, "", body[cidx], 0);
    if (!rule.has_value()) {
      continue;
    }
    if (cidx + 1 < body.size()) {
      *pending_rule = rule;
      *pending_value_index = 1;
      if (!pending_rule->value().repeat_tail &&
          *pending_value_index >= pending_rule->value().value_count) {
        pending_rule->reset();
        *pending_value_index = 0;
      }
    } else {
      *pending_rule = rule;
      *pending_value_index = 0;
    }
    return;
  }
}

void ProtectQuotedDashLiterals_(std::vector<CliTokenWithMeta_> *tokens,
                                const CommandNode *command_tree) {
  if (!tokens || tokens->empty() || !command_tree) {
    return;
  }

  const auto &src = *tokens;
  const CommandNode *node = nullptr;
  std::string command_path = {};
  size_t command_tokens = 0;

  for (size_t idx = 0; idx < src.size(); ++idx) {
    const auto &token = src[idx];
    const std::string &text = token.text;
    if (text.empty() || token.quoted) {
      continue;
    }
    if (command_path.empty()) {
      if (text == "--" || StartsWithLongOption_(text) ||
          StartsWithShortOption_(text)) {
        return;
      }
      if (command_tree->IsTopCommand(text)) {
        node = command_tree->Find(text);
        command_path = text;
        command_tokens = idx + 1;
        continue;
      }
      return;
    }
    if (node && node->subcommands.contains(text)) {
      command_path += " " + text;
      node = command_tree->Find(command_path);
      command_tokens = idx + 1;
      continue;
    }
    break;
  }
  if (!node || command_path.empty()) {
    return;
  }

  std::vector<CliTokenWithMeta_> rewritten = {};
  rewritten.reserve(src.size());
  std::optional<CommandNode::OptionValueRule> pending_value_rule = std::nullopt;
  size_t pending_value_index = 0;
  size_t positional_index = 0;

  for (size_t idx = 0; idx < src.size(); ++idx) {
    const auto &token = src[idx];
    const std::string &text = token.text;
    if (idx < command_tokens || text.empty()) {
      rewritten.push_back(token);
      continue;
    }
    if (pending_value_rule.has_value()) {
      ConsumePendingOptionValue_(&pending_value_rule, &pending_value_index);
      rewritten.push_back(token);
      continue;
    }
    const bool option_definition =
        !token.quoted &&
        (StartsWithLongOption_(text) || StartsWithShortOption_(text));
    if (option_definition) {
      SetPendingOptionValueByToken_(text, command_path, command_tree,
                                    &pending_value_rule, &pending_value_index);
      rewritten.push_back(token);
      continue;
    }

    // Quoted '-' literals collide with CLI11 options.
    // - Path positionals: map to equivalent relative path ("./-x").
    // - Shell command positionals: prefix one private sentinel to keep literal
    //   value while avoiding option classification in CLI11.
    if (token.quoted && StartsWithDashLiteral_(text)) {
      const auto semantic = command_tree->ResolvePositionalSemantic(
          command_path, positional_index);
      if (semantic.has_value() &&
          semantic.value() == AMCommandArgSemantic::Path) {
        auto rewritten_token = token;
        rewritten_token.text = AMStr::fmt("./{}", text);
        rewritten.push_back(std::move(rewritten_token));
        ++positional_index;
        continue;
      }
      if (semantic.has_value() &&
          semantic.value() == AMCommandArgSemantic::ShellCmd) {
        auto rewritten_token = token;
        rewritten_token.text =
            std::string(1, kQuotedDashShellCmdSentinel_) + text;
        rewritten.push_back(std::move(rewritten_token));
        ++positional_index;
        continue;
      }
    }
    rewritten.push_back(token);
    ++positional_index;
  }
  *tokens = std::move(rewritten);
}

} // namespace

/**
 * @brief Split interactive command text into CLI11 argument tokens.
 */
std::vector<std::string>
AMInputPreprocess::SplitCliTokens(const std::string &input) const {
  const auto split = SplitCliTokensWithMeta_(input, input_analyzer_);
  std::vector<std::string> out;
  out.reserve(split.size());
  for (const auto &token : split) {
    if (!token.text.empty()) {
      out.push_back(token.text);
    }
  }
  return out;
}

ECMData<std::vector<std::string>>
AMInputPreprocess::Preprocess(const std::string &input) const {
  const std::string trimmed = AMStr::Strip(input);
  if (trimmed.empty()) {
    return {{}, OK};
  }

  // Branch 1: shell shorthand `!cmd` -> {"cmd", "<cmd>", ...}
  if (!trimmed.empty() && trimmed.front() == '!') {
    const std::string command = AMStr::Strip(trimmed.substr(1));
    if (command.empty()) {
      return {{}, Err(EC::InvalidArg, "", "", "Empty shell command")};
    }
    return {{"cmd", command}, OK};
  }

  // Branch 2: var define shorthand `$name=value` / `${zone:name}=value`
  const size_t eq = FindFirstUnescapedChar_(trimmed, '=');
  if (eq != std::string::npos) {
    const std::string lhs = AMStr::Strip(trimmed.substr(0, eq));
    if (!lhs.empty() && lhs.front() == '$' &&
        (var_interface_service_.ParseVarTokenExpression(lhs).rcm)) {
      const std::string rhs_raw = AMStr::Strip(trimmed.substr(eq + 1));
      const std::string rhs = UnescapeCliToken_(rhs_raw);
      return {{"var", "def", lhs, rhs}, OK};
    }
  }

  // Branch 3: normal token split + shortcut rewrite.
  auto split = SplitCliTokensWithMeta_(input, input_analyzer_);
  ProtectQuotedDashLiterals_(&split, input_analyzer_.CommandTree());
  std::vector<std::string> out = {};
  out.reserve(split.size());
  for (const auto &token : split) {
    if (!token.text.empty()) {
      out.push_back(token.text);
    }
  }
  RewriteVarShortcutTokens(&out);
  return {std::move(out), OK};
}

bool AMInputPreprocess::RewriteVarShortcutTokens(
    std::vector<std::string> *tokens) const {
  return var_interface_service_.RewriteVarShortcutTokens(tokens);
}

ECMData<ResolvedStringMeta>
AMInputPreprocess::ResolveStringMeta(const std::string &input) {
  return {ResolveStringMetaImpl_(input), OK};
}

} // namespace AMInterface::parser
