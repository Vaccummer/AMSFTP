#include "interface/parser/CommandPreprocess.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/token_analyser/TokenTypeAnalyzer.hpp"

using EC = ErrorCode;

namespace AMInterface::parser {
namespace {
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

} // namespace

/**
 * @brief Split interactive command text into CLI11 argument tokens.
 */
std::vector<std::string>
AMInputPreprocess::SplitCliTokens(const std::string &input) const {
  std::vector<std::string> out;
  const auto split = token_type_analyzer_.SplitToken(input);
  out.reserve(split.size());
  for (const auto &token : split) {
    if (token.content_end < token.content_start ||
        token.content_end > input.size()) {
      continue;
    }
    const std::string raw = input.substr(
        token.content_start, token.content_end - token.content_start);
    const std::string normalized = UnescapeCliToken_(raw);
    if (!normalized.empty()) {
      out.push_back(normalized);
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
      return {{}, Err(EC::InvalidArg, __func__, "", "Empty shell command")};
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

  // Branch 3: normal token split.
  return {SplitCliTokens(input), OK};
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


