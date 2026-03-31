#include "interface/parser/CommandPreprocess.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/parser/TokenTypeAnalyzer.hpp"

using EC = ErrorCode;

namespace AMInterface::parser {
namespace {
/**
 * @brief Restore backtick escapes and strip syntactic quote delimiters.
 *
 * Keep `` `$`` intact so escaped variable shorthand is not expanded later.
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
      if (next == '$') {
        out.push_back('`');
        out.push_back('$');
      } else {
        out.push_back(next);
      }
      ++i;
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

std::string UnescapeAllBackticks_(const std::string &text) {
  if (text.empty()) {
    return text;
  }
  std::string out;
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '`' && i + 1 < text.size()) {
      out.push_back(text[i + 1]);
      ++i;
      continue;
    }
    out.push_back(text[i]);
  }
  return out;
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
    return {{}, Ok()};
  }

  // Branch 1: shell shorthand `!cmd` -> {"cmd", "<cmd>", ...}
  if (!trimmed.empty() && trimmed.front() == '!') {
    const std::string command = AMStr::Strip(trimmed.substr(1));
    if (command.empty()) {
      return {{}, Err(EC::InvalidArg, "Empty shell command")};
    }
    return {{"cmd", command}, Ok()};
  }

  // Branch 2: var define shorthand `$name=value` / `${zone:name}=value`
  const size_t eq = FindFirstUnescapedChar_(trimmed, '=');
  if (eq != std::string::npos) {
    const std::string lhs = AMStr::Strip(trimmed.substr(0, eq));
    if (!lhs.empty() && lhs.front() == '$' &&
        isok(var_interface_service_.ParseVarTokenExpression(lhs).rcm)) {
      const std::string rhs_raw = AMStr::Strip(trimmed.substr(eq + 1));
      const std::string rhs = UnescapeAllBackticks_(rhs_raw);
      return {{"var", "def", lhs, rhs}, Ok()};
    }
  }

  // Branch 3: normal token split.
  return {SplitCliTokens(input), Ok()};
}

bool AMInputPreprocess::RewriteVarShortcutTokens(
    std::vector<std::string> *tokens) const {
  return var_interface_service_.RewriteVarShortcutTokens(tokens);
}

} // namespace AMInterface::parser
