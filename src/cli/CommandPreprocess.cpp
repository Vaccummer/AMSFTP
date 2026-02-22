#include "AMCLI/InteractiveLoop.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMManager/Var.hpp"
#include "AMCLI/TokenTypeAnalyzer.hpp"

using EC = ErrorCode;

namespace {
/**
 * @brief Restore backtick escapes for CLI tokens while preserving `` `$``.
 */
std::string UnescapeCliToken_(const std::string &token) {
  if (token.empty()) {
    return token;
  }
  std::string out;
  out.reserve(token.size());
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
    out.push_back(c);
  }
  return out;
}

/**
 * @brief Parse one shorthand variable token and normalize it as `$name`.
 */
bool ParseShortcutVarToken_(const std::string &token,
                            std::string *normalized_token) {
  if (!normalized_token) {
    return false;
  }
  std::string trimmed = AMStr::Strip(token);
  if (trimmed.empty()) {
    return false;
  }
  if (trimmed.size() >= 2 && trimmed[0] == '`' && trimmed[1] == '$') {
    return false;
  }
  if (trimmed.front() != '$' || trimmed.size() < 2) {
    return false;
  }

  std::string name;
  if (trimmed.size() >= 3 && trimmed[1] == '{' && trimmed.back() == '}') {
    name = AMStr::Strip(trimmed.substr(2, trimmed.size() - 3));
  } else {
    name = trimmed.substr(1);
  }
  if (!varsetkn::IsValidVarname(name)) {
    return false;
  }
  *normalized_token = "$" + name;
  return true;
}

/**
 * @brief Join token range with one blank separator.
 */
std::string JoinTokens_(const std::vector<std::string> &tokens, size_t begin) {
  if (begin >= tokens.size()) {
    return "";
  }
  std::string out;
  for (size_t i = begin; i < tokens.size(); ++i) {
    if (!out.empty()) {
      out.push_back(' ');
    }
    out.append(tokens[i]);
  }
  return out;
}

/**
 * @brief Join value suffix where first segment may be attached to `=`.
 */
std::string JoinValueWithTail_(const std::string &first_segment,
                               const std::vector<std::string> &tokens,
                               size_t begin) {
  std::string out = first_segment;
  if (begin >= tokens.size()) {
    return out;
  }
  const std::string tail = JoinTokens_(tokens, begin);
  if (tail.empty()) {
    return out;
  }
  if (!out.empty()) {
    out.push_back(' ');
  }
  out.append(tail);
  return out;
}
} // namespace

/**
 * @brief Detect `!` shell prefix from one interactive command line.
 */
ECM AMInputPreprocess::ParseShellPrefix(const std::string &input,
                                        std::string *shell_command,
                                        bool *is_shell) {
  if (!shell_command || !is_shell) {
    return Err(EC::InvalidArg, "null output pointer");
  }
  *shell_command = "";
  *is_shell = false;
  const std::string trimmed = AMStr::Strip(input);
  if (trimmed.empty() || trimmed.front() != '!') {
    return Ok();
  }
  const std::string shell = AMStr::Strip(trimmed.substr(1));
  if (shell.empty()) {
    return Err(EC::InvalidArg, "Empty shell command");
  }
  *shell_command = shell;
  *is_shell = true;
  return Ok();
}

/**
 * @brief Split interactive command text into CLI11 argument tokens.
 */
std::vector<std::string>
AMInputPreprocess::SplitCliTokens(const std::string &input) {
  std::vector<std::string> out;
  const auto split = AMTokenTypeAnalyzer::SplitToken(input);
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

/**
 * @brief Expand `$var` / `$var=...` shorthand into `var get/def` tokens.
 */
bool AMInputPreprocess::ExpandVarShortcutTokens(
    std::vector<std::string> *tokens) {
  if (!tokens || tokens->empty()) {
    return false;
  }

  const std::vector<std::string> src = *tokens;
  std::string var_token;

  if (src.size() == 1) {
    if (ParseShortcutVarToken_(src[0], &var_token)) {
      *tokens = {"var", "get", var_token};
      return true;
    }

    const size_t eq = src[0].find('=');
    if (eq == std::string::npos) {
      return false;
    }
    if (!ParseShortcutVarToken_(src[0].substr(0, eq), &var_token)) {
      return false;
    }

    *tokens = {"var", "def", var_token, src[0].substr(eq + 1)};
    return true;
  }

  const size_t first_eq = src[0].find('=');
  if (first_eq != std::string::npos &&
      ParseShortcutVarToken_(src[0].substr(0, first_eq), &var_token)) {
    const std::string first_rhs = src[0].substr(first_eq + 1);
    *tokens = {"var", "def", var_token, JoinValueWithTail_(first_rhs, src, 1)};
    return true;
  }

  if (!ParseShortcutVarToken_(src[0], &var_token)) {
    return false;
  }
  if (src[1] == "=") {
    *tokens = {"var", "def", var_token, JoinTokens_(src, 2)};
    return true;
  }
  if (!src[1].empty() && src[1].front() == '=') {
    const std::string first_rhs = src[1].substr(1);
    *tokens = {"var", "def", var_token, JoinValueWithTail_(first_rhs, src, 2)};
    return true;
  }
  return false;
}
