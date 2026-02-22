#include "AMCLI/InteractiveLoop.hpp"
#include "AMBase/CommonTools.hpp"
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
