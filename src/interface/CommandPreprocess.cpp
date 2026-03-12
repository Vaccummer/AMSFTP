#include "interface/CommandPreprocess.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "domain/var/VarModel.hpp"
#include "interface/TokenTypeAnalyzer.hpp"

using EC = ErrorCode;

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

/**
 * @brief Shortcut variable-token classification used by preprocessing.
 */
enum class ShortcutVarKind { None, GetVar, ListAll, ListDomain };

/**
 * @brief Parse one shorthand variable token into command intent.
 */
bool ParseShortcutVarToken_(const std::string &token, ShortcutVarKind *out_kind,
                            std::string *out_var_token,
                            std::string *out_domain) {
  if (!out_kind || !out_var_token || !out_domain) {
    return false;
  }
  *out_kind = ShortcutVarKind::None;
  out_var_token->clear();
  out_domain->clear();

  std::string trimmed = AMStr::Strip(token);
  if (trimmed.empty()) {
    return false;
  }
  if (trimmed.size() >= 2 && trimmed[0] == '`' && trimmed[1] == '$') {
    return false;
  }
  if (trimmed == "$") {
    *out_kind = ShortcutVarKind::ListAll;
    return true;
  }
  if (trimmed.front() != '$') {
    return false;
  }

  size_t end = 0;
  varsetkn::VarRef ref{};
  if (!varsetkn::ParseVarRefAt(trimmed, 0, trimmed.size(), false, true, &end,
                               &ref) ||
      !ref.valid || end != trimmed.size()) {
    return false;
  }

  if (ref.varname.empty()) {
    if (!ref.explicit_domain) {
      return false;
    }
    *out_kind = ShortcutVarKind::ListDomain;
    *out_domain = ref.domain;
    return true;
  }

  if (!varsetkn::IsValidVarname(ref.varname)) {
    return false;
  }
  *out_kind = ShortcutVarKind::GetVar;
  *out_var_token = varsetkn::BuildVarToken(ref);
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
 * @brief Expand variable shorthand into `var get/def/ls` tokens.
 */
bool AMInputPreprocess::ExpandVarShortcutTokens(
    std::vector<std::string> *tokens) {
  if (!tokens || tokens->empty()) {
    return false;
  }

  const std::vector<std::string> src = *tokens;
  ShortcutVarKind kind = ShortcutVarKind::None;
  std::string var_token;
  std::string zone;

  if (src.size() == 1) {
    if (ParseShortcutVarToken_(src[0], &kind, &var_token, &zone)) {
      if (kind == ShortcutVarKind::GetVar) {
        *tokens = {"var", "get", var_token};
        return true;
      }
      if (kind == ShortcutVarKind::ListAll) {
        *tokens = {"var", "ls"};
        return true;
      }
      if (kind == ShortcutVarKind::ListDomain) {
        *tokens = {"var", "ls", zone};
        return true;
      }
    }

    const size_t eq = src[0].find('=');
    if (eq == std::string::npos) {
      return false;
    }
    if (!ParseShortcutVarToken_(src[0].substr(0, eq), &kind, &var_token,
                                &zone) ||
        kind != ShortcutVarKind::GetVar) {
      return false;
    }

    *tokens = {"var", "def", var_token, src[0].substr(eq + 1)};
    return true;
  }

  const size_t first_eq = src[0].find('=');
  if (first_eq != std::string::npos &&
      ParseShortcutVarToken_(src[0].substr(0, first_eq), &kind, &var_token,
                             &zone) &&
      kind == ShortcutVarKind::GetVar) {
    const std::string first_rhs = src[0].substr(first_eq + 1);
    *tokens = {"var", "def", var_token, JoinValueWithTail_(first_rhs, src, 1)};
    return true;
  }

  if (!ParseShortcutVarToken_(src[0], &kind, &var_token, &zone) ||
      kind != ShortcutVarKind::GetVar) {
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


