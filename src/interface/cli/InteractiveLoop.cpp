#include "interface/cli/InteractiveLoop.hpp"
#include "application/client/ClientAppService.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/time.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/completion/Proxy.hpp"
#include "interface/parser/CommandPreprocess.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/parser/TokenTypeAnalyzer.hpp"
#include "interface/prompt/CLICorePrompt.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <magic_enum/magic_enum.hpp>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace AMInterface::cli {

namespace {
using OS_TYPE = AMDomain::client::OS_TYPE;
using DocumentKind = AMDomain::config::DocumentKind;

std::string ResolveStyleSettingString_(
    const AMInterface::style::AMStyleService &style_service,
    const std::vector<std::string> &path, const std::string &fallback = "") {
  if (path.size() < 3 || AMStr::lowercase(path[0]) != "style") {
    return fallback;
  }

  const auto style = style_service.GetInitArg().style;
  const std::string group = AMStr::lowercase(path[1]);
  if (group == "cliprompt") {
    auto shortcut_lookup = [&style](const std::string &key,
                                    const std::string &fallback_value = "") {
      const auto it = style.cli_prompt.shortcut.find(key);
      if (it == style.cli_prompt.shortcut.end()) {
        return fallback_value;
      }
      return it->second;
    };

    if (path.size() == 4) {
      const std::string section = AMStr::lowercase(path[2]);
      const std::string key = AMStr::lowercase(path[3]);
      if (section == "icons") {
        if (key == "windows") {
          return style.cli_prompt.icons.windows;
        }
        if (key == "linux") {
          return style.cli_prompt.icons.linux;
        }
        if (key == "macos") {
          return style.cli_prompt.icons.macos;
        }
        return fallback;
      }
      if (section == "shortcut") {
        return shortcut_lookup(key, fallback);
      }
      if (section == "namedstyles" || section == "named_styles") {
        if (key == "un") {
          return style.cli_prompt.named_styles.un;
        }
        if (key == "at") {
          return style.cli_prompt.named_styles.at;
        }
        if (key == "hn") {
          return style.cli_prompt.named_styles.hn;
        }
        if (key == "en") {
          return style.cli_prompt.named_styles.en;
        }
        if (key == "nn") {
          return style.cli_prompt.named_styles.nn;
        }
        if (key == "cwd") {
          return style.cli_prompt.named_styles.cwd;
        }
        if (key == "ds") {
          return style.cli_prompt.named_styles.ds;
        }
        if (key == "white") {
          return style.cli_prompt.named_styles.white;
        }
        return fallback;
      }
      if (section == "template" || section == "templete") {
        if (key == "core_prompt") {
          return style.cli_prompt.prompt_template.core_prompt;
        }
        if (key == "history_search_prompt") {
          return style.cli_prompt.prompt_template.history_search_prompt;
        }
        return fallback;
      }
      return fallback;
    }

    if (path.size() == 3) {
      const std::string key = AMStr::lowercase(path[2]);
      if (key == "format") {
        return style.cli_prompt.prompt_template.core_prompt;
      }
      if (key == "username" || key == "un") {
        return style.cli_prompt.named_styles.un.empty()
                   ? shortcut_lookup("un")
                   : style.cli_prompt.named_styles.un;
      }
      if (key == "hostname" || key == "hn") {
        return style.cli_prompt.named_styles.hn.empty()
                   ? shortcut_lookup("hn")
                   : style.cli_prompt.named_styles.hn;
      }
      if (key == "nickname" || key == "nn") {
        return style.cli_prompt.named_styles.nn.empty()
                   ? shortcut_lookup("nn")
                   : style.cli_prompt.named_styles.nn;
      }
      if (key == "cwd") {
        return style.cli_prompt.named_styles.cwd.empty()
                   ? shortcut_lookup("cwd")
                   : style.cli_prompt.named_styles.cwd;
      }
      if (key == "dollarsign" || key == "ds") {
        return style.cli_prompt.named_styles.ds.empty()
                   ? shortcut_lookup("ds")
                   : style.cli_prompt.named_styles.ds;
      }
      if (key == "at") {
        return style.cli_prompt.named_styles.at.empty()
                   ? shortcut_lookup("at")
                   : style.cli_prompt.named_styles.at;
      }
      if (key == "en") {
        return style.cli_prompt.named_styles.en.empty()
                   ? shortcut_lookup("en")
                   : style.cli_prompt.named_styles.en;
      }
      if (key == "white") {
        return style.cli_prompt.named_styles.white.empty()
                   ? shortcut_lookup("white")
                   : style.cli_prompt.named_styles.white;
      }
      return fallback;
    }
  }

  if (group == "systeminfo" || group == "system_info") {
    if (path.size() != 3) {
      return fallback;
    }
    const std::string key = AMStr::lowercase(path[2]);
    if (key == "info") {
      return style.system_info.info;
    }
    if (key == "success") {
      return style.system_info.success;
    }
    if (key == "error") {
      return style.system_info.error;
    }
    if (key == "warning") {
      return style.system_info.warning;
    }
  }

  return fallback;
}

/**
 * @brief Track prompt rendering state across iterations.
 */
struct PromptState {
  ECM last_rcm = {EC::Success, ""};
  std::string last_elapsed = "-";
  std::string cached_prefix;
  std::string last_nickname;
  std::string cached_sysicon;
  std::string cached_username;
  std::string cached_hostname;
};

/**
 * @brief Parse a hex color token (#RGB or #RRGGBB) into RGB components.
 *
 * @param hex Color token with or without a leading '#'.
 * @param r Output red component.
 * @param g Output green component.
 * @param b Output blue component.
 * @return True if parsing succeeds; false otherwise.
 */
bool ParseHexColor_(const std::string &hex, int *r, int *g, int *b) {
  if (!r || !g || !b) {
    return false;
  }

  std::string value = hex;
  if (!value.empty() && value.front() == '#') {
    value.erase(value.begin());
  }
  if (!(value.size() == 3 || value.size() == 6)) {
    return false;
  }

  auto hex_to_int = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
      return 10 + (c - 'A');
    }
    return -1;
  };

  if (value.size() == 3) {
    const int r_n = hex_to_int(value[0]);
    const int g_n = hex_to_int(value[1]);
    const int b_n = hex_to_int(value[2]);
    if (r_n < 0 || g_n < 0 || b_n < 0) {
      return false;
    }
    *r = r_n * 17;
    *g = g_n * 17;
    *b = b_n * 17;
    return true;
  }

  for (char c : value) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }

  *r = std::stoi(value.substr(0, 2), nullptr, 16);
  *g = std::stoi(value.substr(2, 2), nullptr, 16);
  *b = std::stoi(value.substr(4, 2), nullptr, 16);
  return true;
}

/**
 * @brief Find the next unescaped target character in the format string.
 *
 * @param input Full format string.
 * @param target Character to search for.
 * @param start Start index for scanning.
 * @return Index of the target or npos if not found.
 */
size_t FindUnescapedChar_(const std::string &input, char target, size_t start) {
  for (size_t i = start; i < input.size(); ++i) {
    if (input[i] == '`') {
      if (i + 1 < input.size()) {
        ++i;
      }
      continue;
    }
    if (input[i] == target) {
      return i;
    }
  }
  return std::string::npos;
}

/**
 * @brief Build an ANSI escape sequence from a style definition string.
 *
 * @param raw Style definition (e.g., "[#RRGGBB b]" or "#RRGGBB b").
 * @param ansi_code Output ANSI escape sequence (e.g., "\x1b[1;38;2;...m").
 * @return True if a valid style was parsed; false otherwise.
 */
bool TryBuildAnsiStyleCode_(const std::string &raw, std::string *ansi_code) {
  if (!ansi_code) {
    return false;
  }
  ansi_code->clear();

  std::string tag = AMStr::Strip(raw);
  if (tag.empty()) {
    return false;
  }
  if (tag.front() == '[' && tag.back() == ']') {
    tag = tag.substr(1, tag.size() - 2);
  }
  tag = AMStr::Strip(tag);
  if (tag.empty()) {
    return false;
  }

  bool bold = false;
  bool italic = false;
  bool underline = false;
  bool reverse = false;
  bool strike = false;
  bool expect_bg = false;
  bool has_style = false;
  int fg_r = -1;
  int fg_g = -1;
  int fg_b = -1;
  int bg_r = -1;
  int bg_g = -1;
  int bg_b = -1;

  std::istringstream iss(tag);
  std::string token;
  while (iss >> token) {
    if (token == "on") {
      expect_bg = true;
      continue;
    }
    if (token == "b") {
      bold = true;
      has_style = true;
      continue;
    }
    if (token == "i") {
      italic = true;
      has_style = true;
      continue;
    }
    if (token == "u") {
      underline = true;
      has_style = true;
      continue;
    }
    if (token == "r") {
      reverse = true;
      has_style = true;
      continue;
    }
    if (token == "s") {
      strike = true;
      has_style = true;
      continue;
    }

    bool is_bg = expect_bg;
    expect_bg = false;
    if (token.rfind("color=", 0) == 0) {
      token = token.substr(6);
      is_bg = false;
    } else if (token.rfind("bgcolor=", 0) == 0) {
      token = token.substr(8);
      is_bg = true;
    } else if (token.rfind("bg=", 0) == 0) {
      token = token.substr(3);
      is_bg = true;
    }

    int r = 0;
    int g = 0;
    int b = 0;
    if (token.rfind('#', 0) == 0 && ParseHexColor_(token, &r, &g, &b)) {
      if (is_bg) {
        bg_r = r;
        bg_g = g;
        bg_b = b;
      } else {
        fg_r = r;
        fg_g = g;
        fg_b = b;
      }
      has_style = true;
      continue;
    }
  }

  if (!has_style) {
    return false;
  }

  std::ostringstream oss;
  oss << "\x1b[";
  bool first = true;
  auto append_code = [&oss, &first](const std::string &code) {
    if (code.empty()) {
      return;
    }
    if (!first) {
      oss << ";";
    }
    oss << code;
    first = false;
  };

  if (bold) {
    append_code("1");
  }
  if (italic) {
    append_code("3");
  }
  if (underline) {
    append_code("4");
  }
  if (reverse) {
    append_code("7");
  }
  if (strike) {
    append_code("9");
  }
  if (fg_r >= 0) {
    append_code(AMStr::fmt("38;2;{};{};{}", fg_r, fg_g, fg_b));
  }
  if (bg_r >= 0) {
    append_code(AMStr::fmt("48;2;{};{};{}", bg_r, bg_g, bg_b));
  }

  oss << "m";
  *ansi_code = oss.str();
  return true;
}

/**
 * @brief Resolve a prompt style tag into an ANSI escape sequence.
 *
 * @param tag_name Tag name from format (e.g., "un" or "#RRGGBB b").
 * @param ansi_code Output ANSI escape sequence when resolved.
 * @return True if a style was resolved; false otherwise.
 */
bool ResolvePromptStyleAnsi_(
    const AMInterface::style::AMStyleService &style_service,
    const std::string &tag_name, std::string *ansi_code) {
  if (!ansi_code) {
    return false;
  }
  ansi_code->clear();
  std::string trimmed = AMStr::Strip(tag_name);
  if (trimmed.empty()) {
    return false;
  }

  if (TryBuildAnsiStyleCode_(trimmed, ansi_code)) {
    return true;
  }

  auto raw = ResolveStyleSettingString_(style_service,
                                        {"Style", "CLIPrompt", trimmed}, "");
  if (raw.empty()) {
    raw = ResolveStyleSettingString_(
        style_service, {"Style", "CLIPrompt", "shortcut", trimmed}, "");
  }
  if (raw.empty()) {
    return false;
  }
  return TryBuildAnsiStyleCode_(raw, ansi_code);
}

/**
 * @brief Resolve the interactive prompt format string from settings.
 *
 * Supports both legacy `Style.CLIPrompt.format` and the newer
 * `Style.CLIPrompt.templete.core_prompt` layout.
 */
std::string ResolveCorePromptFormat_(
    const AMInterface::style::AMStyleService &style_service) {
  std::string format = ResolveStyleSettingString_(
      style_service, {"Style", "CLIPrompt", "templete", "core_prompt"}, "");
  if (!format.empty()) {
    return format;
  }
  format = ResolveStyleSettingString_(
      style_service, {"Style", "CLIPrompt", "template", "core_prompt"}, "");
  if (!format.empty()) {
    return format;
  }
  return ResolveStyleSettingString_(style_service,
                                    {"Style", "CLIPrompt", "format"}, "");
}

/**
 * @brief Decide whether a condition string should be treated as true.
 *
 * @param value Condition string after formatting.
 * @return True if the condition is truthy; false otherwise.
 */
bool IsTruthy_(const std::string &value) {
  std::string trimmed = AMStr::Strip(value);
  if (trimmed.empty()) {
    return false;
  }
  std::string lowered = AMStr::lowercase(trimmed);
  if (lowered == "0" || lowered == "false" || lowered == "no" ||
      lowered == "off") {
    return false;
  }
  return true;
}

/**
 * @brief Token types for prompt condition expressions.
 */
enum class ExprTokenType {
  End,
  Number,
  Ident,
  String,
  LParen,
  RParen,
  And,
  Or,
  Eq,
  Lt,
  Gt,
  Le,
  Ge,
  Invalid
};

/**
 * @brief Single token produced by the condition lexer.
 */
struct ExprToken {
  ExprTokenType type = ExprTokenType::End;
  std::string text;
  double number = 0.0;
};

/**
 * @brief Value container for condition evaluation.
 */
struct ExprValue {
  enum class Kind { Number, String, Bool };
  Kind kind = Kind::String;
  double number = 0.0;
  std::string text;
  bool boolean = false;
};

/**
 * @brief Parser state for the condition evaluator.
 */
struct ExprParserState {
  const std::string *expr = nullptr;
  size_t index = 0;
  ExprToken current;
  bool ok = true;
};

/**
 * @brief Build a numeric expression value.
 */
ExprValue MakeExprNumber_(double value) {
  ExprValue out;
  out.kind = ExprValue::Kind::Number;
  out.number = value;
  return out;
}

/**
 * @brief Build a string expression value.
 */
ExprValue MakeExprString_(const std::string &value) {
  ExprValue out;
  out.kind = ExprValue::Kind::String;
  out.text = value;
  return out;
}

/**
 * @brief Build a boolean expression value.
 */
ExprValue MakeExprBool_(bool value) {
  ExprValue out;
  out.kind = ExprValue::Kind::Bool;
  out.boolean = value;
  return out;
}

/**
 * @brief Convert an expression value into a boolean.
 */
bool ExprValueToBool_(const ExprValue &value) {
  switch (value.kind) {
  case ExprValue::Kind::Bool:
    return value.boolean;
  case ExprValue::Kind::Number:
    return value.number != 0.0;
  case ExprValue::Kind::String:
    return IsTruthy_(value.text);
  default:
    return false;
  }
}

/**
 * @brief Convert an expression value into a string representation.
 */
std::string ExprValueToString_(const ExprValue &value) {
  switch (value.kind) {
  case ExprValue::Kind::Bool:
    return value.boolean ? "true" : "false";
  case ExprValue::Kind::Number: {
    std::ostringstream oss;
    oss << value.number;
    return oss.str();
  }
  case ExprValue::Kind::String:
    return value.text;
  default:
    return "";
  }
}

/**
 * @brief Determine if the character is a delimiter for identifiers.
 */
bool IsExprDelimiter_(char c) {
  return std::isspace(static_cast<unsigned char>(c)) || c == '(' || c == ')' ||
         c == '&' || c == '|' || c == '=' || c == '<' || c == '>';
}

/**
 * @brief Lex the next token from an expression string.
 */
ExprToken NextExprToken_(const std::string &expr, size_t *index) {
  ExprToken token;
  if (!index) {
    token.type = ExprTokenType::Invalid;
    return token;
  }

  size_t i = *index;
  while (i < expr.size() && std::isspace(static_cast<unsigned char>(expr[i]))) {
    ++i;
  }
  if (i >= expr.size()) {
    *index = i;
    token.type = ExprTokenType::End;
    return token;
  }

  const char c = expr[i];
  if (c == '&' && i + 1 < expr.size() && expr[i + 1] == '&') {
    *index = i + 2;
    token.type = ExprTokenType::And;
    return token;
  }
  if (c == '|' && i + 1 < expr.size() && expr[i + 1] == '|') {
    *index = i + 2;
    token.type = ExprTokenType::Or;
    return token;
  }
  if (c == '=' && i + 1 < expr.size() && expr[i + 1] == '=') {
    *index = i + 2;
    token.type = ExprTokenType::Eq;
    return token;
  }
  if (c == '<' && i + 1 < expr.size() && expr[i + 1] == '=') {
    *index = i + 2;
    token.type = ExprTokenType::Le;
    return token;
  }
  if (c == '>' && i + 1 < expr.size() && expr[i + 1] == '=') {
    *index = i + 2;
    token.type = ExprTokenType::Ge;
    return token;
  }
  if (c == '<') {
    *index = i + 1;
    token.type = ExprTokenType::Lt;
    return token;
  }
  if (c == '>') {
    *index = i + 1;
    token.type = ExprTokenType::Gt;
    return token;
  }
  if (c == '(') {
    *index = i + 1;
    token.type = ExprTokenType::LParen;
    return token;
  }
  if (c == ')') {
    *index = i + 1;
    token.type = ExprTokenType::RParen;
    return token;
  }

  if (c == '"' || c == '\'') {
    const char quote = c;
    ++i;
    std::string value;
    while (i < expr.size()) {
      char ch = expr[i];
      if (ch == '\\' && i + 1 < expr.size()) {
        value.push_back(expr[i + 1]);
        i += 2;
        continue;
      }
      if (ch == quote) {
        ++i;
        token.type = ExprTokenType::String;
        token.text = value;
        *index = i;
        return token;
      }
      value.push_back(ch);
      ++i;
    }
    token.type = ExprTokenType::Invalid;
    *index = expr.size();
    return token;
  }

  auto is_digit = [](char ch) {
    return std::isdigit(static_cast<unsigned char>(ch));
  };
  if (is_digit(c) ||
      (c == '.' && i + 1 < expr.size() && is_digit(expr[i + 1])) ||
      (c == '-' && i + 1 < expr.size() && is_digit(expr[i + 1]))) {
    size_t start = i;
    if (expr[i] == '-') {
      ++i;
    }
    bool saw_digit = false;
    while (i < expr.size() && is_digit(expr[i])) {
      saw_digit = true;
      ++i;
    }
    if (i < expr.size() && expr[i] == '.') {
      ++i;
      while (i < expr.size() && is_digit(expr[i])) {
        saw_digit = true;
        ++i;
      }
    }
    if (saw_digit) {
      const std::string number_text = expr.substr(start, i - start);
      token.type = ExprTokenType::Number;
      token.text = number_text;
      token.number = std::strtod(number_text.c_str(), nullptr);
      *index = i;
      return token;
    }
  }

  size_t start = i;
  while (i < expr.size() && !IsExprDelimiter_(expr[i])) {
    ++i;
  }
  token.type = ExprTokenType::Ident;
  token.text = expr.substr(start, i - start);
  *index = i;
  return token;
}

/**
 * @brief Initialize parser state and read the first token.
 */
void InitExprParser_(const std::string &expr, ExprParserState *state) {
  if (!state) {
    return;
  }
  state->expr = &expr;
  state->index = 0;
  state->ok = true;
  state->current = NextExprToken_(expr, &state->index);
}

/**
 * @brief Advance the parser to the next token.
 */
void AdvanceExprParser_(ExprParserState *state) {
  if (!state || !state->expr) {
    return;
  }
  state->current = NextExprToken_(*state->expr, &state->index);
}

/**
 * @brief Parse logical OR expressions.
 */
ExprValue ParseExprOr_(ExprParserState *state);

/**
 * @brief Parse a primary expression node.
 */
ExprValue ParseExprPrimary_(ExprParserState *state) {
  if (!state || !state->ok) {
    return MakeExprBool_(false);
  }

  const ExprToken &tok = state->current;
  if (tok.type == ExprTokenType::Number) {
    AdvanceExprParser_(state);
    return MakeExprNumber_(tok.number);
  }
  if (tok.type == ExprTokenType::String) {
    AdvanceExprParser_(state);
    return MakeExprString_(tok.text);
  }
  if (tok.type == ExprTokenType::Ident) {
    const std::string lowered = AMStr::lowercase(tok.text);
    AdvanceExprParser_(state);
    if (lowered == "true") {
      return MakeExprBool_(true);
    }
    if (lowered == "false") {
      return MakeExprBool_(false);
    }
    return MakeExprString_(tok.text);
  }
  if (tok.type == ExprTokenType::LParen) {
    AdvanceExprParser_(state);
    ExprValue inner = ParseExprOr_(state);
    if (state->current.type == ExprTokenType::RParen) {
      AdvanceExprParser_(state);
      return inner;
    }
    state->ok = false;
    return MakeExprBool_(false);
  }

  state->ok = false;
  return MakeExprBool_(false);
}

/**
 * @brief Compare two expression values using a comparison operator.
 */
bool CompareExprValues_(const ExprValue &lhs, const ExprValue &rhs,
                        ExprTokenType op) {
  const bool both_numeric = lhs.kind == ExprValue::Kind::Number &&
                            rhs.kind == ExprValue::Kind::Number;
  if (both_numeric) {
    switch (op) {
    case ExprTokenType::Eq:
      return lhs.number == rhs.number;
    case ExprTokenType::Lt:
      return lhs.number < rhs.number;
    case ExprTokenType::Le:
      return lhs.number <= rhs.number;
    case ExprTokenType::Gt:
      return lhs.number > rhs.number;
    case ExprTokenType::Ge:
      return lhs.number >= rhs.number;
    default:
      return false;
    }
  }

  const std::string left = ExprValueToString_(lhs);
  const std::string right = ExprValueToString_(rhs);
  switch (op) {
  case ExprTokenType::Eq:
    return left == right;
  case ExprTokenType::Lt:
    return left < right;
  case ExprTokenType::Le:
    return left <= right;
  case ExprTokenType::Gt:
    return left > right;
  case ExprTokenType::Ge:
    return left >= right;
  default:
    return false;
  }
}

/**
 * @brief Parse comparison expressions (==, <, <=, >, >=).
 */
ExprValue ParseExprCompare_(ExprParserState *state) {
  ExprValue left = ParseExprPrimary_(state);
  while (state->ok) {
    ExprTokenType op = state->current.type;
    if (op != ExprTokenType::Eq && op != ExprTokenType::Lt &&
        op != ExprTokenType::Le && op != ExprTokenType::Gt &&
        op != ExprTokenType::Ge) {
      break;
    }
    AdvanceExprParser_(state);
    ExprValue right = ParseExprPrimary_(state);
    const bool result = CompareExprValues_(left, right, op);
    left = MakeExprBool_(result);
  }
  return left;
}

/**
 * @brief Parse logical AND expressions.
 */
ExprValue ParseExprAnd_(ExprParserState *state) {
  ExprValue left = ParseExprCompare_(state);
  while (state->ok && state->current.type == ExprTokenType::And) {
    AdvanceExprParser_(state);
    ExprValue right = ParseExprCompare_(state);
    left = MakeExprBool_(ExprValueToBool_(left) && ExprValueToBool_(right));
  }
  return left;
}

/**
 * @brief Parse logical OR expressions.
 */
ExprValue ParseExprOr_(ExprParserState *state) {
  ExprValue left = ParseExprAnd_(state);
  while (state->ok && state->current.type == ExprTokenType::Or) {
    AdvanceExprParser_(state);
    ExprValue right = ParseExprAnd_(state);
    left = MakeExprBool_(ExprValueToBool_(left) || ExprValueToBool_(right));
  }
  return left;
}

/**
 * @brief Check if an expression contains explicit operators.
 */
bool ContainsExprOperators_(const std::string &expr) {
  if (expr.empty()) {
    return false;
  }
  for (size_t i = 0; i < expr.size(); ++i) {
    const char c = expr[i];
    if (c == '(' || c == ')' || c == '<' || c == '>') {
      return true;
    }
    if (c == '=' && i + 1 < expr.size() && expr[i + 1] == '=') {
      return true;
    }
    if (c == '&' && i + 1 < expr.size() && expr[i + 1] == '&') {
      return true;
    }
    if (c == '|' && i + 1 < expr.size() && expr[i + 1] == '|') {
      return true;
    }
  }
  return false;
}

/**
 * @brief Evaluate a prompt condition expression.
 */
bool EvaluatePromptExpression_(const std::string &expression) {
  if (!ContainsExprOperators_(expression)) {
    return IsTruthy_(expression);
  }

  ExprParserState state;
  InitExprParser_(expression, &state);
  ExprValue value = ParseExprOr_(&state);
  if (!state.ok) {
    return false;
  }
  if (state.current.type != ExprTokenType::End) {
    return false;
  }
  return ExprValueToBool_(value);
}

/**
 * @brief Render a format string segment with variable substitution.
 *
 * @param format Full format string.
 * @param index Current index in the format string; updated on return.
 * @param vars Variable map (keys include the leading '$').
 * @param style_stack Stack of active ANSI style codes.
 * @param enable_styles Whether to interpret [style] tags as ANSI escapes.
 * @param stop_on_brace Stop rendering when an unescaped '}' is reached.
 * @return Rendered segment text.
 */
std::string
RenderPromptSegment_(const AMInterface::style::AMStyleService &style_service,
                     const std::string &format, size_t *index,
                     const std::unordered_map<std::string, std::string> &vars,
                     std::vector<std::string> *style_stack, bool enable_styles,
                     bool stop_on_brace) {
  if (!index) {
    return "";
  }
  std::string output;
  while (*index < format.size()) {
    const char c = format[*index];
    if (c == '`') {
      if (*index + 1 < format.size()) {
        output.push_back(format[*index + 1]);
        *index += 2;
      } else {
        output.push_back('`');
        ++(*index);
      }
      continue;
    }

    if (stop_on_brace && c == '}') {
      ++(*index);
      break;
    }

    if (c == '{') {
      if (format.compare(*index, 3, "{if") == 0) {
        size_t cursor = *index + 3;
        if (cursor < format.size() && format[cursor] == '{') {
          ++cursor;
          std::string cond = RenderPromptSegment_(
              style_service, format, &cursor, vars, nullptr, false, true);
          bool truthy = EvaluatePromptExpression_(cond);

          if (cursor >= format.size() || format[cursor] != '{') {
            output.push_back('{');
            ++(*index);
            continue;
          }
          ++cursor;
          std::string branch_true =
              RenderPromptSegment_(style_service, format, &cursor, vars,
                                   style_stack, enable_styles, true);

          if (cursor >= format.size() || format[cursor] != '{') {
            output.push_back('{');
            ++(*index);
            continue;
          }
          ++cursor;
          std::string branch_false =
              RenderPromptSegment_(style_service, format, &cursor, vars,
                                   style_stack, enable_styles, true);

          if (cursor < format.size() && format[cursor] == '}') {
            ++cursor;
          }

          *index = cursor;
          output += truthy ? branch_true : branch_false;
          continue;
        }
      }

      size_t close = FindUnescapedChar_(format, '}', *index + 1);
      if (close != std::string::npos && format[*index + 1] == '$') {
        const std::string key = format.substr(*index + 1, close - (*index + 1));
        auto it = vars.find(key);
        if (it != vars.end()) {
          output += it->second;
        }
        *index = close + 1;
        continue;
      }

      output.push_back('{');
      ++(*index);
      continue;
    }

    if (c == '[') {
      size_t close = FindUnescapedChar_(format, ']', *index + 1);
      if (close == std::string::npos) {
        output.push_back('[');
        ++(*index);
        continue;
      }
      const std::string tag = format.substr(*index + 1, close - (*index + 1));
      *index = close + 1;

      if (!enable_styles) {
        continue;
      }

      if (tag == "/") {
        if (style_stack && !style_stack->empty()) {
          const std::string prev = style_stack->back();
          style_stack->pop_back();
          if (!prev.empty()) {
            output += "\x1b[0m";
            for (auto it = style_stack->rbegin(); it != style_stack->rend();
                 ++it) {
              if (!it->empty()) {
                output += *it;
                break;
              }
            }
          }
        }
        continue;
      }

      std::string ansi_code;
      if (ResolvePromptStyleAnsi_(style_service, tag, &ansi_code)) {
        if (style_stack) {
          style_stack->push_back(ansi_code);
        }
        output += ansi_code;
      } else {
        if (style_stack) {
          style_stack->push_back("");
        }
      }
      continue;
    }

    output.push_back(c);
    ++(*index);
  }

  return output;
}

/**
 * @brief Render a prompt format string into ANSI-escaped output.
 *
 * @param format Format string from settings.
 * @param vars Variable map (keys include the leading '$').
 * @return Rendered prompt string with ANSI escape sequences.
 */
std::string
RenderPromptFormat_(const AMInterface::style::AMStyleService &style_service,
                    const std::string &format,
                    const std::unordered_map<std::string, std::string> &vars) {
  size_t index = 0;
  std::vector<std::string> style_stack;
  std::string rendered = RenderPromptSegment_(style_service, format, &index,
                                              vars, &style_stack, true, false);
  for (const auto &style : style_stack) {
    if (!style.empty()) {
      rendered += "\x1b[0m";
      break;
    }
  }
  return rendered;
}

/**
 * @brief Convert a tagged string like "[#RRGGBB b]text[/]" into ANSI color.
 *
 * @param tagged Tagged string with bbcode-style colors.
 * @param converted Output string with ANSI escape sequences.
 * @return True if conversion succeeded; false if format is invalid.
 */
bool TryConvertTaggedTextToAnsi_(const std::string &tagged,
                                 std::string *converted) {
  if (!converted) {
    return false;
  }
  converted->clear();

  if (tagged.size() < 6 || tagged.front() != '[') {
    return false;
  }

  const size_t close = tagged.find(']');
  if (close == std::string::npos) {
    return false;
  }
  const size_t suffix_pos = tagged.rfind("[/]");
  if (suffix_pos == std::string::npos || suffix_pos <= close) {
    return false;
  }

  const std::string tag = tagged.substr(1, close - 1);
  const std::string content =
      tagged.substr(close + 1, suffix_pos - (close + 1));

  bool bold = false;
  bool italic = false;
  bool underline = false;
  bool reverse = false;
  bool strike = false;
  bool expect_bg = false;
  bool has_style = false;
  int fg_r = -1;
  int fg_g = -1;
  int fg_b = -1;
  int bg_r = -1;
  int bg_g = -1;
  int bg_b = -1;

  std::istringstream iss(tag);
  std::string token;
  while (iss >> token) {
    if (token == "on") {
      expect_bg = true;
      continue;
    }
    if (token == "b") {
      bold = true;
      has_style = true;
      continue;
    }
    if (token == "i") {
      italic = true;
      has_style = true;
      continue;
    }
    if (token == "u") {
      underline = true;
      has_style = true;
      continue;
    }
    if (token == "r") {
      reverse = true;
      has_style = true;
      continue;
    }
    if (token == "s") {
      strike = true;
      has_style = true;
      continue;
    }

    bool is_bg = expect_bg;
    expect_bg = false;
    if (token.rfind("color=", 0) == 0) {
      token = token.substr(6);
      is_bg = false;
    } else if (token.rfind("bgcolor=", 0) == 0) {
      token = token.substr(8);
      is_bg = true;
    } else if (token.rfind("bg=", 0) == 0) {
      token = token.substr(3);
      is_bg = true;
    }

    int r = 0;
    int g = 0;
    int b = 0;
    if (token.rfind('#', 0) == 0 && ParseHexColor_(token, &r, &g, &b)) {
      if (is_bg) {
        bg_r = r;
        bg_g = g;
        bg_b = b;
      } else {
        fg_r = r;
        fg_g = g;
        fg_b = b;
      }
      has_style = true;
      continue;
    }
  }

  if (!has_style) {
    return false;
  }

  std::ostringstream oss;
  oss << "\x1b[";
  bool first = true;
  auto append_code = [&oss, &first](const std::string &code) {
    if (code.empty()) {
      return;
    }
    if (!first) {
      oss << ";";
    }
    oss << code;
    first = false;
  };

  if (bold) {
    append_code("1");
  }
  if (italic) {
    append_code("3");
  }
  if (underline) {
    append_code("4");
  }
  if (reverse) {
    append_code("7");
  }
  if (strike) {
    append_code("9");
  }
  if (fg_r >= 0) {
    append_code(AMStr::fmt("38;2;{};{};{}", fg_r, fg_g, fg_b));
  }
  if (bg_r >= 0) {
    append_code(AMStr::fmt("48;2;{};{};{}", bg_r, bg_g, bg_b));
  }

  oss << "m" << content << "\x1b[0m";
  *converted = oss.str();
  return true;
}

/**
 * @brief Extract inner text from a tagged string like "[...]text[/]".
 *
 * @param tagged Tagged string to extract from.
 * @param extracted Output string with the inner content only.
 * @return True if extraction succeeded; false otherwise.
 */
bool TryExtractTaggedText_(const std::string &tagged, std::string *extracted) {
  if (!extracted) {
    return false;
  }
  extracted->clear();

  const size_t close = tagged.find(']');
  if (close == std::string::npos) {
    return false;
  }
  const size_t suffix_pos = tagged.rfind("[/]");
  if (suffix_pos == std::string::npos || suffix_pos <= close) {
    return false;
  }

  *extracted = tagged.substr(close + 1, suffix_pos - (close + 1));
  return true;
}

/**
 * @brief Apply a bbcode style tag from settings to text and convert to ANSI.
 *
 * @param path Settings path under the style tree.
 * @param text Raw text to style.
 * @return Styled text with ANSI escape sequences when possible.
 */
std::string
ApplyStyleFromConfig_(const std::vector<std::string> &path,
                      const std::string &text,
                      const AMInterface::style::AMStyleService &style_service) {
  if (text.empty()) {
    return text;
  }

  std::string raw =
      AMStr::Strip(ResolveStyleSettingString_(style_service, path));
  if (raw.empty()) {
    return text;
  }
  if (raw.front() != '[' || raw.back() != ']') {
    return text;
  }
  if (raw.find("[/") != std::string::npos) {
    return text;
  }

  const std::string tagged = raw + text + "[/]";
  std::string converted;
  if (TryConvertTaggedTextToAnsi_(tagged, &converted)) {
    return converted;
  }

  std::string extracted;
  if (TryExtractTaggedText_(tagged, &extracted)) {
    return extracted;
  }
  return text;
}

/**
 * @brief Return the active client or the local client fallback.
 */
AMDomain::client::ClientHandle
ResolveActiveClient_(AMApplication::client::ClientAppService &client_service) {
  return client_service.GetCurrentClient();
}

/**
 * @brief Resolve prompt username/hostname with environment fallbacks.
 */
std::pair<std::string, std::string>
ResolveUserHost_(const AMDomain::client::ClientHandle &client) {
  std::string username;
  std::string hostname;
  if (client) {
    AMDomain::client::ConRequest request = client->ConfigPort().GetRequest();
    username = request.username;
    hostname = request.hostname;
  }

  auto read_env = [](const char *key) {
    std::string value;
    if (AMStr::GetEnv(key, &value)) {
      return value;
    }
    return std::string();
  };

  if (username.empty()) {
#ifdef _WIN32
    username = read_env("USERNAME");
#else
    username = read_env("USER");
#endif
  }
  if (hostname.empty()) {
#ifdef _WIN32
    hostname = read_env("COMPUTERNAME");
#else
    hostname = read_env("HOSTNAME");
#endif
  }
  if (username.empty()) {
    username = "user";
  }
  if (hostname.empty()) {
    hostname = "localhost";
  }
  return {username, hostname};
}

/**
 * @brief Resolve prompt cwd from client runtime metadata.
 */
std::string ResolvePromptCwd_(const AMDomain::client::ClientHandle &client) {
  if (!client) {
    return "/";
  }

  auto normalize = [](const std::string &raw) {
    std::string path = AMStr::Strip(raw);
    if (path.empty()) {
      return std::string();
    }
    return AMPathStr::UnifyPathSep(path, "/");
  };

  auto metadata =
      client->MetaDataPort().QueryTypedValue<AMDomain::host::ClientMetaData>();
  if (metadata.has_value()) {
    std::string cwd = normalize(metadata->cwd);
    if (!cwd.empty()) {
      return cwd;
    }
    cwd = normalize(metadata->login_dir);
    if (!cwd.empty()) {
      return cwd;
    }
  }

  const std::string home = normalize(client->ConfigPort().GetHomeDir());
  if (!home.empty()) {
    return home;
  }
  return "/";
}

/**
 * @brief Select the system icon from settings based on OS type.
 */
std::string
ResolveSysIcon_(const AMInterface::style::AMStyleService &style_service,
                OS_TYPE os_type) {
  std::string key = "windows";
  switch (os_type) {
  case OS_TYPE::Windows:
    key = "windows";
    break;
  case OS_TYPE::Linux:
    key = "linux";
    break;
  case OS_TYPE::MacOS:
    key = "macos";
    break;
  default:
    key = "windows";
    break;
  }

  std::string icon = ResolveStyleSettingString_(
      style_service, {"Style", "CLIPrompt", "icons", key});
  if (icon.empty()) {
    icon = "💻";
  }
  std::string converted;
  if (TryConvertTaggedTextToAnsi_(icon, &converted)) {
    return converted;
  }
  std::string extracted;
  if (TryExtractTaggedText_(icon, &extracted)) {
    return extracted;
  }
  return icon;
}

/**
 * @brief Build the prompt string and update cached prefix when needed.
 */
std::string
BuildPrompt_(PromptState &state,
             AMApplication::client::ClientAppService &client_service,
             const AMInterface::style::AMStyleService &style_service,
             const std::function<void(size_t *, size_t *)> &get_task_counts) {
  auto client = ResolveActiveClient_(client_service);
  std::string nickname =
      client ? client->ConfigPort().GetNickname() : std::string("local");
  if (nickname.empty()) {
    nickname = "local";
  }

  if (state.cached_prefix.empty() || state.last_nickname != nickname ||
      state.cached_sysicon.empty() || state.cached_username.empty() ||
      state.cached_hostname.empty()) {
    OS_TYPE os_type = OS_TYPE::Unknown;
    if (client) {
      try {
        os_type = client->ConfigPort().GetOSType();
      } catch (const std::exception &) {
        os_type = OS_TYPE::Unknown;
      }
    }
    std::string sysicon = ResolveSysIcon_(style_service, os_type);
    auto [username, hostname] = ResolveUserHost_(client);
    state.cached_sysicon = sysicon;
    state.cached_username = username;
    state.cached_hostname = hostname;
    std::string styled_user = ApplyStyleFromConfig_(
        {"Style", "CLIPrompt", "username"}, username, style_service);
    std::string styled_host = ApplyStyleFromConfig_(
        {"Style", "CLIPrompt", "hostname"}, hostname, style_service);
    state.cached_prefix =
        AMStr::fmt("{} {}@{}", sysicon, styled_user, styled_host);
    state.last_nickname = nickname;
  }

  const std::string elapsed =
      state.last_elapsed.empty() ? "-" : state.last_elapsed;
  const bool ok = state.last_rcm.first == EC::Success;
  const std::string status = ok ? "✅" : "❌";
  const std::string ec_name =
      ok ? "" : std::string(magic_enum::enum_name(state.last_rcm.first));

  std::string workdir = "/";
  // if (client) {
  //   workdir = client_service.GetOrInitWorkdir(client);
  // }

  const std::string format = ResolveCorePromptFormat_(style_service);
  if (!format.empty()) {
    std::unordered_map<std::string, std::string> vars;
    vars["$sysicon"] = state.cached_sysicon;
    vars["$username"] = state.cached_username;
    vars["$hostname"] = state.cached_hostname;
    vars["$nickname"] = nickname;
    vars["$cwd"] = workdir;
    vars["$elapsed"] = elapsed;
    vars["$success"] = ok ? "1" : "";
    vars["$ec_name"] = ec_name;
    size_t pending_count = 0;
    size_t running_count = 0;
    if (get_task_counts) {
      get_task_counts(&pending_count, &running_count);
    }
    const size_t total_tasks = pending_count + running_count;
    const std::string time_now =
        FormatTime(static_cast<size_t>(AMTime::seconds()), "%H:%M:%S");

    vars["$task_pending"] = std::to_string(pending_count);
    vars["$task_running"] = std::to_string(running_count);
    vars["$time_now"] = time_now;
    vars["$task_num"] = std::to_string(total_tasks);
    vars["$time_clock"] = time_now;
    const std::string rendered =
        RenderPromptFormat_(style_service, format, vars);
    if (!rendered.empty()) {
      return rendered;
    }
  }

  const std::string styled_elapsed = ApplyStyleFromConfig_(
      {"Style", "SystemInfo", "info"}, elapsed, style_service);
  const std::string styled_status = ApplyStyleFromConfig_(
      {"Style", "SystemInfo", ok ? "success" : "error"}, status, style_service);
  std::string line1 = AMStr::fmt("{}  {}  {}", state.cached_prefix,
                                 styled_elapsed, styled_status);
  if (!ec_name.empty()) {
    const std::string styled_ec = ApplyStyleFromConfig_(
        {"Style", "SystemInfo", "error"}, ec_name, style_service);
    line1 += " " + styled_ec;
  }

  const std::string styled_nickname = ApplyStyleFromConfig_(
      {"Style", "CLIPrompt", "nickname"}, nickname, style_service);
  const std::string styled_cwd = ApplyStyleFromConfig_(
      {"Style", "CLIPrompt", "cwd"}, workdir, style_service);
  const std::string styled_dollar = ApplyStyleFromConfig_(
      {"Style", "CLIPrompt", "dollarsign"}, "$", style_service);
  std::string line2 =
      AMStr::fmt("({}){} {}", styled_nickname, styled_cwd, styled_dollar);
  return line1 + "\n" + line2 + " ";
}

/**
 * @brief Reload settings when `settings.toml` changed on disk.
 *
 * This makes external edits effective without requiring process restart.
 */
ECM ReloadSettingsIfUpdated_(
    AMInterface::prompt::IsoclineProfileManager &prompt_profile_history_manager,
    AMApplication::config::AMConfigAppService &config_service,
    bool *reloaded = nullptr) {
  if (reloaded) {
    *reloaded = false;
  }
  std::filesystem::path settings_path;
  if (!config_service.GetDataPath(DocumentKind::Settings, &settings_path) ||
      settings_path.empty()) {
    return Ok();
  }

  std::error_code ec;
  const auto current_write_time =
      std::filesystem::last_write_time(settings_path, ec);
  if (ec) {
    return Ok();
  }

  static std::filesystem::file_time_type last_write_time{};
  static bool has_last_write_time = false;
  if (!has_last_write_time) {
    last_write_time = current_write_time;
    has_last_write_time = true;
    return Ok();
  }
  if (current_write_time <= last_write_time) {
    return Ok();
  }

  // Avoid clobbering in-memory updates that have not been dumped yet.
  if (config_service.IsDirty(DocumentKind::Settings)) {
    return Ok();
  }

  ECM load_rcm = config_service.Load(DocumentKind::Settings, true);
  if (load_rcm.first != EC::Success) {
    return load_rcm;
  }
  (void)prompt_profile_history_manager;
  last_write_time = current_write_time;
  if (reloaded) {
    *reloaded = true;
  }
  return Ok();
}

/**
 * @brief Print an ECM error message if the code is not Success.
 */
void PrintECM_(AMInterface::prompt::AMPromptIOManager &prompt, const ECM &rcm) {
  if (rcm.first == EC::Success) {
    return;
  }
  std::string name = std::string(magic_enum::enum_name(rcm.first));
  if (rcm.second.empty()) {
    prompt.FmtPrint("❌ {}", name);
    return;
  }
  prompt.FmtPrint("❌ {}: {}", name, rcm.second);
}

/**
 * @brief Update prompt state with the latest result and elapsed duration.
 */
void UpdatePromptState_(PromptState &state, const ECM &rcm,
                        std::chrono::steady_clock::duration elapsed) {
  state.last_rcm = rcm;
  const auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
  state.last_elapsed = AMStr::fmt("{}ms", ms);
}

void RegisterPromptGetters_(AMInterface::prompt::CLIPromtRender &core_prompt,
                            const CLIServices &managers) {
  core_prompt.RegisterGetter("cwd", [&managers]() {
    auto client = managers.client_service->GetCurrentClient();
    return ResolvePromptCwd_(client);
  });
  core_prompt.RegisterGetter("username", [&managers]() {
    auto client = ResolveActiveClient_(managers.client_service.Get());
    return ResolveUserHost_(client).first;
  });
  core_prompt.RegisterGetter("hostname", [&managers]() {
    auto client = ResolveActiveClient_(managers.client_service.Get());
    return ResolveUserHost_(client).second;
  });
  core_prompt.RegisterGetter("os_type", [&managers]() {
    OS_TYPE os_type = OS_TYPE::Unknown;
    auto client = ResolveActiveClient_(managers.client_service.Get());
    if (client) {
      try {
        os_type = client->ConfigPort().GetOSType();
      } catch (const std::exception &) {
        os_type = OS_TYPE::Unknown;
      }
    }
    switch (os_type) {
    case OS_TYPE::Linux:
      return std::string("linux");
    case OS_TYPE::MacOS:
      return std::string("macos");
    case OS_TYPE::Windows:
    default:
      return std::string("windows");
    }
  });
  core_prompt.RegisterGetter("task_pending", [&managers]() {
    size_t pending_count = 0;
    size_t running_count = 0;
    managers.transfer_service->GetTaskCounts(&pending_count, &running_count);
    return std::to_string(pending_count);
  });
  core_prompt.RegisterGetter("task_running", [&managers]() {
    size_t pending_count = 0;
    size_t running_count = 0;
    managers.transfer_service->GetTaskCounts(&pending_count, &running_count);
    return std::to_string(running_count);
  });
}
} // namespace

/**
 * @brief Register callback into one callback vector.
 */
void AMInteractiveEventRegistry::RegisterCallback_(
    std::vector<std::function<void()> *> *callbacks,
    std::function<void()> *clear_fn) {
  if (!callbacks || !clear_fn) {
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if (std::find(callbacks->begin(), callbacks->end(), clear_fn) !=
      callbacks->end()) {
    return;
  }
  callbacks->push_back(clear_fn);
}

/**
 * @brief Register callback for PromptCore-return phase.
 */
void AMInteractiveEventRegistry::RegisterOnCorePromptReturn(
    std::function<void()> *clear_fn) {
  RegisterCallback_(&core_prompt_return_callbacks_, clear_fn);
}

/**
 * @brief Register callback for interactive-loop-exit phase.
 */
void AMInteractiveEventRegistry::RegisterOnInteractiveLoopExit(
    std::function<void()> *clear_fn) {
  RegisterCallback_(&interactive_loop_exit_callbacks_, clear_fn);
}

/**
 * @brief Execute callbacks from one callback vector.
 */
void AMInteractiveEventRegistry::RunCallbacks_(
    const std::vector<std::function<void()> *> &callbacks) {
  for (auto *fn : callbacks) {
    if (!fn || !(*fn)) {
      continue;
    }
    try {
      (*fn)();
    } catch (...) {
    }
  }
}

/**
 * @brief Execute all callbacks for PromptCore-return phase.
 */
void AMInteractiveEventRegistry::RunOnCorePromptReturn() {
  std::vector<std::function<void()> *> callbacks;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks = core_prompt_return_callbacks_;
  }
  RunCallbacks_(callbacks);
}

/**
 * @brief Execute all callbacks for interactive-loop-exit phase.
 */
void AMInteractiveEventRegistry::RunOnInteractiveLoopExit() {
  std::vector<std::function<void()> *> callbacks;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks = interactive_loop_exit_callbacks_;
  }
  RunCallbacks_(callbacks);
}

/**
 * @brief Run the core interactive loop until the user exits.
 */
int RunInteractiveLoop(CLI::App &app, const CliCommands &cli_commands,
                       AMInterface::parser::CommandNode &command_tree,
                       const CLIServices &managers, CliRunContext &ctx) {
  bool skip_loop_exit_callbacks = false;
  const amf &cflag = ctx.task_control_token;

  auto store_exit_code = [&ctx](int code) {
    if (ctx.exit_code) {
      ctx.exit_code->store(code, std::memory_order_relaxed);
    }
  };

  AMInterface::parser::TokenTypeAnalyzer token_type_analyzer;
  token_type_analyzer.SetCommandTree(&command_tree);
  AMInterface::parser::AMInputPreprocess input_preprocess(
      managers.var_interface_service.Get(), token_type_analyzer);

  AMCompleter completer{&command_tree, &token_type_analyzer,
                        &managers.interactive_event_registry};
  completer.Install();

  AMInterface::prompt::CLIPromtRender core_prompt(managers.style_service.Get());
  RegisterPromptGetters_(core_prompt, managers);

  ECM last_dispatch_result = Ok();
  int64_t last_dispatch_elapsed_ms = 0;
  AMInterface::prompt::CLIPromtRender::RenderArg prompt_arg = {};

  while (true) {
    if (cflag->IsInterrupted()) {
      cflag->ClearInterrupt();
      continue;
    }

    // bool settings_reloaded = false;
    // ECM reload_settings_rcm =
    //     ReloadSettingsIfUpdated_(prompt_profile_history_manager,
    //                              managers.config_service,
    //                              &settings_reloaded);
    // if (reload_settings_rcm.first != EC::Success) {
    //   PrintECM_(prompt, reload_settings_rcm);
    // } else if (settings_reloaded) {
    //   core_prompt.InvalidateCache();
    // }

    prompt_arg.current_nickname =
        AMStr::Strip(managers.client_service->CurrentNickname());
    prompt_arg.elapsed_time_ms = last_dispatch_elapsed_ms;
    prompt_arg.result = last_dispatch_result;

    const std::string prompt_text = core_prompt.Render(prompt_arg);
    std::string line;
    (void)managers.config_service->BackupIfNeeded();

    // monitor.SilenceHook("GLOBAL");
    // monitor.ResumeHook("COREPROMPT");
    // ctx.task_control_token->ClearInterrupt();
    bool canceled = !managers.prompt_io_manager->PromptCore(
        prompt_text, &line, &token_type_analyzer);
    // ctx.task_control_token->ClearInterrupt();
    // monitor.SilenceHook("COREPROMPT");
    // monitor.ResumeHook("GLOBAL");
    managers.interactive_event_registry.RunOnCorePromptReturn();

    if (canceled) {
      last_dispatch_result = Ok();
      last_dispatch_elapsed_ms = 0;
      continue;
    }

    std::string trimmed = AMStr::Strip(line);
    if (trimmed.empty()) {
      continue;
    }
    const auto dispatch_begin = AMTime::SteadyNow();
    try {
      auto prep = input_preprocess.Preprocess(trimmed);
      if (prep.rcm.first != EC::Success) {
        PrintECM_(managers.prompt_io_manager.Get(), prep.rcm);
        store_exit_code(static_cast<int>(prep.rcm.first));
        last_dispatch_result = prep.rcm;
        last_dispatch_elapsed_ms = std::max<int64_t>(
            0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
        continue;
      }
      std::vector<std::string> cli_args = std::move(prep.data);
      if (cli_args.empty()) {
        continue;
      }
      // CLI11 consumes args via pop_back, so reverse to preserve order.
      std::reverse(cli_args.begin(), cli_args.end());
      app.clear();
      app.parse(cli_args);
    } catch (const CLI::CallForHelp &e) {
      managers.prompt_io_manager->Print(app.help());
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      last_dispatch_result = parse_rcm;
      last_dispatch_elapsed_ms = std::max<int64_t>(
          0, std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now() - dispatch_begin)
                 .count());
      continue;
    } catch (const CLI::CallForAllHelp &e) {
      managers.prompt_io_manager->Print(app.help("", CLI::AppFormatMode::All));
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      last_dispatch_result = parse_rcm;
      last_dispatch_elapsed_ms =
          AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow());
      continue;
    } catch (const CLI::CallForVersion &e) {
      managers.prompt_io_manager->Print(app.version());
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      last_dispatch_result = parse_rcm;
      last_dispatch_elapsed_ms = std::max<int64_t>(
          0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
      continue;
    } catch (const CLI::ParseError &e) {
      const std::string parse_msg = e.what();
      managers.prompt_io_manager->Print(parse_msg);
      ECM parse_rcm = {EC::InvalidArg, parse_msg};
      store_exit_code(static_cast<int>(parse_rcm.first));
      last_dispatch_result = parse_rcm;
      last_dispatch_elapsed_ms = std::max<int64_t>(
          0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
      continue;
    }

    ctx.async = false;
    ctx.enforce_interactive = true;
    DispatchCliCommands(cli_commands, managers, ctx);
    last_dispatch_result = ctx.rcm;
    last_dispatch_elapsed_ms = std::max<int64_t>(
        0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));

    if (ctx.request_exit) {
      skip_loop_exit_callbacks = ctx.skip_loop_exit_callbacks;
      break;
    }
  }

  if (!skip_loop_exit_callbacks) {
    managers.interactive_event_registry.RunOnInteractiveLoopExit();
  }
  ctx.is_interactive->store(false, std::memory_order_relaxed);
  return ctx.exit_code ? ctx.exit_code->load(std::memory_order_relaxed) : 0;
}

} // namespace AMInterface::cli
