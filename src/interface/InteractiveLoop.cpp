#include "interface/InteractiveLoop.hpp"
#include "foundation/DataClass.hpp"
#include "foundation/Path.hpp"
#include "foundation/tools/time.hpp"
#include "interface/ApplicationAdapters.hpp"
#include "interface/CLIBind.hpp"
#include "interface/CommandPreprocess.hpp"
#include "interface/Completer/Proxy.hpp"
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

namespace {
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
bool ResolvePromptStyleAnsi_(const std::string &tag_name,
                             std::string *ansi_code) {
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

  auto raw = AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
      {"Style", "CLIPrompt", trimmed}, "");
  if (raw.empty()) {
    raw = AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
        {"Style", "CLIPrompt", "shortcut", trimmed}, "");
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
std::string ResolveCorePromptFormat_() {
  std::string format =
      AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
          {"Style", "CLIPrompt", "templete", "core_prompt"}, "");
  if (!format.empty()) {
    return format;
  }
  format = AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
      {"Style", "CLIPrompt", "template", "core_prompt"}, "");
  if (!format.empty()) {
    return format;
  }
  return AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
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
RenderPromptSegment_(const std::string &format, size_t *index,
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
              format, &cursor, vars, nullptr, false, true);
          bool truthy = EvaluatePromptExpression_(cond);

          if (cursor >= format.size() || format[cursor] != '{') {
            output.push_back('{');
            ++(*index);
            continue;
          }
          ++cursor;
          std::string branch_true =
              RenderPromptSegment_(format, &cursor, vars, style_stack,
                                   enable_styles, true);

          if (cursor >= format.size() || format[cursor] != '{') {
            output.push_back('{');
            ++(*index);
            continue;
          }
          ++cursor;
          std::string branch_false =
              RenderPromptSegment_(format, &cursor, vars, style_stack,
                                   enable_styles, true);

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
      if (ResolvePromptStyleAnsi_(tag, &ansi_code)) {
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
RenderPromptFormat_(const std::string &format,
                    const std::unordered_map<std::string, std::string> &vars) {
  size_t index = 0;
  std::vector<std::string> style_stack;
  std::string rendered =
      RenderPromptSegment_(format, &index, vars, &style_stack, true, false);
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
std::string ApplyStyleFromConfig_(const std::vector<std::string> &path,
                                  const std::string &text) {
  if (text.empty()) {
    return text;
  }

  std::string raw = AMStr::Strip(
      AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(path, ""));
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
std::shared_ptr<BaseClient>
ResolveActiveClient_(AMDomain::client::AMClientManager &client_manager) {
  return client_manager.CurrentClient();
}

/**
 * @brief Resolve prompt username/hostname with environment fallbacks.
 */
std::pair<std::string, std::string>
ResolveUserHost_(const std::shared_ptr<BaseClient> &client) {
  std::string username;
  std::string hostname;
  if (client) {
    ConRequest request = client->GetRequest();
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
 * @brief Select the system icon from settings based on OS type.
 */
std::string ResolveSysIcon_(OS_TYPE os_type) {
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

  std::string icon =
      AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
          {"Style", "CLIPrompt", "icons", key}, "");
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
std::string BuildPrompt_(PromptState &state, AMDomain::client::AMClientManager &client_manager,
                         AMDomain::transfer::AMTransferManager &transfer_manager) {
  auto client = ResolveActiveClient_(client_manager);
  std::string nickname = client ? client->GetNickname() : std::string("local");
  if (nickname.empty()) {
    nickname = "local";
  }

  if (state.cached_prefix.empty() || state.last_nickname != nickname ||
      state.cached_sysicon.empty() || state.cached_username.empty() ||
      state.cached_hostname.empty()) {
    OS_TYPE os_type = OS_TYPE::Unknown;
    if (client) {
      try {
        os_type = client->GetOSType();
      } catch (const std::exception &) {
        os_type = OS_TYPE::Unknown;
      }
    }
    std::string sysicon = ResolveSysIcon_(os_type);
    auto [username, hostname] = ResolveUserHost_(client);
    state.cached_sysicon = sysicon;
    state.cached_username = username;
    state.cached_hostname = hostname;
    std::string styled_user =
        ApplyStyleFromConfig_({"Style", "CLIPrompt", "username"}, username);
    std::string styled_host =
        ApplyStyleFromConfig_({"Style", "CLIPrompt", "hostname"}, hostname);
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
  if (client) {
    workdir = client_manager.GetOrInitWorkdir(client);
  }

  const std::string format = ResolveCorePromptFormat_();
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
    transfer_manager.GetTaskCounts(&pending_count, &running_count);
    const size_t total_tasks = pending_count + running_count;
    const std::string time_now =
        FormatTime(static_cast<size_t>(AMTime::seconds()), "%H:%M:%S");

    vars["$task_pending"] = std::to_string(pending_count);
    vars["$task_running"] = std::to_string(running_count);
    vars["$time_now"] = time_now;
    vars["$task_num"] = std::to_string(total_tasks);
    vars["$time_clock"] = time_now;
    const std::string rendered = RenderPromptFormat_(format, vars);
    if (!rendered.empty()) {
      return rendered;
    }
  }

  const std::string styled_elapsed =
      ApplyStyleFromConfig_({"Style", "SystemInfo", "info"}, elapsed);
  const std::string styled_status = ApplyStyleFromConfig_(
      {"Style", "SystemInfo", ok ? "success" : "error"}, status);
  std::string line1 = AMStr::fmt("{}  {}  {}", state.cached_prefix,
                                 styled_elapsed, styled_status);
  if (!ec_name.empty()) {
    const std::string styled_ec =
        ApplyStyleFromConfig_({"Style", "SystemInfo", "error"}, ec_name);
    line1 += " " + styled_ec;
  }

  const std::string styled_nickname =
      ApplyStyleFromConfig_({"Style", "CLIPrompt", "nickname"}, nickname);
  const std::string styled_cwd =
      ApplyStyleFromConfig_({"Style", "CLIPrompt", "cwd"}, workdir);
  const std::string styled_dollar =
      ApplyStyleFromConfig_({"Style", "CLIPrompt", "dollarsign"}, "$");
  std::string line2 =
      AMStr::fmt("({}){} {}", styled_nickname, styled_cwd, styled_dollar);
  return line1 + "\n" + line2 + " ";
}

/**
 * @brief Reload settings when `settings.toml` changed on disk.
 *
 * This makes external edits effective without requiring process restart.
 */
ECM ReloadSettingsIfUpdated_(AMPromptManager &prompt) {
  std::filesystem::path settings_path;
  if (!AMInterface::ApplicationAdapters::Runtime::GetConfigDataPath(
          DocumentKind::Settings, &settings_path) ||
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
  if (AMInterface::ApplicationAdapters::Runtime::IsConfigDirty(
          DocumentKind::Settings)) {
    return Ok();
  }

  ECM load_rcm = AMInterface::ApplicationAdapters::Runtime::LoadConfig(
      DocumentKind::Settings, true);
  if (load_rcm.first != EC::Success) {
    return load_rcm;
  }
  (void)prompt.ReloadPromptProfiles();
  last_write_time = current_write_time;
  return Ok();
}

/**
 * @brief Split a potentially multi-line prompt into a header and a single input
 * line.
 *
 * @param full_prompt Full prompt text that may contain newline separators.
 * @param header Output header string to print before readline (empty if none).
 * @param line Output single-line prompt to pass into ic_readline.
 */
static void SplitPromptForReadline_(const std::string &full_prompt,
                                    std::string *header, std::string *line) {
  if (header) {
    header->clear();
  }
  if (!line) {
    return;
  }
  line->clear();
  if (full_prompt.empty()) {
    return;
  }
  const size_t split = full_prompt.find_last_of('\n');
  if (split == std::string::npos) {
    *line = full_prompt;
    return;
  }
  if (header) {
    *header = full_prompt.substr(0, split);
  }
  *line = full_prompt.substr(split + 1);
}

/**
 * @brief Print an ECM error message if the code is not Success.
 */
void PrintECM_(AMPromptManager &prompt, const ECM &rcm) {
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
 * @brief Execute a shell command via filesystem shell runner and return the
 * raw result.
 */
CR ExecuteShellCommand_(AMDomain::filesystem::AMFileSystem &filesystem, const std::string &command,
                        const amf &task_control_token) {
  return filesystem.ShellRun(command, -1, task_control_token);
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
} // namespace

/**
 * @brief Return singleton registry instance.
 */
AMInteractiveEventRegistry &AMInteractiveEventRegistry::Instance() {
  static AMInteractiveEventRegistry ins;
  return ins;
}

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
int RunInteractiveLoop(const std::string &app_name, const CliManagers &managers,
                       CliRunContext &ctx) {
  if (ctx.is_interactive) {
    ctx.is_interactive->store(true, std::memory_order_relaxed);
  }
  bool skip_loop_exit_callbacks = false;
  auto store_exit_code = [&ctx](int code) {
    if (ctx.exit_code) {
      ctx.exit_code->store(code, std::memory_order_relaxed);
    }
  };

  AMPromptManager &prompt = managers.prompt_manager;
  AMDomain::client::AMClientManager &client_manager = managers.client_manager;
  AMDomain::transfer::AMTransferManager &transfer_manager = managers.transfer_manager;
  AMDomain::filesystem::AMFileSystem &filesystem = managers.filesystem;
  const amf task_control_token = ctx.task_control_token;
  if (!task_control_token) {
    ctx.rcm = Err(EC::InvalidArg, "Session task control token is not bound");
    store_exit_code(static_cast<int>(ctx.rcm.first));
    return static_cast<int>(EC::InvalidArg);
  }

  AMCompleter completer{};
  completer.Install();

  PromptState prompt_state;

  while (true) {
    if (task_control_token->IsKill()) {
      break;
    }

    ECM reload_settings_rcm = ReloadSettingsIfUpdated_(prompt);
    if (reload_settings_rcm.first != EC::Success) {
      PrintECM_(prompt, reload_settings_rcm);
    }

    ECM change_rcm = prompt.ChangeClient(client_manager.CurrentNickname());
    if (change_rcm.first != EC::Success) {
      PrintECM_(prompt, change_rcm);
    }

    const std::string prompt_text =
        BuildPrompt_(prompt_state, client_manager, transfer_manager);

    std::string prompt_header;
    std::string prompt_line;
    SplitPromptForReadline_(prompt_text, &prompt_header, &prompt_line);

    if (!prompt_header.empty()) {
      std::cout << prompt_header << std::endl;
    }

    std::string line;
    (void)AMInterface::ApplicationAdapters::Runtime::BackupConfigIfNeeded();

    // monitor.SilenceHook("GLOBAL");
    // monitor.ResumeHook("COREPROMPT");

    bool canceled = !prompt.PromptCore(prompt_line, &line);

    // monitor.SilenceHook("COREPROMPT");
    // monitor.ResumeHook("GLOBAL");
    AMInteractiveEventRegistry::Instance().RunOnCorePromptReturn();

    if (canceled) {
      continue;
    }

    const auto input_confirmed = std::chrono::steady_clock::now();

    std::string trimmed = AMStr::Strip(line);
    if (trimmed.empty()) {
      continue;
    }
    prompt.AddHistoryEntry(line);

    bool is_shell = false;
    std::string shell_command;
    ECM shell_parse =
        AMInputPreprocess::ParseShellPrefix(trimmed, &shell_command, &is_shell);
    if (shell_parse.first != EC::Success) {
      PrintECM_(prompt, shell_parse);
      store_exit_code(static_cast<int>(shell_parse.first));
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, shell_parse, iter_end - input_confirmed);
      continue;
    }

    if (is_shell) {
      CR shell_result =
          ExecuteShellCommand_(filesystem, shell_command, task_control_token);
      if (shell_result.first.first == EC::Success) {
        const std::string &msg = shell_result.second.first;
        if (!msg.empty()) {
          prompt.Print(msg);
        }
        prompt.FmtPrint("\nCommand exit with code {}",
                        shell_result.second.second);
      } else {
        PrintECM_(prompt, shell_result.first);
      }
      store_exit_code(static_cast<int>(shell_result.first.first));
      const auto shell_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, shell_result.first,
                         shell_end - input_confirmed);
      continue;
    }

    CLI::App app{"AMSFTP Interactive Terminal", app_name};
    CliArgsPool args_pool;
    CliCommands cli_commands = BindCliOptions(app, args_pool);

    try {
      std::vector<std::string> cli_args =
          AMInputPreprocess::SplitCliTokens(trimmed);
      if (cli_args.empty()) {
        continue;
      }
      (void)AMInputPreprocess::ExpandVarShortcutTokens(&cli_args);
      // CLI11 consumes args via pop_back, so reverse to preserve order.
      std::reverse(cli_args.begin(), cli_args.end());
      app.parse(cli_args);
    } catch (const CLI::CallForHelp &e) {
      prompt.Print(app.help());
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, parse_rcm, iter_end - input_confirmed);
      continue;
    } catch (const CLI::CallForAllHelp &e) {
      prompt.Print(app.help("", CLI::AppFormatMode::All));
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, parse_rcm, iter_end - input_confirmed);
      continue;
    } catch (const CLI::CallForVersion &e) {
      prompt.Print(app.version());
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, parse_rcm, iter_end - input_confirmed);
      continue;
    } catch (const CLI::ParseError &e) {
      const std::string parse_msg = e.what();
      prompt.Print(parse_msg);
      ECM parse_rcm = {EC::InvalidArg, parse_msg};
      store_exit_code(static_cast<int>(parse_rcm.first));
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, parse_rcm, iter_end - input_confirmed);
      continue;
    }
    task_control_token->Reset();
    DispatchCliCommands(cli_commands, managers, ctx, false, true);
    if (task_control_token->IsKill()) {
      break;
    }
    const auto exec_end = std::chrono::steady_clock::now();
    task_control_token->Reset();
    UpdatePromptState_(prompt_state, ctx.rcm, exec_end - input_confirmed);

    if (ctx.request_exit) {
      skip_loop_exit_callbacks = ctx.skip_loop_exit_callbacks;
      break;
    }
  }

  prompt.FlushHistory();
  if (!skip_loop_exit_callbacks) {
    AMInteractiveEventRegistry::Instance().RunOnInteractiveLoopExit();
  }
  if (ctx.is_interactive) {
    ctx.is_interactive->store(false, std::memory_order_relaxed);
  }
  return ctx.exit_code ? ctx.exit_code->load(std::memory_order_relaxed) : 0;
}

