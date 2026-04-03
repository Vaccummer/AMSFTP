#include "interface/token_analyser/shared/InputTextRules.hpp"

#include <cctype>

namespace AMInterface::parser::shared {

bool IsQuotedChar(char c) { return c == '"' || c == '\''; }

size_t FindUnescapedChar(const std::string &text, char target) {
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

std::string UnescapeBackticks(const std::string &text, bool unescape_at_sign) {
  if (text.empty()) {
    return text;
  }
  std::string out = {};
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '`' && i + 1 < text.size()) {
      const char next = text[i + 1];
      const bool unescape =
          next == '$' || next == '"' || next == '\'' || next == '`' ||
          (unescape_at_sign && next == '@');
      if (unescape) {
        out.push_back(next);
        ++i;
        continue;
      }
    }
    out.push_back(text[i]);
  }
  return out;
}

bool IsPathLikeText(const std::string &text, bool include_dot_prefix) {
  if (text.empty()) {
    return false;
  }
  if (text[0] == '/' || text[0] == '\\' || text[0] == '~' ||
      (include_dot_prefix && text[0] == '.')) {
    return true;
  }
  if (text.size() >= 2 && std::isalpha(static_cast<unsigned char>(text[0])) &&
      text[1] == ':') {
    return true;
  }
  return text.find('/') != std::string::npos ||
         text.find('\\') != std::string::npos;
}

bool HasClearPathSign(const std::string &text, bool include_dot_prefix) {
  if (text.empty()) {
    return false;
  }
  if (text[0] == '@' || text[0] == '~' || text[0] == '/' || text[0] == '\\' ||
      (include_dot_prefix && text[0] == '.')) {
    return true;
  }
  if (text.size() >= 2 && std::isalpha(static_cast<unsigned char>(text[0])) &&
      text[1] == ':') {
    return true;
  }
  return text.find('/') != std::string::npos ||
         text.find('\\') != std::string::npos;
}

} // namespace AMInterface::parser::shared


