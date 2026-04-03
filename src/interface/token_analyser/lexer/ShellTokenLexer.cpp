#include "interface/token_analyser/lexer/ShellTokenLexer.hpp"

#include "foundation/tools/string.hpp"
#include <algorithm>

namespace AMInterface::parser::lexer {
namespace {

inline bool IsQuoted(char c) { return c == '"' || c == '\''; }

} // namespace

std::vector<AMInterface::parser::model::RawToken>
ShellTokenLexer::Split(const std::string &input) {
  std::vector<AMInterface::parser::model::RawToken> tokens = {};
  size_t i = 0;
  while (i < input.size()) {
    while (i < input.size() && AMStr::IsWhitespace(input[i])) {
      ++i;
    }
    if (i >= input.size()) {
      break;
    }

    AMInterface::parser::model::RawToken token = {};
    token.start = i;
    token.content_start = i;
    token.content_end = i;
    token.end = i;
    token.quoted = false;
    token.type = AMTokenType::Unset;

    char active_quote = 0;
    bool saw_quote = false;
    while (i < input.size()) {
      const char c = input[i];
      if (c == '`' && i + 1 < input.size()) {
        i += 2;
        continue;
      }
      if (active_quote != 0) {
        if (c == active_quote) {
          active_quote = 0;
          saw_quote = true;
        }
        ++i;
        continue;
      }
      if (IsQuoted(c)) {
        active_quote = c;
        saw_quote = true;
        ++i;
        continue;
      }
      if (AMStr::IsWhitespace(c)) {
        break;
      }
      ++i;
    }
    token.end = i;
    token.content_start = token.start;
    token.content_end = token.end;
    token.quoted = saw_quote;

    if (token.start < token.end && IsQuoted(input[token.start])) {
      const char outer_quote = input[token.start];
      size_t close = token.start + 1;
      bool found_close = false;
      while (close < token.end) {
        if (input[close] == '`' && close + 1 < token.end) {
          close += 2;
          continue;
        }
        if (input[close] == outer_quote) {
          found_close = true;
          break;
        }
        ++close;
      }

      token.quoted = true;
      if (found_close && close + 1 == token.end) {
        token.content_start = token.start + 1;
        token.content_end = close;
      } else if (!found_close) {
        token.content_start = std::min(token.start + 1, token.end);
        token.content_end = token.end;
      }
    }

    tokens.push_back(token);
  }
  return tokens;
}

} // namespace AMInterface::parser::lexer


