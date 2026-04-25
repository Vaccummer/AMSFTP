#pragma once

#include "foundation/tools/string.hpp"
#include "foundation/tools/terminal.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace AMPromptUI {

namespace detail {

inline bool IsTagWhitespace(char ch) {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
}

inline bool IsAsciiAlphaNum(char ch) {
  return std::isalnum(static_cast<unsigned char>(ch)) != 0;
}

inline bool IsTagIdentChar(char ch) {
  return IsAsciiAlphaNum(ch) || ch == '_' || ch == '-';
}

inline bool IsTagHexChar(char ch) { return IsAsciiAlphaNum(ch); }

inline size_t SkipTagWhitespace(std::string_view text, size_t pos, size_t end) {
  while (pos < end && IsTagWhitespace(text[pos])) {
    ++pos;
  }
  return pos;
}

inline bool ParseTagAttrName(std::string_view text, size_t *pos, size_t end) {
  if (!pos || *pos >= end) {
    return false;
  }
  size_t cur = *pos;
  if (text[cur] == '#') {
    ++cur;
    const size_t start = cur;
    while (cur < end && IsTagHexChar(text[cur])) {
      ++cur;
    }
    if (cur == start) {
      return false;
    }
    *pos = cur;
    return true;
  }

  const size_t start = cur;
  while (cur < end && IsTagIdentChar(text[cur])) {
    ++cur;
  }
  if (cur == start) {
    return false;
  }
  *pos = cur;
  return true;
}

inline bool ParseTagValue(std::string_view text, size_t *pos, size_t end) {
  if (!pos || *pos >= end) {
    return false;
  }
  size_t cur = *pos;
  if (text[cur] == '"') {
    ++cur;
    while (cur < end && text[cur] != '"') {
      ++cur;
    }
    if (cur >= end || text[cur] != '"') {
      return false;
    }
    *pos = cur + 1;
    return true;
  }

  if (text[cur] == '#') {
    ++cur;
    const size_t start = cur;
    while (cur < end && IsTagHexChar(text[cur])) {
      ++cur;
    }
    if (cur == start) {
      return false;
    }
    *pos = cur;
    return true;
  }

  const size_t start = cur;
  while (cur < end && IsTagIdentChar(text[cur])) {
    ++cur;
  }
  if (cur == start) {
    return false;
  }
  *pos = cur;
  return true;
}

inline bool IsLegalBBCodeTagToken(std::string_view text) {
  size_t pos = 0;
  const size_t end = text.size();
  pos = SkipTagWhitespace(text, pos, end);
  if (pos >= end) {
    return false;
  }

  if (text[pos] == '!') {
    ++pos;
    pos = SkipTagWhitespace(text, pos, end);
  } else if (text[pos] == '/') {
    ++pos;
    pos = SkipTagWhitespace(text, pos, end);
    return pos >= end || IsLegalBBCodeTagToken(text.substr(pos));
  }

  if (pos >= end) {
    return false;
  }

  bool has_any = false;
  while (pos < end) {
    const size_t token_start = pos;
    if (!ParseTagAttrName(text, &pos, end)) {
      return false;
    }
    const size_t token_end = pos;
    has_any = true;

    pos = SkipTagWhitespace(text, pos, end);
    if (pos < end && (token_end - token_start) == 2 &&
        text.compare(token_start, 2, "on") == 0 &&
        (pos >= end || text[pos] != '=')) {
      if (!ParseTagAttrName(text, &pos, end)) {
        return false;
      }
      pos = SkipTagWhitespace(text, pos, end);
    }

    if (pos < end && text[pos] == '=') {
      ++pos;
      pos = SkipTagWhitespace(text, pos, end);
      if (!ParseTagValue(text, &pos, end)) {
        return false;
      }
      pos = SkipTagWhitespace(text, pos, end);
    }

    pos = SkipTagWhitespace(text, pos, end);
  }
  return has_any;
}

} // namespace detail

inline std::string EnsureTrailingNewline(const std::string &text) {
  if (!text.empty() && text.back() == '\n') {
    return text;
  }
  return text + "\n";
}

inline void AppendMoveUpRows(std::string *frame, int rows) {
  if (frame == nullptr || rows <= 0) {
    return;
  }
  *frame += "\r\x1b[" + std::to_string(rows) + "A";
}

inline void AppendClearRows(std::string *frame, int rows) {
  if (frame == nullptr || rows <= 0) {
    return;
  }
  for (int i = 0; i < rows; ++i) {
    *frame += "\x1b[2K\r";
    *frame += "\n";
  }
}

inline std::string StripStyleForMeasure(const std::string &text) {
  std::string out = {};
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    const char ch = text[i];
    if (ch == '\\' && i + 1 < text.size() &&
        (text[i + 1] == '[' || text[i + 1] == ']')) {
      out.push_back(text[i + 1]);
      ++i;
      continue;
    }
    if (ch == '[') {
      const size_t close = text.find(']', i + 1);
      if (close != std::string::npos) {
        const std::string_view token(text.data() + i + 1, close - i - 1);
        if (detail::IsLegalBBCodeTagToken(token)) {
          i = close;
          continue;
        }
      }
    }
    out.push_back(ch);
  }
  return out;
}

inline std::string NormalizeMeasureLine(const std::string &text) {
  std::string out = AMStr::replace_all(text, "\t", "   ");
  out = AMStr::replace_all(out, "\r", "");
  return out;
}

inline int TerminalCols() {
  return std::max(1, AMTerminalTools::GetTerminalViewportInfo().cols);
}

inline int ComputeWrappedRows(const std::vector<std::string> &lines, int cols) {
  if (lines.empty()) {
    return 0;
  }
  const int width = std::max(1, cols);
  int rows = 0;
  for (const auto &line : lines) {
    const std::string plain = NormalizeMeasureLine(StripStyleForMeasure(line));
    const size_t display_width = AMStr::DisplayWidthUtf8(plain);
    const int line_rows = std::max<int>(
        1, static_cast<int>((display_width + static_cast<size_t>(width) - 1) /
                            static_cast<size_t>(width)));
    rows += line_rows;
  }
  return rows;
}

} // namespace AMPromptUI
