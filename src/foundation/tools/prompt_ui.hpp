#pragma once

#include "foundation/tools/string.hpp"
#include "foundation/tools/terminal.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace AMPromptUI {

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
  auto is_style_tag = [](const std::string &tag) {
    if (tag.empty()) {
      return false;
    }
    return tag.front() == '#' || tag.front() == '/' || tag.front() == '!';
  };

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
        const std::string token = text.substr(i + 1, close - i - 1);
        if (is_style_tag(token)) {
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
    const std::string plain =
        NormalizeMeasureLine(StripStyleForMeasure(line));
    const size_t display_width = AMStr::DisplayWidthUtf8(plain);
    const int line_rows =
        std::max<int>(1, static_cast<int>((display_width +
                                           static_cast<size_t>(width) - 1) /
                                          static_cast<size_t>(width)));
    rows += line_rows;
  }
  return rows;
}

} // namespace AMPromptUI
