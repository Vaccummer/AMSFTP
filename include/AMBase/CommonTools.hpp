#pragma once
#define _WINSOCKAPI_
// standard library
#include <algorithm>
#include <atomic>
#include <boost/locale/encoding.hpp>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <deque>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>
#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

// project header
#include "Isocline/isocline.h"
#include "third_party/indicators/color.hpp"
#include "third_party/indicators/cursor_control.hpp"
#include "third_party/indicators/progress_bar.hpp" // On Windows, this library includes windows.h
#include "third_party/indicators/setting.hpp"
#include "third_party/indicators/terminal_size.hpp"

class ProgressBar {
public:
  explicit ProgressBar(size_t total_size = 0, std::string unit = "B",
                       size_t bar_width = 50, bool show_eta = true,
                       bool colored = true)
      : total_(total_size), unit_(std::move(unit)), bar_width_(bar_width),
        show_eta_(show_eta), colored_(colored),
        start_time_(std::chrono::steady_clock::now()) {}

  // Added: dynamically set total size (optionally reset timer)
  void set_total(size_t new_total, bool reset_timer = false) {
    total_ = new_total;
    if (reset_timer) {
      start_time_ = std::chrono::steady_clock::now();
    }
    // If current progress exceeds new total, adjust automatically
    if (current_ > total_) {
      current_ = total_;
    }
    redraw();
  }

  // Update current progress
  void update(size_t current) {
    if (total_ == 0) {
      // If total is unknown, estimate using current as a known maximum
      if (current > current_) {
        total_ = current * 2; // Heuristic: assume final total is 2x current
      }
    }
    if (current > total_)
      current = total_;
    current_ = current;
    redraw();
  }

  void finish() {
    if (total_ == 0)
      total_ = current_; // Prevent division by zero
    update(total_);
    std::cout << "\n";
  }

private:
  void redraw() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_)
            .count();
    double elapsed_sec = elapsed_ms / 1000.0;

    double percent =
        (total_ == 0) ? 0.0 : (static_cast<double>(current_) / total_) * 100.0;
    if (percent > 100.0)
      percent = 100.0;

    double speed = (elapsed_sec > 0) ? current_ / elapsed_sec : 0.0;
    double eta_sec = (speed > 0 && current_ < total_ && total_ > 0)
                         ? (total_ - current_) / speed
                         : 0.0;

    auto [current_str, unit_scale] = format_size(current_);
    auto [total_str, _] = format_size(total_);

    size_t filled =
        (total_ == 0) ? 0 : static_cast<size_t>(percent / 100.0 * bar_width_);
    if (filled > bar_width_)
      filled = bar_width_;

    std::string bar = std::string(filled, '=');
    if (filled < bar_width_) {
      bar += '>';
      bar.resize(bar_width_, ' ');
    } else {
      bar.resize(bar_width_, '=');
    }

    const char *reset = colored_ ? "\033[0m" : "";
    const char *green = colored_ ? "\033[32m" : "";
    const char *yellow = colored_ ? "\033[33m" : "";

    std::cout << "\r";
    std::cout << "[" << green << bar << reset << "] ";

    if (total_ == 0) {
      std::cout << "?% " << current_str << " " << unit_scale;
    } else {
      std::cout << std::fixed << std::setprecision(1) << percent << "% ";
      std::cout << current_str << "/" << total_str << " " << unit_scale;
    }

    if (speed > 0) {
      auto [speed_str, speed_unit] = format_size(static_cast<size_t>(speed));
      std::cout << " " << speed_str << speed_unit << "/s";
    }

    if (show_eta_ && eta_sec > 0) {
      int eta = static_cast<int>(eta_sec);
      int h = eta / 3600, m = (eta % 3600) / 60, s = eta % 60;
      std::cout << " ETA: " << yellow;
      if (h > 0)
        std::cout << h << "h ";
      if (m > 0)
        std::cout << m << "m ";
      std::cout << s << "s" << reset;
    }

    std::cout << std::flush;
  }

  std::pair<std::string, std::string> format_size(size_t size) const {
    if (size == 0)
      return {"0", unit_};

    const char *units[] = {"", "K", "M", "G", "T"};
    int idx = 0;
    double val = static_cast<double>(size);

    while (val >= 1024.0 && idx < 4) {
      val /= 1024.0;
      idx++;
    }

    std::ostringstream oss;
    if (val == static_cast<long long>(val)) {
      oss << static_cast<long long>(val);
    } else {
      oss << std::fixed << std::setprecision(1) << val;
    }

    return {oss.str(), std::string(units[idx]) + unit_};
  }

private:
  size_t total_ = 0;
  size_t current_ = 0;
  std::string unit_;
  size_t bar_width_;
  bool show_eta_;
  bool colored_;
  std::chrono::steady_clock::time_point start_time_;

  ProgressBar(const ProgressBar &) = delete;
  ProgressBar &operator=(const ProgressBar &) = delete;
};

class AMProgressBar2 : public indicators::ProgressBar {
public:
  AMProgressBar2(size_t total_size = 0, std::string prefix = "",
                 std::string unit = "B", size_t bar_width = 50,
                 bool show_eta = true,
                 indicators::Color color = indicators::Color::green)
      : indicators::ProgressBar(
            indicators::option::BarWidth{bar_width},
            indicators::option::Start{"["}, indicators::option::Fill{"█"},
            indicators::option::Lead{"█"}, indicators::option::End{"]"},
            indicators::option::PrefixText{prefix},
            indicators::option::PostfixText{unit},
            indicators::option::MaxProgress{total_size},
            indicators::option::ShowElapsedTime{show_eta},
            indicators::option::ShowRemainingTime{show_eta},
            // indicators::option::ShowRate{true},
            // indicators::option::SampleCount{10},
            indicators::option::ForegroundColor{color}) {}
  void setTotoalSize(size_t total_size) {
    this->set_option(indicators::option::MaxProgress{total_size});
  }
  void setPrefix(std::string prefix) {
    this->set_option(indicators::option::PostfixText{prefix});
  }
  void setColor(indicators::Color color) {
    this->set_option(indicators::option::ForegroundColor{color});
  }
  void setPostfix(std::string prefix) {
    this->set_option(indicators::option::PostfixText{prefix});
  }
  void taskDone() {
    this->set_option(indicators::option::Completed{true});
    this->print_progress();
  }
  void updateProgress(size_t current) {
    this->set_progress(current);
    this->print_progress();
  }
};

/**
 * @brief Forward declaration for DisplayWidthUtf8.
 */

namespace AMStr {
/** Decode next UTF-8 codepoint; returns U+FFFD on error and advances index
 * by 1. */
inline uint32_t NextCodepointUtf8(const std::string &utf8_str, size_t &idx) {
  const size_t str_len = utf8_str.size();
  if (idx >= str_len) {
    return 0;
  }
  const uint8_t c0 = static_cast<uint8_t>(utf8_str[idx]);
  if ((c0 & 0x80) == 0) {
    ++idx;
    return c0;
  }
  if ((c0 & 0xE0) == 0xC0 && idx + 1 < str_len) {
    const uint8_t c1 = static_cast<uint8_t>(utf8_str[idx + 1]);
    if ((c1 & 0xC0) == 0x80) {
      idx += 2;
      return (static_cast<uint32_t>(c0 & 0x1F) << 6) |
             (static_cast<uint32_t>(c1 & 0x3F));
    }
  } else if ((c0 & 0xF0) == 0xE0 && idx + 2 < str_len) {
    const uint8_t c1 = static_cast<uint8_t>(utf8_str[idx + 1]);
    const uint8_t c2 = static_cast<uint8_t>(utf8_str[idx + 2]);
    if ((c1 & 0xC0) == 0x80 && (c2 & 0xC0) == 0x80) {
      idx += 3;
      return (static_cast<uint32_t>(c0 & 0x0F) << 12) |
             (static_cast<uint32_t>(c1 & 0x3F) << 6) |
             (static_cast<uint32_t>(c2 & 0x3F));
    }
  } else if ((c0 & 0xF8) == 0xF0 && idx + 3 < str_len) {
    const uint8_t c1 = static_cast<uint8_t>(utf8_str[idx + 1]);
    const uint8_t c2 = static_cast<uint8_t>(utf8_str[idx + 2]);
    const uint8_t c3 = static_cast<uint8_t>(utf8_str[idx + 3]);
    if ((c1 & 0xC0) == 0x80 && (c2 & 0xC0) == 0x80 && (c3 & 0xC0) == 0x80) {
      idx += 4;
      return (static_cast<uint32_t>(c0 & 0x07) << 18) |
             (static_cast<uint32_t>(c1 & 0x3F) << 12) |
             (static_cast<uint32_t>(c2 & 0x3F) << 6) |
             (static_cast<uint32_t>(c3 & 0x3F));
    }
  }
  ++idx;
  return 0xFFFD;
}

/** Heuristic display width for a Unicode codepoint in monospace terminals. */
inline size_t CodepointDisplayWidth(uint32_t cp) {
  if (cp == 0) {
    return 0;
  }
  // Combining marks (zero width)
  if ((cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF) ||
      (cp >= 0x1DC0 && cp <= 0x1DFF) || (cp >= 0x20D0 && cp <= 0x20FF) ||
      (cp >= 0xFE20 && cp <= 0xFE2F)) {
    return 0;
  }
  // Wide characters (CJK/emoji/box drawing) treated as width 2.
  if ((cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2329 && cp <= 0x232A) ||
      (cp >= 0x2E80 && cp <= 0xA4CF) || (cp >= 0xAC00 && cp <= 0xD7A3) ||
      (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE10 && cp <= 0xFE19) ||
      (cp >= 0xFE30 && cp <= 0xFE6F) || (cp >= 0xFF00 && cp <= 0xFF60) ||
      (cp >= 0xFFE0 && cp <= 0xFFE6) || (cp >= 0x2600 && cp <= 0x27BF) ||
      (cp >= 0x1F1E6 && cp <= 0x1F1FF) || (cp >= 0x1F300 && cp <= 0x1FAFF)) {
    return 2;
  }
  return 1;
}
inline size_t DisplayWidthUtf8(const std::string &utf8_str) {
  size_t width = 0;
  size_t idx = 0;
  while (idx < utf8_str.size()) {
    const uint32_t cp = NextCodepointUtf8(utf8_str, idx);
    width += CodepointDisplayWidth(cp);
  }
  return width;
}

inline void amfmt_append(std::string &out, const std::string &value) {
  out += value;
}
inline void amfmt_append(std::string &out, const char *value) {
  if (value) {
    out += value;
  } else {
    out += "(null)";
  }
}
inline void amfmt_append(std::string &out, char *value) {
  if (value) {
    out += value;
  } else {
    out += "(null)";
  }
}
template <typename T,
          typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
inline void amfmt_append(std::string &out, T value) {
  if constexpr (std::is_signed<T>::value) {
    out += std::to_string(static_cast<long long>(value));
  } else {
    out += std::to_string(static_cast<unsigned long long>(value));
  }
}

template <typename T, typename std::enable_if<std::is_floating_point<T>::value,
                                              int>::type = 0>
inline void amfmt_append(std::string &out, T value) {
  std::ostringstream oss;
  oss << value;
  out += oss.str();
}

template <typename T>
inline constexpr bool amfmt_allowed_v =
    std::disjunction_v<std::is_arithmetic<std::decay_t<T>>,
                       std::is_same<std::decay_t<T>, std::string>,
                       std::is_same<std::decay_t<T>, const char *>,
                       std::is_same<std::decay_t<T>, char *>>;

/**
 * @brief Convert a supported amfmt value into a string.
 */
template <typename T> inline std::string amfmt_to_string(T &&value) {
  static_assert(amfmt_allowed_v<T>,
                "amfmt only accepts string, char*, or integral types");
  std::string out;
  amfmt_append(out, std::forward<T>(value));
  return out;
}

/**
 * @brief Parse a padding specification like "<5" into alignment and width.
 */
inline bool amfmt_parse_padding_spec(const std::string &spec, char *align_out,
                                     size_t *width_out) {
  if (!align_out || !width_out) {
    return false;
  }
  if (spec.empty()) {
    return false;
  }
  const char align = spec.front();
  if (align != '<' && align != '>' && align != '^') {
    return false;
  }
  if (spec.size() == 1) {
    return false;
  }
  size_t width = 0;
  for (size_t i = 1; i < spec.size(); ++i) {
    const char c = spec[i];
    if (c < '0' || c > '9') {
      return false;
    }
    width = width * 10 + static_cast<size_t>(c - '0');
  }
  if (width == 0) {
    return false;
  }
  *align_out = align;
  *width_out = width;
  return true;
}

/**
 * @brief Apply padding to a string using the given alignment and width.
 */
inline std::string amfmt_apply_padding(const std::string &value, char align,
                                       size_t width) {
  const size_t current = DisplayWidthUtf8(value);
  if (current >= width) {
    return value;
  }
  const size_t padding = width - current;
  if (align == '<') {
    return value + std::string(padding, ' ');
  }
  if (align == '>') {
    return std::string(padding, ' ') + value;
  }
  const size_t left = padding / 2;
  const size_t right = padding - left;
  return std::string(left, ' ') + value + std::string(right, ' ');
}

/**
 * @brief Resolve a padding spec token like ":<5" or "<5".
 */
inline bool amfmt_parse_spec_token(const std::string &token, char *align_out,
                                   size_t *width_out) {
  if (!align_out || !width_out) {
    return false;
  }
  if (token.empty()) {
    return false;
  }
  if (token.front() == ':') {
    const std::string inner = token.substr(1);
    return amfmt_parse_padding_spec(inner, align_out, width_out);
  }
  return amfmt_parse_padding_spec(token, align_out, width_out);
}

inline size_t amfmt_count_placeholders(const std::string &templ) {
  size_t count = 0;
  std::string key;
  for (size_t i = 0; i < templ.size(); ++i) {
    char c = templ[i];
    if (c == '{') {
      if (i + 1 < templ.size() && templ[i + 1] == '{') {
        ++i;
        continue;
      }
      key.clear();
      size_t j = i + 1;
      for (; j < templ.size(); ++j) {
        if (templ[j] == '}') {
          ++count;
          i = j;
          break;
        }
        key.push_back(templ[j]);
      }
      if (j >= templ.size()) {
        throw std::runtime_error("amfmt: unmatched '{' in template");
      }
    } else if (c == '}' && i + 1 < templ.size() && templ[i + 1] == '}') {
      ++i;
    }
  }
  return count;
}

template <typename... Args>
inline std::string amfmt(const std::string &templ, Args &&...args) {
  static_assert((amfmt_allowed_v<Args> && ...),
                "amfmt only accepts string, char*, or integral types");
  size_t placeholder_count = amfmt_count_placeholders(templ);
  constexpr size_t arg_count = sizeof...(Args);
  if (placeholder_count == 0) {
    std::string out = templ;
    (amfmt_append(out, std::forward<Args>(args)), ...);
    return out;
  }
  if (placeholder_count != arg_count) {
    throw std::runtime_error("amfmt: argument count mismatch");
  }
  std::vector<std::string> values;
  values.reserve(arg_count);
  (void)std::initializer_list<int>{
      (values.push_back(amfmt_to_string(std::forward<Args>(args))), 0)...};

  std::string out;
  out.reserve(templ.size());
  size_t arg_index = 0;
  for (size_t i = 0; i < templ.size(); ++i) {
    char c = templ[i];
    if (c == '{') {
      if (i + 1 < templ.size() && templ[i + 1] == '{') {
        out.push_back('{');
        ++i;
        continue;
      }
      size_t j = i + 1;
      std::string token;
      for (; j < templ.size(); ++j) {
        if (templ[j] == '}') {
          if (arg_index >= values.size()) {
            throw std::runtime_error("amfmt: argument count mismatch");
          }
          std::string value = values[arg_index++];
          if (!token.empty()) {
            char align = 0;
            size_t width = 0;
            if (!amfmt_parse_spec_token(token, &align, &width)) {
              throw std::runtime_error("amfmt: unsupported format specifier");
            }
            value = amfmt_apply_padding(value, align, width);
          }
          out += value;
          i = j;
          break;
        }
        token.push_back(templ[j]);
      }
      if (j >= templ.size()) {
        throw std::runtime_error("amfmt: unmatched '{' in template");
      }
    } else if (c == '}' && i + 1 < templ.size() && templ[i + 1] == '}') {
      out.push_back('}');
      ++i;
    } else {
      out.push_back(c);
    }
  }
  return out;
}

template <typename... Args>
inline std::string amfmt(const char *templ, Args &&...args) {
  return amfmt(std::string(templ ? templ : ""), std::forward<Args>(args)...);
}

inline void vlowercase(std::string &str) {
  for (char &c : str) {
    if (c >= 'A' && c <= 'Z') {
      c += 32;
    }
  }
}

inline void vuppercase(std::string &str) {
  for (char &c : str) {
    if (c >= 'a' && c <= 'z') {
      c -= 32;
    }
  }
}

inline std::string lowercase(const std::string &str) {
  // Iterate over string (C++98-compatible iterator style)
  std::string str_f = str;
  vlowercase(str_f);
  return str_f;
}

inline std::string uppercase(const std::string &str) {
  std::string str_f = str;
  vuppercase(str_f);
  return str_f;
}

inline std::wstring wstr(const std::string &str) {
  return boost::locale::conv::utf_to_utf<wchar_t>(str);
}

inline std::string wstr(const std::wstring &wstr) {
  return boost::locale::conv::utf_to_utf<char>(wstr);
}

inline std::string wstr(wchar_t *wstr) {
  return boost::locale::conv::utf_to_utf<char>(wstr);
}

inline std::wstring wstr(char *str) {
  return boost::locale::conv::utf_to_utf<wchar_t>(str);
}

inline size_t CharNum(const std::string &utf8_str) {
  const size_t str_len = utf8_str.size();
  size_t char_count = 0;
  size_t idx = 0;

  while (idx < str_len) {
    const uint8_t current = static_cast<uint8_t>(utf8_str[idx]);

    if ((current & 0x80) == 0) {
      ++char_count;
      ++idx;
    } else if ((current & 0xE0) == 0xC0 && idx + 1 < str_len) {
      // Try matching 2-byte character; if invalid, count as single byte
      const uint8_t next = static_cast<uint8_t>(utf8_str[idx + 1]);
      if ((next & 0xC0) == 0x80) {
        ++char_count;
        idx += 2;
        continue;
      }
      ++char_count;
      ++idx;
    } else if ((current & 0xF0) == 0xE0 && idx + 2 < str_len) {
      // Try matching 3-byte character
      const uint8_t next1 = static_cast<uint8_t>(utf8_str[idx + 1]);
      const uint8_t next2 = static_cast<uint8_t>(utf8_str[idx + 2]);
      if ((next1 & 0xC0) == 0x80 && (next2 & 0xC0) == 0x80) {
        ++char_count;
        idx += 3;
        continue;
      }
      ++char_count;
      ++idx;
    } else if ((current & 0xF8) == 0xF0 && idx + 3 < str_len) {
      // Try matching 4-byte character
      const uint8_t next1 = static_cast<uint8_t>(utf8_str[idx + 1]);
      const uint8_t next2 = static_cast<uint8_t>(utf8_str[idx + 2]);
      const uint8_t next3 = static_cast<uint8_t>(utf8_str[idx + 3]);
      if ((next1 & 0xC0) == 0x80 && (next2 & 0xC0) == 0x80 &&
          (next3 & 0xC0) == 0x80) {
        ++char_count;
        idx += 4;
        continue;
      }
      ++char_count;
      ++idx;
    } else {
      // Invalid byte; count as single character
      ++char_count;
      ++idx;
    }
  }

  return char_count;
}

/** Display width for a UTF-8 string (accounts for wide and combining chars). */

/**
 * Repeat a UTF-8 token (e.g., a single box-drawing glyph) for the given count.
 * This is used to build table borders where each column has variable width.
 */
inline std::string RepeatUtf8(const std::string &token, size_t count) {
  std::string out;
  out.reserve(token.size() * count);
  for (size_t i = 0; i < count; ++i) {
    out += token;
  }
  return out;
}

/**
 * Right-pad a UTF-8 string with spaces until it reaches the target display
 * width. Width is measured in UTF-8 codepoint count using CharNum, not byte
 * length.
 */
inline std::string PadRightUtf8(const std::string &text, size_t width) {
  const size_t len = DisplayWidthUtf8(text);
  if (len >= width) {
    return text;
  }
  return text + std::string(width - len, ' ');
}

/** Parse #RRGGBB to ANSI 24-bit foreground color escape code; empty on failure.
 */
inline std::string AnsiColor24(const std::string &hex_color) {
  if (hex_color.size() != 7 || hex_color[0] != '#') {
    return "";
  }
  auto hex_to_int = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
      return 10 + (c - 'A');
    return -1;
  };
  int vals[6];
  for (int i = 0; i < 6; ++i) {
    vals[i] = hex_to_int(hex_color[1 + i]);
    if (vals[i] < 0) {
      return "";
    }
  }
  const int r = vals[0] * 16 + vals[1];
  const int g = vals[2] * 16 + vals[3];
  const int b = vals[4] * 16 + vals[5];
  return AMStr::amfmt("\x1b[38;2;{};{};{}m", r, g, b);
}

/**
 * Build a UTF-8 bordered table string using the provided column keys and rows.
 * Column order strictly follows the order in the keys vector, and missing cells
 * are treated as empty strings so all rows align correctly.
 */
inline std::string
FormatUtf8Table(const std::vector<std::string> &keys,
                const std::vector<std::vector<std::string>> &rows,
                const std::string &skeleton_color = "", size_t pad_left = 1,
                size_t pad_right = 1, size_t pad_top = 0,
                size_t pad_bottom = 0) {
  if (keys.empty()) {
    return "";
  }

  const size_t col_count = keys.size();
  std::vector<size_t> widths(col_count, 0);
  for (size_t c = 0; c < col_count; ++c) {
    widths[c] = DisplayWidthUtf8(keys[c]);
  }
  for (const auto &row : rows) {
    for (size_t c = 0; c < col_count; ++c) {
      const std::string &cell = (c < row.size()) ? row[c] : std::string();
      const size_t cell_len = DisplayWidthUtf8(cell);
      if (cell_len > widths[c]) {
        widths[c] = cell_len;
      }
    }
  }

  const std::string color_prefix = AnsiColor24(skeleton_color);
  const std::string color_suffix = color_prefix.empty() ? "" : "\x1b[0m";

  auto build_border = [&](const std::string &left, const std::string &mid,
                          const std::string &right) {
    std::string line = color_prefix + left + color_suffix;
    for (size_t c = 0; c < col_count; ++c) {
      line += color_prefix + RepeatUtf8("─", widths[c] + pad_left + pad_right) +
              color_suffix;
      line +=
          color_prefix + ((c + 1 == col_count) ? right : mid) + color_suffix;
    }
    return line;
  };

  auto build_row = [&](const std::vector<std::string> &row) {
    std::string line = color_prefix + "│" + color_suffix;
    for (size_t c = 0; c < col_count; ++c) {
      const std::string &cell = (c < row.size()) ? row[c] : std::string();
      line += std::string(pad_left, ' ');
      line += PadRightUtf8(cell, widths[c]);
      line += std::string(pad_right, ' ');
      line += color_prefix + "│" + color_suffix;
    }
    return line;
  };

  auto build_empty_row = [&]() {
    std::string line = color_prefix + "│" + color_suffix;
    for (size_t c = 0; c < col_count; ++c) {
      line += std::string(widths[c] + pad_left + pad_right, ' ');
      line += color_prefix + "│" + color_suffix;
    }
    return line;
  };

  std::ostringstream oss;
  oss << build_border("┌", "┬", "┐") << "\n";
  for (size_t i = 0; i < pad_top; ++i) {
    oss << build_empty_row() << "\n";
  }
  oss << build_row(keys) << "\n";
  for (size_t i = 0; i < pad_bottom; ++i) {
    oss << build_empty_row() << "\n";
  }
  oss << build_border("├", "┼", "┤") << "\n";
  for (size_t r = 0; r < rows.size(); ++r) {
    for (size_t i = 0; i < pad_top; ++i) {
      oss << build_empty_row() << "\n";
    }
    oss << build_row(rows[r]);
    for (size_t i = 0; i < pad_bottom; ++i) {
      oss << "\n" << build_empty_row();
    }
    if (r + 1 < rows.size()) {
      oss << "\n";
    }
  }
  oss << "\n" << build_border("└", "┴", "┘");
  return oss.str();
}

inline std::pair<bool, int> endswith(const std::string &str,
                                     const std::string &suffix) {
  if (suffix.empty())
    return std::make_pair(true, str.size());
  if (str.size() < suffix.size())
    return std::make_pair(false, 0);
  return std::make_pair(
      str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0,
      str.size() - suffix.size());
}

inline std::string ModeTrans(size_t mode_int) {
  // Convert mode_int to octal string, length 9
  if (mode_int > 0777 || mode_int == 0777) {
    return "rwxrwxrwx";
  }
  std::string out = "";
  size_t tmp_int;
  size_t start = 8 * 8 * 8;
  for (int i = 3; i > 0; i--) {
    tmp_int = (mode_int % start) / (start / 8);
    start /= 8;
    switch (tmp_int) {
    case 1:
      out += "--x";
      break;
    case 2:
      out += "-w-";
      break;
    case 3:
      out += "-wx";
      break;
    case 4:
      out += "r--";
      break;
    case 5:
      out += "r-x";
      break;
    case 6:
      out += "rw-";
      break;
    case 7:
      out += "rwx";
      break;
    default:
      out += "---";
    }
  }
  return out;
}

inline size_t ModeTrans(std::string mode_str) {
  std::regex pattern(
      R"(^[r?\-][w?\-][x?\-][r?\-][w?\-][x?\-][r?\-][w?\-][x?\-]$)");
  if (!std::regex_match(mode_str, pattern)) {
    throw std::invalid_argument(amfmt("Invalid mode string: ", mode_str));
  }
  size_t mode_int = 0;
  for (int i = 0; i < 9; i++) {
    if (mode_str[i] != '?' && mode_str[i] != '-') {
      mode_int += (1ULL << (8 - i));
    }
  }
  return mode_int;
}

inline std::string MergeModeStr(const std::string &base_mode_str,
                                const std::string &new_mode_str) {
  std::string pattern_f =
      "^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$";
  std::regex pattern(pattern_f);

  if (!std::regex_match(base_mode_str, pattern)) {
    throw std::invalid_argument(
        amfmt("Invalid base mode string: ", base_mode_str));
  }

  if (!std::regex_match(new_mode_str, pattern)) {
    throw std::invalid_argument(
        amfmt("Invalid new mode string: ", new_mode_str));
  }

  std::string mode_str = "";
  for (int i = 0; i < 9; i++) {
    mode_str += (new_mode_str[i] == '?' ? base_mode_str[i] : new_mode_str[i]);
  }
  return mode_str;
}

inline bool IsModeValid(std::string mode_str) {
  return std::regex_match(mode_str,
                          std::regex("^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?"
                                     "\\-][r?\\-][w?\\-][x?\\-]$"));
}

inline bool IsModeValid(size_t mode_int) { return mode_int <= 0777; }

/**
 * @brief Escape a string for bbcode output by shielding tag delimiters.
 */
inline std::string BBCEscape(const std::string &text) {
  std::string escaped;
  escaped.reserve(text.size());
  for (char c : text) {
    if (c == '\\' || c == '[') {
      escaped.push_back('\\');
    }
    escaped.push_back(c);
  }
  return escaped;
}

inline bool IsWhitespace(char c) {
  return std::isspace(static_cast<unsigned char>(c)) != 0;
}

inline void VStrip(std::string &path) {
  size_t start = 0;
  while (start < path.size() &&
         std::isspace(static_cast<unsigned char>(path[start])) != 0) {
    ++start;
  }
  if (start >= path.size()) {
    return;
  }
  size_t end = path.size();
  while (end > start &&
         std::isspace(static_cast<unsigned char>(path[end - 1])) != 0) {
    --end;
  }
  path = path.substr(start, end - start);
}

inline std::string Strip(const std::string &path) {
  std::string result = path;
  VStrip(result);
  return result;
}

inline void vreplace(std::string &str, const std::string &from,
                     const std::string &to) {
  size_t pos = 0;
  while ((pos = str.find(from, pos)) != std::string::npos) {
    str.replace(pos, from.length(), to);
    pos += to.length();
  }
}
inline std::string replace(std::string str, const std::string &from,
                           const std::string &to) {
  size_t pos = 0;
  while ((pos = str.find(from, pos)) != std::string::npos) {
    str.replace(pos, from.length(), to);
    pos += to.length();
  }
  return str;
}

inline void vreplace_all(std::string &str, const std::string &old_sub,
                         const std::string &new_sub) {
  size_t pos = 0;
  while ((pos = str.find(old_sub, pos)) != std::string::npos) {
    str.replace(pos, old_sub.size(), new_sub);
    // Skip replaced content to avoid repeated replacement (e.g. old_sub is a substring of new_sub)
    pos += new_sub.size();
    // If repeated replacement is allowed (e.g. replace "a" with "aa"), keep pos unchanged
  }
}

inline std::string replace_all(std::string str, const std::string &old_sub,
                               const std::string &new_sub) {
  size_t pos = 0;
  while ((pos = str.find(old_sub, pos)) != std::string::npos) {
    str.replace(pos, old_sub.size(), new_sub);
    // Skip replaced content to avoid repeated replacement (e.g. old_sub is a substring of new_sub)
    pos += new_sub.size();
    // If repeated replacement is allowed (e.g. replace "a" with "aa"), keep pos unchanged
  }
  return str;
}

inline std::string join(const std::vector<std::string> &parts,
                        const std::string &sep) {
  if (parts.empty()) {
    return "";
  }
  std::string out = parts[0];
  for (size_t i = 1; i < parts.size(); ++i) {
    out += sep;
    out += parts[i];
  }
  return out;
}

/**
 * @brief Left pad an ASCII string to a fixed width.
 */
inline std::string PadLeftAscii(std::string_view value, size_t width) {
  if (width == 0) {
    return {};
  }
  if (value.size() >= width) {
    return std::string(value);
  }
  std::string out;
  out.append(width - value.size(), ' ');
  out.append(value);
  return out;
}

/**
 * @brief Count rendered lines in a multi-line string.
 */
inline size_t CountLines(const std::string &text) {
  if (text.empty()) {
    return 0;
  }
  size_t lines = 0;
  for (char ch : text) {
    if (ch == '\n') {
      ++lines;
    }
  }
  if (text.back() != '\n') {
    ++lines;
  }
  return lines;
}

// Export amfmt function
} // namespace AMStr
#define AM_ENUM_NAME(x) std::string(magic_enum::enum_name(x))

/**
 * @brief Progress bar style configuration.
 */
struct AMProgressBarStyle {
  size_t bar_width = 30;
  std::string start = "[";
  std::string end = "]";
  std::string fill = "=";
  std::string lead = ">";
  std::string remainder = " ";
  std::variant<indicators::Color, std::string> color = indicators::Color::blue;
  int width_offset = 30;
  bool show_percentage = true;
  bool show_elapsed_time = true;
  bool show_remaining_time = true;
};

/**
 * @brief Progress bar wrapper that updates its text using
 * indicators::ProgressBar.
 *
 * The bar itself does not print unless it is managed by a group refresh.
 */
class AMProgressBar {
public:
  inline static std::atomic<int> active_count_{0};
  /**
   * @brief Construct a progress bar with a total size and prefix.
   * @param total_size Total number of bytes to complete.
   * @param prefix Display prefix.
   */
  explicit AMProgressBar(int64_t total_size = 0, std::string prefix = "",
                         AMProgressBarStyle style = {})
      : total_size_(std::max<int64_t>(0, total_size)),
        prefix_(std::move(prefix)), prefix_field_(), postfix_(),
        bar_width_(style.bar_width > 0 ? style.bar_width : 30),
        start_token_(style.start), end_token_(style.end),
        show_percentage_(style.show_percentage),
        show_elapsed_time_(style.show_elapsed_time),
        show_remaining_time_(style.show_remaining_time),
        width_offset_(style.width_offset),
        start_time_(std::chrono::steady_clock::now()),
        last_update_time_(start_time_),
        bar_(indicators::option::BarWidth{bar_width_},
             indicators::option::Start{start_token_},
             indicators::option::Fill{style.fill.empty() ? "=" : style.fill},
             indicators::option::Lead{style.lead.empty() ? ">" : style.lead},
             indicators::option::Remainder{
                 style.remainder.empty() ? " " : style.remainder},
             indicators::option::End{end_token_},
             indicators::option::PrefixText{prefix_},
             indicators::option::ForegroundColor{style.color},
             indicators::option::PostfixText{""},
             indicators::option::MaxProgress{static_cast<size_t>(total_size_)},
             indicators::option::ShowPercentage{false},
             indicators::option::ShowElapsedTime{false},
             indicators::option::ShowRemainingTime{false}) {
    std::lock_guard<std::mutex> lock(mtx_);
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
  }

  /**
   * @brief Set or update the total size.
   * @param total_size Total number of bytes.
   * @param reset_timer Whether to reset elapsed time origin.
   */
  void SetTotal(int64_t total_size, bool reset_timer = false) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_size_ = std::max<int64_t>(0, total_size);
    if (current_size_ > total_size_) {
      current_size_ = total_size_;
    }
    if (reset_timer) {
      start_time_ = std::chrono::steady_clock::now();
      last_update_time_ = start_time_;
      last_update_size_ = current_size_;
      speed_samples_.clear();
      speed_bps_ = 0.0;
    }
    bar_.set_option(
        indicators::option::MaxProgress{static_cast<size_t>(total_size_)});
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
  }

  /**
   * @brief Set the display prefix.
   * @param prefix Prefix text.
   */
  void SetPrefix(std::string prefix) {
    std::lock_guard<std::mutex> lock(mtx_);
    prefix_ = std::move(prefix);
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
  }

  /**
   * @brief Advance progress by a delta in bytes.
   * @param delta Bytes to add.
   */
  void Advance(int64_t delta) {
    if (delta <= 0) {
      return;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = std::min<int64_t>(total_size_, current_size_ + delta);
    UpdateSpeedLocked_();
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
    bar_.set_progress(static_cast<size_t>(current_size_));
  }

  /**
   * @brief Set the current progress in bytes.
   * @param current_size Accumulated size in bytes.
   */
  void SetProgress(int64_t current_size) {
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = std::clamp<int64_t>(current_size, 0, total_size_);
    UpdateSpeedLocked_();
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
    bar_.set_progress(static_cast<size_t>(current_size_));
  }

  /**
   * @brief Set the start time using a Unix epoch timestamp (seconds).
   * @param epoch_seconds Unix epoch time in seconds.
   */
  void SetStartTimeEpoch(double epoch_seconds) {
    std::lock_guard<std::mutex> lock(mtx_);
    const auto sys_now = std::chrono::system_clock::now();
    const auto steady_now = std::chrono::steady_clock::now();
    const auto epoch_now =
        std::chrono::duration<double>(sys_now.time_since_epoch()).count();
    const auto delta = epoch_seconds - epoch_now;
    start_time_ =
        steady_now +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::duration<double>(delta));
    last_update_time_ = steady_now;
    last_update_size_ = current_size_;
    speed_samples_.clear();
    speed_bps_ = 0.0;
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
  }

  void SetCursorVisible(bool sign) { indicators::show_console_cursor(sign); }

  /**
   * @brief Set the maximum window size for speed calculation.
   * @param window_size Maximum number of samples to keep.
   */
  void SetSpeedWindowSize(size_t window_size) {
    std::lock_guard<std::mutex> lock(mtx_);
    speed_window_size_ = std::max<size_t>(1, window_size);
    while (speed_samples_.size() > speed_window_size_) {
      speed_samples_.pop_front();
    }
    UpdateSpeedLocked_();
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
  }

  /**
   * @brief Render the progress bar in-place.
   * @param from_group Whether the render is driven by a group.
   */
  void Print(bool from_group = false) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!from_group && !showing_) {
      showing_ = true;
      active_count_.fetch_add(1, std::memory_order_relaxed);
    }
    if (!from_group && !cursor_hidden_) {
      indicators::show_console_cursor(false);
      cursor_hidden_ = true;
    }
    bar_.print_progress(from_group);
  }

  /**
   * @brief Restore cursor visibility if it was hidden by this bar.
   */
  void EndDisplay() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (cursor_hidden_) {
      indicators::show_console_cursor(true);
      cursor_hidden_ = false;
    }
    if (showing_) {
      showing_ = false;
      active_count_.fetch_sub(1, std::memory_order_relaxed);
    }
  }

  /**
   * @brief Mark the bar as completed and clamp to total size.
   */
  void Finish() {
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = total_size_;
    UpdateSpeedLocked_();
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
    bar_.set_option(indicators::option::Completed{true});
    if (cursor_hidden_) {
      indicators::show_console_cursor(true);
      cursor_hidden_ = false;
    }
    if (showing_) {
      showing_ = false;
      active_count_.fetch_sub(1, std::memory_order_relaxed);
    }
    ic_print("\x1b[0m");
  }

  /**
   * @brief Return whether the bar has finished.
   * @return True if finished.
   */
  bool IsFinished() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return bar_.is_completed();
  }

  /**
   * @brief Check whether any progress bar is currently showing.
   */
  static bool IsAnyBarShowing() {
    return active_count_.load(std::memory_order_relaxed) > 0;
  }

private:
  /**
   * @brief Print progress through indicators without ending the line.
   * @param from_group Whether we are called from a group render.
   */
  void PrintLocked_(bool from_group) { bar_.print_progress(from_group); }

  /**
   * @brief Update speed sampling information while holding the lock.
   */
  void UpdateSpeedLocked_() {
    const auto now = std::chrono::steady_clock::now();
    speed_samples_.push_back({now, current_size_});
    while (speed_samples_.size() > speed_window_size_) {
      speed_samples_.pop_front();
    }
    if (speed_samples_.size() >= 2) {
      const auto &first = speed_samples_.front();
      const auto &last = speed_samples_.back();
      const double dt =
          std::chrono::duration<double>(last.when - first.when).count();
      if (dt > 0.0) {
        speed_bps_ = static_cast<double>(last.value - first.value) / dt;
      } else {
        speed_bps_ = 0.0;
      }
    } else {
      speed_bps_ = 0.0;
    }
    last_update_time_ = now;
    last_update_size_ = current_size_;
  }

  /**
   * @brief Compute the postfix string with size, percentage, and speed.
   */
  void UpdatePostfixLocked_() {
    const double percent = (total_size_ <= 0)
                               ? 0.0
                               : (static_cast<double>(current_size_) /
                                  static_cast<double>(total_size_)) *
                                     100.0;
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time_);
    const int64_t elapsed_sec = std::max<int64_t>(0, elapsed.count());
    const double speed_bps = speed_bps_;
    const int64_t remaining_bytes =
        (total_size_ > current_size_) ? (total_size_ - current_size_) : 0;
    const int64_t remain_sec =
        (speed_bps > 0.0) ? static_cast<int64_t>(remaining_bytes / speed_bps)
                          : 0;

    std::string size_part = AMStr::amfmt("{}/{}", FormatSize_(current_size_, 2),
                                         FormatSize_(total_size_, 2));
    std::vector<std::string> bracket_parts;
    if (show_elapsed_time_ || show_remaining_time_) {
      std::string time_part;
      if (show_elapsed_time_) {
        time_part = FormatTimeMMSS_(elapsed_sec);
      }
      if (show_remaining_time_) {
        if (!time_part.empty()) {
          time_part += "<";
        }
        time_part += FormatTimeMMSS_(remain_sec);
      }
      if (!time_part.empty()) {
        bracket_parts.push_back(std::move(time_part));
      }
    }
    bracket_parts.push_back(FormatSpeed_(speed_bps));
    std::ostringstream bracket_oss;
    for (size_t i = 0; i < bracket_parts.size(); ++i) {
      if (i > 0) {
        bracket_oss << ' ';
      }
      bracket_oss << bracket_parts[i];
    }
    if (show_percentage_) {
      postfix_ = AMStr::amfmt("{} | {} [{}]", FormatPercent_(percent),
                              size_part, bracket_oss.str());
    } else {
      postfix_ = AMStr::amfmt("{} [{}]", size_part, bracket_oss.str());
    }
  }

  /**
   * @brief Update the prefix field to a fixed width based on terminal size.
   */
  void UpdatePrefixLocked_() {
    const size_t term_width = indicators::terminal_width();
    const size_t postfix_len = postfix_.size();
    const size_t start_len = start_token_.size();
    const size_t end_len = end_token_.size();
    int max_prefix =
        static_cast<int>(term_width) -
        static_cast<int>(bar_width_ + start_len + end_len + postfix_len) -
        width_offset_;

    prefix_field_ = PadRight_(prefix_, max_prefix > 0 ? max_prefix : 0);
  }

  /**
   * @brief Right pad a string to a given width.
   * @param value Input string.
   * @param width Target width.
   * @return Padded string.
   */
  static std::string PadRight_(std::string_view value, size_t width) {
    if (width == 0) {
      return {};
    }
    if (value.size() >= width) {
      return std::string(value.substr(0, width));
    }
    std::string out(value);
    out.append(width - value.size(), ' ');
    return out;
  }

  static std::string PadLeft_(std::string_view value, size_t width) {
    if (width == 0) {
      return {};
    }
    if (value.size() >= width) {
      return std::string(value);
    }
    std::string out;
    out.append(width - value.size(), ' ');
    out.append(value);
    return out;
  }

  /**
   * @brief Format percentage as a fixed-width string.
   * @param percent Percentage value in [0, 100].
   * @return Formatted percentage string with one decimal place.
   */
  static std::string FormatPercent_(double percent) {
    const double clamped = std::clamp(percent, 0.0, 100.0);
    if (clamped >= 100.0) {
      return PadLeft_("100%", 5);
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << clamped << "%";
    return PadLeft_(oss.str(), 5);
  }

  /**
   * @brief Format bytes into a human readable size.
   * @param bytes Input size in bytes.
   * @param precision Decimal digits.
   * @return Formatted size string.
   */
  static std::string FormatSize_(int64_t bytes, int precision = 1) {
    const char *suffixes[] = {"B", "KB", "MB", "GB", "TB"};
    double size = static_cast<double>(std::max<int64_t>(0, bytes));
    int idx = 0;
    while (size >= 1024.0 && idx < 4) {
      size /= 1024.0;
      ++idx;
    }
    std::ostringstream oss;
    if (idx == 0) {
      oss << static_cast<int64_t>(size);
    } else {
      oss << std::fixed << std::setprecision(precision) << size;
    }
    std::string out = AMStr::amfmt("{}{}", oss.str(), suffixes[idx]);
    return PadLeft_(out, 7);
  }

  static std::string FormatSizeNoSpace_(int64_t bytes, int precision = 1) {
    const char *suffixes[] = {"B", "KB", "MB", "GB", "TB"};
    double size = static_cast<double>(std::max<int64_t>(0, bytes));
    int idx = 0;
    while (size >= 1024.0 && idx < 4) {
      size /= 1024.0;
      ++idx;
    }
    std::ostringstream oss;
    if (idx == 0) {
      oss << static_cast<int64_t>(size);
    } else {
      oss << std::fixed << std::setprecision(precision) << size;
    }
    const std::string out = AMStr::amfmt("{}{}", oss.str(), suffixes[idx]);
    return PadLeft_(out, 7);
  }

  /**
   * @brief Format elapsed seconds into MM:SS.
   * @param seconds Elapsed seconds.
   * @return Formatted time string.
   */
  static std::string FormatTimeMMSS_(int64_t seconds) {
    const int64_t clamped = std::max<int64_t>(0, seconds);
    const int64_t hours = clamped / 3600;
    const int64_t minutes = (clamped % 3600) / 60;
    const int64_t secs = clamped % 60;
    std::ostringstream oss;
    if (hours > 0) {
      oss << hours << ":" << std::setw(2) << std::setfill('0') << minutes << ":"
          << std::setw(2) << std::setfill('0') << secs;
      return oss.str();
    }
    oss << std::setw(2) << std::setfill('0') << minutes << ":" << std::setw(2)
        << std::setfill('0') << secs;
    return PadLeft_(oss.str(), 7);
  }

  /**
   * @brief Format speed in bytes per second.
   * @param bps Speed in bytes/sec.
   * @return Formatted speed string.
   */
  static std::string FormatSpeed_(double bps) {
    const std::string size = FormatSizeNoSpace_(static_cast<int64_t>(bps), 1);
    return PadLeft_(size + "/s", 9);
  }

private:
  mutable std::mutex mtx_;
  int64_t total_size_ = 0;
  int64_t current_size_ = 0;
  std::string prefix_;
  std::string prefix_field_;
  std::string postfix_;
  const size_t bar_width_;
  const std::string start_token_;
  const std::string end_token_;
  const bool show_percentage_;
  const bool show_elapsed_time_;
  const bool show_remaining_time_;
  const int width_offset_;
  std::chrono::steady_clock::time_point start_time_;
  std::chrono::steady_clock::time_point last_update_time_;
  int64_t last_update_size_ = 0;
  struct SpeedSample {
    std::chrono::steady_clock::time_point when;
    int64_t value = 0;
  };
  std::deque<SpeedSample> speed_samples_;
  size_t speed_window_size_ = 10;
  double speed_bps_ = 0.0;
  bool cursor_hidden_ = false;
  bool showing_ = false;
  indicators::ProgressBar bar_;
};

inline void print(const std::string &str) { std::cout << str << "\n"; }

template <typename... Args> inline void print(Args &&...args) {
  if constexpr (sizeof...(Args) >= 2) {
    std::cout << AMStr::amfmt(std::forward<Args>(args)...) << "\n";
  } else {
    (std::cout << ... << std::forward<Args>(args)) << "\n";
  }
}
using Json = nlohmann::ordered_json;

/**
 * @brief Format size to human-readable string.
 */
inline std::string FormatSize(size_t size) {
  static const std::vector<std::string> units = {"B", "KB", "MB", "GB", "TB"};
  auto value = static_cast<double>(size);
  size_t idx = 0;
  while (value >= 1024.0 && idx < 4) {
    value /= 1024.0;
    ++idx;
  }
  std::ostringstream oss;
  if (value == static_cast<size_t>(value)) {
    oss << static_cast<size_t>(value);
  } else {
    oss << std::fixed << std::setprecision(1) << value;
  }
  oss << units[idx];
  return oss.str();
}

inline std::string FormatSize(int64_t size) {
  if (size < 0) {
    return "0B";
  }
  return FormatSize(static_cast<size_t>(size));
}

inline bool GetEnv(std::string_view key, std::string *target) {
  if (!key.data() || !target) {
    return false;
  }
#ifdef _WIN32
  char *buffer = nullptr;
  size_t length = 0;
  if (_dupenv_s(&buffer, &length, key.data()) != 0 || !buffer) {
    return false;
  }
  *target = std::string(buffer);
  std::free(buffer);
  return true;
#else
  const char *value = std::getenv(key.data());
  if (!value) {
    return false;
  }
  *target = std::string(value);
  return true;
#endif
}

/**
 * @brief Remove duplicate entries while preserving original order.
 */
template <typename T>
std::vector<T> UniqueTargetsKeepOrder(const std::vector<T> &targets) {
  std::vector<T> unique;
  unique.reserve(targets.size());
  for (const auto &target : targets) {
    if (std::find(unique.begin(), unique.end(), target) != unique.end()) {
      continue;
    }
    unique.push_back(target);
  }
  return unique;
}

template <class T>
static inline constexpr bool kValueTypeSupported =
    std::is_arithmetic_v<std::decay_t<T>> ||
    std::is_same_v<std::decay_t<T>, std::string> ||
    std::is_same_v<std::decay_t<T>, std::vector<std::string>> ||
    std::is_same_v<std::decay_t<T>, Json>;

template <typename T>
inline static bool QueryKey(const Json &root,
                            const std::vector<std::string> &path, T *value) {
  static_assert(kValueTypeSupported<T>, "T is not supported");
  if (!value) {
    return false;
  }
  const Json *node = &root;
  for (const auto &seg : path) {
    if (!node->is_object()) {
      return false;
    }
    auto it = node->find(seg);
    if (it == node->end()) {
      return false;
    }
    node = &(*it);
  }
  if constexpr (std::is_same_v<T, bool>) {
    if (!node->is_boolean()) {
      if (node->is_number_integer()) {
        *value = node->get<int64_t>() != 0;
        return true;
      }
      if (node->is_number_unsigned()) {
        *value = node->get<size_t>() != 0;
        return true;
      }
      if (node->is_string()) {
        const std::string token = AMStr::lowercase(node->get<std::string>());
        if (token == "true" || token == "1" || token == "yes" ||
            token == "on") {
          *value = true;
          return true;
        }
        if (token == "false" || token == "0" || token == "no" ||
            token == "off") {
          *value = false;
          return true;
        }
      }
      return false;
    }
    *value = node->get<bool>();
    return true;
  } else if constexpr (std::is_same_v<T, std::string>) {
    if (node->is_string()) {
      *value = node->get<std::string>();
      return true;
    }
    if (node->is_boolean()) {
      *value = node->get<bool>() ? "true" : "false";
      return true;
    }
    if (node->is_number_integer()) {
      *value = std::to_string(node->get<int64_t>());
      return true;
    }
    if (node->is_number_unsigned()) {
      *value = std::to_string(node->get<size_t>());
      return true;
    }
    if (node->is_number_float()) {
      *value = std::to_string(node->get<double>());
      return true;
    }
    return false;
  } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
    if (!node->is_array()) {
      return false;
    }
    std::vector<std::string> out;
    out.reserve(node->size());
    for (const auto &item : *node) {
      if (item.is_string()) {
        out.push_back(item.get<std::string>());
        continue;
      }
      if (item.is_boolean()) {
        out.push_back(item.get<bool>() ? "true" : "false");
        continue;
      }
      if (item.is_number_integer()) {
        out.push_back(std::to_string(item.get<int64_t>()));
        continue;
      }
      if (item.is_number_unsigned()) {
        out.push_back(std::to_string(item.get<size_t>()));
        continue;
      }
      if (item.is_number_float()) {
        out.push_back(std::to_string(item.get<double>()));
        continue;
      }
      return false;
    }
    *value = std::move(out);
    return true;
  } else if constexpr (std::is_same_v<T, nlohmann::ordered_json>) {
    *value = *node;
    return true;
  } else if constexpr (std::is_floating_point_v<T>) {
    if (node->is_number()) {
      *value = static_cast<T>(node->get<double>());
      return true;
    }
    if (node->is_string()) {
      try {
        *value = static_cast<T>(std::stod(node->get<std::string>()));
        return true;
      } catch (...) {
        return false;
      }
    }
    return false;
  } else if constexpr (std::is_integral_v<T>) {
    if (node->is_number_integer()) {
      const int64_t raw = node->get<int64_t>();
      if (raw < static_cast<int64_t>(std::numeric_limits<T>::min()) ||
          raw > static_cast<int64_t>(std::numeric_limits<T>::max())) {
        return false;
      }
      *value = static_cast<T>(raw);
      return true;
    }
    if (node->is_number_unsigned()) {
      const uint64_t raw = node->get<uint64_t>();
      if (raw > static_cast<uint64_t>(std::numeric_limits<T>::max())) {
        return false;
      }
      *value = static_cast<T>(raw);
      return true;
    }
    if (node->is_string()) {
      try {
        const int64_t raw = std::stoll(node->get<std::string>());
        if (raw < static_cast<int64_t>(std::numeric_limits<T>::min()) ||
            raw > static_cast<int64_t>(std::numeric_limits<T>::max())) {
          return false;
        }
        *value = static_cast<T>(raw);
        return true;
      } catch (...) {
        return false;
      }
    }
    return false;
  } else {
    return false;
  }
}

template <typename T>
inline static bool SetKey(nlohmann::ordered_json &root,
                          const std::vector<std::string> &path, T value) {
  static_assert(kValueTypeSupported<T>, "T is not supported");
  if (path.empty()) {
    root = value;
    return true;
  }
  nlohmann::ordered_json *node = &root;
  for (size_t i = 0; i < path.size(); ++i) {
    const std::string &seg = path[i];
    if (i + 1 == path.size()) {
      (*node)[seg] = value;
      return true;
    }
    if (!node->is_object()) {
      *node = nlohmann::ordered_json::object();
    }
    if (!node->contains(seg) || !(*node)[seg].is_object()) {
      (*node)[seg] = nlohmann::ordered_json::object();
    }
    node = &(*node)[seg];
  }
  return false;
}

inline bool DelKey(Json &root, const std::vector<std::string> &path) {
  if (path.empty()) {
    return false;
  }
  Json *node = &root;
  for (size_t i = 0; i < path.size(); ++i) {
    const std::string &seg = path[i];
    if (!node->is_object()) {
      return false;
    }
    auto it = node->find(seg);
    if (it == node->end()) {
      return false;
    }
    if (i + 1 == path.size()) {
      node->erase(it);
      return true;
    }
    node = &(*it);
  }
  return false;
}

template <typename T> bool StrValueParse(const std::string &input, T *out) {
  static_assert(std::is_arithmetic_v<std::decay_t<T>> ||
                    std::is_same_v<std::decay_t<T>, std::string> ||
                    std::is_same_v<T, bool>,
                "T is not supported");
  if constexpr (std::is_same_v<T, bool>) {
    const std::string token = AMStr::lowercase(input);
    if (token == "true") {
      *out = true;
      return true;
    }
    if (token == "false") {
      *out = false;
      return true;
    }
  }
  if constexpr (std::is_same_v<T, std::string>) {
    *out = input;
    return true;
  }
  if constexpr (std::is_arithmetic_v<std::decay_t<T>>) {
    try {
      auto tmp_d = std::stod(input);
      if (tmp_d < 0 && std::is_unsigned_v<std::decay_t<T>>) {
        return false;
      }
      if (tmp_d > static_cast<double>(std::numeric_limits<T>::max()) ||
          tmp_d < static_cast<double>(std::numeric_limits<T>::min())) {
        return false;
      }
      *out = static_cast<T>(tmp_d);
      return true;
    } catch (...) {
      return false;
    }
  }

  return false;
}

template <typename T> std::vector<T> VectorDedup(const std::vector<T> &input) {
  std::vector<T> output;
  output.reserve(input.size());
  for (const auto &item : input) {
    if (std::find(output.begin(), output.end(), item) == output.end()) {
      output.push_back(item);
    }
  }
  return output;
}

/**
 * @brief Parse a hex color string (#RRGGBB) into an ANSI escape sequence.
 */
inline std::optional<std::string> HexToAnsi(const std::string &value) {
  std::string token = AMStr::Strip(value);
  if (token.empty()) {
    return std::nullopt;
  }
  if (token.rfind("#", 0) == 0) {
    token.erase(0, 1);
  }
  if (token.size() != 6) {
    return std::nullopt;
  }
  auto hex_to_int = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
      return 10 + (c - 'A');
    return -1;
  };
  std::array<int, 6> vals;
  for (size_t i = 0; i < 6; ++i) {
    vals[i] = hex_to_int(token[i]);
    if (vals[i] < 0) {
      return std::nullopt;
    }
  }
  int r = vals[0] * 16 + vals[1];
  int g = vals[2] * 16 + vals[3];
  int b = vals[4] * 16 + vals[5];
  return AMStr::amfmt("\x1b[38;2;{};{};{}m", r, g, b);
}
