#pragma once
#include <algorithm>
#include <boost/locale/encoding.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <magic_enum/magic_enum.hpp>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#ifndef AM_ENUM_NAME
#define AM_ENUM_NAME(x) std::string(magic_enum::enum_name(x))
#endif

namespace AMStr {
uint32_t NextCodepointUtf8(const std::string &utf8_str, size_t &idx);
size_t CodepointDisplayWidth(uint32_t cp);
size_t DisplayWidthUtf8(const std::string &utf8_str);

void amfmt_append(std::string &out, const std::string &value);
void amfmt_append(std::string &out, const char *value);
void amfmt_append(std::string &out, char *value);

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

template <typename T> inline std::string amfmt_to_string(T &&value) {
  static_assert(amfmt_allowed_v<T>,
                "amfmt only accepts string, char*, or integral types");
  std::string out;
  amfmt_append(out, std::forward<T>(value));
  return out;
}

bool amfmt_parse_padding_spec(const std::string &spec, char *align_out,
                              size_t *width_out);
std::string amfmt_apply_padding(const std::string &value, char align,
                                size_t width);
bool amfmt_parse_spec_token(const std::string &token, char *align_out,
                            size_t *width_out);
size_t amfmt_count_placeholders(const std::string &templ);

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

void vlowercase(std::string &str);
void vuppercase(std::string &str);
std::string lowercase(const std::string &str);
std::string uppercase(const std::string &str);
std::wstring wstr(const std::string &str);
std::string wstr(const std::wstring &wstr);
std::string wstr(wchar_t *wstr);
std::wstring wstr(char *str);
size_t CharNum(const std::string &utf8_str);

std::string RepeatUtf8(const std::string &token, size_t count);
std::string PadRightUtf8(const std::string &text, size_t width);
std::string AnsiColor24(const std::string &hex_color);

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

std::pair<bool, int> endswith(const std::string &str,
                              const std::string &suffix);
std::string ModeTrans(size_t mode_int);
size_t ModeTrans(std::string mode_str);
std::string MergeModeStr(const std::string &base_mode_str,
                         const std::string &new_mode_str);
bool IsModeValid(std::string mode_str);
bool IsModeValid(size_t mode_int);
std::string BBCEscape(const std::string &text);
bool IsWhitespace(char c);
void VStrip(std::string &path);
std::string Strip(const std::string &path);
void vreplace(std::string &str, const std::string &from, const std::string &to);
std::string replace(std::string str, const std::string &from,
                    const std::string &to);
void vreplace_all(std::string &str, const std::string &old_sub,
                  const std::string &new_sub);
std::string replace_all(std::string str, const std::string &old_sub,
                        const std::string &new_sub);
std::string join(const std::vector<std::string> &parts, const std::string &sep);
std::string PadLeftAscii(std::string_view value, size_t width);
size_t CountLines(const std::string &text);
} // namespace AMStr

void print(const std::string &str);

template <typename... Args> inline void print(Args &&...args) {
  if constexpr (sizeof...(Args) >= 2) {
    std::cout << AMStr::amfmt(std::forward<Args>(args)...) << "\n";
  } else {
    (std::cout << ... << std::forward<Args>(args)) << "\n";
  }
}

std::string FormatSize(size_t size);
std::string FormatSize(int64_t size);
bool GetEnv(std::string_view key, std::string *target);
std::optional<std::string> HexToAnsi(const std::string &value);

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
