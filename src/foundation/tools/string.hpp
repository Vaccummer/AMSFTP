#pragma once
#include <algorithm>
#include <boost/locale/encoding.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <magic_enum/magic_enum.hpp>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace AMStr {
uint32_t NextCodepointUtf8(const std::string &utf8_str, size_t &idx);
size_t CodepointDisplayWidth(uint32_t cp);
size_t DisplayWidthUtf8(const std::string &utf8_str);

namespace detail {
template <typename T> inline constexpr bool always_false_v = false;

bool fmt_parse_padding_spec(const std::string &spec, char *align_out,
                            size_t *width_out);
std::string fmt_apply_padding(const std::string &value, char align,
                              size_t width);
bool fmt_parse_spec_token(const std::string &token, char *align_out,
                          size_t *width_out);
size_t fmt_count_placeholders(const std::string &templ);
} // namespace detail

template <typename T>
std::string ToString(const T &value, bool full_enum_name = false) {
  using D = std::decay_t<T>;

  if constexpr (std::is_same_v<D, bool>) {
    return value ? "true" : "false";
  } else if constexpr (std::is_same_v<D, std::string>) {
    return value;
  } else if constexpr (std::is_same_v<D, std::string_view>) {
    return std::string(value);
  } else if constexpr (std::is_same_v<D, const char *> ||
                       std::is_same_v<D, char *>) {
    return value ? std::string(value) : std::string();
  } else if constexpr (std::is_convertible_v<const T &, std::string_view>) {
    return std::string(std::string_view(value));
  } else if constexpr (std::is_enum_v<D>) {
    const std::string enum_name = std::string(magic_enum::enum_name(value));
    if (!enum_name.empty()) {
      if (full_enum_name) {
        const std::string enum_type_name =
            std::string(magic_enum::enum_type_name<D>());
        if (!enum_type_name.empty()) {
          return enum_type_name + "::" + enum_name;
        }
      }
      return enum_name;
    }
    using U = std::underlying_type_t<D>;
    if constexpr (std::is_signed_v<U>) {
      return std::to_string(static_cast<long long>(static_cast<U>(value)));
    } else {
      return std::to_string(
          static_cast<unsigned long long>(static_cast<U>(value)));
    }
  } else if constexpr (std::is_integral_v<D>) {
    if constexpr (std::is_signed_v<D>) {
      return std::to_string(static_cast<long long>(value));
    } else {
      return std::to_string(static_cast<unsigned long long>(value));
    }
  } else if constexpr (std::is_floating_point_v<D>) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
  } else {
    static_assert(detail::always_false_v<D>,
                  "ToString only supports string-like, enum, bool, and "
                  "arithmetic types");
    return {};
  }
}

template <typename... Args>
std::string fmt(const std::string &templ, Args &&...args) {
  size_t placeholder_count = detail::fmt_count_placeholders(templ);
  constexpr size_t arg_count = sizeof...(Args);
  if (placeholder_count == 0) {
    std::string out = templ;
    ((out += AMStr::ToString(std::forward<Args>(args))), ...);
    return out;
  }
  if (placeholder_count != arg_count) {
    throw std::runtime_error("fmt: argument count mismatch");
  }
  std::vector<std::string> values;
  values.reserve(arg_count);
  (void)std::initializer_list<int>{
      (values.push_back(AMStr::ToString(std::forward<Args>(args))), 0)...};

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
            throw std::runtime_error("fmt: argument count mismatch");
          }
          std::string value = values[arg_index++];
          if (!token.empty()) {
            char align = 0;
            size_t width = 0;
            if (!detail::fmt_parse_spec_token(token, &align, &width)) {
              throw std::runtime_error("fmt: unsupported format specifier");
            }
            value = detail::fmt_apply_padding(value, align, width);
          }
          out += value;
          i = j;
          break;
        }
        token.push_back(templ[j]);
      }
      if (j >= templ.size()) {
        throw std::runtime_error("fmt: unmatched '{' in template");
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

template <typename... Args> std::string fmt(const char *templ, Args &&...args) {
  return fmt(std::string(templ ? templ : ""), std::forward<Args>(args)...);
}

void vlowercase(std::string &str);
void vuppercase(std::string &str);
std::string lowercase(const std::string &str);
std::string uppercase(const std::string &str);
bool Equals(std::string_view lhs, std::string_view rhs,
            bool case_sensitive = true);
std::wstring wstr(const std::string &str);
std::string wstr(const std::wstring &wstr);
std::string wstr(wchar_t *wstr);
std::wstring wstr(char *str);
size_t CharNum(const std::string &utf8_str);

std::string RepeatUtf8(const std::string &token, size_t count);
std::string PadRightUtf8(const std::string &text, size_t width);
std::string AnsiColor24(const std::string &hex_color);
std::string FormatUtf8Table(const std::vector<std::string> &keys,
                            const std::vector<std::vector<std::string>> &rows,
                            const std::string &skeleton_color = "",
                            size_t pad_left = 1, size_t pad_right = 1,
                            size_t pad_top = 0, size_t pad_bottom = 0);

std::pair<bool, int> endswith(const std::string &str,
                              const std::string &suffix);
bool StartsWith(std::string_view text, std::string_view prefix);
bool EndsWith(std::string_view text, std::string_view suffix);
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
std::string PadRightAscii(std::string_view value, size_t width);
std::string FormatSize(size_t size, int max_nums, int max_point,
                       size_t pad_width, bool pad_left);
std::string FormatSize(int64_t size, int max_nums, int max_point,
                       size_t pad_width, bool pad_left);
std::string FormatSpeed(double bytes_per_second, int max_nums, int max_point,
                        size_t pad_width, bool pad_left);
size_t CountLines(const std::string &text);
void print(const std::string &str);

template <typename... Args> inline void print(Args &&...args) {
  if constexpr (sizeof...(Args) >= 2) {
    std::cout << AMStr::fmt(std::forward<Args>(args)...) << "\n";
  } else {
    (std::cout << ... << std::forward<Args>(args)) << "\n";
  }
}

inline bool GetBool(const std::string &text, bool *out) {
  if (!out) {
    return false;
  }
  const std::string normalized = AMStr::lowercase(AMStr::Strip(text));
  if (normalized == "true" || normalized == "1" || normalized == "yes" ||
      normalized == "y" || normalized == "on") {
    *out = true;
    return true;
  }
  if (normalized == "false" || normalized == "0" || normalized == "no" ||
      normalized == "n" || normalized == "off") {
    *out = false;
    return true;
  }
  return false;
}

template <typename T>
// support signed and unsigned integer types and floating point types, but not
// bool.
inline bool GetNumber(const std::string &text, T *out) {
  static_assert(std::is_arithmetic_v<T> && !std::is_same_v<T, bool>,
                "GetNumber only supports non-bool arithmetic types");
  if (!out) {
    return false;
  }

  const std::string trimmed = AMStr::Strip(text);
  if (trimmed.empty()) {
    return false;
  }

  if constexpr (std::is_integral_v<T>) {
    if constexpr (std::is_unsigned_v<T>) {
      if (!trimmed.empty() && trimmed.front() == '-') {
        return false;
      }
      std::istringstream iss(trimmed);
      unsigned long long parsed = 0;
      char extra = '\0';
      if (!(iss >> parsed)) {
        return false;
      }
      if (iss >> extra) {
        return false;
      }
      if (parsed >
          static_cast<unsigned long long>(std::numeric_limits<T>::max())) {
        return false;
      }
      *out = static_cast<T>(parsed);
      return true;
    } else {
      std::istringstream iss(trimmed);
      long long parsed = 0;
      char extra = '\0';
      if (!(iss >> parsed)) {
        return false;
      }
      if (iss >> extra) {
        return false;
      }
      if (parsed < static_cast<long long>(std::numeric_limits<T>::min()) ||
          parsed > static_cast<long long>(std::numeric_limits<T>::max())) {
        return false;
      }
      *out = static_cast<T>(parsed);
      return true;
    }
  } else {
    std::istringstream iss(trimmed);
    long double parsed = 0;
    char extra = '\0';
    if (!(iss >> parsed)) {
      return false;
    }
    if (iss >> extra) {
      return false;
    }
    if (parsed < static_cast<long double>(std::numeric_limits<T>::lowest()) ||
        parsed > static_cast<long double>(std::numeric_limits<T>::max())) {
      return false;
    }
    *out = static_cast<T>(parsed);
    return true;
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

} // namespace AMStr
