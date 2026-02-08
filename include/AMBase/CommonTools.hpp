#pragma once
#include <atomic>
#include <chrono>
#include <cstddef>
#include <indicators/color.hpp>
#include <indicators/setting.hpp>
#define _WINSOCKAPI_
#include "Isocline/isocline.h"
#include <algorithm>
#include <boost/locale/encoding.hpp>
#include <cctype>
#include <cstdlib>
#include <deque>
#include <indicators/cursor_control.hpp>
#include <indicators/cursor_movement.hpp>
#include <indicators/dynamic_progress.hpp>
#include <indicators/multi_progress.hpp>
#include <indicators/progress_bar.hpp> // win 平台上该库会包含 windows.h
#include <indicators/terminal_size.hpp>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
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

class ProgressBar {
public:
  explicit ProgressBar(size_t total_size = 0, std::string unit = "B",
                       size_t bar_width = 50, bool show_eta = true,
                       bool colored = true)
      : total_(total_size), unit_(std::move(unit)), bar_width_(bar_width),
        show_eta_(show_eta), colored_(colored),
        start_time_(std::chrono::steady_clock::now()) {}

  // ✅ 新增：动态设置总大小（可选是否重置计时器）
  void set_total(size_t new_total, bool reset_timer = false) {
    total_ = new_total;
    if (reset_timer) {
      start_time_ = std::chrono::steady_clock::now();
    }
    // 如果当前进度超过新 total，自动修正
    if (current_ > total_) {
      current_ = total_;
    }
    redraw();
  }

  // 更新当前进度
  void update(size_t current) {
    if (total_ == 0) {
      // 如果 total 未知，以 current 作为“已知最大值”估算
      if (current > current_) {
        total_ = current * 2; // 启发式：假设最终是当前的2倍
      }
    }
    if (current > total_)
      current = total_;
    current_ = current;
    redraw();
  }

  void finish() {
    if (total_ == 0)
      total_ = current_; // 防止除零
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

namespace AMStr {
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
struct amfmt_allowed
    : std::bool_constant<
          std::disjunction_v<std::is_arithmetic<std::decay_t<T>>,
                             std::is_same<std::decay_t<T>, std::string>,
                             std::is_same<std::decay_t<T>, const char *>,
                             std::is_same<std::decay_t<T>, char *>>> {};

template <typename T> inline std::string amfmt_to_string(T &&value) {
  static_assert(amfmt_allowed<T>::value,
                "amfmt only accepts string, char*, or integral types");
  std::string out;
  amfmt_append(out, std::forward<T>(value));
  return out;
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
  static_assert((amfmt_allowed<Args>::value && ...),
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
      for (; j < templ.size(); ++j) {
        if (templ[j] == '}') {
          if (arg_index >= values.size()) {
            throw std::runtime_error("amfmt: argument count mismatch");
          }
          out += values[arg_index++];
          i = j;
          break;
        }
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
  // 遍历字符串（C++98兼容的迭代器写法）
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
      // 尝试匹配2字节字符，无效则按单字节计数
      const uint8_t next = static_cast<uint8_t>(utf8_str[idx + 1]);
      if ((next & 0xC0) == 0x80) {
        ++char_count;
        idx += 2;
        continue;
      }
      ++char_count;
      ++idx;
    } else if ((current & 0xF0) == 0xE0 && idx + 2 < str_len) {
      // 尝试匹配3字节字符
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
      // 尝试匹配4字节字符
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
      // 无效字节，按单字符计数
      ++char_count;
      ++idx;
    }
  }

  return char_count;
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
  // 把mode_int转换为8进制字符串, 长度为9
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
 * @brief Return true when a character is treated as whitespace for parsing.
 */
inline bool IsWhitespace(char c) {
  return std::isspace(static_cast<unsigned char>(c)) != 0;
}

/**
 * @brief Trim leading and trailing whitespace only and return a copy.
 */
inline std::string TrimWhitespaceCopy(const std::string &input) {
  size_t start = 0;
  while (start < input.size() && IsWhitespace(input[start])) {
    ++start;
  }
  if (start >= input.size()) {
    return "";
  }
  size_t end = input.size();
  while (end > start && IsWhitespace(input[end - 1])) {
    --end;
  }
  return input.substr(start, end - start);
}

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

inline std::string Strip(std::string path) {
  const std::string trim_chars = " \t\n\r\"'";

  size_t start = path.find_first_not_of(trim_chars);

  if (start == std::string::npos || start > path.size() - 2) {
    return "";
  }

  size_t end = path.find_last_not_of(trim_chars);
  return path.substr(start, end - start + 1);
}

inline void VStrip(std::string &path) {
  const std::string trim_chars = " \t\n\r\"'";

  size_t start = path.find_first_not_of(trim_chars);
  if (start == std::string::npos) {
    path = "";
    return;
  }
  size_t end = path.find_last_not_of(trim_chars);
  path = path.substr(start, end - start + 1);
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
    // 跳过替换后的内容，避免重复替换（如old_sub是new_sub的子串）
    pos += new_sub.size();
    // 如果允许重复替换（比如把"a"换成"aa"），则pos不移动，保持pos不变
  }
}

inline std::string replace_all(std::string str, const std::string &old_sub,
                               const std::string &new_sub) {
  size_t pos = 0;
  while ((pos = str.find(old_sub, pos)) != std::string::npos) {
    str.replace(pos, old_sub.size(), new_sub);
    // 跳过替换后的内容，避免重复替换（如old_sub是new_sub的子串）
    pos += new_sub.size();
    // 如果允许重复替换（比如把"a"换成"aa"），则pos不移动，保持pos不变
  }
  return str;
}

} // namespace AMStr
// 导出amfmt函数

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

  /**
   * @brief Format percentage as a fixed-width string.
   * @param percent Percentage value in [0, 100].
   * @return Formatted percentage string with one decimal place.
   */
  static std::string FormatPercent_(double percent) {
    const double clamped = std::clamp(percent, 0.0, 100.0);
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << clamped << "%";
    return oss.str();
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
      oss << static_cast<int64_t>(size) << ' ' << suffixes[idx];
    } else {
      oss << std::fixed << std::setprecision(precision) << size << ' '
          << suffixes[idx];
    }
    return oss.str();
  }

  /**
   * @brief Format elapsed seconds into MM:SS.
   * @param seconds Elapsed seconds.
   * @return Formatted time string.
   */
  static std::string FormatTimeMMSS_(int64_t seconds) {
    const int64_t clamped = std::max<int64_t>(0, seconds);
    const int64_t minutes = clamped / 60;
    const int64_t secs = clamped % 60;
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << minutes << ":" << std::setw(2)
        << std::setfill('0') << secs;
    return oss.str();
  }

  /**
   * @brief Format speed in bytes per second.
   * @param bps Speed in bytes/sec.
   * @return Formatted speed string.
   */
  static std::string FormatSpeed_(double bps) {
    const std::string size = FormatSize_(static_cast<int64_t>(bps), 1);
    return size + "/s";
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

