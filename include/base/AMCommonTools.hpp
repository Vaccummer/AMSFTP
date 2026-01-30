#pragma once
#include <chrono>
#define _WINSOCKAPI_
#include "base/cfgffi.h"
#include <algorithm>
#include <array>
#include <boost/locale/encoding.hpp>
#include <cctype>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <indicators/progress_bar.hpp> // win 平台上该库会包含 windows.h
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

/*
class ProgressBar {
public:
  explicit ProgressBar(uint64_t total_size = 0, std::string unit = "B",
                       size_t bar_width = 50, bool show_eta = true,
                       bool colored = true)
      : total_(total_size), unit_(std::move(unit)), bar_width_(bar_width),
        show_eta_(show_eta), colored_(colored),
        start_time_(std::chrono::steady_clock::now()) {}

  // ✅ 新增：动态设置总大小（可选是否重置计时器）
  void set_total(uint64_t new_total, bool reset_timer = false) {
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
  void update(uint64_t current) {
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
      auto [speed_str, speed_unit] = format_size(static_cast<uint64_t>(speed));
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

  std::pair<std::string, std::string> format_size(uint64_t size) const {
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
  uint64_t total_ = 0;
  uint64_t current_ = 0;
  std::string unit_;
  size_t bar_width_;
  bool show_eta_;
  bool colored_;
  std::chrono::steady_clock::time_point start_time_;

  ProgressBar(const ProgressBar &) = delete;
  ProgressBar &operator=(const ProgressBar &) = delete;
};

class AMProgressBar : public indicators::ProgressBar {
public:
  AMProgressBar(uint64_t total_size = 0, std::string prefix = "",
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
  void setTotoalSize(uint64_t total_size) {
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
  void updateProgress(uint64_t current) {
    this->set_progress(current);
    this->print_progress();
  }
};
*/
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

inline std::string ModeTrans(uint64_t mode_int) {
  // 把mode_int转换为8进制字符串, 长度为9
  if (mode_int > 0777 || mode_int == 0777) {
    return "rwxrwxrwx";
  }
  std::string out = "";
  uint64_t tmp_int;
  uint64_t start = 8 * 8 * 8;
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

inline uint64_t ModeTrans(std::string mode_str) {
  std::regex pattern(
      R"(^[r?\-][w?\-][x?\-][r?\-][w?\-][x?\-][r?\-][w?\-][x?\-]$)");
  if (!std::regex_match(mode_str, pattern)) {
    throw std::invalid_argument(amfmt("Invalid mode string: ", mode_str));
  }
  uint64_t mode_int = 0;
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

inline bool IsModeValid(uint64_t mode_int) { return mode_int <= 0777; }

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

class AMProgressBarGroup;

/**
 * @brief Thread-safe ANSI progress bar designed for atomic group refresh.
 *
 * This progress bar does not print by itself. It delegates rendering to
 * AMProgressBarGroup which coordinates multiple bars and performs atomic
 * redraws to avoid tearing.
 */
class AMProgressBar {
public:
  /**
   * @brief Construct a progress bar with total size and optional prefix.
   * @param total_size Total number of bytes for completion.
   * @param prefix Display prefix (left-aligned).
   */
  explicit AMProgressBar(int64_t total_size = 0, std::string prefix = "")
      : total_size_(std::max<int64_t>(0, total_size)),
        prefix_(std::move(prefix)),
        start_time_(std::chrono::steady_clock::now()),
        last_update_time_(start_time_) {}

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
    }
    RequestRefreshLocked_();
  }

  /**
   * @brief Set the display prefix.
   * @param prefix Prefix text (left-aligned).
   */
  void SetPrefix(std::string prefix) {
    std::lock_guard<std::mutex> lock(mtx_);
    prefix_ = std::move(prefix);
    RequestRefreshLocked_();
  }

  /**
   * @brief Advance progress by a delta in bytes.
   * @param delta Bytes to add (negative values are ignored).
   */
  void Advance(int64_t delta) {
    if (delta <= 0) {
      return;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = std::min(total_size_, current_size_ + delta);
    UpdateSpeedLocked_();
    RequestRefreshLocked_();
  }

  /**
   * @brief Set the current progress in bytes.
   * @param current_size Accumulated size in bytes.
   */
  void SetProgress(int64_t current_size) {
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = std::clamp<int64_t>(current_size, 0, total_size_);
    UpdateSpeedLocked_();
    RequestRefreshLocked_();
  }

  /**
   * @brief Mark the bar as completed and clamp to total size.
   */
  void Finish() {
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = total_size_;
    UpdateSpeedLocked_();
    finished_ = true;
    RequestRefreshLocked_();
  }

  /**
   * @brief Return whether the bar has finished.
   * @return True if finished.
   */
  bool IsFinished() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return finished_;
  }

private:
  friend class AMProgressBarGroup;

  /**
   * @brief Format the bar into a single display line.
   * @param prefix_width Width of the prefix field.
   * @param percent_width Width of percentage field.
   * @param size_width Width of size fields.
   * @param time_width Width of time fields.
   * @param speed_width Width of speed field.
   * @param now Current time point for consistent group rendering.
   * @return Fully formatted line.
   */
  std::string RenderLine(size_t prefix_width, size_t percent_width,
                         size_t size_width, size_t time_width,
                         size_t speed_width,
                         std::chrono::steady_clock::time_point now) const {
    std::lock_guard<std::mutex> lock(mtx_);

    const double percent = (total_size_ <= 0)
                               ? 0.0
                               : (static_cast<double>(current_size_) /
                                  static_cast<double>(total_size_)) *
                                     100.0;

    const auto elapsed =
        std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
    const int64_t elapsed_sec = std::max<int64_t>(0, elapsed.count());

    const double speed_bps =
        (elapsed_sec > 0) ? static_cast<double>(current_size_) / elapsed_sec
                          : 0.0;

    const int64_t remaining_bytes =
        (total_size_ > current_size_) ? (total_size_ - current_size_) : 0;
    const int64_t remain_sec =
        (speed_bps > 0.0) ? static_cast<int64_t>(remaining_bytes / speed_bps)
                          : 0;

    std::string prefix_field = PadRight_(prefix_, prefix_width);
    std::string percent_field =
        PadLeft_(FormatPercent_(percent), percent_width);

    std::string current_field =
        PadLeft_(FormatSize_(current_size_, 4), size_width);
    std::string total_field = PadLeft_(FormatSize_(total_size_, 4), size_width);

    std::string elapsed_field =
        PadLeft_(FormatTimeMMSS_(elapsed_sec), time_width);
    std::string remain_field =
        PadLeft_(FormatTimeMMSS_(remain_sec), time_width);

    std::string speed_field =
        PadLeft_(FormatSpeed_(speed_bps, speed_width), speed_width);

    return AMStr::amfmt("{}    {} | {}/{} [{}<{} {}]", prefix_field,
                        percent_field, current_field, total_field,
                        elapsed_field, remain_field, speed_field);
  }

  /**
   * @brief Bind this bar to a group for refresh coordination.
   * @param group Owning group pointer.
   */
  void BindGroup_(AMProgressBarGroup *group) {
    std::lock_guard<std::mutex> lock(mtx_);
    group_ = group;
  }

  /**
   * @brief Clear group binding when removed from a group.
   */
  void UnbindGroup_() {
    std::lock_guard<std::mutex> lock(mtx_);
    group_ = nullptr;
  }

  /**
   * @brief Request a group refresh while holding the lock.
   */
  void RequestRefreshLocked_() const;

  /**
   * @brief Update speed sampling information while holding the lock.
   */
  void UpdateSpeedLocked_() {
    last_update_time_ = std::chrono::steady_clock::now();
    last_update_size_ = current_size_;
  }

  /**
   * @brief Right pad a string to a given width.
   * @param value Input string.
   * @param width Target width.
   * @return Padded string.
   */
  static std::string PadRight_(std::string_view value, size_t width) {
    if (value.size() >= width) {
      return std::string(value.substr(0, width));
    }
    std::string out(value);
    out.append(width - value.size(), ' ');
    return out;
  }

  /**
   * @brief Left pad a string to a given width.
   * @param value Input string.
   * @param width Target width.
   * @return Padded string.
   */
  static std::string PadLeft_(std::string_view value, size_t width) {
    if (value.size() >= width) {
      return std::string(value.substr(value.size() - width));
    }
    std::string out(width - value.size(), ' ');
    out.append(value.begin(), value.end());
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
   * @brief Format a byte size with significant digits and IEC units.
   * @param bytes Size in bytes.
   * @param sig_digits Number of significant digits.
   * @return Human-readable size string.
   */
  static std::string FormatSize_(int64_t bytes, int sig_digits) {
    static constexpr const char *kUnits[] = {"B", "KB", "MB", "GB", "TB"};
    const double sign = (bytes < 0) ? -1.0 : 1.0;
    double value = static_cast<double>(std::llabs(bytes));
    size_t unit_index = 0;
    while (value >= 1000.0 && unit_index < std::size(kUnits) - 1) {
      value /= 1024.0;
      unit_index++;
    }

    if (value == 0.0) {
      return "0 B";
    }

    (void)sig_digits;
    int decimals = 0;
    if (value < 10.0) {
      decimals = 2;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(decimals) << (sign * value) << " "
        << kUnits[unit_index];
    return oss.str();
  }

  /**
   * @brief Format time as mm:ss.
   * @param seconds Seconds to format.
   * @return Time string in mm:ss.
   */
  static std::string FormatTimeMMSS_(int64_t seconds) {
    const int64_t clamped = std::max<int64_t>(0, seconds);
    const int64_t mm = clamped / 60;
    const int64_t ss = clamped % 60;
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << mm << ":" << std::setw(2)
        << std::setfill('0') << ss;
    return oss.str();
  }

  /**
   * @brief Format speed using the size formatter with 1 decimal place.
   * @param bytes_per_sec Speed in bytes per second.
   * @param width Target width for compacting if necessary.
   * @return Human-readable speed string.
   */
  static std::string FormatSpeed_(double bytes_per_sec, size_t width) {
    const int64_t rounded = static_cast<int64_t>(std::max(0.0, bytes_per_sec));
    std::string base = FormatSize_(rounded, 4);
    auto pos = base.find(' ');
    if (pos != std::string::npos) {
      std::string number = base.substr(0, pos);
      std::string unit = base.substr(pos + 1);
      std::ostringstream oss;
      oss << std::fixed << std::setprecision(1) << std::stod(number) << " "
          << unit << "/s";
      base = oss.str();
    } else {
      base += "/s";
    }
    if (base.size() > width && width > 0) {
      return base.substr(base.size() - width);
    }
    return base;
  }

private:
  mutable std::mutex mtx_;
  int64_t total_size_ = 0;
  int64_t current_size_ = 0;
  std::string prefix_;
  bool finished_ = false;
  std::chrono::steady_clock::time_point start_time_;
  std::chrono::steady_clock::time_point last_update_time_;
  int64_t last_update_size_ = 0;
  AMProgressBarGroup *group_ = nullptr;
};

/**
 * @brief Thread-safe group renderer for multiple progress bars.
 *
 * The group owns a terminal region and redraws all bars atomically using
 * ANSI escape sequences to prevent tearing and overlapping output.
 */
class AMProgressBarGroup {
public:
  /**
   * @brief Construct a group with configurable field widths.
   * @param prefix_width Width of prefix field (left-aligned).
   * @param percent_width Width of percentage field.
   * @param size_width Width of accumulated/total size fields.
   * @param time_width Width of elapsed/remain time fields.
   * @param speed_width Width of speed field.
   * @param refresh_interval_ms Background refresh interval in milliseconds.
   */
  explicit AMProgressBarGroup(size_t prefix_width = 16,
                              size_t percent_width = 7, size_t size_width = 12,
                              size_t time_width = 5, size_t speed_width = 12,
                              int refresh_interval_ms = 100)
      : prefix_width_(prefix_width), percent_width_(percent_width),
        size_width_(size_width), time_width_(time_width),
        speed_width_(speed_width),
        refresh_interval_ms_(std::max(16, refresh_interval_ms)) {}

  /**
   * @brief Destroy the group and stop background refresh.
   */
  ~AMProgressBarGroup() { Stop(); }

  /**
   * @brief Start background refresh thread if not already running.
   */
  void Start() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (running_) {
      return;
    }
    running_ = true;
    worker_ = std::thread([this]() { Run_(); });
  }

  /**
   * @brief Stop background refresh thread and finalize display.
   */
  void Stop() {
    {
      std::lock_guard<std::mutex> lock(mtx_);
      if (!running_) {
        return;
      }
      running_ = false;
      dirty_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
      worker_.join();
    }
    Refresh(true);
  }

  /**
   * @brief Add a progress bar to the group.
   * @param bar Shared progress bar instance.
   */
  void AddBar(const std::shared_ptr<AMProgressBar> &bar) {
    if (!bar) {
      return;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    bars_.push_back(bar);
    bar->BindGroup_(this);
    dirty_ = true;
    cv_.notify_all();
  }

  /**
   * @brief Remove a progress bar from the group.
   * @param bar Shared progress bar instance.
   */
  void RemoveBar(const std::shared_ptr<AMProgressBar> &bar) {
    if (!bar) {
      return;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    bars_.erase(std::remove_if(bars_.begin(), bars_.end(),
                               [&](const std::weak_ptr<AMProgressBar> &w) {
                                 auto sp = w.lock();
                                 return !sp || sp == bar;
                               }),
                bars_.end());
    bar->UnbindGroup_();
    dirty_ = true;
    cv_.notify_all();
  }

  /**
   * @brief Trigger a refresh request from a bar update.
   */
  void RequestRefresh() {
    {
      std::lock_guard<std::mutex> lock(mtx_);
      dirty_ = true;
    }
    cv_.notify_all();
  }

  /**
   * @brief Perform an immediate atomic refresh.
   * @param force Whether to refresh even if not marked dirty.
   */
  void Refresh(bool force = false) {
    std::vector<std::shared_ptr<AMProgressBar>> bars;
    size_t prefix_width = 0;
    {
      std::lock_guard<std::mutex> lock(mtx_);
      if (!force && !dirty_) {
        return;
      }
      dirty_ = false;
      prefix_width = prefix_width_;
      bars.reserve(bars_.size());
      for (auto it = bars_.begin(); it != bars_.end();) {
        if (auto sp = it->lock()) {
          bars.push_back(sp);
          ++it;
        } else {
          it = bars_.erase(it);
        }
      }
    }

    const auto now = std::chrono::steady_clock::now();
    const size_t term_width = GetTerminalWidth_();
    const size_t other_width = ComputeOtherFieldsWidth_();
    const size_t max_prefix_width =
        (term_width > other_width + 1) ? (term_width - other_width - 1) : 0;
    const size_t effective_prefix_width =
        std::min(prefix_width, max_prefix_width);
    std::vector<std::string> lines;
    lines.reserve(bars.size());
    for (const auto &bar : bars) {
      lines.push_back(bar->RenderLine(effective_prefix_width, percent_width_,
                                      size_width_, time_width_, speed_width_,
                                      now));
    }
    RenderLinesAtomic_(lines);
  }

  /**
   * @brief Configure the prefix field width.
   * @param width New width.
   */
  void SetPrefixWidth(size_t width) {
    std::lock_guard<std::mutex> lock(mtx_);
    prefix_width_ = width;
    dirty_ = true;
    cv_.notify_all();
  }

  /**
   * @brief Configure the percentage field width.
   * @param width New width.
   */
  void SetPercentWidth(size_t width) {
    std::lock_guard<std::mutex> lock(mtx_);
    percent_width_ = width;
    dirty_ = true;
    cv_.notify_all();
  }

  /**
   * @brief Configure the size field width.
   * @param width New width.
   */
  void SetSizeWidth(size_t width) {
    std::lock_guard<std::mutex> lock(mtx_);
    size_width_ = width;
    dirty_ = true;
    cv_.notify_all();
  }

  /**
   * @brief Configure the time field width.
   * @param width New width.
   */
  void SetTimeWidth(size_t width) {
    std::lock_guard<std::mutex> lock(mtx_);
    time_width_ = width;
    dirty_ = true;
    cv_.notify_all();
  }

  /**
   * @brief Configure the speed field width.
   * @param width New width.
   */
  void SetSpeedWidth(size_t width) {
    std::lock_guard<std::mutex> lock(mtx_);
    speed_width_ = width;
    dirty_ = true;
    cv_.notify_all();
  }

private:
  /**
   * @brief Compute the total width of all non-prefix fields and separators.
   * @return Width in characters.
   */
  size_t ComputeOtherFieldsWidth_() const {
    // Format: "{prefix}    {percentage} | {acc}/{total}     [ {elapse}<{remain}
    // {speed} ]"
    const size_t separators_width =
        4 + 3 + 1 + 5 + 3 + 1 + 2 + 2; // spaces and symbols between fields
    return percent_width_ + (2 * size_width_) + (2 * time_width_) +
           speed_width_ + separators_width;
  }

  /**
   * @brief Get terminal width in characters, with a safe fallback.
   * @return Terminal width, defaulting to 120 when unknown.
   */
  static size_t GetTerminalWidth_() {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(h, &csbi)) {
      const int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
      if (width > 0) {
        return static_cast<size_t>(width);
      }
    }
#else
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0) {
      return static_cast<size_t>(w.ws_col);
    }
#endif
    return 120;
  }

  /**
   * @brief Background refresh loop.
   */
  void Run_() {
    std::unique_lock<std::mutex> lock(mtx_);
    while (running_) {
      cv_.wait_for(lock, std::chrono::milliseconds(refresh_interval_ms_),
                   [&]() { return !running_ || dirty_; });
      if (!running_) {
        break;
      }
      lock.unlock();
      Refresh(true);
      lock.lock();
    }
  }

  /**
   * @brief Render all lines using ANSI escape sequences atomically.
   * @param lines Lines to render.
   */
  void RenderLinesAtomic_(const std::vector<std::string> &lines) {
    std::lock_guard<std::mutex> out_lock(out_mtx_);

    if (last_rendered_lines_ > 0) {
      std::cout << "\x1b[" << last_rendered_lines_ << "F";
    }

    for (size_t i = 0; i < lines.size(); ++i) {
      std::cout << "\x1b[2K\r" << lines[i];
      if (i + 1 < lines.size()) {
        std::cout << "\n";
      }
    }

    if (lines.empty()) {
      std::cout << "\x1b[2K\r";
    }

    std::cout << std::flush;
    last_rendered_lines_ = lines.size();
  }

private:
  mutable std::mutex mtx_;
  std::condition_variable cv_;
  std::vector<std::weak_ptr<AMProgressBar>> bars_;
  bool running_ = false;
  bool dirty_ = true;
  std::thread worker_;
  size_t prefix_width_;
  size_t percent_width_;
  size_t size_width_;
  size_t time_width_;
  size_t speed_width_;
  int refresh_interval_ms_;
  std::mutex out_mtx_;
  size_t last_rendered_lines_ = 0;
};

/**
 * @brief Request a refresh from the owning group.
 */
inline void AMProgressBar::RequestRefreshLocked_() const {
  if (group_ != nullptr) {
    group_->RequestRefresh();
  }
}

inline void print(const std::string &str) { std::cout << str << "\n"; }

template <typename... Args>
inline void print(Args &&...args) {
  if constexpr (sizeof...(Args) >= 2) {
    std::cout << AMStr::amfmt(std::forward<Args>(args)...) << "\n";
  } else {
    (std::cout << ... << std::forward<Args>(args)) << "\n";
  }
}
using Json = nlohmann::ordered_json;

class AMConfigProcessor {
public:
  using Path = std::vector<std::string>;
  using Match =
      std::variant<std::string, std::regex, std::unordered_set<std::string>>;
  using FormatPath = std::vector<Match>;
  using Value =
      std::variant<int64_t, bool, std::string, std::vector<std::string>>;

  struct PathLess {
    bool operator()(const Path &a, const Path &b) const {
      return std::lexicographical_compare(a.begin(), a.end(), b.begin(),
                                          b.end());
    }
  };

  using FlatMap = std::map<Path, Value, PathLess>;

  static void FilterKeys(FlatMap &data, const std::vector<Path> &formats) {
    std::vector<FormatPath> converted;
    converted.reserve(formats.size());
    for (const auto &fmt : formats) {
      FormatPath fmt_path;
      fmt_path.reserve(fmt.size());
      for (const auto &seg : fmt) {
        fmt_path.emplace_back(seg);
      }
      converted.push_back(std::move(fmt_path));
    }
    FilterKeys(data, converted);
  }

  static void FilterKeys(FlatMap &data,
                         const std::vector<FormatPath> &formats) {
    if (formats.empty())
      return;

    for (auto it = data.begin(); it != data.end();) {
      if (!MatchesAnyFormat(it->first, formats)) {
        it = data.erase(it);
        continue;
      }
      ++it;
    }
  }

  static const Value *Query(const FlatMap &data, const Path &key) {
    auto it = data.find(key);
    if (it == data.end())
      return nullptr;
    return &it->second;
  }

  static const Value *Query(FlatMap &data, const Path &key,
                            Value default_value) {
    auto it = data.find(key);
    if (it == data.end()) {
      auto inserted = data.emplace(key, std::move(default_value));
      return &inserted.first->second;
    }
    return &it->second;
  }

  static bool Modify(FlatMap &data, const Path &key, const Value &value) {
    auto it = data.find(key);
    if (it == data.end())
      return false;
    it->second = value;
    return true;
  }

private:
  static bool MatchesAnyFormat(const Path &key,
                               const std::vector<FormatPath> &formats) {
    for (const auto &fmt : formats) {
      if (key.size() != fmt.size())
        continue;
      if (PathMatchesFormat(key, fmt))
        return true;
    }
    return false;
  }

  static bool PathMatchesFormat(const Path &key, const FormatPath &fmt) {
    for (size_t i = 0; i < key.size(); ++i) {
      if (!SegmentMatchesFormat(key[i], fmt[i]))
        return false;
    }
    return true;
  }

  static bool SegmentMatchesFormat(const std::string &segment,
                                   const Match &format) {
    if (std::holds_alternative<std::string>(format)) {
      const std::string &fmt = std::get<std::string>(format);
      if (fmt == "*")
        return true;
      if (fmt.size() >= 2 && fmt.front() == '^' && fmt.back() == '$') {
        try {
          std::regex re(fmt);
          return std::regex_match(segment, re);
        } catch (const std::regex_error &e) {
          (void)e;
          return false;
        }
      }
      return segment == fmt;
    }
    if (std::holds_alternative<std::regex>(format)) {
      return std::regex_match(segment, std::get<std::regex>(format));
    }
    const auto &set = std::get<std::unordered_set<std::string>>(format);
    return set.find(segment) != set.end();
  }
};
