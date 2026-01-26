#pragma once
#include <chrono>
#define _WINSOCKAPI_
#include <algorithm>
#include <boost/locale/encoding.hpp>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <indicators/progress_bar.hpp> // win 平台上该库会包含 windows.h
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <variant>
#include <vector>
#include <toml++/toml.h>

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

inline void print(const std::string &str) { std::cout << str << std::endl; }

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
    if (c >= 'a' && c <= 'z') {
      c -= 32;
    }
  }
}

inline void vuppercase(std::string &str) {
  for (char &c : str) {
    if (c >= 'a' && c <= 'z') {
      c += 32;
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

  static FlatMap ParseFile(const std::string &path) {
    FlatMap out;
    try {
      if (path.empty()) {
        throw std::runtime_error("empty toml path");
      }
      toml::table root = toml::parse_file(path);
      Path base;
      FlattenNode(root, base, out);
      return out;
    } catch (const toml::parse_error &e) {
      throw std::runtime_error(
          AMStr::amfmt("Failed to parse toml \"{}\": {}", path, e.what()));
    } catch (const std::exception &e) {
      throw std::runtime_error(
          AMStr::amfmt("Failed to parse toml \"{}\": {}", path, e.what()));
    } catch (...) {
      throw std::runtime_error(
          AMStr::amfmt("Failed to parse toml \"{}\": unknown error", path));
    }
  }

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

  static bool DumpToFile(const FlatMap &data, const std::string &path,
                         std::string *error = nullptr) {
    toml::table root = ToToml(data, error);
    if (error && !error->empty())
      return false;
    return WriteTomlToFile(root, path, error);
  }

  static toml::table ToToml(const FlatMap &data,
                            std::string *error = nullptr) {
    toml::table root;
    for (const auto &item : data) {
      if (!SetNodeValue(root, item.first, item.second, error))
        return toml::table{};
    }
    return root;
  }

  static bool WriteTomlToFile(const toml::table &node,
                              const std::string &path,
                              std::string *error = nullptr) {
    std::ofstream out(path);
    if (!out.is_open()) {
      if (error)
        *error = "failed to open output file";
      return false;
    }
    out << node;
    if (!out.good()) {
      if (error)
        *error = "failed to write toml";
      return false;
    }
    return static_cast<bool>(out);
  }

private:
  static bool SetNodeValue(toml::table &root, const Path &path,
                           const Value &value, std::string *error) {
    if (path.empty()) {
      if (error)
        *error = "empty path not allowed";
      return false;
    }

    toml::table *current = &root;

    std::string cur_path; // 用 -> 连接

    auto append_path = [&](const std::string &seg) {
      if (!cur_path.empty())
        cur_path += "->";
      cur_path += seg;
    };

    auto set_err = [&](const std::string &msg) {
      if (!error)
        return;
      if (!cur_path.empty())
        *error = msg + " at path: " + cur_path;
      else
        *error = msg;
    };

    for (size_t i = 0; i < path.size(); ++i) {
      const std::string &seg = path[i];
      const bool is_leaf = (i + 1 == path.size());

      if (is_leaf) {
        // ---- 叶子写入前：检查是否会覆盖已有深结构（table/array）----
        toml::node *existing = current->get(seg);

        // 拼出完整路径（包含 leaf）
        append_path(seg);

        if (existing && (existing->is_table() || existing->is_array())) {
          set_err("leaf assignment conflicts with existing structured node");
          return false;
        }

        // ---- 正常写 leaf ----
        if (std::holds_alternative<int64_t>(value)) {
          current->insert_or_assign(seg, std::get<int64_t>(value));
          return true;
        }
        if (std::holds_alternative<bool>(value)) {
          current->insert_or_assign(seg, std::get<bool>(value));
          return true;
        }
        if (std::holds_alternative<std::string>(value)) {
          current->insert_or_assign(seg, std::get<std::string>(value));
          return true;
        }
        if (std::holds_alternative<std::vector<std::string>>(value)) {
          toml::array seq;
          for (const auto &item : std::get<std::vector<std::string>>(value))
            seq.push_back(item);
          current->insert_or_assign(seg, std::move(seq));
          return true;
        }

        set_err("unsupported value type");
        return false;
      }

      // ---- 非叶子：要下钻到 seg ----
      append_path(seg);

      toml::node *existing = current->get(seg);
      if (existing) {
        // key 存在：必须是 map 才能继续下钻
        if (!existing->is_table()) {
          set_err("path conflict: cannot descend into non-table node");
          return false;
        }
        current = existing->as_table();
        continue;
      }

      // key 不存在：创建一个 map，再下钻
      auto inserted = current->insert(seg, toml::table{});
      toml::node &node = inserted.first->second;
      toml::table *next = node.as_table();
      if (!next) {
        set_err("failed to create table node");
        return false;
      }
      current = next;
    }

    // 理论不可达
    set_err("unexpected traversal end");
    return false;
  }
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

  static bool IsInteger(const std::string &s) {
    if (s.empty())
      return false;
    size_t i = 0;
    if (s[0] == '-' || s[0] == '+')
      i = 1;
    if (i == s.size())
      return false;
    for (; i < s.size(); ++i) {
      if (!std::isdigit(static_cast<unsigned char>(s[i])))
        return false;
    }
    return true;
  }

  static Value ParseScalar(const toml::node &node) {
    if (auto v = node.value<int64_t>())
      return *v;
    if (auto v = node.value<bool>())
      return *v;
    if (auto v = node.value<std::string>())
      return *v;
    if (auto v = node.value<double>()) {
      std::ostringstream oss;
      oss << *v;
      return oss.str();
    }
    if (auto v = node.as_date()) {
      std::ostringstream oss;
      oss << *v;
      return oss.str();
    }
    if (auto v = node.as_time()) {
      std::ostringstream oss;
      oss << *v;
      return oss.str();
    }
    if (auto v = node.as_date_time()) {
      std::ostringstream oss;
      oss << *v;
      return oss.str();
    }
    return std::string{};
  }

  static std::string ScalarToString(const toml::node &node) {
    if (auto v = node.value<std::string>())
      return *v;
    if (auto v = node.value<int64_t>())
      return std::to_string(*v);
    if (auto v = node.value<bool>())
      return *v ? "true" : "false";
    if (auto v = node.value<double>()) {
      std::ostringstream oss;
      oss << *v;
      return oss.str();
    }
    if (auto v = node.as_date()) {
      std::ostringstream oss;
      oss << *v;
      return oss.str();
    }
    if (auto v = node.as_time()) {
      std::ostringstream oss;
      oss << *v;
      return oss.str();
    }
    if (auto v = node.as_date_time()) {
      std::ostringstream oss;
      oss << *v;
      return oss.str();
    }
    return {};
  }

  static void FlattenNode(const toml::node &node, Path &path, FlatMap &out) {
    if (node.is_table()) {
      const toml::table &tbl = *node.as_table();
      for (const auto &item : tbl) {
        std::string key = std::string(item.first.str());
        path.push_back(key);
        FlattenNode(item.second, path, out);
        path.pop_back();
      }
      return;
    }

    if (node.is_array()) {
      const toml::array &arr = *node.as_array();
      bool all_scalar = true;
      std::vector<std::string> items;
      items.reserve(arr.size());
      for (const auto &child : arr) {
        if (!child.is_value()) {
          all_scalar = false;
          break;
        }
        items.push_back(ScalarToString(child));
      }
      if (all_scalar) {
        out[path] = std::move(items);
        return;
      }
      for (std::size_t i = 0; i < arr.size(); ++i) {
        path.push_back(std::to_string(i));
        FlattenNode(arr[i], path, out);
        path.pop_back();
      }
      return;
    }

    if (node.is_value()) {
      out[path] = ParseScalar(node);
      return;
    }
  }
};
