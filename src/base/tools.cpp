#include "AMBase/DataClass.hpp"
#include "AMBase/tools/auth.hpp"
#include "AMBase/tools/json.hpp"
#include <array>
#include <ctime>
#include <iomanip>
#include <regex>
#include <sstream>

namespace {
int HexToInt_(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}
} // namespace

namespace AMStr {
uint32_t NextCodepointUtf8(const std::string &utf8_str, size_t &idx) {
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

size_t CodepointDisplayWidth(uint32_t cp) {
  if (cp == 0) {
    return 0;
  }
  if ((cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF) ||
      (cp >= 0x1DC0 && cp <= 0x1DFF) || (cp >= 0x20D0 && cp <= 0x20FF) ||
      (cp >= 0xFE20 && cp <= 0xFE2F)) {
    return 0;
  }
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

size_t DisplayWidthUtf8(const std::string &utf8_str) {
  size_t width = 0;
  size_t idx = 0;
  while (idx < utf8_str.size()) {
    const uint32_t cp = NextCodepointUtf8(utf8_str, idx);
    width += CodepointDisplayWidth(cp);
  }
  return width;
}

bool detail::fmt_parse_padding_spec(const std::string &spec, char *align_out,
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

std::string detail::fmt_apply_padding(const std::string &value, char align,
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

bool detail::fmt_parse_spec_token(const std::string &token, char *align_out,
                                  size_t *width_out) {
  if (!align_out || !width_out) {
    return false;
  }
  if (token.empty()) {
    return false;
  }
  if (token.front() == ':') {
    const std::string inner = token.substr(1);
    return fmt_parse_padding_spec(inner, align_out, width_out);
  }
  return fmt_parse_padding_spec(token, align_out, width_out);
}

size_t detail::fmt_count_placeholders(const std::string &templ) {
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
        throw std::runtime_error("fmt: unmatched '{' in template");
      }
    } else if (c == '}' && i + 1 < templ.size() && templ[i + 1] == '}') {
      ++i;
    }
  }
  return count;
}

void vlowercase(std::string &str) {
  for (char &c : str) {
    if (c >= 'A' && c <= 'Z') {
      c += 32;
    }
  }
}

void vuppercase(std::string &str) {
  for (char &c : str) {
    if (c >= 'a' && c <= 'z') {
      c -= 32;
    }
  }
}

std::string lowercase(const std::string &str) {
  std::string str_f = str;
  vlowercase(str_f);
  return str_f;
}

std::string uppercase(const std::string &str) {
  std::string str_f = str;
  vuppercase(str_f);
  return str_f;
}

std::wstring wstr(const std::string &str) {
  return boost::locale::conv::utf_to_utf<wchar_t>(str);
}

std::string wstr(const std::wstring &wstr) {
  return boost::locale::conv::utf_to_utf<char>(wstr);
}

std::string wstr(wchar_t *wstr) {
  return boost::locale::conv::utf_to_utf<char>(wstr);
}

std::wstring wstr(char *str) {
  return boost::locale::conv::utf_to_utf<wchar_t>(str);
}

size_t CharNum(const std::string &utf8_str) {
  const size_t str_len = utf8_str.size();
  size_t char_count = 0;
  size_t idx = 0;

  while (idx < str_len) {
    const uint8_t current = static_cast<uint8_t>(utf8_str[idx]);

    if ((current & 0x80) == 0) {
      ++char_count;
      ++idx;
    } else if ((current & 0xE0) == 0xC0 && idx + 1 < str_len) {
      const uint8_t next = static_cast<uint8_t>(utf8_str[idx + 1]);
      if ((next & 0xC0) == 0x80) {
        ++char_count;
        idx += 2;
        continue;
      }
      ++char_count;
      ++idx;
    } else if ((current & 0xF0) == 0xE0 && idx + 2 < str_len) {
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
      ++char_count;
      ++idx;
    }
  }

  return char_count;
}

std::string RepeatUtf8(const std::string &token, size_t count) {
  std::string out;
  out.reserve(token.size() * count);
  for (size_t i = 0; i < count; ++i) {
    out += token;
  }
  return out;
}

std::string PadRightUtf8(const std::string &text, size_t width) {
  const size_t len = DisplayWidthUtf8(text);
  if (len >= width) {
    return text;
  }
  return text + std::string(width - len, ' ');
}

std::string AnsiColor24(const std::string &hex_color) {
  if (hex_color.size() != 7 || hex_color[0] != '#') {
    return "";
  }
  auto hex_to_int = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
      return 10 + (c - 'A');
    }
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
  return AMStr::fmt("\x1b[38;2;{};{};{}m", r, g, b);
}

std::string FormatUtf8Table(const std::vector<std::string> &keys,
                            const std::vector<std::vector<std::string>> &rows,
                            const std::string &skeleton_color, size_t pad_left,
                            size_t pad_right, size_t pad_top,
                            size_t pad_bottom) {
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
                              const std::string &suffix) {
  if (suffix.empty()) {
    return std::make_pair(true, str.size());
  }
  if (str.size() < suffix.size()) {
    return std::make_pair(false, 0);
  }
  return std::make_pair(
      str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0,
      static_cast<int>(str.size() - suffix.size()));
}

std::string ModeTrans(size_t mode_int) {
  if (mode_int > 0777 || mode_int == 0777) {
    return "rwxrwxrwx";
  }
  std::string out;
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

size_t ModeTrans(std::string mode_str) {
  std::regex pattern(
      R"(^[r?\-][w?\-][x?\-][r?\-][w?\-][x?\-][r?\-][w?\-][x?\-]$)");
  if (!std::regex_match(mode_str, pattern)) {
    throw std::invalid_argument(fmt("Invalid mode string: ", mode_str));
  }
  size_t mode_int = 0;
  for (int i = 0; i < 9; i++) {
    if (mode_str[i] != '?' && mode_str[i] != '-') {
      mode_int += (1ULL << (8 - i));
    }
  }
  return mode_int;
}

std::string MergeModeStr(const std::string &base_mode_str,
                         const std::string &new_mode_str) {
  std::string pattern_f =
      "^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$";
  std::regex pattern(pattern_f);

  if (!std::regex_match(base_mode_str, pattern)) {
    throw std::invalid_argument(
        fmt("Invalid base mode string: ", base_mode_str));
  }
  if (!std::regex_match(new_mode_str, pattern)) {
    throw std::invalid_argument(fmt("Invalid new mode string: ", new_mode_str));
  }

  std::string mode_str;
  for (int i = 0; i < 9; i++) {
    mode_str += (new_mode_str[i] == '?' ? base_mode_str[i] : new_mode_str[i]);
  }
  return mode_str;
}

bool IsModeValid(std::string mode_str) {
  return std::regex_match(mode_str,
                          std::regex("^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?"
                                     "\\-][r?\\-][w?\\-][x?\\-]$"));
}

bool IsModeValid(size_t mode_int) { return mode_int <= 0777; }

std::string BBCEscape(const std::string &text) {
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

bool IsWhitespace(char c) {
  return std::isspace(static_cast<unsigned char>(c)) != 0;
}

void VStrip(std::string &path) {
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

std::string Strip(const std::string &path) {
  std::string result = path;
  VStrip(result);
  return result;
}

void vreplace(std::string &str, const std::string &from,
              const std::string &to) {
  size_t pos = 0;
  while ((pos = str.find(from, pos)) != std::string::npos) {
    str.replace(pos, from.length(), to);
    pos += to.length();
  }
}

std::string replace(std::string str, const std::string &from,
                    const std::string &to) {
  size_t pos = 0;
  while ((pos = str.find(from, pos)) != std::string::npos) {
    str.replace(pos, from.length(), to);
    pos += to.length();
  }
  return str;
}

void vreplace_all(std::string &str, const std::string &old_sub,
                  const std::string &new_sub) {
  size_t pos = 0;
  while ((pos = str.find(old_sub, pos)) != std::string::npos) {
    str.replace(pos, old_sub.size(), new_sub);
    pos += new_sub.size();
  }
}

std::string replace_all(std::string str, const std::string &old_sub,
                        const std::string &new_sub) {
  size_t pos = 0;
  while ((pos = str.find(old_sub, pos)) != std::string::npos) {
    str.replace(pos, old_sub.size(), new_sub);
    pos += new_sub.size();
  }
  return str;
}

std::string join(const std::vector<std::string> &parts,
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

std::string PadLeftAscii(std::string_view value, size_t width) {
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

size_t CountLines(const std::string &text) {
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

void print(const std::string &str) { std::cout << str << "\n"; }

std::string FormatSize(size_t size) {
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

std::string FormatSize(int64_t size) {
  if (size < 0) {
    return "0B";
  }
  return AMStr::FormatSize(static_cast<size_t>(size));
}

bool GetEnv(std::string_view key, std::string *target) {
  if (!key.data() || !target) {
    return false;
  }
#ifdef _WIN32
  const std::string key_utf8(key);
  const std::wstring key_w = AMStr::wstr(key_utf8);
  size_t length = 0;
  if (_wgetenv_s(&length, nullptr, 0, key_w.c_str()) != 0 || length == 0) {
    return false;
  }
  std::wstring value_w(length, L'\0');
  if (_wgetenv_s(&length, value_w.data(), value_w.size(), key_w.c_str()) != 0) {
    return false;
  }
  if (!value_w.empty() && value_w.back() == L'\0') {
    value_w.pop_back();
  }
  *target = AMStr::wstr(value_w);
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
} // namespace AMStr

namespace AMJson {
bool DelKey(AMJson::Json &root, const std::vector<std::string> &path) {
  if (path.empty()) {
    return false;
  }
  AMJson::Json *node = &root;
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
} // namespace AMJson

namespace AMStr {
std::optional<std::string> HexToAnsi(const std::string &value) {
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
  std::array<int, 6> vals;
  for (size_t i = 0; i < 6; ++i) {
    vals[i] = HexToInt_(token[i]);
    if (vals[i] < 0) {
      return std::nullopt;
    }
  }
  int r = vals[0] * 16 + vals[1];
  int g = vals[2] * 16 + vals[3];
  int b = vals[4] * 16 + vals[5];
  return AMStr::fmt("\x1b[38;2;{};{};{}m", r, g, b);
}
} // namespace AMStr

namespace AMAuth {
void SecureZero(std::string &value) {
  std::fill(value.begin(), value.end(), '\0');
  value.clear();
  value.shrink_to_fit();
}

bool IsEncrypted(const std::string &value) {
  return value.rfind(std::string(kEncryptedPrefix), 0) == 0;
}

std::string HexEncode(const std::string &bytes) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.resize(bytes.size() * 2);
  for (size_t i = 0; i < bytes.size(); ++i) {
    const unsigned char b = static_cast<unsigned char>(bytes[i]);
    out[i * 2] = kHex[(b >> 4) & 0x0F];
    out[i * 2 + 1] = kHex[b & 0x0F];
  }
  return out;
}

std::string HexDecode(const std::string &hex) {
  auto hex_to_val = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
      return 10 + (c - 'A');
    }
    if (c >= 'a' && c <= 'f') {
      return 10 + (c - 'a');
    }
    return -1;
  };

  if (hex.size() % 2 != 0) {
    return {};
  }

  std::string out;
  out.resize(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int hi = hex_to_val(hex[i]);
    const int lo = hex_to_val(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return {};
    }
    out[i / 2] = static_cast<char>((hi << 4) | lo);
  }
  return out;
}

std::string XorWithKey(const std::string &input) {
  if (input.empty()) {
    return {};
  }
  std::string out = input;
  for (size_t i = 0; i < out.size(); ++i) {
    const char key_ch = kPasswordKey[i % kPasswordKey.size()];
    out[i] = static_cast<char>(out[i] ^ key_ch);
  }
  return out;
}

std::string EncryptPassword(const std::string &plain) {
  if (plain.empty()) {
    return {};
  }
  if (IsEncrypted(plain)) {
    return plain;
  }
  const std::string xored = XorWithKey(plain);
  const std::string encoded = HexEncode(xored);
  return std::string(kEncryptedPrefix) + encoded;
}

std::string DecryptPassword(const std::string &stored) {
  if (stored.empty() || !IsEncrypted(stored)) {
    return stored;
  }
  const std::string payload =
      stored.substr(std::string(kEncryptedPrefix).size());
  std::string decoded = HexDecode(payload);
  if (decoded.empty() && !payload.empty()) {
    return {};
  }
  decoded = XorWithKey(decoded);
  return decoded;
}
} // namespace AMAuth

const std::shared_ptr<TaskControlToken> TaskControlToken::Global =
    std::make_shared<TaskControlToken>();

double timenow() {
  return std::chrono::duration<double>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

int64_t am_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

double am_s() {
  return std::chrono::duration<double>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

std::string FormatTime(const size_t &time, const std::string &format) {
  auto timeT = static_cast<time_t>(time);

  struct tm timeInfo;
#ifdef _WIN32
  localtime_s(&timeInfo, &timeT);
#else
  localtime_r(&timeT, &timeInfo);
#endif

  std::ostringstream oss;
  oss << std::put_time(&timeInfo, format.c_str());
  return oss.str();
}

std::string FormatTimeHM(double timestamp) {
  if (timestamp <= 0.0) {
    return "-";
  }
  return FormatTime(static_cast<size_t>(timestamp), "%H:%M");
}

bool isok(const ECM &ecm) { return ecm.first == EC::Success; }

ECM Ok() {
  const static ECM ok_instance{EC::Success, ""};
  return ok_instance;
}

ECM Err(EC code, const std::string &msg) { return {code, msg}; }

PathType cast_fs_type(const fs::file_type &type) {
  switch (type) {
  case fs::file_type::directory:
    return PathType::DIR;
  case fs::file_type::symlink:
    return PathType::SYMLINK;
  case fs::file_type::regular:
    return PathType::FILE;
  case fs::file_type::block:
    return PathType::BlockDevice;
  case fs::file_type::character:
    return PathType::CharacterDevice;
  case fs::file_type::fifo:
    return PathType::FIFO;
  case fs::file_type::socket:
    return PathType::Socket;
  case fs::file_type::unknown:
    return PathType::Unknown;
  default:
    return PathType::Unknown;
  }
}

EC fec(const std::error_code &ec) {
  if (!ec) {
    return EC::Success;
  }
  auto errc = static_cast<std::errc>(ec.value());
  switch (errc) {
  case std::errc::no_such_file_or_directory:
    return EC::FileNotExist;
  case std::errc::permission_denied:
    return EC::PermissionDenied;
  case std::errc::file_exists:
    return EC::PathAlreadyExists;
  case std::errc::not_a_directory:
    return EC::NotADirectory;
  case std::errc::is_a_directory:
    return EC::NotAFile;
  case std::errc::directory_not_empty:
    return EC::DirNotEmpty;
  case std::errc::no_space_on_device:
    return EC::FilesystemNoSpace;
  case std::errc::read_only_file_system:
    return EC::FileWriteProtected;
  case std::errc::too_many_symbolic_link_levels:
    return EC::SymlinkLoop;
  case std::errc::filename_too_long:
    return EC::InvalidFilename;
  case std::errc::invalid_argument:
    return EC::InvalidArg;
  case std::errc::io_error:
    return EC::LocalFileError;
  case std::errc::not_supported:
  case std::errc::operation_not_supported:
    return EC::OperationUnsupported;
  case std::errc::timed_out:
    return EC::OperationTimeout;
  case std::errc::connection_refused:
  case std::errc::network_unreachable:
  case std::errc::host_unreachable:
    return EC::NoConnection;
  case std::errc::connection_reset:
    return EC::ConnectionLost;
  default:
    return EC::UnknownError;
  }
}

ECM fecm(const std::error_code &ec) {
  if (!ec) {
    return {EC::Success, ""};
  }
  return {fec(ec), ec.message()};
}
