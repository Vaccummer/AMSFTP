#pragma once
// 自身依赖
#include "AMDataClass.hpp"
#include "AMEnum.hpp"
// 标准库头文件（跨平台，无需条件编译）
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <functional>
#include <regex>
#include <stdexcept>
#include <string>
#include <variant>

// 第三方库头文件（跨平台，需链接 fmt 库）
#include <boost/locale/encoding.hpp>
#include <fmt/format.h>

namespace fs = std::filesystem;
using EC = ErrorCode;
using ECM = std::pair<ErrorCode, std::string>;
using amf = std::shared_ptr<InterruptFlag>;

inline PathType cast_fs_type(const fs::file_type &type) {
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
// 将 std::filesystem 错误转换为 ErrorCode
inline EC fec(const std::error_code &ec) {
  if (!ec)
    return EC::Success;
  // 使用 std::errc 进行跨平台映射
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

// 将 std::filesystem 错误转换为 ECM (ErrorCode + message)
inline ECM fecm(const std::error_code &ec) { return {fec(ec), ec.message()}; }

// Windows 特有头文件（仅在 Windows 平台包含）

namespace AMStr {
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
    throw std::invalid_argument(
        fmt::format("Invalid mode string: {}", mode_str));
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
        fmt::format("Invalid base mode string: {}", base_mode_str));
  }

  if (!std::regex_match(new_mode_str, pattern)) {
    throw std::invalid_argument(
        fmt::format("Invalid new mode string: {}", new_mode_str));
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

namespace AMPathStr {
inline std::string GetPathSep(const std::string &path) {
#ifdef AMForceUsingUnixSep
  // force to use unix path separator
  return "/";
#endif
  if (path[0] == '/') {
    return "/";
  } else if (path[0] == '\\') {
    return "\\";
  }
  int slash_count = 0;
  int anti_slash_count = 0;
  for (auto &c : path) {
    if (c == '/') {
      slash_count++;
    } else if (c == '\\') {
      anti_slash_count++;
    }
  }
  return slash_count < anti_slash_count ? "\\" : "/";
}

inline std::string RegexEscape(const std::string &input) {
  // 返回转义
  std::string escaped;
  escaped.reserve(input.size() * 2); // 预分配内存优化性能

  for (char c : input) {
    // 匹配需要转义的正则元字符
    switch (c) {
    case '\\':
    case '^':
    case '$':
    case '.':
    case '|':
    case '?':
    case '*':
    case '+':
    case '(':
    case ')':
    case '[':
    case ']':
    case '{':
    case '}':
      escaped += '\\'; // 添加转义符
      break;
    default:
      break;
    }
    escaped += c; // 追加当前字符
  }

  return escaped;
}

inline std::string UnifyPathSep(std::string path, std::string sep = "") {
  path = AMStr::Strip(path);
  if (AMStr::CharNum(path) < 2)
    return path;
  sep = sep.empty() ? GetPathSep(path) : sep;
  std::string head = path.substr(0, 2);
  if (head == "//" || head == "\\\\") {
    path = path.substr(2);
  } else {
    head.clear();
  }
  path = std::regex_replace(path, std::regex("[\\\\/]+"), sep);
  if (path.back() == sep[0]) {
    path.pop_back();
  }
  return head + path;
}

inline bool IsAbs(const std::string &path, const std::string &sep = "") {
  return std::regex_search(
      UnifyPathSep(path, sep),
      std::regex(
          R"am(^(?:[a-zA-Z]:$)|(?:~$)|(?:[A-Za-z]:[/\\]|/|[\\/]{2}|~[\\/]))am"));
}

inline std::string extname(std::string path) {
  AMStr::VStrip(path);
  AMStr::vlowercase(path);
  std::string ext = "";
  size_t dot_pos = path.find_last_of('.');
  if (dot_pos != std::string::npos) {
    ext = path.substr(dot_pos + 1);
    std::string test_ext = ".tar." + ext;
    if (AMStr::endswith(path, test_ext).first) {
      return test_ext.substr(1);
    } else {
      return ext;
    }
  } else {
    return "";
  }
}

inline std::pair<std::string, std::string>
split_basename(const std::string &basename) {
  std::string base = AMStr::Strip(basename);
  std::string ext = "";
  size_t dot_pos = base.find_last_of('.');
  if (dot_pos != std::string::npos) {
    ext = base.substr(dot_pos + 1);
    std::string test_ext = ".tar." + ext;
    // 检测base是否已test_ext结尾
    auto [check, pos] = AMStr::endswith(base, test_ext);
    if (check) {
      return {base.substr(0, pos), test_ext.substr(1)};
    } else {
      return {base.substr(0, dot_pos), ext};
    }
  } else {
    return {base, ""};
  }
}

inline std::vector<std::string> split(const std::string &path) {
  std::string pathf = AMStr::Strip(path);
  if (AMStr::CharNum(pathf) < 3) {
    return {pathf};
  }
  std::vector<std::string> result{};
  // AMStr::CharNum(pathf) >= 3, 防止substr越界
  std::string head = pathf.substr(0, 2);
  if (head == "//" || head == "\\\\") {
    // 匹配网络路径
    pathf = pathf.substr(2);
  } else if (head[0] == '/') {
    // 匹配unix根目录
    result.emplace_back("/");
    pathf = pathf.substr(1);
    head.clear();
  } else {
    head.clear();
  }
  std::string cur = "";
  for (auto c : pathf) {
    if (c == '\\' || c == '/') {
      if (!cur.empty()) {
        result.push_back(cur);
        cur = "";
      }
    } else if (c == ' ') {
      if (cur.empty()) {
        continue;
      }
    } else {
      cur += c;
    }
  }
  if (!cur.empty()) {
    result.push_back(cur);
  }

  if (!head.empty()) {
    if (result.empty()) {
      return {head};
    }
    result[0] = head + result[0];
  }
  for (auto &part : result) {
    AMStr::VStrip(part);
  }
  return result;
}

inline std::vector<std::string> resplit(const std::string &path, char front_esc,
                                        char back_esc,
                                        const std::string &head = "") {
  if (AMStr::CharNum(path) < 3) {
    return {path};
  }
  std::vector<std::string> parts{};
  std::string tmp_str = "";
  bool in_brackets = false;
  std::string bracket_str = "";
  for (auto &sig : path) {
    if (in_brackets) {
      if (sig == back_esc) {
        in_brackets = false;
        if (!bracket_str.empty()) {
          parts.push_back(head + bracket_str);
          bracket_str.clear();
        }
      } else {
        bracket_str += sig;
      }
    } else {
      if (sig == front_esc) {
        in_brackets = true;
      } else if (sig == '/' || sig == '\\') {
        if (!tmp_str.empty()) {
          parts.push_back(tmp_str);
          tmp_str.clear();
        }
      } else {
        tmp_str += sig;
      }
    }
  }
  return parts;
}

template <typename... Args> std::string join(Args &&...args) {
  std::vector<std::string> segments;
  std::string ori_str;
  fs::path combined;
  std::string sep = "";

  auto process_arg = [&](auto &&arg) {
    using T = std::decay_t<decltype(arg)>;
    if constexpr (std::is_same_v<T, std::filesystem::path>) {
      if (!arg.empty()) {
        segments.push_back(arg.string());
        ori_str += arg.string();
      }
    } else if constexpr (std::is_same_v<T, std::string> ||
                         std::is_same_v<T, const std::string>) {
      if (!arg.empty()) {
        segments.push_back(arg);
        ori_str += arg;
      }
    } else if constexpr (std::is_same_v<T, std::vector<std::string>> ||
                         std::is_same_v<T, const std::vector<std::string>>) {
      for (auto &seg : arg) {
        if (!seg.empty()) {
          segments.push_back(seg);
          ori_str += seg;
        }
      }
    } else if constexpr (std::is_same_v<T, std::wstring> ||
                         std::is_same_v<T, const std::wstring>) {
      std::string s = AMStr::wstr(arg);
      if (!s.empty()) {
        segments.push_back(s);
        ori_str += s;
      }
    } else if constexpr (std::is_same_v<T, const char *> ||
                         std::is_same_v<T, char *>) {
      std::string s = std::string(arg);
      if (!s.empty()) {
        segments.push_back(s);
        ori_str += s;
      }
    } else if constexpr (std::is_same_v<T, const wchar_t *> ||
                         std::is_same_v<T, wchar_t *>) {
      std::string s = AMStr::wstr(arg);
      if (!s.empty()) {
        segments.push_back(s);
        ori_str += s;
      }
    } else if constexpr (std::is_same_v<T, SepType>) {
      switch (arg) {
      case SepType::Unix:
        sep = "/";
        break;
      case SepType::Windows:
        sep = "\\";
        break;
      }
    }
  };

  (process_arg(std::forward<Args>(args)), ...);

  if (segments.empty())
    return "";
  else if (segments.size() == 1) {
    return segments.front();
  }

  std::string result;

  if (segments[0] == "/") {
    result = "/";
    sep = "/";
  } else if (segments[0] == "//") {
    result = "//";
    sep = "/";
  } else if (segments[0] == "\\\\") {
    result = "\\\\";
    sep = "\\";
  } else {
    sep = sep.empty() ? GetPathSep(ori_str) : sep;
    result = segments[0] + sep;
  }

  for (size_t i = 1; i < segments.size(); i++) {
    result += segments[i] + sep;
  }
  result = UnifyPathSep(result, sep);
  return result;
};

inline std::string dirname(const std::string &path) {
  fs::path p(path);
  if (p.parent_path().empty()) {
    return "";
  }
  return p.parent_path().string();
}

inline std::string basename(const std::string &path) {
  std::string pathf = AMStr::Strip(path);
  while ((pathf.back() == '/' || pathf.back() == '\\') && path.size() > 1) {
    pathf.pop_back();
  }
  fs::path p(pathf);
  return p.filename().string();
}
} // namespace AMPathStr

namespace AMFS {

#ifdef _WIN32
struct FileTimes {
  double creation_time; // 创建时间
  double modify_time;   // 修改时间
  double access_time;   // 最近访问时间
};

inline bool is_valid_utf8(const std::string &str) {
  int remaining = 0;
  for (unsigned char c : str) {
    if (remaining > 0) {
      if ((c & 0xC0) != 0x80)
        return false;
      --remaining;
    } else {
      if ((c & 0x80) == 0x00)
        continue; // 单字节 0xxxxxxx
      else if ((c & 0xE0) == 0xC0)
        remaining = 1; // 双字节 110xxxxx
      else if ((c & 0xF0) == 0xE0)
        remaining = 2; // 三字节 1110xxxx
      else if ((c & 0xF8) == 0xF0)
        remaining = 3; // 四字节 11110xxx
      else
        return false;
    }
  }
  return (remaining == 0);
}

inline double FileTimeToUnixTime(const FILETIME &ft) {
  const int64_t UNIX_EPOCH_DIFF =
      11644473600LL; // 1601-01-01 到 1970-01-01 的秒数
  int64_t filetime_100ns =
      (static_cast<int64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
  return static_cast<double>(filetime_100ns) / 1e7 - UNIX_EPOCH_DIFF;
}

inline std::string GetFileOwner(const std::wstring &path) {
  PSID pSidOwner = NULL;
  PSECURITY_DESCRIPTOR pSD = NULL;
  DWORD dwRtnCode = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                                          OWNER_SECURITY_INFORMATION,
                                          &pSidOwner, NULL, NULL, NULL, &pSD);

  std::wstring owner = L"";
  if (dwRtnCode == ERROR_SUCCESS) {
    wchar_t szOwnerName[256];
    wchar_t szDomainName[256];
    DWORD dwNameLen = 256;
    DWORD dwDomainLen = 256;
    SID_NAME_USE eUse;

    if (LookupAccountSidW(NULL, pSidOwner, szOwnerName, &dwNameLen,
                          szDomainName, &dwDomainLen, &eUse)) {
      owner = szOwnerName;
    } else {
      wchar_t username[257];
      DWORD username_len = 257;
      if (GetUserNameW(username, &username_len)) {
        owner = std::wstring(username, username_len - 1);
      }
    }
  }

  if (pSD) {
    LocalFree(pSD);
  }

  return AMStr::wstr(owner);
}

inline std::tuple<double, double, double> GetTime(const std::wstring &path) {
  std::wstring wpath(path.begin(), path.end());

  // 使用 FindFirstFile 获取文件信息（支持文件和目录）
  WIN32_FIND_DATAW find_data;
  HANDLE hFind = FindFirstFileW(wpath.c_str(), &find_data);
  if (hFind == INVALID_HANDLE_VALUE) {
    return {0, 0, 0};
  }
  FindClose(hFind);
  return std::make_tuple(FileTimeToUnixTime(find_data.ftCreationTime),
                         FileTimeToUnixTime(find_data.ftLastWriteTime),
                         FileTimeToUnixTime(find_data.ftLastAccessTime));
}

inline bool is_readonly(const std::wstring &path) {
  DWORD attributes = GetFileAttributesW(path.c_str());
  if (attributes != INVALID_FILE_ATTRIBUTES &&
      attributes & FILE_ATTRIBUTE_READONLY) {
    return true;
  }
  return false;
}
#endif

using CB =
    std::shared_ptr<std::function<void(std::string, std::string, std::string)>>;
using WRD =
    std::vector<std::pair<std::vector<std::string>, std::vector<PathInfo>>>;
using amf = std::shared_ptr<InterruptFlag>;
using EC = ErrorCode;
using ECM = std::pair<ErrorCode, std::string>;

inline std::string HomePath() {
#ifdef _WIN32
  // Windows: 优先使用API
  wchar_t path[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path))) {
    return AMStr::wstr(path);
  }
  // 备选环境变量
  const char *userprofile = std::getenv("USERPROFILE");
  if (userprofile)
    return std::string(userprofile);
#else
  // Linux/macOS
  const char *home = std::getenv("HOME");
  if (home)
    return std::string(home);

  // 备选: 读取/etc/passwd

  struct passwd *pw = getpwuid(getuid());
  if (pw && pw->pw_dir)
    return std::string(pw->pw_dir);
#endif
  return "/home/am";
}

inline std::string CWD() { return fs::current_path().string(); }

// 将路径转换为绝对路径，支持解析~ . ..符号， 不要求路径存在
inline std::string abspath(const std::string &path,
                           const bool parsing_home = true,
                           const std::string &home = "",
                           const std::string &cwd = "",
                           const std::string &sep = "") {
  std::string new_path = AMPathStr::UnifyPathSep(path, sep);
  if (AMPathStr::IsAbs(new_path, sep) && !parsing_home) {
    return new_path;
  }
  std::string new_sep = sep.empty() ? AMPathStr::GetPathSep(path) : sep;
  if (!AMPathStr::IsAbs(new_path, new_sep)) {
    new_path =
        cwd.empty() ? CWD() + new_sep + new_path : cwd + new_sep + new_path;
  }
  std::vector<std::string> parts = AMPathStr::split(new_path);
  if (parts.empty()) {
    return "";
  }
  std::vector<std::string> new_parts{};
  std::string tmp_part;
  std::string result;
  if (parts.empty()) {
    return "";
  } else if (parts.size() == 1) {
    if (parts[0] == "~" && parsing_home) {
      return home.empty() ? HomePath() : home;
    }
    return parts.front();
  } else if (parts[0] == "/") {
    new_sep = "/";
  } else if (parts[0] == "~" && parsing_home) {
    std::string hm = home.empty() ? HomePath() : home;
    for (const auto &seg : AMPathStr::split(hm)) {
      new_parts.push_back(seg);
    }
    parts.erase(parts.begin());
  }

  for (auto &tmp_part : parts) {
    if (tmp_part == ".") {
      continue;
    } else if (tmp_part == "..") {
      if (!new_parts.empty()) {
        new_parts.pop_back();
      }
    } else {
      new_parts.push_back(tmp_part);
    }
  }
  if (new_parts.size() == 0) {
    return "";
  }
  if (new_parts.front() == "/") {
    result = "/";
    new_parts.erase(new_parts.begin());
  }
  for (auto &part : new_parts) {
    result += part + new_sep;
  }
  if (!result.empty()) {
    result.pop_back();
  }
  return result;
}

inline ECM mkdirs(const std::string &path) {
  std::error_code ec;
  fs::create_directories(fs::path(path), ec);
  if (ec) {
    return {fec(ec), fmt::format("Mkdir {} failed: {}", path, ec.message())};
  }
  return ECM{EC::Success, ""};
}

inline std::pair<ECM, PathInfo> stat(const std::string &path,
                                     bool trace_link = false) {
  PathInfo info;
  std::string pathf = path;
  fs::path p(pathf);
  info.name = p.filename().string();
  info.path = pathf;
  info.dir = p.parent_path().string();
  fs::file_status status;
  std::error_code ec;
  if (trace_link) {
    status = fs::status(p, ec);
  } else {
    status = fs::symlink_status(p, ec);
  }
  if (ec) {
    return {
        ECM{fec(ec), fmt::format("Stat {} failed: {}", pathf, ec.message())},
        info};
  }
  info.type = cast_fs_type(status.type());

  auto size_f = fs::file_size(p, ec);
  if (!ec) {
    info.size = size_f;
  }

#ifdef _WIN32
  if (is_readonly(AMStr::wstr(pathf))) {
    info.mode_int = 0333;
    info.mode_str = "r-xr-xr-x";
  } else {
    info.mode_int = 0666;
    info.mode_str = "rwxrwxrwx";
  }

  auto [create_time, access_time, modify_time] = GetTime(AMStr::wstr(path));
  info.create_time = create_time;
  info.access_time = access_time;
  info.modify_time = modify_time;
  info.owner = GetFileOwner(AMStr::wstr(path));
#else
  struct stat file_stat;
  // 调用 stat 获取文件元数据（支持符号链接，若需跟随链接用 stat 而非 lstat）
  if (stat(path.c_str(), &file_stat) == -1) {
    return std::make_pair("Fail to stat file: " + std::string(strerror(errno)),
                          info);
  }

  // 1. 拥有者和组（通过 UID/GID 转换）
  struct passwd *pw = getpwuid(file_stat.st_uid); // UID -> 用户名
  info.owner = pw ? pw->pw_name : std::to_string(file_stat.st_uid);

  // 2. 八进制权限（0777格式）
  info.mode_int = file_stat.st_mode & 0777;
  info.mode_str = ModeTrans(info.mode_int);

  // 3. 访问时间（access time）和修改时间（modify time）
  // 使用 struct timespec 成员（包含秒和纳秒，POSIX 标准）
  info.access_time =
      timespec_to_double(file_stat.st_atim); // st_atim 是 timespec 类型
  info.modify_time =
      timespec_to_double(file_stat.st_mtim); // st_mtim 是 timespec 类型
#endif
#ifdef __APPLE__
  info.create_time = timespec_to_double(file_stat.st_birthtimespec);
#endif
  return {{EC::Success, ""}, info};
}

inline std::pair<ECM, std::vector<PathInfo>>
listdir(const std::string &path, amf interrupt_flag = nullptr,
        int timeout_ms = -1,
        std::chrono::steady_clock::time_point start_time =
            std::chrono::steady_clock::now()) {
  std::string pathf = path;
  std::vector<PathInfo> result = {};
  fs::path p(pathf);
  if (!fs::exists(p)) {
    return {ECM{EC::PathNotExist, fmt::format("Path not found: {}", pathf)},
            result};
  }
  if (!fs::is_directory(p)) {
    return {ECM{EC::NotADirectory,
                fmt::format("Path is not a directory: {}", pathf)},
            result};
  }
  std::variant<PathInfo, std::pair<std::string, std::exception>> sr;
  std::vector<std::string> dir_paths = {};
  std::error_code ec;
  auto dir_iter = fs::directory_iterator(p, ec);
  if (ec) {
    return {
        ECM{fec(ec), fmt::format("Listdir {} failed: {}", pathf, ec.message())},
        result};
  }
  for (const auto &entry : dir_iter) {
    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Listdir interrupted by user"}, result};
    }
    if (timeout_ms > 0 && std::chrono::steady_clock::now() - start_time >
                              std::chrono::milliseconds(timeout_ms)) {
      return {ECM{EC::OperationTimeout, "Listdir timeout"}, result};
    }
    auto [error, info] = stat(entry.path().string(), false);
    if (error.first != EC::Success) {
      continue;
    }
    result.push_back(info);
  }
  return {ECM{EC::Success, ""}, result};
}
} // namespace AMFS

class BasePathMatch {
private:
  virtual std::pair<ECM, PathInfo> stat(const std::string &path,
                                        bool trace_link = false,
                                        amf interrupt_flag = nullptr,
                                        int timeout_ms = -1,
                                        int64_t start_time = -1) = 0;
  virtual std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1, int64_t start_time = -1) = 0;
  virtual std::pair<ECM, std::vector<PathInfo>>
  iwalk(const std::string &path, bool ignore_sepcial_file = true,
        amf interrupt_flag = nullptr, int timeout_ms = -1,
        int64_t start_time = -1) = 0;
  std::string star_rep = "amspecial1123exchange2123for1233star4123dd";
  std::string less_rep = "amspecial4123exchange3332for2less131aa";
  std::string greater_rep = "amspecial721exchange623for511greater422ff";

  void _find(std::vector<PathInfo> &results, const PathInfo &path,
             const std::vector<std::string> &match_parts,
             const SearchType &type, const std::string &sep,
             amf interrupt_flag = nullptr, int timeout_ms = -1,
             int64_t start_time = -1) {
    if (match_parts.empty()) {
      if (type == SearchType::All ||
          (type == SearchType::Directory && path.type == PathType::DIR) ||
          (type == SearchType::File && path.type == PathType::FILE)) {
        results.push_back(path);
      }
      return;
    }

    if (path.type != PathType::DIR) {
      // 当前路径已经是文件，无法继续匹配
      return;
    }

    std::string cur_pattern = match_parts[0];

    if (std::regex_search(cur_pattern, std::regex("^\\*\\*+$"))) {
      std::vector<std::string> relative_parts;
      auto [error, sub_list] =
          iwalk(path.path, true, interrupt_flag, timeout_ms, start_time);
      if (error.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_list) {
        if (interrupt_flag && interrupt_flag->check()) {
          return;
        }
        if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
          return;
        }
        if ((sub.type == PathType::DIR && type == SearchType::File) ||
            (sub.type != PathType::DIR && type == SearchType::Directory)) {
          continue;
        }
        // sub.path relative to path.path
        relative_parts = AMPathStr::split(sub.path.substr(path.path.size()));
        if (walk_match(relative_parts, match_parts)) {
          results.push_back(sub);
        }
      }
      return;
    }
    // 处理不匹配模式
    else if (cur_pattern.find("*") == std::string::npos &&
             (cur_pattern.find("<") == std::string::npos ||
              cur_pattern.find(">") == std::string::npos)) {
      auto new_parts2 = match_parts;
      new_parts2.erase(new_parts2.begin());
      auto [error2, sub_list2] =
          listdir(path.path, interrupt_flag, timeout_ms, start_time);
      if (error2.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_list2) {
        if (interrupt_flag && interrupt_flag->check()) {
          return;
        }
        if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
          return;
        }
        if (sub.name == cur_pattern) {
          _find(results, sub, new_parts2, type, sep, interrupt_flag, timeout_ms,
                start_time);
        }
      }
    }
    // 进入匹配模式
    else {
      auto new_parts3 = match_parts;
      new_parts3.erase(new_parts3.begin());
      auto [error3, sub_list3] =
          listdir(path.path, interrupt_flag, timeout_ms, start_time);
      if (error3.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_list3) {
        if (interrupt_flag && interrupt_flag->check()) {
          return;
        }
        if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
          return;
        }
        if (name_match(sub.name, cur_pattern)) {
          _find(results, sub, new_parts3, type, sep);
        }
      }
    }

    return;
  }

  std::string _rep(const std::string &str, const std::string &from,
                   const std::string &to) {
    std::string result = str;
    if (from.empty())
      return result; // 避免空字符串导致无限循环
    size_t pos = 0;
    while ((pos = result.find(from, pos)) != std::string::npos) {
      result.replace(pos, from.length(), to);
      pos +=
          to.length(); // 跳过替换后的内容，防止重复替换（比如from是to的子串）
    }
    return result;
  }

public:
  bool str_match(const std::string &name, const std::string &pattern) {
    std::string patternf = "^" + pattern + "$";
    std::wstring w_pattern = AMStr::wstr(patternf);
    std::wstring w_name = AMStr::wstr(name);
    try {
      bool res = std::regex_search(w_name, std::wregex(w_pattern));
      return res;
    } catch (const std::regex_error) {
      return false;
    }
  }

  bool name_match(const std::string &name, const std::string &pattern) {
    // 将pattern中的*换成star_rep，<换成less_rep，>换成greater_rep
    std::string pattern_new = pattern;
    pattern_new = _rep(pattern_new, "*", star_rep);
    pattern_new = _rep(pattern_new, "<", less_rep);
    pattern_new = _rep(pattern_new, ">", greater_rep);
    pattern_new = AMPathStr::RegexEscape(pattern_new);
    // 将path中的star_rep换成.*，less_rep换成[，greater_rep换成], 不要用正则替换
    pattern_new = _rep(pattern_new, star_rep, ".*");
    pattern_new = _rep(pattern_new, less_rep, "[");
    pattern_new = _rep(pattern_new, greater_rep, "]");
    return str_match(name, pattern_new);
  };

  bool walk_match(const std::vector<std::string> &parts,
                  const std::vector<std::string> &match_parts) {
    if (match_parts.size() > parts.size()) {
      return false;
    }
    size_t pos = 0;
    bool is_match;
    for (auto &part : match_parts) {
      is_match = false;
      for (size_t i = pos; i < parts.size(); i++) {
        if (name_match(parts[i], part)) {
          is_match = true;
          pos = i + 1;
          break;
        }
      }
      if (!is_match) {
        return false;
      }
    }
    return true;
  }

  std::vector<PathInfo> find(const std::string &path,
                             SearchType type = SearchType::All,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) {
    std::vector<PathInfo> results = {};
    auto parts = AMPathStr::split(path);
    if (parts.empty()) {
      return results;
    } else if (parts.size() == 1) {
      auto [error, info] =
          stat(parts[0], false, interrupt_flag, timeout_ms, start_time);
      if (error.first != EC::Success) {
        return {};
      }
      if (error.first == EC::Success &&
          (type == SearchType::All ||
           (type == SearchType::Directory && info.type == PathType::DIR) ||
           (type == SearchType::File && info.type == PathType::FILE))) {
        results.push_back(info);
      }
      return results;
    }

    std::string sep = AMPathStr::GetPathSep(path);
    std::string cur_path = parts[0];
    bool is_stop = false;
    std::vector<std::string> match_parts = {};

    for (size_t i = 1; i < parts.size(); i++) {
      // 没有* < >时，链接到cur_path
      if (parts[i].find("*") == std::string::npos &&
          parts[i].find("<") == std::string::npos &&
          parts[i].find(">") == std::string::npos && !is_stop) {
        cur_path = AMPathStr::join(cur_path, parts[i]);
      } else {
        is_stop = true;
        match_parts.push_back(parts[i]);
      }
    }

    // 检查cur_path是否存在
    auto [error, info] =
        stat(cur_path, false, interrupt_flag, timeout_ms, start_time);
    if (error.first != EC::Success) {
      return {};
    }
    _find(results, info, match_parts, type, sep, interrupt_flag, timeout_ms,
          start_time);
    return results;
  }
};

/*
class PathMatch : public BasePathMatch {
private:
  std::pair<bool, PathInfo> istat(const std::string &path) override {
    auto [error, info] = stat(path);
    if (error.empty()) {
      return std::make_pair(true, info);
    }
    return std::make_pair(false, PathInfo());
  }

  std::vector<PathInfo> ilistdir(const std::string &path) override {
    return listdir(path);
  }

  std::vector<PathInfo> iiwalk(const std::string &path) override {
    return iwalk(path);
  }
};*/