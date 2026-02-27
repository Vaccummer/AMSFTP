#pragma once
// standard library
#ifdef _WIN32
#define _WINSOCKAPI_
#include <accctrl.h> // Define SE_OBJECT_TYPE enum
#include <aclapi.h>  // Define security operation APIs
#include <shlobj.h>
#include <windows.h>
#endif

// project header
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"

using EC = ErrorCode;
using result_map = std::unordered_map<std::string, ErrorCode>;
using ECM = std::pair<EC, std::string>;
namespace fs = std::filesystem;

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
  // Return escaped text
  std::string escaped;
  escaped.reserve(input.size() * 2); // Pre-allocate memory for performance

  for (char c : input) {
    // Match regex metacharacters that require escaping
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
      escaped += '\\'; // Add escape char
      break;
    default:
      break;
    }
    escaped += c; // Append current character
  }

  return escaped;
}

inline std::string UnifyPathSep(std::string path, std::string sep = "") {
  path = AMStr::Strip(path);
  if (AMStr::CharNum(path) < 2)
    return path;
  sep = sep.empty() ? GetPathSep(path) : sep;
  bool drive_root = false;
  if (path.size() >= 3) {
    const char drive = path[0];
    if (((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) &&
        path[1] == ':') {
      drive_root = true;
      for (size_t i = 2; i < path.size(); ++i) {
        if (path[i] != '/' && path[i] != '\\') {
          drive_root = false;
          break;
        }
      }
    }
  }
  std::string head = path.substr(0, 2);
  if (head == "//" || head == "\\\\") {
    path = path.substr(2);
  } else {
    head.clear();
  }
  path = std::regex_replace(path, std::regex("[\\\\/]+"), sep);
  if (path.empty()) {
    return head.empty() ? path : head;
  }
  if (path.back() == sep[0]) {
    if (!drive_root) {
      path.pop_back();
    }
  }
  return head + path;
}

inline bool IsAbs(const std::string &path, const std::string &sep = "") {
  static std::regex pattern_f =
      std::regex(R"am(^(?:[A-Za-z]:$|~$|[A-Za-z]:[/\\]|/|[\\/]{2}|~[\\/]))am");
  return std::regex_search(UnifyPathSep(path, sep), pattern_f);
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
    // Check whether base already ends with test_ext
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
  // AMStr::CharNum(pathf) >= 3, prevent substr out-of-range
  std::string head = pathf.substr(0, 2);
  if (head == "//" || head == "\\\\") {
    // Match network path
    pathf = pathf.substr(2);
  } else if (head[0] == '/') {
    // Match unix root directory
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

/**
 * @brief Normalize a joined path by resolving "." and ".." without forcing
 * absolute paths.
 */
inline std::string NormalizeJoinedPath(const std::string &path,
                                       const std::string &sep = "") {
  std::string normalized = UnifyPathSep(path, sep);
  if (normalized.empty()) {
    return normalized;
  }

  std::string use_sep = sep.empty() ? GetPathSep(normalized) : sep;
  const bool drive_only = normalized.size() == 2 &&
                          ((normalized[0] >= 'A' && normalized[0] <= 'Z') ||
                           (normalized[0] >= 'a' && normalized[0] <= 'z')) &&
                          normalized[1] == ':';
  if (drive_only) {
    return normalized + use_sep;
  }

  const bool drive_root_anchor =
      normalized.size() >= 3 &&
      ((normalized[0] >= 'A' && normalized[0] <= 'Z') ||
       (normalized[0] >= 'a' && normalized[0] <= 'z')) &&
      normalized[1] == ':' && (normalized[2] == '/' || normalized[2] == '\\');
  const bool unc_root =
      normalized.rfind("//", 0) == 0 || normalized.rfind("\\\\", 0) == 0;

  std::vector<std::string> parts = split(normalized);
  if (parts.empty()) {
    return normalized;
  }

  auto is_drive_part = [](const std::string &part) {
    return part.size() == 2 &&
           ((part[0] >= 'A' && part[0] <= 'Z') ||
            (part[0] >= 'a' && part[0] <= 'z')) &&
           part[1] == ':';
  };

  const bool absolute = unc_root || drive_root_anchor ||
                        (!parts.empty() && (parts.front() == "/" ||
                                            is_drive_part(parts.front())));

  size_t anchor_min = 0;
  if (unc_root) {
    anchor_min = std::min<size_t>(2, parts.size());
  } else if (absolute) {
    anchor_min = 1;
  }

  std::vector<std::string> new_parts;
  new_parts.reserve(parts.size());

  for (const auto &part : parts) {
    if (part == "." || part.empty()) {
      continue;
    }
    if (part == "..") {
      if (new_parts.size() > anchor_min) {
        new_parts.pop_back();
      } else if (!absolute) {
        new_parts.push_back(part);
      }
      continue;
    }
    new_parts.push_back(part);
  }

  if (new_parts.empty()) {
    if (unc_root && parts.size() >= 2) {
      return parts[0] + use_sep + parts[1];
    }
    if (!parts.empty() && parts.front() == "/") {
      return "/";
    }
    if (drive_root_anchor && !parts.empty() && is_drive_part(parts.front())) {
      return parts.front() + use_sep;
    }
    return "";
  }

  std::string result;
  if (unc_root) {
    result = new_parts.front();
    if (new_parts.size() >= 2) {
      result += use_sep + new_parts[1];
      for (size_t i = 2; i < new_parts.size(); ++i) {
        result += use_sep + new_parts[i];
      }
    }
    return result;
  }

  if (new_parts.front() == "/") {
    result = "/";
    for (size_t i = 1; i < new_parts.size(); ++i) {
      result += new_parts[i];
      if (i + 1 < new_parts.size()) {
        result += use_sep;
      }
    }
    return result;
  }

  if (drive_root_anchor && is_drive_part(new_parts.front())) {
    result = new_parts.front();
    if (new_parts.size() == 1) {
      return result + use_sep;
    }
    result += use_sep;
    for (size_t i = 1; i < new_parts.size(); ++i) {
      result += new_parts[i];
      if (i + 1 < new_parts.size()) {
        result += use_sep;
      }
    }
    return result;
  }

  result = new_parts.front();
  for (size_t i = 1; i < new_parts.size(); ++i) {
    result += use_sep + new_parts[i];
  }
  return result;
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
  return NormalizeJoinedPath(result, sep);
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
  double creation_time; // Creation time
  double modify_time;   // Modification time
  double access_time;   // Last access time
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
        continue; // Single byte 0xxxxxxx
      else if ((c & 0xE0) == 0xC0)
        remaining = 1; // Two-byte 110xxxxx
      else if ((c & 0xF0) == 0xE0)
        remaining = 2; // Three-byte 1110xxxx
      else if ((c & 0xF8) == 0xF0)
        remaining = 3; // Four-byte 11110xxx
      else
        return false;
    }
  }
  return (remaining == 0);
}

inline double FileTimeToUnixTime(const FILETIME &ft) {
  const int64_t UNIX_EPOCH_DIFF =
      11644473600LL; // Seconds from 1601-01-01 to 1970-01-01
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

  // Use FindFirstFile to get file info (supports files and directories)
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
using WalkErrorCallback =
    std::shared_ptr<std::function<void(const std::string &, const ECM &)>>;
using WRD =
    std::vector<std::pair<std::vector<std::string>, std::vector<PathInfo>>>;
using amf = std::shared_ptr<TaskControlToken>;
using EC = ErrorCode;
using ECM = std::pair<ErrorCode, std::string>;
using WER = std::vector<std::pair<std::string, ECM>>;
using WRI = std::pair<std::vector<PathInfo>, WER>;

inline std::string HomePath() {
#ifdef _WIN32
  std::array<wchar_t, MAX_PATH> path{};
  if (SUCCEEDED(
          SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, path.data()))) {
    return AMStr::wstr(path.data());
  }
  std::string userprofile = "";
  GetEnv("USERPROFILE", &userprofile);
  return userprofile;
#else
  // Linux/macOS
  std::string home = "";
  GetEnv("HOME", &home);
  if (!home.empty())
    return home;

  struct passwd *pw = getpwuid(getuid());
  if (pw && pw->pw_dir)
    return std::string(pw->pw_dir);
#endif
  return "/home/am";
}

inline std::string CWD() { return fs::current_path().string(); }

inline std::string abspath(const std::string &path,
                           const bool parsing_home = true,
                           const std::string &home = "",
                           const std::string &cwd = "",
                           const std::string &sep = "") {
  std::string new_path = AMPathStr::UnifyPathSep(path, sep);
  std::string new_sep = sep.empty() ? AMPathStr::GetPathSep(path) : sep;
  const bool drive_only = new_path.size() == 2 &&
                          ((new_path[0] >= 'A' && new_path[0] <= 'Z') ||
                           (new_path[0] >= 'a' && new_path[0] <= 'z')) &&
                          new_path[1] == ':';
  if (drive_only) {
    return new_path + new_sep;
  }
  if (AMPathStr::IsAbs(new_path, sep) && !parsing_home) {
    return new_path;
  }
  if (!AMPathStr::IsAbs(new_path, new_sep)) {
    const std::string base = cwd.empty() ? CWD() : cwd;
    new_path = AMPathStr::join(base, new_path);
  }
  const bool drive_root_anchor = new_path.size() >= 3 &&
                                 ((new_path[0] >= 'A' && new_path[0] <= 'Z') ||
                                  (new_path[0] >= 'a' && new_path[0] <= 'z')) &&
                                 new_path[1] == ':' &&
                                 (new_path[2] == '/' || new_path[2] == '\\');
  std::vector<std::string> parts = AMPathStr::split(new_path);
  if (parts.empty()) {
    return "";
  }
  auto is_drive_part = [](const std::string &part) {
    return part.size() == 2 &&
           ((part[0] >= 'A' && part[0] <= 'Z') ||
            (part[0] >= 'a' && part[0] <= 'z')) &&
           part[1] == ':';
  };
  auto is_unc_root = [](const std::vector<std::string> &parts_vec) {
    if (parts_vec.size() != 2) {
      return false;
    }
    const std::string &first = parts_vec[0];
    return first.rfind("//", 0) == 0 || first.rfind("\\\\", 0) == 0;
  };
  std::vector<std::string> new_parts{};
  std::string tmp_part;
  std::string result;
  if (parts.size() == 1) {
    if (parts[0] == "~" && parsing_home) {
      return home.empty() ? HomePath() : home;
    }
    if (drive_root_anchor && is_drive_part(parts[0])) {
      return parts[0] + new_sep;
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
      if (new_parts.empty()) {
        continue;
      }
      /* Keep root anchors from being popped by "..". */
      if ((new_parts.size() == 1 &&
           (new_parts.front() == "/" || is_drive_part(new_parts.front()))) ||
          is_unc_root(new_parts)) {
        continue;
      }
      new_parts.pop_back();
    } else {
      new_parts.push_back(tmp_part);
    }
  }
  if (new_parts.size() == 0) {
    if (drive_root_anchor && !parts.empty() && is_drive_part(parts.front())) {
      return parts.front() + new_sep;
    }
    if (!parts.empty() && parts.front() == "/") {
      return "/";
    }
    if (is_unc_root(parts) && parts.size() >= 2) {
      return parts[0] + new_sep + parts[1];
    }
    return "";
  }
  if (drive_root_anchor && new_parts.size() == 1 &&
      is_drive_part(new_parts.front())) {
    return new_parts.front() + new_sep;
  }
  if (new_parts.front() == "/") {
    result = "/";
    new_parts.erase(new_parts.begin());
  }
  for (auto &part : new_parts) {
    result += part + new_sep;
  }
  if (!result.empty()) {
    if (result.size() == 1 && (result[0] == '/' || result[0] == '\\')) {
      return result;
    }
    result.pop_back();
  }
  return result;
}

inline ECM mkdirs(const std::string &path) {
  std::error_code ec;
  fs::create_directories(fs::path(path), ec);
  if (ec) {
    return {fec(ec), AMStr::amfmt("Mkdir {} failed: {}", path, ec.message())};
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
        ECM{fec(ec), AMStr::amfmt("Stat {} failed: {}", pathf, ec.message())},
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
  // Call stat to get file metadata (supports symlinks; use stat instead of lstat to follow links)
  if (stat(path.c_str(), &file_stat) == -1) {
    return std::make_pair("Fail to stat file: " + std::string(strerror(errno)),
                          info);
  }

  // 1. Owner and group (via UID/GID conversion)
  struct passwd *pw = getpwuid(file_stat.st_uid); // UID -> username
  info.owner = pw ? pw->pw_name : std::to_string(file_stat.st_uid);

  // 2. Octal permissions (0777 format)
  info.mode_int = file_stat.st_mode & 0777;
  info.mode_str = ModeTrans(info.mode_int);

  // 3. Access time and modification time
  // Use struct timespec fields (seconds + nanoseconds, POSIX standard)
  info.access_time =
      timespec_to_double(file_stat.st_atim); // st_atim is timespec type
  info.modify_time =
      timespec_to_double(file_stat.st_mtim); // st_mtim is timespec type
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
    return {ECM{EC::PathNotExist, AMStr::amfmt("Path not found: {}", pathf)},
            result};
  }
  if (!fs::is_directory(p)) {
    return {ECM{EC::NotADirectory,
                AMStr::amfmt("Path is not a directory: {}", pathf)},
            result};
  }
  std::variant<PathInfo, std::pair<std::string, std::exception>> sr;
  std::vector<std::string> dir_paths = {};
  std::error_code ec;
  auto dir_iter = fs::directory_iterator(p, ec);
  if (ec) {
    return {ECM{fec(ec),
                AMStr::amfmt("Listdir {} failed: {}", pathf, ec.message())},
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
