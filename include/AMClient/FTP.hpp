#pragma once
// Standard library
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>

// Internal dependencies
#include "AMClient/Base.hpp"

// Internal dependencies

// Third-party libraries
#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace {
struct MemoryStruct {
  char *memory;
  size_t size;
};
// Parse IIS/DOS directory listing line
// Format: 03-03-25  11:27AM                90624 zlib1.dll
//       01-10-26  12:01PM       <DIR>          AMSFTP
inline PathInfo ParseDOSListLine(const std::string &line,
                                 const std::string &dir_path) {
  PathInfo info;
  info.type = PathType::Unknown;

  // Skip leading spaces
  size_t pos = 0;
  while (pos < line.size() && std::isspace(line[pos]))
    pos++;
  if (pos >= line.size())
    return info;

  // Parse date (MM-DD-YY)
  size_t date_start = pos;
  size_t date_end = line.find_first_of(" \t", pos);
  if (date_end == std::string::npos)
    return info;
  std::string date_str = line.substr(date_start, date_end - date_start);

  // Skip spaces until time field
  pos = date_end;
  while (pos < line.size() && std::isspace(line[pos]))
    pos++;
  if (pos >= line.size())
    return info;

  // Parse time (HH:MMAM/PM)
  size_t time_start = pos;
  size_t time_end = line.find_first_of(" \t", pos);
  if (time_end == std::string::npos)
    return info;
  std::string time_str = line.substr(time_start, time_end - time_start);

  // Parse date/time to Unix timestamp
  try {
    // Parse date MM-DD-YY
    int month = 0, day = 0, year = 0;
    if (sscanf_s(date_str.c_str(), "%d-%d-%d", &month, &day, &year) == 3) {
      // Handle two-digit year
      if (year < 100) {
        year += (year >= 70) ? 1900 : 2000;
      }

      // Parse time HH:MMAM/PM
      int hour = 0, minute = 0;
      std::array<char, 3> ampm = {0};
      if (sscanf_s(time_str.c_str(), "%d:%d%2s", &hour, &minute, ampm) >= 2) {
        // Convert 12-hour clock to 24-hour
        std::string ampm_str(ampm.data());
        std::transform(ampm_str.begin(), ampm_str.end(), ampm_str.begin(),
                       ::toupper);
        if (ampm_str == "PM" && hour != 12) {
          hour += 12;
        } else if (ampm_str == "AM" && hour == 12) {
          hour = 0;
        }

        // Build tm struct and convert to time_t
        struct tm tm_time = {};
        tm_time.tm_year = year - 1900;
        tm_time.tm_mon = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min = minute;
        tm_time.tm_sec = 0;
        tm_time.tm_isdst = -1; // Let system decide DST automatically

        time_t unix_time = mktime(&tm_time);
        if (unix_time != -1) {
          info.modify_time = static_cast<double>(unix_time);
        }
      }
    }
  } catch (...) {
    // Parse failed; keep modify_time as 0
  }

  // Skip spaces until <DIR> or file size
  pos = time_end;
  while (pos < line.size() && std::isspace(line[pos]))
    pos++;
  if (pos >= line.size())
    return info;

  // Check whether it is a directory (<DIR>) or file size
  if (line.substr(pos, 5) == "<DIR>") {
    info.type = PathType::DIR;
    info.size = 0;
    pos += 5;
  } else {
    // Parse file size
    size_t size_end = line.find_first_of(" \t", pos);
    if (size_end == std::string::npos)
      return info;
    std::string size_str = line.substr(pos, size_end - pos);
    try {
      info.size = std::stoull(size_str);
    } catch (...) {
      info.size = 0;
    }
    info.type = PathType::FILE;
    pos = size_end;
  }

  // Skip spaces until filename
  while (pos < line.size() && std::isspace(line[pos]))
    pos++;
  if (pos >= line.size())
    return info;

  // The remaining part is filename
  std::string name = line.substr(pos);
  // Trim trailing spaces and \r
  while (!name.empty() && (std::isspace(name.back()) || name.back() == '\r')) {
    name.pop_back();
  }

  if (name.empty())
    return info;

  info.name = name;
  info.path = AMPathStr::join(dir_path, name, SepType::Unix);
  info.dir = dir_path;

  return info;
}

// Parse Unix directory listing line
// Format: -rw-r--r-- 1 owner group size month day time filename
//       drwxr-xr-x 1 owner group size month day time filename
inline PathInfo ParseUnixListLine(const std::string &line,
                                  const std::string &dir_path) {
  PathInfo info;
  info.type = PathType::Unknown;

  std::istringstream iss(line);
  std::string perms, links, owner, group, size_str, month, day, time_or_year,
      name;

  if (!(iss >> perms >> links >> owner >> group >> size_str >> month >> day >>
        time_or_year)) {
    return info;
  }

  // Get filename (rest of line)
  std::getline(iss >> std::ws, name);
  // Remove trailing \r if present (FTP uses CRLF)
  if (!name.empty() && name.back() == '\r') {
    name.pop_back();
  }

  // Handle symlink (name -> target)
  if (!name.empty() && perms.size() > 0 && perms[0] == 'l') {
    size_t arrow_pos = name.find(" -> ");
    if (arrow_pos != std::string::npos) {
      name = name.substr(0, arrow_pos);
    }
  }

  info.name = name;
  info.path = AMPathStr::join(dir_path, name, SepType::Unix);
  info.dir = dir_path;
  info.owner = owner;

  // Parse type
  if (!perms.empty()) {
    if (perms[0] == 'd') {
      info.type = PathType::DIR;
    } else if (perms[0] == 'l') {
      info.type = PathType::SYMLINK;
    } else if (perms[0] == '-') {
      info.type = PathType::FILE;
    } else {
      info.type = PathType::Unknown;
    }
  }

  // Parse size
  try {
    info.size = std::stoull(size_str);
  } catch (...) {
    info.size = 0;
  }

  // Parse permissions (skip first char which is type)
  if (perms.size() > 1) {
    info.mode_str = perms.substr(1);
  }

  return info;
}

// Auto-detect and parse directory listing line
inline PathInfo ParseListLine(const std::string &line,
                              const std::string &dir_path) {
  // Skip empty lines
  if (line.empty())
    return {};

  // Detect line format: DOS/IIS usually starts with digits (date)
  // Unix format starts with permission chars (d, -, l, etc.)
  size_t first_nonspace = 0;
  while (first_nonspace < line.size() && std::isspace(line[first_nonspace]))
    first_nonspace++;

  if (first_nonspace >= line.size())
    return {};

  char first_char = line[first_nonspace];

  // DOS/IIS format starts with digits (date like 01-10-26)
  if (std::isdigit(first_char)) {
    return ParseDOSListLine(line, dir_path);
  }

  // Unix format starts with permission chars (d, -, l, c, b, p, s)
  if (first_char == 'd' || first_char == '-' || first_char == 'l' ||
      first_char == 'c' || first_char == 'b' || first_char == 'p' ||
      first_char == 's') {
    return ParseUnixListLine(line, dir_path);
  }

  // Unknown format
  return {};
}

// Parse MLSD line (directory listing)
// Format: type=file;size=1024;modify=20210315120000;perm=rwx; filename
// Unlike MLST, each MLSD line includes filename and must be extracted
inline PathInfo ParseMLSDLine(const std::string &line,
                              const std::string &dir_path) {
  PathInfo info;

  // Find separator between facts and filename (filename after last space)
  size_t space_pos = line.rfind(' ');
  if (space_pos == std::string::npos) {
    info.type = PathType::Unknown;
    return info;
  }

  std::string facts = line.substr(0, space_pos);
  std::string filename = line.substr(space_pos + 1);

  // Remove carriage return from filename
  if (!filename.empty() && filename.back() == '\r') {
    filename.pop_back();
  }

  info.name = filename;
  info.dir = dir_path;
  info.path = AMPathStr::join(dir_path, filename, SepType::Unix);

  // Parse facts (;-separated key=value)
  std::istringstream ss(facts);
  std::string fact;
  while (std::getline(ss, fact, ';')) {
    if (fact.empty())
      continue;

    size_t eq_pos = fact.find('=');
    if (eq_pos == std::string::npos)
      continue;

    std::string key = fact.substr(0, eq_pos);
    std::string value = fact.substr(eq_pos + 1);

    // Compare in lowercase
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    if (key == "type") {
      std::transform(value.begin(), value.end(), value.begin(), ::tolower);
      if (value == "file") {
        info.type = PathType::FILE;
      } else if (value == "dir") {
        info.type = PathType::DIR;
      } else if (value == "cdir" || value == "pdir") {
        // Current/parent directory, skip
        info.type = PathType::Unknown;
      } else if (value == "os.unix=symlink" || value == "os.unix=slink") {
        info.type = PathType::SYMLINK;
      } else {
        info.type = PathType::Unknown;
      }
    } else if (key == "size") {
      try {
        info.size = std::stoull(value);
      } catch (...) {
        info.size = 0;
      }
    } else if (key == "modify") {
      if (value.length() >= 14) {
        struct tm tm = {};
        tm.tm_year = std::stoi(value.substr(0, 4)) - 1900;
        tm.tm_mon = std::stoi(value.substr(4, 2)) - 1;
        tm.tm_mday = std::stoi(value.substr(6, 2));
        tm.tm_hour = std::stoi(value.substr(8, 2));
        tm.tm_min = std::stoi(value.substr(10, 2));
        tm.tm_sec = std::stoi(value.substr(12, 2));
        info.modify_time = static_cast<double>(mktime(&tm));
      }
    } else if (key == "create") {
      if (value.length() >= 14) {
        struct tm tm = {};
        tm.tm_year = std::stoi(value.substr(0, 4)) - 1900;
        tm.tm_mon = std::stoi(value.substr(4, 2)) - 1;
        tm.tm_mday = std::stoi(value.substr(6, 2));
        tm.tm_hour = std::stoi(value.substr(8, 2));
        tm.tm_min = std::stoi(value.substr(10, 2));
        tm.tm_sec = std::stoi(value.substr(12, 2));
        info.create_time = static_cast<double>(mktime(&tm));
      }
    } else if (key == "perm") {
      info.mode_str = value;
    } else if (key == "unix.mode") {
      try {
        info.mode_int = std::stoul(value, nullptr, 8);
        info.mode_str = AMStr::ModeTrans(info.mode_int);
      } catch (...) {
      }
    } else if (key == "unix.owner") {
      info.owner = value;
    }
  }

  return info;
}

// Parse MLST response format
// Format: type=file;size=1024;modify=20210315120000;perm=rwx; filename
inline PathInfo ParseMLSTLine(const std::string &line,
                              const std::string &path) {
  PathInfo info;
  info.path = path;
  info.name = AMPathStr::basename(path);
  info.dir = AMPathStr::dirname(path);

  // Find separator between facts and filename (filename after last space)
  size_t space_pos = line.rfind(' ');
  if (space_pos == std::string::npos) {
    info.type = PathType::Unknown;
    return info;
  }

  std::string facts = line.substr(0, space_pos);

  // Parse facts (;-separated key=value)
  std::istringstream ss(facts);
  std::string fact;
  while (std::getline(ss, fact, ';')) {
    if (fact.empty())
      continue;

    size_t eq_pos = fact.find('=');
    if (eq_pos == std::string::npos)
      continue;

    std::string key = fact.substr(0, eq_pos);
    std::string value = fact.substr(eq_pos + 1);

    // Compare in lowercase
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    if (key == "type") {
      std::transform(value.begin(), value.end(), value.begin(), ::tolower);
      if (value == "file") {
        info.type = PathType::FILE;
      } else if (value == "dir" || value == "cdir" || value == "pdir") {
        info.type = PathType::DIR;
      } else if (value == "os.unix=symlink" || value == "os.unix=slink") {
        info.type = PathType::SYMLINK;
      } else {
        info.type = PathType::Unknown;
      }
    } else if (key == "size") {
      try {
        info.size = std::stoull(value);
      } catch (...) {
        info.size = 0;
      }
    } else if (key == "modify") {
      // Format: YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.sss
      if (value.length() >= 14) {
        struct tm tm = {};
        tm.tm_year = std::stoi(value.substr(0, 4)) - 1900;
        tm.tm_mon = std::stoi(value.substr(4, 2)) - 1;
        tm.tm_mday = std::stoi(value.substr(6, 2));
        tm.tm_hour = std::stoi(value.substr(8, 2));
        tm.tm_min = std::stoi(value.substr(10, 2));
        tm.tm_sec = std::stoi(value.substr(12, 2));
        info.modify_time = static_cast<double>(mktime(&tm));
      }
    } else if (key == "create") {
      if (value.length() >= 14) {
        struct tm tm = {};
        tm.tm_year = std::stoi(value.substr(0, 4)) - 1900;
        tm.tm_mon = std::stoi(value.substr(4, 2)) - 1;
        tm.tm_mday = std::stoi(value.substr(6, 2));
        tm.tm_hour = std::stoi(value.substr(8, 2));
        tm.tm_min = std::stoi(value.substr(10, 2));
        tm.tm_sec = std::stoi(value.substr(12, 2));
        info.create_time = static_cast<double>(mktime(&tm));
      }
    } else if (key == "perm") {
      info.mode_str = value;
    } else if (key == "unix.mode") {
      try {
        info.mode_int = std::stoul(value, nullptr, 8);
        info.mode_str = AMStr::ModeTrans(info.mode_int);
      } catch (...) {
      }
    } else if (key == "unix.owner") {
      info.owner = value;
    }
  }

  return info;
}

inline std::string MlistPath(const std::string &path, bool is_dir = false) {
  std::string pathf = AMPathStr::UnifyPathSep(path, "/");
  // Replace spaces with %20
  AMStr::vreplace_all(pathf, " ", "%20");
  while (!pathf.empty() && (pathf.back() == '/' || pathf.back() == '\\')) {
    pathf.pop_back();
  }
  if (is_dir) {
    pathf += "/"; // Directory always ends with /, including empty path (root)
  }
  if (!pathf.empty() && pathf.front() != '/') {
    pathf = "/" + pathf;
  }
  return pathf;
}

inline EC GetFTPErrorCode(CURLcode curl_code) {
  switch (curl_code) {
  case CURLE_OK:
    return EC::Success;
  case CURLE_UNSUPPORTED_PROTOCOL:
    return EC::UnsupportFTPProtocol;
  case CURLE_URL_MALFORMAT:
    return EC::IllegealURLFormat;
  case CURLE_COULDNT_RESOLVE_HOST:
    return EC::NetworkError;
  case CURLE_COULDNT_CONNECT:
    return EC::FTPConnectFailed;
  case CURLE_OPERATION_TIMEDOUT:
    return EC::OperationTimeout;
  case CURLE_GOT_NOTHING:
  case CURLE_FTP_CANT_RECONNECT:
    return EC::ConnectionLost;
  case CURLE_SEND_ERROR:
    return EC::FTPSendError;
  case CURLE_RECV_ERROR:
    return EC::FTPRecvError;
  case CURLE_FTP_WEIRD_SERVER_REPLY:
    return EC::IllegealSeverReply;
  case CURLE_FTP_ACCESS_DENIED:
    return EC::PermissionDenied;
  case CURLE_FTP_USER_PASSWORD_INCORRECT:
    return EC::AuthFailed;
  case CURLE_FTP_QUOTE_ERROR:
  case CURLE_FTP_PRET_FAILED:
    return EC::OperationUnsupported;
  case CURLE_FTP_COULDNT_RETR_FILE:
    return EC::FileNotExist;
  case CURLE_FTP_WRITE_ERROR:
    return EC::FTPWriteError;
  default:
    return EC::CommonFailure;
  }
}
} // namespace

// FTP Client using libcurl
class AMFTPClient : public BaseClient {
  using AuthCallback =
      std::function<std::optional<std::string>(const AuthCBInfo &)>;

private:
  CURL *curl = nullptr;
  CURLM *multi = nullptr; // Reused multi handle
  std::atomic<bool> connected = false;
  std::atomic<bool> mlst_supported = true; // Whether MLST is supported; try by default first
  std::atomic<bool> mlst_checked = false;  // Whether MLST support has been checked
  std::regex ftp_url_pattern = std::regex("^ftp://.*$");
  std::string url = "";
  std::string current_url = ""; // Keep CURLOPT_URL string lifetime valid
  std::string session_password_plain_;
  AuthCallback auth_cb_ = {};
  bool auth_cb_enabled_ = false;
  // Execute curl request non-blocking; supports interrupt and timeout.
  // Wait strategy is event-driven by libcurl socket state and internal timers.
  NBResult<CURLcode> nb_perform(amf interrupt_flag, int timeout_ms,
                                int64_t start_time) {
    if (!multi || !curl) {
      return {CURLE_FAILED_INIT, WaitResult::Error};
    }
    start_time = start_time == -1 ? am_ms() : start_time;

    // Ensure curl is not left in multi (avoid leftovers from previous operations)
    // curl_multi_remove_handle(multi, curl);

    CURLMcode add_result = curl_multi_add_handle(multi, curl);
    if (add_result != CURLM_OK) {
      return {CURLE_FAILED_INIT, WaitResult::Error};
    }

    size_t wakeup_token = 0;
#if LIBCURL_VERSION_NUM >= 0x074400
    if (interrupt_flag) {
      wakeup_token = interrupt_flag->RegisterWakeup([this]() {
        if (multi) {
          curl_multi_wakeup(multi);
        }
      });
    }
#endif

    int still_running = 1;
    CURLcode result = CURLE_OK;
    WaitResult wait_result = WaitResult::Ready;

    auto cleanup_wakeup = [&]() {
      if (interrupt_flag && wakeup_token != 0) {
        interrupt_flag->UnregisterWakeup(wakeup_token);
      }
    };

    auto remaining_timeout_ms = [&]() -> int64_t {
      if (timeout_ms <= 0) {
        return -1;
      }
      const int64_t elapsed = am_ms() - start_time;
      if (elapsed >= static_cast<int64_t>(timeout_ms)) {
        return 0;
      }
      return static_cast<int64_t>(timeout_ms) - elapsed;
    };

    while (still_running) {
      CURLMcode mc = curl_multi_perform(multi, &still_running);

      if (mc != CURLM_OK) {
        result = CURLE_FAILED_INIT;
        wait_result = WaitResult::Error;
        break;
      }

      if (!still_running)
        break;

      // Check interrupt
      if (interrupt_flag && !interrupt_flag->IsRunning()) {
        wait_result = WaitResult::Interrupted;
        break;
      }

      const int64_t remaining_ms = remaining_timeout_ms();
      if (remaining_ms == 0) {
        wait_result = WaitResult::Timeout;
        break;
      }

      long curl_wait_ms = -1;
      mc = curl_multi_timeout(multi, &curl_wait_ms);
      if (mc != CURLM_OK) {
        result = CURLE_FAILED_INIT;
        wait_result = WaitResult::Error;
        break;
      }

      int wait_ms = std::numeric_limits<int>::max();
      if (curl_wait_ms >= 0) {
        wait_ms = static_cast<int>(
            std::min<long>(curl_wait_ms, std::numeric_limits<int>::max()));
      }
      if (remaining_ms > 0) {
        wait_ms =
            static_cast<int>(std::min<int64_t>(wait_ms, remaining_ms));
      }

      // Wait for socket events based on libcurl timer/socket state.
      int numfds = 0;
      mc = curl_multi_poll(multi, nullptr, 0, wait_ms, &numfds);

      if (mc != CURLM_OK) {
        result = CURLE_FAILED_INIT;
        wait_result = WaitResult::Error;
        break;
      }
    }

    cleanup_wakeup();

    // Get actual result
    if (wait_result == WaitResult::Ready) {
      CURLMsg *msg;
      int msgs_left;
      while ((msg = curl_multi_info_read(multi, &msgs_left))) {
        if (msg->msg == CURLMSG_DONE && msg->easy_handle == curl) {
          result = msg->data.result;
        }
      }
    }

    curl_multi_remove_handle(multi, curl);
    // Do not call curl_easy_reset here so caller can use curl_easy_getinfo
    // Get file info; SetupPath will call curl_easy_reset before next operation

    return {result, wait_result};
  }

  ECM NBResultToECM(const NBResult<CURLcode> &nb_res) {
    if (nb_res.status == WaitResult::Interrupted) {
      return {EC::Terminate, "Interrupted by user"};
    }
    if (nb_res.status == WaitResult::Timeout) {
      return {EC::OperationTimeout, "Operation timed out"};
    }
    if (nb_res.status == WaitResult::Error) {
      return {EC::CommonFailure, "Multi handle error"};
    }
    if (nb_res.value == CURLE_OK) {
      return {EC::Success, ""};
    }
    if (nb_res.value == CURLE_FTP_USER_PASSWORD_INCORRECT) {
      return {EC::AuthFailed, curl_easy_strerror(nb_res.value)};
    }
    long response_code = 0;
    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) ==
            CURLE_OK &&
        response_code == 530) {
      return {EC::AuthFailed, "FTP authentication failed (530)"};
    }
    if (nb_res.value == CURLE_OPERATION_TIMEDOUT) {
      return {EC::OperationTimeout, curl_easy_strerror(nb_res.value)};
    }
    return {EC::CommonFailure, curl_easy_strerror(nb_res.value)};
  }

  static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                    void *userp) {
    size_t realsize = size * nmemb;
    auto *mem = (struct MemoryStruct *)userp;

    char *ptr = (char *)realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
      return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
  }

  // Use MLST to get file info (modern method)
  SR try_mlst(const std::string &path, amf interrupt_flag, int timeout_ms,
              int64_t start_time) {
    if (!curl || !multi) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, PathInfo()};
    }

    // Reset curl options
    SetupPath(path);

    // Set MLST command
    struct curl_slist *commands = nullptr;
    std::string command = AMStr::amfmt("MLST {}", MlistPath(path));
    commands = curl_slist_append(commands, command.c_str());

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    // Capture header (MLST response is in header)
    struct MemoryStruct header_chunk;
    header_chunk.memory = (char *)malloc(1);
    header_chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&header_chunk);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_slist_free_all(commands);

    if (!nb_res.ok()) {
      free(header_chunk.memory);
      return {NBResultToECM(nb_res), PathInfo()};
    }

    if (nb_res.value != CURLE_OK) {
      free(header_chunk.memory);
      ECM rcm = {GetFTPErrorCode(nb_res.value),
                 AMStr::amfmt("MLST {} error: {}", path,
                              curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, rcm.first, path, "MLST", rcm.second);
      return {rcm, PathInfo()};
    }

    // Parse response
    std::string response(header_chunk.memory, header_chunk.size);
    free(header_chunk.memory);

    // Find line starting with 250- (MLST data line) or direct facts line
    // Format:
    // 250- Listing path
    //  type=file;size=123; filename    <- note leading space
    // 250 End
    PathInfo info;
    std::istringstream iss(response);
    std::string line;
    bool found = false;

    while (std::getline(iss, line)) {
      // Remove \r
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }

      // MLST data line starts with a space
      if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
        line = line.substr(1); // Remove leading space
        info = ParseMLSTLine(line, path);
        found = true;
        break;
      }
    }

    if (!found || info.type == PathType::Unknown) {
      return {ECM{EC::CommonFailure, "Failed to parse MLST response"},
              PathInfo()};
    }

    return {ECM{EC::Success, ""}, info};
  }

  // Legacy stat method (fallback)
  // Steps: 1) try as directory 2) try SIZE to get file info
  SR stat_legacy(const std::string &path, amf interrupt_flag, int timeout_ms,
                 int64_t start_time) {

    // Step 1: try as directory (judge by listing)
    ECM ecm = SetupPath(path, true);
    if (ecm.first != EC::Success) {
      return {ecm, PathInfo()};
    }

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);
    free(chunk.memory);
    if (nb_res.ok() && nb_res.value == CURLE_OK) {
      PathInfo info;
      info.path = path;
      info.name = AMPathStr::basename(path);
      info.dir = AMPathStr::dirname(path);
      info.type = PathType::DIR;
      info.size = 0;
      return {ECM{EC::Success, ""}, info};
    }

    if (!nb_res.ok()) {
      return {NBResultToECM(nb_res), {}};
    }

    // Step 2: try as file (NOBODY mode triggers SIZE)
    // SIZE returns error for nonexistent file, not 0
    ecm = SetupPath(path, false);
    if (ecm.first != EC::Success) {
      return {ecm, {}};
    }

    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);

    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);
    free(chunk.memory);

    // Handle interrupt/timeout
    if (!nb_res.ok()) {
      return {NBResultToECM(nb_res), {}};
    }

    // SIZE success -> file
    if (nb_res.value == CURLE_OK) {
      PathInfo info;
      info.path = path;
      info.name = AMPathStr::basename(path);
      info.dir = AMPathStr::dirname(path);
      info.type = PathType::FILE;

      curl_off_t filesize = 0;
      curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &filesize);
      info.size = filesize >= 0 ? static_cast<size_t>(filesize) : 0;

      long filetime = 0;
      curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      if (filetime > 0) {
        info.modify_time = static_cast<double>(filetime);
      }

      return {ECM{EC::Success, ""}, info};
    }

    // SIZE failed -> path does not exist
    return {ECM{GetFTPErrorCode(nb_res.value),
                AMStr::amfmt("legacy_stat {} error: {}", path,
                             curl_easy_strerror(nb_res.value))},
            {}};
  }

  // Use MLSD to list directory (modern method)
  std::pair<ECM, std::vector<PathInfo>> try_mlsd(const std::string &path,
                                                 amf interrupt_flag,
                                                 int timeout_ms,
                                                 int64_t start_time) {
    if (!curl || !multi) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, {}};
    }
    // Use MLSD URL format
    SetupPath(path, true);

    // Use MLSD custom request
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "MLSD");

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);

    // Reset custom request
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, nullptr);

    if (!nb_res.ok()) {
      free(chunk.memory);
      return {NBResultToECM(nb_res), {}};
    }

    if (nb_res.value != CURLE_OK) {
      free(chunk.memory);
      long response_code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

      // 500/502 = command unsupported, 550 = directory does not exist
      if (response_code == 500 || response_code == 502 ||
          nb_res.value == CURLE_QUOTE_ERROR ||
          nb_res.value == CURLE_FTP_COULDNT_RETR_FILE) {

        return {ECM{EC::OperationUnsupported, "MLSD not supported"}, {}};
      }
      if (response_code == 550) {

        return {ECM{EC::PathNotExist, AMStr::amfmt("Path not found: {}", path)},
                {}};
      }

      return {ECM{EC::FTPListFailed, curl_easy_strerror(nb_res.value)}, {}};
    }

    // Parse MLSD response
    std::string listing(chunk.memory, chunk.size);
    free(chunk.memory);

    std::vector<PathInfo> file_list;
    std::istringstream iss(listing);
    std::string line;

    // Remove trailing / from path
    std::string dir_path = path;
    if (!dir_path.empty() && dir_path.back() == '/') {
      dir_path.pop_back();
    }

    while (std::getline(iss, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.empty())
        continue;

      PathInfo info = ParseMLSDLine(line, dir_path);
      // Filter invalid entries and . ..
      if (info.type != PathType::Unknown && info.name != "." &&
          info.name != "..") {
        file_list.push_back(info);
      }
    }

    return {ECM{EC::Success, ""}, file_list};
  }

  ECM _librmfile(const std::string &path, amf interrupt_flag = nullptr,
                 int timeout_ms = -1, int64_t start_time = -1) {
    ECM ecm = SetupPath(path);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *commands = nullptr;
    commands =
        curl_slist_append(commands, AMStr::amfmt("DELE {}", path).c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(commands);

    if (!nb_res.ok()) {
      return NBResultToECM(nb_res);
    }
    if (nb_res.value != CURLE_OK) {
      ECM ecm = {GetFTPErrorCode(nb_res.value),
                 AMStr::amfmt("rmfile {} failed: {}", path,
                              curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, ecm.first, path, "rmfile", ecm.second);
      return ecm;
    }
    return {EC::Success, ""};
  }

  ECM _librmdir(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1, int64_t start_time = -1) {

    ECM ecm = SetupPath("", true);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *commands = nullptr;
    std::string rmd_cmd = AMStr::amfmt("RMD {}", MlistPath(path));
    commands = curl_slist_append(commands, rmd_cmd.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(commands);

    if (!nb_res.ok()) {
      return NBResultToECM(nb_res);
    }
    if (nb_res.value != CURLE_OK) {
      ECM ecm = {GetFTPErrorCode(nb_res.value),
                 AMStr::amfmt("rmdir {} failed: {}", path,
                              curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, ecm.first, path, "rmdir", ecm.second);
      return ecm;
    }
    return {EC::Success, ""};
  }

public:
  std::shared_ptr<AMFTPClient> mirror_client = nullptr;

  AMFTPClient(const ConRequest &request, ssize_t buffer_capacity = 10,
              TraceCallback trace_cb = {}, AuthCallback auth_cb = {})
      : BaseClient(request, buffer_capacity, std::move(trace_cb)),
        auth_cb_(std::move(auth_cb)) {
    this->res_data.protocol = ClientProtocol::FTP;
    auth_cb_enabled_ = static_cast<bool>(auth_cb_);

    if (res_data.username.empty()) {
      res_data.username = "anonymous";
      res_data.password = res_data.password.empty() ? "anonymous@example.com"
                                                    : res_data.password;
    }
    this->url = AMStr::amfmt("ftp://{}:{}", res_data.hostname,
                             std::to_string(res_data.port));
  }

  ~AMFTPClient() {
    if (multi) {
      if (curl) {
        curl_multi_remove_handle(multi, curl);
      }
      curl_multi_cleanup(multi);
    }
    if (curl) {
      curl_easy_cleanup(curl);
    }
    AMAuth::SecureZero(session_password_plain_);
  }

  ECM SetupPath(const std::string &path, bool is_dir = false) {
    if (!curl) {
      return {EC::NoConnection, "CURL not initialized"};
    }
    if (session_password_plain_.empty() && !res_data.password.empty()) {
      session_password_plain_ = AMAuth::DecryptPassword(res_data.password);
    }
    std::string path_f = path;
    if (!path_f.empty()) {
      path_f = MlistPath(path, is_dir);
    }
    curl_easy_reset(curl);
    current_url = AMStr::amfmt("{}{}", this->url, path_f);
    curl_easy_setopt(curl, CURLOPT_URL, current_url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, res_data.username.c_str());
    const std::string &password_to_use = session_password_plain_.empty()
                                             ? res_data.password
                                             : session_password_plain_;
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password_to_use.c_str());
    return {EC::Success, ""};
  }

  CURL *GetCURL() { return curl; }

  ECM Connect(bool force = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (connected && !force && Check().first == EC::Success) {
      return {EC::Success, ""};
    }

    if (connected && force) {
      connected = false;
      AMAuth::SecureZero(session_password_plain_);
      // Clean up old handles
      if (multi) {
        if (curl) {
          curl_multi_remove_handle(multi, curl);
        }
        curl_multi_cleanup(multi);
        multi = nullptr;
      }
      if (curl) {
        curl_easy_cleanup(curl);
        curl = nullptr;
      }
    }

    if (session_password_plain_.empty() && !res_data.password.empty()) {
      session_password_plain_ = AMAuth::DecryptPassword(res_data.password);
    }

    curl = curl_easy_init();
    if (!curl) {
      return {EC::NoConnection, "CURL easy init failed"};
    }
    multi = curl_multi_init();
    if (!multi) {
      curl_easy_cleanup(curl);
      curl = nullptr;
      return {EC::NoConnection, "CURL multi init failed"};
    }

    auto NotifyAuth = [&](bool need_password, const std::string &password_enc,
                          bool password_correct) {
      if (!auth_cb_enabled_) {
        return;
      }
      ConRequest request = res_data;
      request.password = password_correct ? password_enc : "";
      CallCallbackSafe(auth_cb_, AuthCBInfo(need_password, std::move(request),
                                            password_enc, password_correct));
    };

    ECM rcm = Check(interrupt_flag, timeout_ms, start_time);

    if (rcm.first == EC::AuthFailed && auth_cb_enabled_) {
      int trials = 0;
      while (trials < 2 && rcm.first == EC::AuthFailed) {
        auto [password_opt, rcm2] =
            CallCallbackSafeRet<std::optional<std::string>>(
                auth_cb_, AuthCBInfo(true, res_data, "", false));
        if (!password_opt.has_value() || rcm2.first != EC::Success) {
          break;
        }

        std::string password_plain = std::move(*password_opt);
        std::string password_enc = AMAuth::EncryptPassword(password_plain);
        res_data.password = password_enc;
        session_password_plain_ = std::move(password_plain);

        rcm = Check(interrupt_flag, timeout_ms, start_time);
        if (rcm.first == EC::Success) {
          NotifyAuth(false, password_enc, true);
          break;
        }
        NotifyAuth(false, password_enc, false);
        AMAuth::SecureZero(session_password_plain_);
        session_password_plain_.clear();
        trials++;
      }
    } else if (rcm.first == EC::Success && auth_cb_enabled_ &&
               !res_data.password.empty()) {
      NotifyAuth(false, res_data.password, true);
    }

    if (rcm.first != EC::Success) {
      return rcm;
    }
    // Get home directory using PWD command
    home_dir = "/";
    SetState({EC::Success, ""});
    trace(TraceLevel::Info, EC::Success, nickname, "Connect",
          "Connect success");
    connected.store(true, std::memory_order_relaxed);
    return rcm;
  }

  // return in uint ms, -1 for error
  double GetRTT(ssize_t times = 5, amf interrupt_flag = nullptr) override {
    if (times <= 0) {
      times = 1;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!curl || !multi) {
      return -1.0;
    }
    amf flag = interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::vector<double> rtts;
    rtts.reserve(static_cast<size_t>(times));

    for (ssize_t i = 0; i < times; i++) {
      if (flag && !flag->IsRunning()) {
        break;
      }
      ECM ecm = SetupPath("", true);
      if (ecm.first != EC::Success) {
        return -1.0;
      }
      struct MemoryStruct chunk;
      chunk.memory = (char *)malloc(1);
      chunk.size = 0;
      curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

      double start_time = am_s();
      auto nb_res = nb_perform(flag, -1, start_time);
      double end_time = am_s();
      free(chunk.memory);

      if (nb_res.ok() && nb_res.value == CURLE_OK) {
        rtts.push_back(end_time - start_time);
      } else if (nb_res.status == WaitResult::Interrupted) {
        break;
      }
    }

    if (rtts.empty()) {
      return -1.0;
    }
    double sum = 0.0;
    for (double v : rtts) {
      sum += v;
    }
    return sum * (double)1000.0 / static_cast<double>(rtts.size());
  }

  ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
            int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx); // Prevent concurrent curl access
    ECM ecm = SetupPath("", true);
    if (ecm.first != EC::Success) {
      return ecm;
    }
    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);
    free(chunk.memory);
    if (!nb_res.ok()) {
      return NBResultToECM(nb_res);
    }

    if (nb_res.ok() && nb_res.value == CURLE_OK) {
      return {EC::Success, ""};
    }
    ecm = {GetFTPErrorCode(nb_res.value),
           AMStr::amfmt("Check error: {}", curl_easy_strerror(nb_res.value))};
    trace(TraceLevel::Error, ecm.first, "/", "Check", ecm.second);
    return ecm;
  }

  SR stat(const std::string &path, bool trace_link = false,
          amf interrupt_flag = nullptr, int timeout_ms = -1,
          int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (!curl) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, PathInfo()};
    }

    if (trace_link) {
      return {ECM{EC::UnImplentedMethod,
                  "Trace link is not supported in FTP Client"},
              PathInfo()};
    }

    if (interrupt_flag && !interrupt_flag->IsRunning()) {
      return {ECM{EC::Terminate, "Interrupted by user"}, PathInfo()};
    }

    // Prefer MLST (modern method)
    /*
    if (mlst_supported.load(std::memory_order_relaxed)) {
      auto [ecm, info] =
          try_mlst(pathf, interrupt_flag, timeout_ms, start_time);

      if (ecm.first == EC::Success) {
        mlst_checked.store(true, std::memory_order_relaxed);
        return {ecm, info};
      }

      // MLST unsupported; mark and fall back
      if (ecm.first == EC::OperationUnsupported) {
        mlst_supported.store(false, std::memory_order_relaxed);
        mlst_checked.store(true, std::memory_order_relaxed);
        // Continue using legacy method
      } else if (ecm.first == EC::Terminate ||
                 ecm.first == EC::OperationTimeout) {
        // Interrupted or timed out; return directly
        return {ecm, PathInfo()};
      } else if (ecm.first == EC::PathNotExist) {
        // Path does not exist

        return {ecm, PathInfo()};
      }
      // Other errors also fall back to legacy method
    }*/
    auto [rcm, info] =
        stat_legacy(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first == EC::Success) {
      return {rcm, info};
    }
    trace(TraceLevel::Error, rcm.first, path, "stat", rcm.second);
    return {rcm, {}};
  }

  std::pair<ECM, std::vector<PathInfo>>
  listdir_combine(const std::string &path, amf interrupt_flag = nullptr,
                  int max_time_ms = -1, int64_t start_time = -1) {
    if (start_time == -1) {
      start_time = am_ms();
    }
    std::string pathf = path;
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, AMStr::amfmt("Invalid path: {}", path)}, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;

    if (!curl) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, {}};
    }

    if (interrupt_flag && !interrupt_flag->IsRunning()) {
      return {ECM{EC::Terminate, "Interrupted by user"}, {}};
    }

    // Prefer MLSD (modern method)
    if (false) {
      auto [ecm, file_list] =
          try_mlsd(pathf, interrupt_flag, max_time_ms, start_time);

      if (ecm.first == EC::Success) {
        mlst_checked.store(true, std::memory_order_relaxed);
        return {ecm, file_list};
      }

      // MLSD unsupported; mark and fall back
      if (ecm.first == EC::OperationUnsupported) {
        mlst_supported.store(false, std::memory_order_relaxed);
        mlst_checked.store(true, std::memory_order_relaxed);
        // Continue using legacy method
      } else if (ecm.first == EC::Terminate ||
                 ecm.first == EC::OperationTimeout) {
        // Interrupted or timed out; return directly
        return {ecm, {}};
      } else if (ecm.first == EC::PathNotExist) {
        // Path does not exist
        return {ecm, {}};
      }
      // Other errors also fall back to legacy method
    }

    // Legacy method
    return listdir(pathf, interrupt_flag, max_time_ms, start_time);
  }

  // Legacy LIST method (fallback)
  std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1, int64_t start_time = -1) override {
    ECM ecm = SetupPath(path, true);

    if (ecm.first != EC::Success) {
      return {ecm, {}};
    }
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);

    if (!nb_res.ok()) {
      free(chunk.memory);
      return {NBResultToECM(nb_res), {}};
    }

    if (nb_res.value != CURLE_OK) {
      free(chunk.memory);
      ECM rcm = ECM{
          GetFTPErrorCode(nb_res.value),
          AMStr::amfmt("List failed: {}", curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, rcm.first, path, "listdir", rcm.second);
      return {rcm, {}};
    }

    std::string listing(chunk.memory, chunk.size);
    free(chunk.memory);

    std::vector<PathInfo> file_list;
    std::istringstream iss(listing);
    std::string line;

    while (std::getline(iss, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }

      if (line.empty())
        continue;
      PathInfo info = ParseListLine(line, path);
      if (info.type != PathType::Unknown && info.name != "." &&
          info.name != "..") {
        file_list.push_back(info);
      }
    }

    return {ECM{EC::Success, ""}, file_list};
  }

  // Define iwalk in base class since almost all iwalks are based on listdir
  void _iwalk(const PathInfo &info, WRV &result, RMR &errors,
              bool show_all = false, bool ignore_special_file = true,
              AMFS::WalkErrorCallback error_callback = nullptr,
              amf interrupt_flag = nullptr, int timeout_ms = -1,
              int64_t start_time = -1) {

    auto [rcm2, list_info] =
        listdir(info.path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      if (rcm2.first != EC::OperationTimeout) {
        if (error_callback && *error_callback) {
          (*error_callback)(info.path, rcm2);
        }
        errors.emplace_back(info.path, rcm2);
      }
      return;
    }

    const bool filter_hidden = !show_all;
    const bool filter_special = !show_all && ignore_special_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };
    bool no_subdir = true;
    for (auto &item : list_info) {
      if (interrupt_flag && !interrupt_flag->IsRunning()) {
        return;
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        return;
      }
      if (filter_hidden && is_hidden_name(item.name)) {
        continue;
      }
      if ((item.type != PathType::DIR)) {
        if (filter_special && static_cast<int>(item.type) < 0) {
          continue;
        }
        result.push_back(item);
        continue;
      }
      no_subdir = false;
      _iwalk(item, result, errors, show_all, ignore_special_file,
             error_callback);
    }

    if (no_subdir) {
      result.push_back(info);
      return;
    }
  }

  std::pair<ECM, WRI> iwalk(const std::string &path, bool show_all = false,
                            bool ignore_special_file = true,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) override {
    if (start_time == -1) {
      start_time = am_ms();
    }

    if (path.empty()) {
      ECM out = {EC::InvalidArg, "Invalid empty path"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      return {out, {WRV{}, RMR{}}};
    }
    WRV result = {};
    RMR errors = {};
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      errors.emplace_back(path, rcm);
      return {rcm, {WRV{}, errors}};
    } else if (info.type != PathType::DIR) {
      return {{EC::Success, ""}, {WRV{info}, errors}};
    }
    _iwalk(info, result, errors, show_all, ignore_special_file, error_callback,
           interrupt_flag, timeout_ms, start_time);
    if (interrupt_flag && !interrupt_flag->IsRunning()) {
      ECM out = {EC::Terminate, "iwalk interrupted by user"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      return {out, {result, errors}};
    }
    return {ECM{EC::Success, ""}, {result, errors}};
  }

  void _walk(const std::vector<std::string> &parts, WRD &result, RMR &errors,
             int cur_depth = 0, int max_depth = -1, bool show_all = false,
             bool ignore_special_file = true,
             AMFS::WalkErrorCallback error_callback = nullptr,
             amf interrupt_flag = nullptr, int timeout_ms = -1,
             int64_t start_time = -1) {
    if (max_depth != -1 && cur_depth > max_depth) {
      return;
    }
    std::string pathf = AMPathStr::join(parts);
    auto [rcm2, list_info] =
        listdir(pathf, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      if (rcm2.first != EC::OperationTimeout) {
        if (error_callback && *error_callback) {
          (*error_callback)(pathf, rcm2);
        }
        errors.emplace_back(pathf, rcm2);
      }
      return;
    }
    if (list_info.empty()) {
      result.push_back({parts, {}});
      return;
    }

    const bool filter_hidden = !show_all;
    const bool filter_special = !show_all && ignore_special_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };
    std::vector<PathInfo> files_info = {};
    for (auto &info : list_info) {
      if (interrupt_flag && !interrupt_flag->IsRunning()) {
        return;
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        return;
      }
      if (filter_hidden && is_hidden_name(info.name)) {
        continue;
      }
      if (info.type == PathType::DIR) {
        auto new_parts = parts;
        new_parts.push_back(info.name);
        _walk(new_parts, result, errors, cur_depth + 1, max_depth, show_all,
              ignore_special_file, error_callback, interrupt_flag, timeout_ms,
              start_time);
      } else {
        if (filter_special && static_cast<int>(info.type) < 0) {
          continue;
        }
        files_info.push_back(info);
      }
    }
    if (!files_info.empty()) {
      result.emplace_back(parts, files_info);
    }
  }

  std::pair<ECM, WRDR> walk(const std::string &path, int max_depth = -1,
                            bool show_all = false,
                            bool ignore_special_file = true,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, br] = stat(path, false, interrupt_flag, timeout_ms, start_time);
    RMR errors = {};
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      errors.emplace_back(path, rcm);
      return {rcm, {WRD{}, errors}};
    }
    WRD result_dict = {};
    std::vector<std::string> parts = {path};
    _walk(parts, result_dict, errors, 0, max_depth, show_all,
          ignore_special_file, error_callback, interrupt_flag, timeout_ms,
          start_time);
    if (interrupt_flag && !interrupt_flag->IsRunning()) {
      ECM out = {EC::Terminate, "Interrupted by user, no action conducted"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      return {out, {result_dict, errors}};
    }
    return {ECM{EC::Success, ""}, {result_dict, errors}};
  }
  ECM mkdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1, int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    // Check if already exists
    //
    // Use MKD command to create directory
    ECM ecm = SetupPath("", true);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *commands = nullptr;
    commands = curl_slist_append(
        commands, AMStr::amfmt("MKD {}", MlistPath(path, true)).c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(commands);

    if (!nb_res.ok()) {
      return NBResultToECM(nb_res);
    }
    if (nb_res.value != CURLE_OK) {
      ecm = {GetFTPErrorCode(nb_res.value),
             AMStr::amfmt("mkdir {} failed: {}", path,
                          curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, ecm.first, path, "mkdir", ecm.second);
      return ecm;
    }
    return {EC::Success, ""};
  }

  ECM mkdirs(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
    auto parts = AMPathStr::split(path);
    if (parts.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    if (parts.size() == 1) {
      return mkdir(path, interrupt_flag, timeout_ms, start_time);
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    std::string current_path = parts.front();
    for (size_t i = 1; i < parts.size(); i++) {
      current_path = AMPathStr::join(current_path, parts[i]);
      ECM ecm = mkdir(current_path, interrupt_flag, timeout_ms, start_time);
      if (ecm.first != EC::Success) {
        return ecm;
      }
    }
    return {EC::Success, ""};
  }

  ECM rmfile(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (info.type != PathType::FILE) {
      return {EC::NotAFile, AMStr::amfmt("Path is not a file: {}", path)};
    }
    return _librmfile(path);
  }

  ECM rmdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1, int64_t start_time = -1) override {
    if (start_time == -1) {
      start_time = am_ms();
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (path.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    auto [rcm, info] = stat(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (info.type != PathType::DIR) {
      return {EC::NotADirectory,
              AMStr::amfmt("Path is not a directory: {}", path)};
    }
    return _librmdir(path, interrupt_flag, timeout_ms, start_time);
  }

  void _rm(const PathInfo &info, RMR &errors,
           AMFS::WalkErrorCallback error_callback = nullptr,
           amf interrupt_flag = nullptr, int timeout_ms = -1,
           int64_t start_time = -1) {
    if (info.type != PathType::DIR) {
      ECM rc = _librmfile(info.path, interrupt_flag, timeout_ms, start_time);
      if (rc.first != EC::Success) {
        errors.emplace_back(info.path, rc);
      }
      return;
    }
    auto [rcm2, file_list] =
        listdir(info.path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(info.path, rcm2);
      }
      errors.emplace_back(info.path, rcm2);
      return;
    }
    for (const auto &itemf : file_list) {
      if (interrupt_flag && !interrupt_flag->IsRunning()) {
        return;
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        return;
      }
      _rm(itemf, errors, error_callback, interrupt_flag, timeout_ms,
          start_time);
    }
    // Delete directory after removing all contents
    ECM rc = _librmdir(info.path, interrupt_flag, timeout_ms, start_time);
    if (rc.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(info.path, rc);
      }
      errors.emplace_back(info.path, rc);
    }
  }

  std::pair<ECM, RMR> remove(const std::string &path,
                             AMFS::WalkErrorCallback error_callback = nullptr,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    RMR errors = {};
    auto [rcm, info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      return {rcm, {}};
    }
    _rm(info, errors, error_callback, interrupt_flag, timeout_ms, start_time);
    return {ECM{EC::Success, ""}, errors};
  }

  ECM rename(const std::string &src, const std::string &dst, bool mkdir = true,
             bool overwrite = false, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
    if (start_time == -1) {
      start_time = am_ms();
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);

    std::string srcf = AMFS::abspath(src, true, home_dir, home_dir);
    std::string dstf = AMFS::abspath(dst, true, home_dir, home_dir);
    if (srcf.empty() || dstf.empty()) {
      return {EC::InvalidArg,
              AMStr::amfmt("Invalid path: {} or {}", srcf, dstf)};
    }

    // Check source exists
    auto [rcm, sbr] = stat(srcf, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return rcm;
    }

    // Check destination
    auto [rcm2, sbr2] =
        stat(dstf, false, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first == EC::Success) {
      if (sbr2.type != sbr.type) {
        return {EC::PathAlreadyExists,
                AMStr::amfmt(
                    "Dst already exists and is not the same type as src: {} ",
                    dstf)};
      }
      if (!overwrite) {
        return {EC::PathAlreadyExists,
                AMStr::amfmt("Dst already exists: {} and overwrite is false",
                             dstf)};
      }
    } else {
      if (mkdir) {
        ECM ecm = mkdirs(AMPathStr::dirname(dstf), interrupt_flag, timeout_ms,
                         start_time);
        if (ecm.first != EC::Success) {
          return ecm;
        }
      }
    }

    // Use RNFR and RNTO commands via QUOTE
    std::string url = AMStr::amfmt("{}{}", this->url, "/");
    ECM ecm = SetupPath(url, sbr.type == PathType::DIR);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *headerlist = nullptr;
    std::string rnfr_cmd = "RNFR " + MlistPath(srcf, sbr.type == PathType::DIR);
    std::string rnto_cmd = "RNTO " + MlistPath(dstf, sbr.type == PathType::DIR);
    headerlist = curl_slist_append(headerlist, rnfr_cmd.c_str());
    headerlist = curl_slist_append(headerlist, rnto_cmd.c_str());

    // Use POSTQUOTE instead of QUOTE - commands run after the transfer
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, headerlist);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);
    if (!nb_res.ok()) {
      return NBResultToECM(nb_res);
    }
    CURLcode res = nb_res.value;

    // Clean up
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(headerlist);

    if (res != CURLE_OK) {
      return {EC::FTPRenameFailed,
              AMStr::amfmt("Rename failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  // // Upload with ProgressData (legacy - for AMSFTPWorker)
  // void Upload(const std::string &dst, WkProgressData *pd,
  //             curl_read_callback read_callback) {
  //   std::lock_guard<std::recursive_mutex> lock(mtx);
  //   ECM ecm = SetupPath(dst, false);
  //   if (ecm.first != EC::Success) {
  //     pd->task_info.lock()->cur_task->rcm = ecm;
  //     pd->set_terminate();
  //     return;
  //   }

  //   curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  //   curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
  //   curl_easy_setopt(curl, CURLOPT_READDATA, pd);
  //   curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
  //                    (curl_off_t)pd->task_info.lock()->cur_task->size);
  //   curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS,
  //   CURLFTP_CREATE_DIR);

  //   CURLcode res = curl_easy_perform(curl);

  //   if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
  //     pd->set_terminate();
  //   } else if (res != CURLE_OK) {
  //     pd->task_info.lock()->cur_task->rcm =
  //         ECM{EC::FTPUploadFailed,
  //             AMStr::amfmt("Upload failed: {}", curl_easy_strerror(res))};
  //     pd->set_terminate();
  //   }
  // }

  // // Download with ProgressData (legacy - for AMSFTPWorker)
  // void Download(const std::string &src, curl_write_callback write_callback,
  //               WkProgressData *pd) {
  //   std::lock_guard<std::recursive_mutex> lock(mtx);
  //   ECM ecm = SetupPath(src, false);
  //   if (ecm.first != EC::Success) {
  //     pd->task_info.lock()->cur_task->rcm = ecm;
  //     pd->set_terminate();
  //     return;
  //   }
  //   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  //   curl_easy_setopt(curl, CURLOPT_WRITEDATA, pd);
  //   CURLcode res = curl_easy_perform(curl);
  //   if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
  //     pd->set_terminate();
  //   } else if (res != CURLE_OK) {
  //     pd->task_info.lock()->cur_task->rcm =
  //         ECM{EC::FTPDownloadFailed,
  //             AMStr::amfmt("Download failed: {}", curl_easy_strerror(res))};
  //     pd->set_terminate();
  //   }
  // }
};

