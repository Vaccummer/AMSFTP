#pragma once
// Standard library
#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>

// Internal dependencies
#include "domain/client/ClientPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/client/common/Base.hpp"

// Internal dependencies

// Third-party libraries
#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace AMInfra::client::FTP {
class AMFTPIOCore;
constexpr const char *const kFTPHomeDir = "/";
struct MemoryStruct {
  char *memory;
  size_t size;
};

namespace {
constexpr int kMaxPollTimeoutMs = 2000;

double ParseMListTime_(const std::string &value) {
  if (value.length() < 14) {
    return 0.0;
  }
  try {
    struct tm tm = {};
    tm.tm_year = std::stoi(value.substr(0, 4)) - 1900;
    tm.tm_mon = std::stoi(value.substr(4, 2)) - 1;
    tm.tm_mday = std::stoi(value.substr(6, 2));
    tm.tm_hour = std::stoi(value.substr(8, 2));
    tm.tm_min = std::stoi(value.substr(10, 2));
    tm.tm_sec = std::stoi(value.substr(12, 2));
    return static_cast<double>(mktime(&tm));
  } catch (...) {
    return 0.0;
  }
}

bool SplitMLSDFactsAndName_(const std::string &line, std::string *facts,
                            std::string *filename) {
  if (!facts || !filename) {
    return false;
  }

  std::string linef = line;
  if (!linef.empty() && linef.back() == '\r') {
    linef.pop_back();
  }
  const size_t first_non_space = linef.find_first_not_of(" \t");
  if (first_non_space == std::string::npos) {
    return false;
  }
  linef = linef.substr(first_non_space);

  const size_t split_pos = linef.find_first_of(" \t");
  if (split_pos == std::string::npos) {
    return false;
  }

  const size_t name_pos = linef.find_first_not_of(" \t", split_pos);
  if (name_pos == std::string::npos) {
    return false;
  }

  *facts = linef.substr(0, split_pos);
  *filename = linef.substr(name_pos);
  return (!facts->empty() && !filename->empty());
}

size_t MListPermToUnixMode_(const std::string &perm_text, PathType type) {
  const std::string lowered = AMStr::lowercase(perm_text);
  auto has = [&lowered](char c) {
    return lowered.find(c) != std::string::npos;
  };

  bool can_read = false;
  bool can_write = false;
  bool can_exec = false;

  if (type == PathType::DIR) {
    can_read = has('l');
    can_exec = has('e');
    can_write = has('c') || has('m') || has('p') || has('f') || has('d');
  } else if (type == PathType::FILE) {
    can_read = has('r');
    can_write = has('w') || has('a') || has('d') || has('f');
    can_exec = false;
  } else {
    can_read = has('r') || has('l');
    can_exec = has('e');
    can_write = has('w') || has('a') || has('d') || has('f') || has('c') ||
                has('m') || has('p');
  }

  size_t mode = 0;
  if (can_read) {
    mode |= 0400;
  }
  if (can_write) {
    mode |= 0200;
  }
  if (can_exec) {
    mode |= 0100;
  }
  return mode;
}

void ParseMListFacts_(const std::string &facts, PathInfo *info,
                      bool treat_cdir_pdir_as_dir) {
  if (!info) {
    return;
  }
  std::string perm_text = "";
  bool has_unix_mode = false;

  for (auto &&segment : facts | std::views::split(';')) {
    std::string fact(segment.begin(), segment.end());
    fact = AMStr::Strip(fact);
    if (fact.empty()) {
      continue;
    }

    const size_t eq_pos = fact.find('=');
    if (eq_pos == std::string::npos) {
      continue;
    }

    const std::string key =
        AMStr::lowercase(AMStr::Strip(fact.substr(0, eq_pos)));
    const std::string value = AMStr::Strip(fact.substr(eq_pos + 1));
    if (value.empty()) {
      continue;
    }

    if (key == "type") {
      const std::string type_value = AMStr::lowercase(value);
      if (type_value == "file") {
        info->type = PathType::FILE;
      } else if (type_value == "dir") {
        info->type = PathType::DIR;
      } else if (type_value == "cdir" || type_value == "pdir") {
        info->type =
            (treat_cdir_pdir_as_dir ? PathType::DIR : PathType::Unknown);
      } else if (type_value.starts_with("os.unix=symlink") ||
                 type_value.starts_with("os.unix=slink")) {
        info->type = PathType::SYMLINK;
      } else {
        info->type = PathType::Unknown;
      }
    } else if (key == "size") {
      try {
        info->size = std::stoull(value);
      } catch (...) {
        info->size = 0;
      }
    } else if (key == "modify") {
      info->modify_time = ParseMListTime_(value);
    } else if (key == "create") {
      info->create_time = ParseMListTime_(value);
    } else if (key == "perm" || key == "perms") {
      perm_text = value;
    } else if (key == "unix.mode") {
      try {
        info->mode_int = std::stoul(value, nullptr, 8);
        info->mode_str = AMStr::ModeTrans(info->mode_int);
        has_unix_mode = true;
      } catch (...) {
      }
    } else if (key == "unix.owner") {
      info->owner = value;
    }
  }

  if (!has_unix_mode && !perm_text.empty()) {
    info->mode_int = MListPermToUnixMode_(perm_text, info->type);
    info->mode_str = AMStr::ModeTrans(info->mode_int);
  }
}

namespace parse {

PathInfo ParseDOSListLine(const std::string &line,
                          const std::string &dir_path) {
  PathInfo info;
  info.type = PathType::Unknown;

  size_t pos = 0;
  while (pos < line.size() && std::isspace(line[pos])) {
    pos++;
  }
  if (pos >= line.size()) {
    return info;
  }

  const size_t date_start = pos;
  const size_t date_end = line.find_first_of(" \t", pos);
  if (date_end == std::string::npos) {
    return info;
  }
  const std::string date_str = line.substr(date_start, date_end - date_start);

  pos = date_end;
  while (pos < line.size() && std::isspace(line[pos])) {
    pos++;
  }
  if (pos >= line.size()) {
    return info;
  }

  const size_t time_start = pos;
  const size_t time_end = line.find_first_of(" \t", pos);
  if (time_end == std::string::npos) {
    return info;
  }
  const std::string time_str = line.substr(time_start, time_end - time_start);

  try {
    int month = 0;
    int day = 0;
    int year = 0;
    if (sscanf_s(date_str.c_str(), "%d-%d-%d", &month, &day, &year) == 3) {
      if (year < 100) {
        year += (year >= 70) ? 1900 : 2000;
      }

      int hour = 0;
      int minute = 0;
      std::array<char, 3> ampm = {0};
      if (sscanf_s(time_str.c_str(), "%d:%d%2s", &hour, &minute, ampm) >= 2) {
        std::string ampm_str(ampm.data());
        std::transform(ampm_str.begin(), ampm_str.end(), ampm_str.begin(),
                       ::toupper);
        if (ampm_str == "PM" && hour != 12) {
          hour += 12;
        } else if (ampm_str == "AM" && hour == 12) {
          hour = 0;
        }

        struct tm tm_time = {};
        tm_time.tm_year = year - 1900;
        tm_time.tm_mon = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min = minute;
        tm_time.tm_sec = 0;
        tm_time.tm_isdst = -1;

        time_t unix_time = mktime(&tm_time);
        if (unix_time != -1) {
          info.modify_time = static_cast<double>(unix_time);
        }
      }
    }
  } catch (...) {
  }

  pos = time_end;
  while (pos < line.size() && std::isspace(line[pos])) {
    pos++;
  }
  if (pos >= line.size()) {
    return info;
  }

  if (line.substr(pos, 5) == "<DIR>") {
    info.type = PathType::DIR;
    info.size = 0;
    pos += 5;
  } else {
    const size_t size_end = line.find_first_of(" \t", pos);
    if (size_end == std::string::npos) {
      return info;
    }
    const std::string size_str = line.substr(pos, size_end - pos);
    try {
      info.size = std::stoull(size_str);
    } catch (...) {
      info.size = 0;
    }
    info.type = PathType::FILE;
    pos = size_end;
  }

  while (pos < line.size() && std::isspace(line[pos])) {
    pos++;
  }
  if (pos >= line.size()) {
    return info;
  }

  std::string name = line.substr(pos);
  while (!name.empty() && (std::isspace(name.back()) || name.back() == '\r')) {
    name.pop_back();
  }
  if (name.empty()) {
    return info;
  }

  info.name = name;
  info.path = AMPath::join(dir_path, name, SepType::Unix);
  info.dir = dir_path;
  return info;
}

PathInfo ParseUnixListLine(const std::string &line,
                           const std::string &dir_path) {
  PathInfo info;
  info.type = PathType::Unknown;

  std::istringstream iss(line);
  std::string perms;
  std::string links;
  std::string owner;
  std::string group;
  std::string size_str;
  std::string month;
  std::string day;
  std::string time_or_year;
  std::string name;

  if (!(iss >> perms >> links >> owner >> group >> size_str >> month >> day >>
        time_or_year)) {
    return info;
  }

  std::getline(iss >> std::ws, name);
  if (!name.empty() && name.back() == '\r') {
    name.pop_back();
  }

  if (!name.empty() && !perms.empty() && perms[0] == 'l') {
    const size_t arrow_pos = name.find(" -> ");
    if (arrow_pos != std::string::npos) {
      name = name.substr(0, arrow_pos);
    }
  }

  info.name = name;
  info.path = AMPath::join(dir_path, name, SepType::Unix);
  info.dir = dir_path;
  info.owner = owner;

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

  try {
    info.size = std::stoull(size_str);
  } catch (...) {
    info.size = 0;
  }

  if (perms.size() > 1) {
    info.mode_str = perms.substr(1);
  }
  return info;
}

PathInfo ParseListLine(const std::string &line, const std::string &dir_path) {
  if (line.empty()) {
    return {};
  }

  size_t first_nonspace = 0;
  while (first_nonspace < line.size() && std::isspace(line[first_nonspace])) {
    first_nonspace++;
  }
  if (first_nonspace >= line.size()) {
    return {};
  }

  const char first_char = line[first_nonspace];
  if (std::isdigit(first_char)) {
    return ParseDOSListLine(line, dir_path);
  }
  if (first_char == 'd' || first_char == '-' || first_char == 'l' ||
      first_char == 'c' || first_char == 'b' || first_char == 'p' ||
      first_char == 's') {
    return ParseUnixListLine(line, dir_path);
  }
  return {};
}

std::string ParseListName(const std::string &line) {
  if (line.empty()) {
    return "";
  }
  std::string linef = line;
  if (!linef.empty() && linef.back() == '\r') {
    linef.pop_back();
  }

  size_t first_nonspace = 0;
  while (first_nonspace < linef.size() &&
         std::isspace(static_cast<unsigned char>(linef[first_nonspace]))) {
    first_nonspace++;
  }
  if (first_nonspace >= linef.size()) {
    return "";
  }

  const char first_char = linef[first_nonspace];
  if (std::isdigit(static_cast<unsigned char>(first_char))) {
    size_t pos = first_nonspace;
    for (int token = 0; token < 3; token++) {
      const size_t token_end = linef.find_first_of(" \t", pos);
      if (token_end == std::string::npos) {
        return "";
      }
      pos = linef.find_first_not_of(" \t", token_end);
      if (pos == std::string::npos) {
        return "";
      }
    }
    std::string name = linef.substr(pos);
    while (!name.empty() &&
           (std::isspace(static_cast<unsigned char>(name.back())) ||
            name.back() == '\r')) {
      name.pop_back();
    }
    return name;
  }

  if (first_char == 'd' || first_char == '-' || first_char == 'l' ||
      first_char == 'c' || first_char == 'b' || first_char == 'p' ||
      first_char == 's') {
    std::istringstream iss(linef.substr(first_nonspace));
    std::string perms;
    std::string links;
    std::string owner;
    std::string group;
    std::string size_str;
    std::string month;
    std::string day;
    std::string time_or_year;
    if (!(iss >> perms >> links >> owner >> group >> size_str >> month >> day >>
          time_or_year)) {
      return "";
    }
    std::string name;
    std::getline(iss >> std::ws, name);
    if (!name.empty() && name.back() == '\r') {
      name.pop_back();
    }
    if (!name.empty() && !perms.empty() && perms[0] == 'l') {
      const size_t arrow_pos = name.find(" -> ");
      if (arrow_pos != std::string::npos) {
        name = name.substr(0, arrow_pos);
      }
    }
    return name;
  }

  return "";
}

PathInfo ParseMLSDLine(const std::string &line, const std::string &dir_path) {
  PathInfo info;
  info.type = PathType::Unknown;

  std::string facts;
  std::string filename;
  if (!SplitMLSDFactsAndName_(line, &facts, &filename)) {
    return info;
  }

  info.name = filename;
  info.dir = dir_path;
  info.path = AMPath::join(dir_path, filename, SepType::Unix);
  ParseMListFacts_(facts, &info, false);

  return info;
}

std::string ParseMLSDName(const std::string &line) {
  std::string facts;
  std::string filename;
  if (!SplitMLSDFactsAndName_(line, &facts, &filename)) {
    return "";
  }
  return filename;
}

PathInfo ParseMLSTLine(const std::string &line, const std::string &path) {
  PathInfo info;
  info.type = PathType::Unknown;
  info.path = path;
  info.name = AMPath::basename(path);
  info.dir = AMPath::dirname(path);

  std::string linef = line;
  if (!linef.empty() && linef.back() == '\r') {
    linef.pop_back();
  }
  const size_t first_non_space = linef.find_first_not_of(" \t");
  if (first_non_space == std::string::npos) {
    return info;
  }
  linef = linef.substr(first_non_space);

  const size_t fact_end = linef.find_first_of(" \t");
  const std::string facts =
      (fact_end == std::string::npos ? linef : linef.substr(0, fact_end));
  ParseMListFacts_(facts, &info, true);
  return info;
}

} // namespace parse

std::string MlistPath(const std::string &path, bool is_dir) {
  std::string pathf = AMPath::UnifyPathSep(path, kFTPHomeDir);
  AMStr::vreplace_all(pathf, " ", "%20");
  while (!pathf.empty() && (pathf.back() == '/' || pathf.back() == '\\')) {
    pathf.pop_back();
  }
  if (is_dir) {
    pathf += kFTPHomeDir;
  }
  if (!pathf.empty() && pathf.front() != '/') {
    pathf = kFTPHomeDir + pathf;
  }
  return pathf;
}

EC CastCurlEC(CURLcode curl_code) {
  switch (curl_code) {
  case CURLE_OK:
    return EC::Success;
  case CURLE_ABORTED_BY_CALLBACK:
    return EC::Terminate;
  case CURLE_OPERATION_TIMEDOUT:
    return EC::OperationTimeout;
  case CURLE_UNSUPPORTED_PROTOCOL:
#ifdef CURLE_NOT_BUILT_IN
  case CURLE_NOT_BUILT_IN:
#endif
    return EC::UnsupportFTPProtocol;
  case CURLE_URL_MALFORMAT:
    return EC::IllegealURLFormat;
  case CURLE_COULDNT_RESOLVE_HOST:
    return EC::DNSResolveError;
#ifdef CURLE_COULDNT_RESOLVE_PROXY
  case CURLE_COULDNT_RESOLVE_PROXY:
    return EC::DNSResolveError;
#endif
  case CURLE_COULDNT_CONNECT:
    return EC::FTPConnectFailed;
  case CURLE_GOT_NOTHING:
  case CURLE_FTP_CANT_RECONNECT:
    return EC::ConnectionLost;
#ifdef CURLE_PEER_FAILED_VERIFICATION
  case CURLE_PEER_FAILED_VERIFICATION:
    return EC::AuthFailed;
#endif
#ifdef CURLE_SSL_CACERT_BADFILE
  case CURLE_SSL_CACERT_BADFILE:
    return EC::AuthFailed;
#endif
#ifdef CURLE_SSL_CRL_BADFILE
  case CURLE_SSL_CRL_BADFILE:
    return EC::AuthFailed;
#endif
#ifdef CURLE_SSL_ISSUER_ERROR
  case CURLE_SSL_ISSUER_ERROR:
    return EC::AuthFailed;
#endif
#ifdef CURLE_SSL_CONNECT_ERROR
  case CURLE_SSL_CONNECT_ERROR:
    return EC::ConnectionLost;
#endif
#ifdef CURLE_REMOTE_ACCESS_DENIED
  case CURLE_REMOTE_ACCESS_DENIED:
    return EC::PermissionDenied;
#endif
  case CURLE_SEND_ERROR:
    return EC::FTPSendError;
  case CURLE_RECV_ERROR:
    return EC::FTPRecvError;
  case CURLE_READ_ERROR:
    return EC::FTPReadError;
  case CURLE_WRITE_ERROR:
    return EC::FTPWriteError;
  case CURLE_UPLOAD_FAILED:
    return EC::FTPUploadFailed;
  case CURLE_PARTIAL_FILE:
    return EC::FTPDownloadFailed;
  case CURLE_FTP_WEIRD_SERVER_REPLY:
#ifdef CURLE_WEIRD_SERVER_REPLY
  case CURLE_WEIRD_SERVER_REPLY:
#endif
#ifdef CURLE_FTP_WEIRD_PASS_REPLY
  case CURLE_FTP_WEIRD_PASS_REPLY:
#endif
#ifdef CURLE_FTP_WEIRD_PASV_REPLY
  case CURLE_FTP_WEIRD_PASV_REPLY:
#endif
#ifdef CURLE_FTP_WEIRD_227_FORMAT
  case CURLE_FTP_WEIRD_227_FORMAT:
#endif
    return EC::IllegealSeverReply;
#ifdef CURLE_FTP_CANT_GET_HOST
  case CURLE_FTP_CANT_GET_HOST:
    return EC::DNSResolveError;
#endif
  case CURLE_FTP_ACCESS_DENIED:
    return EC::PermissionDenied;
  case CURLE_FTP_USER_PASSWORD_INCORRECT:
  case CURLE_LOGIN_DENIED:
    return EC::AuthFailed;
  case CURLE_FTP_QUOTE_ERROR:
  case CURLE_FTP_PRET_FAILED:
    return EC::OperationUnsupported;
  case CURLE_FTP_COULDNT_RETR_FILE:
    return EC::FileNotExist;
#ifdef CURLE_REMOTE_FILE_NOT_FOUND
  case CURLE_REMOTE_FILE_NOT_FOUND:
    return EC::PathNotExist;
#endif
#ifdef CURLE_REMOTE_FILE_EXISTS
  case CURLE_REMOTE_FILE_EXISTS:
    return EC::PathAlreadyExists;
#endif
#ifdef CURLE_REMOTE_DISK_FULL
  case CURLE_REMOTE_DISK_FULL:
    return EC::FilesystemNoSpace;
#endif
#ifdef CURLE_FTP_BAD_FILE_LIST
  case CURLE_FTP_BAD_FILE_LIST:
    return EC::FTPListFailed;
#endif
  case CURLE_OUT_OF_MEMORY:
    return EC::MemAllocError;
#ifdef CURLE_FILE_COULDNT_READ_FILE
  case CURLE_FILE_COULDNT_READ_FILE:
    return EC::LocalFileReadError;
#endif
  default:
    return EC::UnknownError;
  }
}

std::string BuildBaseUrl(const ConRequest &request) {
  return AMStr::fmt("ftp://{}:{}", request.hostname,
                    std::to_string(request.port));
}

size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                           void *userp) {
  size_t realsize = size * nmemb;
  auto *mem = (MemoryStruct *)userp;

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

size_t DiscardWriteCallback(void *contents, size_t size, size_t nmemb,
                            void *userp) {
  (void)contents;
  (void)userp;
  return size * nmemb;
}

OS_TYPE ParseSystResponseToOs(const std::string &response) {
  const std::string lowered = AMStr::lowercase(response);
  if (lowered.empty()) {
    return OS_TYPE::Unknown;
  }
  if (lowered.find("filezilla") != std::string::npos &&
      lowered.find("unix") != std::string::npos) {
    return OS_TYPE::Unix;
  }
  if (lowered.find("windows") != std::string::npos ||
      lowered.find("win32") != std::string::npos ||
      lowered.find("win64") != std::string::npos ||
      lowered.find("ms-dos") != std::string::npos ||
      lowered.find("microsoft") != std::string::npos) {
    return OS_TYPE::Windows;
  }
  if (lowered.find("freebsd") != std::string::npos) {
    return OS_TYPE::FreeBSD;
  }
  if (lowered.find("darwin") != std::string::npos ||
      lowered.find("macos") != std::string::npos ||
      lowered.find("mac os") != std::string::npos) {
    return OS_TYPE::MacOS;
  }
  if (lowered.find("linux") != std::string::npos) {
    return OS_TYPE::Linux;
  }
  if (lowered.find("unix") != std::string::npos ||
      lowered.find("type: l8") != std::string::npos) {
    return OS_TYPE::Unix;
  }
  return OS_TYPE::Unknown;
}

int ResolveCurrentTimeoutMs(CURLM *multi, const ControlComponent &control) {
  int wait_ms = kMaxPollTimeoutMs;

  long curl_wait_ms = -1;
  if (multi != nullptr &&
      curl_multi_timeout(multi, &curl_wait_ms) == CURLM_OK &&
      curl_wait_ms >= 0) {
    wait_ms = wait_ms > curl_wait_ms ? curl_wait_ms : wait_ms;
  }

  const auto remain_opt = control.RemainTime_ms();
  if (remain_opt.has_value()) {
    wait_ms = wait_ms > *remain_opt ? *remain_opt : wait_ms;
  }
  return wait_ms;
}

ECM GetECM(CURL *curl, CURLcode curl_code, const std::string &command,
           bool *has_response_code) {
  if (has_response_code) {
    *has_response_code = false;
  }
  if (curl_code == CURLE_OK) {
    return OK;
  }
  if (curl == nullptr) {
    return {EC::NoConnection, "", "", "curl handle is invalid",
            RawError{RawErrorSource::Curl, static_cast<int>(curl_code)}};
  }

  long response_code = 0;
  if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) ==
          CURLE_OK &&
      response_code > 0) {
    if (has_response_code) {
      *has_response_code = true;
    }
    const std::string cmd = AMStr::lowercase(command);
    EC ec = EC::CommonFailure;
    std::string msg =
        AMStr::fmt("FTP server returned response code {}", response_code);
    switch (response_code) {
    case 421:
      ec = EC::ConnectionLost;
      msg = "FTP server closed control connection (421)";
      break;
    case 425:
    case 426:
      ec = EC::FTPRecvError;
      msg = AMStr::fmt("FTP data transfer failed ({})", response_code);
      break;
    case 430:
    case 530:
    case 532:
      ec = EC::AuthFailed;
      msg = AMStr::fmt("FTP authentication failed ({})", response_code);
      break;
    case 450:
      ec = EC::PathUsingByOthers;
      msg = "FTP file is unavailable (450)";
      break;
    case 451:
      ec = EC::CommonFailure;
      msg = "FTP server aborted operation (451)";
      break;
    case 452:
    case 552:
      ec = EC::FilesystemNoSpace;
      msg = AMStr::fmt("FTP server reports insufficient storage ({})",
                       response_code);
      break;
    case 500:
    case 501:
    case 502:
    case 503:
    case 504:
      ec = EC::OperationUnsupported;
      msg = AMStr::fmt("FTP command is invalid or unsupported ({})",
                       response_code);
      break;
    case 550:
      if (cmd == "mkd" || cmd.starts_with("mkd")) {
        ec = EC::PathAlreadyExists;
        msg = "FTP directory already exists or cannot be created (550)";
      } else {
        ec = EC::PathNotExist;
        msg = "FTP path does not exist or is inaccessible (550)";
      }
      break;
    case 551:
      ec = EC::InvalidArg;
      msg = "FTP request has invalid parameters (551)";
      break;
    case 553:
      ec = EC::InvalidFilename;
      msg = "FTP filename is invalid (553)";
      break;
    default:
      ec = EC::UnknownError;
      msg = AMStr::fmt("Unexpected FTP response code {}", response_code);
      break;
    }
    return {ec, "", "", msg,
            RawError{RawErrorSource::Curl, static_cast<int>(curl_code)}};
  }

  return {CastCurlEC(curl_code), "", "", curl_easy_strerror(curl_code),
          RawError{RawErrorSource::Curl, static_cast<int>(curl_code)}};
}

ECM NBResultToECM(CURL *curl, CURLcode code, const std::string &action,
                  const std::string &target) {
  auto with_context = [&](ECM ecm) -> ECM {
    if (!action.empty()) {
      ecm.operation = action;
    }
    if (!target.empty()) {
      ecm.target = target;
    }
    return ecm;
  };
  if (code == CURLE_OK) {
    return with_context(OK);
  }

  bool has_response_code = false;
  ECM response_mapped = GetECM(curl, code, action, &has_response_code);
  if (has_response_code) {
    long response_code = 0;
    if (curl &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) ==
            CURLE_OK &&
        response_code > 0) {
      response_mapped.raw_error =
          RawError(RawErrorSource::Curl, static_cast<int>(response_code));
    } else {
      response_mapped.raw_error = RawError(RawErrorSource::Curl, 0);
    }
    return with_context(std::move(response_mapped));
  }

  ECM curl_mapped = {CastCurlEC(code), "", "", curl_easy_strerror(code),
                     RawError(RawErrorSource::Curl, static_cast<int>(code))};
  return with_context(std::move(curl_mapped));
}

ECM NBResultRCMToECM(const NBResult<CURLcode> &nb_res,
                     const std::string &operation, const std::string &target) {
  ECM rcm = nb_res.rcm;
  rcm.operation = operation;
  rcm.target = target;
  return rcm;
}

} // namespace

class FTPBase : public ClientIOBase {
protected:
  CURL *curl = nullptr;
  CURLM *multi = nullptr; // Reused multi handle
  mutable std::recursive_mutex mtx;
  std::string current_url = ""; // Keep CURLOPT_URL string lifetime valid

  void trace(AMDomain::client::TraceLevel level, EC error_code,
             const std::string &target = "", const std::string &action = "",
             const std::string &msg = "") const {
    ClientIOBase::trace(TraceInfo(
        level, error_code, config_part_->GetNickname(), target, action, msg,
        config_part_->GetRequest(), AMDomain::client::TraceSource::Client));
  }

  void trace(const ECM &rcm) const {
    if (!rcm) {
      ClientIOBase::trace(TraceInfo(
          AMDomain::client::TraceLevel::Error, rcm.code,
          config_part_->GetNickname(), rcm.target, rcm.operation, rcm.error,
          config_part_->GetRequest(), AMDomain::client::TraceSource::Client));
    }
  }

public:
  FTPBase(AMDomain::client::IClientConfigPort *config_port,
          InterruptControl *control_port, TraceCallback trace_cb = {},
          AuthCallback auth_cb = {})
      : ClientIOBase(config_port, control_port) {
    if (control_port == nullptr) {
      throw std::invalid_argument(
          "AMFTPIOCore requires non-null task control port");
    }
    if (request_atomic_.lock()->protocol != ClientProtocol::FTP) {
      throw std::invalid_argument("AMFTPIOCore requires FTP protocol request");
    }
    RegisterTraceCallback(std::move(trace_cb));
    RegisterAuthCallback(std::move(auth_cb));
    if (config_part_->GetHomeDir().empty()) {
      config_part_->SetHomeDir(kFTPHomeDir);
    }
  }

  ~FTPBase() override {
    if (multi) {
      if (curl) {
        curl_multi_remove_handle(multi, curl);
      }
      curl_multi_cleanup(multi);
    }
    if (curl) {
      curl_easy_cleanup(curl);
    }
  }

  NBResult<CURLcode> NBPerform(const ControlComponent &control) {
    if (!multi || !curl) {
      return {CURLE_FAILED_INIT,
              {EC::NoConnection, "", "", "CURL not initialized"}};
    }

    auto kill_rcm = control.BuildECM();
    if (kill_rcm.has_value()) {
      if ((*kill_rcm).code == EC::OperationTimeout) {
        return {CURLcode::CURLE_OPERATION_TIMEDOUT, (*kill_rcm)};
      } else if ((*kill_rcm).code == EC::Terminate) {
        return {CURLcode::CURLE_ABORTED_BY_CALLBACK, (*kill_rcm)};
      } else {
        return {CURLcode::CURLE_FAILED_INIT, (*kill_rcm)};
      }
    }

    auto stop_request = control.BuildRequestECM();
    if (stop_request.has_value()) {
      if ((*stop_request).code == EC::OperationTimeout) {
        return {CURLcode::CURLE_OPERATION_TIMEDOUT, (*stop_request)};
      } else if ((*stop_request).code == EC::Terminate) {
        return {CURLcode::CURLE_ABORTED_BY_CALLBACK, (*stop_request)};
      } else {
        return {CURLcode::CURLE_FAILED_INIT, (*stop_request)};
      }
    }

    bool handle_added = false;
    CURLMcode add_result = curl_multi_add_handle(multi, curl);
    if (add_result != CURLM_OK) {
      return {CURLE_FAILED_INIT,
              {EC::InvalidHandle, "", "", "Failed to add CURL handle to multi",
               RawError(RawErrorSource::Curl, static_cast<int>(add_result))}};
    }
    handle_added = true;

    struct CurlMultiHandleGuard {
      CURLM *multi;
      CURL *curl;
      bool handle_added;

      ~CurlMultiHandleGuard() {
        if (handle_added && multi && curl) {
          curl_multi_remove_handle(multi, curl);
        }
      }
    } multi_handle_guard(multi, curl, handle_added);

    const sptr<InterruptControl> interrupt =
        stop_request.has_value() ? nullptr : control.InterruptRaw();

    [[maybe_unused]] const InterruptWakeupSafeGuard wakeup_guard(
        interrupt, [this]() {
          if (multi) {
            curl_multi_wakeup(multi);
          }
        });

    int still_running = 1;
    CURLcode result = CURLE_OK;

    while (still_running) {
      CURLMcode mc = curl_multi_perform(multi, &still_running);
      if (mc != CURLM_OK) {
        result = CURLE_FAILED_INIT;
        return {result,
                {EC::InvalidHandle, "", "", "Failed to perform multi handle",
                 RawError(RawErrorSource::Curl, static_cast<int>(mc))}};
      }

      if (!still_running) {
        break;
      }

      int wait_ms = ResolveCurrentTimeoutMs(multi, control);

      int numfds = 0;
      mc = curl_multi_poll(multi, nullptr, 0, wait_ms, &numfds);
      if (mc != CURLM_OK) {
        result = CURLE_FAILED_INIT;
        return {result,
                {EC::InvalidHandle, "", "", "Failed to poll multi handle",
                 RawError(RawErrorSource::Curl, static_cast<int>(mc))}};
        break;
      }

      kill_rcm = control.BuildECM();
      if (kill_rcm.has_value()) {
        if ((*kill_rcm).code == EC::OperationTimeout) {
          return {CURLcode::CURLE_OPERATION_TIMEDOUT, (*kill_rcm)};
        } else if ((*kill_rcm).code == EC::Terminate) {
          return {CURLcode::CURLE_ABORTED_BY_CALLBACK, (*kill_rcm)};
        } else {
          return {CURLcode::CURLE_FAILED_INIT, (*kill_rcm)};
        }
      }
    }

    CURLMsg *msg;
    int msgs_left;
    while ((msg = curl_multi_info_read(multi, &msgs_left))) {
      if (msg->msg == CURLMSG_DONE && msg->easy_handle == curl) {
        result = msg->data.result;
      }
    }

    return {result, {}};
  }

  ECM SetupPath(const std::string &path, bool is_dir = false) {
    ConRequest request = request_atomic_.lock().load();
    if (request.protocol != ClientProtocol::FTP) {
      throw std::invalid_argument("AMFTPIOCore only accepts FTP protocol");
    }
    if (!curl) {
      return {EC::NoConnection, "", "", "CURL not initialized"};
    }

    std::string decrypted_password = "";
    if (!request.password.empty()) {
      decrypted_password = AMAuth::DecryptPassword(request.password);
    }

    std::string path_f = path;
    if (!path_f.empty()) {
      path_f = MlistPath(path, is_dir);
    }

    curl_easy_reset(curl);
    current_url = AMStr::fmt("{}{}", BuildBaseUrl(request), path_f);
    curl_easy_setopt(curl, CURLOPT_URL, current_url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, request.username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, decrypted_password.c_str());
    // Prevent accidental stdout/stderr leakage from libcurl when a call does
    // not install explicit body/header handlers.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, DiscardWriteCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, nullptr);
    return OK;
  }

  std::pair<ECM, std::string> SYST_Query(const ControlComponent &control) {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("SYST_Query", kFTPHomeDir);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm), ""};
    }
    if (auto stop_request = control.BuildRequestECM("SYST_Query", kFTPHomeDir);
        stop_request.has_value()) {
      return {std::move(*stop_request), ""};
    }
    if (!curl || !multi) {
      return {{EC::NoConnection, "", "", "CURL not initialized"}, ""};
    }

    ECM ecm = SetupPath("", true);
    if (ecm.code != EC::Success) {
      return {ecm, ""};
    }

    MemoryStruct header_chunk;
    header_chunk.memory = (char *)malloc(1);
    header_chunk.size = 0;

    struct curl_slist *commands = nullptr;
    commands = curl_slist_append(commands, "SYST");
    curl_easy_setopt(curl, CURLOPT_QUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&header_chunk);

    const auto nb_res = NBPerform(control);

    curl_easy_setopt(curl, CURLOPT_QUOTE, nullptr);
    curl_slist_free_all(commands);

    if (!nb_res) {
      free(header_chunk.memory);
      return {NBResultRCMToECM(nb_res, "SYST_Query", kFTPHomeDir), ""};
    }
    if (nb_res.value != CURLE_OK) {
      free(header_chunk.memory);
      return {NBResultToECM(curl, nb_res.value, "SYST_Query", kFTPHomeDir), ""};
    }

    std::string response(header_chunk.memory, header_chunk.size);
    free(header_chunk.memory);

    std::istringstream iss(response);
    std::string line;
    while (std::getline(iss, line)) {
      line = AMStr::Strip(line);
      if (line.empty()) {
        continue;
      }
      if (line.size() >= 3 &&
          std::isdigit(static_cast<unsigned char>(line[0])) &&
          std::isdigit(static_cast<unsigned char>(line[1])) &&
          std::isdigit(static_cast<unsigned char>(line[2]))) {
        return {OK, line};
      }
    }
    response = AMStr::Strip(response);
    if (!response.empty()) {
      return {OK, response};
    }
    return {{EC::CommonFailure, "", "", "SYST returned empty response"}, ""};
  }

  ECMData<AMFSI::StatResult> MLST_libstat(const AMFSI::StatArgs &args,
                                          const ControlComponent &control) {
    ECM rcm = OK;
    auto stop_rcm = control.BuildRequestECM("MLST_stat", args.path);
    if (stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    const std::string &path = args.path;
    if (!curl || !multi) {
      return {ECM{EC::NoConnection, "", "", "CURL not initialized"}};
    }

    rcm = SetupPath(path, false);
    if (!rcm) {
      return {std::move(rcm)};
    }

    struct curl_slist *commands = nullptr;
    std::string command = AMStr::fmt("MLST {}", MlistPath(path, true));
    commands = curl_slist_append(commands, command.c_str());

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    MemoryStruct header_chunk;
    header_chunk.memory = (char *)malloc(1);
    header_chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&header_chunk);

    auto nb_res = NBPerform(control);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_slist_free_all(commands);

    if (!nb_res) {
      free(header_chunk.memory);
      rcm = NBResultRCMToECM(nb_res, "MLST", path);
      return {std::move(rcm)};
    }
    if (nb_res.value != CURLE_OK) {
      free(header_chunk.memory);
      rcm = NBResultToECM(curl, nb_res.value, "MLST", path);
      trace(rcm);
      return {std::move(rcm)};
    }

    std::string response(header_chunk.memory, header_chunk.size);
    free(header_chunk.memory);

    PathInfo info;
    std::istringstream iss(response);
    std::string line;
    bool found = false;
    while (std::getline(iss, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
        line = line.substr(1);
        info = parse::ParseMLSTLine(line, path);
        found = true;
        break;
      }
    }

    if (!found || info.type == PathType::Unknown) {
      return {ECM{EC::CommonFailure, "MLST", path,
                  "Failed to parse MLST response"}};
    }
    return {AMFSI::StatResult{info}, std::move(rcm)};
  }

  ECMData<AMFSI::StatResult> Common_libstat(const AMFSI::StatArgs &args,
                                            const ControlComponent &control) {
    ECM rcm = OK;
    auto stop_rcm = control.BuildRequestECM("Common_stat", args.path);
    if (stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    const std::string &path = args.path;

    rcm = SetupPath(path, true);
    if (!rcm) {
      return {std::move(rcm)};
    }

    MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = NBPerform(control);
    free(chunk.memory);
    if (nb_res && nb_res.value == CURLE_OK) {
      PathInfo info;
      info.path = path;
      info.name = AMPath::basename(path);
      info.dir = AMPath::dirname(path);
      info.type = PathType::DIR;
      info.size = 0;
      return {AMFSI::StatResult{info}, std::move(rcm)};
    }

    if (!nb_res) {
      rcm = NBResultRCMToECM(nb_res, "Common_libstat", path);
      return {std::move(rcm)};
    }

    rcm = SetupPath(path, false);
    if (!rcm) {
      return {std::move(rcm)};
    }

    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    nb_res = NBPerform(control);
    free(chunk.memory);

    if (!nb_res) {
      rcm = NBResultRCMToECM(nb_res, "Common_libstat", path);
      return {std::move(rcm)};
    }
    if (nb_res.value == CURLE_OK) {
      PathInfo info;
      info.path = path;
      info.name = AMPath::basename(path);
      info.dir = AMPath::dirname(path);
      info.type = PathType::FILE;
      curl_off_t filesize = 0;
      curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &filesize);
      info.size = filesize >= 0 ? static_cast<size_t>(filesize) : 0;
      long filetime = 0;
      curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      if (filetime > 0) {
        info.modify_time = static_cast<double>(filetime);
      }
      return {AMFSI::StatResult{info}, std::move(rcm)};
    }

    // Keep error mapping consistent with other FTP calls so path-not-exist
    // is classified correctly (instead of collapsing to UnknownError).
    rcm = NBResultToECM(curl, nb_res.value, "Common_libstat", path);
    return {std::move(rcm)};
  }

  ECMData<AMFSI::ListResult> MLSD_Listdir(const AMFSI::ListdirArgs &args,
                                          const ControlComponent &control) {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("MLSD_Listdir", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("MLSD_Listdir", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    const std::string &path = args.path;
    if (!curl || !multi) {
      return {ECM{EC::NoConnection, "", "", "CURL not initialized"}};
    }

    rcm = SetupPath(path, true);
    if (!rcm) {
      return {std::move(rcm)};
    }
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "MLSD");

    MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = NBPerform(control);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, nullptr);

    if (!nb_res) {
      free(chunk.memory);
      rcm = NBResultRCMToECM(nb_res, "MLSD_Listdir", path);
      return {std::move(rcm)};
    }
    if (nb_res.value != CURLE_OK) {
      free(chunk.memory);
      return {NBResultToECM(curl, nb_res.value, "MLSD_Listdir", path)};
    }

    std::string listing(chunk.memory, chunk.size);
    free(chunk.memory);

    std::vector<PathInfo> file_list;
    std::istringstream iss(listing);
    std::string line;
    std::string dir_path = path;
    if (!dir_path.empty() && dir_path.back() == '/') {
      dir_path.pop_back();
    }

    while (std::getline(iss, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.empty()) {
        continue;
      }
      PathInfo info = parse::ParseMLSDLine(line, dir_path);
      if (info.type != PathType::Unknown && info.name != "." &&
          info.name != "..") {
        file_list.push_back(info);
      }
    }
    return {AMFSI::ListResult{std::move(file_list)}, std::move(rcm)};
  }

  ECMData<AMFSI::ListResult> Common_Listdir(const AMFSI::ListdirArgs &args,
                                            const ControlComponent &control) {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("Common_Listdir", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request =
            control.BuildRequestECM("Common_Listdir", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    const std::string &path = args.path;
    rcm = SetupPath(path, true);
    if (!rcm) {
      return {std::move(rcm)};
    }

    MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = NBPerform(control);
    if (!nb_res) {
      free(chunk.memory);
      rcm = NBResultRCMToECM(nb_res, "Common_Listdir", path);
      return {std::move(rcm)};
    }
    if (nb_res.value != CURLE_OK) {
      free(chunk.memory);
      rcm = NBResultToECM(curl, nb_res.value, "Common_Listdir", path);
      return {std::move(rcm)};
    }

    std::string listing(chunk.memory, chunk.size);
    free(chunk.memory);

    std::string dir_path = path;
    if (!dir_path.empty() && dir_path.back() == '/') {
      dir_path.pop_back();
    }

    std::vector<PathInfo> file_list;
    std::istringstream iss(listing);
    std::string line;
    while (std::getline(iss, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.empty()) {
        continue;
      }
      PathInfo info = parse::ParseListLine(line, dir_path);
      if (info.type != PathType::Unknown && info.name != "." &&
          info.name != "..") {
        file_list.push_back(info);
      }
    }
    return {AMFSI::ListResult{std::move(file_list)}, std::move(rcm)};
  }

  ECMData<AMFSI::ListNamesResult>
  MLSD_ListNames(const AMFSI::ListNamesArgs &args,
                 const ControlComponent &control) {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("MLSD_ListNames", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request =
            control.BuildRequestECM("MLSD_ListNames", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    const std::string &path = args.path;
    if (!curl || !multi) {
      return {ECM{EC::NoConnection, "", "", "CURL not initialized"}};
    }

    rcm = SetupPath(path, true);
    if (!rcm) {
      return {std::move(rcm)};
    }
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "MLSD");

    MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = NBPerform(control);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, nullptr);

    if (!nb_res) {
      free(chunk.memory);
      rcm = NBResultRCMToECM(nb_res, "MLSD_ListNames", path);
      return {std::move(rcm)};
    }
    if (nb_res.value != CURLE_OK) {
      free(chunk.memory);
      return {NBResultToECM(curl, nb_res.value, "MLSD_ListNames", path)};
    }

    std::string listing(chunk.memory, chunk.size);
    free(chunk.memory);

    std::vector<std::string> names;
    std::istringstream iss(listing);
    std::string line;
    while (std::getline(iss, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.empty()) {
        continue;
      }
      std::string name = parse::ParseMLSDName(line);
      if (!name.empty() && name != "." && name != "..") {
        names.push_back(std::move(name));
      }
    }
    return {AMFSI::ListNamesResult{std::move(names)}, std::move(rcm)};
  }

  ECMData<AMFSI::ListNamesResult>
  Common_ListNames(const AMFSI::ListNamesArgs &args,
                   const ControlComponent &control) {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("Common_ListNames", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request =
            control.BuildRequestECM("Common_ListNames", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    const std::string &path = args.path;
    rcm = SetupPath(path, true);
    if (!rcm) {
      return {std::move(rcm)};
    }

    MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = NBPerform(control);
    if (!nb_res) {
      free(chunk.memory);
      rcm = NBResultRCMToECM(nb_res, "Common_ListNames", path);
      return {std::move(rcm)};
    }
    if (nb_res.value != CURLE_OK) {
      free(chunk.memory);
      rcm = NBResultToECM(curl, nb_res.value, "Common_ListNames", path);
      return {std::move(rcm)};
    }

    std::string listing(chunk.memory, chunk.size);
    free(chunk.memory);

    std::vector<std::string> names;
    std::istringstream iss(listing);
    std::string line;
    while (std::getline(iss, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.empty()) {
        continue;
      }
      std::string name = parse::ParseListName(line);
      if (!name.empty() && name != "." && name != "..") {
        names.push_back(std::move(name));
      }
    }
    return {AMFSI::ListNamesResult{std::move(names)}, std::move(rcm)};
  }

  CURL *GetCURL() { return curl; }

  std::recursive_mutex &TransferMutex() { return mtx; }
};

// FTP Client using libcurl
class AMFTPIOCore : public FTPBase {
private:
  enum class CapabilityState : int {
    Unknown = 0,
    Supported = 1,
    Unsupported = 2,
  };
  CapabilityState mlst_state_ = CapabilityState::Unknown;
  CapabilityState mlsd_state_ = CapabilityState::Unknown;

public:
  std::shared_ptr<AMFTPIOCore> mirror_client = nullptr;

  AMFTPIOCore(AMDomain::client::IClientConfigPort *config_port,
              InterruptControl *control_port, TraceCallback trace_cb = {},
              AuthCallback auth_cb = {})
      : FTPBase(config_port, control_port, std::move(trace_cb),
                std::move(auth_cb)) {}

  ECMData<AMFSI::UpdateOSTypeResult>
  UpdateOSType(const AMFSI::UpdateOSTypeArgs &args,
               const ControlComponent &control) override {
    (void)args;
    ECM rcm = OK;
    if (auto stop_rcm =
            control.BuildECM("UpdateOSType", config_part_->GetNickname());
        stop_rcm.has_value()) {
      return {{OS_TYPE::Unknown}, std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM(
            "UpdateOSType", config_part_->GetNickname());
        stop_request.has_value()) {
      return {{OS_TYPE::Unknown}, std::move(*stop_request)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!curl || !multi) {
      config_part_->SetOSType(OS_TYPE::Unknown);
      return {{config_part_->GetOSType()}, std::move(rcm)};
    }
    auto syst_query = SYST_Query(control);
    rcm = syst_query.first;
    if (rcm.code != EC::Success) {
      config_part_->SetOSType(OS_TYPE::Unknown);
      trace(rcm);
      return {{config_part_->GetOSType()}, std::move(rcm)};
    }
    config_part_->SetOSType(ParseSystResponseToOs(syst_query.second));
    return {{config_part_->GetOSType()}, std::move(rcm)};
  }

  ECMData<AMFSI::UpdateHomeDirResult>
  UpdateHomeDir(const AMFSI::UpdateHomeDirArgs &args,
                const ControlComponent &control) override {
    (void)args;
    (void)control;
    ECMData<AMFSI::UpdateHomeDirResult> out = {};
    config_part_->SetHomeDir(kFTPHomeDir);
    out.data.home_dir = kFTPHomeDir;
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::CheckResult> Check(const AMFSI::CheckArgs &args,
                                    const ControlComponent &control) override {
    (void)args;
    ECM rcm = OK;
    auto out = ECMData<AMFSI::CheckResult>();
    out.data.status = config_part_->GetState().data.status;
    if (auto stop_rcm = control.BuildECM("Check", kFTPHomeDir);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
      return out;
    }
    if (auto stop_request = control.BuildRequestECM("Check", kFTPHomeDir);
        stop_request.has_value()) {
      out.rcm = std::move(*stop_request);
      return out;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    rcm = SetupPath("", true);
    if (!rcm) {
      out.rcm = std::move(rcm);
      if (out.rcm.code == EC::NoConnection) {
        out.data.status = AMDomain::client::ClientStatus::NoConnection;
      } else {
        out.data.status = AMDomain::client::ClientStatus::ConnectionBroken;
      }
      trace(out.rcm);
      return out;
    }
    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    auto nb_res = NBPerform(control);
    free(chunk.memory);
    if (!nb_res) {
      out.rcm = NBResultRCMToECM(nb_res, "Check", kFTPHomeDir);
      if (out.rcm.code == EC::NoConnection) {
        out.data.status = AMDomain::client::ClientStatus::NoConnection;
      } else {
        out.data.status = AMDomain::client::ClientStatus::ConnectionBroken;
      }
      return out;
    }
    if (nb_res.value == CURLE_OK) {
      out.rcm = OK;
      out.data.status = AMDomain::client::ClientStatus::OK;
      return out;
    }
    out.rcm = NBResultToECM(curl, nb_res.value, "Check", kFTPHomeDir);

    if (out.rcm.code == EC::NoConnection) {
      out.data.status = AMDomain::client::ClientStatus::NoConnection;
    } else {
      out.data.status = AMDomain::client::ClientStatus::ConnectionBroken;
    }
    config_part_->SetState({out.rcm, out.data.status});
    trace(out.rcm);
    return out;
  }

  ECMData<AMFSI::ConnectResult>
  Connect(const AMFSI::ConnectArgs &args,
          const ControlComponent &control) override {
    ECMData<AMFSI::ConnectResult> out = {};
    out.data.status = config_part_->GetState().data.status;
    ECM rcm = OK;
    ConRequest request = request_atomic_.lock().load();
    if (request.protocol != ClientProtocol::FTP) {
      throw std::invalid_argument("AMFTPIOCore only accepts FTP protocol");
    }
    const std::string connect_target =
        AMStr::fmt("{}:{}", request.hostname, request.port);
    if (auto stop_rcm = control.BuildECM("Connect", connect_target);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
      return out;
    }
    if (auto stop_request = control.BuildRequestECM("Connect", connect_target);
        stop_request.has_value()) {
      out.rcm = std::move(*stop_request);
      return out;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    connect_state("initialize FTP connection", connect_target);

    const auto state = config_part_->GetState();
    if (!args.force &&
        state.data.status == AMDomain::client::ClientStatus::OK &&
        Check({}, control).rcm.code == EC::Success) {
      out.rcm = OK;
      out.data.status = AMDomain::client::ClientStatus::OK;
      return out;
    }

    if (args.force) {
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

    curl = curl_easy_init();
    if (!curl) {
      out.rcm = {EC::NoConnection, "", "", "CURL easy init failed"};
      out.data.status = AMDomain::client::ClientStatus::NoConnection;
      return out;
    }
    multi = curl_multi_init();
    if (!multi) {
      curl_easy_cleanup(curl);
      curl = nullptr;
      out.rcm = {EC::NoConnection, "", "", "CURL multi init failed"};
      out.data.status = AMDomain::client::ClientStatus::NoConnection;
      return out;
    }

    auto NotifyAuth = [&](bool need_password, const std::string &password_enc,
                          bool password_correct) {
      ConRequest auth_request = request_atomic_.lock().load();
      auth_request.password = password_correct ? password_enc : "";
      (void)auth(AuthCBInfo(need_password, std::move(auth_request),
                            password_enc, password_correct));
    };

    auto check_res = Check({}, control);
    out.rcm = check_res.rcm;
    out.data.status = check_res.data.status;
    if (out.rcm.code == EC::AuthFailed) {
      int trials = 0;
      while (trials < 2 && out.rcm.code == EC::AuthFailed) {
        auto password_opt =
            auth(AuthCBInfo(true, request_atomic_.lock().load(), "", false));
        if (!password_opt.has_value()) {
          break;
        }

        std::string password_plain = std::move(*password_opt);
        std::string password_enc = AMAuth::EncryptPassword(password_plain);
        request.password = password_enc;
        request_atomic_.lock().store(request);

        check_res = Check({}, control);
        out.rcm = check_res.rcm;
        out.data.status = check_res.data.status;
        if (out.rcm.code == EC::Success) {
          NotifyAuth(false, password_enc, true);
          break;
        }
        NotifyAuth(false, password_enc, false);
        trials++;
      }
    } else if (out.rcm.code == EC::Success) {
      request = request_atomic_.lock().load();
      if (!request.password.empty()) {
        NotifyAuth(false, request.password, true);
      }
    }

    if (out.rcm.code != EC::Success) {
      const auto status =
          (out.rcm.code == EC::NoConnection)
              ? AMDomain::client::ClientStatus::NoConnection
              : AMDomain::client::ClientStatus::ConnectionBroken;
      config_part_->SetState({out.rcm, status});
      out.data.status = status;
      return out;
    }
    config_part_->SetState({OK, AMDomain::client::ClientStatus::OK});
    out.data.status = AMDomain::client::ClientStatus::OK;
    (void)UpdateOSType({}, control);
    connect_state("FTP connection established", connect_target);
    trace(AMDomain::client::TraceLevel::Info, EC::Success,
          config_part_->GetNickname(), "Connect", "Connect success");
    return out;
  }

  ECMData<AMFSI::RTTResult> GetRTT(const AMFSI::GetRTTArgs &args,
                                   const ControlComponent &control) override {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("GetRTT", kFTPHomeDir);
        stop_rcm.has_value()) {
      return {{-1.0}, std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("GetRTT", kFTPHomeDir);
        stop_request.has_value()) {
      return {{-1.0}, std::move(*stop_request)};
    }
    int times = args.times > 0 ? args.times : 1;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!curl || !multi) {
      return {{-1.0}, ECM{EC::NoConnection, "", "", "CURL not initialized"}};
    }
    std::vector<double> rtts;
    rtts.reserve(static_cast<size_t>(times));
    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    for (ssize_t i = 0; i < times; i++) {
      if (auto stop_rcm = control.BuildECM("GetRTT", kFTPHomeDir);
          stop_rcm.has_value()) {
        free(chunk.memory);
        return {{-1.0}, std::move(*stop_rcm)};
      }
      if (auto stop_request = control.BuildRequestECM("GetRTT", kFTPHomeDir);
          stop_request.has_value()) {
        free(chunk.memory);
        return {{-1.0}, std::move(*stop_request)};
      }
      rcm = SetupPath("", true);
      if (!rcm) {
        free(chunk.memory);
        return {{-1.0}, std::move(rcm)};
      }
      curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
      auto rtt_start_ms = AMTime::miliseconds();
      auto nb_res = NBPerform(control);
      auto rtt_end_ms = AMTime::miliseconds();
      if (nb_res && nb_res.value == CURLE_OK) {
        rtts.push_back(rtt_end_ms - rtt_start_ms);
      } else {
        free(chunk.memory);
        rcm = !nb_res
                  ? NBResultRCMToECM(nb_res, "GetRTT", kFTPHomeDir)
                  : NBResultToECM(curl, nb_res.value, "GetRTT", kFTPHomeDir);
        trace(rcm);
        return {{-1.0}, std::move(rcm)};
      }
    }
    free(chunk.memory);
    if (rtts.empty()) {
      return {{-1.0},
              ECM{EC::UnknownError, "", "", "RTT measure results empty"}};
    } else {
      double sum = 0.0;
      for (double rtt : rtts) {
        sum += rtt;
      }
      return {{sum / rtts.size()}, std::move(rcm)};
    }
  }

  ECMData<AMFSI::RunResult>
  ConductCmd(const AMFSI::ConductCmdArgs &args,
             const ControlComponent &control) override {
    (void)args;
    (void)control;
    ECMData<AMFSI::RunResult> res;
    res.rcm = ECM{EC::OperationUnsupported, "", "",
                  "FTP client does not support ConductCmd"};
    res.data.output = "";
    res.data.exit_code = -1;
    return res;
  }

  ECMData<AMFSI::StatResult> stat(const AMFSI::StatArgs &args,
                                  const ControlComponent &control) override {
    ECM rcm = OK;
    auto stop_rcm = control.BuildECM("stat", args.path);
    if (stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    auto stop_request = control.BuildRequestECM("stat", args.path);
    if (stop_request.has_value()) {
      return {std::move(*stop_request)};
    }

    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (!curl) {
      return {ECM{EC::NoConnection, "", "", "CURL not initialized"}};
    }

    if (args.trace_link) {
      return {ECM{EC::UnImplentedMethod, "", "",
                  "Trace link is not supported in FTP Client"}};
    }

    // Prefer MLST (modern method)
    if (mlst_state_ != CapabilityState::Unsupported) {
      auto mlst_res = MLST_libstat(args, control);
      if (mlst_res.rcm.code == EC::Success) {
        mlst_state_ = CapabilityState::Supported;
        return mlst_res;
      }

      // MLST unsupported; mark and fall back
      if (mlst_res.rcm.code == EC::OperationUnsupported) {
        mlst_state_ = CapabilityState::Unsupported;
        // Continue using legacy method
      } else if (mlst_res.rcm.code == EC::Terminate ||
                 mlst_res.rcm.code == EC::OperationTimeout ||
                 mlst_res.rcm.code == EC::PathNotExist) {
        // Interrupted or timed out; return directly
        return {std::move(mlst_res.rcm)};
      }
      // Other errors also fall back to legacy method
    }
    auto common_res = Common_libstat(args, control);
    if (common_res.rcm.code == EC::Success) {
      return common_res;
    }
    trace(common_res.rcm);
    return {std::move(common_res.rcm)};
  }

  ECMData<AMFSI::ListResult> listdir(const AMFSI::ListdirArgs &args,
                                     const ControlComponent &control) override {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("listdir", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("listdir", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    if (mlsd_state_ != CapabilityState::Unsupported) {
      auto mlsd_res = MLSD_Listdir(args, control);
      if (mlsd_res.rcm.code == EC::Success) {
        mlsd_state_ = CapabilityState::Supported;
        return mlsd_res;
      }
      if (mlsd_res.rcm.code == EC::OperationUnsupported) {
        mlsd_state_ = CapabilityState::Unsupported;
      } else if (mlsd_res.rcm.code == EC::Terminate ||
                 mlsd_res.rcm.code == EC::OperationTimeout ||
                 mlsd_res.rcm.code == EC::PathNotExist) {
        return {std::move(mlsd_res.rcm)};
      }
    }

    auto common_res = Common_Listdir(args, control);
    if (common_res.rcm.code != EC::Success) {
      trace(common_res.rcm);
    }
    return common_res;
  }

  ECMData<AMFSI::ListNamesResult>
  listnames(const AMFSI::ListNamesArgs &args,
            const ControlComponent &control) override {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("listnames", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("listnames", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    if (mlsd_state_ != CapabilityState::Unsupported) {
      auto mlsd_res = MLSD_ListNames(args, control);
      if (mlsd_res.rcm.code == EC::Success) {
        mlsd_state_ = CapabilityState::Supported;
        return mlsd_res;
      }
      if (mlsd_res.rcm.code == EC::OperationUnsupported) {
        mlsd_state_ = CapabilityState::Unsupported;
      } else if (mlsd_res.rcm.code == EC::Terminate ||
                 mlsd_res.rcm.code == EC::OperationTimeout ||
                 mlsd_res.rcm.code == EC::PathNotExist) {
        return {std::move(mlsd_res.rcm)};
      }
    }

    auto common_res = Common_ListNames(args, control);
    if (common_res.rcm.code != EC::Success) {
      trace(common_res.rcm);
    }
    return common_res;
  }

  ECMData<AMFSI::MkdirResult> mkdir(const AMFSI::MkdirArgs &args,
                                    const ControlComponent &control) override {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("mkdir", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("mkdir", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    rcm = SetupPath("", true);
    if (!rcm) {
      return {std::move(rcm)};
    }

    struct curl_slist *commands = nullptr;
    commands = curl_slist_append(
        commands, AMStr::fmt("MKD {}", MlistPath(args.path, true)).c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    auto nb_res = NBPerform(control);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(commands);

    if (!nb_res) {
      rcm = NBResultRCMToECM(nb_res, "mkdir", args.path);
      trace(rcm);
      return {std::move(rcm)};
    }
    if (nb_res.value == CURLE_OK) {
      return {{}, std::move(rcm)};
    }

    rcm = NBResultToECM(curl, nb_res.value, "MKD", args.path);
    rcm.operation = "mkdir";

    auto stat_res = stat(AMFSI::StatArgs(args.path, false), control);
    if (stat_res.rcm.code == EC::Success) {
      if (stat_res.data.info.type == PathType::DIR) {
        return {{}, OK};
      }
      rcm = {EC::PathAlreadyExists, "mkdir", args.path,
             "Path exists and is not a directory"};
      trace(rcm);
      return {std::move(rcm)};
    }
    if (stat_res.rcm.code == EC::Terminate ||
        stat_res.rcm.code == EC::OperationTimeout) {
      return {std::move(stat_res.rcm)};
    }

    trace(rcm);
    return {std::move(rcm)};
  }

  ECMData<AMFSI::MkdirsResult>
  mkdirs(const AMFSI::MkdirsArgs &args,
         const ControlComponent &control) override {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("mkdirs", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("mkdirs", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    if (args.path.empty()) {
      return {ECM{EC::InvalidArg, "mkdirs", args.path, "Invalid empty path"}};
    }

    const auto parts = AMPath::split(args.path);
    if (parts.empty()) {
      return {
          ECM{EC::InvalidArg, "AMPath::split", args.path, "Path split failed"}};
    }

    std::string current_path = "";
    for (const auto &part : parts) {
      if (part.empty() || part == ".") {
        continue;
      }
      if (part == kFTPHomeDir) {
        current_path = kFTPHomeDir;
        continue;
      }
      const std::string stop_target =
          current_path.empty() ? args.path : current_path;
      if (auto stop_rcm = control.BuildECM("mkdirs", stop_target);
          stop_rcm.has_value()) {
        return {std::move(*stop_rcm)};
      }
      if (auto stop_request = control.BuildRequestECM("mkdirs", stop_target);
          stop_request.has_value()) {
        return {std::move(*stop_request)};
      }

      if (current_path.empty()) {
        current_path = part;
      } else {
        current_path = AMPath::join(current_path, part);
      }

      auto mk_res = mkdir(AMFSI::MkdirArgs{current_path}, control);
      if (mk_res.rcm.code != EC::Success) {
        return {std::move(mk_res.rcm)};
      }
    }

    return {{}, std::move(rcm)};
  }

  ECMData<AMFSI::RMResult> rmdir(const AMFSI::RmdirArgs &args,
                                 const ControlComponent &control) override {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("rmdir", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("rmdir", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (args.path.empty()) {
      return {ECM{EC::InvalidArg, "rmdir", args.path, "Invalid empty path"}};
    }
    auto res = stat(AMFSI::StatArgs(args.path, false), control);
    if (!res) {
      return {std::move(res.rcm)};
    }
    if (res.data.info.type != PathType::DIR) {
      return {ECM{EC::NotADirectory, "rmdir", args.path,
                  "Path is not a directory"}};
    }
    rcm = SetupPath("", true);
    if (!rcm) {
      return {std::move(rcm)};
    }

    struct curl_slist *commands = nullptr;
    std::string rmd_cmd = AMStr::fmt("RMD {}", MlistPath(args.path, true));
    commands = curl_slist_append(commands, rmd_cmd.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    auto nb_res = NBPerform(control);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(commands);

    if (!nb_res) {
      rcm = NBResultRCMToECM(nb_res, "rmdir", args.path);
      trace(rcm);
      return {std::move(rcm)};
    }
    if (nb_res.value != CURLE_OK) {
      rcm = NBResultToECM(curl, nb_res.value, "RMD", args.path);
      rcm.operation = "rmdir";
      trace(rcm);
      return {std::move(rcm)};
    }

    return {{}, std::move(rcm)};
  }

  ECMData<AMFSI::RMResult> rmfile(const AMFSI::RmfileArgs &args,
                                  const ControlComponent &control) override {
    ECM rcm = OK;
    if (auto stop_rcm = control.BuildECM("rmfile", args.path);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("rmfile", args.path);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto stat_res = stat(AMFSI::StatArgs(args.path, false), control);
    if (!stat_res) {
      return {std::move(stat_res.rcm)};
    }
    if (stat_res.data.info.type != PathType::FILE) {
      return {ECM{EC::NotAFile, "rmfile", args.path, "Path is not a file"}};
    }

    rcm = SetupPath(args.path, false);
    if (!rcm) {
      return {std::move(rcm)};
    }

    struct curl_slist *commands = nullptr;
    commands =
        curl_slist_append(commands, AMStr::fmt("DELE {}", args.path).c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    auto nb_res = NBPerform(control);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(commands);

    if (!nb_res) {
      rcm = NBResultRCMToECM(nb_res, "rmfile", args.path);
      trace(rcm);
      return {std::move(rcm)};
    }
    if (nb_res.value != CURLE_OK) {
      rcm = NBResultToECM(curl, nb_res.value, "DELE", args.path);
      rcm.operation = "rmfile";
      trace(rcm);
      return {std::move(rcm)};
    }

    return {{}, std::move(rcm)};
  }

  ECMData<AMFSI::MoveResult> rename(const AMFSI::RenameArgs &args,
                                    const ControlComponent &control) override {
    ECM rcm = OK;
    const std::string rename_target =
        AMStr::fmt("{} -> {}", args.src, args.dst);
    if (auto stop_rcm = control.BuildECM("rename", rename_target);
        stop_rcm.has_value()) {
      return {std::move(*stop_rcm)};
    }
    if (auto stop_request = control.BuildRequestECM("rename", rename_target);
        stop_request.has_value()) {
      return {std::move(*stop_request)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);

    rcm = SetupPath("", true);
    if (!rcm) {
      return {std::move(rcm)};
    }

    struct curl_slist *headerlist = nullptr;
    std::string rnfr_cmd = "RNFR " + MlistPath(args.src, args.isdir);
    std::string rnto_cmd = "RNTO " + MlistPath(args.dst, args.isdir);
    headerlist = curl_slist_append(headerlist, rnfr_cmd.c_str());
    headerlist = curl_slist_append(headerlist, rnto_cmd.c_str());

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, headerlist);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    auto nb_res = NBPerform(control);

    if (!nb_res) {
      rcm = NBResultRCMToECM(nb_res, "rename", rename_target);
      trace(rcm);
      return {std::move(rcm)};
    }

    CURLcode res = nb_res.value;

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(headerlist);

    if (res != CURLE_OK) {
      rcm = NBResultToECM(curl, res, "rename", rename_target);
      trace(rcm);
      return {std::move(rcm)};
    }

    return {{}, std::move(rcm)};
  }
};

} // namespace AMInfra::client::FTP
