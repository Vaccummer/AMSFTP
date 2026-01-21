#pragma once
// 标准库
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <fmt/format.h>
#include <iostream>
#include <mutex>
#include <pybind11/pytypes.h>
#include <regex>
#include <sstream>
#include <string>

// 标准库

// 自身依赖
#include "AMBaseClient.hpp"
#include "AMDataClass.hpp"
#include "AMEnum.hpp"
#include "AMPath.hpp"

// 自身依赖

// 第三方库
#include <libssh2.h>
#include <libssh2_sftp.h>

#include <curl/curl.h>
#include <fmt/core.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
// 第三方库

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

using EC = ErrorCode;
using ECM = std::pair<EC, std::string>;

inline PathInfo ParseListLine(const std::string &line,
                              const std::string &dir_path) {
  PathInfo info;

  // Parse FTP LIST format: -rw-r--r-- 1 owner group size month day time
  // filename or drwxr-xr-x 1 owner group size month day time filename
  std::istringstream iss(line);
  std::string perms, links, owner, group, size_str, month, day, time_or_year,
      name;

  if (!(iss >> perms >> links >> owner >> group >> size_str >> month >> day >>
        time_or_year)) {
    info.type = PathType::Unknown;
    return info;
  }

  // Get filename (rest of line)
  std::getline(iss >> std::ws, name);
  // Remove trailing \r if present (FTP uses CRLF)
  if (!name.empty() && name.back() == '\r') {
    name.pop_back();
  }

  info.name = name;
  info.path = AMPathStr::join(dir_path, name, SepType::Unix);
  info.dir = dir_path;
  info.owner = owner;

  // Parse type
  if (perms[0] == 'd') {
    info.type = PathType::DIR;
  } else if (perms[0] == 'l') {
    info.type = PathType::SYMLINK;
  } else if (perms[0] == '-') {
    info.type = PathType::FILE;
  } else {
    info.type = PathType::Unknown;
  }

  // Parse size
  try {
    info.size = std::stoull(size_str);
  } catch (...) {
    info.size = 0;
  }

  // Parse permissions (skip first char which is type)
  info.mode_str = perms.substr(1);

  return info;
}
// 解析 MLSD 行（目录列表）
// 格式: type=file;size=1024;modify=20210315120000;perm=rwx; filename
// 与 MLST 不同，MLSD 每行包含文件名，需要从行中提取
inline PathInfo ParseMLSDLine(const std::string &line,
                              const std::string &dir_path) {
  PathInfo info;

  // 查找 facts 和 filename 的分隔（最后一个空格后是文件名）
  size_t space_pos = line.rfind(' ');
  if (space_pos == std::string::npos) {
    info.type = PathType::Unknown;
    return info;
  }

  std::string facts = line.substr(0, space_pos);
  std::string filename = line.substr(space_pos + 1);

  // 去除文件名的回车
  if (!filename.empty() && filename.back() == '\r') {
    filename.pop_back();
  }

  info.name = filename;
  info.dir = dir_path;
  info.path = AMPathStr::join(dir_path, filename, SepType::Unix);

  // 解析 facts (;分隔的 key=value)
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

    // 转小写比较
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    if (key == "type") {
      std::transform(value.begin(), value.end(), value.begin(), ::tolower);
      if (value == "file") {
        info.type = PathType::FILE;
      } else if (value == "dir") {
        info.type = PathType::DIR;
      } else if (value == "cdir" || value == "pdir") {
        // 当前目录和父目录，跳过
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

// 解析 MLST 响应格式
// 格式: type=file;size=1024;modify=20210315120000;perm=rwx; filename
inline PathInfo ParseMLSTLine(const std::string &line,
                              const std::string &path) {
  PathInfo info;
  info.path = path;
  info.name = AMPathStr::basename(path);
  info.dir = AMPathStr::dirname(path);

  // 查找 facts 和 filename 的分隔（最后一个空格后是文件名）
  size_t space_pos = line.rfind(' ');
  if (space_pos == std::string::npos) {
    info.type = PathType::Unknown;
    return info;
  }

  std::string facts = line.substr(0, space_pos);

  // 解析 facts (;分隔的 key=value)
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

    // 转小写比较
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
      // 格式: YYYYMMDDHHMMSS 或 YYYYMMDDHHMMSS.sss
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
  // 替换空格为%20
  AMStr::vreplace_all(pathf, " ", "%20");
  while (!pathf.empty() && (pathf.back() == '/' || pathf.back() == '\\')) {
    pathf.pop_back();
  }
  if (!pathf.empty() && is_dir) {
    pathf += "/";
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

// FTP Client using libcurl
class AMFTPClient : public BaseClient {
private:
  CURL *curl = nullptr;
  CURLM *multi = nullptr; // 复用的 multi handle
  std::atomic<bool> connected = false;
  std::atomic<bool> mlst_supported = true; // 是否支持 MLST，默认先尝试
  std::atomic<bool> mlst_checked = false;  // 是否已检测过 MLST 支持
  std::regex ftp_url_pattern = std::regex("^ftp://.*$");
  std::string url = "";
  // 非阻塞执行 curl 请求，支持中断和超时
  // poll_interval_ms: 每次轮询间隔，越小响应越快，但 CPU 占用越高

  NBResult<CURLcode> nb_perform(amf interrupt_flag, int timeout_ms,
                                int64_t start_time) {
    if (!multi) {
      return {CURLE_FAILED_INIT, WaitResult::Error};
    }

    curl_multi_add_handle(multi, curl);

    int still_running = 1;
    CURLcode result = CURLE_OK;
    WaitResult wait_result = WaitResult::Ready;

    while (still_running) {
      CURLMcode mc = curl_multi_perform(multi, &still_running);
      if (mc != CURLM_OK) {
        result = CURLE_FAILED_INIT;
        wait_result = WaitResult::Error;
        break;
      }

      if (!still_running)
        break;

      // 检查中断
      if (interrupt_flag && interrupt_flag->check()) {
        wait_result = WaitResult::Interrupted;
        break;
      }

      // 检查超时
      if (timeout_ms > 0) {
        if (am_ms() - start_time >= timeout_ms) {
          wait_result = WaitResult::Timeout;
          break;
        }
      }

      // 非阻塞等待 socket 事件
      int numfds = 0;
      mc = curl_multi_poll(multi, NULL, 0, poll_interval_ms, &numfds);
      if (mc != CURLM_OK) {
        result = CURLE_FAILED_INIT;
        wait_result = WaitResult::Error;
        break;
      }
    }

    // 获取真实结果
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

  ECM SetupPath(const std::string &path, bool is_dir = false) {
    if (!curl) {
      return {EC::NoConnection, "CURL not initialized"};
    }
    std::string path_f = path;
    if (!path_f.empty()) {
      path_f = MlistPath(path, is_dir);
    }
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL,
                     fmt::format("{}{}", this->url, path_f).c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, res_data.username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, res_data.password.c_str());
    return {EC::Success, ""};
  }

  // 使用 MLST 命令获取文件信息（现代方法）
  SR try_mlst(const std::string &path, amf interrupt_flag, int timeout_ms,
              int64_t start_time) {
    if (!curl || !multi) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, PathInfo()};
    }

    // 重置 curl 选项
    SetupPath(path);

    // 设置 MLST 命令
    struct curl_slist *commands = nullptr;
    commands = curl_slist_append(
        commands, fmt::format("MLST {}", MlistPath(path)).c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    // 捕获 header（MLST 响应在 header 中）
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
                 fmt::format("MLST {} error: {}", path,
                             curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, rcm.first, path, "MLST", rcm.second);
      return {rcm, PathInfo()};
    }

    // 解析响应
    std::string response(header_chunk.memory, header_chunk.size);
    free(header_chunk.memory);

    // 查找 250- 开头的行（MLST 数据行）或直接的 facts 行
    // 格式:
    // 250- Listing path
    //  type=file;size=123; filename    <- 注意开头有空格
    // 250 End
    PathInfo info;
    std::istringstream iss(response);
    std::string line;
    bool found = false;

    while (std::getline(iss, line)) {
      // 去掉 \r
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      std::cout << "line:" << line << "\n";

      // MLST 数据行以空格开头
      if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
        line = line.substr(1); // 去掉开头空格
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

  // 传统 stat 方法（回退用）
  SR stat_legacy(const std::string &path, amf interrupt_flag, int timeout_ms,
                 int64_t start_time) {
    std::cout << "stat_legacy1" << std::endl;
    // 先尝试作为目录
    ECM ecm = SetupPath(path, true);
    if (ecm.first != EC::Success) {
      return {ecm, PathInfo()};
    }
    std::cout << "stat_legacy2" << std::endl;
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

    std::cout << "stat_legacy3" << std::endl;
    if (!nb_res.ok()) {
      return {NBResultToECM(nb_res), PathInfo()};
    }

    std::cout << "stat_legacy4" << std::endl;
    // 尝试作为文件
    ecm = SetupPath(path);
    if (ecm.first != EC::Success) {
      return {ecm, PathInfo()};
    }

    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);

    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);

    if (nb_res.ok() && nb_res.value == CURLE_OK) {
      PathInfo info;
      info.path = path;
      info.name = AMPathStr::basename(path);
      info.dir = AMPathStr::dirname(path);
      info.type = PathType::FILE;

      curl_off_t filesize = 0;
      curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &filesize);
      info.size = filesize >= 0 ? static_cast<uint64_t>(filesize) : 0;

      long filetime = 0;
      curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      if (filetime >= 0) {
        info.modify_time = filetime;
      }

      free(chunk.memory);
      return {ECM{EC::Success, ""}, info};
    }

    free(chunk.memory);

    if (!nb_res.ok()) {
      return {NBResultToECM(nb_res), PathInfo()};
    }

    // 最后回退：列出父目录查找
    std::string parent = AMPathStr::dirname(path);
    std::string filename = AMPathStr::basename(path);

    auto [rcm, files] = listdir(parent, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {ECM{EC::PathNotExist, fmt::format("Path not found: {}", path)},
              PathInfo()};
    }

    for (const auto &file : files) {
      if (file.name == filename) {
        return {ECM{EC::Success, ""}, file};
      }
    }

    return {ECM{EC::PathNotExist, fmt::format("Path not found: {}", path)},
            PathInfo()};
  }

  // 使用 MLSD 命令列出目录（现代方法）
  std::pair<ECM, std::vector<PathInfo>> try_mlsd(const std::string &path,
                                                 amf interrupt_flag,
                                                 int timeout_ms,
                                                 int64_t start_time) {
    if (!curl || !multi) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, {}};
    }
    // 使用 MLSD URL 格式
    SetupPath(path, true);

    // 使用 MLSD 自定义请求
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "MLSD");

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);

    // 重置自定义请求
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, nullptr);

    if (!nb_res.ok()) {
      free(chunk.memory);
      return {NBResultToECM(nb_res), {}};
    }

    if (nb_res.value != CURLE_OK) {
      free(chunk.memory);
      long response_code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

      // 500/502 = 命令不支持, 550 = 目录不存在
      if (response_code == 500 || response_code == 502 ||
          nb_res.value == CURLE_QUOTE_ERROR ||
          nb_res.value == CURLE_FTP_COULDNT_RETR_FILE) {
        std::cout << "Not Supported" << "\n";
        return {ECM{EC::OperationUnsupported, "MLSD not supported"}, {}};
      }
      if (response_code == 550) {
        std::cout << "Path not ex" << "\n";
        return {ECM{EC::PathNotExist, fmt::format("Path not found: {}", path)},
                {}};
      }

      std::cout << "Others: " << response_code << "\n";
      std::cout << "result_value: " << nb_res.value << "\n";
      return {ECM{EC::FTPListFailed, curl_easy_strerror(nb_res.value)}, {}};
    }

    // 解析 MLSD 响应
    std::string listing(chunk.memory, chunk.size);
    free(chunk.memory);

    std::vector<PathInfo> file_list;
    std::istringstream iss(listing);
    std::string line;

    // 去除路径末尾的 /
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
      std::cout << "line: " << line << std::endl;

      PathInfo info = ParseMLSDLine(line, dir_path);
      // 过滤掉无效项和 . ..
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
        curl_slist_append(commands, fmt::format("DELE {}", path).c_str());
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
                 fmt::format("rmfile {} failed: {}", path,
                             curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, ecm.first, path, "rmfile", ecm.second);
      return ecm;
    }
    return {EC::Success, ""};
  }

  ECM _librmdir(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1, int64_t start_time = -1) {

    ECM ecm = SetupPath(url, true);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *commands = nullptr;
    commands = curl_slist_append(commands, fmt::format("RMD {}", path).c_str());
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
                 fmt::format("rmdir {} failed: {}", path,
                             curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, ecm.first, path, "rmdir", ecm.second);
      return ecm;
    }
    return {EC::Success, ""};
  }

public:
  AMFTPClient(const ConRequst &request, ssize_t buffer_capacity = 10,
              const py::object &trace_cb = py::none())
      : BaseClient(request, buffer_capacity, trace_cb) {
    this->PROTOCOL = ClientProtocol::FTP;

    if (res_data.username.empty()) {
      res_data.username = "anonymous";
      res_data.password = res_data.password.empty() ? "anonymous@example.com"
                                                    : res_data.password;
    }
    this->url = fmt::format("ftp://{}:{}", res_data.hostname, res_data.port);
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
  }

  ECM Connect(bool force = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (connected && !force && Check().first == EC::Success) {
      return {EC::Success, ""};
    }

    if (connected && force) {
      connected = false;
      // 清理旧的 handles
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
      return {EC::NoConnection, "CURL easy init failed"};
    }
    multi = curl_multi_init();
    if (!multi) {
      curl_easy_cleanup(curl);
      curl = nullptr;
      return {EC::NoConnection, "CURL multi init failed"};
    }

    ECM rcm = Check(interrupt_flag, timeout_ms, start_time);

    if (rcm.first != EC::Success) {
      return rcm;
    }
    // Get home directory using PWD command
    home_dir = "/";
    SetState({EC::Success, ""});
    trace(TraceLevel::Info, EC::Success, nickname, "Connect",
          "Connect success");
    connected.store(true);
    return rcm;
  }

  ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
            int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
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
           fmt::format("Check error: {}", curl_easy_strerror(nb_res.value))};
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
    std::cout << "fstat1" << std::endl;
    if (!curl) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, PathInfo()};
    }
    std::cout << "fstat2" << std::endl;
    if (trace_link) {
      return {ECM{EC::UnImplentedMethod,
                  "Trace link is not supported in FTP Client"},
              PathInfo()};
    }
    std::cout << "fstat3" << std::endl;
    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Interrupted by user"}, PathInfo()};
    }
    std::cout << "fstat4" << std::endl;
    std::string pathf = path;
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)},
              PathInfo()};
    }
    std::cout << "fstat5" << std::endl;

    // 优先使用 MLST（现代方法）
    if (mlst_supported.load()) {
      auto [ecm, info] =
          try_mlst(pathf, interrupt_flag, timeout_ms, start_time);

      if (ecm.first == EC::Success) {
        mlst_checked.store(true);
        return {ecm, info};
      }

      // MLST 不支持，标记并回退
      if (ecm.first == EC::OperationUnsupported) {
        mlst_supported.store(false);
        mlst_checked.store(true);
        // 继续使用传统方法
      } else if (ecm.first == EC::Terminate ||
                 ecm.first == EC::OperationTimeout) {
        // 中断或超时，直接返回
        return {ecm, PathInfo()};
      } else if (ecm.first == EC::PathNotExist) {
        // 路径不存在
        return {ecm, PathInfo()};
      }
      // 其他错误也回退到传统方法
    }
    std::cout << "fstat6" << std::endl;
    // 传统方法
    return stat_legacy(pathf, interrupt_flag, timeout_ms, start_time);
  }

  std::pair<ECM, std::vector<PathInfo>>
  listdir_combine(const std::string &path, amf interrupt_flag = nullptr,
                  int max_time_ms = -1, int64_t start_time = -1) {
    if (start_time == -1) {
      start_time = am_ms();
    }
    std::string pathf = path;
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)}, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;

    if (!curl) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, {}};
    }

    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Interrupted by user"}, {}};
    }

    // 优先使用 MLSD（现代方法）
    if (false) {
      auto [ecm, file_list] =
          try_mlsd(pathf, interrupt_flag, max_time_ms, start_time);

      if (ecm.first == EC::Success) {
        mlst_checked.store(true);
        return {ecm, file_list};
      }

      // MLSD 不支持，标记并回退
      if (ecm.first == EC::OperationUnsupported) {
        mlst_supported.store(false);
        mlst_checked.store(true);
        // 继续使用传统方法
      } else if (ecm.first == EC::Terminate ||
                 ecm.first == EC::OperationTimeout) {
        // 中断或超时，直接返回
        return {ecm, {}};
      } else if (ecm.first == EC::PathNotExist) {
        // 路径不存在
        return {ecm, {}};
      }
      // 其他错误也回退到传统方法
    }

    // 传统方法
    return listdir(pathf, interrupt_flag, max_time_ms, start_time);
  }

  // 传统 LIST 方法（回退用）
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
      ECM rcm =
          ECM{GetFTPErrorCode(nb_res.value),
              fmt::format("List failed: {}", curl_easy_strerror(nb_res.value))};
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

  void _iwalk(const PathInfo &info, WRV &result,
              bool ignore_special_file = true, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1) {

    auto [rcm2, list_info] =
        listdir(info.path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return;
    }

    bool no_subdir = true;
    for (auto &item : list_info) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        return;
      }
      if ((item.type != PathType::DIR)) {
        result.push_back(item);
        continue;
      }
      no_subdir = false;
      _iwalk(item, result, ignore_special_file);
    }

    if (no_subdir) {
      result.push_back(info);
      return;
    }
  }

  std::pair<ECM, std::vector<PathInfo>>
  iwalk(const std::string &path, bool ignore_special_file = true,
        amf interrupt_flag = nullptr, int timeout_ms = -1,
        int64_t start_time = -1) override {
    if (start_time == -1) {
      start_time = am_ms();
    }

    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, {}};
    }
    WRV result = {};
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    } else if (info.type != PathType::DIR) {
      return {{EC::Success, ""}, {info}};
    }
    _iwalk(info, result, ignore_special_file);
    return {ECM{EC::Success, ""}, result};
  }

  void _walk(const std::vector<std::string> &parts, WRD &result,
             int cur_depth = 0, int max_depth = -1,
             bool ignore_special_file = true, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) {
    if (max_depth != -1 && cur_depth > max_depth) {
      return;
    }
    std::string pathf = AMPathStr::join(parts);
    auto [rcm2, list_info] =
        listdir(pathf, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return;
    }
    if (list_info.empty()) {
      result.push_back({parts, {}});
      return;
    }

    std::vector<PathInfo> files_info = {};
    for (auto &info : list_info) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        return;
      }
      if (info.type == PathType::DIR) {
        auto new_parts = parts;
        new_parts.push_back(info.name);
        _walk(new_parts, result, cur_depth + 1, max_depth, ignore_special_file,
              interrupt_flag, timeout_ms, start_time);
      } else {
        if (ignore_special_file && static_cast<int>(info.type) < 0) {
          continue;
        }
        files_info.push_back(info);
      }
    }
    if (!files_info.empty()) {
      result.emplace_back(parts, files_info);
    }
  }

  std::pair<ECM, WRD> walk(const std::string &path, int max_depth = -1,
                           bool ignore_special_file = true,
                           amf interrupt_flag = nullptr, int timeout_ms = -1,
                           int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, br] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    WRD result_dict = {};
    std::vector<std::string> parts = {path};
    _walk(parts, result_dict, 0, max_depth, ignore_special_file);
    return {ECM{EC::Success, ""}, result_dict};
  }

  ECM mkdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1, int64_t start_time = -1) override {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    // Check if already exists
    auto [rcm, info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first == EC::Success) {
      if (info.type == PathType::DIR) {
        return {EC::Success, ""};
      } else {
        return {EC::PathAlreadyExists,
                fmt::format("Path exists and is not a directory: {}", path)};
      }
    }

    ECM ecm = SetupPath(url, true);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR);

    auto nb_res = nb_perform(interrupt_flag, timeout_ms, start_time);
    if (!nb_res.ok()) {
      return NBResultToECM(nb_res);
    }
    if (nb_res.value != CURLE_OK) {
      ecm = {GetFTPErrorCode(nb_res.value),
             fmt::format("mkdir {} failed: {}", path,
                         curl_easy_strerror(nb_res.value))};
      trace(TraceLevel::Error, ecm.first, path, "mkdir", ecm.second);
    }
    return ecm;
  }

  ECM mkdirs(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
    return mkdir(path, interrupt_flag, timeout_ms, start_time);
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
      return {EC::NotAFile, fmt::format("Path is not a file: {}", path)};
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
              fmt::format("Path is not a directory: {}", path)};
    }
    return _librmdir(path, interrupt_flag, timeout_ms, start_time);
  }

  void _rm(const PathInfo &info, RMR &errors, amf interrupt_flag = nullptr,
           int timeout_ms = -1, int64_t start_time = -1) {
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
      errors.emplace_back(info.path, rcm2);
      return;
    }
    for (const auto &itemf : file_list) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        return;
      }
      _rm(itemf, errors, interrupt_flag, timeout_ms, start_time);
    }
    // Delete directory after removing all contents
    ECM rc = _librmdir(info.path, interrupt_flag, timeout_ms, start_time);
    if (rc.first != EC::Success) {
      errors.emplace_back(info.path, rc);
    }
  }

  std::pair<ECM, RMR> remove(const std::string &path,
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
      return {rcm, {}};
    }
    _rm(info, errors, interrupt_flag, timeout_ms, start_time);
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
              fmt::format("Invalid path: {} or {}", srcf, dstf)};
    }

    // Check source exists
    auto [rcm, sbr] = stat(srcf);
    if (rcm.first != EC::Success) {
      return rcm;
    }

    // Check destination
    auto [rcm2, sbr2] = stat(dstf);
    if (rcm2.first == EC::Success) {
      if (sbr2.type != sbr.type) {
        return {EC::PathAlreadyExists,
                fmt::format(
                    "Dst already exists and is not the same type as src: {} ",
                    dstf)};
      }
      if (!overwrite) {
        return {
            EC::PathAlreadyExists,
            fmt::format("Dst already exists: {} and overwrite is false", dstf)};
      }
    }

    // Use RNFR and RNTO commands via QUOTE
    std::string url = fmt::format("{}{}", this->url, "/");
    ECM ecm = SetupPath(url);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *headerlist = nullptr;
    std::string rnfr_cmd = "RNFR " + srcf;
    std::string rnto_cmd = "RNTO " + dstf;
    headerlist = curl_slist_append(headerlist, rnfr_cmd.c_str());
    headerlist = curl_slist_append(headerlist, rnto_cmd.c_str());

    // Use POSTQUOTE instead of QUOTE - commands run after the transfer
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, headerlist);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    CURLcode res = curl_easy_perform(curl);

    // Clean up
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(headerlist);

    if (res != CURLE_OK) {
      return {EC::FTPRenameFailed,
              fmt::format("Rename failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  void Upload(const std::string &dst, curl_read_callback read_callback,
              ProgressData *pd) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    ECM ecm = SetupPath(dst, false);
    if (ecm.first != EC::Success) {
      pd->rcm = ecm;
      pd->is_terminate.store(true);
      return;
    }
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, pd);
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      pd->is_terminate.store(true);
    } else if (res != CURLE_OK) {
      pd->rcm = ECM{EC::FTPUploadFailed,
                    fmt::format("Upload failed: {}", curl_easy_strerror(res))};
      pd->is_terminate.store(true);
    }
  }

  void Download(const std::string &src, curl_write_callback write_callback,
                ProgressData *pd) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    ECM ecm = SetupPath(src, false);
    if (ecm.first != EC::Success) {
      pd->rcm = ecm;
      pd->is_terminate.store(true);
      return;
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pd);
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      pd->is_terminate.store(true);
    } else if (res != CURLE_OK) {
      pd->rcm =
          ECM{EC::FTPDownloadFailed,
              fmt::format("Download failed: {}", curl_easy_strerror(res))};
      pd->is_terminate.store(true);
    }
  }
};
