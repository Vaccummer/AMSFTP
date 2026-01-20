#pragma once
// 标准库
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
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

// Wait result for non-blocking socket operations

// FTP Client using libcurl
class AMFTPClient : public BaseClient {
private:
  CURL *curl = nullptr;
  CURLM *multi = nullptr; // 复用的 multi handle
  std::atomic<bool> connected = false;
  std::regex ftp_url_pattern = std::regex("^ftp://.*$");
  std::string url = "";

  void _iwalk(const PathInfo &info, WRV &result,
              bool ignore_special_file = true) {

    if (info.type != PathType::DIR) {
      result.push_back(info);
      return;
    }

    auto [rcm2, list_info] = listdir(info.path);
    if (rcm2.first != EC::Success) {
      return;
    }

    if (list_info.empty()) {
      result.push_back(info);
      return;
    }

    for (auto &item : list_info) {
      _iwalk(item, result, ignore_special_file);
    }
  }

  void _walk(const std::vector<std::string> &parts, WRD &result,
             int cur_depth = 0, int max_depth = -1,
             bool ignore_special_file = true) {
    if (max_depth != -1 && cur_depth > max_depth) {
      return;
    }
    std::string pathf = AMPathStr::join(parts);
    auto [rcm2, list_info] = listdir(pathf);
    if (rcm2.first != EC::Success) {
      return;
    }
    if (list_info.empty()) {
      result.push_back({parts, {}});
      return;
    }

    std::vector<PathInfo> files_info = {};
    for (auto &info : list_info) {
      if (info.type == PathType::DIR) {
        auto new_parts = parts;
        new_parts.push_back(info.name);
        _walk(new_parts, result, cur_depth + 1, max_depth, ignore_special_file);
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

public:
  std::recursive_mutex mtx;

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

  ECM SetupPath(const std::string &path) {
    if (!curl) {
      return {EC::NoConnection, "CURL not initialized"};
    }
    std::string f_path = path;
    // 清除path开头的所有/ 与
    while (!f_path.empty() && (f_path[0] == '/' || f_path[0] == '\\')) {
      f_path = f_path.substr(1);
    }

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL,
                     fmt::format("{}/{}", this->url, f_path).c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, res_data.username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, res_data.password.c_str());
    return {EC::Success, ""};
  }

  PathInfo ParseListLine(const std::string &line, const std::string &dir_path) {
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

  void _rm(const PathInfo &info, RMR &errors) {
    if (info.type != PathType::DIR) {
      ECM rc = _librmfile(info.path);
      if (rc.first != EC::Success) {
        errors.emplace_back(info.path, rc);
      }
      return;
    }
    auto [rcm2, file_list] = listdir(info.path);
    if (rcm2.first != EC::Success) {
      errors.emplace_back(info.path, rcm2);
      return;
    }
    for (const auto &itemf : file_list) {
      _rm(itemf, errors);
    }
    // Delete directory after removing all contents
    ECM rc = _librmdir(info.path);
    if (rc.first != EC::Success) {
      errors.emplace_back(info.path, rc);
    }
  }

  ECM _librmfile(const std::string &path) {
    if (!curl) {
      return {EC::NoConnection, "CURL not initialized"};
    }
    ECM ecm = SetupPath(path);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *commands = nullptr;
    commands =
        curl_slist_append(commands, fmt::format("DELE {}", path).c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    CURLcode res = curl_easy_perform(curl);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(commands);

    if (res != CURLE_OK) {
      return {EC::CommonFailure,
              fmt::format("rmfile failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  ECM _librmdir(const std::string &path) {
    if (!curl) {
      return {EC::NoConnection, "CURL not initialized"};
    }
    std::string url = BuildUrl("/");
    ECM ecm = SetupCurl(url);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *commands = nullptr;
    commands = curl_slist_append(commands, fmt::format("RMD {}", path).c_str());
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, commands);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    CURLcode res = curl_easy_perform(curl);

    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_slist_free_all(commands);

    if (res != CURLE_OK) {
      return {EC::DirNotEmpty,
              fmt::format("rmdir failed: {}", curl_easy_strerror(res))};
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

  ECM Connect(bool force = false, int timeout_ms = -1,
              amf interrupt_flag = nullptr) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (connected && !force && GetState().first == EC::Success) {
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

    // Test connection by getting home directory
    SetupAuth("");
    if (timeout_ms > 0) {
      curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    }
    ECM rcm = Check(true);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    // Get home directory using PWD command
    home_dir = GetHomeDir();
    SetState({EC::Success, ""});
    trace(TraceLevel::Info, EC::Success, nickname, "Connect",
          "Connect success");
    connected.store(true);
    return {EC::Success, ""};
  }

  ECM GetState() override {
    std::lock_guard<std::mutex> lock(state_mtx);
    return state;
  }

  ECM Check(int timeout_ms = -1) override {
    if (!curl) {
      connected = false;
      return {EC::NoConnection, "CURL not initialized"};
    }

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    CURLcode res = curl_easy_perform(curl);

    free(chunk.memory);

    std::string error_msg = "";

    if (res != CURLE_OK) {
      connected = false;
      error_msg = fmt::format("Connect failed: {}", curl_easy_strerror(res));
      SetState({EC::FTPConnectFailed, error_msg});
      if (need_trace) {
        trace(TraceLevel::Critical, EC::FTPConnectFailed, nickname, "Connect",
              error_msg);
      }
      return {EC::FTPConnectFailed, error_msg};
    }

    if (need_trace) {
      trace(TraceLevel::Info, EC::Success, nickname, "Check",
            "Check connection success");
    }
    curl_easy_reset(curl);
    return {EC::Success, ""};
  }

  std::string GetHomeDir() override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!home_dir.empty()) {
      return home_dir;
    }

    if (!curl) {
      return "";
    }

    std::string url =
        fmt::format("ftp://{}:{}/", res_data.hostname, res_data.port);
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, res_data.username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, res_data.password.c_str());
    curl_easy_setopt(curl, CURLOPT_FTP_RESPONSE_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    struct curl_slist *headerlist = nullptr;
    headerlist = curl_slist_append(headerlist, "PWD");
    curl_easy_setopt(curl, CURLOPT_QUOTE, headerlist);

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&chunk);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headerlist);

    std::string pwd_path = "/";
    if (res == CURLE_OK && chunk.size > 0) {
      std::string response(chunk.memory, chunk.size);
      // Parse PWD response: 257 "/path" is current directory
      size_t start = response.find('"');
      if (start != std::string::npos) {
        size_t end = response.find('"', start + 1);
        if (end != std::string::npos) {
          pwd_path = response.substr(start + 1, end - start - 1);
        }
      }
    }

    free(chunk.memory);

    if (res != CURLE_OK) {
      return "";
    }
    this->home_dir = pwd_path;
    return pwd_path;
  }

private:
  // 非阻塞执行 curl 请求，支持中断和超时
  // poll_interval_ms: 每次轮询间隔，越小响应越快，但 CPU 占用越高
  NBResult<CURLcode>
  nb_perform(amf interrupt_flag, int timeout_ms,
             std::chrono::steady_clock::time_point start_time) {
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
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start_time)
                           .count();
        if (elapsed >= timeout_ms) {
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

public:
  SR stat(const std::string &path, bool trace_link = false,
          amf interrupt_flag = nullptr, int timeout_ms = -1,
          std::chrono::steady_clock::time_point start_time =
              std::chrono::steady_clock::now()) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;

    if (!curl) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, PathInfo()};
    }

    std::string pathf = path;
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)},
              PathInfo()};
    }

    // First try to list as directory (append / to path)
    ECM ecm = SetupPath(pathf + "/");
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

    if (nb_res.ok() && nb_res.value == CURLE_OK) {
      // It's a directory
      free(chunk.memory);
      PathInfo info;
      info.path = pathf;
      info.name = AMPathStr::basename(pathf);
      info.dir = AMPathStr::dirname(pathf);
      info.type = PathType::DIR;
      info.size = 0;
      return {ECM{EC::Success, ""}, info};
    }

    free(chunk.memory);

    // Check if interrupted or timed out
    if (!nb_res.ok()) {
      return {NBResultToECM(nb_res), PathInfo()};
    }

    // Not a directory, try as file using SIZE command
    ecm = SetupPath(pathf);
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
      info.path = pathf;
      info.name = AMPathStr::basename(pathf);
      info.dir = AMPathStr::dirname(pathf);
      info.type = PathType::FILE;

      // Get file size
      curl_off_t filesize = 0;
      curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &filesize);
      info.size = filesize >= 0 ? static_cast<uint64_t>(filesize) : 0;

      // Get modification time
      long filetime = 0;
      curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      if (filetime >= 0) {
        info.modify_time = filetime;
      }

      free(chunk.memory);
      return {ECM{EC::Success, ""}, info};
    }

    free(chunk.memory);

    // Check if interrupted or timed out
    if (!nb_res.ok()) {
      return {NBResultToECM(nb_res), PathInfo()};
    }

    // Fallback: try listing parent directory
    std::string parent = AMPathStr::dirname(pathf);
    std::string filename = AMPathStr::basename(pathf);

    auto [rcm, files] = listdir(parent, timeout_ms, interrupt_flag, start_time);
    if (rcm.first != EC::Success) {
      return {ECM{EC::PathNotExist, fmt::format("Path not found: {}", pathf)},
              PathInfo()};
    }

    for (const auto &file : files) {
      if (file.name == filename) {
        return {ECM{EC::Success, ""}, file};
      }
    }

    return {ECM{EC::PathNotExist, fmt::format("Path not found: {}", pathf)},
            PathInfo()};
  }

  std::pair<ECM, bool> exists(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              std::chrono::steady_clock::time_point start_time =
                                  std::chrono::steady_clock::now()) override {
    auto [rcm, path_info] = stat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first == EC::Success) {
      return {rcm, true};
    } else if (rcm.first == EC::PathNotExist || rcm.first == EC::FileNotExist) {
      return {{EC::Success, ""}, false};
    } else {
      return {rcm, false};
    }
  }

  std::pair<ECM, bool> is_dir(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              std::chrono::steady_clock::time_point start_time =
                                  std::chrono::steady_clock::now()) override {
    auto [rcm, path_info] = stat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""}, path_info.type == PathType::DIR};
  }

  std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, int max_time_ms = -1,
          amf interrupt_flag = nullptr,
          std::chrono::steady_clock::time_point start_time =
              std::chrono::steady_clock::now()) override {
    std::string pathf = path;
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)}, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;

    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Interrupted by user"}, {}};
    }

    ECM ecm = SetupPath(pathf + "/");
    if (ecm.first != EC::Success) {
      return {ecm, {}};
    }

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    auto nb_res = nb_perform(interrupt_flag, max_time_ms, start_time);

    if (!nb_res.ok()) {
      free(chunk.memory);
      return {NBResultToECM(nb_res), {}};
    }

    if (nb_res.value != CURLE_OK) {
      free(chunk.memory);
      return {
          ECM{EC::FTPListFailed,
              fmt::format("List failed: {}", curl_easy_strerror(nb_res.value))},
          {}};
    }

    std::string listing(chunk.memory, chunk.size);
    free(chunk.memory);

    std::vector<PathInfo> file_list;
    std::istringstream iss(listing);
    std::string line;

    while (std::getline(iss, line)) {
      // Remove trailing \r (FTP uses CRLF)
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.empty())
        continue;
      PathInfo info = ParseListLine(line, pathf);
      if (info.type != PathType::Unknown && info.name != "." &&
          info.name != "..") {
        file_list.push_back(info);
      }
    }

    return {ECM{EC::Success, ""}, file_list};
  }

  WRV iwalk(const std::string &path, amf interrupt_flag = nullptr,
            bool ignore_special_file = true) override {
    WRV result = {};
    if (path.empty()) {
      return result;
    }
    auto [rcm, info] = stat(path);
    if (rcm.first != EC::Success) {
      return result;
    } else if (info.type != PathType::DIR) {
      return {info};
    }
    _iwalk(info, result, ignore_special_file);
    return result;
  }

  std::pair<ECM, WRD> walk(const std::string &path, int max_depth = -1,
                           amf interrupt_flag = nullptr,
                           bool ignore_special_file = true) override {
    auto [rcm, br] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    WRD result_dict = {};
    std::vector<std::string> parts = {path};
    _walk(parts, result_dict, 0, max_depth, ignore_special_file);
    return {ECM{EC::Success, ""}, result_dict};
  }

  ECM mkdir(const std::string &path) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (path.empty()) {
      return {EC::InvalidArg, fmt::format("Invalid path: {}", path)};
    }

    // Check if already exists
    auto [rcm, info] = stat(path);
    if (rcm.first == EC::Success) {
      if (info.type == PathType::DIR) {
        return {EC::Success, ""};
      } else {
        return {EC::PathAlreadyExists,
                fmt::format("Path exists and is not a directory: {}", path)};
      }
    }

    std::string url = BuildUrl(path + "/");
    ECM ecm = SetupCurl(url);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      return {EC::FTPMkdirFailed,
              fmt::format("mkdir failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  ECM mkdirs(const std::string &path) override { return mkdir(path); }

  ECM rmfile(const std::string &path) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (path.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    auto [rcm, info] = stat(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (info.type != PathType::FILE) {
      return {EC::NotAFile, fmt::format("Path is not a file: {}", path)};
    }
    return _librmfile(path);
  }

  ECM rmdir(const std::string &path) override {
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
    return _librmdir(path);
  }

  std::pair<ECM, RMR> remove(const std::string &path) override {
    RMR errors = {};
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    _rm(info, errors);
    return {ECM{EC::Success, ""}, errors};
  }

  ECM rename(const std::string &src, const std::string &dst,
             bool overwrite = false) override {
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
    std::string url = BuildUrl("/");
    ECM ecm = SetupCurl(url);
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

  ECM move(const std::string &src, const std::string &dst,
           bool need_mkdir = false, bool force_write = false) override {
    std::string srcf = src;
    std::string dstf = dst;

    auto [rcm, ssr] = stat(srcf);
    if (rcm.first != EC::Success) {
      return rcm;
    }

    auto [rcm2, dsr] = stat(dstf);
    if (rcm2.first != EC::Success) {
      EC rc = rcm2.first;
      if ((rc == EC::PathNotExist || rc == EC::FileNotExist) && need_mkdir) {
        ECM ecm = mkdirs(dstf);
        if (ecm.first != EC::Success) {
          return ecm;
        }
      } else {
        return rcm2;
      }
    } else {
      if (dsr.type != PathType::DIR) {
        return {EC::NotADirectory,
                fmt::format("Dst is not a directory: {}", dstf)};
      }
    }

    std::string dst_path = AMFS::join(dstf, AMFS::basename(srcf));
    return rename(srcf, dst_path, force_write);
  }

  void Upload(const std::string &dst, curl_read_callback read_callback,
              ProgressData *pd) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    std::string dst_path = AMFS::abspath(dst, true, home_dir, home_dir);
    std::string url = BuildUrl(dst_path);
    ECM ecm = SetupCurl(url);
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
    std::string src_path = AMFS::abspath(src, true, home_dir, home_dir);
    std::string url = BuildUrl(src_path);
    ECM ecm = SetupCurl(url);
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
