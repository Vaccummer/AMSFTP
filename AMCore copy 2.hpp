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
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <pybind11/pytypes.h>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// 标准库

// 自身依赖
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

#define _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR // in case mutex constructor is not
                                             // supported

extern std::atomic<bool> is_wsa_initialized;

void cleanup_wsa();

inline bool isok(ECM &ecm) { return ecm.first == EC::Success; }

namespace py = pybind11;
namespace fs = std::filesystem;
using amf = std::shared_ptr<InterruptFlag>;
using PathInfo = PathInfo;
using PathType = PathType;
using EC = ErrorCode;
using ECM = std::pair<EC, std::string>;
using TASKS = std::vector<TransferTask>;              // load_task返回类型
using RMR = std::vector<std::pair<std::string, ECM>>; // rm函数的返回类型
using BR = std::pair<bool, ECM>;                      // is_dir函数返回类型
using SR = std::pair<ECM, PathInfo>;                  // stat函数返回类型
using WRV = std::vector<PathInfo>;                    // iwalk函数返回类型
using WRD = AMFS::WRD;                                // walk函数返回类型
using WR = std::pair<ECM, WRV>;                       // iwalk函数返回类型
using SIZER = std::pair<ECM, uint64_t>;               // getsize函数返回类型
using CR =
    std::pair<ECM, std::pair<std::string, size_t>>; // ConductCmd函数返回类型
inline bool isdir(const LIBSSH2_SFTP_ATTRIBUTES &attrs);
inline bool isreg(const LIBSSH2_SFTP_ATTRIBUTES &attrs);
inline bool IsValidKey(const std::string &key);

// Wait result for non-blocking socket operations

class AMTracer {
private:
  py::function trace_cb;
  std::vector<TraceInfo> buffer = {};
  std::mutex buffer_mutex;
  ssize_t capacity = 10;
  std::atomic<bool> is_py_trace = false;
  std::atomic<bool> is_trace_pause = false;
  std::unordered_map<std::string, py::object> public_var_dict;
  std::mutex public_var_mutex; // 专门用于保护 public_var_dict 的锁
  py::object deepcopy_func;    // 缓存的 deepcopy 函数
protected:
  ConRequst res_data;
  void push(const TraceInfo &value) {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    if (buffer.size() < static_cast<size_t>(capacity)) {
      buffer.push_back(value);
    } else {
      buffer.erase(buffer.begin());
      buffer.push_back(value);
    }
  }
  std::string nickname;

public:
  AMTracer(const ConRequst &request, int buffer_capacity = 10,
           const py::object &trace_cb = py::none())
      : res_data(request), nickname(request.nickname) {
    if (buffer_capacity > 0) {
      capacity = buffer_capacity;
    }
    buffer.reserve(capacity);
    if (!trace_cb.is_none()) {
      this->trace_cb = py::cast<py::function>(trace_cb);
      this->is_py_trace = true;
    } else {
      this->is_py_trace = false;
    }
    // 初始化时导入 deepcopy 函数并缓存
    try {
      py::gil_scoped_acquire gil;
      py::module_ copy_module = py::module_::import("copy");
      deepcopy_func = copy_module.attr("deepcopy");
    } catch (const py::error_already_set &e) {
      // 如果导入失败，deepcopy_func 保持为 none
      deepcopy_func = py::none();
      trace(TraceLevel::Error, EC::DeepcopyFunctionNotAvailable,
            "Deepcopy Function", "Initialize",
            fmt::format("Failed to import copy module: {}", e.what()));
    }
  }
  ECM SetPublicVar(const std::string &key, py::object value,
                   bool overwrite = false) {
    std::lock_guard<std::mutex> lock(public_var_mutex);

    if (!overwrite && public_var_dict.find(key) != public_var_dict.end()) {
      return {
          EC::KeyAlreadyExists,
          fmt::format("Key already exists and overwrite is false: {}", key)};
    }

    // 使用缓存的 deepcopy 函数来创建深拷贝
    // 这样 C++ 拥有对象的完整副本，不受 Python 端修改影响
    if (!deepcopy_func.is_none()) {
      try {
        py::gil_scoped_acquire gil;
        public_var_dict[key] = deepcopy_func(value);
        return {EC::Success, ""};
      } catch (const py::error_already_set &e) {
        // 如果深拷贝失败（某些对象不支持深拷贝）
        return {
            EC::DeepcopyFailed,
            fmt::format(
                "Deepcopy failed, object is not supported to be stored: {}: {}",
                key, e.what())};
      }
    } else {
      return {EC::DeepcopyFunctionNotAvailable,
              "Deepcopy function not available"};
    }
  }

  py::object GetPublicVar(const std::string &key,
                          py::object default_value = py::none()) {
    std::lock_guard<std::mutex> lock(public_var_mutex);

    auto it = public_var_dict.find(key);
    if (it != public_var_dict.end()) {
      return it->second;
    }

    // 键不存在，返回默认值
    return default_value;
  }

  bool DelPublicVar(const std::string &key) {
    // 确保持有 GIL，因为要操作 py::object
    py::gil_scoped_acquire gil;
    std::lock_guard<std::mutex> lock(public_var_mutex);
    return public_var_dict.erase(key) > 0;
  }

  void ClearPublicVar() {
    // 确保持有 GIL，因为要销毁 py::object
    py::gil_scoped_acquire gil;
    std::lock_guard<std::mutex> lock(public_var_mutex);
    public_var_dict.clear();
  }

  py::dict GetAllPublicVars() {
    std::lock_guard<std::mutex> lock(public_var_mutex);
    py::gil_scoped_acquire gil;
    py::dict result;
    if (!deepcopy_func.is_none()) {
      // 使用缓存的 deepcopy 函数
      for (const auto &[key, value] : public_var_dict) {
        try {
          result[py::str(key)] = deepcopy_func(value);
        } catch (const py::error_already_set) {
          // 深拷贝失败，使用原始引用
          continue;
        }
      }
    }
    return result;
  }

  size_t GetTraceNum() {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    return buffer.size();
  }

  std::shared_ptr<TraceInfo> LastTrace() {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    if (buffer.size() == 0) {
      return nullptr;
    }
    return std::make_shared<TraceInfo>(buffer[buffer.size() - 1]);
  }

  std::vector<TraceInfo> GetAllTraces() {
    std::vector<TraceInfo> result;
    result.reserve(buffer.size());
    for (auto &item : buffer) {
      result.push_back(item);
    }
    return result;
  }

  void ClearTracer() {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    buffer.clear();
  }

  size_t TracerCapacity(ssize_t size = 0) {
    if (size <= 0) {
      return capacity;
    }

    if (size > capacity) {
      capacity = size;
      return capacity;
    } else {
      std::lock_guard<std::mutex> lock(buffer_mutex);
      buffer.resize(size);
      capacity = size;
      return capacity;
    }
  }

  void trace(TraceLevel level, EC error_code, const std::string &target = "",
             const std::string &action = "", const std::string &msg = "") {
    this->trace(TraceInfo(level, error_code, nickname, target, action, msg));
  }

  void trace(const TraceInfo &trace_info) {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    if (is_trace_pause.load()) {
      return;
    }
    this->push(trace_info);
    if (is_py_trace.load()) {
      try {
        py::gil_scoped_acquire acquire;
        trace_cb(trace_info);
      } catch (const py::error_already_set &e) {
        // 如果trace_cb抛出异常，忽略
        return;
      }
    }
    this->push(trace_info);
  }

  void SetTraceState(bool is_pause) { is_trace_pause.store(is_pause); }

  void SetPyTrace(const py::object &trace = py::none()) {
    if (trace.is_none()) {
      is_py_trace.store(false);
      trace_cb = py::function();
    } else {
      trace_cb = py::cast<py::function>(trace);
      is_py_trace.store(true);
    }
  }

  inline std::string GetNickname() { return this->nickname; }

  inline ConRequst GetRequest() { return this->res_data; }
};

class SafeChannel {
public:
  LIBSSH2_CHANNEL *channel = nullptr;
  bool closed = false; // 标记是否已正常关闭

  ~SafeChannel() {
    if (channel) {
      if (!closed) {
        // 未正常关闭，需要发信号终止远程进程
        libssh2_channel_send_eof(channel);
        libssh2_channel_signal(channel, "TERM");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        libssh2_channel_signal(channel, "KILL");
        libssh2_channel_close(channel);
      }
      libssh2_channel_free(channel);
      channel = nullptr;
    }
  }

  // 正常关闭 channel（阻塞模式）
  // 成功返回 true，失败返回 false
  bool close() {
    if (!channel || closed) {
      return closed;
    }
    if (libssh2_channel_close(channel) == 0 &&
        libssh2_channel_wait_closed(channel) == 0) {
      closed = true;
    }
    return closed;
  }

  // 非阻塞关闭，需配合 wait_for_socket 使用
  // 返回值: 0=成功, EAGAIN=需等待, <0=错误
  int close_nonblock() {
    if (!channel)
      return -1;
    if (closed)
      return 0;

    int rc = libssh2_channel_close(channel);
    if (rc == 0) {
      rc = libssh2_channel_wait_closed(channel);
      if (rc == 0) {
        closed = true;
      }
    }
    return rc;
  }

  SafeChannel(LIBSSH2_SESSION *session) {
    this->channel =
        libssh2_channel_open_ex(session, "session", sizeof("session") - 1,
                                4 * AMMB, 32 * AMKB, nullptr, 0);
  }
};

class BaseClient : public AMTracer, public BasePathMatch {
private:
  ssize_t buffer_size = AMMB * 8;
  ECM state = {EC::NoConnection, "Client Not Initialized"};

protected:
  std::atomic<bool> terminate_cmd = false;
  ClientProtocol PROTOCOL = ClientProtocol::Base;
  // NOLINTNEXTLINE
  virtual void SetState(const ECM &state) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: SetState", GetProtocolName()));
  }

public:
  OS_TYPE os_type = OS_TYPE::Uncertain;
  std::string home_dir = "";
  std::string trash_dir = "";
  virtual ~BaseClient() = default;
  BaseClient(const ConRequst &request, int buffer_capacity = 10,
             const py::object &trace_cb = py::none())
      : AMTracer(request, buffer_capacity, trace_cb), BasePathMatch() {}
  ClientProtocol GetProtocol() { return PROTOCOL; }
  ssize_t TransferRingBufferSize(ssize_t buffer_size = -1) {
    if (buffer_size <= 0) {
      return this->buffer_size;
    }
    this->buffer_size = buffer_size;
    return this->buffer_size;
  }

  std::string GetProtocolName() {
    switch (PROTOCOL) {
    case ClientProtocol::Base:
      return "base";
    case ClientProtocol::SFTP:
      return "sftp";
    case ClientProtocol::FTP:
      return "ftp";
    case ClientProtocol::LOCAL:
      return "local";
    default:
      return "unknown";
    }
  }

  std::variant<ECM, std::string>
  TrashDir(const std::string &trash_dir = "", amf interrupt_flag = nullptr,
           int timeout_ms = -1,
           std::chrono::steady_clock::time_point start_time =
               std::chrono::steady_clock::now()) {
    if (trash_dir.empty()) {
      return this->trash_dir;
    }
    ECM rcm = mkdirs(trash_dir, interrupt_flag, timeout_ms, start_time);
    if (rcm.first == EC::Success) {
      this->trash_dir = trash_dir;
    }
    return rcm;
  }

  ECM GetState() { return this->state; };

  // NOLINTBEGIN
  virtual ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
                    std::chrono::steady_clock::time_point start_time =
                        std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: Check", GetProtocolName()));
  }

  virtual ECM Connect(bool force = false, amf interrupt_flag = nullptr,
                      int timeout_ms = -1,
                      std::chrono::steady_clock::time_point start_time =
                          std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: Connect", GetProtocolName()));
  }

  virtual OS_TYPE GetOSType(bool update = false) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: GetOSType", GetProtocolName()));
  }

  virtual double GetRTT(ssize_t times = 5, amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: GetRTT", GetProtocolName()));
  }

  virtual CR ConductCmd(const std::string &cmd, int max_time_s = -1,
                        amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: ConductCmd", GetProtocolName()));
  }

  virtual std::string StrUid(const long &uid) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: StrUid", GetProtocolName()));
  }

  virtual std::string GetHomeDir() {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: GetHomeDir", GetProtocolName()));
  }

  virtual std::pair<ECM, std::string>
  realpath(const std::string &path, amf interrupt_flag = nullptr,
           int timeout_ms = -1,
           std::chrono::steady_clock::time_point start_time =
               std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: realpath", GetProtocolName()));
  }
  virtual std::pair<ECM, std::unordered_map<std::string, ECM>>
  chmod(const std::string &path, std::variant<std::string, uint64_t> mode,
        bool recursive = false, amf interrupt_flag = nullptr,
        int timeout_ms = -1,
        std::chrono::steady_clock::time_point start_time =
            std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: chmod", GetProtocolName()));
  }
  virtual SR stat(const std::string &path, amf interrupt_flag = nullptr,
                  int timeout_ms = -1,
                  std::chrono::steady_clock::time_point start_time =
                      std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: stat", GetProtocolName()));
  }
  virtual std::pair<ECM, PathType>
  get_path_type(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1,
                std::chrono::steady_clock::time_point start_time =
                    std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(
        fmt::format("{} Client doesn't implement funtion: get_path_type",
                    GetProtocolName()));
  }
  virtual std::pair<ECM, bool>
  exists(const std::string &path, amf interrupt_flag = nullptr,
         int timeout_ms = -1,
         std::chrono::steady_clock::time_point start_time =
             std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: exists", GetProtocolName()));
  }
  virtual std::pair<ECM, bool>
  is_regular(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: is_regular", GetProtocolName()));
  }
  virtual std::pair<ECM, bool>
  is_dir(const std::string &path, amf interrupt_flag = nullptr,
         int timeout_ms = -1,
         std::chrono::steady_clock::time_point start_time =
             std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: is_dir", GetProtocolName()));
  }
  virtual std::pair<ECM, bool>
  is_symlink(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: is_symlink", GetProtocolName()));
  }
  virtual std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1,
          std::chrono::steady_clock::time_point start_time =
              std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: listdir", GetProtocolName()));
  }
  virtual ECM mkdir(const std::string &path, amf interrupt_flag = nullptr,
                    int timeout_ms = -1,
                    std::chrono::steady_clock::time_point start_time =
                        std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: mkdir", GetProtocolName()));
  }
  virtual ECM mkdirs(const std::string &path, amf interrupt_flag = nullptr,
                     int timeout_ms = -1,
                     std::chrono::steady_clock::time_point start_time =
                         std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: mkdirs", GetProtocolName()));
  };

  virtual std::string GetAvailableTrashDir() {
    throw UnimplementedMethodException(
        fmt::format("{} Client doesn't implement funtion: GetAvailableTrashDir",
                    GetProtocolName()));
  }

  virtual ECM EnsureTrashDir() {
    throw UnimplementedMethodException(
        fmt::format("{} Client doesn't implement funtion: EnsureTrashDir",
                    GetProtocolName()));
  }

  virtual ECM rmdir(const std::string &path, amf interrupt_flag = nullptr,
                    int timeout_ms = -1,
                    std::chrono::steady_clock::time_point start_time =
                        std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: rmdir", GetProtocolName()));
  }
  virtual ECM rmfile(const std::string &path, amf interrupt_flag = nullptr,
                     int timeout_ms = -1,
                     std::chrono::steady_clock::time_point start_time =
                         std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: rmfile", GetProtocolName()));
  }
  virtual ECM rename(const std::string &src, const std::string &dst,
                     bool mkdir = true, bool overwrite = false,
                     amf interrupt_flag = nullptr, int timeout_ms = -1,
                     std::chrono::steady_clock::time_point start_time =
                         std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: rename", GetProtocolName()));
  }
  virtual std::pair<ECM, RMR>
  remove(const std::string &path, amf interrupt_flag = nullptr,
         int timeout_ms = -1,
         std::chrono::steady_clock::time_point start_time =
             std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: remove", GetProtocolName()));
  };
  virtual ECM saferm(const std::string &path, amf interrupt_flag = nullptr,
                     int timeout_ms = -1,
                     std::chrono::steady_clock::time_point start_time =
                         std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: saferm", GetProtocolName()));
  }
  virtual ECM move(const std::string &src, const std::string &dst,
                   bool need_mkdir = false, bool force_write = false,
                   amf interrupt_flag = nullptr, int timeout_ms = -1,
                   std::chrono::steady_clock::time_point start_time =
                       std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: move", GetProtocolName()));
  }
  virtual ECM copy(const std::string &src, const std::string &dst,
                   bool need_mkdir = false, int timeout_ms = -1,
                   amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: copy", GetProtocolName()));
  }
  virtual WRV iwalk(const std::string &path, bool ignore_sepcial_file = true,
                    amf interrupt_flag = nullptr, int timeout_ms = -1,
                    std::chrono::steady_clock::time_point start_time =
                        std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: iwalk", GetProtocolName()));
  }
  virtual std::pair<ECM, WRD>
  walk(const std::string &path, int max_depth = -1,
       bool ignore_special_file = true, amf interrupt_flag = nullptr,
       int timeout_ms = -1,
       std::chrono::steady_clock::time_point start_time =
           std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: walk", GetProtocolName()));
  }
  virtual uint64_t getsize(const std::string &path,
                           bool ignore_sepcial_file = true,
                           amf interrupt_flag = nullptr, int timeout_ms = -1,
                           std::chrono::steady_clock::time_point start_time =
                               std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: getsize", GetProtocolName()));
  }
  // NOLINTEND

  std::pair<bool, PathInfo> istat(const std::string &path) override {
    auto [rcm, sr] = stat(path);
    if (rcm.first != EC::Success) {
      return std::make_pair(false, PathInfo());
    }
    return std::make_pair(true, sr);
  }

  std::vector<PathInfo> ilistdir(const std::string &path) override {
    auto [rcm, sr] = listdir(path);
    if (rcm.first != EC::Success) {
      return {};
    }
    return sr;
  }

  std::vector<PathInfo> iiwalk(const std::string &path) override {
    return iwalk(path);
  }
};

class AMSession : public BaseClient {
protected:
  amf session_interrupt_flag = nullptr;
  std::atomic<bool> has_connected;
  SOCKET sock = INVALID_SOCKET;
  void SetState(const ECM &state) override {
    std::lock_guard<std::mutex> lock(state_mtx);
    CurError = state;
  }
  // Optimized wait_for_socket: reduces overhead from frequent calls
  inline WaitResult
  wait_for_socket(SocketWaitType wait_dir, const amf &flag = nullptr,
                  std::chrono::steady_clock::time_point start_time =
                      std::chrono::steady_clock::now(),
                  int64_t timeout_ms = -1, int poll_interval_ms = 50) {
    // Fast path: check if socket is already ready without select
    if (wait_dir == SocketWaitType::Auto) {
      int dir = libssh2_session_block_directions(session);
      if (dir == 0) {
        return WaitResult::Ready;
      }
    }

    // Pre-check interrupt and timeout before entering select
    if (flag && flag->check()) {
      return WaitResult::Interrupted;
    }
    if (timeout_ms > 0) {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - start_time)
                         .count();
      if (elapsed >= timeout_ms) {
        return WaitResult::Timeout;
      }
    }

    // Pre-compute wait directions (avoid repeated switch in loop)
    bool wait_read = false;
    bool wait_write = false;
    bool is_auto = (wait_dir == SocketWaitType::Auto);

    if (!is_auto) {
      switch (wait_dir) {
      case SocketWaitType::Read:
        wait_read = true;
        break;
      case SocketWaitType::Write:
        wait_write = true;
        break;
      case SocketWaitType::ReadWrite:
        wait_read = true;
        wait_write = true;
        break;
      default:
        break;
      }
    }

    // Pre-compute timeval (reuse in loop)
    struct timeval tv;
    tv.tv_sec = poll_interval_ms / 1000;
    tv.tv_usec = (poll_interval_ms % 1000) * 1000;

    while (true) {
      fd_set readfds, writefds;
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);

      if (is_auto) {
        int dir = libssh2_session_block_directions(session);
        if (dir == 0) {
          return WaitResult::Ready;
        }
        if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
          FD_SET(sock, &readfds);
        }
        if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
          FD_SET(sock, &writefds);
        }
      } else {
        if (wait_read) {
          FD_SET(sock, &readfds);
        }
        if (wait_write) {
          FD_SET(sock, &writefds);
        }
      }

#ifdef _WIN32
      int rc = select(0, &readfds, &writefds, nullptr, &tv);
#else
      int rc = select(sock + 1, &readfds, &writefds, nullptr, &tv);
#endif

      if (rc > 0) {
        return WaitResult::Ready;
      }
      if (rc < 0) {
        return WaitResult::Error;
      }

      // rc == 0: select timeout, check interrupt and timeout
      if (flag && flag->check()) {
        return WaitResult::Interrupted;
      }
      if (timeout_ms > 0) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start_time)
                           .count();
        if (elapsed >= timeout_ms) {
          return WaitResult::Timeout;
        }
      }
    }
  }

  // 非阻塞执行 libssh2 函数（返回 int 类型，EAGAIN 表示需要等待）
  // 用法: auto result = nb_exec(flag, timeout_ms, libssh2_sftp_unlink, sftp,
  // path);
  template <typename Func, typename... Args>
  auto nb_exec(const amf &interrupt_flag, int64_t timeout_ms, Func &&func,
               Args &&...args)
      -> NBResult<decltype(func(std::forward<Args>(args)...))> {
    using RetType = decltype(func(std::forward<Args>(args)...));

    auto time_start = std::chrono::steady_clock::now();
    libssh2_session_set_blocking(session, 0);

    RetType rc;
    WaitResult wr = WaitResult::Ready;

    while (true) {
      rc = func(std::forward<Args>(args)...);

      // 对于返回 int 的函数，EAGAIN 表示需要等待
      if constexpr (std::is_same_v<RetType, int> ||
                    std::is_same_v<RetType, ssize_t>) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
          break;
        }
      }
      // 对于返回指针的函数，nullptr + EAGAIN 表示需要等待
      else if constexpr (std::is_pointer_v<RetType>) {
        if (rc != nullptr ||
            libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) {
          break;
        }
      } else {
        break; // 其他类型直接返回
      }

      wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, time_start,
                           timeout_ms);
      if (wr != WaitResult::Ready) {
        libssh2_session_set_blocking(session, 1);
        return {rc, wr};
      }
    }

    libssh2_session_set_blocking(session, 1);
    return {rc, WaitResult::Ready};
  }

  ECM ErrorRecord(int code, TraceLevel level, const std::string &taregt,
                  const std::string &action, std::string prompt = "") {
    if (code < 0) {
      return {EC::Success, ""};
    }
    auto ec = GetLastEC();
    auto msg = GetLastErrorMsg();
    if (prompt.empty()) {
      prompt = fmt::format("{} on {} error:{}", action, taregt, msg);
    } else {
      AMStr::vreplace(prompt, "{action}", action);
      AMStr::vreplace(prompt, "{target}", taregt);
      AMStr::vreplace(prompt, "{error}", msg);
    }
    trace(level, ec, taregt, action, prompt);
    return {ec, prompt};
  }

  // NBResult 版本的 ErrorRecord
  // 处理: 超时、终止、socket error、执行完成但报错、执行成功
  // 返回 {EC::Success, ""} 表示成功，其他表示失败
  template <typename T>
  ECM ErrorRecord(const NBResult<T> &result, TraceLevel level,
                  const std::string &target, const std::string &action,
                  std::string prompt = "") {
    // 1. 超时
    if (result.is_timeout()) {
      std::string msg = fmt::format("{} on {} timeout", action, target);
      trace(level, EC::OperationTimeout, target, action, msg);
      return {EC::OperationTimeout, msg};
    }

    // 2. 终止
    if (result.is_interrupted()) {
      std::string msg =
          fmt::format("{} on {} interrupted by user", action, target);
      trace(level, EC::Terminate, target, action, msg);
      return {EC::Terminate, msg};
    }

    // 3. Socket error
    if (result.is_error()) {
      std::string msg = fmt::format("Encountered socket error during {} on {}",
                                    action, target);
      trace(level, EC::SocketRecvError, target, action, msg);
      return {EC::SocketRecvError, msg};
    }

    // 4 & 5. 执行完成 - 检查返回值判断是否报错
    // 对于 int/ssize_t: < 0 表示失败（但 LIBSSH2 中 0 表示成功）
    // 对于指针: nullptr 表示失败
    if constexpr (std::is_same_v<T, int> || std::is_same_v<T, ssize_t>) {
      if (result.value < 0) {
        // 执行完成但报错
        auto ec = GetLastEC();
        auto errmsg = GetLastErrorMsg();
        std::string msg = prompt.empty() ? fmt::format("{} on {} error: {}",
                                                       action, target, errmsg)
                                         : prompt;
        AMStr::vreplace(msg, "{action}", action);
        AMStr::vreplace(msg, "{target}", target);
        AMStr::vreplace(msg, "{error}", errmsg);
        trace(level, ec, target, action, msg);
        return {ec, msg};
      }
    } else if constexpr (std::is_pointer_v<T>) {
      if (result.value == nullptr) {
        auto ec = GetLastEC();
        auto errmsg = GetLastErrorMsg();
        std::string msg = prompt.empty() ? fmt::format("{} on {} error: {}",
                                                       action, target, errmsg)
                                         : prompt;
        AMStr::vreplace(msg, "{action}", action);
        AMStr::vreplace(msg, "{target}", target);
        AMStr::vreplace(msg, "{error}", errmsg);
        trace(level, ec, target, action, msg);
        return {ec, msg};
      }
    }

    // 5. 执行成功
    return {EC::Success, ""};
  }

private:
  ECM CurError = {EC::NoConnection, "Connection not established"};
  std::mutex state_mtx;
  int64_t poll_interval_ms = 20;

  bool password_auth_cb = false;
  std::vector<std::string> private_keys;
  py::function auth_cb = py::function(); // Callable[[IsPasswordDemand:bool,
                                         // ConRequst, TrialTimes:int], str]

  void LoadDefaultPrivateKeys() {
    trace(TraceLevel::Debug, EC::Success, "~/.ssh", "LoadDefaultPrivateKeys",
          "Shared private keys not provided, loading default private keys from "
          "~/.ssh");
    auto listd = AMFS::listdir("~/.ssh");
    for (auto &info : listd) {
      if (info.type == PathType::FILE) {
        if (IsValidKey(info.path)) {
          this->private_keys.push_back(info.path);
        }
      }
    }
  }

  void Disconnect() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    has_connected.store(false);
    if (sftp) {
      libssh2_sftp_shutdown(sftp);
      sftp = nullptr;
    }
    if (session) {
      libssh2_session_disconnect(session, "Normal Shutdown");
      libssh2_session_free(session);
      session = nullptr;
    }
    if (sock != INVALID_SOCKET) {
#ifdef _WIN32
      closesocket(sock);
#else
      close(sock);
#endif
      sock = INVALID_SOCKET;
    }
  }

public:
  LIBSSH2_SESSION *session = nullptr;
  LIBSSH2_SFTP *sftp = nullptr;
  ConRequst res_data;
  std::recursive_mutex mtx; // lock of the session and sftp

  virtual ~AMSession() { Disconnect(); }

  AMSession(const ConRequst &request,
            const std::vector<std::string> &private_keys,
            ssize_t error_num = 10, const py::object &trace_cb = py::none(),
            const py::object &auth_cb = py::none())
      : BaseClient(request, error_num, trace_cb), private_keys(private_keys),
        res_data(request) {
    if (!auth_cb.is_none()) {
      this->auth_cb = py::cast<py::function>(auth_cb);
      this->password_auth_cb = true;
    }
    if (private_keys.empty()) {
      LoadDefaultPrivateKeys();
    }
    has_connected.store(false);
  }

  // 便捷宏/lambda 版本，用于更简洁的调用
  // 用法: auto result = nb_call(flag, timeout, [&]{ return
  // libssh2_sftp_unlink(sftp, path); });
  template <typename Func>
  auto nb_call(const amf interrupt_flag, int64_t timeout_ms,
               std::chrono::steady_clock::time_point start_time, Func &&func)
      -> NBResult<decltype(func())> {
    using RetType = decltype(func());

    libssh2_session_set_blocking(session, 0);

    RetType rc;
    WaitResult wr = WaitResult::Ready;

    while (true) {
      rc = func();

      if constexpr (std::is_same_v<RetType, int> ||
                    std::is_same_v<RetType, ssize_t>) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
          break;
        }
      } else if constexpr (std::is_pointer_v<RetType>) {
        if (rc != nullptr ||
            libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) {
          break;
        }
      } else {
        break;
      }

      wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, start_time,
                           timeout_ms, poll_interval_ms);
      if (wr != WaitResult::Ready) {
        libssh2_session_set_blocking(session, 1);
        return {rc, wr};
      }
    }

    libssh2_session_set_blocking(session, 1);
    return {rc, WaitResult::Ready};
  }

  std::vector<std::string> GetKeys() { return this->private_keys; }

  void SetKeys(const std::vector<std::string> &keys) {
    this->private_keys = keys;
  }

  ECM GetState() override {
    std::lock_guard<std::mutex> lock(state_mtx);
    return CurError;
  }

  ECM Check(int timeout_ms = -1, amf interrupt_flag = nullptr) override {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    if (!session) {
      return {EC::NoSession, "Session not initialized"};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    char path_t[1024];
    ECM rcm;
    auto ori_res = nb_exec(interrupt_flag, timeout_ms, [&] {
      return libssh2_sftp_realpath(sftp, ".", path_t, sizeof(path_t));
    });
    switch (ori_res.status) {
    case WaitResult::Ready:
      rcm = ErrorRecord(ori_res.value, TraceLevel::Debug, ".", "Check",
                        "Sftp status check failed: {error}");
      SetState(rcm);
      return rcm;
    case WaitResult::Timeout:
      rcm = {EC::OperationTimeout, "Check timedout"};
      SetState(rcm);
      return rcm;
    case WaitResult::Interrupted:
      rcm = {EC::Terminate, "Check was interrupted"};
      return rcm;
    case WaitResult::Error:
      rcm = {EC::SocketRecvError, "Check socket error"};
      SetState(rcm);
      return rcm;
    }
  }

  ECM BaseConnect(bool force = false, int timeout_ms = -1,
                  amf interrupt_flag = nullptr) {
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (has_connected.load()) {
      if (!force) {
        return GetState();
      }
      Disconnect();
      has_connected.store(false);
    }

    ECM rcm = {EC::Success, ""};
    int rcr;
    auto time_start = std::chrono::steady_clock::now();
    WaitResult wr = WaitResult::Ready;
    bool password_auth;
    std::string password_tmp;
    const char *auth_list = nullptr;

    // 使用SocketConnector建立连接
    SocketConnector connector;

    if (!connector.Connect(res_data.hostname, res_data.port, timeout_ms)) {
      trace(TraceLevel::Critical, connector.error_code,
            fmt::format("{}", connector.sock), "SocketConnector.Connect",
            connector.error_msg);
      return {connector.error_code, connector.error_msg};
    }
    sock = connector.sock;

    // 检查中断/超时
    if (interrupt_flag && interrupt_flag->check()) {
      return {EC::Terminate, "Connection interrupted"};
    }
    if (timeout_ms > 0) {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - time_start)
                         .count();
      if (elapsed >= timeout_ms) {
        return {EC::OperationTimeout, "Connection timed out"};
      }
    }

    session = libssh2_session_init();
    if (!session) {
      trace(TraceLevel::Critical, EC::SessionCreateFailed, "",
            "libssh2_session_init", "Session initialization failed");
      return {EC::SessionCreateFailed, "Libssh2 Session initialization failed"};
    }

    // 设置非阻塞模式进行握手
    libssh2_session_set_blocking(session, 0);

    if (res_data.compression) {
      libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
      libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS,
                                  "zlib@openssh.com,zlib,none");
    }

    // 非阻塞握手
    while ((rcr = libssh2_session_handshake(session, sock)) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, time_start,
                           timeout_ms);
      if (wr != WaitResult::Ready) {
        goto interrupted_or_sock_error;
      }
    }
    rcm = ErrorRecord(rcr, TraceLevel::Critical, fmt::format("socket {}", sock),
                      "libssh2_session_handshake");
    if (rcm.first != EC::Success) {
      goto interrupted_or_sock_error;
    }

    // 获取认证列表（非阻塞）

    while ((auth_list =
                libssh2_userauth_list(session, res_data.username.c_str(),
                                      res_data.username.length())) == nullptr &&
           libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, time_start,
                           timeout_ms);
      if (wr != WaitResult::Ready) {
        goto interrupted_or_sock_error;
      }
    }

    if (auth_list == nullptr) {
      rcm = ErrorRecord(-1, TraceLevel::Critical, "", "GetAuthList",
                        "Fail to {action} : {error}");
      goto interrupted_or_sock_error;
    }

    trace(TraceLevel::Debug, EC::Success, res_data.username,
          "libssh2_userauth_list",
          fmt::format("Authentication methods: {}", auth_list));

    // ========== 进入认证阶段，不再检测 timeout ==========
    // 切换到阻塞模式，简化认证流程（认证可能涉及用户交互）
    libssh2_session_set_blocking(session, 1);

    password_auth = (strstr(auth_list, "password") != nullptr);

    // 专用私钥认证
    if (!res_data.keyfile.empty()) {
      // 检查中断（不检查超时）
      if (interrupt_flag && interrupt_flag->check()) {
        return {EC::Terminate, "Authentication interrupted"};
      }
      rcr = libssh2_userauth_publickey_fromfile(
          session, res_data.username.c_str(), nullptr, res_data.keyfile.c_str(),
          nullptr);
      if (rcr == 0) {
        trace(TraceLevel::Info, EC::Success, "Success",
              "PrivatedKeyAuthorizeResult",
              fmt::format("Dedicated private key \"{}\" authorize success",
                          res_data.keyfile));
        goto OK;
      } else {
        trace(TraceLevel::Debug, EC::PublickeyAuthFailed, res_data.keyfile,
              "DedicatedPrivateKeyAuthorizeResult",
              fmt::format("Dedicated private key \"{}\" authorize success",
                          res_data.keyfile));
      }
    }

    // 密码认证
    if (!res_data.password.empty() && password_auth) {
      if (interrupt_flag && interrupt_flag->check()) {
        return {EC::Terminate, "Authentication interrupted"};
      }
      rcr = libssh2_userauth_password(session, res_data.username.c_str(),
                                      res_data.password.c_str());
      if (rcr == 0) {
        trace(TraceLevel::Info, EC::Success, "Success",
              "PasswordAuthorizeResult", "Password authorize success");
        goto OK;
      } else {
        trace(TraceLevel::Debug, EC::AuthFailed, res_data.password,
              "PasswordAuth",
              fmt::format("Wrong Password: {}", res_data.password));
      }
    }

    // 共享私钥认证
    if (!private_keys.empty()) {
      for (auto private_key : private_keys) {
        if (interrupt_flag && interrupt_flag->check()) {
          return {EC::Terminate, "Authentication interrupted"};
        }
        if (private_key == res_data.keyfile) {
          continue;
        }
        rcr = libssh2_userauth_publickey_fromfile(
            session, res_data.username.c_str(), nullptr, private_key.c_str(),
            nullptr);
        if (rcr == 0) {
          trace(TraceLevel::Info, EC::Success, private_key,
                "PrivatedKeyAuthorizeResult",
                fmt::format("Shared private key \"{}\" authorize success",
                            private_key));
          goto OK;
        } else {
          trace(TraceLevel::Debug, EC::PrivateKeyAuthFailed, "Failed",
                "PrivatedKeyAuthorizeResult", rcm.second);
        }
      }
    }

    // 交互式密码认证回调
    if (password_auth_cb && password_auth) {
      trace(TraceLevel::Info, EC::Success, "Interactive", "PasswordAuthorize",
            "Using password authentication callback to get another password");
      int trial_times = 0;
      while (trial_times < 2) {
        if (interrupt_flag && interrupt_flag->check()) {
          return {EC::Terminate, "Authentication interrupted"};
        }
        {
          py::gil_scoped_acquire acquire;
          try {
            password_tmp = py::cast<std::string>(
                auth_cb(AuthCBInfo(true, res_data, trial_times)));
          } catch (const std::exception &e) {
            trace(TraceLevel::Error, EC::PyCBError, "AuthCB", "Call",
                  fmt::format("Password authentication callback error: {}",
                              e.what()));
            break;
          }
        }
        if (password_tmp.empty()) {
          break;
        }
        rcr = libssh2_userauth_password(session, res_data.username.c_str(),
                                        password_tmp.c_str());
        trial_times++;
        if (rcr == 0) {
          trace(TraceLevel::Info, EC::Success, "Success",
                "PasswordAuthorizeResult", "Password authorize success");
          goto OK;
        } else {
          trace(TraceLevel::Debug, EC::AuthFailed, "Failed",
                "PasswordAuthorizeResult",
                fmt::format("Wrong Password: {}", password_tmp));
          {
            py::gil_scoped_acquire acquire;
            auth_cb(false, res_data, trial_times);
          }
        }
      }
    }
    rcm.first = EC::AuthFailed;
    rcm.second = "All authorize methods failed";

  OK:
    // 检查中断
    if (rcm.first != EC::Success) {
      Disconnect();
      return rcm;
    }

    sftp = libssh2_sftp_init(session);
    rcm =
        ErrorRecord(sftp ? 0 : -1, TraceLevel::Critical, "",
                    "libssh2_sftp_init", "SFTP initialization failed: {error}");
    if (rcm.first != EC::Success) {
      Disconnect();
      return rcm;
    }

    has_connected.store(true);
    return {EC::Success, ""};

  interrupted_or_sock_error:
    libssh2_session_set_blocking(session, 1);
    Disconnect();
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Connection timed out during handshake"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Connection interrupted during handshake"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during handshake"};
    default:
      return {EC::UnknownError,
              "Logic error, waitresult is ok but enter fail branch"};
    }
  }

  EC GetLastEC() {
    if (!session) {
      return EC::NoSession;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    int ori_code = libssh2_session_last_errno(session);
    if (ori_code != LIBSSH2_ERROR_SFTP_PROTOCOL) {
      return Int2EC.at(ori_code);
    } else {
      if (!sftp) {
        return EC::NoConnection;
      }
      int ori_code2 = libssh2_sftp_last_error(sftp);
      return Int2EC.at(ori_code2);
    }
  }

  std::string GetLastErrorMsg() {
    if (!session) {
      return "Session not initialized";
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    int ori_code = libssh2_session_last_errno(session);
    if (ori_code != LIBSSH2_ERROR_SFTP_PROTOCOL) {
      char *errmsg = nullptr;
      int errmsg_len;
      libssh2_session_last_error(session, &errmsg, &errmsg_len, 0);
      return errmsg;
    } else {
      if (!sftp) {
        return "SFTP not initialized";
      }
      int ori_code2 = libssh2_sftp_last_error(sftp);

      if (SFTPMessage.find(ori_code2) != SFTPMessage.end()) {
        return SFTPMessage.at(ori_code2);
      }
      return "Unknown SFTP error";
    }
  }

  void SetAuthCallback(const py::object &auth_cb = py::none()) {
    if (auth_cb.is_none()) {
      this->password_auth_cb = false;
      this->auth_cb = py::function();
    } else {
      this->auth_cb = py::cast<py::function>(auth_cb);
      this->password_auth_cb = true;
    }
  }
};

class AMSFTPClient : public AMSession {
private:
  std::map<long, std::string> user_id_map;
  bool is_trash_dir_ensure = false;

  PathInfo FormatStat(const std::string &path,
                      const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
    PathInfo info;
    info.path = path;
    info.name = AMFS::basename(path);
    info.dir = AMFS::dirname(path);
    long uid = attrs.uid;
    std::string user_name = StrUid(uid);
    if (user_name.empty()) {
      info.owner = res_data.username;
    } else {
      info.owner = user_name;
    }

    if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
      info.size = attrs.filesize;
    }

    if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
      info.access_time = attrs.atime;
      info.modify_time = attrs.mtime;
    }

    if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
      const uint32_t mode = attrs.permissions;
      const uint32_t file_type = mode & LIBSSH2_SFTP_S_IFMT;
      switch (file_type) {
      case LIBSSH2_SFTP_S_IFDIR:
        info.type = PathType::DIR;
        break;
      case LIBSSH2_SFTP_S_IFLNK:
        info.type = PathType::SYMLINK;
        break;
      case LIBSSH2_SFTP_S_IFREG:
        info.type = PathType::FILE;
        break;
      case LIBSSH2_SFTP_S_IFBLK:
        info.type = PathType::BlockDevice;
        break;
      case LIBSSH2_SFTP_S_IFCHR:
        info.type = PathType::CharacterDevice;
        break;
      case LIBSSH2_SFTP_S_IFSOCK:
        info.type = PathType::Socket;
        break;
      case LIBSSH2_SFTP_S_IFIFO:
        info.type = PathType::FIFO;
        break;
      default:
        info.type = PathType::Unknown;
        break;
      }
      info.mode_int = mode & 0777;
      info.mode_str = AMStr::ModeTrans(info.mode_int);
    }

    return info;
  }

  std::pair<ECM, std::string>
  lib_realpath(const std::string &path, amf interrupt_flag = nullptr,
               int timeout_ms = -1,
               std::chrono::steady_clock::time_point start_time =
                   std::chrono::steady_clock::now()) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, ""};
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Interrupted by user"}, ""};
    }
    char path_t[1024] = {0};
    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_realpath(sftp, path.c_str(), path_t, sizeof(path_t));
    });
    return {ErrorRecord(nb_res, TraceLevel::Debug, path,
                        "libssh2_sftp_realpath",
                        "Realpath \"{target}\" failed: {error}"),
            std::string(path_t)};
  }

  ECM lib_rename(const std::string &src, const std::string &dst,
                 const bool &overwrite, amf interrupt_flag = nullptr,
                 int timeout_ms = -1,
                 std::chrono::steady_clock::time_point start_time =
                     std::chrono::steady_clock::now()) {
    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }

    if (!overwrite) {
      auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
        return libssh2_sftp_rename_ex(sftp, src.c_str(), src.size(),
                                      dst.c_str(), dst.size(),
                                      LIBSSH2_SFTP_RENAME_NATIVE);
      });
      return ErrorRecord(
          nb_res, TraceLevel::Debug, fmt::format("{} -> {}", src, dst),
          "libssh2_sftp_rename_ex", "Rename {target} failed: {error}");
    } else {
      auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
        return libssh2_sftp_rename_ex(
            sftp, src.c_str(), src.size(), dst.c_str(), dst.size(),
            LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_NATIVE);
      });
      return ErrorRecord(
          nb_res, TraceLevel::Debug, fmt::format("{} -> {}", src, dst),
          "libssh2_sftp_rename_ex", "Rename {target} failed: {error}");
    }
  }

  std::pair<ECM, LIBSSH2_SFTP_ATTRIBUTES>
  lib_getstat(const std::string &path, amf interrupt_flag = nullptr,
              int timeout_ms = -1,
              std::chrono::steady_clock::time_point start_time =
                  std::chrono::steady_clock::now()) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"},
              LIBSSH2_SFTP_ATTRIBUTES()};
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Interrupted by user"},
              LIBSSH2_SFTP_ATTRIBUTES()};
    }
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_stat(sftp, path.c_str(), &attrs);
    });
    ECM rcm = ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_stat",
                          "Get stat failed: {error}");
    return {rcm, attrs};
  }

  ECM lib_setstat(const std::string &path, LIBSSH2_SFTP_ATTRIBUTES &attrs,
                  amf interrupt_flag = nullptr, int timeout_ms = -1,
                  std::chrono::steady_clock::time_point start_time =
                      std::chrono::steady_clock::now()) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return {EC::Terminate, "Interrupted by user"};
    }
    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_setstat(sftp, path.c_str(), &attrs);
    });
    return ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_setstat",
                       "Set stat failed: {error}");
  }

  ECM lib_unlink(const std::string &path, amf interrupt_flag = nullptr,
                 int timeout_ms = -1,
                 std::chrono::steady_clock::time_point start_time =
                     std::chrono::steady_clock::now()) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return {EC::Terminate, "Interrupted by user"};
    }

    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_unlink(sftp, path.c_str());
    });
    return ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_unlink",
                       "Unlink \"{target}\" failed: {error}");
  }

  ECM lib_rmdir(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1,
                std::chrono::steady_clock::time_point start_time =
                    std::chrono::steady_clock::now()) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return {EC::Terminate, "Interrupted by user"};
    }

    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_rmdir(sftp, path.c_str());
    });
    return ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_rmdir",
                       "Remove directory failed: {error}");
  }

  ECM lib_mkdir(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1,
                std::chrono::steady_clock::time_point start_time =
                    std::chrono::steady_clock::now()) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return {EC::Terminate, "Interrupted by user"};
    }

    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_mkdir_ex(sftp, path.c_str(), path.size(), 0740);
    });
    return ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_mkdir_ex",
                       "Create directory \"{target}\" failed: {error}");
  }

  std::pair<ECM, std::vector<std::pair<std::string, LIBSSH2_SFTP_ATTRIBUTES>>>
  lib_listdir(const std::string &path, amf interrupt_flag = nullptr,
              int timeout_ms = -1,
              std::chrono::steady_clock::time_point start_time =
                  std::chrono::steady_clock::now()) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, {}};
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Interrupted by user"}, {}};
    }
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    std::vector<std::pair<std::string, LIBSSH2_SFTP_ATTRIBUTES>> file_list = {};
    LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
    std::string name;
    ECM rcm;
    const size_t buffer_size = 4096;
    std::vector<char> filename_buffer = std::vector<char>(buffer_size, 0);
    auto oepn_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_open_ex(sftp, path.c_str(), path.size(), 0,
                                  LIBSSH2_SFTP_OPENDIR, LIBSSH2_FXF_READ);
    });
    rcm = ErrorRecord(oepn_res, TraceLevel::Debug, path, "libssh2_sftp_open_ex",
                      "Open directory {path} failed: {error}");
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    NBResult<int> read_res;

    while (true) {
      if (timeout_ms > 0 && std::chrono::steady_clock::now() - start_time >
                                std::chrono::milliseconds(timeout_ms)) {
        rcm = ECM{EC::OperationTimeout,
                  fmt::format("Path: {} readdir timeout", path)};
        break;
      }
      if (interrupt_flag && interrupt_flag->check()) {
        rcm = ECM{EC::Terminate,
                  fmt::format("Path: {} readdir interrupted by user", path)};
        break;
      }
      read_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
        return libssh2_sftp_readdir_ex(sftp_handle, filename_buffer.data(),
                                       buffer_size, nullptr, 0, &attrs);
      });
      if (read_res.value == 0) {
        break;
      }
      rcm = ErrorRecord(read_res, TraceLevel::Debug, path,
                        "libssh2_sftp_readdir_ex",
                        "Path: {} readdir failed: {error}");
      if (rcm.first != EC::Success) {
        if (rcm.first == EC::PermissionDenied) {
          continue;
        }
        break;
      }

      name.assign(filename_buffer.data(), read_res.value);

      if (name == "." || name == ".." || name.empty()) {
        continue;
      }
      file_list.emplace_back(AMFS::join(path, name), attrs);
    }

    if (sftp_handle) {
      libssh2_sftp_close_handle(sftp_handle);
    }
    return {rcm, file_list};
  }

protected:
  void _iwalk(const std::string &path, const LIBSSH2_SFTP_ATTRIBUTES &attrs,
              WRV &result, bool ignore_sepcial_file = true,
              amf interrupt_flag = nullptr, int timeout_ms = -1,
              std::chrono::steady_clock::time_point start_time =
                  std::chrono::steady_clock::now()) {
    // 搜索目录下所有最深层的路径, 用于递归传输路径
    if (interrupt_flag && interrupt_flag->check()) {
      return;
    }

    if (!isdir(attrs)) {
      // 非目录直接加入
      if (!isreg(attrs) && ignore_sepcial_file) {
        return;
      }
      result.push_back(FormatStat(path, attrs));
      return;
    }

    auto [rcm2, attrs_list] =
        lib_listdir(path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return;
    }

    if (attrs_list.empty()) {
      // 末级空目录直接加入
      result.push_back(FormatStat(path, attrs));
      return;
    }
    for (auto &attrs : attrs_list) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      if (timeout_ms > 0 && std::chrono::steady_clock::now() - start_time >
                                std::chrono::milliseconds(timeout_ms)) {
        return;
      }
      _iwalk(attrs.first, attrs.second, result, ignore_sepcial_file,
             interrupt_flag, timeout_ms, start_time);
    }
  }

  void _walk(const std::vector<std::string> &parts, WRD &result,
             int cur_depth = 0, int max_depth = -1,
             bool ignore_sepcial_file = true, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) {
    if (max_depth != -1 && cur_depth > max_depth) {
      return;
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return;
    }
    std::string pathf = AMFS::join(parts);
    auto [rcm2, list_info] =
        lib_listdir(pathf, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return;
    }

    if (list_info.empty()) {
      result.push_back({parts, {}});
      return;
    }

    std::vector<PathInfo> files_info = {};
    for (auto &[path, attrs] : list_info) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      if (timeout_ms > 0 && std::chrono::steady_clock::now() - start_time >
                                std::chrono::milliseconds(timeout_ms)) {
        return;
      }
      if (isdir(attrs)) {
        auto new_parts = parts;
        new_parts.push_back(AMFS::basename(path));
        _walk(new_parts, result, cur_depth + 1, max_depth, ignore_sepcial_file,
              interrupt_flag, timeout_ms, start_time);
      } else {
        if (ignore_sepcial_file && !isreg(attrs)) {
          continue;
        }
        files_info.push_back(FormatStat(path, attrs));
      }
    }
    if (list_info.empty()) {
      return;
    }
    result.emplace_back(parts, files_info);
  }

  void _rm(const std::string &path, const LIBSSH2_SFTP_ATTRIBUTES &attrs,
           RMR &errors, amf interrupt_flag = nullptr, int timeout_ms = -1,
           std::chrono::steady_clock::time_point start_time =
               std::chrono::steady_clock::now()) {
    if (interrupt_flag && interrupt_flag->check()) {
      return;
    }
    if (!isdir(attrs)) {
      ECM ecm = lib_unlink(path, interrupt_flag, timeout_ms, start_time);
      if (ecm.first != EC::Success) {
        errors.emplace_back(path, ecm);
      }
      return;
    }

    auto [rcm2, file_list] =
        lib_listdir(path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      errors.emplace_back(path, rcm2);
      return;
    }

    if (interrupt_flag && interrupt_flag->check()) {
      return;
    }

    for (auto &file : file_list) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      _rm(file.first, file.second, errors, interrupt_flag, timeout_ms,
          start_time);
    }

    ECM ecm = lib_rmdir(path, interrupt_flag, timeout_ms, start_time);
    if (ecm.first != EC::Success) {
      errors.emplace_back(path, ecm);
    }
  }

  void _chmod(const std::string &path, uint64_t mode, bool recursive,
              std::unordered_map<std::string, ECM> &errors,
              LIBSSH2_SFTP_ATTRIBUTES attrs, amf interrupt_flag = nullptr,
              int timeout_ms = -1,
              std::chrono::steady_clock::time_point start_time =
                  std::chrono::steady_clock::now()) {
    if (interrupt_flag && interrupt_flag->check()) {
      return;
    }
    ECM rcm;
    if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      errors[path] = {EC::NoPermissionAttribute,
                      "stat does not have permission attribute"};
      return;
    }

    if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      errors[path] = {EC::NoPermissionAttribute,
                      "server didn't return permission attribute"};
      return;
    }

    uint64_t file_type = attrs.permissions & LIBSSH2_SFTP_S_IFMT;
    uint64_t new_mode_int = (mode & ~LIBSSH2_SFTP_S_IFMT) | file_type;

    attrs.permissions = new_mode_int;
    attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;

    if (((uint64_t)attrs.permissions & 0777) != (mode & 0777)) {
      rcm = lib_setstat(path, attrs, interrupt_flag, timeout_ms, start_time);
      if (rcm.first != EC::Success) {
        errors[path] = rcm;
        return;
      }
    }

    if (recursive && file_type == LIBSSH2_SFTP_S_IFDIR) {
      auto [rcm2, list] =
          lib_listdir(path, interrupt_flag, timeout_ms, start_time);
      if (rcm2.first != EC::Success) {
        errors[path] = rcm2;
        return;
      }
      for (auto &item : list) {
        if (interrupt_flag && interrupt_flag->check()) {
          return;
        }
        if (timeout_ms > 0 && std::chrono::steady_clock::now() - start_time >
                                  std::chrono::milliseconds(timeout_ms)) {
          return;
        }
        _chmod(item.first, mode, recursive, errors, item.second, interrupt_flag,
               timeout_ms, start_time);
      }
    }
  }

  ECM _precheck(const std::string &path) {
    if (path.empty()) {
      return {EC::InvalidArg, fmt::format("Invalid path: {}", path)};
    }
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }
    return {EC::Success, ""};
  }

  // 用于AMFS::BasePathMatch
  std::pair<bool, PathInfo>
  istat(const std::string &path, amf interrupt_flag = nullptr,
        int timeout_ms = -1,
        std::chrono::steady_clock::time_point start_time =
            std::chrono::steady_clock::now()) override {
    auto [rcm, sr] = stat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return std::make_pair(false, PathInfo());
    }
    return std::make_pair(true, sr);
  }
  std::vector<PathInfo>
  ilistdir(const std::string &path, amf interrupt_flag = nullptr,
           int timeout_ms = -1,
           std::chrono::steady_clock::time_point start_time =
               std::chrono::steady_clock::now()) override {
    auto [rcm, sr] = listdir(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {};
    }
    return sr;
  }
  std::vector<PathInfo>
  iiwalk(const std::string &path, bool ignore_sepcial_file = true,
         amf interrupt_flag = nullptr, int timeout_ms = -1,
         std::chrono::steady_clock::time_point start_time =
             std::chrono::steady_clock::now()) override {
    return iwalk(path, ignore_sepcial_file, interrupt_flag, timeout_ms,
                 start_time);
  }

public:
  AMSFTPClient(const ConRequst &request,
               const std::vector<std::string> &keys = {},
               unsigned int tracer_capacity = 10,
               const py::object &trace_cb = py::none(),
               const py::object &auth_cb = py::none())
      : AMSession(request, keys, tracer_capacity, trace_cb, auth_cb) {
    this->PROTOCOL = ClientProtocol::SFTP;
    if (request.trash_dir.empty()) {
      this->trash_dir = AMFS::join(GetHomeDir(), ".AMSFTP_Trash");
    }
  }

  // 获取 RTT (Round Trip Time)，返回平均值（毫秒）
  // 通过执行简单的 SFTP 操作来测量
  double GetRTT(ssize_t times = 5, amf interrupt_flag = nullptr) override {
    if (times <= 0)
      times = 1;
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (!session || !sftp) {
      return -1.0;
    }

    std::vector<double> rtts;
    rtts.reserve(times);

    // 使用 libssh2_sftp_stat 测量 RTT（最小开销的 SFTP 操作）
    LIBSSH2_SFTP_ATTRIBUTES attrs;

    for (ssize_t i = 0; i < times; i++) {
      if (interrupt_flag && interrupt_flag->check()) {
        break;
      }

      auto start = std::chrono::steady_clock::now();

      // stat "/" 是最轻量的操作
      int rc = libssh2_sftp_stat(sftp, "/", &attrs);

      auto end = std::chrono::steady_clock::now();

      if (rc == 0) {
        double rtt_ms =
            std::chrono::duration<double, std::milli>(end - start).count();
        rtts.push_back(rtt_ms);
      }
    }

    if (rtts.empty()) {
      return -1.0;
    }

    // 计算平均值
    double sum = 0.0;
    for (double rtt : rtts) {
      sum += rtt;
    }
    return sum / rtts.size();
  }

  CR ConductCmd(const std::string &cmd, int max_time_ms = -1,
                amf interrupt_flag = nullptr) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    SafeChannel sf(session);
    if (!sf.channel) {
      return {ECM{EC::NoConnection, "Channel not initialized"}, {"", -1}};
    }

    auto time_start = std::chrono::steady_clock::now();
    int exit_status = -1;
    std::string output;
    std::array<char, 4096> buffer;
    WaitResult wr = WaitResult::Ready;
    int rc;

    // 设置非阻塞模式
    libssh2_session_set_blocking(session, 0);

    // 1. 执行命令
    while ((rc = libssh2_channel_exec(sf.channel, cmd.c_str())) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, time_start,
                           max_time_ms);
      if (wr != WaitResult::Ready) {
        goto cleanup;
      }
    }
    if (rc < 0) {
      libssh2_session_set_blocking(session, 1);
      return {ECM{GetLastEC(),
                  fmt::format("Channel exec failed: {}", GetLastErrorMsg())},
              {"", -1}};
    }

    // 2. 读取输出
    while (true) {
      ssize_t nbytes =
          libssh2_channel_read(sf.channel, buffer.data(), buffer.size() - 1);

      if (nbytes > 0) {
        output.append(buffer.data(), nbytes);
      } else if (nbytes == 0) {
        break; // EOF
      } else if (nbytes == LIBSSH2_ERROR_EAGAIN) {
        wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, time_start,
                             max_time_ms);
        if (wr != WaitResult::Ready) {
          goto cleanup;
        }
      } else {
        libssh2_session_set_blocking(session, 1);
        return {ECM{GetLastEC(),
                    fmt::format("Channel read failed: {}", GetLastErrorMsg())},
                {"", -1}};
      }
    }

    // 3. 清理输出末尾空白
    while (!output.empty() &&
           (output.back() == '\n' || output.back() == '\r')) {
      output.pop_back();
    }

    // 4. 非阻塞关闭通道
    while ((rc = sf.close_nonblock()) == LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, time_start,
                           max_time_ms);
      if (wr != WaitResult::Ready) {
        goto cleanup;
      }
    }

    // 5. 获取退出状态
    exit_status = libssh2_channel_get_exit_status(sf.channel);

    libssh2_session_set_blocking(session, 1);
    return {ECM{EC::Success, ""}, {output, exit_status}};

  cleanup:
    // sf.closed == false，析构时会自动发送 TERM/KILL 信号
    libssh2_session_set_blocking(session, 1);
    switch (wr) {
    case WaitResult::Timeout:
      return {ECM{EC::OperationTimeout,
                  fmt::format("Command timed out (killed): {}", cmd)},
              {output, -1}};
    case WaitResult::Interrupted:
      return {ECM{EC::Terminate,
                  fmt::format("Command interrupted (killed): {}", cmd)},
              {output, -1}};
    case WaitResult::Error:
      return {ECM{EC::SocketRecvError,
                  fmt::format("Socket error during command: {}", cmd)},
              {output, -1}};
    case WaitResult::Ready:
      return {ECM{EC::Success, ""}, {output, exit_status}};
    }
  }

  OS_TYPE GetOSType(bool update = false) override {
    if (os_type != OS_TYPE::Uncertain && !update) {
      return os_type;
    }
    auto [rcm, out] = ConductCmd("uname -s");
    if (rcm.first != EC::Success) {
      os_type = OS_TYPE::Uncertain;
      return os_type;
    }
    int code = out.second;
    if (code == 0) {
      std::string out_str = out.first;
      // 将out_str转换为小写
      std::transform(out_str.begin(), out_str.end(), out_str.begin(),
                     ::tolower);
      if (out_str.find("linux") != std::string::npos) {
        os_type = OS_TYPE::Linux;
      } else if (out_str.find("darwin") != std::string::npos) {
        os_type = OS_TYPE::MacOS;
      } else if (out_str.find("cygwin") != std::string::npos) {
        os_type = OS_TYPE::Windows;
      } else if (out_str.find("freebsd") != std::string::npos) {
        os_type = OS_TYPE::FreeBSD;
      } else {
        os_type = OS_TYPE::Unix;
      }
      return os_type;
    }

    auto [rcm2, out2] = ConductCmd("systeminfo | findstr /i \"OS Name\"");
    if (rcm2.first != EC::Success) {
      os_type = OS_TYPE::Uncertain;
      return os_type;
    }

    code = out2.second;
    if (code != 0) {
      os_type = OS_TYPE::Unknown;
      return os_type;
    }
    std::string out_str2 = out2.first;
    if (out_str2.find("Windows") != std::string::npos) {
      os_type = OS_TYPE::Windows;
      return os_type;
    }
    os_type = OS_TYPE::Unix;
    return os_type;
  }

  std::string StrUid(const long &uid) override {
    if (user_id_map.find(uid) != user_id_map.end()) {
      return user_id_map[uid];
    }

    std::string cmd = fmt::format("id -un {}", uid);
    auto [rcm, cr] = ConductCmd(cmd, 3000);
    if (rcm.first != EC::Success) {
      return "unkown";
    }
    if (cr.second != 0) {
      return "unkown";
    } else {
      user_id_map[uid] = cr.first;
      return cr.first;
    }
  }

  std::string GetHomeDir() override {
    if (!home_dir.empty()) {
      return home_dir;
    }
    auto [rcm, path_obj] =
        realpath("", nullptr, 3000, std::chrono::steady_clock::now());
    if (rcm.first == EC::Success) {
      home_dir = path_obj;
      return home_dir;
    }
    switch (GetOSType()) {
    case OS_TYPE::Windows:
      home_dir = "C:\\Users\\" + res_data.username;
      return home_dir;
    case OS_TYPE::Linux:
      home_dir = "/home/" + res_data.username;
      return home_dir;
    case OS_TYPE::MacOS:
      home_dir = "/Users/" + res_data.username;
      return home_dir;
    case OS_TYPE::FreeBSD:
      home_dir = "/usr/home/" + res_data.username;
      return home_dir;
    case OS_TYPE::Unix:
      home_dir = "/home/" + res_data.username;
      return home_dir;
    default:
      return "C:\\Users\\" + res_data.username;
    }
  }

  ECM Connect(bool force = false, int timeout_ms = -1,
              amf interrupt_flag = nullptr) override {
    bool not_init = has_connected;
    ECM ecm = BaseConnect(force, timeout_ms, interrupt_flag);
    if (!not_init && isok(ecm)) {
      GetOSType();
      GetHomeDir();
    }
    return ecm;
  }

  ECM SetTrashDir(const std::string &trash_dir = "") override {
    ECM rcm = mkdirs(trash_dir);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    this->trash_dir = trash_dir;
    return {EC::Success, ""};
  }

  std::string GetAvailableTrashDir() override {
    std::string trash_dir = AMFS::join(GetHomeDir(), ".AMSFTP_Trash");
    int count = 1;
    while (true) {
      if (mkdirs(trash_dir).first == EC::Success) {
        return trash_dir;
      }
      trash_dir = AMFS::join(
          GetHomeDir(), fmt::format(".AMSFTP_Trash({})", rand() % 1000000));
      count++;
      if (count > 3) {
        return "";
      }
    }
  }

  ECM EnsureTrashDir() override {
    ECM rcm = Check();
    if (rcm.first != EC::Success) {
      return rcm;
    }

    if (trash_dir.empty() || mkdirs(trash_dir).first != EC::Success) {
      trash_dir = GetAvailableTrashDir();
      if (trash_dir.empty()) {
        trace(TraceLevel::Warning, EC::UnknownError,
              fmt::format("{}@{}", "", "TrashDir"), "EnsureTrashDir",
              "Can't automatically find a available trash directory");
        return {EC::UnknownError,
                "Can't automatically find a available trash directory"};
      }
      trace(TraceLevel::Info, EC::Success, trash_dir, "EnsureTrashDir",
            fmt::format("Set trash_dir to: \"{}\"", trash_dir));
    }
    return {EC::Success, ""};
  }
  // 解析并返回绝对路径,
  // ~在client中解析，..和.其他由服务器解析，有这些符号时需要路径真实存在
  std::pair<ECM, std::string>
  realpath(const std::string &path, amf interrupt_flag = nullptr,
           int timeout_ms = -1,
           std::chrono::steady_clock::time_point start_time =
               std::chrono::steady_clock::now()) override {
    auto pathf = path;
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return {rcm, ""};
    }
    if (std::regex_search(path, std::regex("^~[\\\\/]"))) {
      // 解析~符号
      pathf = AMFS::join(GetHomeDir(), pathf.substr(1), AMFS::SepType::Unix);
    } else if (path == "~") {
      return {ECM{EC::Success, ""}, GetHomeDir()};
    }
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;

    auto [rcm2, path_t] =
        lib_realpath(path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return {rcm2, ""};
    }
    if (GetOSType() == OS_TYPE::Windows) {
      // windows server返回的路径会在前面加个/或\，需要去掉
      return {rcm2, path_t.substr(1)};
    }
    return {rcm2, path_t};
  }

  std::pair<ECM, std::unordered_map<std::string, ECM>>
  chmod(const std::string &path, std::variant<std::string, uint64_t> mode,
        bool recursive = false, amf interrupt_flag = nullptr,
        int timeout_ms = -1,
        std::chrono::steady_clock::time_point start_time =
            std::chrono::steady_clock::now()) override {
    if (static_cast<int>(GetOSType()) <= 0) {
      return {ECM{EC::UnImplentedMethod, "Chmod only supported on Unix System"},
              {}};
    }
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, attrs] =
        lib_getstat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      return {ECM{EC::NoPermissionAttribute,
                  "stat does not have permission attribute"},
              {}};
    }

    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Interrupted by user, no action conducted"},
              {}};
    }
    std::unordered_map<std::string, ECM> ecm_map{};
    uint64_t mode_int;
    if (std::holds_alternative<std::string>(mode)) {
      if (!AMStr::IsModeValid(std::get<std::string>(mode))) {
        return {ECM{EC::InvalidArg, fmt::format("Invalid mode: {}",
                                                std::get<std::string>(mode))},
                {}};
      }
      mode_int = AMStr::ModeTrans(std::get<std::string>(mode));
    } else if (std::holds_alternative<uint64_t>(mode)) {
      if (!AMStr::IsModeValid(std::get<uint64_t>(mode))) {
        return {ECM{EC::InvalidArg,
                    fmt::format("Invalid mode: {}", std::get<uint64_t>(mode))},
                {}};
      }
      mode_int = std::get<uint64_t>(mode);
    } else {
      return {ECM{EC::InvalidArg, fmt::format("Invalid mode data type")}, {}};
    }
    _chmod(path, mode_int, recursive, ecm_map, attrs, interrupt_flag,
           timeout_ms, start_time);
    return {ECM{EC::Success, ""}, ecm_map};
  }

  // 获取路径信息，自带AMFS::abspath
  SR stat(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1,
          std::chrono::steady_clock::time_point start_time =
              std::chrono::steady_clock::now()) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return {rcm, PathInfo()};
    }
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    auto [rcm2, attrs] =
        lib_getstat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return {rcm2, PathInfo()};
    }
    return {rcm, FormatStat(path, attrs)};
  }

  std::pair<ECM, PathType>
  get_path_type(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1,
                std::chrono::steady_clock::time_point start_time =
                    std::chrono::steady_clock::now()) override {
    auto [rcm, path_info] = stat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {ECM{rcm.first, rcm.second}, PathType::Unknown};
    }
    return {rcm, path_info.type};
  }

  // 判断路径是否存在，自带AMFS::abspath
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

  std::pair<ECM, bool>
  is_regular(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    auto [rcm, path_info] = stat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::FILE ? true : false};
  }

  std::pair<ECM, bool> is_dir(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              std::chrono::steady_clock::time_point start_time =
                                  std::chrono::steady_clock::now()) override {
    auto [rcm, path_info] = stat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::DIR ? true : false};
  }

  std::pair<ECM, bool>
  is_symlink(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    auto [rcm, path_info] = stat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::SYMLINK ? true : false};
  }

  std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1,
          std::chrono::steady_clock::time_point start_time =
              std::chrono::steady_clock::now()) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    auto [rcm2, attr_list] =
        lib_listdir(path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return {rcm2, {}};
    }
    std::vector<PathInfo> file_list(attr_list.size());
    for (size_t i = 0; i < attr_list.size(); i++) {
      file_list[i] = FormatStat(attr_list[i].first, attr_list[i].second);
    }
    return {rcm2, file_list};
  }

  // Iterator version that yields PathInfo one by one using Python generator
  py::object iterator_listdir(const std::string &path) {
    if (!sftp) {
      throw std::runtime_error("SFTP not initialized");
    }

    auto pathf = path;
    if (pathf.empty()) {
      throw std::invalid_argument(fmt::format("Invalid path: {}", path));
    }

    auto [rcm, br] = is_dir(path);
    if (rcm.first != EC::Success) {
      throw std::runtime_error(rcm.second);
    } else if (!br) {
      throw std::runtime_error(
          fmt::format("Path is not a directory: {}", pathf));
    }

    // State holder for the generator
    struct IteratorState {
      AMSFTPClient *client;
      std::string pathf;
      LIBSSH2_SFTP_HANDLE *sftp_handle;
      bool finished;

      IteratorState(AMSFTPClient *cli, const std::string &p)
          : client(cli), pathf(p), sftp_handle(nullptr), finished(false) {
        std::lock_guard<std::recursive_mutex> lock(client->mtx);
        sftp_handle =
            libssh2_sftp_open_ex(client->sftp, pathf.c_str(), pathf.size(), 0,
                                 LIBSSH2_SFTP_OPENDIR, LIBSSH2_FXF_READ);
        if (!sftp_handle) {
          finished = true;
          throw std::runtime_error(
              fmt::format("Failed to open directory: {}", pathf));
        }
      }

      ~IteratorState() {
        if (sftp_handle) {
          std::lock_guard<std::recursive_mutex> lock(client->mtx);
          libssh2_sftp_close_handle(sftp_handle);
          sftp_handle = nullptr;
        }
      }

      py::object next() {
        if (finished) {
          throw py::stop_iteration();
        }

        std::lock_guard<std::recursive_mutex> lock(client->mtx);
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        const size_t buffer_size = 4096;
        std::vector<char> filename_buffer(buffer_size);
        std::string name;
        std::string path_i;

        while (true) {
          int rct = libssh2_sftp_readdir_ex(sftp_handle, filename_buffer.data(),
                                            buffer_size, nullptr, 0, &attrs);

          if (rct < 0) {
            finished = true;
            throw std::runtime_error(fmt::format("Failed to read directory: {}",
                                                 client->GetLastErrorMsg()));
          } else if (rct == 0) {
            finished = true;
            throw py::stop_iteration();
          }

          name.assign(filename_buffer.data(), rct);
          if (name == "." || name == "..") {
            continue;
          }

          path_i = AMFS::join(pathf, name);
          PathInfo info = client->FormatStat(path_i, attrs);
          return py::cast(info);
        }
      }
    };

    // Create the generator state
    auto state = std::make_shared<IteratorState>(this, pathf);

    // Create a generator using Python's compile and exec
    py::gil_scoped_acquire gil;

    // Get builtins module
    py::module_ builtins = py::module_::import("builtins");

    // Compile and execute the generator function
    std::string code = R"(
def _amsftp_gen(next_func):
    while True:
        try:
            yield next_func()
        except StopIteration:
            break
)";

    py::dict local_ns;
    py::object compiled = builtins.attr("compile")(code, "<string>", "exec");
    builtins.attr("exec")(compiled, py::globals(), local_ns);

    // Create the next function wrapper
    py::object next_func =
        py::cpp_function([state]() -> py::object { return state->next(); });

    // Call the generator function
    py::object gen_func = local_ns["_amsftp_gen"];
    return gen_func(next_func);
  }

  // 创建一级目录，自带AMFS::abspath
  ECM mkdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1,
            std::chrono::steady_clock::time_point start_time =
                std::chrono::steady_clock::now()) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    return lib_mkdir(path, interrupt_flag, timeout_ms, start_time);
  }

  // 递归创建多级目录，直到报错为止，自带AMFS::abspath
  ECM mkdirs(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    std::vector<std::string> parts = AMFS::split(path);
    if (parts.empty()) {
      return {EC::InvalidArg,
              fmt::format("Path split failed, get empty parts: {}", path)};
    } else if (parts.size() == 1) {
      return lib_mkdir(path, interrupt_flag, timeout_ms, start_time);
    }

    std::string current_path = parts.front();
    for (size_t i = 1; i < parts.size(); i++) {
      current_path = AMFS::join(current_path, parts[i], AMFS::SepType::Unix);
      rcm = lib_mkdir(current_path, interrupt_flag, timeout_ms, start_time);
      if (rcm.first != EC::Success) {
        return rcm;
      }
    }
    return rcm;
  }

  ECM rmfile(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    return lib_unlink(path, interrupt_flag, timeout_ms, start_time);
  }

  ECM rmdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1,
            std::chrono::steady_clock::time_point start_time =
                std::chrono::steady_clock::now()) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    return lib_rmdir(path, interrupt_flag, timeout_ms, start_time);
  }

  // 删除文件或目录，自带AMFS::abspath
  std::pair<ECM, RMR> remove(const std::string &path,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             std::chrono::steady_clock::time_point start_time =
                                 std::chrono::steady_clock::now()) override {
    ECM rcm0 = _precheck(path);
    if (rcm0.first != EC::Success) {
      return {rcm0, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    RMR errors = {};
    auto [rcm, sr] = lib_getstat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    _rm(path, sr, errors, interrupt_flag, timeout_ms, start_time);
    return {ECM{EC::Success, ""}, errors};
  }

  // 将原路径变成新路径，自带AMFS::abspath
  ECM rename(const std::string &src, const std::string &dst, bool mkdir = true,
             bool overwrite = false, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    ECM rcm0 = _precheck(src);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    ECM rcm1 = _precheck(dst);
    if (rcm1.first != EC::Success) {
      return rcm1;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (mkdir) {
      rcm0 = mkdirs(AMFS::dirname(dst), interrupt_flag, timeout_ms, start_time);
      if (rcm0.first != EC::Success) {
        return rcm0;
      }
    }
    return lib_rename(src, dst, overwrite, interrupt_flag, timeout_ms,
                      start_time);
  }

  // 安全删除文件或目录，将目录移动到trash_dir中
  ECM saferm(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    ECM rcm0 = _precheck(path);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    rcm0 = EnsureTrashDir();
    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    auto [rcm1, info] =
        lib_getstat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm1.first != EC::Success) {
      return rcm1;
    }
    std::string base = AMFS::basename(path);
    std::string base_name = base;
    std::string base_ext = "";
    std::string target_path;

    if (!isdir(info)) {
      auto base_info = AMFS::split_basename(base);
      base_name = base_info.first;
      base_ext = base_info.second;
    }

    // 获取当前时间，以2026-01-01-19-06格式
    std::string current_time =
        AMFS::FormatTime(std::time(nullptr), "%Y-%m-%d-%H-%M-%S");

    target_path =
        AMFS::join(trash_dir, current_time, base_name + "." + base_ext);
    size_t i = 1;
    std::string base_name_tmp = base_name;

    while (true) {
      auto [rcm, br] = exists(target_path);
      if (rcm.first != EC::Success) {
        return rcm;
      }
      if (!br) {
        break;
      }
      base_name_tmp = base_name + "(" + std::to_string(i) + ")";
      target_path = AMFS::join(trash_dir, current_time,
                               (base_name_tmp + ".") += base_ext);
      i++;
    }

    rcm0 = mkdirs(AMFS::join(trash_dir, current_time), interrupt_flag,
                  timeout_ms, start_time);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }

    return lib_rename(path, target_path, false, interrupt_flag, timeout_ms,
                      start_time);
  }

  // 将源路径移动到目标文件夹
  ECM move(const std::string &src, const std::string &dst,
           bool need_mkdir = false, bool force_write = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1,
           std::chrono::steady_clock::time_point start_time =
               std::chrono::steady_clock::now()) override {

    return rename(src, AMFS::join(dst, AMFS::basename(src)), need_mkdir,
                  force_write, interrupt_flag, timeout_ms, start_time);
  }

  // 废弃，复制使用桥接模式或者直接执行指令
  ECM copy(const std::string &src, const std::string &dst,
           bool need_mkdir = false, int timeout_ms = -1,
           amf interrupt_flag = nullptr) override {
    if (!sftp) {
      return ECM{EC::NoConnection, "SFTP not initialized"};
    }
    std::string srcf = src;
    std::string dstf = dst;
    if (srcf.empty() || dstf.empty()) {
      return std::make_pair(EC::InvalidArg,
                            fmt::format("Invalid path: {} or {}", srcf, dstf));
    }
    auto [rcm, br] = exists(srcf);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (!br) {
      return {EC::PathNotExist, fmt::format("Src not exists: {}", srcf)};
    }

    auto [rcm2, br2] = is_dir(dstf);
    if (rcm2.first != EC::Success) {
      if (rcm2.first == EC::PathNotExist) {
        if (need_mkdir) {
          ECM ecm = mkdirs(dstf);
          if (ecm.first != EC::Success) {
            return ecm;
          }
        } else {
          return {EC::ParentDirectoryNotExist,
                  fmt::format("Dst dir not exists: {}", dstf)};
        }
      }
    } else if (!br2) {
      return {EC::NotADirectory,
              fmt::format("Dst exists but not a directory: {}", dstf)};
    }

    std::string dst_path = AMFS::join(dstf, AMFS::basename(srcf));
    auto [rcm0, sbr0] = exists(dst_path);

    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    if (sbr0) {
      return {EC::PathAlreadyExists,
              fmt::format("Dst {} already has path named {}", dstf,
                          AMFS::basename(srcf))};
    }

    std::string command = "cp -r \"" + srcf + "\" \"" + dstf + "\"";

    auto [rcm3, resp] = ConductCmd(command);

    if (rcm3.first != EC::Success) {
      return rcm3;
    }

    if (resp.second != 0) {
      std::string msg =
          fmt::format("Copy cmd conducted failed with exit code: {}, error: {}",
                      resp.second, resp.first);
      trace(TraceLevel::Error, EC::InhostCopyFailed,
            fmt::format("{}@{}->{}", res_data.nickname, srcf, dstf), "Copy",
            msg);
      return {EC::InhostCopyFailed, msg};
    }

    return {EC::Success, ""};
  }

  // 递归遍历某一路径下的所有文件和底层目录，返回PathInfo的vector
  WRV iwalk(const std::string &path, bool ignore_sepcial_file = true,
            amf interrupt_flag = nullptr, int timeout_ms = -1,
            std::chrono::steady_clock::time_point start_time =
                std::chrono::steady_clock::now()) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return {};
    }
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm2, attrs] =
        lib_getstat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return {};
    }
    if (!isdir(attrs)) {
      if (!isreg(attrs) && ignore_sepcial_file) {
        return {};
      }
      return {FormatStat(path, attrs), {}};
    }
    // get all files and deepest folders
    WRV result = {};
    _iwalk(path, attrs, result, ignore_sepcial_file, interrupt_flag, timeout_ms,
           start_time);
    return result;
  }

  // 真实的walk函数，返回([root_path, part1, part2, ...], PathInfo)的vector
  std::pair<ECM, WRD> walk(const std::string &path, int max_depth = -1,
                           bool ignore_special_file = true,
                           amf interrupt_flag = nullptr, int timeout_ms = -1,
                           std::chrono::steady_clock::time_point start_time =
                               std::chrono::steady_clock::now()) override {
    ECM rcm0 = _precheck(path);
    if (rcm0.first != EC::Success) {
      return {rcm0, {}};
    }
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->session_interrupt_flag;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, br] = stat(path, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    } else if (br.type != PathType::DIR) {
      return {{EC::NotADirectory, "Path is not a directory"}, {}};
    }
    WRD result_dict = {};
    std::vector<std::string> parts = {path};
    _walk(parts, result_dict, 0, max_depth, ignore_special_file, interrupt_flag,
          timeout_ms, start_time);
    // 打印result_dict的类型
    if (interrupt_flag && interrupt_flag->check()) {
      return {ECM{EC::Terminate, "Interrupted by user, no action conducted"},
              result_dict};
    }
    return {ECM{EC::Success, ""}, result_dict};
  }

  // 获取某一路径下的所有文件和底层目录的总大小,
  // 但是在读取时遇到错误不会throw，也不会记录其大小，可能存在偏差
  uint64_t getsize(const std::string &path, bool ignore_sepcial_file = true,
                   amf interrupt_flag = nullptr, int timeout_ms = -1,
                   std::chrono::steady_clock::time_point start_time =
                       std::chrono::steady_clock::now()) override {
    WRV list = iwalk(path, ignore_sepcial_file, interrupt_flag, timeout_ms,
                     start_time);
    if (interrupt_flag && interrupt_flag->check()) {
      return -1;
    }
    uint64_t size = 0;
    for (auto &item : list) {
      size += item.size;
    }
    return size;
  }
};

class AMLocalClient : public BaseClient {
public:
  AMLocalClient(ConRequst request, size_t buffer_capacity = 10,
                const py::object &trace_cb = py::none())
      : BaseClient(request, buffer_capacity, trace_cb) {
    this->PROTOCOL = ClientProtocol::LOCAL;
  }
  ECM GetState() override { return {EC::Success, ""}; };

  ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
            std::chrono::steady_clock::time_point start_time =
                std::chrono::steady_clock::now()) override {
    return {EC::Success, ""};
  }

  ECM Connect(bool force = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1,
              std::chrono::steady_clock::time_point start_time =
                  std::chrono::steady_clock::now()) override {
    return {EC::Success, ""};
  }

  OS_TYPE GetOSType(bool update = false) override {
    if (!update && this->os_type != OS_TYPE::Uncertain) {
      return this->os_type;
    }

#ifdef _WIN32
    this->os_type = OS_TYPE::Windows;
#elif defined(_WIN64)
    this->os_type = OS_TYPE::Windows;
#elif defined(__linux__) || defined(__gnu_linux__)
    this->os_type = OS_TYPE::Linux;
#elif defined(__APPLE__) && defined(__MACH__)
    this->os_type = OS_TYPE::MacOS;
#elif defined(__FreeBSD__)
    this->os_type = OS_TYPE::FreeBSD;
#else
    this->os_type = OS_TYPE::Unknown;
#endif
    return this->os_type;
  }

  double GetRTT(ssize_t times = 5, amf interrupt_flag = nullptr) override {
    return 0;
  }

  std::string GetHomeDir() override {
    if (!this->home_dir.empty()) {
      return this->home_dir;
    }
    this->home_dir = AMFS::HomePath();
    return this->home_dir;
  }

  SR stat(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1,
          std::chrono::steady_clock::time_point start_time =
              std::chrono::steady_clock::now()) {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, PathInfo()};
    }
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
    // 调用 stat 获取文件元数据（支持符号链接，若需跟随链接用 stat 而非
    // lstat）
    if (stat(path.c_str(), &file_stat) == -1) {
      return std::make_pair(
          "Fail to stat file: " + std::string(strerror(errno)), info);
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
  std::pair<ECM, PathType>
  get_path_type(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1,
                std::chrono::steady_clock::time_point start_time =
                    std::chrono::steady_clock::now()) {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, PathType::Unknown};
    }
    std::string pathf = path;
    fs::path p(pathf);
    fs::file_status status;
    std::error_code ec;
    status = fs::status(p, ec);
    if (ec) {
      return {ECM{fec(ec), fmt::format("Get path type {} failed: {}", pathf,
                                       ec.message())},
              PathType::Unknown};
    }
    return {ECM{EC::Success, ""}, cast_fs_type(status.type())};
  }
  std::pair<ECM, bool> exists(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              std::chrono::steady_clock::time_point start_time =
                                  std::chrono::steady_clock::now()) {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, false};
    }
    return {ECM{EC::Success, ""}, fs::exists(fs::path(path))};
  }
  std::pair<ECM, bool>
  is_regular(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, false};
    }
    return {ECM{EC::Success, ""}, fs::is_regular_file(fs::path(path))};
  }
  std::pair<ECM, bool> is_dir(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              std::chrono::steady_clock::time_point start_time =
                                  std::chrono::steady_clock::now()) {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, false};
    }
    return {ECM{EC::Success, ""}, fs::is_directory(fs::path(path))};
  }

  std::pair<ECM, bool>
  is_symlink(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, false};
    }
    return {ECM{EC::Success, ""}, fs::is_symlink(fs::path(path))};
  }

  std::pair<ECM, std::vector<PathInfo>>
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
      return {ECM{fec(ec),
                  fmt::format("Listdir {} failed: {}", pathf, ec.message())},
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

  inline void _iwalk(const std::string &path, std::vector<PathInfo> &result,
                     bool ignore_sepcial_file, amf interrupt_flag = nullptr,
                     int timeout_ms = -1,
                     std::chrono::steady_clock::time_point start_time =
                         std::chrono::steady_clock::now()) {
    std::error_code ec;
    auto iter = fs::directory_iterator(path, ec);
    if (ec) {
      return;
    }
    bool end_dir = true;
    PathType type = PathType::Unknown;
    for (const auto &entry : iter) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      if (timeout_ms > 0 && std::chrono::steady_clock::now() - start_time >
                                std::chrono::milliseconds(timeout_ms)) {
        return;
      }
      type = cast_fs_type(entry.status().type());
      if (type == PathType::DIR) {
        end_dir = false;
        _iwalk(entry.path().string(), result, ignore_sepcial_file,
               interrupt_flag, timeout_ms, start_time);
      }
      if (ignore_sepcial_file && type != PathType::FILE) {
        continue;
      }
      auto [error, info] = stat(entry.path().string(), false);
      if (error.first != EC::Success) {
        continue;
      }
      result.push_back(info);
    }
    if (end_dir) {
      auto [error2, info2] = stat(path, false);
      if (error2.first != EC::Success) {
        return;
      }
      result.push_back(info2);
    }
  }

  inline std::vector<PathInfo>
  iwalk(const std::string &path, bool ignore_sepcial_file = true,
        amf interrupt_flag = nullptr, int timeout_ms = -1,
        std::chrono::steady_clock::time_point start_time =
            std::chrono::steady_clock::now()) {
    std::vector<PathInfo> result = {};
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return result;
    }
    if (info.type != PathType::DIR) {
      return {info};
    }
    _iwalk(path, result, ignore_sepcial_file, interrupt_flag, timeout_ms,
           start_time);
    return result;
  }
  inline void _walk(std::vector<std::string> parts, WRD &result, int cur_depth,
                    int max_depth, bool ignore_sepcial_file = true,
                    amf interrupt_flag = nullptr, int timeout_ms = -1,
                    std::chrono::steady_clock::time_point start_time =
                        std::chrono::steady_clock::now()) {
    if (max_depth > 0 && cur_depth > max_depth) {
      return;
    }
    std::string pathf = AMPathStr::join(parts);
    std::vector<PathInfo> files_info = {};
    bool empty_dir = true;
    auto [error, info] = listdir(pathf, interrupt_flag, timeout_ms, start_time);
    if (error.first != EC::Success) {
      return;
    }
    for (const auto &entry : info) {
      empty_dir = false;
      if (entry.type == PathType::DIR) {
        auto n_parts = parts;
        n_parts.push_back(entry.name);
        _walk(n_parts, result, cur_depth + 1, max_depth, ignore_sepcial_file);
      } else if (static_cast<int>(entry.type) < 0 && ignore_sepcial_file) {
        continue;
      } else {
        files_info.push_back(entry);
      }
    }
    if (!empty_dir && files_info.empty()) {
      return;
    }
    result.push_back(std::make_pair(parts, files_info));
  }

  inline std::pair<ECM, WRD>
  walk(const std::string &path, int max_depth, bool ignore_sepcial_file = true,
       amf interrupt_flag = nullptr, int timeout_ms = -1,
       std::chrono::steady_clock::time_point start_time =
           std::chrono::steady_clock::now()) {
    WRD result = {};
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return {error, result};
    } else if (info.type != PathType::DIR) {
      return {ECM{EC::NotADirectory,
                  fmt::format("Path is not a directory: {}", path)},
              result};
    }

    _walk({path}, result, 0, max_depth, ignore_sepcial_file, interrupt_flag,
          timeout_ms, start_time);

    return {{EC::Success, ""}, result};
  }

  inline void _getsize(const std::string &path, uint64_t &result,
                       bool trace_link) {
    fs::path p(path);
    if (!fs::exists(p)) {
      return;
    }
    if (fs::is_directory(p)) {
      for (const auto &entry : fs::directory_iterator(p)) {
        _getsize(entry.path().string(), result, trace_link);
      }
    } else if (fs::is_symlink(p)) {
      if (trace_link) {
        _getsize(fs::read_symlink(p).string(), result, trace_link);
      }
    } else if (fs::is_regular_file(p)) {
      result += fs::file_size(p);
    }
  }

  inline uint64_t getsize(const std::string &path, bool trace_link = false) {
    uint64_t result = 0;
    _getsize(path, result, trace_link);
    return result;
  }
};
// FTP Client using libcurl
class AMFTPClient : public BaseClient {
protected:
  void SetState(const ECM &state) override {
    std::lock_guard<std::mutex> lock(state_mtx);
    this->state = state;
  }

private:
  CURL *curl = nullptr;
  std::string home_dir = "";
  std::atomic<bool> connected = false;
  std::regex ftp_url_pattern = std::regex("^ftp://.*$");
  std::string url = "";
  std::mutex state_mtx;

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
    std::string pathf = AMFS::join(parts);
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

  struct MemoryStruct {
    char *memory;
    size_t size;
  };

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

  ECM SetupAuth(const std::string &path) {
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
    info.path = AMFS::join(dir_path, name, AMFS::SepType::Unix);
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
    std::string url = BuildUrl("/");
    ECM ecm = SetupCurl(url);
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
    }
    curl = curl_easy_init();

    if (!curl) {
      return {EC::NoConnection, "CURL not initialized"};
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

  SR stat(const std::string &path) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!curl) {
      return {ECM{EC::NoConnection, "CURL not initialized"}, PathInfo()};
    }

    std::string pathf = path;
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)},
              PathInfo()};
    }

    // First try to list as directory (append / to path)
    std::string dir_url = BuildUrl(pathf + "/");
    ECM ecm = SetupCurl(dir_url);
    if (ecm.first != EC::Success) {
      return {ecm, PathInfo()};
    }

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
      // It's a directory
      free(chunk.memory);
      PathInfo info;
      info.path = pathf;
      info.name = AMFS::basename(pathf);
      info.dir = AMFS::dirname(pathf);
      info.type = PathType::DIR;
      info.size = 0;
      return {ECM{EC::Success, ""}, info};
    }

    free(chunk.memory);

    // Not a directory, try as file using SIZE command
    std::string file_url = BuildUrl(pathf);
    ecm = SetupCurl(file_url);
    if (ecm.first != EC::Success) {
      return {ecm, PathInfo()};
    }

    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);

    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
      PathInfo info;
      info.path = pathf;
      info.name = AMFS::basename(pathf);
      info.dir = AMFS::dirname(pathf);
      info.type = PathType::FILE;

      // Get file size
      double filesize = 0;
      curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &filesize);
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

    // Fallback: try listing parent directory
    std::string parent = AMFS::dirname(pathf);
    std::string filename = AMFS::basename(pathf);

    auto [rcm, files] = listdir(parent);
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

  std::pair<ECM, bool> exists(const std::string &path) override {
    auto [rcm, path_info] = stat(path);
    if (rcm.first == EC::Success) {
      return {rcm, true};
    } else if (rcm.first == EC::PathNotExist || rcm.first == EC::FileNotExist) {
      return {{EC::Success, ""}, false};
    } else {
      return {rcm, false};
    }
  }

  std::pair<ECM, bool> is_dir(const std::string &path) override {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""}, path_info.type == PathType::DIR};
  }

  std::pair<ECM, std::vector<PathInfo>> listdir(const std::string &path,
                                                int max_time_ms = -1) override {
    std::string pathf = path;
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)}, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    std::string url = BuildUrl(pathf + "/");

    ECM ecm = SetupCurl(url);

    if (ecm.first != EC::Success) {
      return {ecm, {}};
    }

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    // 修复核心1：为curl设置全局超时，覆盖网络请求的全阶段（连接、响应、传输）
    if (max_time_ms > 0) {
      // CURLOPT_TIMEOUT_MS：整个curl操作的最大允许时间（毫秒），到时间自动终止请求
      curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,
                       static_cast<long>(max_time_ms));
    }
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OPERATION_TIMEDOUT) {
      free(chunk.memory);
      return {ECM{EC::OperationTimeout,
                  fmt::format("Curl Operation timeout: {}ms", max_time_ms)},
              {}};
    } else if (res != CURLE_OK) {
      free(chunk.memory);
      return {ECM{EC::FTPListFailed,
                  fmt::format("List failed: {}", curl_easy_strerror(res))},
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

class UnionFileHandle {
public:
  // Local file handle
#ifdef _WIN32
  HANDLE file_handle = INVALID_HANDLE_VALUE;
#else
  int file_handle = -1;
#endif

  // SFTP file handle
  LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
  std::shared_ptr<AMSFTPClient> client = nullptr;

  // Common members
  std::string path;
  bool is_write = false;
  size_t file_size = 0;
  size_t offset = 0;
  bool is_sftp = false;

  ~UnionFileHandle() { Close(); }

  void Close() {
    if (is_sftp) {
      if (sftp_handle) {
        libssh2_sftp_close_handle(sftp_handle);
        sftp_handle = nullptr;
      }
    } else {
#ifdef _WIN32
      if (file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle);
        file_handle = INVALID_HANDLE_VALUE;
      }
#else
      if (file_handle != -1) {
        close(file_handle);
        file_handle = -1;
      }
#endif
    }
  }

  ECM Init(const std::string &path, size_t file_size,
           std::shared_ptr<AMSFTPClient> client = nullptr,
           bool is_write = false, bool sequential = true) {
    this->path = path;
    this->is_write = is_write;
    this->file_size = file_size;
    this->client = client;
    this->is_sftp = (client != nullptr);

    if (is_sftp) {
      // SFTP file
      if (is_write) {
        sftp_handle = libssh2_sftp_open(
            client->sftp, path.c_str(),
            LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);
      } else {
        sftp_handle = libssh2_sftp_open(client->sftp, path.c_str(),
                                        LIBSSH2_FXF_READ, 0400);
      }
      if (!sftp_handle) {
        EC rc = client->GetLastEC();
        std::string msg = client->GetLastErrorMsg();
        return {rc, fmt::format("Open sftp file \"{}\" failed: {}", path, msg)};
      }
    } else {
      // Local file
#ifdef _WIN32
      DWORD access = is_write ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
      DWORD share = is_write ? 0 : FILE_SHARE_READ;
      DWORD creation = is_write ? CREATE_ALWAYS : OPEN_EXISTING;
      DWORD flags =
          sequential ? FILE_FLAG_SEQUENTIAL_SCAN : FILE_ATTRIBUTE_NORMAL;

      file_handle = CreateFileW(AMStr::wstr(path).c_str(), access, share,
                                nullptr, creation, flags, nullptr);

      if (file_handle == INVALID_HANDLE_VALUE) {
        return {EC::LocalFileOpenError,
                fmt::format("Failed to open local file \"{}\": error code {}",
                            path, GetLastError())};
      }
#else
      int flags = is_write ? (O_RDWR | O_CREAT | O_TRUNC) : O_RDONLY;
      file_handle = open(path.c_str(), flags, 0644);

      if (file_handle == -1) {
        return {EC::LocalFileOpenError,
                fmt::format("Failed to open local file \"{}\": {}", path,
                            strerror(errno))};
      }
#endif
    }

    return {EC::Success, ""};
  }

  bool IsValid() const {
    if (is_sftp) {
      return sftp_handle != nullptr;
    } else {
#ifdef _WIN32
      return file_handle != INVALID_HANDLE_VALUE;
#else
      return file_handle != -1;
#endif
    }
  }

  std::pair<ssize_t, ECM> Read(std::shared_ptr<StreamRingBuffer> ring_buffer) {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "File not initialized"}};
    }

    auto [write_ptr, max_write] = ring_buffer->get_write_ptr();
    ssize_t to_read =
        max_write > file_size - offset ? file_size - offset : max_write;
    ssize_t bytes_read;
    if (to_read > 0) {
      if (is_sftp) {
        // SFTP read
        std::lock_guard<std::recursive_mutex> lock(client->mtx);
        bytes_read = libssh2_sftp_read(sftp_handle, write_ptr, to_read);
        if (bytes_read > 0) {
          ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {bytes_read, {EC::Success, ""}};
        } else if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          return {
              bytes_read,
              {rc, fmt::format("Read sftp file \"{}\" failed: {}", path, msg)}};
        }
      } else {
        // Local file read
#ifdef _WIN32
        DWORD bytes_read = 0;
        if (!ReadFile(file_handle, write_ptr, static_cast<DWORD>(to_read),
                      &bytes_read, nullptr)) {
          return {-1,
                  {EC::LocalFileReadError,
                   fmt::format("Read local file \"{}\" failed: error code {}",
                               path, GetLastError())}};
        }
        if (bytes_read > 0) {
          ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), {EC::Success, ""}};
        } else {
          return {0, {EC::EndOfFile, "End of file"}};
        }
#else
        ssize_t bytes_read = read(file_handle, write_ptr, to_read);
        if (bytes_read > 0) {
          ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), {EC::Success, ""}};
        } else if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileReadError,
                   fmt::format("Read local file \"{}\" failed: {}", path,
                               strerror(errno))}};
        }
#endif
      }
    }
    return {0, {EC::Success, ""}};
  }

  std::pair<ssize_t, ECM> Write(std::shared_ptr<StreamRingBuffer> ring_buffer) {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "File not initialized"}};
    }

    auto [read_ptr, max_read] = ring_buffer->get_read_ptr();
    ssize_t to_write =
        max_read > file_size - offset ? file_size - offset : max_read;
    ssize_t bytes_written;
    if (to_write > 0) {
      if (is_sftp) {
        // SFTP write
        std::lock_guard<std::recursive_mutex> lock(client->mtx);
        bytes_written = libssh2_sftp_write(sftp_handle, read_ptr, to_write);
        if (bytes_written > 0) {
          ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {bytes_written, {EC::Success, ""}};
        } else if (bytes_written == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          return {bytes_written,
                  {rc, fmt::format("Write sftp file \"{}\" failed: {}", path,
                                   msg)}};
        }
      } else {
        // Local file write
#ifdef _WIN32
        DWORD bytes_written = 0;
        if (!WriteFile(file_handle, read_ptr, static_cast<DWORD>(to_write),
                       &bytes_written, nullptr)) {
          return {-1,
                  {EC::LocalFileWriteError,
                   fmt::format("Write local file \"{}\" failed: error code {}",
                               path, GetLastError())}};
        }
        if (bytes_written > 0) {
          ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {static_cast<int>(bytes_written), {EC::Success, ""}};
        } else {
          return {0, {EC::EndOfFile, "End of file"}};
        }
#else
        ssize_t bytes_written = write(file_handle, read_ptr, to_write);
        if (bytes_written > 0) {
          ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {static_cast<int>(bytes_written), {EC::Success, ""}};
        } else if (bytes_written == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileWriteError,
                   fmt::format("Write local file \"{}\" failed: {}", path,
                               strerror(errno))}};
        }
#endif
      }
    }
    return {0, {EC::Success, ""}};
  }
};

using AMCilent =
    std::variant<std::shared_ptr<AMSFTPClient>, std::shared_ptr<AMFTPClient>>;
std::optional<AMCilent>
CreateClient(const ConRequst &requeset, ClientProtocol protocol,
             ssize_t trace_num = 10, py::object trace_cb = py::none(),
             ssize_t buffer_size = 8 * AMMB, std::vector<std::string> keys = {},
             py::object auth_cb = py::none());

class ClientMaintainer {
private:
  std::unordered_map<std::string, std::shared_ptr<BaseClient>> hosts;
  std::atomic<bool> is_heartbeat;
  std::thread heartbeat_thread;
  py::function disconnect_cb;
  bool is_disconnect_cb = false;
  std::recursive_mutex beat_mtx;

  void HeartbeatAct(int interval_s) {
    int millsecond = 0;
    ECM rcm;
    while (true) {
      // 遍历hosts字典
      {
        std::lock_guard<std::recursive_mutex> lock(beat_mtx);
        for (auto &host : hosts) {
          rcm = host.second->Check();
          if (rcm.first != EC::Success) {
            if (is_disconnect_cb) {
              py::gil_scoped_acquire acquire;
              disconnect_cb(host.second, rcm);
            }
          }
        }
      }
      while (millsecond < interval_s * 1000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        millsecond += 100;
        if (!is_heartbeat.load()) {
          return;
        }
      }
      millsecond = 0;
    }
  }

public:
  ~ClientMaintainer() {
    is_heartbeat.store(false);
    if (heartbeat_thread.joinable()) {
      heartbeat_thread.join();
    }
  }

  std::shared_ptr<BaseClient> GetHost(const std::string &nickname) {
    if (hosts.find(nickname) == hosts.end()) {
      return nullptr;
    }
    return hosts[nickname];
  }

  ClientMaintainer(int heartbeat_interval_s = 60,
                   py::object disconnect_cb = py::none()) {
    this->is_heartbeat.store(true);
    heartbeat_thread = std::thread(
        [this, heartbeat_interval_s]() { HeartbeatAct(heartbeat_interval_s); });
    if (!disconnect_cb.is_none()) {
      this->disconnect_cb = py::cast<py::function>(disconnect_cb);
      this->is_disconnect_cb = true;
    }
  }

  std::vector<std::string> get_nicknames() {
    std::vector<std::string> host_list;
    for (auto &host : hosts) {
      host_list.push_back(host.first);
    }
    return host_list;
  }

  std::optional<AMCilent> get_client(const std::string &nickname) {
    if (hosts.find(nickname) == hosts.end()) {
      return std::nullopt;
    }
    auto client = hosts[nickname];
    if (client->GetProtocol() == ClientProtocol::SFTP) {
      return std::dynamic_pointer_cast<AMSFTPClient>(client);
    } else if (client->GetProtocol() == ClientProtocol::FTP) {
      return std::dynamic_pointer_cast<AMFTPClient>(client);
    }
    return std::nullopt;
  }

  std::vector<AMCilent> get_clients() {
    std::vector<AMCilent> client_list;
    for (auto &host : hosts) {
      if (host.second->GetProtocol() == ClientProtocol::SFTP) {
        client_list.emplace_back(
            std::dynamic_pointer_cast<AMSFTPClient>(host.second));
      } else if (host.second->GetProtocol() == ClientProtocol::FTP) {
        client_list.emplace_back(
            std::dynamic_pointer_cast<AMFTPClient>(host.second));
      }
    }
    return client_list;
  }

  void add_client(const std::string &nickname,
                  std::shared_ptr<AMSFTPClient> client,
                  bool overwrite = false) {
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (hosts.find(nickname) != hosts.end()) {
      if (!overwrite) {
        return;
      }
      hosts.erase(nickname);
    }

    hosts[nickname] = std::dynamic_pointer_cast<BaseClient>(client);
  }
  void add_client(const std::string &nickname,
                  std::shared_ptr<AMFTPClient> client, bool overwrite = false) {
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (hosts.find(nickname) != hosts.end()) {
      if (!overwrite) {
        return;
      }
      hosts.erase(nickname);
    }
    hosts[nickname] = std::dynamic_pointer_cast<BaseClient>(client);
  }

  void remove_client(const std::string &nickname) {
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (hosts.find(nickname) != hosts.end()) {
      hosts.erase(nickname);
    }
  }

  ECM test_client(const std::string &nickname, bool update = false) {
    if (nickname.empty()) {
      return ECM{EC::InvalidArg, "Host nickname is empty"};
    } else if (hosts.find(nickname) == hosts.end()) {
      return ECM{EC::ClientNotFound,
                 fmt::format("Client not found: {}", nickname)};
    }
    if (!update) {
      ECM rcm = hosts[nickname]->GetState();
      if (rcm.first != EC::Success) {
        return hosts[nickname]->Check();
      } else {
        return rcm;
      }
    } else {
      return hosts[nickname]->Connect();
    }
  }

  void SetDisconnectCallback(py::object callback = py::none()) {
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (callback.is_none()) {
      is_disconnect_cb = false;
      disconnect_cb = py::function();
    } else {
      is_disconnect_cb = true;
      disconnect_cb = py::cast<py::function>(callback);
    }
  };
};

class AMSFTPWorker {
private:
  ECM Transit(const std::string &src, const std::string &dst,
              const std::shared_ptr<AMSFTPClient> &src_worker,
              const std::shared_ptr<AMSFTPClient> &dst_worker) {
    ErrorCode rc_final = EC::Success;
    std::string error_msg = "";
    LIBSSH2_SFTP_HANDLE *srcFile = nullptr;
    LIBSSH2_SFTP_HANDLE *dstFile = nullptr;
    std::lock_guard<std::recursive_mutex> lock(src_worker->mtx);
    std::lock_guard<std::recursive_mutex> lock2(dst_worker->mtx);
    dst_worker->mkdir(AMFS::dirname(dst));
    srcFile = libssh2_sftp_open(src_worker->sftp, src.c_str(), LIBSSH2_FXF_READ,
                                0400);
    dstFile = libssh2_sftp_open(
        dst_worker->sftp, dst.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);

    if (!srcFile) {
      rc_final = src_worker->GetLastEC();
      error_msg = fmt::format("Failed to open src remote file: {}, cause {}",
                              src, src_worker->GetLastErrorMsg());
      src_worker->trace(
          TraceLevel::Error, rc_final,
          fmt::format("{}@{}", src_worker->res_data.nickname, src),
          "Remote2Remote", error_msg);
      return {rc_final, error_msg};
    }

    if (!dstFile) {
      // 获取错误代码
      rc_final = dst_worker->GetLastEC();
      error_msg = fmt::format("Failed to open dst remote file: {}, cause {}",
                              dst, dst_worker->GetLastErrorMsg());
      dst_worker->trace(
          TraceLevel::Error, rc_final,
          fmt::format("{}@{}", dst_worker->res_data.nickname, dst),
          "Remote2Remote", error_msg);
      return {rc_final, error_msg};
    }

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_fstat(srcFile, &attrs);
    uint64_t file_size = attrs.filesize;

    // uint64_t buffer_size_ori = calculate_buffer_size(file_size, 32 * AMGB);
    uint64_t all_read = 0;
    uint64_t all_write = 0;
    uint64_t last_callback_write = 0;
    long rc_read, rc_write;
    uint64_t idle_count = 0;

    libssh2_session_set_blocking(src_worker->session, 0);
    libssh2_session_set_blocking(dst_worker->session, 0);

    while (all_write < file_size) {
      bool did_work = false;

      // === 生产者：从源读取数据写入缓冲区 ===
      if (all_read < file_size && pd.ring_buffer->writable() > 0) {
        auto [write_ptr, max_write] = pd.ring_buffer->get_write_ptr();
        size_t to_read = std::min<size_t>(max_write, file_size - all_read);

        if (to_read > 0) {
          rc_read = libssh2_sftp_read(srcFile, write_ptr, to_read);
          if (rc_read > 0) {
            pd.ring_buffer->commit_write(rc_read);
            all_read += rc_read;
            did_work = true;
            idle_count = 0;
          } else if (rc_read < 0 && rc_read != LIBSSH2_ERROR_EAGAIN) {
            rc_final = src_worker->GetLastEC();
            error_msg = fmt::format("Sftp read error: {}",
                                    src_worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 消费者：从缓冲区读取数据写入目标 ===
      if (pd.ring_buffer->available() > 0) {
        auto [read_ptr, max_read] = pd.ring_buffer->get_read_ptr();

        if (max_read > 0) {
          rc_write = libssh2_sftp_write(dstFile, read_ptr, max_read);
          if (rc_write > 0) {
            pd.ring_buffer->commit_read(rc_write);
            all_write += rc_write;
            did_work = true;
            idle_count = 0;
          } else if (rc_write < 0 && rc_write != LIBSSH2_ERROR_EAGAIN) {
            rc_final = dst_worker->GetLastEC();
            error_msg = fmt::format("Sftp write error: {}",
                                    dst_worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 进度回调（每写入buffer_size或完成时触发）===
      if (all_write - last_callback_write >= pd.ring_buffer->get_capacity() ||
          all_write == file_size) {
        last_callback_write = all_write;
        pd.this_size = all_write;
        pd.accumulated_size += (all_write - last_callback_write);
        InnerCallback();

        // 暂停/终止检查
        while (pd.is_pause.load() && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (pd.is_terminate.load()) {
          rc_final = EC::Terminate;
          error_msg = "Transfer cancelled";
          goto clean;
        }
      }

      // === 空闲时让出CPU ===
      if (!did_work) {
        idle_count++;
        if (idle_count > 10) {
          std::this_thread::sleep_for(std::chrono::microseconds(20));
          idle_count = 0;
        }
      }
    }

  clean:
    libssh2_session_set_blocking(src_worker->session, 1);
    libssh2_session_set_blocking(dst_worker->session, 1);

    InnerCallback(true);

    if (srcFile) {
      libssh2_sftp_close_handle(srcFile);
    }

    if (dstFile) {
      libssh2_sftp_close_handle(dstFile);
    }

    return {rc_final, error_msg};
  }

  ECM InHostCopy(const std::string &src, const std::string &dst,
                 const std::shared_ptr<AMSFTPClient> &worker,
                 uint64_t chunk_size = 256 * AMKB) {
    ErrorCode rc_final = EC::Success;
    std::string error_msg = "";
    LIBSSH2_SFTP_HANDLE *srcFile = nullptr;
    LIBSSH2_SFTP_HANDLE *dstFile = nullptr;
    std::lock_guard<std::recursive_mutex> lock(worker->mtx);
    worker->mkdirs(AMFS::dirname(dst));
    srcFile =
        libssh2_sftp_open(worker->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);

    if (!srcFile) {
      rc_final = worker->GetLastEC();
      error_msg = fmt::format("Failed to open src remote file: {}, cause {}",
                              src, worker->GetLastErrorMsg());
      worker->trace(TraceLevel::Error, rc_final,
                    fmt::format("{}@{}", worker->res_data.nickname, src),
                    "Remote2Remote", error_msg);
      return {rc_final, error_msg};
    }
    dstFile = libssh2_sftp_open(
        worker->sftp, dst.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);
    if (!dstFile) {
      // 获取错误代码
      rc_final = worker->GetLastEC();
      error_msg = fmt::format("Failed to open dst remote file: {}, cause {}",
                              dst, worker->GetLastErrorMsg());
      worker->trace(TraceLevel::Error, rc_final,
                    fmt::format("{}@{}", worker->res_data.nickname, dst),
                    "Remote2Remote", error_msg);
      return {rc_final, error_msg};
    }

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_fstat(srcFile, &attrs);
    uint64_t file_size = attrs.filesize;

    // uint64_t buffer_size_ori = calculate_buffer_size(file_size, 32 * AMGB);
    StreamRingBuffer ring(chunk_size);
    uint64_t all_read = 0;
    uint64_t all_write = 0;
    uint64_t last_callback_write = 0;
    long rc_read, rc_write;
    uint64_t idle_count = 0;

    libssh2_session_set_blocking(worker->session, 0);

    while (all_write < file_size) {
      bool did_work = false;

      // === 生产者：从源读取数据写入缓冲区 ===
      if (all_read < file_size && ring.writable() > 0) {
        auto [write_ptr, max_write] = ring.get_write_ptr();
        size_t to_read = std::min<size_t>(max_write, file_size - all_read);

        if (to_read > 0) {
          rc_read = libssh2_sftp_read(srcFile, write_ptr, to_read);
          if (rc_read > 0) {
            ring.commit_write(rc_read);
            all_read += rc_read;
            did_work = true;
            idle_count = 0;
          } else if (rc_read < 0 && rc_read != LIBSSH2_ERROR_EAGAIN) {
            rc_final = worker->GetLastEC();
            error_msg =
                fmt::format("Sftp read error: {}", worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 消费者：从缓冲区读取数据写入目标 ===
      if (ring.available() > 0) {
        auto [read_ptr, max_read] = ring.get_read_ptr();

        if (max_read > 0) {
          rc_write = libssh2_sftp_write(dstFile, read_ptr, max_read);
          if (rc_write > 0) {
            ring.commit_read(rc_write);
            all_write += rc_write;
            did_work = true;
            idle_count = 0;
          } else if (rc_write < 0 && rc_write != LIBSSH2_ERROR_EAGAIN) {
            rc_final = worker->GetLastEC();
            error_msg =
                fmt::format("Sftp write error: {}", worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 进度回调（每写入buffer_size或完成时触发）===
      if (all_write - last_callback_write >= chunk_size ||
          all_write == file_size) {

        last_callback_write = all_write;
        pd.accumulated_size += (all_write - last_callback_write);
        pd.this_size = all_write;
        InnerCallback();

        // 暂停/终止检查
        while (pd.is_pause.load() && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (pd.is_terminate.load()) {
          rc_final = EC::Terminate;
          error_msg = "Transfer cancelled";
          goto clean;
        }
      }

      // === 空闲时让出CPU ===
      if (!did_work) {
        idle_count++;
        if (idle_count > 10) {
          std::this_thread::sleep_for(std::chrono::microseconds(20));
          idle_count = 0;
        }
      }
    }

  clean:
    libssh2_session_set_blocking(worker->session, 1);

    InnerCallback(true);

    if (srcFile) {
      libssh2_sftp_close_handle(srcFile);
    }

    if (dstFile) {
      libssh2_sftp_close_handle(dstFile);
    }

    return {rc_final, error_msg};
  }

  void Reading(const TransferTask &task, std::shared_ptr<BaseClient> client,
               ConRequst request = ConRequst()) {
    if ((client && client->GetProtocol() == ClientProtocol::SFTP) ||
        (!client && request.nickname.empty())) {
      UnionFileHandle file_handle;
      std::shared_ptr<AMSFTPClient> clientf = nullptr;
      if (client) {
        clientf = std::static_pointer_cast<AMSFTPClient>(client);
      }
      ECM rcm = file_handle.Init(task.src, task.size, clientf, false, true);
      if (rcm.first != EC::Success) {
        pd.is_terminate.store(true);
        pd.rcm = rcm;
        return;
      }
      while (file_handle.offset < file_handle.file_size &&
             !pd.is_terminate.load()) {
        while (pd.ring_buffer->writable() == 0 && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause.load() && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate.load()) {
          return;
        }
        auto [bytes_read, ecm] = file_handle.Read(pd.ring_buffer);
        if (ecm.first != EC::Success) {
          pd.is_terminate.store(true);
          pd.rcm = ecm;
          return;
        }
      }
    } else if (!client && !request.nickname.empty()) {
      auto client_ftp = std::make_shared<AMFTPClient>(request);
      ECM ecm = client_ftp->Connect();
      if (ecm.first != EC::Success) {
        pd.is_terminate.store(true);
        pd.rcm = ecm;
        return;
      }
      client_ftp->Download(task.src, FTPGiveData, &pd);
    } else if (client && client->GetProtocol() == ClientProtocol::FTP) {
      // 读取FTP文件，而且需要创建额外的ftp客户端
      auto client_ftp = std::static_pointer_cast<AMFTPClient>(client);
      client_ftp->Download(task.src, FTPGiveData, &pd);
    }
  }

  void Writing(const TransferTask &task, std::shared_ptr<BaseClient> client,
               ConRequst request = ConRequst()) {
    if ((client && client->GetProtocol() == ClientProtocol::SFTP) ||
        (!client && request.nickname.empty())) {
      UnionFileHandle file_handle;
      std::shared_ptr<AMSFTPClient> clientf = nullptr;
      if (client) {
        clientf = std::static_pointer_cast<AMSFTPClient>(client);
      }
      ECM rcm = file_handle.Init(task.dst, task.size, clientf, true, true);
      if (rcm.first != EC::Success) {
        pd.is_terminate.store(true);
        pd.rcm = rcm;
        return;
      }
      while (file_handle.offset < file_handle.file_size &&
             !pd.is_terminate.load()) {
        while (pd.ring_buffer->available() == 0 && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause.load() && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate.load()) {
          return;
        }
        auto [bytes_write, ecm] = file_handle.Write(pd.ring_buffer);
        if (ecm.first != EC::Success) {
          pd.is_terminate.store(true);
          pd.rcm = ecm;
          return;
        }
        pd.accumulated_size += bytes_write;
        pd.this_size = file_handle.offset;
        InnerCallback();
      }
    } else if (!client && !request.nickname.empty()) {
      auto client_ftp = std::make_shared<AMFTPClient>(request);
      ECM ecm = client_ftp->Connect();
      if (ecm.first != EC::Success) {
        pd.is_terminate.store(true);
        pd.rcm = ecm;
        return;
      }
      client_ftp->Upload(task.dst, FTPGiveData, &pd);
    } else if (client && client->GetProtocol() == ClientProtocol::FTP) {
      // 读取FTP文件，而且需要创建额外的ftp客户端
      auto client_ftp = std::static_pointer_cast<AMFTPClient>(client);
      client_ftp->Upload(task.dst, FTPGiveData, &pd);
    }
  }

  std::pair<ECM, PathInfo> Ustat(const std::string &path,
                                 const std::shared_ptr<ClientMaintainer> &hostm,
                                 const std::string &nickname = "") {
    if (nickname.empty()) {
      auto res = AMFS::stat(path);
      if (!res.first.empty()) {
        return {ECM{EC::LocalStatError, res.first}, res.second};
      }
      return {ECM{EC::Success, ""}, res.second};
    }
    ECM rc = hostm->test_client(nickname);
    if (rc.first != EC::Success) {
      return {rc, PathInfo()};
    }
    auto client = hostm->GetHost(nickname);
    if (!client) {
      return {ECM{EC::NoSession, "Client not found"}, PathInfo()};
    }
    return client->stat(path);
  }

  std::vector<PathInfo> Uiwalk(const std::string &path,
                               const std::shared_ptr<ClientMaintainer> &hostm,
                               const std::string &nickname = "",
                               bool ignore_special_file = true) {
    if (nickname.empty()) {
      return AMFS::iwalk(path, ignore_special_file);
    }
    ECM rc = hostm->test_client(nickname);
    if (rc.first != EC::Success) {
      return {};
    }
    auto client = hostm->GetHost(nickname);
    if (!client) {
      return {};
    }
    return client->iwalk(path, ignore_special_file);
  }
  ECM _UnionTransfer(const TransferTask &task,
                     std::shared_ptr<BaseClient> src_client = nullptr,
                     std::shared_ptr<BaseClient> dst_client = nullptr) {
    ConRequst request;
    if (src_client && src_client->GetProtocol() == ClientProtocol::SFTP &&
        dst_client && dst_client->GetProtocol() == ClientProtocol::SFTP) {
      // 走SFTP非阻塞模式
      return this->Transit(task.src, task.dst,
                           std::static_pointer_cast<AMSFTPClient>(src_client),
                           std::static_pointer_cast<AMSFTPClient>(dst_client));
    } else if (src_client && src_client->GetProtocol() == ClientProtocol::FTP &&
               dst_client && dst_client->GetProtocol() == ClientProtocol::FTP) {
      // 双FTP模式
      request = src_client->GetRequest();
    }
    // 启动一个thread执行Reading
    std::thread reading_thread(
        [&]() { this->Reading(task, src_client, request); });

    this->Writing(task, dst_client, request);
    if (reading_thread.joinable()) {
      reading_thread.join();
    }
    if (pd.rcm.first == EC::Success) {
      if (pd.is_terminate.load()) {
        return {EC::Terminate, "Transfer terminated by user"};
      } else {
        return {EC::Success, ""};
      }
    } else {
      return pd.rcm;
    }
  }
  ssize_t CalculateBufferSize(std::shared_ptr<BaseClient> src_client,
                              std::shared_ptr<BaseClient> dst_client,
                              ssize_t provided_size) {
    ssize_t src_size = src_client ? src_client->TransferRingBufferSize() : -1;
    ssize_t dst_size = dst_client ? dst_client->TransferRingBufferSize() : -1;
    bool is_local = !src_client && !dst_client;
    if (provided_size > AMMinBufferSize && provided_size < AMMaxBufferSize) {
      // 优先使用用户提供的缓冲区大小
      return provided_size;
    } else if (src_size < 0 && dst_size < 0) {
      if (is_local) {
        return AMDefaultLocalBufferSize;
      } else {
        return AMDefaultRemoteBufferSize;
      }
    } else if (src_size > 0 && dst_size < 0) {
      return std::max<ssize_t>(std::min<ssize_t>(src_size, AMMaxBufferSize),
                               AMMinBufferSize);
    } else if (src_size > 0 && dst_size > 0) {
      return std::max<ssize_t>(
          std::min<ssize_t>({src_size, dst_size, AMMaxBufferSize}),
          AMMinBufferSize);
    } else {
      return std::max<ssize_t>(std::min<ssize_t>(dst_size, AMMaxBufferSize),
                               AMMinBufferSize);
    }
  }

  std::tuple<ECM, std::shared_ptr<BaseClient>, std::shared_ptr<BaseClient>>
  TestHost(const TransferTask &task,
           const std::shared_ptr<ClientMaintainer> &hostm) {
    std::shared_ptr<BaseClient> src_client = nullptr;
    std::shared_ptr<BaseClient> dst_client = nullptr;
    ECM rcm = ECM{EC::Success, ""};
    if (!task.src_host.empty()) {
      src_client = hostm->GetHost(task.src_host);
      if (!src_client) {
        return {ECM{EC::NoSession,
                    fmt::format("Source host \"{}\" not found", task.src_host)},
                nullptr, nullptr};
      }
      rcm = src_client->Check();
      if (rcm.first != EC::Success) {
        return {
            ECM{rcm.first, fmt::format("Source host \"{}\" connection error",
                                       task.src_host)},
            nullptr, nullptr};
      }
    }
    if (!task.dst_host.empty()) {
      dst_client = hostm->GetHost(task.dst_host);
      if (!dst_client) {
        return {
            ECM{EC::NoSession, fmt::format("Destination host \"{}\" not found",
                                           task.dst_host)},
            nullptr, nullptr};
      }
      rcm = dst_client->Check();
      if (rcm.first != EC::Success) {
        return {ECM{rcm.first,
                    fmt::format("Destination host \"{}\" connection error",
                                task.dst_host)},
                nullptr, nullptr};
      }
    }
    return {rcm, src_client, dst_client};
  }

public:
  TransferCallback callback;
  ProgressData pd;

  inline void InnerCallback(bool force = false) {
    if (callback.need_progress_cb) {
      auto time_now = timenow();
      if (force || ((time_now - pd.cb_time) > pd.cb_interval_s)) {
        pd.cb_time = time_now;
        ECM cb_error = {EC::Success, ""};
        auto ctrl_opt = callback.CallProgress(
            ProgressCBInfo(pd.src, pd.dst, pd.src_host, pd.dst_host,
                           pd.this_size, pd.file_size, pd.accumulated_size,
                           pd.total_size),
            &cb_error);
        if (cb_error.first != EC::Success && callback.need_error_cb) {
          callback.error_cb(ErrorCBInfo(cb_error, pd.src, pd.dst, pd.src_host,
                                        pd.dst_host));
        }
        if (ctrl_opt.has_value()) {
          SetState(*ctrl_opt);
        }
      }
    }
  }
  AMSFTPWorker(const TransferCallback &callback, float cb_interval_s = 0.2)
      : callback(callback), pd(cb_interval_s) {
    this->pd.progress_cb = [this](bool force) { InnerCallback(force); };
  }

  static size_t FTPNeedData(char *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    // size指块数，但这个值往往是1
    auto *pd = static_cast<ProgressData *>(userdata);
    while (pd->ring_buffer->available() == 0 && !pd->is_terminate.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    while (pd->is_pause.load() && !pd->is_terminate.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (pd->is_terminate.load()) {
      return CURL_READFUNC_ABORT;
    }

    auto [read_ptr, read_len] = pd->ring_buffer->get_read_ptr();
    ssize_t to_read = read_len > size * nmemb ? size * nmemb : read_len;
    if (to_read > 0) {
      try {
        memcpy(ptr, read_ptr, to_read);
        pd->ring_buffer->commit_read(to_read);
        pd->this_size += to_read;
        pd->accumulated_size += to_read;
        pd->progress_cb(false);
        return to_read;
      } catch (const std::exception &e) {
        pd->is_terminate.store(true);
        pd->rcm = ECM{EC::BufferReadError, e.what()};
        return CURL_READFUNC_ABORT;
      }
    } else if (to_read == 0) {
      return 0;
    } else {
      pd->is_terminate.store(true);
      pd->rcm = ECM{EC::BufferReadError, "Get Negativate value for data size"};
      return CURL_READFUNC_ABORT;
    }
  }

  static size_t FTPGiveData(char *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    auto *pd = static_cast<ProgressData *>(userdata);
    while (pd->ring_buffer->writable() == 0 && !pd->is_terminate.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    while (pd->is_pause.load() && !pd->is_terminate.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (pd->is_terminate.load()) {
      return CURL_READFUNC_ABORT;
    }
    auto [write_ptr, write_len] = pd->ring_buffer->get_write_ptr();
    ssize_t to_read = write_len > size * nmemb ? size * nmemb : write_len;
    if (to_read > 0) {
      try {
        memcpy(ptr, write_ptr, to_read);
        pd->ring_buffer->commit_write(to_read);
        pd->this_size += to_read;
        pd->accumulated_size += to_read;
        pd->progress_cb(false);
        return to_read;
      } catch (const std::exception &e) {
        pd->is_terminate.store(true);
        pd->rcm = ECM{EC::BufferWriteError, e.what()};
        return CURL_READFUNC_ABORT;
      }
    } else if (to_read == 0) {
      return 0;
    } else {
      pd->is_terminate.store(true);
      pd->rcm = ECM{EC::BufferWriteError, "Get Negativate value for data size"};
      return CURL_READFUNC_ABORT;
    }
  }

  inline void SetState(TransferControl state) {
    switch (state) {
    case TransferControl::Running:
      this->pd.is_pause.store(false);
      break;
    case TransferControl::Pause:
      this->pd.is_pause.store(true);
      break;
    case TransferControl::Terminate:
      this->pd.is_terminate.store(true);
      break;
    default:
      break;
    }
  }

  inline TransferControl GetState() {
    if (pd.is_terminate.load()) {
      return TransferControl::Terminate;
    } else if (pd.is_pause.load()) {
      return TransferControl::Pause;
    } else {
      return TransferControl::Running;
    }
  }

  TASKS EraseOverlapTasks(const TASKS &tasks) {
    std::unordered_set<std::string> dst_set{};
    TASKS result{};
    std::string task_id;
    for (auto &task : tasks) {
      task_id = task.src + task.src_host + task.dst + task.dst_host;
      if (dst_set.count(task_id) == 0) {
        dst_set.insert(task_id);
        result.push_back(task);
      }
    }
    return result;
  }

  TASKS transfer(const TASKS &tasks,
                 const std::shared_ptr<ClientMaintainer> &hostm,
                 ssize_t buffer_size = -1) {
    if (tasks.empty()) {
      return {};
    }
    auto tasksf = EraseOverlapTasks(tasks);
    this->pd.reset();
    ECM rcm = ECM{EC::Success, ""};
    std::shared_ptr<BaseClient> src_client = nullptr;
    std::shared_ptr<BaseClient> dst_client = nullptr;
    std::tuple<ECM, std::shared_ptr<BaseClient>, std::shared_ptr<BaseClient>>
        test_res;
    for (auto &task : tasksf) {
      pd.total_size += task.size;
    }

    if (callback.need_total_size_cb) {
      callback.total_size_cb(pd.total_size);
    }

    for (auto &task : tasksf) {
      if (task.IsSuccess) {
        // 跳过在load_tasks中，未设置overlap且dst已经存在的任务
        continue;
      }

      if (pd.is_terminate.load()) {
        task.rc = ECM(EC::Terminate, "Transfer cancelled by user");
        goto check;
      }

      test_res = TestHost(task, hostm);
      rcm = std::get<0>(test_res);

      if (rcm.first != EC::Success) {
        task.rc = rcm;
        goto check;
      }

      src_client = std::get<1>(test_res);
      dst_client = std::get<2>(test_res);
      if (task.path_type == PathType::DIR) {
        task.rc = dst_client->mkdirs(task.dst);
      }
      pd.next_file(task,
                   CalculateBufferSize(src_client, dst_client, buffer_size));
      task.rc = _UnionTransfer(task, src_client, dst_client);
      InnerCallback(true);

    check:
      if (task.rc.first != EC::Success) {
        if (callback.need_error_cb && task.rc.first != EC::Terminate) {
          callback.error_cb(ErrorCBInfo(task.rc, task.src, task.dst,
                                        task.src_host, task.dst_host));
        }
      } else {
        task.IsSuccess = true;
      }
    }
    return tasksf;
  }

  std::pair<ECM, TASKS>
  load_tasks(const std::string &src, const std::string &dst,
             const std::shared_ptr<ClientMaintainer> &hostm,
             const std::string &src_host = "", const std::string &dst_host = "",
             bool overwrite = false, bool mkdir = true,
             bool ignore_sepcial_file = true) {
    WRV result = {};
    TASKS tasks = {};
    ECM rc;
    std::shared_ptr<AMSFTPClient> src_client;
    // 去除src的dst左右端的空格
    if (!src_host.empty()) {
      rc = hostm->test_client(src_host);
      if (rc.first != EC::Success) {
        return {rc, tasks};
      }
    }
    if (!dst_host.empty()) {
      rc = hostm->test_client(dst_host);
      if (rc.first != EC::Success) {
        return {rc, tasks};
      }
    }

    auto [rcm, src_stat] = Ustat(src, hostm, src_host);

    if (rcm.first != EC::Success) {
      return {rcm, tasks};
    }

    std::string srcf = src_stat.path;
    std::string dstf;
    if (dst_host.empty()) {
      dstf = AMFS::abspath(dst);
    } else {
      auto client = hostm->GetHost(dst_host);
      if (!client) {
        return {
            ECM(EC::NoSession,
                fmt::format("Destination SFTP Client: {} not found", dst_host)),
            tasks};
      }
      dstf = dst;
    }

    // 检查是否为 src_file -> dst_file 的传输
    bool is_dst_file = false;
    if (src_stat.type == PathType::FILE) {
      // 检查dst的扩展名和src扩展名是否相同
      std::string dst_ext = AMFS::extname(dstf);
      if (AMFS::extname(srcf) == dst_ext && !dst_ext.empty()) {
        is_dst_file = true;
      }
    }

    if (src_stat.type != PathType::DIR) {
      if (ignore_sepcial_file && src_stat.type != PathType::FILE &&
          src_stat.type != PathType::SYMLINK) {
        return {ECM{EC::NotAFile, fmt::format("Src is not a common file and "
                                              "ignore_sepcial_file is true: {}",
                                              srcf)},
                {}};
      }

      if (!is_dst_file) {
        dstf = AMFS::join(dstf, AMFS::basename(srcf));
      }
      auto [rcm7, dst_info4] = Ustat(dstf, hostm, dst_host);

      // 检验目标路径是否存在
      if (rcm7.first == EC::Success) {
        if (dst_info4.type == PathType::DIR) {
          return {
              ECM(EC::NotADirectory,
                  fmt::format("Dst already exists and is not a directory: {}",
                              dstf)),
              tasks};
        } else if (!overwrite) {
          return {ECM{EC::PathAlreadyExists,
                      fmt::format("Dst already exists: {}", dstf)},
                  tasks};
        }
      }

      // 检测dst的父级目录是否存在
      auto [rcm3, dst_parent_info] =
          Ustat(AMFS::dirname(dstf), hostm, dst_host);
      if (rcm3.first != EC::Success && !mkdir) {
        return {ECM{EC::ParentDirectoryNotExist,
                    fmt::format("Dst parent path not exists: {}",
                                AMFS::dirname(dstf))},
                tasks};
      } else if (dst_parent_info.type != PathType::DIR) {
        return {ECM(EC::NotADirectory,
                    fmt::format("Dst parent path is not a directory: {}",
                                dst_parent_info.path)),
                tasks};
      }

      tasks.emplace_back(srcf, dstf, src_host, dst_host, src_stat.size,
                         src_stat.type);
      return {ECM(EC::Success, ""), tasks};
    }

    auto [rcm2, dst_info] = Ustat(dstf, hostm, dst_host);

    if (rcm2.first != EC::Success && !mkdir) {
      return {ECM{EC::ParentDirectoryNotExist,
                  fmt::format("Dst parent path not exists: {}", dstf)},
              tasks};
    } else if (rcm2.first == EC::Success && dst_info.type != PathType::DIR) {
      return {ECM(EC::NotADirectory,
                  fmt::format("Dst already exists and is not a directory: {}",
                              dstf)),
              tasks};
    }

    auto result2 = Uiwalk(srcf, hostm, src_host, ignore_sepcial_file);

    std::string dst_n;
    for (auto &item : result2) {
      dst_n = AMFS::join(dstf, fs::relative(item.path, AMFS::dirname(srcf)));
      tasks.emplace_back(item.path, dst_n, src_host, dst_host, item.size,
                         item.type);
    }
    return {ECM(EC::Success, ""), tasks};
  };
};
