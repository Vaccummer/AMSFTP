#pragma once
// 标准库
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <pybind11/pytypes.h>
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
inline bool isdir(const LIBSSH2_SFTP_ATTRIBUTES &attrs);
inline bool isreg(const LIBSSH2_SFTP_ATTRIBUTES &attrs);
inline bool IsValidKey(const std::string &key);

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

protected:
  int poll_interval_ms = 20;
  amf ClientInterruptFlag = std::make_shared<InterruptFlag>();
  ClientProtocol PROTOCOL = ClientProtocol::Base;
  ECM state = {EC::NoConnection, "Client Not Initialized"};
  std::mutex state_mtx;
  // NOLINTNEXTLINE
  void SetState(const ECM &state) {
    std::lock_guard<std::mutex> lock(state_mtx);
    this->state = state;
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

  // 对远程服务器move是不能跨文件系统的，本地可以直接move
  // 远程move得用transfer再删除
  ECM move(const std::string &src, const std::string &dst,
           bool need_mkdir = false, bool force_write = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1,
           std::chrono::steady_clock::time_point start_time =
               std::chrono::steady_clock::now()) {

    return rename(src, AMPathStr::join(dst, AMPathStr::basename(src)),
                  need_mkdir, force_write, interrupt_flag, timeout_ms,
                  start_time);
  }

  // 获取某一路径下的所有文件和底层目录的总大小,
  // 但是在读取时遇到错误不会throw，也不会记录其大小，可能存在偏差
  int64_t getsize(const std::string &path, bool ignore_sepcial_file = true,
                  amf interrupt_flag = nullptr, int timeout_ms = -1,
                  std::chrono::steady_clock::time_point start_time =
                      std::chrono::steady_clock::now()) {
    auto [rcm, list] = iwalk(path, ignore_sepcial_file, interrupt_flag,
                             timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return -1;
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return -1;
    }
    uint64_t size = 0;
    for (auto &item : list) {
      size += item.size;
    }
    return size;
  }

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
  virtual SR stat(const std::string &path, bool trace_link = false,
                  amf interrupt_flag = nullptr, int timeout_ms = -1,
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

  virtual ECM copy(const std::string &src, const std::string &dst,
                   bool need_mkdir = false, int timeout_ms = -1,
                   amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: copy", GetProtocolName()));
  }
  virtual std::pair<ECM, WRV>
  iwalk(const std::string &path, bool ignore_sepcial_file = true,
        amf interrupt_flag = nullptr, int timeout_ms = -1,
        std::chrono::steady_clock::time_point start_time =
            std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: iwalk", GetProtocolName()));
  }
  virtual std::pair<ECM, WRD>
  walk(const std::string &path, int max_depth = -1,
       bool ignore_special_file = false, amf interrupt_flag = nullptr,
       int timeout_ms = -1,
       std::chrono::steady_clock::time_point start_time =
           std::chrono::steady_clock::now()) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: walk", GetProtocolName()));
  }
  // NOLINTEND
};
