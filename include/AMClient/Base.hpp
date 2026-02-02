#pragma once
// 标准库
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>

#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// 自身依赖
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/Path.hpp"
// 自身依赖

// 第三方库
#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// #define _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR // in case mutex constructor is
// not
//                                              // supported

#ifdef _WIN32
extern std::atomic<bool> is_wsa_initialized;
inline void cleanup_wsa() {
  // 清理wsa，如果wsa已经初始化，则清理wsa
  if (is_wsa_initialized.load()) {
    WSACleanup();
    is_wsa_initialized.store(false);
  }
}
#endif

inline bool isok(ECM &ecm) { return ecm.first == EC::Success; }
inline bool isdir(const LIBSSH2_SFTP_ATTRIBUTES &attrs);
inline bool isreg(const LIBSSH2_SFTP_ATTRIBUTES &attrs);
inline bool IsValidKey(const std::string &key);

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
using SIZER = std::pair<ECM, size_t>;                 // getsize函数返回类型
using TraceCallback = std::function<void(const TraceInfo &)>;
using CR =
    std::pair<ECM, std::pair<std::string, int>>; // ConductCmd函数返回类型
// Wait result for non-blocking socket operations
inline std::mutex AMlog_mutex;

class AMTracer {
private:
  TraceCallback trace_cb;
  std::list<TraceInfo> buffer = {};
  std::recursive_mutex buffer_mutex;
  ssize_t capacity = 10;
  std::atomic<bool> is_trace_cb = false;
  std::atomic<bool> is_trace_pause = false;
  std::unordered_map<TraceLevel, std::string> trace_level_str = {
      {TraceLevel::Debug, "🐛"},   {TraceLevel::Info, "ℹ️"},
      {TraceLevel::Warning, "⚠️"},  {TraceLevel::Error, "❌"},
      {TraceLevel::Critical, "☠️"},
  };
  void WriteLog(const TraceInfo &trace_info) {
    std::lock_guard<std::mutex> lock(AMlog_mutex);
    std::ofstream file("AMSFTP.log", std::ios::app);
    if (!file.is_open()) {
      return;
    }
    std::string sign;
    if (trace_level_str.find(trace_info.level) != trace_level_str.end()) {
      sign = trace_level_str[trace_info.level];
    } else {
      sign = "ℹ️";
    }
    auto time_now = FormatTime(timenow(), "%Y/%m/%d %H:%M:%S");
    auto out = time_now + " " + sign + " " +
               std::string(magic_enum::enum_name(trace_info.level)) + " " +
               std::string(trace_info.message);
    file << out << std::endl;
  }

protected:
  ConRequst res_data;
  void push(const TraceInfo &value) {
    if (buffer.size() >= static_cast<size_t>(capacity)) {
      buffer.pop_front();
    }
    buffer.push_back(value);
  }
  std::string nickname;

public:
  /** Thread-safe public key/value map for client metadata (lock with
   * public_kv_mtx). */
  std::recursive_mutex public_kv_mtx;
  std::unordered_map<std::string, std::string> public_kv;

  AMTracer(const ConRequst &request, int buffer_capacity = 10,
           TraceCallback trace_cb = {})
      : trace_cb(std::move(trace_cb)), res_data(request),
        nickname(request.nickname) {
    capacity = buffer_capacity > 0 ? buffer_capacity : 10;
    this->is_trace_cb = static_cast<bool>(this->trace_cb);
  }
  size_t GetTraceNum() {
    std::lock_guard<std::recursive_mutex> lock(buffer_mutex);
    return buffer.size();
  }

  std::shared_ptr<TraceInfo> LastTrace() {
    std::lock_guard<std::recursive_mutex> lock(buffer_mutex);
    if (buffer.empty()) {
      return nullptr;
    }
    return std::make_shared<TraceInfo>(buffer.back());
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
    std::lock_guard<std::recursive_mutex> lock(buffer_mutex);
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
      std::lock_guard<std::recursive_mutex> lock(buffer_mutex);
      while (buffer.size() > static_cast<size_t>(size)) {
        buffer.pop_front();
      }
      capacity = size;
      return capacity;
    }
  }

  void trace(TraceLevel level, EC error_code, const std::string &target = "",
             const std::string &action = "", const std::string &msg = "") {
    this->trace(TraceInfo(level, error_code, nickname, target, action, msg));
  }

  void trace(const TraceInfo &trace_info) {
    std::lock_guard<std::recursive_mutex> lock(buffer_mutex);
    if (is_trace_pause.load()) {
      return;
    }
    this->push(trace_info);
    if (is_trace_cb.load()) {
      CallCallbackSafe(trace_cb, trace_info);
    } else {
      this->WriteLog(trace_info);
    }
    this->push(trace_info);
  }

  void SetTraceState(bool is_pause) { is_trace_pause.store(is_pause); }

  void SetTraceCallback(TraceCallback trace = {}) {
    trace_cb = std::move(trace);
    is_trace_cb.store(static_cast<bool>(trace_cb));
  }

  void SetPyTrace(TraceCallback trace = {}) { SetTraceCallback(trace); }

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

  // 发送退出信号（不等待关闭）
  void request_exit() {
    if (!channel) {
      return;
    }
    libssh2_channel_send_eof(channel);
    libssh2_channel_signal(channel, "TERM");
  }

  // 强制终止并关闭（阻塞模式）
  bool terminate_and_close(int wait_ms = 50) {
    if (!channel || closed) {
      return closed;
    }
    libssh2_channel_send_eof(channel);
    libssh2_channel_signal(channel, "TERM");
    std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
    libssh2_channel_signal(channel, "KILL");
    return close();
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
  std::string uid;
  std::recursive_mutex mtx;
  OS_TYPE os_type = OS_TYPE::Uncertain;
  std::string home_dir = "";
  std::string trash_dir = "";
  virtual ~BaseClient() = default;
  BaseClient(const ConRequst &request, int buffer_capacity = 10,
             TraceCallback trace_cb = {})
      : AMTracer(request, buffer_capacity, std::move(trace_cb)),
        BasePathMatch() {
    // 生成一个随机uid
    this->uid = GenerateUID();
  }

  std::string GetUID() { return this->uid; }

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

  std::variant<ECM, std::string> TrashDir(const std::string &trash_dir = "",
                                          amf interrupt_flag = nullptr,
                                          int timeout_ms = -1,
                                          int64_t start_time = -1) {
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
           int64_t start_time = -1) {

    return rename(src, AMPathStr::join(dst, AMPathStr::basename(src)),
                  need_mkdir, force_write, interrupt_flag, timeout_ms,
                  start_time);
  }

  // 获取某一路径下的所有文件和底层目录的总大小,
  // 但是在读取时遇到错误不会throw，也不会记录其大小，可能存在偏差
  virtual int64_t getsize(const std::string &path,
                          bool ignore_sepcial_file = true,
                          amf interrupt_flag = nullptr, int timeout_ms = -1,
                          int64_t start_time = -1) {
    auto [rcm, list] = iwalk(path, ignore_sepcial_file, interrupt_flag,
                             timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return -1;
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return -1;
    }
    size_t size = 0;
    for (auto &item : list) {
      size += item.size;
    }
    return size;
  }

  std::pair<ECM, PathType> get_path_type(const std::string &path,
                                         amf interrupt_flag = nullptr,
                                         int timeout_ms = -1,
                                         int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {ECM{rcm.first, rcm.second}, PathType::Unknown};
    }
    return {rcm, path_info.type};
  }

  // 判断路径是否存在，自带AMFS::abspath
  std::pair<ECM, bool> exists(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first == EC::Success) {
      return {rcm, true};
    } else if (rcm.first == EC::PathNotExist || rcm.first == EC::FileNotExist) {
      return {{EC::Success, ""}, false};
    } else {
      return {rcm, false};
    }
  }

  std::pair<ECM, bool> is_regular(const std::string &path,
                                  amf interrupt_flag = nullptr,
                                  int timeout_ms = -1,
                                  int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::FILE ? true : false};
  }

  std::pair<ECM, bool> is_dir(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::DIR ? true : false};
  }

  std::pair<ECM, bool> is_symlink(const std::string &path,
                                  amf interrupt_flag = nullptr,
                                  int timeout_ms = -1,
                                  int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::SYMLINK ? true : false};
  }

  virtual ECM Check([[maybe_unused]] amf interrupt_flag = nullptr,
                    [[maybe_unused]] int timeout_ms = -1,
                    [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: Check", GetProtocolName()));
  }

  virtual ECM Connect([[maybe_unused]] bool force = false,
                      [[maybe_unused]] amf interrupt_flag = nullptr,
                      [[maybe_unused]] int timeout_ms = -1,
                      [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: Connect", GetProtocolName()));
  }

  virtual OS_TYPE GetOSType([[maybe_unused]] bool update = false) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: GetOSType", GetProtocolName()));
  }

  virtual double GetRTT([[maybe_unused]] ssize_t times = 5,
                        [[maybe_unused]] amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: GetRTT", GetProtocolName()));
  }

  virtual CR ConductCmd([[maybe_unused]] const std::string &cmd,
                        [[maybe_unused]] int max_time_s = -1,
                        [[maybe_unused]] amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: ConductCmd", GetProtocolName()));
  }

  virtual std::string StrUid([[maybe_unused]] const long &uid) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: StrUid", GetProtocolName()));
  }

  virtual std::string GetHomeDir() {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: GetHomeDir", GetProtocolName()));
  }

  virtual std::pair<ECM, std::string>
  realpath([[maybe_unused]] const std::string &path,
           [[maybe_unused]] amf interrupt_flag = nullptr,
           [[maybe_unused]] int timeout_ms = -1,
           [[maybe_unused]] int64_t start_time = -1) {

    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: realpath", GetProtocolName()));
  }
  virtual std::pair<ECM, std::unordered_map<std::string, ECM>>
  chmod([[maybe_unused]] const std::string &path,
        [[maybe_unused]] std::variant<std::string, size_t> mode,
        [[maybe_unused]] bool recursive = false,
        [[maybe_unused]] amf interrupt_flag = nullptr,
        [[maybe_unused]] int timeout_ms = -1,
        [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: chmod", GetProtocolName()));
  }
  SR stat([[maybe_unused]] const std::string &path,
          [[maybe_unused]] bool trace_link = false,
          [[maybe_unused]] amf interrupt_flag = nullptr,
          [[maybe_unused]] int timeout_ms = -1,
          [[maybe_unused]] int64_t start_time = -1) override {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: stat", GetProtocolName()));
  }
  std::pair<ECM, std::vector<PathInfo>>
  listdir([[maybe_unused]] const std::string &path,
          [[maybe_unused]] amf interrupt_flag = nullptr,
          [[maybe_unused]] int timeout_ms = -1,
          [[maybe_unused]] int64_t start_time = -1) override {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: listdir", GetProtocolName()));
  }
  virtual ECM mkdir([[maybe_unused]] const std::string &path,
                    [[maybe_unused]] amf interrupt_flag = nullptr,
                    [[maybe_unused]] int timeout_ms = -1,
                    [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: mkdir", GetProtocolName()));
  }
  virtual ECM mkdirs([[maybe_unused]] const std::string &path,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: mkdirs", GetProtocolName()));
  };

  virtual ECM rmdir([[maybe_unused]] const std::string &path,
                    [[maybe_unused]] amf interrupt_flag = nullptr,
                    [[maybe_unused]] int timeout_ms = -1,
                    [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: rmdir", GetProtocolName()));
  }
  virtual ECM rmfile([[maybe_unused]] const std::string &path,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: rmfile", GetProtocolName()));
  }
  virtual ECM rename([[maybe_unused]] const std::string &src,
                     [[maybe_unused]] const std::string &dst,
                     [[maybe_unused]] bool mkdir = true,
                     [[maybe_unused]] bool overwrite = false,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: rename", GetProtocolName()));
  }

  virtual std::pair<ECM, RMR>
  remove([[maybe_unused]] const std::string &path,
         [[maybe_unused]] amf interrupt_flag = nullptr,
         [[maybe_unused]] int timeout_ms = -1,
         [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: remove", GetProtocolName()));
  };
  virtual ECM saferm([[maybe_unused]] const std::string &path,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: saferm", GetProtocolName()));
  }

  virtual ECM copy([[maybe_unused]] const std::string &src,
                   [[maybe_unused]] const std::string &dst,
                   [[maybe_unused]] bool need_mkdir = false,
                   [[maybe_unused]] int timeout_ms = -1,
                   [[maybe_unused]] amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: copy", GetProtocolName()));
  }

  std::pair<ECM, std::vector<PathInfo>>
  iwalk([[maybe_unused]] const std::string &path,
        [[maybe_unused]] bool ignore_special_file = true,
        [[maybe_unused]] amf interrupt_flag = nullptr,
        [[maybe_unused]] int timeout_ms = -1,
        [[maybe_unused]] int64_t start_time = -1) override {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: iwalk", GetProtocolName()));
  }

  virtual std::pair<ECM, WRD>
  walk([[maybe_unused]] const std::string &path,
       [[maybe_unused]] int max_depth = -1,
       [[maybe_unused]] bool ignore_special_file = false,
       [[maybe_unused]] amf interrupt_flag = nullptr,
       [[maybe_unused]] int timeout_ms = -1,
       [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::amfmt(
        "{} Client doesn't implement funtion: walk", GetProtocolName()));
  }
};
