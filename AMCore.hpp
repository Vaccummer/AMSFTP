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
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
// 标准库

#define AMForceUsingUnixSep
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
using PathInfo = AMFS::PathInfo;
using PathType = AMFS::PathType;
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
    std::pair<ECM, std::pair<std::string, int>>; // ConductCmd函数返回类型

class AMTracer {
private:
  py::function trace_cb;
  std::vector<TraceInfo> buffer = {};
  std::mutex buffer_mutex;
  int capacity = 10;
  std::atomic<bool> is_py_trace = false;
  std::atomic<bool> is_trace_pause = false;
  std::unordered_map<std::string, py::object> public_var_dict;
  std::mutex public_var_mutex; // 专门用于保护 public_var_dict 的锁
  py::object deepcopy_func;    // 缓存的 deepcopy 函数
protected:
  ConRequst res_data;
  void push(const TraceInfo &value) {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    if (buffer.size() < capacity) {
      buffer.push_back(value);
    } else {
      buffer.erase(buffer.begin());
      buffer.push_back(value);
    }
  }
  std::string nickname;

public:
  AMTracer(ConRequst request, int buffer_capacity = 10,
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
            "Deepcopy Function", "Initialize", "Failed to import copy module");
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
        } catch (const py::error_already_set &e) {
          // 深拷贝失败，使用原始引用
          continue;
        }
      }
    }
    return result;
  }

  int GetTraceNum() {
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

  int TracerCapacity(int size = -1) {
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

  void trace(const TraceLevel &level, const EC &error_code,
             const std::string &target = "", const std::string &action = "",
             const std::string &msg = "") {
    TraceInfo trace_info(level, error_code, nickname, target, action, msg);
    this->trace(trace_info);
  }

  void trace(const TraceInfo &trace_info) {
    if (is_trace_pause.load()) {
      return;
    }
    this->push(trace_info);
    if (is_py_trace.load()) {
      py::gil_scoped_acquire acquire;
      trace_cb(trace_info);
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
  ~SafeChannel() {
    if (channel) {
      libssh2_channel_close(channel);
      libssh2_channel_free(channel);
    }
  }

  SafeChannel(LIBSSH2_SESSION *session) {
    this->channel =
        libssh2_channel_open_ex(session, "session", sizeof("session") - 1,
                                4 * AMMB, 32 * AMKB, nullptr, 0);
  }
};

class BaseClient : public AMTracer, public AMFS::BasePathMatch {
private:
  ssize_t buffer_size = AMMB * 8;

protected:
  std::atomic<bool> terminate_cmd = false;
  ClientProtocol PROTOCOL = ClientProtocol::Base;
  virtual void SetState(const ECM &state) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: SetState", GetProtocolName()));
  }

public:
  OS_TYPE os_type = OS_TYPE::Uncertain;
  std::string home_dir = "";
  std::string trash_dir = "";

  // std::lock_guard<std::recursive_mutex> lock(mtx);
  ClientProtocol GetProtocol() { return PROTOCOL; }

  ssize_t TransferRingBufferSize(ssize_t buffer_size = -1) {
    if (buffer_size < 0) {
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
    default:
      return "Unknown";
    }
  }
  BaseClient(ConRequst request, size_t buffer_capacity = 10,
             const py::object &trace_cb = py::none())
      : AMTracer(request, buffer_capacity, trace_cb), AMFS::BasePathMatch() {}
  virtual ECM GetState() {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: GetState", GetProtocolName()));
  };
  virtual ECM Check(bool need_trace = false) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: Check", GetProtocolName()));
  }
  virtual ECM Connect(bool force = false) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: Connect", GetProtocolName()));
  }

  virtual OS_TYPE GetOSType(bool update = false) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: GetOSType", GetProtocolName()));
  }

  virtual double GetRTT(size_t times = 5) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: GetRTT", GetProtocolName()));
  }

  virtual CR ConductCmd(const std::string &cmd, int max_time_s = -1) {
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
  virtual inline std::string GetTrashDir() {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: GetTrashDir", GetProtocolName()));
  }
  virtual ECM SetTrashDir(const std::string &trash_dir) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: SetTrashDir", GetProtocolName()));
  }
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
  virtual std::pair<ECM, std::string> realpath(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: realpath", GetProtocolName()));
  }
  virtual std::variant<std::unordered_map<std::string, ECM>, ECM>
  chmod(const std::string &path, std::variant<std::string, uint64_t> mode,
        bool recursive = false) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: chmod", GetProtocolName()));
  }
  virtual SR stat(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: stat", GetProtocolName()));
  }
  virtual std::pair<ECM, PathType> get_path_type(const std::string &path) {
    throw UnimplementedMethodException(
        fmt::format("{} Client doesn't implement funtion: get_path_type",
                    GetProtocolName()));
  }
  virtual std::pair<ECM, bool> exists(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: exists", GetProtocolName()));
  }
  virtual std::pair<ECM, bool> is_regular(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: is_regular", GetProtocolName()));
  }
  virtual std::pair<ECM, bool> is_dir(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: is_dir", GetProtocolName()));
  }
  virtual std::pair<ECM, bool> is_symlink(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: is_symlink", GetProtocolName()));
  }
  virtual std::pair<ECM, std::vector<PathInfo>> listdir(const std::string &path,
                                                        int max_time_ms = -1) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: listdir", GetProtocolName()));
  }
  virtual ECM mkdir(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: mkdir", GetProtocolName()));
  }
  virtual ECM mkdirs(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: mkdirs", GetProtocolName()));
  };
  virtual ECM rmdir(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: rmdir", GetProtocolName()));
  }
  virtual ECM rmfile(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: rmfile", GetProtocolName()));
  }
  virtual ECM rename(const std::string &src, const std::string &dst,
                     bool overwrite = false) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: rename", GetProtocolName()));
  }
  virtual std::variant<RMR, ECM> remove(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: remove", GetProtocolName()));
  };
  virtual ECM saferm(const std::string &path) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: saferm", GetProtocolName()));
  }
  virtual ECM move(const std::string &src, const std::string &dst,
                   bool need_mkdir = false, bool force_write = false) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: move", GetProtocolName()));
  }
  virtual ECM virtual copy(const std::string &src, const std::string &dst,
                           bool need_mkdir = false) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: copy", GetProtocolName()));
  }
  virtual WRV iwalk(const std::string &path, bool ignore_sepcial_file = true) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: iwalk", GetProtocolName()));
  }
  virtual std::pair<ECM, WRD> walk(const std::string &path, int max_depth = -1,
                                   bool ignore_sepcial_file = true) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: walk", GetProtocolName()));
  }
  virtual uint64_t getsize(const std::string &path,
                           bool ignore_sepcial_file = true) {
    throw UnimplementedMethodException(fmt::format(
        "{} Client doesn't implement funtion: getsize", GetProtocolName()));
  }

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
  std::atomic<bool> has_connected;
  void SetState(const ECM &state) override {
    std::lock_guard<std::mutex> lock(state_mtx);
    CurError = state;
  }

private:
  ECM CurError = {EC::NoConnection, "Connection not established"};
  std::mutex state_mtx;
  SOCKET sock = INVALID_SOCKET;
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

  ~AMSession() { Disconnect(); }

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

  auto GetLibssh2Version() { return libssh2_version(LIBSSH2_VERSION_NUM); }

  bool IsValidKey(const std::string &key) {
    std::ifstream file(key);
    if (!file.is_open())
      return false;

    std::string line;
    std::getline(file, line);

    // 匹配所有SSH私钥的标准开头标记
    const std::vector<std::string> private_key_headers = {
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----"};
    for (const auto &header : private_key_headers) {
      if (line.find(header) == 0) { // 开头匹配
        return true;
      }
    }
    return false;
  }

  std::vector<std::string> GetKeys() { return this->private_keys; }

  void SetKeys(const std::vector<std::string> &keys) {
    this->private_keys = keys;
  }

  ECM GetState() override {
    std::lock_guard<std::mutex> lock(state_mtx);
    return CurError;
  }

  ECM BaseCheck() {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    if (!session) {
      return {EC::NoSession, "Session not initialized"};
    }

    char path_t[1024];
    int rcr;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_realpath(sftp, ".", path_t, sizeof(path_t));
    }
    if (rcr < 0) {
      EC rc = GetLastEC();
      return std::make_pair(rc, "Sftp status check failed");
    }

    return {EC::Success, ""};
  }

  ECM BaseConnect(bool force = false) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (has_connected.load()) {
      if (!force) {
        return GetState();
      }
      Disconnect();
      has_connected.store(false);
    }

    std::string msg = "";
    EC rc = EC::Success;
    int rcr;

    // 使用SocketConnector建立连接
    SocketConnector connector;

    if (!connector.Connect(res_data.hostname, res_data.port,
                           res_data.timeout_s)) {
      trace(TraceLevel::Critical, connector.error_code,
            fmt::format("{}", connector.sock), "SocketConnector.Connect",
            connector.error_msg);
      return {connector.error_code, connector.error_msg};
    }
    sock = connector.sock;

    session = libssh2_session_init();
    if (!session) {
      trace(TraceLevel::Critical, EC::SessionCreateFailed, "",
            "libssh2_session_init", "Session initialization failed");
      return {EC::SessionCreateFailed, "Libssh2 Session initialization failed"};
    }

    libssh2_session_set_blocking(session, 1);

    if (res_data.compression) {
      libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
      libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS,
                                  "zlib@openssh.com,zlib,none");
    }

    rcr = libssh2_session_handshake(session, sock);

    if (rcr != 0) {
      msg = fmt::format("Session handshake failed: {}", GetLastErrorMsg());
      rc = GetLastEC();
      trace(TraceLevel::Critical, rc,
            fmt::format("session_code:{}, socket:{}", rcr, sock),
            "libssh2_session_handshake", msg);
      return {rc, msg};
    }

    const char *auth_list = libssh2_userauth_list(
        session, res_data.username.c_str(), res_data.username.length());

    if (auth_list == nullptr) {
      msg = fmt::format("Fail to negotiate authentication method: {}",
                        GetLastErrorMsg());
      rc = GetLastEC();
      trace(TraceLevel::Critical, rc, res_data.nickname, "GetAuthList", msg);
      return {rc, msg};
    }

    trace(TraceLevel::Debug, EC::Success, res_data.username,
          "libssh2_userauth_list",
          fmt::format("Authentication methods: {}", auth_list));

    bool password_auth = false;
    if (strstr(auth_list, "password") != nullptr) {
      password_auth = true;
    }

    rc = EC::AuthFailed;

    std::string password_tmp;
    if (!res_data.keyfile.empty()) {
      trace(TraceLevel::Debug, EC::Success, "PrivateKey", "Authorize",
            fmt::format("Using dedicated private key: {}", res_data.keyfile));
      rcr = libssh2_userauth_publickey_fromfile(
          session, res_data.username.c_str(), nullptr, res_data.keyfile.c_str(),
          nullptr);
      if (rcr == 0) {
        rc = EC::Success;
        msg = "";
        trace(TraceLevel::Info, EC::Success, "Success",
              "PrivatedKeyAuthorizeResult",
              fmt::format("Dedicated private key \"{}\" authorize success",
                          res_data.keyfile));
        goto OK;
      } else {
        msg = fmt::format("Dedicated private key \"{}\" authorize failed: {}",
                          res_data.keyfile, GetLastErrorMsg());
        rc = GetLastEC();
        trace(TraceLevel::Debug, rc, "Failed", "PrivatedKeyAuthorizeResult",
              msg);
      }
    }
    if (!res_data.password.empty() && password_auth) {
      trace(TraceLevel::Debug, EC::Success, res_data.password,
            "PasswordAuthorize",
            fmt::format("Using  password to authorize: {}", res_data.password));
      rcr = libssh2_userauth_password(session, res_data.username.c_str(),
                                      res_data.password.c_str());
      if (rcr == 0) {
        rc = EC::Success;
        msg = "";
        trace(TraceLevel::Info, EC::Success, "Success",
              "PasswordAuthorizeResult", "Password authorize success");
        goto OK;
      } else {
        rc = EC::AuthFailed;
        trace(TraceLevel::Debug, EC::AuthFailed, "Failed",
              "PasswordAuthorizeResult",
              fmt::format("Wrong Password: {}", res_data.password));
      }
    }
    if (!private_keys.empty()) {
      trace(TraceLevel::Debug, EC::Success, "SharedPrivateKey", "Authorize",
            fmt::format("Using shared private keys to authorize"));
      for (auto private_key : private_keys) {
        if (private_key == res_data.keyfile) {
          continue;
        }

        rcr = libssh2_userauth_publickey_fromfile(
            session, res_data.username.c_str(), nullptr, private_key.c_str(),
            nullptr);
        if (rcr == 0) {
          msg = fmt::format("Shared private key \"{}\" authorize success",
                            private_key);
          trace(TraceLevel::Info, EC::Success, "Success",
                "PrivatedKeyAuthorizeResult", msg);
          rc = EC::Success;
          goto OK;
        } else {
          msg = fmt::format("Shared private key \"{}\" authorize failed",
                            private_key);
          trace(TraceLevel::Debug, EC::PrivateKeyAuthFailed, "Failed",
                "PrivatedKeyAuthorizeResult", msg);
        }
      }
    }

    if (password_auth_cb && password_auth) {
      trace(TraceLevel::Debug, EC::Success, "Interactive", "PasswordAuthorize",
            "Using password authentication callback to get another password");
      int trial_times = 0;
      while (trial_times < 2) {
        {
          py::gil_scoped_acquire acquire;
          password_tmp = py::cast<std::string>(
              auth_cb(AuthCBInfo(true, res_data, trial_times)));
        }
        if (password_tmp.empty()) {
          break;
        }
        rcr = libssh2_userauth_password(session, res_data.username.c_str(),
                                        password_tmp.c_str());
        trial_times++;
        if (rcr == 0) {
          rc = EC::Success;
          msg = "";
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

  OK:
    if (rc != EC::Success) {
      trace(TraceLevel::Critical, EC::AuthFailed, "Failed",
            "FinalAuthorizeState", "All authorize methods failed");
      return {rc, "All authorize methods failed"};
    }

    sftp = libssh2_sftp_init(session);
    if (!sftp) {
      rc = GetLastEC();
      msg = fmt::format("SFTP initialization failed: {}", GetLastErrorMsg());
      trace(TraceLevel::Critical, rc, "Failed", "libssh2_sftp_init", msg);
      Disconnect();
      return {rc, msg};
    }

    has_connected.store(true);
    return {EC::Success, ""};
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
      return std::string(errmsg);
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

  PathInfo FormatStat(const std::string &path, LIBSSH2_SFTP_ATTRIBUTES &attrs) {
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
      info.mode_str = AMFS::Str::ModeTrans(info.mode_int);
    }

    return info;
  }

  // 无任何检查的stat， 只是封装了返回值格式化和错误格式化
  SR lib_stat(const std::string &path) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, PathInfo()};
    }

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    EC rc;
    std::string msg = "";
    int rct;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rct = libssh2_sftp_stat(sftp, path.c_str(), &attrs);
    }

    if (rct != 0) {
      rc = GetLastEC();
      msg = fmt::format("stat {} failed: {}", path, GetLastErrorMsg());
      trace(TraceLevel::Error, rc,
            fmt::format("{}@{}", res_data.nickname, path), "stat", msg);
      return {ECM{rc, msg}, PathInfo()};
    }

    return {ECM{EC::Success, ""}, FormatStat(path, attrs)};
  }

  ECM lib_rmfile(const std::string &path) {
    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }

    int rcr;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_unlink(sftp, path.c_str());
    }

    if (rcr != 0) {
      EC rc = GetLastEC();
      std::string msg_tmp = GetLastErrorMsg();
      std::string msg =
          fmt::format("Path: {} rmfile failed: {}", path, msg_tmp);
      trace(TraceLevel::Error, rc,
            fmt::format("{}@{}", res_data.nickname, path), "Rmfile", msg_tmp);
      return {rc, msg};
    }
    trace(TraceLevel::Warning, EC::Success,
          fmt::format("{}@{}", res_data.nickname, path), "Rmfile",
          fmt::format("Permanently remove file: {}", path));
    return {EC::Success, ""};
  }

  ECM lib_rename(const std::string &src, const std::string &dst,
                 const bool &overwrite) {
    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }

    int rcr;
    if (!overwrite) {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_rename_ex(sftp, src.c_str(), src.size(), dst.c_str(),
                                   dst.size(), LIBSSH2_SFTP_RENAME_NATIVE);
    } else {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_rename_ex(
          sftp, src.c_str(), src.size(), dst.c_str(), dst.size(),
          LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_NATIVE);
    }
    if (rcr != 0) {
      EC rc = GetLastEC();
      std::string msg = GetLastErrorMsg();
      return {rc, fmt::format("Rename {} to {} failed: {}", src, dst, msg)};
    }
    return {EC::Success, ""};
  }

  void _iwalk(const std::string &path, WRV &result,
              bool ignore_sepcial_file = true) {
    // 搜索目录下所有最深层的路径, 用于递归传输路径
    auto [rcm, info_path] = stat(path);
    if (rcm.first != EC::Success) {
      return;
    }

    if (info_path.type != PathType::DIR) {
      // 非目录直接加入
      result.push_back(info_path);
      return;
    }

    auto [rcm2, list_info] = listdir(path);
    if (rcm2.first != EC::Success) {
      return;
    }

    if (list_info.empty()) {
      // 末级空目录直接加入
      result.push_back(info_path);
      return;
    }
    for (auto &info : list_info) {
      _iwalk(info.path, result, ignore_sepcial_file);
    }
  }

  void _walk(const std::vector<std::string> &parts, WRD &result,
             int cur_depth = 0, int max_depth = -1,
             bool ignore_sepcial_file = true) {
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
        _walk(new_parts, result, cur_depth + 1, max_depth, ignore_sepcial_file);
      } else {
        if (ignore_sepcial_file && static_cast<int>(info.type) < 0) {
          continue;
        }
        files_info.push_back(info);
      }
    }
    if (list_info.empty()) {
      return;
    }
    result.emplace_back(parts, files_info);
  }

  void _GetSize(const std::string &path, uint64_t &size,
                bool ignore_sepcial_file = true) {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return;
    }

    switch (path_info.type) {
    case PathType::FILE:
      size += path_info.size;
      return;
    case PathType::SYMLINK:
      return;
    case PathType::DIR:
      break;
    default:
      if (ignore_sepcial_file && static_cast<int>(path_info.type) < 0) {
        return;
      } else {
        size += path_info.size;
      }
    }

    auto [rcm2, list_info] = listdir(path);

    if (rcm2.first != EC::Success) {
      return;
    }

    for (auto &item : list_info) {
      _GetSize(item.path, size);
    }
  }

  void _rm(const std::string &path, RMR &errors) {
    auto [rcm, br] = is_dir(path);
    if (rcm.first != EC::Success) {
      errors.push_back(std::make_pair(path, rcm));
      return;
    }

    if (!br) {
      ECM ecm = lib_rmfile(path);
      if (ecm.first != EC::Success) {
        errors.push_back(std::make_pair(path, ecm));
      }
      return;
    }

    auto [rcm2, file_list] = listdir(path);
    if (rcm2.first != EC::Success) {
      errors.push_back(std::make_pair(path, rcm));
      return;
    }

    for (auto &file : file_list) {
      _rm(file.path, errors);
    }

    ECM ecm = rmdir(path);
    if (ecm.first != EC::Success) {
      errors.push_back(std::make_pair(path, ecm));
    }
  }

  void _chmod(const std::string &path, const std::string &mode, bool recursive,
              std::unordered_map<std::string, ECM> &errors) {
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    EC rc;
    std::string msg = "";

    int rct;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rct = libssh2_sftp_stat(sftp, path.c_str(), &attrs);
    }

    if (rct != 0) {
      rc = GetLastEC();
      msg = fmt::format("stat {} failed: {}", path, GetLastErrorMsg());
      errors[path] = {rc, msg};
      return;
    }
    if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      msg = fmt::format("stat {} does not have permission attribute", path);
      errors[path] = {EC::NoPermissionAttribute, msg};
      return;
    }

    std::string new_mode = AMFS::Str::MergeModeStr(
        AMFS::Str::ModeTrans(attrs.permissions & 0777), mode);

    uint64_t new_mode_int = AMFS::Str::ModeTrans(new_mode);

    uint64_t file_type = attrs.permissions & LIBSSH2_SFTP_S_IFMT;
    new_mode_int = (new_mode_int & ~LIBSSH2_SFTP_S_IFMT) | file_type;

    attrs.permissions = new_mode_int;
    attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;

    int rcr;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_setstat(sftp, path.c_str(), &attrs);
    }

    if (rcr != 0) {
      rc = GetLastEC();
      msg = fmt::format("chmod {} failed: {}", path, GetLastErrorMsg());
      errors[path] = {rc, msg};
    }

    if (recursive && file_type == LIBSSH2_SFTP_S_IFDIR) {
      auto [rcm, list] = listdir(path);
      if (rcm.first != EC::Success) {
        errors[path] = rcm;
        return;
      }
      for (auto &item : list) {
        _chmod(item.path, mode, recursive, errors);
      }
    }
  }

  void _chmod(const std::string &path, const uint64_t &mode, bool recursive,
              std::unordered_map<std::string, ECM> &errors) {
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    EC rc;
    std::string msg = "";

    int rct;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rct = libssh2_sftp_stat(sftp, path.c_str(), &attrs);
    }

    if (rct != 0) {
      rc = GetLastEC();
      msg = fmt::format("stat {} failed: {}", path, GetLastErrorMsg());
      errors[path] = {rc, msg};
      return;
    }

    if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      msg = fmt::format("stat {} does not have permission attribute", path);
      errors[path] = {EC::NoPermissionAttribute, msg};
      return;
    }

    uint64_t file_type = attrs.permissions & LIBSSH2_SFTP_S_IFMT;
    uint64_t new_mode_int = (mode & ~LIBSSH2_SFTP_S_IFMT) | file_type;

    attrs.permissions = new_mode_int;
    attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;

    int rcr;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_setstat(sftp, path.c_str(), &attrs);
    }

    if (rcr != 0) {
      rc = GetLastEC();
      msg = fmt::format("chmod {} failed: {}", path, GetLastErrorMsg());
      errors[path] = {rc, msg};
    }

    if (recursive && file_type == LIBSSH2_SFTP_S_IFDIR) {
      auto [rcm, list] = listdir(path);
      if (rcm.first != EC::Success) {
        errors[path] = rcm;
        return;
      }
      for (auto &item : list) {
        _chmod(item.path, mode, recursive, errors);
      }
    }
  }

  // 用于AMFS::BasePathMatch
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
      return std::vector<PathInfo>();
    }
    return sr;
  }
  std::vector<PathInfo> iiwalk(const std::string &path) override {
    return iwalk(path);
  }

public:
  ~AMSFTPClient() {}
  double GetRTT(size_t times = 5) override {
    double total_time = 0;
    double time_start;
    double time_end;
    int rc;
    for (size_t i = 0; i < times; i++) {
      SafeChannel channel(session);
      time_start = timenow();
      rc = libssh2_channel_exec(channel.channel, "echo amsftp");
      if (rc != 0) {
        return -1;
      }
      time_end = timenow();
      total_time += (time_end - time_start);
    }
    return total_time / times;
  }

  void TerminateCmd() { terminate_cmd.store(true); }

  CR ConductCmd(const std::string &cmd, int max_time_s = -1) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    terminate_cmd.store(false);
    bool time_out = false;
    SafeChannel sf(session);
    if (!sf.channel) {
      return {ECM{EC::NoConnection, "Channel not initialized"},
              std::pair<std::string, int>("", -1)};
    }
    double time_start = timenow();
    int out;
    {
      // 设置不阻塞
      libssh2_session_set_blocking(session, 0);
      while (true) {
        out = libssh2_channel_exec(sf.channel, cmd.c_str());
        if (out != LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        if (max_time_s > 0 && timenow() - time_start > max_time_s) {
          time_out = true;

          break;
        }
        if (terminate_cmd) {
          terminate_cmd.store(true);
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }

    if (terminate_cmd.load()) {
      libssh2_session_set_blocking(session, 1);
      return {ECM{EC::Terminate, "Command terminated"},
              std::pair<std::string, int>("", -1)};
    } else if (time_out) {
      libssh2_session_set_blocking(session, 1);
      return {ECM{EC::OperationTimeout, "Command timed out"},
              std::pair<std::string, int>("", -1)};
    }

    EC error_code;
    std::string error_msg;
    if (out < 0) {
      error_code = GetLastEC();
      error_msg = fmt::format("{} Host channel operation failed: {}",
                              res_data.nickname, GetLastErrorMsg());
      return {ECM{error_code, error_msg}, std::pair<std::string, int>("", -1)};
    }

    std::string output;
    std::array<char, 4096> cmd_out;
    bool output_time_out = false;
    while (true) {
      int nbytes = -1;
      {
        nbytes = libssh2_channel_read(sf.channel, cmd_out.data(),
                                      sizeof(cmd_out) - 1);
      }

      if (nbytes < 0) {
        if (libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
          // 读取超时检查
          if (max_time_s > 0 && timenow() - time_start > max_time_s) {
            output_time_out = true;
            break;
          }
          if (terminate_cmd.load()) {
            break;
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
          continue;
        }
        EC error_code = GetLastEC();
        std::string error_msg =
            fmt::format("{} Host channel output read failed: {}",
                        res_data.nickname, GetLastErrorMsg());
        libssh2_session_set_blocking(session, 1);
        return {ECM{error_code, error_msg}, std::make_pair(std::string(), -1)};
      }
      if (nbytes == 0) {
        break; // 输出读取完成
      }
      output.append(cmd_out.data(), nbytes);
    }
    libssh2_session_set_blocking(session, 1);
    // 读取过程中检查终止信号
    if (terminate_cmd.load()) {
      return {ECM{EC::Terminate, "Command terminated"},
              std::make_pair(output, -1)};
    }

    if (output_time_out) {
      return {ECM{EC::OperationTimeout, "Output read timed out"},
              std::make_pair(output, -1)};
    }

    // 7. 获取退出状态并清理资源
    int exit_status = libssh2_channel_get_exit_status(sf.channel);

    // 8. 清理输出的末尾空白字符
    output.erase(std::find_if(output.rbegin(), output.rend(),
                              [](char c) { return c != '\n' && c != '\r'; })
                     .base(),
                 output.end());

    return {ECM{EC::Success, ""}, std::make_pair(output, exit_status)};
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

  AMSFTPClient(const ConRequst &request, const std::vector<std::string> &keys,
               unsigned int tracer_capacity = 10,
               const py::object &trace_cb = py::none(),
               const py::object &auth_cb = py::none())
      : AMSession(request, keys, tracer_capacity, trace_cb, auth_cb) {
    this->PROTOCOL = ClientProtocol::SFTP;
    if (request.trash_dir.empty()) {
      this->trash_dir = AMFS::join(GetHomeDir(), ".AMSFTP_Trash");
    } else {
      this->trash_dir =
          AMFS::abspath(request.trash_dir, true, GetHomeDir(), GetHomeDir());
    }
    if (this->trash_dir.empty()) {
      this->trash_dir = AMFS::join(GetHomeDir(), ".AMSFTP_Trash");
    }
  }

  std::string StrUid(const long &uid) override {
    if (user_id_map.find(uid) != user_id_map.end()) {
      return user_id_map[uid];
    }

    std::string cmd = fmt::format("id -un {}", uid);
    auto [rcm, cr] = ConductCmd(cmd);
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
    auto [rcm, path_obj] = realpath("");
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

  ECM Check(bool need_trace = false) override {
    ECM rc = BaseCheck();
    SetState(rc);
    if (!need_trace) {
      return rc;
    }
    if (rc.first != EC::Success) {
      trace(TraceLevel::Critical, rc.first, "home_path", "Check",
            "Sftp status check failed");
    } else {
      trace(TraceLevel::Info, EC::Success, "Connection Status", "Check",
            "Session status check success");
    }
    return rc;
  }

  ECM Connect(bool force = false) override {
    bool not_init = has_connected;
    ECM ecm = BaseConnect(force);
    if (!not_init && isok(ecm)) {
      GetOSType();
      GetHomeDir();
    }
    return ecm;
  }

  inline std::string GetTrashDir() override { return this->trash_dir; }

  ECM SetTrashDir(const std::string &trash_dir = "") override {
    auto pathf = AMFS::abspath(trash_dir, true, GetHomeDir(), GetHomeDir());
    if (pathf.empty()) {
      return {EC::InvalidArg, fmt::format("Invalid path: {}", trash_dir)};
    }
    ECM rcm = mkdirs(pathf);
    if (rcm.first == EC::Success) {
      this->trash_dir = pathf;
    }
    return rcm;
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
        trace(TraceLevel::Error, EC::UnknownError,
              fmt::format("{}@{}", res_data.nickname, "TrashDir"),
              "EnsureTrashDir",
              "Can't automatically find a available trash directory");
        return {EC::UnknownError,
                "Can't automatically find a available trash directory"};
      }
      trace(TraceLevel::Info, EC::Success,
            fmt::format("{}@{}", res_data.nickname, "TrashDir"),
            "EnsureTrashDir",
            fmt::format("Set trash_dir to: \"{}\"", trash_dir));
    }
    return {EC::Success, ""};
  }
  // 解析并返回绝对路径,
  // ~在client中解析，..和.其他由服务器解析，有这些符号时需要路径真实存在
  std::pair<ECM, std::string> realpath(const std::string &path) override {
    std::string pathf = path;
    if (std::regex_search(path, std::regex("^~[\\\\/]"))) {
      // 解析~符号
      pathf = AMFS::join(GetHomeDir(), pathf.substr(1), AMFS::SepType::Unix);
    } else if (pathf == "~") {
      return {ECM{EC::Success, ""}, GetHomeDir()};
    }
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, ""};
    }
    std::array<char, 1024> path_t;
    int rcr;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_realpath(sftp, pathf.c_str(), path_t.data(),
                                  sizeof(path_t));
    }
    if (rcr < 0) {
      EC rc = GetLastEC();
      std::string msg =
          fmt::format("realpath {} failed: {}", pathf, GetLastErrorMsg());
      trace(TraceLevel::Error, rc,
            fmt::format("{}@{}", res_data.nickname, pathf), "Realpath", msg);
      return {ECM{rc, msg}, ""};
    } else {
      if (GetOSType() == OS_TYPE::Windows) {
        // windows server返回的路径会在前面加个/或\，需要去掉
        return {ECM{EC::Success, ""}, std::string(path_t.data()).substr(1)};
      }
      return {ECM{EC::Success, ""}, std::string(path_t.data())};
    }
  }

  std::variant<std::unordered_map<std::string, ECM>, ECM>
  chmod(const std::string &path, std::variant<std::string, uint64_t> mode,
        bool recursive = false) override {
    if (static_cast<int>(GetOSType()) <= 0) {
      return ECM{EC::UnImplentedMethod, "Chmod only supported on Unix System"};
    }
    auto pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());

    auto [rcm, br] = exists(pathf);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (!br) {
      return ECM{EC::PathNotExist,
                 fmt::format("Path does not exist: {}", pathf)};
    }
    std::unordered_map<std::string, ECM> ecm_map{};

    if (std::holds_alternative<std::string>(mode)) {
      if (!AMFS::Str::IsModeValid(std::get<std::string>(mode))) {
        return ECM{EC::InvalidArg, fmt::format("Invalid mode: {}",
                                               std::get<std::string>(mode))};
      }
      _chmod(path, std::get<std::string>(mode), recursive, ecm_map);
    } else if (std::holds_alternative<uint64_t>(mode)) {
      if (!AMFS::Str::IsModeValid(std::get<uint64_t>(mode))) {
        return ECM{EC::InvalidArg,
                   fmt::format("Invalid mode: {}", std::get<uint64_t>(mode))};
      }
      _chmod(path, std::get<uint64_t>(mode), recursive, ecm_map);
    } else {
      return ECM{EC::InvalidArg, fmt::format("Invalid mode data type")};
    }
    return ecm_map;
  }

  // 获取路径信息，自带AMFS::abspath
  SR stat(const std::string &path) override {
    std::string pathf = AMFS::abspath(path, true, GetHomeDir());

    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)},
              PathInfo()};
    }

    return lib_stat(pathf);
  }

  std::pair<ECM, PathType> get_path_type(const std::string &path) override {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {ECM{rcm.first, rcm.second}, PathType::Unknown};
    }
    return {rcm, path_info.type};
  }

  // 判断路径是否存在，自带AMFS::abspath
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

  std::pair<ECM, bool> is_regular(const std::string &path) override {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::FILE ? true : false};
  }

  std::pair<ECM, bool> is_dir(const std::string &path) override {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::DIR ? true : false};
  }

  std::pair<ECM, bool> is_symlink(const std::string &path) override {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::SYMLINK ? true : false};
  }

  std::pair<ECM, std::vector<PathInfo>> listdir(const std::string &path,
                                                int max_time_ms = -1) override {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, {}};
    }

    auto pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)}, {}};
    }

    std::string msg = "";
    std::vector<PathInfo> file_list = {};
    auto [rcm, br] = is_dir(path);
    if (rcm.first != EC::Success) {
      return {rcm, file_list};
    } else if (!br) {
      return {ECM{EC::NotADirectory,
                  fmt::format("Path is not a directory: {}", pathf)},
              file_list};
    }

    double start_time = timenow();
    double end_time = start_time;
    double max_time = max_time_ms / 1000.0;
    bool is_truncated = false;

    LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    std::string name;
    std::string path_i;
    const size_t buffer_size = 4096;
    std::vector<char> filename_buffer(buffer_size);
    EC rc;
    int rct;
    PathInfo info;
    bool is_sucess = false;

    std::lock_guard<std::recursive_mutex> lock(mtx);
    sftp_handle = libssh2_sftp_open_ex(sftp, pathf.c_str(), pathf.size(), 0,
                                       LIBSSH2_SFTP_OPENDIR, LIBSSH2_FXF_READ);

    if (!sftp_handle) {
      std::string tmp_msg = GetLastErrorMsg();
      trace(TraceLevel::Error, EC::InvalidHandle,
            fmt::format("{}@{}", res_data.nickname, path), "ListDir", tmp_msg);
      msg = fmt::format("Path: {} handle open failed: {}", pathf, tmp_msg);
      rc = EC::InvalidHandle;
      goto clean;
    }

    while (true) {
      rct = libssh2_sftp_readdir_ex(sftp_handle, filename_buffer.data(),
                                    buffer_size, nullptr, 0, &attrs);
      if (max_time_ms > 0) {
        end_time = timenow();
        if (end_time - start_time > max_time) {
          is_sucess = true;
          is_truncated = true;
          break;
        }
      }

      if (rct < 0) {
        rc = GetLastEC();
        std::string tmp_msg = GetLastErrorMsg();
        trace(TraceLevel::Error, rc,
              fmt::format("{}@{}", res_data.nickname, path), "ListDir",
              tmp_msg);
        msg = fmt::format("Path: {} readdir failed: {}", pathf, tmp_msg);
        goto clean;
      } else if (rct == 0) {
        is_sucess = true;
        break;
      }
      name.assign(filename_buffer.data(), rct);

      if (name == "." || name == "..") {
        continue;
      }

      path_i = AMFS::join(pathf, name);
      info = FormatStat(path_i, attrs);
      file_list.push_back(info);
    }

  clean:
    if (sftp_handle) {
      libssh2_sftp_close_handle(sftp_handle);
    }
    if (is_sucess) {
      // EC is Success, but message is not empty if truncated
      return {ECM{EC::Success, is_truncated ? "truncate" : ""}, file_list};
    } else {
      return {ECM{rc, msg}, {}};
    }
  }

  // Iterator version that yields PathInfo one by one using Python generator
  py::object iterator_listdir(const std::string &path) {
    if (!sftp) {
      throw std::runtime_error("SFTP not initialized");
    }

    auto pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
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
  ECM mkdir(const std::string &path) override {
    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }

    std::string pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
    if (pathf.empty()) {
      return std::make_pair(EC::InvalidArg,
                            fmt::format("Invalid path: {}", path));
    }

    std::string msg = "";
    auto [rcm, info] = stat(pathf);
    if (rcm.first == EC::Success) {

      if (info.type == PathType::DIR) {
        return {EC::Success, ""};
      } else {
        return {EC::PathAlreadyExists,
                fmt::format("Path exists and is not a directory: {}", pathf)};
      }
    }

    int rcr;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_mkdir_ex(sftp, path.c_str(), path.size(), 0740);
    }

    if (rcr != 0) {
      EC rc = GetLastEC();
      std::string msg_tmp = GetLastErrorMsg();
      msg = fmt::format("Path: {} mkdir failed: {}", pathf, msg_tmp);
      trace(TraceLevel::Error, rc,
            fmt::format("{}@{}", res_data.nickname, pathf), "Mkdir", msg_tmp);
      return {rc, msg};
    }
    return {EC::Success, ""};
  }

  // 递归创建多级目录，直到报错为止，自带AMFS::abspath
  ECM mkdirs(const std::string &path) override {
    std::string pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
    if (pathf.empty()) {
      return std::make_pair(EC::InvalidArg,
                            fmt::format("Invalid path: {}", path));
    }

    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }

    std::vector<std::string> parts = AMFS::split(pathf);
    if (parts.empty()) {
      return {EC::InvalidArg,
              fmt::format("Path split failed, get empty parts: {}", pathf)};
    } else if (parts.size() == 1) {
      return mkdir(pathf);
    }

    std::string current_path = parts.front();
    for (size_t i = 1; i < parts.size(); i++) {
      current_path = AMFS::join(current_path, parts[i], AMFS::SepType::Unix);
      ECM rc = mkdir(current_path);
      if (!isok(rc)) {
        return rc;
      }
    }
    return {EC::Success, ""};
  }

  ECM rmfile(const std::string &path) override {
    if (path.empty()) {
      return std::make_pair(EC::InvalidArg,
                            fmt::format("Invalid path: {}", path));
    }

    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }
    auto pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
    auto [rcm, info] = stat(pathf);
    ECM ecm;
    std::string msg = "";
    if (rcm.first != EC::Success) {
      trace(TraceLevel::Error, rcm.first,
            fmt::format("{}@{}", res_data.nickname, path), "rmfile",
            rcm.second);
      return rcm;
    } else {
      PathType type = info.type;
      switch (type) {
      case PathType::DIR:
        msg = fmt::format("Path is not a dir but use rmfile: {}", path);
        trace(TraceLevel::Warning, EC::NotAFile,
              fmt::format("{}@{}", res_data.nickname, path), "rmfile", msg);
        return {EC::NotAFile, msg};
      case PathType::SYMLINK: {
      }
      case PathType::FILE: {
      }
      default: {
        msg = fmt::format("Path is special file: {}", path);
        return {EC::OperationUnsupported, msg};
      }
      }
    }

    return lib_rmfile(pathf);
  }

  ECM rmdir(const std::string &path) override {
    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }

    std::string pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
    if (pathf.empty()) {
      return std::make_pair(EC::InvalidArg,
                            fmt::format("Invalid path: {}", path));
    }

    std::string msg = "";
    EC rc;

    int rcr;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_rmdir(sftp, pathf.c_str());
    }
    if (rcr < 0) {
      rc = GetLastEC();
      std::string tmp_msg = GetLastErrorMsg();
      msg = fmt::format("Path: {} rmdir failed: {}", path, tmp_msg);
      trace(TraceLevel::Error, rc,
            fmt::format("{}@{}", res_data.nickname, path), "Rmdir", tmp_msg);
      return {rc, msg};
    }
    trace(TraceLevel::Warning, EC::Success,
          fmt::format("{}@{}", res_data.nickname, path), "rmdir",
          fmt::format("Permanently remove directory: {}", path));
    return {EC::Success, ""};
  }

  // 删除文件或目录，自带AMFS::abspath
  std::variant<RMR, ECM> remove(const std::string &path) override {
    if (!sftp) {
      return ECM{EC::NoConnection, "SFTP not initialized"};
    }
    RMR errors = {};
    std::string pathn = AMFS::abspath(path, true, GetHomeDir());
    if (pathn.empty()) {
      return std::make_pair(EC::InvalidArg,
                            fmt::format("Invalid path: {}", path));
    }
    _rm(pathn, errors);
    return errors;
  }

  // 将原路径变成新路径，自带AMFS::abspath
  ECM rename(const std::string &src, const std::string &dst,
             bool overwrite = false) override {
    if (!sftp) {
      return ECM{EC::NoConnection, "SFTP not initialized"};
    }
    std::string srcf = AMFS::abspath(src, true, GetHomeDir(), GetHomeDir());
    std::string dstf = AMFS::abspath(dst, true, GetHomeDir(), GetHomeDir());
    if (srcf.empty() || dstf.empty()) {
      return std::make_pair(EC::InvalidArg,
                            fmt::format("Invalid path: {} or {}", srcf, dstf));
    }
    auto [rcm, sbr] = exists(srcf);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (!sbr) {
      return {EC::PathNotExist, fmt::format("Src not exists: {}", srcf)};
    }
    auto [rcm2, dbr] = exists(dstf);
    if (rcm2.first != EC::Success) {
      return rcm2;
    }
    if (dbr && !overwrite) {
      return {
          EC::PathAlreadyExists,
          fmt::format("Dst already exists: {} and overwrite is false", dstf)};
    }

    return lib_rename(src, dst, overwrite);
  }

  // 安全删除文件或目录，将目录移动到trash_dir中，自带AMFS::abspath
  ECM saferm(const std::string &path) override {
    auto [rcm, info] = stat(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::string pathf = info.path;
    if (!is_trash_dir_ensure) {
      return {EC::NotADirectory,
              fmt::format("Trash dir not ready: {}", this->trash_dir)};
    }

    std::string base = AMFS::basename(pathf);
    std::string base_name = base;
    std::string base_ext = "";
    std::string target_path;

    if (info.type != PathType::DIR) {
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

    mkdirs(AMFS::join(trash_dir, current_time));
    return lib_rename(path, target_path, false);
  }

  // 将源路径移动到目标文件夹，自带AMFS::abspath
  ECM move(const std::string &src, const std::string &dst,
           bool need_mkdir = false, bool force_write = false) override {
    if (!sftp) {
      return ECM{EC::NoConnection, "SFTP not initialized"};
    }
    std::string srcf = AMFS::abspath(src, true, GetHomeDir(), GetHomeDir());
    std::string dstf = AMFS::abspath(dst, true, GetHomeDir(), GetHomeDir());
    auto [rcm, ssr] = stat(srcf);
    // src不存在就直接退出
    if (rcm.first != EC::Success) {
      return rcm;
    }

    auto [rcm2, dsr] = stat(dstf);
    if (rcm2.first != EC::Success) {
      EC rc = rcm.first;
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

    // 使用不带检查的_rename
    return lib_rename(srcf, dst_path, force_write);
  }

  // 在服务器内将源路径复制到目标文件夹，自带AMFS::abspath,
  // 使用的时shell指令，不稳定
  ECM copy(const std::string &src, const std::string &dst,
           bool need_mkdir = false) {
    if (!sftp) {
      return ECM{EC::NoConnection, "SFTP not initialized"};
    }
    std::string srcf = AMFS::abspath(src, true, GetHomeDir(), GetHomeDir());
    std::string dstf = AMFS::abspath(dst, true, GetHomeDir(), GetHomeDir());
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
      return {EC::PathNotExist,
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
  WRV iwalk(const std::string &path, bool ignore_sepcial_file = true) override {
    // 搜索某一路径下的所有文件, 返回pathinfo的vector
    if (!sftp) {
      return {};
    }
    // get all files and deepest folders
    WRV result = {};
    auto path_n = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
    _iwalk(path_n, result, ignore_sepcial_file);
    return result;
  }

  // 真实的walk函数，返回([root_path, part1, part2, ...], PathInfo)的vector
  std::pair<ECM, WRD> walk(const std::string &path, int max_depth = -1,
                           bool ignore_special_file = true) override {
    auto pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
    auto [rcm, br] = stat(pathf);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    WRD result_dict = {};
    std::vector<std::string> parts = {pathf};
    _walk(parts, result_dict, 0, max_depth, ignore_special_file);
    // 打印result_dict的类型
    return {ECM{EC::Success, ""}, result_dict};
  }

  // 获取某一路径下的所有文件和底层目录的总大小
  uint64_t getsize(const std::string &path,
                   bool ignore_sepcial_file = true) override {
    WRV list = iwalk(path, ignore_sepcial_file);
    uint64_t size = 0;
    for (auto &item : list) {
      size += item.size;
    }
    return size;
  }
};

// FTP File Handle - 模拟 LIBSSH2_SFTP_HANDLE 的接口
class AMFTPFileHandle {
private:
  CURL *curl = nullptr;
  std::string remote_path;
  std::string host;
  int port;
  std::string username;
  std::string password;
  bool is_read_mode;
  bool is_write_mode;
  bool is_open = false;

  // For reading
  std::string read_buffer;
  size_t read_position = 0;
  bool read_complete = false;

  // For writing
  std::string write_buffer;
  bool write_complete = false;

  static size_t ReadCallback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
    size_t realsize = size * nmemb;
    auto *handle = static_cast<AMFTPFileHandle *>(userp);
    handle->read_buffer.append(static_cast<char *>(contents), realsize);
    return realsize;
  }

  static size_t WriteCallback(void *ptr, size_t size, size_t nmemb,
                              void *userp) {
    auto *handle = static_cast<AMFTPFileHandle *>(userp);
    size_t to_write =
        size * nmemb > handle->write_buffer.size() - handle->read_position
            ? handle->write_buffer.size() - handle->read_position
            : size * nmemb;

    if (to_write > 0) {
      memcpy(ptr, handle->write_buffer.data() + handle->read_position,
             to_write);
      handle->read_position += to_write;
    }

    return to_write;
  }

public:
  AMFTPFileHandle(const std::string &host, int port,
                  const std::string &username, const std::string &password,
                  const std::string &remote_path, bool read_mode,
                  bool write_mode)
      : host(host), port(port), username(username), password(password),
        remote_path(remote_path), is_read_mode(read_mode),
        is_write_mode(write_mode) {

    curl = curl_easy_init();
    if (!curl) {
      throw std::runtime_error("Failed to initialize CURL for file handle");
    }

    std::string url = fmt::format("ftp://{}:{}{}", host, port, remote_path);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
    curl_easy_setopt(curl, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);

    if (read_mode) {
      // Setup for reading
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ReadCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
    } else if (write_mode) {
      // Setup for writing
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
      curl_easy_setopt(curl, CURLOPT_READFUNCTION, WriteCallback);
      curl_easy_setopt(curl, CURLOPT_READDATA, this);
    }

    is_open = true;
  }

  ~AMFTPFileHandle() { Close(); }

  // Read data from remote file
  ssize_t Read(char *buffer, size_t buffer_size) {
    if (!is_open || !is_read_mode) {
      return -1;
    }

    // If we haven't started reading, fetch the file
    if (!read_complete && read_position == 0) {
      CURLcode res = curl_easy_perform(curl);
      if (res != CURLE_OK) {
        return -1;
      }
      read_complete = true;
      read_position = 0;
    }

    // Copy from buffer
    size_t available = read_buffer.size() - read_position;
    size_t to_copy = buffer_size > available ? available : buffer_size;

    if (to_copy > 0) {
      memcpy(buffer, read_buffer.data() + read_position, to_copy);
      read_position += to_copy;
      return static_cast<ssize_t>(to_copy);
    }

    return 0; // EOF
  }

  // Write data to remote file
  ssize_t Write(const char *buffer, size_t buffer_size) {
    if (!is_open || !is_write_mode) {
      return -1;
    }

    // Append to write buffer
    write_buffer.append(buffer, buffer_size);
    return static_cast<ssize_t>(buffer_size);
  }

  // Flush and close
  bool Close() {
    if (!is_open) {
      return true;
    }

    bool success = true;

    // If in write mode, flush the buffer
    if (is_write_mode && !write_buffer.empty() && !write_complete) {
      curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                       (curl_off_t)write_buffer.size());
      read_position = 0; // Reset for WriteCallback

      CURLcode res = curl_easy_perform(curl);
      if (res != CURLE_OK) {
        success = false;
      }
      write_complete = true;
    }

    if (curl) {
      curl_easy_cleanup(curl);
      curl = nullptr;
    }

    is_open = false;
    return success;
  }

  bool IsOpen() const { return is_open; }
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
  std::string host;
  int port = 21;
  std::string username;
  std::string password;
  std::string home_dir = "";
  std::atomic<bool> connected = false;
  std::regex ftp_url_pattern = std::regex("^ftp://.*$");
  ECM state = {EC::NoConnection, "Client Not Initialized"};
  std::mutex state_mtx;

  void _iwalk(const std::string &path, WRV &result,
              bool ignore_special_file = true) {
    auto [rcm, info_path] = stat(path);
    if (rcm.first != EC::Success) {
      return;
    }

    if (info_path.type != PathType::DIR) {
      result.push_back(info_path);
      return;
    }

    auto [rcm2, list_info] = listdir(path);
    if (rcm2.first != EC::Success) {
      return;
    }

    if (list_info.empty()) {
      result.push_back(info_path);
      return;
    }

    for (auto &info : list_info) {
      _iwalk(info.path, result, ignore_special_file);
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
  ConRequst request;
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

  std::string BuildUrl(const std::string &path) {
    std::string url = fmt::format("ftp://{}:{}", host, port);
    if (!path.empty()) {
      if (path[0] != '/') {
        url += "/";
      }
      url += path;
    }
    return url;
  }

  ECM SetupCurl(const std::string &url) {
    if (!curl) {
      return {EC::NoConnection, "CURL not initialized"};
    }

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
    curl_easy_setopt(curl, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);

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

  void _rm(const std::string &path, RMR &errors) {
    auto [rcm, info] = stat(path);
    if (rcm.first != EC::Success) {
      errors.emplace_back(path, rcm);
      return;
    }

    if (info.type == PathType::FILE || info.type == PathType::SYMLINK) {
      ECM rc = rmfile(path);
      if (rc.first != EC::Success) {
        errors.emplace_back(path, rc);
      }
      return;
    }

    if (info.type == PathType::DIR) {
      // List directory
      auto [rcm2, file_list] = listdir(path);
      if (rcm2.first != EC::Success) {
        errors.emplace_back(path, rcm2);
        return;
      }

      // Recursively delete contents
      for (const auto &item : file_list) {
        if (item.name == "." || item.name == "..")
          continue;
        std::string sub_path = AMFS::join(path, item.name, AMFS::SepType::Unix);
        _rm(sub_path, errors);
      }

      // Delete the empty directory
      ECM rc = rmdir(path);
      if (rc.first != EC::Success) {
        errors.emplace_back(path, rc);
      }
    }
  }

public:
  AMFTPClient(ConRequst request, size_t buffer_capacity = 10,
              const py::object &trace_cb = py::none())
      : BaseClient(request, buffer_capacity, trace_cb), request(request) {
    this->PROTOCOL = ClientProtocol::FTP;

    if (username.empty()) {
      this->username = "anonymous";
      this->password =
          request.password.empty() ? "anonymous@example.com" : request.password;
    }

    this->host = request.hostname;

    this->port = request.port;
  }

  ~AMFTPClient() {
    if (curl) {
      curl_easy_cleanup(curl);
    }
  }

  ECM Connect(bool force = false) override {
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
    std::string test_url = fmt::format("ftp://{}:{}/", host, port);
    ECM ecm = SetupCurl(test_url);
    if (ecm.first != EC::Success) {
      connected = false;
      return ecm;
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

  ECM Check(bool need_trace = false) override {
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

    std::string url = fmt::format("ftp://{}:{}/", host, port);
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
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

    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);
    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)},
              PathInfo()};
    }

    // Try to use SIZE and MDTM commands for files, or LIST for detailed info
    std::string url = BuildUrl(pathf);
    ECM ecm = SetupCurl(url);
    if (ecm.first != EC::Success) {
      return {ecm, PathInfo()};
    }

    // First try to check if it's a directory by trying to list it
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);

    struct MemoryStruct chunk;
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
      // It's likely a directory or file
      PathInfo info;
      info.path = pathf;
      info.name = AMFS::basename(pathf);
      info.dir = AMFS::dirname(pathf);

      // Get file size
      double filesize = 0;
      res =
          curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &filesize);
      if (res == CURLE_OK && filesize >= 0) {
        info.size = static_cast<uint64_t>(filesize);
        info.type = PathType::FILE;
      } else {
        // No size means it's likely a directory
        info.type = PathType::DIR;
        info.size = 0;
      }

      // Get modification time
      long filetime = 0;
      res = curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      if (res == CURLE_OK && filetime >= 0) {
        info.modify_time = filetime;
      }

      free(chunk.memory);
      return {ECM{EC::Success, ""}, info};
    }

    free(chunk.memory);

    // If HEAD request failed, try listing parent directory as fallback
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

    double start_time = timenow();

    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);
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

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
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
      if (max_time_ms > 0 && timenow() - start_time > max_time_ms) {
        return {ECM{EC::Success, "Timeout"}, file_list};
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

  WRV iwalk(const std::string &path, bool ignore_special_file = true) override {
    WRV result;
    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);
    _iwalk(pathf, result, ignore_special_file);
    return result;
  }

  std::pair<ECM, WRD> walk(const std::string &path, int max_depth = -1,
                           bool ignore_special_file = true) override {
    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);
    auto [rcm, br] = stat(pathf);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    WRD result_dict = {};
    std::vector<std::string> parts = {pathf};
    _walk(parts, result_dict, 0, max_depth, ignore_special_file);
    return {ECM{EC::Success, ""}, result_dict};
  }

  ECM mkdir(const std::string &path) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir, "/");
    if (pathf.empty()) {
      return {EC::InvalidArg, fmt::format("Invalid path: {}", path)};
    }

    // Check if already exists
    auto [rcm, info] = stat(pathf);
    if (rcm.first == EC::Success) {
      if (info.type == PathType::DIR) {
        return {EC::Success, ""};
      } else {
        return {EC::PathAlreadyExists,
                fmt::format("Path exists and is not a directory: {}", pathf)};
      }
    }

    std::string url = BuildUrl(pathf + "/");
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

  ECM mkdirs(const std::string &path) override {
    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);
    if (pathf.empty()) {
      return {EC::InvalidArg, fmt::format("Invalid path: {}", path)};
    }

    std::vector<std::string> parts = AMFS::split(pathf);
    if (parts.empty()) {
      return {EC::InvalidArg, fmt::format("Path split failed: {}", pathf)};
    }

    std::string current_path = parts.front();
    for (size_t i = 1; i < parts.size(); i++) {
      current_path = AMFS::join(current_path, parts[i], AMFS::SepType::Unix);
      ECM rc = mkdir(current_path);
      if (rc.first != EC::Success) {
        return rc;
      }
    }

    return {EC::Success, ""};
  }

  ECM rmfile(const std::string &path) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);
    if (pathf.empty()) {
      return {EC::InvalidArg, fmt::format("Invalid path: {}", path)};
    }

    // Check if it's a file
    auto [rcm, info] = stat(pathf);
    if (rcm.first != EC::Success) {
      return rcm;
    }

    if (info.type == PathType::DIR) {
      return {EC::NotAFile,
              fmt::format("Path is a directory, use rmdir: {}", path)};
    }

    // Delete using FTP DELE command
    std::string url = BuildUrl(pathf);
    ECM ecm = SetupCurl(url);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    // DELE is default for curl when uploading with CURLOPT_UPLOAD and no read
    // data
    struct curl_slist *commands = nullptr;
    commands =
        curl_slist_append(commands, fmt::format("DELE {}", pathf).c_str());
    curl_easy_setopt(curl, CURLOPT_QUOTE, commands);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(commands);

    if (res != CURLE_OK) {
      return {EC::CommonFailure,
              fmt::format("rmfile failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  ECM rmdir(const std::string &path) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);
    if (pathf.empty()) {
      return {EC::InvalidArg, fmt::format("Invalid path: {}", path)};
    }

    // Delete directory using FTP RMD command
    std::string url = BuildUrl(pathf);
    ECM ecm = SetupCurl(url);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    struct curl_slist *commands = nullptr;
    commands =
        curl_slist_append(commands, fmt::format("RMD {}", pathf).c_str());
    curl_easy_setopt(curl, CURLOPT_QUOTE, commands);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(commands);

    if (res != CURLE_OK) {
      return {EC::DirNotEmpty,
              fmt::format("rmdir failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  std::variant<RMR, ECM> remove(const std::string &path) override {
    RMR errors = {};
    std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);
    if (pathf.empty()) {
      return ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)};
    }
    _rm(pathf, errors);
    return errors;
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
    if (rcm2.first != EC::Success) {
      return rcm2;
    } else if (!overwrite) {
      return {
          EC::PathAlreadyExists,
          fmt::format("Dst already exists: {} and overwrite is false", dstf)};
    } else if (sbr2.type != sbr.type) {
      return {
          EC::PathAlreadyExists,
          fmt::format("Dst already exists and is not the same type as src: {} ",
                      dstf)};
    }

    // Use RNFR and RNTO commands
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

    curl_easy_setopt(curl, CURLOPT_QUOTE, headerlist);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headerlist);

    if (res != CURLE_OK) {
      return {EC::FTPRenameFailed,
              fmt::format("Rename failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  ECM move(const std::string &src, const std::string &dst,
           bool need_mkdir = false, bool force_write = false) override {
    std::string srcf = AMFS::abspath(src, true, home_dir, home_dir);
    std::string dstf = AMFS::abspath(dst, true, home_dir, home_dir);

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

  // 改进的 upload 方法，支持暂停和中断
  ECM upload(
      const std::string &local_path, const std::string &remote_path,
      std::function<void(uint64_t, uint64_t)> progress_callback = nullptr,
      std::atomic<bool> *is_paused = nullptr,
      std::atomic<bool> *is_cancelled = nullptr) {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    // Open local file
    std::ifstream local_file(local_path, std::ios::binary | std::ios::ate);
    if (!local_file) {
      return {EC::LocalFileError,
              fmt::format("Cannot open local file: {}", local_path)};
    }

    // Get file size
    uint64_t file_size = local_file.tellg();
    local_file.seekg(0, std::ios::beg);

    // Build URL
    std::string remote_pathf =
        AMFS::abspath(remote_path, true, home_dir, home_dir);
    std::string url = BuildUrl(remote_pathf);

    ECM ecm = SetupCurl(url);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    // Setup upload
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READDATA, &local_file);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_size);

    // 传递暂停/取消标志
    struct TransferContext {
      std::ifstream *file;
      std::atomic<bool> *paused;
      std::atomic<bool> *cancelled;
    };

    TransferContext ctx{&local_file, is_paused, is_cancelled};

    // Setup read callback with pause/cancel support
    curl_easy_setopt(
        curl, CURLOPT_READFUNCTION,
        +[](void *ptr, size_t size, size_t nmemb, void *userp) -> size_t {
          auto *context = static_cast<TransferContext *>(userp);

          // 检查是否取消
          if (context->cancelled && context->cancelled->load()) {
            return CURL_READFUNC_ABORT; // 中断传输
          }

          // 处理暂停
          while (context->paused && context->paused->load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // 暂停期间也检查取消
            if (context->cancelled && context->cancelled->load()) {
              return CURL_READFUNC_ABORT;
            }
          }

          // 正常读取数据
          context->file->read(static_cast<char *>(ptr), size * nmemb);
          return context->file->gcount();
        });
    curl_easy_setopt(curl, CURLOPT_READDATA, &ctx);

    // Setup progress callback with pause/cancel support
    struct ProgressContext {
      std::function<void(uint64_t, uint64_t)> *callback;
      std::atomic<bool> *paused;
      std::atomic<bool> *cancelled;
    };

    ProgressContext prog_ctx{&progress_callback, is_paused, is_cancelled};

    if (progress_callback) {
      curl_easy_setopt(
          curl, CURLOPT_XFERINFOFUNCTION,
          +[](void *clientp, curl_off_t dltotal, curl_off_t dlnow,
              curl_off_t ultotal, curl_off_t ulnow) -> int {
            auto *context = static_cast<ProgressContext *>(clientp);

            // 检查是否取消
            if (context->cancelled && context->cancelled->load()) {
              return 1; // 返回非0中断传输
            }

            // 调用进度回调
            if (context->callback && *context->callback) {
              (*context->callback)(ulnow, ultotal);
            }

            return 0; // 继续传输
          });
      curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &prog_ctx);
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    }

    CURLcode res = curl_easy_perform(curl);
    local_file.close();

    if (res == CURLE_ABORTED_BY_CALLBACK) {
      return {EC::Terminate, "Upload cancelled by user"};
    } else if (res != CURLE_OK) {
      return {EC::CommonFailure,
              fmt::format("Upload failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  ECM download(
      const std::string &remote_path, const std::string &local_path,
      std::function<void(uint64_t, uint64_t)> progress_callback = nullptr,
      std::atomic<bool> *is_paused = nullptr,
      std::atomic<bool> *is_cancelled = nullptr) {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    // Create local directory
    AMFS::mkdirs(AMFS::dirname(local_path));

    // Open local file for writing
    std::ofstream local_file(local_path, std::ios::binary);
    if (!local_file) {
      return {EC::LocalFileError,
              fmt::format("Cannot create local file: {}", local_path)};
    }

    // Build URL
    std::string remote_pathf =
        AMFS::abspath(remote_path, true, home_dir, home_dir);
    std::string url = BuildUrl(remote_pathf);

    ECM ecm = SetupCurl(url);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    // 传递暂停/取消标志
    struct WriteContext {
      std::ofstream *file;
      std::atomic<bool> *paused;
      std::atomic<bool> *cancelled;
    };

    WriteContext ctx{&local_file, is_paused, is_cancelled};

    // Setup download with pause/cancel support
    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION,
        +[](void *ptr, size_t size, size_t nmemb, void *userp) -> size_t {
          auto *context = static_cast<WriteContext *>(userp);

          // 检查是否取消
          if (context->cancelled && context->cancelled->load()) {
            return 0; // 返回0中断传输
          }

          // 处理暂停
          while (context->paused && context->paused->load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // 暂停期间也检查取消
            if (context->cancelled && context->cancelled->load()) {
              return 0;
            }
          }

          // 正常写入数据
          context->file->write(static_cast<const char *>(ptr), size * nmemb);
          return size * nmemb;
        });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

    // Setup progress callback with pause/cancel support
    struct ProgressContext {
      std::function<void(uint64_t, uint64_t)> *callback;
      std::atomic<bool> *paused;
      std::atomic<bool> *cancelled;
    };

    ProgressContext prog_ctx{&progress_callback, is_paused, is_cancelled};

    if (progress_callback) {
      curl_easy_setopt(
          curl, CURLOPT_XFERINFOFUNCTION,
          +[](void *clientp, curl_off_t dltotal, curl_off_t dlnow,
              curl_off_t ultotal, curl_off_t ulnow) -> int {
            auto *context = static_cast<ProgressContext *>(clientp);

            // 检查是否取消
            if (context->cancelled && context->cancelled->load()) {
              return 1; // 返回非0中断传输
            }

            // 调用进度回调
            if (context->callback && *context->callback) {
              (*context->callback)(dlnow, dltotal);
            }

            return 0; // 继续传输
          });
      curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &prog_ctx);
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    }

    CURLcode res = curl_easy_perform(curl);
    local_file.close();

    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      return {EC::Terminate, "Download cancelled by user"};
    } else if (res != CURLE_OK) {
      return {EC::CommonFailure,
              fmt::format("Download failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
  }

  // 内存中介传输：从回调读取数据，上传到 FTP
  // 用于 SFTP -> FTP 或其他协议 -> FTP 的传输
  ECM upload_from_callback(
      const std::string &remote_path,
      std::function<size_t(char *, size_t)> read_callback, // 读取数据的回调
      uint64_t total_size,                                 // 总大小
      std::function<void(uint64_t, uint64_t)> progress_callback = nullptr,
      std::atomic<bool> *is_paused = nullptr,
      std::atomic<bool> *is_cancelled = nullptr) {

    std::lock_guard<std::recursive_mutex> lock(mtx);

    std::string remote_pathf =
        AMFS::abspath(remote_path, true, home_dir, home_dir);
    std::string url = BuildUrl(remote_pathf);

    ECM ecm = SetupCurl(url);
    if (ecm.first != EC::Success) {
      return ecm;
    }

    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)total_size);

    // 传递所有上下文
    struct UploadContext {
      std::function<size_t(char *, size_t)> *read_cb;
      std::atomic<bool> *paused;
      std::atomic<bool> *cancelled;
    };

    UploadContext ctx{&read_callback, is_paused, is_cancelled};

    curl_easy_setopt(
        curl, CURLOPT_READFUNCTION,
        +[](void *ptr, size_t size, size_t nmemb, void *userp) -> size_t {
          auto *context = static_cast<UploadContext *>(userp);

          if (context->cancelled && context->cancelled->load()) {
            return CURL_READFUNC_ABORT;
          }

          while (context->paused && context->paused->load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (context->cancelled && context->cancelled->load()) {
              return CURL_READFUNC_ABORT;
            }
          }

          // 调用用户提供的读取回调
          return (*context->read_cb)(static_cast<char *>(ptr), size * nmemb);
        });
    curl_easy_setopt(curl, CURLOPT_READDATA, &ctx);

    // 进度回调
    struct ProgressContext {
      std::function<void(uint64_t, uint64_t)> *callback;
      std::atomic<bool> *cancelled;
    };

    ProgressContext prog_ctx{&progress_callback, is_cancelled};

    if (progress_callback) {
      curl_easy_setopt(
          curl, CURLOPT_XFERINFOFUNCTION,
          +[](void *clientp, curl_off_t dltotal, curl_off_t dlnow,
              curl_off_t ultotal, curl_off_t ulnow) -> int {
            auto *context = static_cast<ProgressContext *>(clientp);

            if (context->cancelled && context->cancelled->load()) {
              return 1;
            }

            if (context->callback && *context->callback) {
              (*context->callback)(ulnow, ultotal);
            }

            return 0;
          });
      curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &prog_ctx);
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    }

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_ABORTED_BY_CALLBACK) {
      return {EC::Terminate, "Upload cancelled"};
    } else if (res != CURLE_OK) {
      return {EC::CommonFailure,
              fmt::format("Upload failed: {}", curl_easy_strerror(res))};
    }

    return {EC::Success, ""};
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

  // 内存中介传输：下载 FTP，写入回调
  // 用于 FTP -> SFTP 或 FTP -> 其他协议的传输
  ECM download_to_callback(
      const std::string &remote_path,
      std::function<size_t(const char *, size_t)>
          write_callback, // 写入数据的回调
      std::function<void(uint64_t, uint64_t)> progress_callback = nullptr,
      std::atomic<bool> *is_paused = nullptr,
      std::atomic<bool> *is_cancelled = nullptr) {

    // std::lock_guard<std::recursive_mutex> lock(mtx);

    // std::string remote_pathf =
    //     AMFS::abspath(remote_path, true, home_dir, home_dir);
    // std::string url = BuildUrl(remote_pathf);

    // ECM ecm = SetupCurl(url);
    // if (ecm.first != EC::Success) {
    //   return ecm;
    // }

    // // 传递所有上下文
    // struct DownloadContext {
    //   std::function<size_t(const char *, size_t)> *write_cb;
    //   std::atomic<bool> *paused;
    //   std::atomic<bool> *cancelled;
    // };

    // DownloadContext ctx{&write_callback, is_paused, is_cancelled};

    // curl_easy_setopt(
    //     curl, CURLOPT_WRITEFUNCTION,
    //     +[](void *ptr, size_t size, size_t nmemb, void *userp) -> size_t {
    //       auto *context = static_cast<DownloadContext *>(userp);

    //       if (context->cancelled && context->cancelled->load()) {
    //         return 0; // 中断
    //       }

    //       while (context->paused && context->paused->load()) {
    //         std::this_thread::sleep_for(std::chrono::milliseconds(100));
    //         if (context->cancelled && context->cancelled->load()) {
    //           return 0;
    //         }
    //       }

    //       // 调用用户提供的写入回调
    //       return (*context->write_cb)(static_cast<const char *>(ptr),
    //                                   size * nmemb);
    //     });
    // curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

    // // 进度回调
    // struct ProgressContext {
    //   std::function<void(uint64_t, uint64_t)> *callback;
    //   std::atomic<bool> *cancelled;
    // };

    // ProgressContext prog_ctx{&progress_callback, is_cancelled};

    // if (progress_callback) {
    //   curl_easy_setopt(
    //       curl, CURLOPT_XFERINFOFUNCTION,
    //       +[](void *clientp, curl_off_t dltotal, curl_off_t dlnow,
    //           curl_off_t ultotal, curl_off_t ulnow) -> int {
    //         auto *context = static_cast<ProgressContext *>(clientp);

    //         if (context->cancelled && context->cancelled->load()) {
    //           return 1;
    //         }

    //         if (context->callback && *context->callback) {
    //           (*context->callback)(dlnow, dltotal);
    //         }

    //         return 0;
    //       });
    //   curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &prog_ctx);
    //   curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    // }

    // CURLcode res = curl_easy_perform(curl);

    // if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
    //   return {EC::Terminate, "Download cancelled"};
    // } else if (res != CURLE_OK) {
    //   return {EC::CommonFailure,
    //           fmt::format("Download failed: {}", curl_easy_strerror(res))};
    // }

    // return {EC::Success, ""};
  }

  //   // Open local file for writing
  //   std::ofstream local_file(local_path, std::ios::binary);
  //   if (!local_file) {
  //     return {EC::LocalFileError,
  //             fmt::format("Cannot create local file: {}", local_path)};
  //   }

  //   // Build URL
  //   std::string remote_pathf =
  //       AMFS::abspath(remote_path, true, home_dir, home_dir);
  //   std::string url = BuildUrl(remote_pathf);

  //   ECM ecm = SetupCurl(url);
  //   if (ecm.first != EC::Success) {
  //     return ecm;
  //   }

  //   // Setup download
  //   curl_easy_setopt(
  //       curl, CURLOPT_WRITEFUNCTION,
  //       +[](void *ptr, size_t size, size_t nmemb, void *stream) -> size_t {
  //         std::ofstream *file = static_cast<std::ofstream *>(stream);
  //         file->write(static_cast<const char *>(ptr), size * nmemb);
  //         return size * nmemb;
  //       });
  //   curl_easy_setopt(curl, CURLOPT_WRITEDATA, &local_file);

  //   // Setup progress callback if provided
  //   if (progress_callback) {
  //     curl_easy_setopt(
  //         curl, CURLOPT_XFERINFOFUNCTION,
  //         +[](void *clientp, curl_off_t dltotal, curl_off_t dlnow,
  //             curl_off_t ultotal, curl_off_t ulnow) -> int {
  //           auto *callback =
  //               static_cast<std::function<void(uint64_t, uint64_t)>
  //               *>(clientp);
  //           (*callback)(dlnow, dltotal);
  //           return 0;
  //         });
  //     curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progress_callback);
  //     curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
  //   }

  //   CURLcode res = curl_easy_perform(curl);
  //   local_file.close();

  //   if (res != CURLE_OK) {
  //     return {EC::CommonFailure,
  //             fmt::format("Download failed: {}", curl_easy_strerror(res))};
  //   }

  //   return {EC::Success, ""};

  //   // 模拟 libssh2_sftp_open 接口，返回文件句柄指针
  //   AMFTPFileHandle *ftp_open(const std::string &path, bool read_mode,
  //                             bool write_mode) {
  //     std::string pathf = AMFS::abspath(path, true, home_dir, home_dir);

  //     try {
  //       auto *handle = new AMFTPFileHandle(host, port, username, password,
  //       pathf,
  //                                          read_mode, write_mode);
  //       return handle;
  //     } catch (const std::exception &e) {
  //       return nullptr;
  //     }
  //   }

  //   // 模拟 libssh2_sftp_read
  //   ssize_t ftp_read(AMFTPFileHandle *handle, char *buffer, size_t
  //   buffer_size) {
  //     if (!handle) {
  //       return -1;
  //     }
  //     return handle->Read(buffer, buffer_size);
  //   }

  //   // 模拟 libssh2_sftp_write
  //   ssize_t ftp_write(AMFTPFileHandle *handle, const char *buffer,
  //                     size_t buffer_size) {
  //     if (!handle) {
  //       return -1;
  //     }
  //     return handle->Write(buffer, buffer_size);
  //   }

  //   // 模拟 libssh2_sftp_close_handle
  //   bool ftp_close(AMFTPFileHandle *handle) {
  //     if (!handle) {
  //       return false;
  //     }
  //     bool success = handle->Close();
  //     delete handle;
  //     return success;
  //   }
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

      file_handle = CreateFileW(AMFS::Str::AMStr(path).c_str(), access, share,
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

class HostMaintainer {
private:
  std::unordered_map<std::string, std::shared_ptr<BaseClient>> hosts;
  std::atomic<bool> is_heartbeat;
  std::thread heartbeat_thread;
  py::function disconnect_cb;
  bool is_disconnect_cb = false;

  void HeartbeatAct(int interval_s) {
    int millsecond = 0;
    ECM rcm;
    while (true) {
      // 遍历hosts字典
      for (auto &host : hosts) {
        rcm = host.second->Check();
        if (rcm.first != EC::Success) {
          if (is_disconnect_cb) {
            py::gil_scoped_acquire acquire;
            disconnect_cb(host.second, rcm);
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
  ~HostMaintainer() {
    is_heartbeat.store(false);
    if (heartbeat_thread.joinable()) {
      heartbeat_thread.join();
    }
  }

  HostMaintainer(int heartbeat_interval_s = 60,
                 py::object disconnect_cb = py::none()) {
    this->is_heartbeat.store(true);
    heartbeat_thread = std::thread(
        [this, heartbeat_interval_s]() { HeartbeatAct(heartbeat_interval_s); });
    if (!disconnect_cb.is_none()) {
      this->disconnect_cb = py::cast<py::function>(disconnect_cb);
      this->is_disconnect_cb = true;
    }
  }

  std::vector<std::string> get_hosts() {
    std::vector<std::string> host_list;
    for (auto &host : hosts) {
      host_list.push_back(host.first);
    }
    return host_list;
  }

  std::vector<std::shared_ptr<BaseClient>> get_clients() {
    std::vector<std::shared_ptr<BaseClient>> client_list;
    for (auto &host : hosts) {
      client_list.push_back(host.second);
    }
    return client_list;
  }

  void add_host(const std::string &nickname, std::shared_ptr<BaseClient> client,
                bool overwrite = false) {
    if (hosts.find(nickname) != hosts.end()) {
      if (!overwrite) {
        return;
      }
      hosts.erase(nickname);
    }
    hosts[nickname] = client;
  }

  void remove_host(const std::string &nickname) {
    if (hosts.find(nickname) != hosts.end()) {
      hosts.erase(nickname);
    }
  }

  std::shared_ptr<BaseClient> get_host(const std::string &nickname) {
    if (hosts.find(nickname) == hosts.end()) {
      return nullptr;
    }
    return hosts[nickname];
  }

  ECM test_host(const std::string &nickname, bool update = false) {
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
};

class AMSFTPWorker {
private:
  // Optimized memory-mapped file copy
  // Key optimizations:
  // 1. Large view size (512MB) to minimize map/unmap overhead
  // 2. NO flush inside loop - only flush once at end
  // 3. FILE_FLAG_SEQUENTIAL_SCAN for better OS prefetch
  // 4. Small chunk memcpy inside large view for progress reporting
  ECM Local2LocalMMap(const std::string &src, const std::string &dst,
                      uint64_t chunk_size) {
    return {EC::Success, ""};
    //     ErrorCode rc_r = EC::Success;
    //     std::string error_msg = "";

    //     // Open source file with sequential access hint
    //     LocalFileHandle src_handle;
    //     ECM src_init = src_handle.Init(src, false, true);
    //     if (src_init.first != EC::Success) {
    //       return src_init;
    //     }

    //     // Get source file size
    //     uint64_t file_size = 0;
    //     ECM size_result = src_handle.GetFileSize(file_size);
    //     if (size_result.first != EC::Success) {
    //       return size_result;
    //     }

    //     // Handle empty file
    //     if (file_size == 0) {
    //       AMFS::mkdirs(AMFS::dirname(dst));
    //       LocalFileHandle dst_handle;
    //       ECM dst_init = dst_handle.Init(dst, true);
    //       if (dst_init.first != EC::Success) {
    //         return dst_init;
    //       }
    //       pd.accumulated_size += 0;
    //       pd.this_size = 0;
    //       InnerCallback(true);
    //       return {EC::Success, ""};
    //     }

    //     // Create destination directory and file
    //     AMFS::mkdirs(AMFS::dirname(dst));
    //     LocalFileHandle dst_handle;
    //     ECM dst_init = dst_handle.Init(dst, true, true);
    //     if (dst_init.first != EC::Success) {
    //       return dst_init;
    //     }

    //     // Set destination file size
    //     ECM set_size_result = dst_handle.SetFileSize(file_size);
    //     if (set_size_result.first != EC::Success) {
    //       return set_size_result;
    //     }

    // #ifdef _WIN32
    //     // Create file mapping for source
    //     HANDLE hSrcMapping = CreateFileMappingW(src_handle.file_handle,
    //     nullptr,
    //                                             PAGE_READONLY, 0, 0,
    //                                             nullptr);
    //     if (hSrcMapping == nullptr) {
    //       return {EC::LocalFileMapError, "Failed to create source file
    //       mapping"};
    //     }

    //     // Create file mapping for destination
    //     LARGE_INTEGER dst_size;
    //     dst_size.QuadPart = file_size;
    //     HANDLE hDstMapping =
    //         CreateFileMappingW(dst_handle.file_handle, nullptr,
    //         PAGE_READWRITE,
    //                            dst_size.HighPart, dst_size.LowPart, nullptr);
    //     if (hDstMapping == nullptr) {
    //       CloseHandle(hSrcMapping);
    //       return {EC::LocalFileMapError,
    //               "Failed to create destination file mapping"};
    //     }

    //     // Optimized: Use large views (512MB) to minimize map/unmap overhead
    //     uint64_t offset = 0;
    //     const uint64_t MAX_VIEW_SIZE = 512ULL * 1024 * 1024; // 512MB per
    //     view

    //     while (offset < file_size && !pd.is_terminate.load()) {
    //       // Handle pause
    //       while (pd.is_pause.load() && !pd.is_terminate.load()) {
    //         std::this_thread::sleep_for(std::chrono::milliseconds(100));
    //       }

    //       if (pd.is_terminate.load()) {
    //         rc_r = EC::Terminate;
    //         error_msg = "Transfer cancelled";
    //         break;
    //       }

    //       uint64_t remaining = file_size - offset;
    //       auto view_size = std::min<uint64_t>(remaining, MAX_VIEW_SIZE);

    //       DWORD offset_high = static_cast<DWORD>(offset >> 32);
    //       DWORD offset_low = static_cast<DWORD>(offset & 0xFFFFFFFF);

    //       // Map large view once
    //       void *src_view =
    //           MapViewOfFile(hSrcMapping, FILE_MAP_READ, offset_high,
    //           offset_low,
    //                         static_cast<SIZE_T>(view_size));
    //       if (src_view == nullptr) {
    //         rc_r = EC::LocalFileMapError;
    //         error_msg = "Failed to map source file view";
    //         break;
    //       }

    //       void *dst_view =
    //           MapViewOfFile(hDstMapping, FILE_MAP_WRITE, offset_high,
    //           offset_low,
    //                         static_cast<SIZE_T>(view_size));
    //       if (dst_view == nullptr) {
    //         UnmapViewOfFile(src_view);
    //         rc_r = EC::LocalFileMapError;
    //         error_msg = "Failed to map destination file view";
    //         break;
    //       }

    //       // Copy in small chunks within the view for progress reporting
    //       uint64_t view_offset = 0;
    //       while (view_offset < view_size && !pd.is_terminate.load()) {
    //         uint64_t copy_size =
    //             std::min<uint64_t>(chunk_size, view_size - view_offset);

    //         // Direct memory copy
    //         memcpy(static_cast<char *>(dst_view) + view_offset,
    //                static_cast<const char *>(src_view) + view_offset,
    //                static_cast<size_t>(copy_size));

    //         view_offset += copy_size;
    //         offset += copy_size;
    //         pd.accumulated_size += copy_size;
    //         pd.this_size = offset;
    //         InnerCallback();
    //       }

    //       // Unmap views - NO flush here! Let OS handle writeback
    //       asynchronously UnmapViewOfFile(dst_view);
    //       UnmapViewOfFile(src_view);
    //     }

    //     // Cleanup - only flush ONCE at the end for maximum performance
    //     CloseHandle(hDstMapping);
    //     if (rc_r == EC::Success) {
    //       FlushFileBuffers(
    //           dst_handle.file_handle); // Single flush at end, not per chunk!
    //     }

    // #else
    //     // Optimized: Large view size (1GB), remove msync per chunk
    //     uint64_t offset = 0;
    //     const uint64_t MAX_VIEW_SIZE = 1ULL * 1024 * 1024 * 1024; // 1GB per
    //     mmap

    //     while (offset < file_size && !pd.is_terminate.load()) {
    //       while (pd.is_pause.load() && !pd.is_terminate.load()) {
    //         std::this_thread::sleep_for(std::chrono::milliseconds(100));
    //       }

    //       if (pd.is_terminate.load()) {
    //         rc_r = EC::Terminate;
    //         error_msg = "Transfer cancelled";
    //         break;
    //       }

    //       uint64_t remaining = file_size - offset;
    //       uint64_t view_size = std::min(remaining, MAX_VIEW_SIZE);

    //       // Map large view once
    //       void *src_map = mmap(nullptr, view_size, PROT_READ, MAP_SHARED,
    //                            src_handle.file_handle, offset);
    //       if (src_map == MAP_FAILED) {
    //         rc_r = EC::LocalFileMapError;
    //         error_msg = "Failed to mmap source file";
    //         break;
    //       }

    //       // Tell kernel: sequential access for better prefetch
    //       madvise(src_map, view_size, MADV_SEQUENTIAL);

    //       void *dst_map = mmap(nullptr, view_size, PROT_WRITE, MAP_SHARED,
    //                            dst_handle.file_handle, offset);
    //       if (dst_map == MAP_FAILED) {
    //         munmap(src_map, view_size);
    //         rc_r = EC::LocalFileMapError;
    //         error_msg = "Failed to mmap destination file";
    //         break;
    //       }

    //       // Copy in small chunks within view for progress reporting
    //       uint64_t view_offset = 0;
    //       while (view_offset < view_size && !pd.is_terminate.load()) {
    //         uint64_t copy_size = std::min(chunk_size, view_size -
    //         view_offset);

    //         memcpy(static_cast<char *>(dst_map) + view_offset,
    //                static_cast<const char *>(src_map) + view_offset,
    //                copy_size);

    //         view_offset += copy_size;
    //         offset += copy_size;
    //         pd.accumulated_size += copy_size;
    //         pd.this_size = offset;
    //         InnerCallback();
    //       }

    //       // Unmap - NO msync here! Let kernel handle writeback
    //       asynchronously munmap(dst_map, view_size); munmap(src_map,
    //       view_size);
    //     }

    //     // Cleanup - only fsync ONCE at the end for maximum performance
    //     if (rc_r == EC::Success) {
    //       fsync(dst_handle.file_handle); // Single sync at end, not per
    //       chunk!
    //     }
    // #endif

    //     // Final callback
    //     InnerCallback(true);

    //     return {rc_r, error_msg};
  }

  ECM Local2Local(const std::string &src, const std::string &dst,
                  uint64_t chunk_size) {
    ErrorCode rc_r = EC::Success;
    std::string error_msg = "";

    // Get source file size
    uint64_t file_size = 0;
#ifdef _WIN32
    HANDLE hFile = CreateFileW(AMFS::Str::AMStr(src).c_str(), GENERIC_READ,
                               FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
      return {EC::LocalFileMapError, "Failed to open source file"};
    }
    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li)) {
      CloseHandle(hFile);
      return {EC::LocalFileMapError, "Failed to get file size"};
    }
    file_size = li.QuadPart;
    CloseHandle(hFile);
#else
    struct stat file_stat;
    if (stat(src.c_str(), &file_stat) == -1) {
      return {EC::LocalFileMapError, "Failed to stat source file"};
    }
    file_size = file_stat.st_size;
#endif
    // Create destination directory
    AMFS::mkdirs(AMFS::dirname(dst));

    // Create ring buffer (2x chunk_size for overlapping read/write)
    StreamRingBuffer ring_buffer(chunk_size * 2);

    // Open source file for reading
#ifdef _WIN32
    HANDLE hSrcFile = CreateFileW(AMFS::Str::AMStr(src).c_str(), GENERIC_READ,
                                  FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hSrcFile == INVALID_HANDLE_VALUE) {
      return {EC::LocalFileMapError, "Failed to open source file for reading"};
    }
#else
    int src_fd = open(src.c_str(), O_RDONLY);
    if (src_fd == -1) {
      return {EC::LocalFileMapError, "Failed to open source file for reading"};
    }
#endif

    // Open destination file for writing
#ifdef _WIN32
    HANDLE hDstFile =
        CreateFileW(AMFS::Str::AMStr(dst).c_str(), GENERIC_WRITE, 0, nullptr,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDstFile == INVALID_HANDLE_VALUE) {
      CloseHandle(hSrcFile);
      return {EC::LocalFileMapError, "Failed to create destination file"};
    }
#else
    int dst_fd = open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd == -1) {
      close(src_fd);
      return {EC::LocalFileMapError, "Failed to create destination file"};
    }
#endif

    uint64_t offset = 0;
    uint64_t total_read = 0;
    std::atomic<bool> read_finished(false);
    std::atomic<bool> read_error(false);
    std::string read_error_msg = "";

    // Async read thread
    std::thread read_thread([&]() {
      uint64_t remaining = file_size;
      while (remaining > 0 && !pd.is_terminate.load() && !read_error) {
        // Wait for writable space
        while (ring_buffer.writable() == 0 && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (pd.is_terminate.load())
          break;

        auto [write_ptr, write_len] = ring_buffer.get_write_ptr();
        uint64_t to_read = std::min<uint64_t>(
            write_len, std::min<uint64_t>(chunk_size, remaining));

        if (to_read > 0) {
#ifdef _WIN32
          DWORD bytes_read = 0;
          if (!ReadFile(hSrcFile, write_ptr, static_cast<DWORD>(to_read),
                        &bytes_read, nullptr)) {
            read_error = true;
            read_error_msg = "Failed to read from source file";
            break;
          }
          if (bytes_read == 0)
            break;
          ring_buffer.commit_write(bytes_read);
          remaining -= bytes_read;
          total_read += bytes_read;
#else
          ssize_t bytes_read = read(src_fd, write_ptr, to_read);
          if (bytes_read < 0) {
            read_error = true;
            read_error_msg = "Failed to read from source file";
            break;
          }
          if (bytes_read == 0)
            break;
          ring_buffer.commit_write(bytes_read);
          remaining -= bytes_read;
          total_read += bytes_read;
#endif
        }
      }
      read_finished = true;
    });

    // Main write thread (current thread)
    while ((!read_finished || ring_buffer.available() > 0) &&
           !pd.is_terminate.load()) {
      // Handle pause
      while (pd.is_pause.load() && !pd.is_terminate.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
      }

      if (pd.is_terminate.load()) {
        rc_r = EC::Terminate;
        error_msg = "Transfer cancelled";
        break;
      }

      // Wait for readable data
      while (ring_buffer.available() == 0 && !read_finished && !read_error &&
             !pd.is_terminate.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }

      if (read_error) {
        rc_r = EC::LocalFileMapError;
        error_msg = read_error_msg;
        break;
      }

      if (ring_buffer.available() == 0)
        break;

      auto [read_ptr, read_len] = ring_buffer.get_read_ptr();
      if (read_len > 0) {
#ifdef _WIN32
        DWORD bytes_written = 0;
        if (!WriteFile(hDstFile, read_ptr, static_cast<DWORD>(read_len),
                       &bytes_written, nullptr)) {
          rc_r = EC::LocalFileMapError;
          error_msg = "Failed to write to destination file";
          break;
        }
        ring_buffer.commit_read(bytes_written);
        offset += bytes_written;
        pd.accumulated_size += bytes_written;
        pd.this_size = offset;
#else
        ssize_t bytes_written = write(dst_fd, read_ptr, read_len);
        if (bytes_written < 0) {
          rc_r = EC::LocalFileWriteError;
          error_msg = "Failed to write to destination file";
          break;
        }
        ring_buffer.commit_read(bytes_written);
        offset += bytes_written;
        current_size += bytes_written;
#endif
        InnerCallback();
      }
    }

    // Wait for read thread to finish
    read_thread.join();

    // Close files
#ifdef _WIN32
    CloseHandle(hSrcFile);
    if (rc_r == EC::Success) {
      FlushFileBuffers(hDstFile);
    }
    CloseHandle(hDstFile);
#else
    close(src_fd);
    if (rc_r == EC::Success) {
      fsync(dst_fd);
    }
    close(dst_fd);
#endif

    // Final callback
    InnerCallback(true);

    return {rc_r, error_msg};
  }

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
                                 const std::shared_ptr<HostMaintainer> &hostm,
                                 const std::string &nickname = "") {
    if (nickname.empty()) {
      auto res = AMFS::stat(path);
      if (!res.first.empty()) {
        return {ECM{EC::LocalStatError, res.first}, res.second};
      }
      return {ECM{EC::Success, ""}, res.second};
    }
    ECM rc = hostm->test_host(nickname);
    if (rc.first != EC::Success) {
      return {rc, PathInfo()};
    }
    auto client = hostm->get_host(nickname);
    if (!client) {
      return {ECM{EC::NoSession, "Client not found"}, PathInfo()};
    }
    return client->stat(path);
  }

  std::vector<PathInfo> Uiwalk(const std::string &path,
                               const std::shared_ptr<HostMaintainer> &hostm,
                               const std::string &nickname = "",
                               bool ignore_special_file = true) {
    if (nickname.empty()) {
      return AMFS::iwalk(path, ignore_special_file);
    }
    ECM rc = hostm->test_host(nickname);
    if (rc.first != EC::Success) {
      return {};
    }
    auto client = hostm->get_host(nickname);
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
           const std::shared_ptr<HostMaintainer> &hostm) {
    std::shared_ptr<BaseClient> src_client = nullptr;
    std::shared_ptr<BaseClient> dst_client = nullptr;
    ECM rcm = ECM{EC::Success, ""};
    if (!task.src_host.empty()) {
      src_client = hostm->get_host(task.src_host);
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
      dst_client = hostm->get_host(task.dst_host);
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
        py::gil_scoped_acquire acquire;
        py::object result = callback.progress_cb(ProgressCBInfo(
            pd.src, pd.dst, pd.src_host, pd.dst_host, pd.this_size,
            pd.file_size, pd.accumulated_size, pd.total_size));
        if (!result.is_none()) {
          if (py::isinstance<TransferControl>(result)) {
            SetState(py::cast<TransferControl>(result));
          }
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
                 const std::shared_ptr<HostMaintainer> &hostm,
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
      py::gil_scoped_acquire acquire;
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
          py::gil_scoped_acquire acquire;
          callback.error_cb(ErrorCBInfo(task.rc, task.src, task.dst,
                                        task.src_host, task.dst_host));
        }
      } else {
        task.IsSuccess = true;
      }
    }
    return tasksf;
  }

  std::pair<ECM, TASKS> load_tasks(const std::string &src,
                                   const std::string &dst,
                                   const std::shared_ptr<HostMaintainer> &hostm,
                                   const std::string &src_host = "",
                                   const std::string &dst_host = "",
                                   bool overwrite = false, bool mkdir = true,
                                   bool ignore_sepcial_file = true) {
    WRV result = {};
    TASKS tasks = {};
    ECM rc;
    std::shared_ptr<AMSFTPClient> src_client;
    // 去除src的dst左右端的空格
    if (!src_host.empty()) {
      rc = hostm->test_host(src_host);
      if (rc.first != EC::Success) {
        return {rc, tasks};
      }
    }
    if (!dst_host.empty()) {
      rc = hostm->test_host(dst_host);
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
      auto client = hostm->get_host(dst_host);
      if (!client) {
        return {
            ECM(EC::NoSession,
                fmt::format("Destination SFTP Client: {} not found", dst_host)),
            tasks};
      }
      dstf =
          AMFS::abspath(dst, true, client->GetHomeDir(), client->GetHomeDir());
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