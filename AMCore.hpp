#pragma once
// 标准库
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <stdio.h>
#include <string>
#include <thread>
#include <time.h>
#include <vector>
// 标准库

// 自身依赖
#include "AMDataClass.hpp"
#include "AMEnum.hpp"
#include "AMPath.hpp"
// 自身依赖

// 第三方库
#include <fmt/core.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
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
using WRD = std::vector<
    std::pair<std::vector<std::string>, PathInfo>>; // walk函数返回类型
using WR = std::pair<ECM, WRV>;                     // iwalk函数返回类型
using SIZER = std::pair<ECM, uint64_t>;             // getsize函数返回类型
using CR =
    std::pair<ECM, std::pair<std::string, int>>; // ConductCmd函数返回类型

class AMTracer {
private:
  py::function trace_cb;
  std::vector<TraceInfo> buffer = {};
  size_t capacity = 10;
  std::atomic<bool> is_py_trace = false;
  std::atomic<bool> is_trace_pause = false;

  void push(const TraceInfo value) {
    if (buffer.size() < capacity) {
      buffer.push_back(value);
    } else {
      buffer.erase(buffer.begin());
      buffer.push_back(value);
    }
  }

public:
  std::string nickname;

  AMTracer(unsigned int buffer_capacity = 10, py::object trace_cb = py::none(),
           std::string nickname = "")
      : nickname(nickname) {
    if (buffer_capacity <= 0) {
      capacity = 10;
    } else {
      capacity = buffer_capacity;
    }
    if (!trace_cb.is_none()) {
      this->trace_cb = py::cast<py::function>(trace_cb);
      this->is_py_trace = true;
    } else {
      this->is_py_trace = false;
    }
  }

  size_t GetTracerSize() const { return buffer.size(); }

  size_t GetTracerCapacity() const { return capacity; }

  std::variant<py::object, TraceInfo> LastTrace() {
    if (buffer.size() == 0) {
      return py::none();
    }
    return buffer[buffer.size() - 1];
  }

  std::vector<TraceInfo> GetAllTraces() {
    std::vector<TraceInfo> result;
    for (auto &item : buffer) {
      result.push_back(item);
    }
    return result;
  }

  bool IsTracerEmpty() const { return buffer.size() == 0; }

  void ClearTracer() { buffer.clear(); }

  void SetTracerCapacity(unsigned int size) {
    if (size <= 0) {
      return;
    }

    if (size > capacity) {
      capacity = size;
    } else {
      buffer.resize(size);
      capacity = size;
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

  void PauseTrace() { is_trace_pause.store(true); }

  void ResumeTrace() { is_trace_pause.store(false); }

  void SetPyTrace(py::object trace = py::none()) {
    if (trace.is_none()) {
      is_py_trace.store(false);
      trace_cb = py::function();
    } else {
      trace_cb = py::cast<py::function>(trace);
      is_py_trace.store(true);
    }
  }
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

class AMSession : public AMTracer {
protected:
  std::atomic<bool> has_connected;

private:
  ECM CurError = {EC::NoConnection, "Connection not established"};
  std::mutex state_mtx;
  SOCKET sock = INVALID_SOCKET;
  bool password_auth_cb = false;
  std::vector<std::string> private_keys;
  py::function auth_cb = py::function(); // Callable[[IsPasswordDemand:bool,
                                         // ConRequst, TrialTimes:int], str]

  void LoadDefaultPrivateKeys() {
    trace(TraceLevel::Debug, EC::Success, res_data.nickname,
          "LoadDefaultPrivateKeys",
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

  void SetState(const ECM &state) {
    std::lock_guard<std::mutex> lock(state_mtx);
    CurError = state;
  }

  ECM BaseCheck() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    if (!session) {
      return {EC::NoSession, "Session not initialized"};
    }

    char path_t[1024];
    int rcr;
    {
      rcr = libssh2_sftp_realpath(sftp, ".", path_t, sizeof(path_t));
    }
    if (rcr < 0) {
      EC rc = GetLastEC();
      return std::make_pair(rc, "Sftp status check failed");
    }

    return {EC::Success, ""};
  }

public:
  LIBSSH2_SESSION *session = nullptr;
  LIBSSH2_SFTP *sftp = nullptr;
  ConRequst res_data;
  std::recursive_mutex mtx; // lock of the session and sftp

  ~AMSession() { Disconnect(); }

  AMSession(ConRequst request, std::vector<std::string> private_keys,
            unsigned int error_num = 10, py::object trace_cb = py::none(),
            py::object auth_cb = py::none())
      : AMTracer(error_num, trace_cb, request.nickname),
        private_keys(private_keys), res_data(request) {
    if (!auth_cb.is_none()) {
      this->auth_cb = py::cast<py::function>(auth_cb);
      this->password_auth_cb = true;
    }
    if (private_keys.empty()) {
      LoadDefaultPrivateKeys();
    }
    has_connected.store(false);
  }

  inline std::string GetNickname() { return this->nickname; }

  ConRequst GetRequest() { return this->res_data; }

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

  ECM GetState() {
    std::lock_guard<std::mutex> lock(state_mtx);
    return CurError;
  }

  ECM Check(bool need_trace = false) {
    ECM rc = BaseCheck();
    SetState(rc);
    if (!need_trace) {
      return rc;
    }
    if (rc.first != EC::Success) {
      trace(TraceLevel::Critical, rc.first, "home_path", "Check",
            "Sftp status check failed");
    } else {
      trace(TraceLevel::Info, EC::Success,
            fmt::format("{}@{}", res_data.nickname, "SSHSeesion"), "Check",
            "Session status check success");
    }
    return rc;
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
      trace(TraceLevel::Critical, connector.error_code, res_data.nickname,
            "ConnectSocket", connector.error_msg);
      return {connector.error_code, connector.error_msg};
    }
    sock = connector.sock;

    session = libssh2_session_init();
    if (!session) {
      trace(TraceLevel::Critical, EC::SessionCreateFailed, res_data.nickname,
            "SessionInit", "Session initialization failed");
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
      trace(TraceLevel::Critical, rc, res_data.nickname, "SessionHandshake",
            msg);
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
    trace(TraceLevel::Debug, EC::Success, res_data.nickname, "GetAuthList",
          fmt::format("Authentication methods: {}", auth_list));

    bool password_auth = false;
    if (strstr(auth_list, "password") != NULL) {
      password_auth = true;
    }

    rc = EC::AuthFailed;

    std::string password_tmp;
    if (!res_data.keyfile.empty()) {
      trace(TraceLevel::Debug, EC::Success, res_data.nickname,
            "PrivateKeyAuthorize",
            fmt::format("Using dedicated private key: {}", res_data.keyfile));
      rcr = libssh2_userauth_publickey_fromfile(
          session, res_data.username.c_str(), nullptr, res_data.keyfile.c_str(),
          nullptr);
      if (rcr == 0) {
        rc = EC::Success;
        msg = "";
        trace(TraceLevel::Info, EC::Success, res_data.nickname,
              "PrivateKeyAuthorize",
              fmt::format("Dedicated private key \"{}\" authorize success",
                          res_data.keyfile));
        goto OK;
      } else {
        msg = fmt::format("Dedicated private key \"{}\" authorize failed: {}",
                          res_data.keyfile, GetLastErrorMsg());
        rc = GetLastEC();
        trace(TraceLevel::Debug, rc, res_data.nickname, "PrivateKeyAuthorize",
              msg);
      }
    }
    if (!res_data.password.empty() && password_auth) {
      trace(TraceLevel::Debug, EC::Success, res_data.nickname,
            "PasswordAuthorize",
            fmt::format("Using  password to authorize: {}", res_data.password));
      rcr = libssh2_userauth_password(session, res_data.username.c_str(),
                                      res_data.password.c_str());
      if (rcr == 0) {
        rc = EC::Success;
        msg = "";
        trace(TraceLevel::Info, EC::Success, res_data.nickname,
              "PasswordAuthorize", "Password authorize success");
        goto OK;
      } else {
        rc = EC::AuthFailed;
        trace(TraceLevel::Debug, EC::AuthFailed, res_data.nickname,
              "PasswordAuthorize",
              fmt::format("Wrong Password: {}", res_data.password));
      }
    }
    if (!private_keys.empty()) {
      trace(TraceLevel::Debug, EC::Success, res_data.nickname,
            "PrivateKeyAuthorize",
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
          trace(TraceLevel::Info, EC::Success, res_data.nickname,
                "PrivateKeyAuthorize", msg);
          rc = EC::Success;
          goto OK;
        } else {
          msg = fmt::format("Shared private key \"{}\" authorize failed",
                            private_key);
          trace(TraceLevel::Debug, EC::PrivateKeyAuthFailed, res_data.nickname,
                "PrivateKeyAuthorize", msg);
        }
      }
    }

    if (password_auth_cb && password_auth) {
      trace(TraceLevel::Debug, EC::Success, res_data.nickname,
            "PasswordAuthorize",
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
          trace(TraceLevel::Info, EC::Success, res_data.nickname,
                "PasswordAuthorize", "Password authorize success");
          goto OK;
        } else {
          trace(TraceLevel::Debug, EC::AuthFailed, res_data.nickname,
                "PasswordAuthorize",
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
      trace(TraceLevel::Critical, EC::AuthFailed, res_data.nickname,
            "FinalAuthorizeState", "All authorize methods failed");
      return {rc, "All authorize methods failed"};
    }

    sftp = libssh2_sftp_init(session);
    if (!sftp) {
      rc = GetLastEC();
      msg = fmt::format("SFTP initialization failed: {}", GetLastErrorMsg());
      trace(TraceLevel::Critical, rc, res_data.nickname, "SFTPInitialization",
            msg);
      Disconnect();
      return {rc, msg};
    }

    // Start Heartbeat Thread
    has_connected.store(true);
    // is_heartbeat.store(true);
    // heartbeat_thread = std::thread([this]()
    //                                {
    //                                HeartbeatAct(this->heartbeat_interval_s);
    //                                });

    return {EC::Success, ""};
  }

  EC GetLastEC() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!session) {
      return EC::NoSession;
    }

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
      char *errmsg = NULL;
      int errmsg_len;
      int errcode =
          libssh2_session_last_error(session, &errmsg, &errmsg_len, 0);
      if (errcode != 0) {
        return "Unknown session error";
      }
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

  void SetAuthCallback(py::object auth_cb = py::none()) {
    if (auth_cb.is_none()) {
      this->password_auth_cb = false;
      this->auth_cb = py::function();
    } else {
      this->auth_cb = py::cast<py::function>(auth_cb);
      this->password_auth_cb = true;
    }
  }
};

class BaseSFTPClient : public AMSession {

public:
  OS_TYPE os_type = OS_TYPE::Uncertain;
  std::string home_dir = "";
  std::string trash_dir = "";
  // std::lock_guard<std::recursive_mutex> lock(mtx);

  BaseSFTPClient(ConRequst request, std::vector<std::string> keys,
                 unsigned int error_num = 10, py::object trace_cb = py::none(),
                 py::object auth_cb = py::none())
      : AMSession(request, keys, error_num, trace_cb, auth_cb) {
    if (request.trash_dir.empty()) {
      this->trash_dir = "./.AMSFTP_Trash";
    } else {
      this->trash_dir = request.trash_dir;
    }
  }

  double GetRTT(uint64_t times = 5) {
    double total_time = 0;
    double time_start;
    double time_end;
    int rc;
    for (uint64_t i = 0; i < times; i++) {
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

  CR ConductCmd(const std::string &cmd) {
    SafeChannel sf(session);
    if (!sf.channel) {
      return {ECM{EC::NoConnection, "Channel not initialized"},
              std::pair<std::string, int>("", -1)};
    }

    int out;
    {
      out = libssh2_channel_exec(sf.channel, cmd.c_str());
    }
    EC error_code;
    std::string error_msg;

    if (out < 0) {
      error_code = GetLastEC();
      error_msg = fmt::format("{} Host channel operation failed: {}",
                              res_data.nickname, GetLastErrorMsg());
      return {ECM{error_code, error_msg}, std::pair<std::string, int>("", -1)};
    }

    char cmd_out[4096];
    int nbytes;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      nbytes = libssh2_channel_read(sf.channel, cmd_out, sizeof(cmd_out) - 1);
    }

    if (nbytes < 0) {
      error_code = GetLastEC();
      error_msg = fmt::format("{} Host channel output read failed: {}",
                              res_data.nickname, GetLastErrorMsg());
      return {ECM{error_code, error_msg}, std::pair<std::string, int>("", -1)};
    }

    int exit_status;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      exit_status = libssh2_channel_get_exit_status(sf.channel);
    }
    std::string output(cmd_out, nbytes);
    output.erase(std::find_if(output.rbegin(), output.rend(),
                              [](char c) { return c != '\n' && c != '\r'; })
                     .base(),
                 output.end());
    return {ECM{EC::Success, ""},
            std::pair<std::string, int>(output, exit_status)};
  }

  OS_TYPE GetOSType(const bool &update = false) {
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
    os_type = OS_TYPE::Unknown;
    return os_type;
  }
};

class AMSFTPClient : public BaseSFTPClient, public AMFS::BasePathMatch {
private:
  std::map<long, std::string> user_id_map;
  bool is_trash_dir_ensure = false;
  std::unordered_map<std::string, py::object> public_var_dict;
  std::mutex public_var_mutex; // 专门用于保护 public_var_dict 的锁
  py::object deepcopy_func;    // 缓存的 deepcopy 函数

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

  void _walk(std::vector<std::string> parts, WRD &result, int cur_depth = 0,
             int max_depth = -1, bool ignore_sepcial_file = true) {
    if (max_depth != -1 && cur_depth > max_depth) {
      return;
    }
    std::string path = AMFS::join(parts);
    auto [rcm, info_path] = stat(path);
    if (rcm.first != EC::Success) {
      return;
    }
    if (info_path.type != PathType::DIR) {
      return;
    }
    auto [rcm2, list_info] = listdir(path);
    if (rcm2.first != EC::Success) {
      return;
    }
    if (list_info.empty()) {
      if (parts.size() == 1) {
        return;
      }
      std::vector<std::string> ta = parts;
      ta.pop_back();
      result.push_back(std::make_pair(ta, info_path));
      return;
    }

    for (auto &info : list_info) {
      if (info.type == PathType::DIR) {
        auto new_parts = parts;
        new_parts.push_back(info.name);
        _walk(new_parts, result, cur_depth + 1, max_depth, ignore_sepcial_file);
      } else {
        if (ignore_sepcial_file && static_cast<int>(info.type) < 0) {
          continue;
        }
        auto t_parts = parts;
        t_parts.push_back(info.name);
        result.push_back(std::make_pair(t_parts, info));
      }
    }
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
              std::map<std::string, ECM> &errors) {
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
      std::cout << "rcr: " << rcr << std::endl;
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
              std::map<std::string, ECM> &errors) {
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
      std::cout << "rcr: " << rcr << std::endl;
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

  AMSFTPClient(ConRequst request, std::vector<std::string> keys,
               unsigned int error_num = 10, py::object trace_cb = py::none(),
               py::object auth_cb = py::none())
      : BaseSFTPClient(request, keys, error_num, trace_cb, auth_cb),
        AMFS::BasePathMatch() {
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

  bool HasPublicVar(const std::string &key) {
    std::lock_guard<std::mutex> lock(public_var_mutex);
    return public_var_dict.find(key) != public_var_dict.end();
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

  std::string StrUid(const long &uid) {
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

  std::string GetHomeDir(const bool &update = false) {
    if (!home_dir.empty() && !update) {
      return home_dir;
    }
    auto [rcm, path_obj] = realpath("");
    if (rcm.first == EC::Success) {
      home_dir = path_obj;
      return home_dir;
    }
    switch (GetOSType()) {
    case OS_TYPE::Windows:
      return "C:\\Users\\" + res_data.username;
    case OS_TYPE::Linux:
      return "/home/" + res_data.username;
    case OS_TYPE::MacOS:
      return "/Users/" + res_data.username;
    case OS_TYPE::FreeBSD:
      return "/usr/home/" + res_data.username;
    case OS_TYPE::Unix:
      return "/home/" + res_data.username;
    default:
      return "";
    }
  }

  ECM Connect(bool force = false) {
    bool not_init = has_connected;
    ECM ecm = BaseConnect(force);
    if (!not_init && isok(ecm)) {
      GetOSType();
      GetHomeDir();
    }
    return ecm;
  }

  inline std::string GetTrashDir() { return this->trash_dir; }

  ECM SetTrashDir(std::string trash_dir = "") {
    this->trash_dir = trash_dir;
    return EnsureTrashDir();
  }

  ECM EnsureTrashDir() {
    std::string tmp_trash_dir =
        this->trash_dir.empty() ? ".AMSFTP_Trash" : this->trash_dir;
    tmp_trash_dir =
        AMFS::abspath(tmp_trash_dir, true, GetHomeDir(), GetHomeDir());
    this->trash_dir = tmp_trash_dir;
    auto [rcm, br] = is_dir(tmp_trash_dir);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (br) {
      // 是目录说明创建成功
      is_trash_dir_ensure = true;
      return {EC::Success, ""};
    } else {
      // 不是目录，说明路径中已经有文件存在，冲突报错
      is_trash_dir_ensure = false;
      return {
          EC::NotADirectory,
          fmt::format("Trash directory path exists but is not a directory: {}",
                      tmp_trash_dir)};
    }

    ECM res = mkdirs(tmp_trash_dir);
    if (res.first != EC::Success) {
      is_trash_dir_ensure = false;
      trace(TraceLevel::Critical, EC::Success,
            fmt::format("{}@{}", res_data.nickname, "TrashDir"),
            "EnsureTrashDir",
            fmt::format("Fail to set trash_dir to: \"{}\"", tmp_trash_dir));
      return res;
    } else {
      is_trash_dir_ensure = true;
      return {EC::Success, ""};
    }
  }

  // 解析并返回绝对路径,
  // ~在client中解析，..和.其他由服务器解析，有这些符号时需要路径真实存在
  std::pair<ECM, std::string> realpath(const std::string &path) {
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
    char path_t[1024];
    int rcr;
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      rcr = libssh2_sftp_realpath(sftp, pathf.c_str(), path_t, sizeof(path_t));
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
        return {ECM{EC::Success, ""}, std::string(path_t).substr(1)};
      }
      return {ECM{EC::Success, ""}, std::string(path_t)};
    }
  }

  std::variant<std::map<std::string, ECM>, ECM>
  chmod(const std::string &path, std::variant<std::string, uint64_t> mode,
        bool recursive = false) {
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
    std::map<std::string, ECM> ecm_map{};

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
  SR stat(const std::string &path) {
    std::string pathf = AMFS::abspath(path, true, GetHomeDir());

    if (pathf.empty()) {
      return {ECM{EC::InvalidArg, fmt::format("Invalid path: {}", path)},
              PathInfo()};
    }

    return lib_stat(pathf);
  }

  std::pair<ECM, PathType> get_path_type(const std::string &path) {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {ECM{rcm.first, rcm.second}, PathType::Unknown};
    }
    return {rcm, path_info.type};
  }

  // 判断路径是否存在，自带AMFS::abspath
  std::pair<ECM, bool> exists(const std::string &path) {
    auto [rcm, path_info] = stat(path);
    if (rcm.first == EC::Success) {
      return {rcm, true};
    } else if (rcm.first == EC::PathNotExist || rcm.first == EC::FileNotExist) {
      return {rcm, false};
    } else {
      return {rcm, false};
    }
  }

  std::pair<ECM, bool> is_regular(const std::string &path) {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::FILE ? true : false};
  }

  std::pair<ECM, bool> is_dir(const std::string &path) {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::DIR ? true : false};
  }

  std::pair<ECM, bool> is_symlink(const std::string &path) {
    auto [rcm, path_info] = stat(path);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::SYMLINK ? true : false};
  }

  std::pair<ECM, std::vector<PathInfo>> listdir(const std::string &path,
                                                long max_time_ms = -1) {
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
      return {ECM{EC::Success, ""}, file_list};
    } else {
      return {ECM{rc, msg}, {}};
    }
  }

  // 创建一级目录，自带AMFS::abspath
  ECM mkdir(const std::string &path) {
    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }

    std::string pathf = AMFS::abspath(path, true, GetHomeDir(), GetHomeDir());
    if (pathf.empty()) {
      return std::make_pair(EC::InvalidArg,
                            fmt::format("Invalid path: {}", path));
    }

    std::string msg = "";
    auto [rcm, br] = is_dir(pathf);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (!br) {
      return {EC::PathAlreadyExists,
              fmt::format("Path exists and is not a directory: {}", pathf)};
    } else {
      return {EC::Success, ""};
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
  ECM mkdirs(const std::string &path) {
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

  ECM rmfile(const std::string &path) {
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

  ECM rmdir(const std::string &path) {
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
  std::variant<RMR, ECM> remove(const std::string &path) {
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
             bool overwrite = false) {
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
  ECM saferm(const std::string &path) {
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
      target_path =
          AMFS::join(trash_dir, current_time, base_name_tmp + "." + base_ext);
      i++;
    }

    mkdirs(AMFS::join(trash_dir, current_time));
    return lib_rename(path, target_path, false);
  }

  // 将源路径移动到目标文件夹，自带AMFS::abspath
  ECM move(const std::string &src, const std::string &dst,
           bool need_mkdir = false, bool force_write = false) {
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
  WRV iwalk(const std::string &path, bool ignore_sepcial_file = true) {
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
                           bool ignore_special_file = true) {
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
  uint64_t getsize(const std::string &path, bool ignore_sepcial_file = true) {
    WRV list = iwalk(path, ignore_sepcial_file);
    uint64_t size = 0;
    for (auto &item : list) {
      size += item.size;
    }
    return size;
  }
};

class HostMaintainer {
private:
  std::unordered_map<std::string, std::shared_ptr<AMSFTPClient>> hosts;
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

  std::vector<std::shared_ptr<AMSFTPClient>> get_clients() {
    std::vector<std::shared_ptr<AMSFTPClient>> client_list;
    for (auto &host : hosts) {
      client_list.push_back(host.second);
    }
    return client_list;
  }

  void add_host(const std::string &nickname,
                std::shared_ptr<AMSFTPClient> client, bool overwrite = false) {
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

  std::shared_ptr<AMSFTPClient> get_host(const std::string &nickname) {
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
  inline void InnerCallback(const std::string &src, const std::string &dst,
                            const std::string &src_host,
                            const std::string &dst_host, uint64_t this_size,
                            uint64_t file_size, uint64_t accumulated_size,
                            uint64_t total_size) {
    if (callback.need_progress_cb) {
      auto time_now = timenow();
      if ((time_now - cb_time) > cb_interval_s) {
        cb_time = time_now;
        py::gil_scoped_acquire acquire;
        py::object result = callback.progress_cb(
            ProgressCBInfo(src, dst, src_host, dst_host, this_size, file_size,
                           accumulated_size, total_size));
        if (!result.is_none()) {
          if (py::isinstance<TransferControl>(result)) {
            auto control = result.cast<TransferControl>();
            switch (control) {
            case TransferControl::Pause:
              pause();
              break;
            case TransferControl::Terminate:
              terminate();
              break;
            default:
              break;
            }
          }
        }
      }
    }
  }

  ECM Local2Local(const std::string &src, const std::string &dst,
                  uint64_t chunk_size) {
    ErrorCode rc_r = EC::Success;
    std::string error_msg = "";
    FileMapper srcm(src, MapType::Read, error_msg);
    if (!srcm.file_ptr) {
      EC rc = EC::LocalFileMapError;
      return {rc, error_msg};
    }
    AMFS::mkdirs(AMFS::dirname(dst));
    FileMapper dstm(dst, MapType::Write, error_msg);
    if (!dstm.file_ptr) {
      EC rc = EC::LocalFileMapError;
      return {rc, error_msg};
    }

    uint64_t offset = 0;
    uint64_t remaining = srcm.file_size;
    uint64_t buffer_size;
    uint64_t local_size = 0;
    py::object result;
    char *src_ptr = static_cast<char *>(srcm.file_ptr);
    char *dst_ptr = static_cast<char *>(dstm.file_ptr);

    while (remaining > 0) {

      local_size = 0;
      buffer_size = std::min<uint64_t>(chunk_size, remaining);

      while (local_size < buffer_size) {
        // 使用两个文件映射进行读写
        CopyMemory(dst_ptr + offset, src_ptr + offset,
                   static_cast<SIZE_T>(buffer_size));
      }

      remaining -= buffer_size;
      offset += buffer_size;
      current_size += buffer_size;
      InnerCallback(src, dst, "", "", offset, srcm.file_size, current_size,
                    total_size);

      while (IsPause() && !IsTerminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
      }

      if (IsTerminate()) {
        rc_r = EC::Terminate;
        error_msg = "Transfer cancelled";
        goto clean;
      }
    }

  clean:
    if (callback.need_progress_cb) {
      py::gil_scoped_acquire acquire;
      callback.progress_cb(ProgressCBInfo(
          src, dst, "", "", offset, srcm.file_size, current_size, total_size));
    }

    return {rc_r, error_msg};
  }

  ECM Local2Remote(const std::string &src, const std::string &dst,
                   std::shared_ptr<AMSFTPClient> client, uint64_t chunk_size) {
    ErrorCode rc_r = EC::Success;
    LIBSSH2_SFTP_HANDLE *sftpFile;
    std::string error_msg = "Error to create FileMapper";
    std::lock_guard<std::recursive_mutex> lock(client->mtx);
    client->mkdirs(AMFS::dirname(dst));
    sftpFile = libssh2_sftp_open(
        client->sftp, dst.c_str(),
        LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);
    if (!sftpFile) {
      std::string msg = fmt::format("Failed to open remote file: {}, cause {}",
                                    dst, client->GetLastErrorMsg());
      rc_r = client->GetLastEC();
      client->trace(TraceLevel::Error, rc_r,
                    fmt::format("{}@{}", client->res_data.nickname, dst),
                    "Remote2Local", msg);
      return {rc_r, msg};
    }

    FileMapper l_file_m(src, MapType::Read, error_msg);
    if (!l_file_m.file_ptr) {
      libssh2_sftp_close_handle(sftpFile);
      EC rc = EC::LocalFileMapError;
      return {rc, error_msg};
    }

    uint64_t offset = 0;
    uint64_t remaining = l_file_m.file_size;
    uint64_t buffer_size;
    uint64_t local_size = 0;
    py::object result;

    long rc;

    while (remaining > 0) {
      local_size = 0;
      buffer_size = std::min<uint64_t>(chunk_size, remaining);

      while (local_size < buffer_size) {

        rc = libssh2_sftp_write(sftpFile,
                                l_file_m.file_ptr + offset + local_size,
                                buffer_size - local_size);

        if (rc > 0) {
          local_size += rc;
        } else if (rc == 0) {
          if (local_size < buffer_size) {
            rc_r = EC::UnexpectedEOF;
          }
          goto clean;
        } else {
          rc_r = EC::ConnectionLost;
          error_msg =
              fmt::format("Sftp write error: {}", client->GetLastErrorMsg());
          goto clean;
        }
      }

      remaining -= buffer_size;
      offset += buffer_size;
      current_size += buffer_size;
      InnerCallback(src, dst, "", client->GetNickname(), offset,
                    l_file_m.file_size, current_size, total_size);

      while (IsPause() && !IsTerminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }

      if (IsTerminate()) {
        rc_r = EC::Terminate;
        error_msg = "Transfer cancelled";
        goto clean;
      }
    }
  clean:
    if (callback.need_progress_cb) {
      py::gil_scoped_acquire acquire;
      callback.progress_cb(ProgressCBInfo(src, dst, "", client->GetNickname(),
                                          offset, l_file_m.file_size,
                                          current_size, total_size));
    }

    if (sftpFile) {
      libssh2_sftp_close_handle(sftpFile);
    }

    return {rc_r, error_msg};
  }

  ECM Remote2Local(const std::string &src, const std::string &dst,
                   std::shared_ptr<AMSFTPClient> client, uint64_t chunk_size) {
    EC rc_r = EC::Success;
    LIBSSH2_SFTP_HANDLE *sftpFile;
    std::string error_msg = "";
    std::lock_guard<std::recursive_mutex> lock(client->mtx);
    sftpFile =
        libssh2_sftp_open(client->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);
    if (!sftpFile) {
      rc_r = client->GetLastEC();
      std::string msg = fmt::format("Failed to open remote file: {}, cause {}",
                                    src, client->GetLastErrorMsg());
      client->trace(TraceLevel::Error, rc_r,
                    fmt::format("{}@{}", client->res_data.nickname, src),
                    "Remote2Local", msg);
      return {rc_r, msg};
    }

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_fstat(sftpFile, &attrs);
    uint64_t file_size = attrs.filesize;
    if (file_size == 0) {
      rc_r = client->GetLastEC();
      error_msg = fmt::format("Failed to get remote file size, cause {}", src,
                              client->GetLastErrorMsg());
      libssh2_sftp_close_handle(sftpFile);
      client->trace(TraceLevel::Error, rc_r,
                    fmt::format("{}@{}", client->res_data.nickname, src),
                    "Remote2Local", error_msg);
      return {rc_r, error_msg};
    }

    AMFS::mkdirs(AMFS::dirname(dst));
    FileMapper l_file_m(dst, MapType::Write, error_msg, file_size);

    if (!l_file_m.file_ptr) {
      rc_r = EC::LocalFileMapError;
      libssh2_sftp_close_handle(sftpFile);
      client->trace(TraceLevel::Error, rc_r, fmt::format("Local@{}", dst),
                    "Remote2Local", error_msg);
      return {rc_r, error_msg};
    }

    uint64_t buffer_size;
    uint64_t offset = 0;
    uint64_t local_size = 0;
    long bytes;
    py::object result;

    while (offset < file_size) {
      buffer_size = std::min<uint64_t>(chunk_size, file_size - offset);
      local_size = 0;
      while (local_size < buffer_size) {
        bytes =
            libssh2_sftp_read(sftpFile, l_file_m.file_ptr + offset + local_size,
                              buffer_size - local_size);
        if (bytes > 0) {
          local_size += bytes;
        }

        else if (bytes == 0) {
          if (offset < file_size) {
            rc_r = EC::UnexpectedEOF;
          }
          goto clean;
        } else {
          rc_r = EC::ConnectionLost;
          error_msg =
              fmt::format("Sftp read error: {}", client->GetLastErrorMsg());
          goto clean;
        }
      }
      offset += buffer_size;
      current_size += buffer_size;
      InnerCallback(src, dst, client->GetNickname(), "", offset, file_size,
                    current_size, total_size);

      while (IsPause() && !IsTerminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }

      if (IsTerminate()) {
        rc_r = EC::Terminate;
        error_msg = "Transfer cancelled";
        goto clean;
      }
    }

  clean:
    if (callback.need_progress_cb) {
      py::gil_scoped_acquire acquire;
      callback.progress_cb(ProgressCBInfo(src, dst, client->GetNickname(), "",
                                          offset, file_size, current_size,
                                          total_size));
    }
    if (sftpFile) {
      libssh2_sftp_close_handle(sftpFile);
    }
    return {rc_r, error_msg};
  }

  ECM Bridge(const std::string &src, const std::string &dst,
             std::shared_ptr<AMSFTPClient> src_worker,
             std::shared_ptr<AMSFTPClient> dst_worker,
             uint64_t chunk_size = 256 * AMKB) {

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
    StreamRingBuffer ring(chunk_size);
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
            rc_final = src_worker->GetLastEC();
            error_msg = fmt::format("Sftp read error: {}",
                                    src_worker->GetLastErrorMsg());
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
            rc_final = dst_worker->GetLastEC();
            error_msg = fmt::format("Sftp write error: {}",
                                    dst_worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 进度回调（每写入buffer_size或完成时触发）===
      if (all_write - last_callback_write >= chunk_size ||
          all_write == file_size) {
        current_size += (all_write - last_callback_write);
        last_callback_write = all_write;
        InnerCallback(src, dst, src_worker->GetNickname(),
                      dst_worker->GetNickname(), all_write, file_size,
                      current_size, total_size);

        // 暂停/终止检查
        while (IsPause() && !IsTerminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (IsTerminate()) {
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

    if (callback.need_progress_cb) {
      py::gil_scoped_acquire acquire;
      callback.progress_cb(ProgressCBInfo(src, dst, src_worker->GetNickname(),
                                          dst_worker->GetNickname(), all_write,
                                          file_size, current_size, total_size));
    }

    if (srcFile) {
      libssh2_sftp_close_handle(srcFile);
    }

    if (dstFile) {
      libssh2_sftp_close_handle(dstFile);
    }

    return {rc_final, error_msg};
  }

  std::pair<ECM, PathInfo> Ustat(const std::string &path,
                                 std::shared_ptr<HostMaintainer> hostm,
                                 std::string nickname = "") {
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
                               std::shared_ptr<HostMaintainer> hostm,
                               std::string nickname = "",
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

public:
  TransferCallback callback;
  float cb_interval_s;
  std::atomic<bool> is_terminate = false;
  std::atomic<bool> is_pause = false;
  uint64_t current_size = 0;
  long long total_size = 0;
  std::string current_filename = "";
  double cb_time = timenow();

  AMSFTPWorker(TransferCallback callback = TransferCallback(),
               float cb_interval_s = 0.2)
      : callback(callback), cb_interval_s(cb_interval_s) {}

  inline void reset() {
    cb_time = timenow();
    current_size = 0;
    total_size = 0;
    current_filename = "";
    is_terminate.store(false, std::memory_order_relaxed);
    is_pause.store(false, std::memory_order_relaxed);
  }

  inline void terminate() {
    is_terminate.store(true, std::memory_order_release);
  }

  inline void pause() { is_pause.store(true, std::memory_order_relaxed); }

  inline void resume() { is_pause.store(false, std::memory_order_release); }

  inline bool IsTerminate() {
    return is_terminate.load(std::memory_order_acquire);
  }

  inline bool IsPause() { return is_pause.load(std::memory_order_acquire); }

  inline bool IsRunning() {
    return !is_terminate.load(std::memory_order_acquire) &&
           !is_pause.load(std::memory_order_acquire);
  }

  inline void set_cb_interval(float interval_s) {
    this->cb_interval_s = interval_s;
  }

  TASKS EraseOverlapTasks(TASKS &tasks) {
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

  TASKS transfer(TASKS tasks, std::shared_ptr<HostMaintainer> hostm,
                 uint64_t chunk_large = 16 * AMMB,
                 uint64_t chunk_middle = 2 * AMMB,
                 uint64_t chunk_small = 256 * AMKB) {
    if (tasks.empty()) {
      return {};
    }

    std::unordered_map<std::string, std::string> host_status{};
    reset();

    if (callback.need_total_size_cb) {
      uint64_t total_size = 0;
      for (auto &task : tasks) {
        total_size += task.size;
      }
      py::gil_scoped_acquire acquire;
      callback.total_size_cb(total_size);
    }
    std::string src_path;
    std::string dst_path;
    std::string src_host;
    std::string dst_host;
    std::shared_ptr<AMSFTPClient> src_client;
    std::shared_ptr<AMSFTPClient> dst_client;
    ECM rc;

    tasks = EraseOverlapTasks(tasks);
    for (auto &task : tasks) {
      if (task.IsSuccess) {
        // 跳过在load_tasks中，未设置overlap且dst已经存在的任务
        continue;
      }

      if (callback.need_progress_cb) {
        py::gil_scoped_acquire acquire;
        callback.progress_cb(ProgressCBInfo(task.src, task.dst, task.src_host,
                                            task.dst_host, 0, task.size,
                                            current_size, total_size));
      }

      if (IsTerminate()) {
        rc = ECM(EC::Terminate, "Transfer cancelled");
        goto check;
      }
      src_host = task.src_host;
      dst_host = task.dst_host;

      if (task.path_type == PathType::DIR) {
        if (dst_host.empty()) {
          std::string errors = AMFS::mkdirs(task.dst);
          if (!errors.empty()) {
            rc = ECM(EC::UnknownError, errors);
            goto check;
          }
          goto check;
        }
        rc = hostm->test_host(dst_host);
        if (rc.first != EC::Success) {
          goto check;
        }
        dst_client = hostm->get_host(dst_host);
        if (!dst_client) {
          rc = ECM(EC::NoSession, "Destination SFTP Client not found");
          goto check;
        }
        rc = dst_client->mkdirs(task.dst);
        goto check;
      }

      if (src_host.empty() && dst_host.empty()) {
        // local2local
        if (fs::exists(task.dst) && !task.overwrite) {
          rc = ECM{EC::PathAlreadyExists,
                   fmt::format("Dst already exists: {}", task.dst)};
          goto check;
        }
        rc = Local2Local(task.src, task.dst, chunk_large);
      } else if (src_host.empty() && !dst_host.empty()) {
        // local2remote
        rc = hostm->test_host(dst_host);
        if (rc.first != EC::Success) {
          goto check;
        }
        dst_client = hostm->get_host(dst_host);
        if (!dst_client) {
          rc = ECM(EC::NoSession, "Destination SFTP Client not found");
          goto check;
        }
        auto [rcmt, br] = dst_client->exists(task.dst);
        if (rcmt.first != EC::Success) {
          rc = rcmt;
          goto check;
        } else if (br && !task.overwrite) {
          rc = ECM{EC::PathAlreadyExists,
                   fmt::format("Dst already exists: {}", task.dst)};
          goto check;
        }
        rc = Local2Remote(task.src, task.dst, dst_client, chunk_middle);
      } else if (!src_host.empty() && dst_host.empty()) {
        // remote2local
        if (fs::exists(task.dst) && !task.overwrite) {
          rc = ECM{EC::PathAlreadyExists,
                   fmt::format("Dst already exists: {}", task.dst)};
          goto check;
        }
        rc = hostm->test_host(src_host);
        if (rc.first != EC::Success) {
          goto check;
        }
        src_client = hostm->get_host(src_host);
        if (!src_client) {
          rc = ECM(EC::NoSession, "Source SFTP Client not found");
          goto check;
        }
        rc = Remote2Local(task.src, task.dst, src_client, chunk_middle);
      } else {
        // remote2remote
        rc = hostm->test_host(src_host);
        if (rc.first != EC::Success) {
          goto check;
        }
        rc = hostm->test_host(dst_host);
        if (rc.first != EC::Success) {
          goto check;
        }
        src_client = hostm->get_host(src_host);
        if (!src_client) {
          rc = ECM(EC::NoSession, "Source SFTP Client not found");
          goto check;
        }
        dst_client = hostm->get_host(dst_host);
        if (!dst_client) {
          rc = ECM(EC::NoSession, "Destination SFTP Client not found");
          goto check;
        }
        auto [rcmp, br2] = dst_client->exists(task.dst);
        if (rcmp.first != EC::Success) {
          rc = rcmp;
          goto check;
        } else if (br2 && !task.overwrite) {
          rc = ECM{EC::PathAlreadyExists,
                   fmt::format("Dst already exists: {}", task.dst)};
          goto check;
        }
        rc = Bridge(task.src, task.dst, src_client, dst_client, chunk_small);
      }
    check:
      task.rc = rc;
      if (rc.first != EC::Success) {
        if (callback.need_error_cb && rc.first != EC::Terminate) {
          py::gil_scoped_acquire acquire;
          callback.error_cb(
              ErrorCBInfo(rc, src_path, dst_path, src_host, dst_host));
        }
      } else {
        task.IsSuccess = true;
      }
    }

    return tasks;
  }

  std::pair<ECM, TASKS> load_tasks(const std::string &src,
                                   const std::string &dst,
                                   std::shared_ptr<HostMaintainer> hostm,
                                   std::string src_hostname = "",
                                   std::string dst_hostname = "",
                                   bool overwrite = false, bool mkdir = true,
                                   bool ignore_sepcial_file = true) {
    WRV result = {};
    TASKS tasks = {};
    ECM rc;
    std::shared_ptr<AMSFTPClient> src_client;
    // 去除src的dst左右端的空格
    rc = hostm->test_host(src_hostname);
    if (rc.first != EC::Success) {
      return {rc, tasks};
    }
    rc = hostm->test_host(dst_hostname);
    if (rc.first != EC::Success) {
      return {rc, tasks};
    }

    auto [rcm, src_stat] = Ustat(src, hostm, src_hostname);

    if (rcm.first != EC::Success) {
      return {rcm, tasks};
    }

    std::string srcf = src_stat.path;
    std::string dstf;
    if (dst_hostname.empty()) {
      dstf = AMFS::abspath(dst);
    } else {
      auto client = hostm->get_host(dst_hostname);
      if (!client) {
        return {ECM(EC::NoSession,
                    fmt::format("Destination SFTP Client: {} not found",
                                dst_hostname)),
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

    auto [rcm2, dst_info] = Ustat(dstf, hostm, dst_hostname);

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

      // 检验目标路径是否存在
      if (rcm2.first == EC::Success) {
        if (dst_info.type == PathType::DIR) {
          return {ECM(EC::NotADirectory,
                      fmt::format("Dst already exists and is a directory: {}",
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
          Ustat(AMFS::dirname(dstf), hostm, dst_hostname);
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

      tasks.push_back(TransferTask(srcf, src_hostname, dstf, dst_hostname,
                                   src_stat.size, src_stat.type, overwrite));
      return {ECM(EC::Success, ""), tasks};
    }

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

    auto result2 = Uiwalk(srcf, hostm, src_hostname, ignore_sepcial_file);

    std::string dst_n;
    for (auto &item : result2) {
      dst_n = AMFS::join(dstf, fs::relative(item.path, AMFS::dirname(srcf)));
      tasks.push_back(TransferTask(item.path, src_hostname, dst_n, dst_hostname,
                                   item.size, item.type, overwrite));
    }
    return {ECM(EC::Success, ""), tasks};
  };
};
