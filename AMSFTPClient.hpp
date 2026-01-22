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
#include <fstream>
#include <memory>
#include <mutex>
#include <pybind11/pytypes.h>
#include <regex>
#include <string>
#include <vector>

// 标准库

// 自身依赖
#include "AMBaseClient.hpp"
#include "AMDataClass.hpp"
#include "AMEnum.hpp"
#include "AMPath.hpp"

// 自身依赖

// 第三方库
#include <curl/curl.h>
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

inline std::atomic<bool> is_wsa_initialized(false);

inline std::string GetLibssh2Version() {
  return libssh2_version(LIBSSH2_VERSION_NUM);
}
inline bool IsValidKey(const std::string &key) {
  std::ifstream file(key);
  if (!file.is_open())
    return false;

  std::string line;
  std::getline(file, line);

  // 匹配所有SSH私钥的标准开头标记
  const std::vector<std::string> private_key_headers = {
      "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----"};
  for (const auto &header : private_key_headers) {
    if (line.find(header) == 0) { // 开头匹配
      return true;
    }
  }
  return false;
}
inline bool isdir(const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
  return (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
         (attrs.permissions & LIBSSH2_SFTP_S_IFDIR);
}
inline bool isreg(const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
  return (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
         (attrs.permissions & LIBSSH2_SFTP_S_IFREG);
}
inline void cleanup_wsa();
// Wait result for non-blocking socket operations

class AMSession : public BaseClient {
protected:
  std::atomic<bool> has_connected;
  SOCKET sock = INVALID_SOCKET;
  // Optimized wait_for_socket: reduces overhead from frequent calls

  ECM ErrorRecord(int code, TraceLevel level, const std::string &taregt,
                  const std::string &action, std::string prompt = "") {
    if (code >= 0) {
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

  // 便捷宏/lambda 版本，用于更简洁的调用
  // 用法: auto result = nb_call(flag, timeout, [&]{ return
  // libssh2_sftp_unlink(sftp, path); });
  template <typename Func>
  auto nb_call(const amf interrupt_flag, int64_t timeout_ms, int64_t start_time,
               Func &&func) -> NBResult<decltype(func())> {
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

private:
  ECM CurError = {EC::NoConnection, "Connection not established"};
  bool password_auth_cb = false;
  std::vector<std::string> private_keys;
  py::function auth_cb = py::function(); // Callable[[IsPasswordDemand:bool,
                                         // ConRequst, TrialTimes:int], str]

  void LoadDefaultPrivateKeys() {
    trace(TraceLevel::Debug, EC::Success, "~/.ssh", "LoadDefaultPrivateKeys",
          "Shared private keys not provided, loading default private keys from "
          "~/.ssh");
    auto [error, listd] = AMFS::listdir("~/.ssh");
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

  inline WaitResult wait_for_socket(SocketWaitType wait_dir,
                                    const amf &flag = nullptr,
                                    int64_t start_time = -1,
                                    int64_t timeout_ms = -1,
                                    int poll_interval_ms = 20) {
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
      if (am_ms() - start_time >= timeout_ms) {
        return WaitResult::Timeout;
      }
    }

    // Pre-compute wait directions
    bool wait_read = false;
    bool wait_write = false;
    bool is_auto = (wait_dir == SocketWaitType::Auto);
    bool is_read_or_write = (wait_dir == SocketWaitType::ReadOrWrite);

    if (!is_auto) {
      switch (wait_dir) {
      case SocketWaitType::Read:
        wait_read = true;
        break;
      case SocketWaitType::Write:
        wait_write = true;
        break;
      case SocketWaitType::ReadWrite:
      case SocketWaitType::ReadOrWrite:
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
        // ReadOrWrite 模式下返回具体的读写状态
        if (is_read_or_write) {
          if (FD_ISSET(sock, &readfds)) {
            return WaitResult::ReadReady;
          }
          return WaitResult::WriteReady;
        }
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
        if (am_ms() - start_time >= timeout_ms) {
          return WaitResult::Timeout;
        }
      }
    }
  }

  std::vector<std::string> GetKeys() { return this->private_keys; }

  void SetKeys(const std::vector<std::string> &keys) {
    this->private_keys = keys;
  }

  ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
            int64_t start_time = -1) override {
    auto rcm = stat(".", false, interrupt_flag, timeout_ms, start_time).first;
    SetState(rcm);
    return rcm;
  }

  ECM BaseConnect(bool force = false, amf interrupt_flag = nullptr,
                  int64_t start_time = -1, int timeout_ms = -1) {
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    std::cout << "baseconnect start_time: " << start_time << std::endl;
    std::cout << "baseconnect timeout_ms: " << timeout_ms << std::endl;
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
      if (am_ms() - start_time >= timeout_ms) {
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
    while (true) {
      rcr = libssh2_session_handshake(session, sock);
      wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, start_time,
                           timeout_ms);
      if (wr != WaitResult::Ready) {
        goto interrupted_or_sock_error;
      }
      if (rcr != LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      std::cout << "libssh2_session_handshake: " << rcr << std::endl;
    }
    std::cout << "libssh2_session_handshake2: " << rcr << std::endl;
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
      wr = wait_for_socket(SocketWaitType::Auto, interrupt_flag, start_time,
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
      return rcm;
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

  PathInfo FormatStat(const std::string &path,
                      const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
    PathInfo info;
    info.path = path;
    info.name = AMPathStr::basename(path);
    info.dir = AMPathStr::dirname(path);
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

  std::pair<ECM, std::string> lib_realpath(const std::string &path,
                                           amf interrupt_flag = nullptr,
                                           int timeout_ms = -1,
                                           int64_t start_time = -1) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, ""};
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
                 int timeout_ms = -1, int64_t start_time = -1) {
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
  lib_getstat(const std::string &path, bool trace_link = false,
              amf interrupt_flag = nullptr, int timeout_ms = -1,
              int64_t start_time = -1) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"},
              LIBSSH2_SFTP_ATTRIBUTES()};
    }
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    NBResult<int> nb_res;
    if (trace_link) {
      nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
        return libssh2_sftp_stat(sftp, path.c_str(), &attrs);
      });
    } else {
      nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
        return libssh2_sftp_lstat(sftp, path.c_str(), &attrs);
      });
    }
    ECM rcm = ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_stat",
                          "Get stat failed: {error}");
    return {rcm, attrs};
  }

  ECM lib_setstat(const std::string &path, LIBSSH2_SFTP_ATTRIBUTES &attrs,
                  amf interrupt_flag = nullptr, int timeout_ms = -1,
                  int64_t start_time = -1) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_setstat(sftp, path.c_str(), &attrs);
    });
    return ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_setstat",
                       "Set stat failed: {error}");
  }

  ECM lib_unlink(const std::string &path, amf interrupt_flag = nullptr,
                 int timeout_ms = -1, int64_t start_time = -1) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_unlink(sftp, path.c_str());
    });
    return ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_unlink",
                       "Unlink \"{target}\" failed: {error}");
  }

  ECM lib_rmdir(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1, int64_t start_time = -1) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_rmdir(sftp, path.c_str());
    });
    return ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_rmdir",
                       "Remove directory failed: {error}");
  }

  ECM lib_mkdir(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1, int64_t start_time = -1) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    NBResult<int> nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
      return libssh2_sftp_mkdir_ex(sftp, path.c_str(), path.size(), 0740);
    });
    return ErrorRecord(nb_res, TraceLevel::Debug, path, "libssh2_sftp_mkdir_ex",
                       "Create directory \"{target}\" failed: {error}");
  }

  std::pair<ECM, std::vector<std::pair<std::string, LIBSSH2_SFTP_ATTRIBUTES>>>
  lib_listdir(const std::string &path, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, {}};
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
      if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
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
      file_list.emplace_back(AMPathStr::join(path, name), attrs);
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
              int64_t start_time = -1) {
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
      if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
        return;
      }
      _iwalk(attrs.first, attrs.second, result, ignore_sepcial_file,
             interrupt_flag, timeout_ms, start_time);
    }
  }

  void _walk(const std::vector<std::string> &parts, WRD &result,
             int cur_depth = 0, int max_depth = -1,
             bool ignore_sepcial_file = true, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) {
    if (max_depth != -1 && cur_depth > max_depth) {
      return;
    }
    if (interrupt_flag && interrupt_flag->check()) {
      return;
    }
    std::string pathf = AMPathStr::join(parts);
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
      if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
        return;
      }
      if (isdir(attrs)) {
        auto new_parts = parts;
        new_parts.push_back(AMPathStr::basename(path));
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
           int64_t start_time = -1) {
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
              int timeout_ms = -1, int64_t start_time = -1) {
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
        if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
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

public:
  AMSFTPClient(const ConRequst &request,
               const std::vector<std::string> &keys = {},
               unsigned int tracer_capacity = 10,
               const py::object &trace_cb = py::none(),
               const py::object &auth_cb = py::none())
      : AMSession(request, keys, tracer_capacity, trace_cb, auth_cb) {
    this->PROTOCOL = ClientProtocol::SFTP;
    if (request.trash_dir.empty()) {
      this->trash_dir = AMPathStr::join(GetHomeDir(), ".AMSFTP_Trash");
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

      auto start = -1;

      // stat "/" 是最轻量的操作
      int rc = libssh2_sftp_stat(sftp, "/", &attrs);

      auto end = -1;

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

    auto time_start = -1;
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
    default:
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
    auto [rcm, path_obj] = realpath("", nullptr, 3000, -1);
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

  ECM Connect(bool force = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1) override {
    bool not_init = has_connected;
    std::cout << "connect start_time: " << start_time << std::endl;
    std::cout << "connect timeout_ms: " << timeout_ms << std::endl;
    ECM ecm = BaseConnect(force, interrupt_flag, start_time, timeout_ms);
    if (!not_init && isok(ecm)) {
      GetOSType();
      GetHomeDir();
    }
    return ecm;
  }

  // 解析并返回绝对路径,
  // ~在client中解析，..和.其他由服务器解析，有这些符号时需要路径真实存在
  std::pair<ECM, std::string> realpath(const std::string &path,
                                       amf interrupt_flag = nullptr,
                                       int timeout_ms = -1,
                                       int64_t start_time = -1) override {
    auto pathf = path;
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return {rcm, ""};
    }
    if (std::regex_search(path, std::regex("^~[\\\\/]"))) {
      // 解析~符号
      pathf = AMPathStr::join(GetHomeDir(), pathf.substr(1), SepType::Unix);
    } else if (path == "~") {
      return {ECM{EC::Success, ""}, GetHomeDir()};
    }
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;

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
        int timeout_ms = -1, int64_t start_time = -1) override {
    if (static_cast<int>(GetOSType()) <= 0) {
      return {ECM{EC::UnImplentedMethod, "Chmod only supported on Unix System"},
              {}};
    }
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, attrs] =
        lib_getstat(path, false, interrupt_flag, timeout_ms, start_time);
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
  SR stat(const std::string &path, bool trace_link = false,
          amf interrupt_flag = nullptr, int timeout_ms = -1,
          int64_t start_time = -1) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return {rcm, PathInfo()};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    auto [rcm2, attrs] =
        lib_getstat(path, trace_link, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return {rcm2, PathInfo()};
    }
    return {rcm, FormatStat(path, attrs)};
  }

  std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1, int64_t start_time = -1) override {

    ECM rcm = _precheck(path);

    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
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

          path_i = AMPathStr::join(pathf, name);
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
            int timeout_ms = -1, int64_t start_time = -1) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    auto [rcm2, attrs] =
        lib_getstat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first == EC::Success) {
      if (isdir(attrs)) {
        return {EC::Success, ""};
      } else {
        return {EC::PathAlreadyExists,
                fmt::format("Path exists and is not a directory: {}", path)};
      }
    }
    return lib_mkdir(path, interrupt_flag, timeout_ms, start_time);
  }

  // 递归创建多级目录，直到报错为止，自带AMFS::abspath
  ECM mkdirs(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    std::vector<std::string> parts = AMPathStr::split(path);
    if (parts.empty()) {
      return {EC::InvalidArg,
              fmt::format("Path split failed, get empty parts: {}", path)};
    } else if (parts.size() == 1) {
      return lib_mkdir(path, interrupt_flag, timeout_ms, start_time);
    }

    std::string current_path = parts.front();
    for (size_t i = 1; i < parts.size(); i++) {
      current_path = AMPathStr::join(current_path, parts[i], SepType::Unix);
      rcm = lib_mkdir(current_path, interrupt_flag, timeout_ms, start_time);
      if (rcm.first != EC::Success) {
        return rcm;
      }
    }
    return rcm;
  }

  ECM rmfile(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    return lib_unlink(path, interrupt_flag, timeout_ms, start_time);
  }

  ECM rmdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1, int64_t start_time = -1) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    return lib_rmdir(path, interrupt_flag, timeout_ms, start_time);
  }

  // 删除文件或目录，自带AMFS::abspath
  std::pair<ECM, RMR> remove(const std::string &path,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) override {
    ECM rcm0 = _precheck(path);
    if (rcm0.first != EC::Success) {
      return {rcm0, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    RMR errors = {};
    auto [rcm, sr] =
        lib_getstat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    _rm(path, sr, errors, interrupt_flag, timeout_ms, start_time);
    return {ECM{EC::Success, ""}, errors};
  }

  // 将原路径变成新路径，自带AMFS::abspath
  ECM rename(const std::string &src, const std::string &dst, bool mkdir = true,
             bool overwrite = false, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
    ECM rcm0 = _precheck(src);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    ECM rcm1 = _precheck(dst);
    if (rcm1.first != EC::Success) {
      return rcm1;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    if (mkdir) {
      rcm0 = mkdirs(AMPathStr::dirname(dst), interrupt_flag, timeout_ms,
                    start_time);
      if (rcm0.first != EC::Success) {
        return rcm0;
      }
    }
    return lib_rename(src, dst, overwrite, interrupt_flag, timeout_ms,
                      start_time);
  }

  // 安全删除文件或目录，将目录移动到trash_dir中
  ECM saferm(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
    ECM rcm0 = _precheck(path);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    if (trash_dir.empty()) {
      return {EC::InvalidArg, "Trash directory not set"};
    }
    auto [rcm1, info] =
        lib_getstat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm1.first != EC::Success) {
      return rcm1;
    }
    std::string base = AMPathStr::basename(path);
    std::string base_name = base;
    std::string base_ext = "";
    std::string target_path;

    if (!isdir(info)) {
      auto base_info = AMPathStr::split_basename(base);
      base_name = base_info.first;
      base_ext = base_info.second;
    }

    // 获取当前时间，以2026-01-01-19-06格式
    std::string current_time =
        FormatTime(std::time(nullptr), "%Y-%m-%d-%H-%M-%S");

    target_path =
        AMPathStr::join(trash_dir, current_time, base_name + "." + base_ext);
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
      target_path = AMPathStr::join(trash_dir, current_time,
                                    (base_name_tmp + ".") += base_ext);
      i++;
    }

    rcm0 = mkdirs(AMPathStr::join(trash_dir, current_time), interrupt_flag,
                  timeout_ms, start_time);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }

    return lib_rename(path, target_path, false, interrupt_flag, timeout_ms,
                      start_time);
  }

  // 将源路径移动到目标文件夹

  /*
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

    std::string dst_path = AMPathStr::join(dstf, AMPathStr::basename(srcf));
    auto [rcm0, sbr0] = exists(dst_path);

    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    if (sbr0) {
      return {EC::PathAlreadyExists,
              fmt::format("Dst {} already has path named {}", dstf,
                          AMPathStr::basename(srcf))};
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
  }*/

  // 递归遍历某一路径下的所有文件和底层目录，返回PathInfo的vector
  std::pair<ECM, WRV> iwalk(const std::string &path,
                            bool ignore_sepcial_file = true,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) override {
    ECM rcm = _precheck(path);
    if (rcm.first != EC::Success) {
      return {};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    auto [rcm2, attrs] =
        lib_getstat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      return {};
    }
    if (!isdir(attrs)) {
      if (!isreg(attrs) && ignore_sepcial_file) {
        return {};
      }
      return {ECM{EC::Success, ""}, {FormatStat(path, attrs)}};
    }
    // get all files and deepest folders
    WRV result = {};
    _iwalk(path, attrs, result, ignore_sepcial_file, interrupt_flag, timeout_ms,
           start_time);
    return {ECM{EC::Success, ""}, result};
  }

  // 真实的walk函数，返回([root_path, part1, part2, ...], PathInfo)的vector
  std::pair<ECM, WRD> walk(const std::string &path, int max_depth = -1,
                           bool ignore_special_file = false,
                           amf interrupt_flag = nullptr, int timeout_ms = -1,
                           int64_t start_time = -1) override {
    ECM rcm0 = _precheck(path);
    if (rcm0.first != EC::Success) {
      return {rcm0, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    auto [rcm, br] = stat(path, false, interrupt_flag, timeout_ms, start_time);
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
};
