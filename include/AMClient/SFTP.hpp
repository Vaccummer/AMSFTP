#pragma once
// standard library
#include "AMBase/Enum.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>
#ifdef _WIN32
#define _WINSOCKAPI_
#include <shlobj.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

// project headers
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMClient/Base.hpp"

#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

// Socket wait direction
enum class SocketWaitType {
  Read,        // Wait for socket readable
  Write,       // Wait for socket writable
  ReadWrite,   // Wait for both readable and writable
  ReadOrWrite, // Wait for readable or writable, returns ReadReady/WriteReady
  Auto         // Determine from libssh2_session_block_directions
};

// Cross-platform socket connector
class SocketConnector {
public:
  SOCKET sock = INVALID_SOCKET;
  std::string error_msg = "";
  EC error_code = EC::Success;

  SocketConnector() = default;

  ~SocketConnector() {}

  /**
   * @brief Connect to the specified host with an optional timeout and
   *        interrupt flag.
   *
   * @param hostname Target hostname or IP address.
   * @param port Target port.
   * @param timeout_ms Connection timeout in milliseconds; <=0 uses a default.
   * @param interrupt_flag Optional interrupt flag to terminate the connection.
   * @return True on successful connection, false otherwise. On failure,
   *         error_code and error_msg are updated.
   */
  bool Connect(const std::string &hostname, int port, int timeout_ms,
               std::shared_ptr<InterruptFlag> interrupt_flag = nullptr) {
    auto is_interrupted = [&]() {
      return interrupt_flag && interrupt_flag->check();
    };
    auto mark_interrupted = [&]() {
      error_code = EC::Terminate;
      error_msg = "Connection interrupted";
    };

    if (is_interrupted()) {
      mark_interrupted();
      return false;
    }

    // 1. DNS resolve - use AF_UNSPEC for IPv4/IPv6
    addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC; // support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int dns_err = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(),
                              &hints, &result);
    if (dns_err != 0) {
#ifdef _WIN32
      auto dns_err_str = gai_strerrorA(dns_err);
      error_msg = AMStr::amfmt("DNS resolve failed: {} (hostname={})",
                               dns_err_str, hostname);
#else
      auto dns_err_str = gai_strerror(dns_err);
      error_msg = AMStr::amfmt("DNS resolve failed: {} (hostname={})",
                               dns_err_str, hostname);
#endif
      error_code = EC::DNSResolveError;
      return false;
    }

    if (is_interrupted()) {
      mark_interrupted();
      freeaddrinfo(result);
      return false;
    }

    // 2. Try connecting all resolved addresses (IPv4/IPv6 dual-stack)
    addrinfo *rp = nullptr;
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
      if (is_interrupted()) {
        mark_interrupted();
        freeaddrinfo(result);
        return false;
      }

      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock == INVALID_SOCKET) {
        continue; // Try next address
      }

      // 3. Set non-blocking mode
      if (!SetNonBlocking(true)) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue;
      }

      if (is_interrupted()) {
        mark_interrupted();
        closesocket(sock);
        sock = INVALID_SOCKET;
        freeaddrinfo(result);
        return false;
      }

      // 4. Start connection
      int conn_result = connect(sock, rp->ai_addr, (int)rp->ai_addrlen);

#ifdef _WIN32
      bool in_progress =
          (conn_result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
#else
      bool in_progress = (conn_result == -1 && errno == EINPROGRESS);
#endif

      if (conn_result == 0) {
        // Immediate success (can happen on local connection)
        if (is_interrupted()) {
          mark_interrupted();
          closesocket(sock);
          sock = INVALID_SOCKET;
          freeaddrinfo(result);
          return false;
        }
        SetNonBlocking(false);
        freeaddrinfo(result);
        return true;
      }

      if (!in_progress) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue; // Try next address
      }

      // 5. Use select to wait for connection complete
      const int64_t total_timeout_ms = timeout_ms > 0 ? timeout_ms : 6000;
      const int64_t start_ms = am_ms();
      int64_t remaining_ms = total_timeout_ms;
      int select_result = 0;
      bool timed_out = false;

      while (remaining_ms > 0) {
        if (is_interrupted()) {
          mark_interrupted();
          closesocket(sock);
          sock = INVALID_SOCKET;
          freeaddrinfo(result);
          return false;
        }

        const int64_t wait_ms =
            remaining_ms > 100 ? static_cast<int64_t>(100) : remaining_ms;

        fd_set write_fds, error_fds;
        FD_ZERO(&write_fds);
        FD_ZERO(&error_fds);
        FD_SET(sock, &write_fds);
        FD_SET(sock, &error_fds);

        timeval timeout;
        timeout.tv_sec = static_cast<long>(wait_ms / 1000);
        timeout.tv_usec = static_cast<long>((wait_ms % 1000) * 1000);

        select_result =
            select((int)sock + 1, nullptr, &write_fds, &error_fds, &timeout);

        if (select_result > 0) {
          if (FD_ISSET(sock, &error_fds)) {
            select_result = -1;
          }
          break;
        }

        if (select_result < 0) {
          break;
        }

        remaining_ms = total_timeout_ms - (am_ms() - start_ms);
      }

      if (remaining_ms <= 0) {
        timed_out = true;
      }

      if (select_result <= 0 || timed_out) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue; // Try next address
      }

      // 6. Check socket errors
      int sock_error = 0;
      socklen_t len = sizeof(sock_error);
      if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&sock_error, &len) <
              0 ||
          sock_error != 0) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue; // Try next address
      }

      // 7. Restore blocking mode, connection successful
      if (is_interrupted()) {
        mark_interrupted();
        closesocket(sock);
        sock = INVALID_SOCKET;
        freeaddrinfo(result);
        return false;
      }
      SetNonBlocking(false);
      freeaddrinfo(result);
      return true;
    }

    // All addresses failed
    freeaddrinfo(result);
    error_msg = "Socket connect failed for all addresses";
    error_code = EC::SocketConnectFailed;
    return false;
  }

private:
  bool SetNonBlocking(bool non_blocking) {
#ifdef _WIN32
    u_long mode = non_blocking ? 1 : 0;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
      error_msg = "Failed to set socket non-blocking mode";
      error_code = EC::SocketCreateError;
      return false;
    }
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
      error_msg = "Failed to get socket flags";
      error_code = EC::SocketCreateError;
      return false;
    }
    flags = non_blocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    if (fcntl(sock, F_SETFL, flags) < 0) {
      error_msg = "Failed to set socket non-blocking mode";
      error_code = EC::SocketCreateError;
      return false;
    }
#endif
    return true;
  }
};

struct TerminalWindowInfo {
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
  std::string term = "xterm-256color";
};

class KnownHostQuery {
public:
  std::string nickname = "";
  std::string hostname = "";
  int port = 0;
  std::string protocol = "";
  std::string username = "";
  KnownHostQuery(std::string_view nickname, std::string_view hostname, int port,
                 std::string_view protocol, std::string_view username,
                 std::string_view fingerprint = "")
      : nickname(nickname), hostname(hostname), port(port), protocol(protocol),
        username(username), fingerprint(fingerprint) {}

  KnownHostQuery() = default;

  [[nodiscard]] bool IsValid() const {
    return !hostname.empty() && port > 0 && port <= 65535;
  }

  [[nodiscard]] std::vector<std::string> GetPath() const {
    return {this->hostname, std::to_string(this->port), this->username,
            this->protocol};
  }

  bool SetFingerprint(const std::string &fingerprint) {
    if (fingerprint.empty()) {
      return false;
    }
    this->fingerprint = fingerprint;
    return true;
  }

  [[nodiscard]] std::string GetFingerprint() const { return this->fingerprint; }

private:
  std::string fingerprint = "";
};

#ifdef _WIN32
inline static std::atomic<bool> is_wsa_initialized(false);

inline void AMInitWSA() {
  WSADATA wsaData;
  int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (result != 0) {
    throw std::runtime_error("WSAStartup failed");
  }
  is_wsa_initialized.store(true, std::memory_order_relaxed);
}
inline void AMInitWSA();

inline void cleanup_wsa() {
  // Cleanup WSA if initialized
  if (is_wsa_initialized.load(std::memory_order_relaxed)) {
    WSACleanup();
    is_wsa_initialized.store(false, std::memory_order_relaxed);
  }
}
#endif

inline std::string GetLibssh2Version() {
  return libssh2_version(LIBSSH2_VERSION_NUM);
}

inline std::string SSHCodeToString(int code) {
  static const std::unordered_map<int, std::string> SFTPMessage = {
      {LIBSSH2_FX_EOF, "End of file"},
      {LIBSSH2_FX_NO_SUCH_FILE, "File does not exist"},
      {LIBSSH2_FX_PERMISSION_DENIED, "Permission denied"},
      {LIBSSH2_FX_FAILURE, "Generic failure"},
      {LIBSSH2_FX_BAD_MESSAGE, "Bad message format"},
      {LIBSSH2_FX_NO_CONNECTION, "No connection exists"},
      {LIBSSH2_FX_CONNECTION_LOST, "Connection lost"},
      {LIBSSH2_FX_OP_UNSUPPORTED, "Operation not supported"},
      {LIBSSH2_FX_INVALID_HANDLE, "Invalid handle"},
      {LIBSSH2_FX_NO_SUCH_PATH, "No such path"},
      {LIBSSH2_FX_FILE_ALREADY_EXISTS, "File already exists"},
      {LIBSSH2_FX_WRITE_PROTECT, "Target is write protected"},
      {LIBSSH2_FX_NO_MEDIA, "Target Storage Media is not available"},
      {LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM, "No space on filesystem"},
      {LIBSSH2_FX_QUOTA_EXCEEDED, "Space quota exceeded"},
      {LIBSSH2_FX_UNKNOWN_PRINCIPAL, "User not found in host"},
      {LIBSSH2_FX_LOCK_CONFLICT, "Path is locked by another process"},
      {LIBSSH2_FX_DIR_NOT_EMPTY, "Directory is not empty"},
      {LIBSSH2_FX_NOT_A_DIRECTORY, "Target is not a directory"},
      {LIBSSH2_FX_INVALID_FILENAME, "Filename is invalid"},
      {LIBSSH2_FX_LINK_LOOP, "Symbolic link loop"}};
  auto it = SFTPMessage.find(code);
  if (it != SFTPMessage.end()) {
    return it->second;
  }
  return "Unknown error code: " + std::to_string(code);
}

inline EC IntToEC(int code) {
  static const std::unordered_map<int, ErrorCode> Int2EC = [] {
    std::unordered_map<int, ErrorCode> map;
    for (auto [val, name] : magic_enum::enum_entries<ErrorCode>()) {
      map[static_cast<int>(val)] = val;
    }
    return map;
  }();
  auto it = Int2EC.find(code);
  if (it != Int2EC.end()) {
    return it->second;
  } else {
    return EC::UnknownError;
  }
}

inline bool IsValidKey(const std::string &key) {
  std::ifstream file(key);
  if (!file.is_open())
    return false;

  std::string line;
  std::getline(file, line);

  // Match standard header markers of all SSH private keys
  const std::vector<std::string> private_key_headers = {
      "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----"};
  for (const auto &header : private_key_headers) {
    if (line.find(header) == 0) { // Prefix match
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

using AuthCallback =
    std::function<std::optional<std::string>(const AuthCBInfo &)>;

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
      prompt = action + " on " + taregt + " error:" + msg;
    } else {
      AMStr::vreplace(prompt, "{action}", action);
      AMStr::vreplace(prompt, "{target}", taregt);
      AMStr::vreplace(prompt, "{error}", msg);
    }
    trace(level, ec, taregt, action, prompt);
    return {ec, prompt};
  }

  template <typename T>
  ECM ErrorRecord(const NBResult<T> &result, TraceLevel level,
                  const std::string &target, const std::string &action,
                  std::string prompt = "") {
    // 1. Timeout
    if (result.is_timeout()) {
      std::string msg = AMStr::amfmt("{} on {} timeout", action, target);
      trace(level, EC::OperationTimeout, target, action, msg);
      return {EC::OperationTimeout, msg};
    }

    // 2. Terminate
    if (result.is_interrupted()) {
      std::string msg =
          AMStr::amfmt("{} on {} interrupted by user", action, target);
      trace(level, EC::Terminate, target, action, msg);
      return {EC::Terminate, msg};
    }

    // 3. Socket error
    if (result.is_error()) {
      std::string msg = AMStr::amfmt("Encountered socket error during {} on {}",
                                     action, target);
      trace(level, EC::SocketRecvError, target, action, msg);
      return {EC::SocketRecvError, msg};
    }

    // 4 & 5. Execution finished - check return value for errors
    // For int/ssize_t: <0 means failure (while LIBSSH2 uses 0 as success)
    // For pointers: nullptr means failure
    if constexpr (std::is_same_v<T, int> || std::is_same_v<T, ssize_t>) {
      if (result.value < 0) {
        // Execution finished but failed
        auto ec = GetLastEC();
        auto errmsg = GetLastErrorMsg();
        std::string msg = prompt.empty() ? AMStr::amfmt("{} on {} error: {}",
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
        std::string msg = prompt.empty() ? AMStr::amfmt("{} on {} error: {}",
                                                        action, target, errmsg)
                                         : prompt;
        AMStr::vreplace(msg, "{action}", action);
        AMStr::vreplace(msg, "{target}", target);
        AMStr::vreplace(msg, "{error}", errmsg);
        trace(level, ec, target, action, msg);
        return {ec, msg};
      }
    }

    // 5. Success
    return {EC::Success, ""};
  }

private:
  ECM CurError = {EC::NoConnection, "Connection not established"};
  bool password_auth_cb = false;
  std::vector<std::string> private_keys = {};
  AuthCallback auth_cb = {}; // optional<string>(AuthCBInfo)
  using KnownHostCallback = std::function<ECM(const KnownHostQuery &)>;
  KnownHostCallback known_host_cb = {};

  /**
   * @brief Encode binary data as RFC 4648 Base64 without line breaks.
   */
  static std::string Base64Encode(const unsigned char *data, size_t len) {
    static const char kBase64Alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!data || len == 0) {
      return "";
    }
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
      uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
      const size_t remain = len - i;
      if (remain > 1) {
        chunk |= static_cast<uint32_t>(data[i + 1]) << 8;
      }
      if (remain > 2) {
        chunk |= static_cast<uint32_t>(data[i + 2]);
      }
      out.push_back(kBase64Alphabet[(chunk >> 18) & 0x3F]);
      out.push_back(kBase64Alphabet[(chunk >> 12) & 0x3F]);
      out.push_back(remain > 1 ? kBase64Alphabet[(chunk >> 6) & 0x3F] : '=');
      out.push_back(remain > 2 ? kBase64Alphabet[chunk & 0x3F] : '=');
    }
    return out;
  }

  /**
   * @brief Map libssh2 host key type to the OpenSSH protocol string.
   */
  static std::string HostKeyTypeToProtocol(int type) {
    switch (type) {
    case LIBSSH2_HOSTKEY_TYPE_RSA:
      return "ssh-rsa";
    case LIBSSH2_HOSTKEY_TYPE_DSS:
      return "ssh-dss";
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
      return "ecdsa-sha2-nistp256";
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
      return "ecdsa-sha2-nistp384";
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
      return "ecdsa-sha2-nistp521";
    case LIBSSH2_HOSTKEY_TYPE_ED25519:
      return "ssh-ed25519";
    default:
      return "";
    }
  }

  /**
   * @brief Verify the remote host key using an external callback when set.
   */
  ECM VerifyKnownHostFingerprint() {
    if (!known_host_cb) {
      return {EC::Success, ""};
    }

    size_t key_len = 0;
    int key_type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    const char *key_ptr = libssh2_session_hostkey(session, &key_len, &key_type);
    if (!key_ptr || key_len == 0) {
      return {EC::HostkeyInitFailed, "Failed to read host key from session"};
    }

    const std::string actual_protocol = HostKeyTypeToProtocol(key_type);
    if (actual_protocol.empty()) {
      return {EC::AlgorithmUnsupported, "Unsupported host key algorithm"};
    }

    auto *key_bytes = reinterpret_cast<const unsigned char *>(key_ptr);

    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest;
    std::string actual_sha = "";
    if (SHA256(key_bytes, key_len, digest.data())) {
      actual_sha = Base64Encode(digest.data(), SHA256_DIGEST_LENGTH);
    }

    KnownHostQuery entry{res_data.nickname, res_data.hostname, res_data.port,
                         actual_protocol,   res_data.username, actual_sha};
    return known_host_cb(std::move(entry));
  }

  void LoadDefaultPrivateKeys() {
    trace(TraceLevel::Debug, EC::Success, "~/.ssh", "LoadDefaultPrivateKeys",
          "Shared private keys not provided, loading default private keys from "
          "~/.ssh");
    auto [error, listd] = AMFS::listdir(AMFS::abspath("~/.ssh"));
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
    has_connected.store(false, std::memory_order_relaxed);
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
            ssize_t error_num = 10, TraceCallback trace_cb = {},
            AuthCallback auth_cb = {})
      : BaseClient(request, error_num, std::move(trace_cb)),
        private_keys(private_keys), auth_cb(std::move(auth_cb)),
        res_data(request) {
    if (this->auth_cb) {
      this->password_auth_cb = true;
    }
    if (private_keys.empty()) {
      LoadDefaultPrivateKeys();
    }
    has_connected.store(false, std::memory_order_relaxed);
  }

  inline std::function<bool()> MakeInterruptCb(const amf &flag) const {
    return [flag]() { return flag && flag->check(); };
  }
  template <typename Func>
  auto nb_call(const std::function<bool()> &interrupt_cb, int64_t timeout_ms,
               int64_t start_time, Func &&func) -> NBResult<decltype(func())> {
    using RetType = decltype(func());

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

      wr = wait_for_socket(SocketWaitType::Auto, interrupt_cb, start_time,
                           timeout_ms, poll_interval_ms);
      if (wr != WaitResult::Ready) {
        libssh2_session_set_blocking(session, 1);
        return {rc, wr};
      }
    }

    return {rc, WaitResult::Ready};
  }

  template <typename Func>
  auto nb_call(const amf interrupt_flag, int64_t timeout_ms, int64_t start_time,
               Func &&func) -> NBResult<decltype(func())> {
    return nb_call(MakeInterruptCb(interrupt_flag), timeout_ms, start_time,
                   std::forward<Func>(func));
  }

  inline WaitResult
  wait_for_socket(SocketWaitType wait_dir,
                  const std::function<bool()> &interrupt_cb = {},
                  int64_t start_time = -1, int64_t timeout_ms = -1,
                  int poll_interval_ms = 20) {
    // Fast path: check if socket is already ready without select
    if (wait_dir == SocketWaitType::Auto) {
      int dir = libssh2_session_block_directions(session);
      if (dir == 0) {
        return WaitResult::Ready;
      }
    }

    // Pre-check interrupt and timeout before entering select
    if (interrupt_cb && interrupt_cb()) {
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
        // ReadOrWrite return specific read/write state in this mode
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
      if (interrupt_cb && interrupt_cb()) {
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
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (has_connected.load(std::memory_order_relaxed)) {
      if (!force) {
        return GetState();
      }
      Disconnect();
      has_connected.store(false, std::memory_order_relaxed);
    }

    ECM rcm = {EC::Success, ""};
    int rcr;
    WaitResult wr = WaitResult::Ready;
    bool password_auth;
    std::string password_tmp;
    std::string stored_password_enc = res_data.password;
    const char *auth_list = nullptr;

    /**
     * @brief Notify authentication callbacks in a unified manner.
     */
    auto NotifyAuth = [&](bool need_password, const std::string &password_enc,
                          bool password_correct) {
      if (!auth_cb) {
        return;
      }
      ConRequst request = res_data;
      request.password = password_correct ? password_enc : "";
      CallCallbackSafe(auth_cb, AuthCBInfo(need_password, std::move(request),
                                           password_enc, password_correct));
    };

    // Use SocketConnector to establish connection
    SocketConnector connector;

    if (!connector.Connect(res_data.hostname, res_data.port, timeout_ms,
                           interrupt_flag)) {
      trace(TraceLevel::Critical, connector.error_code,
            AMStr::amfmt("{}", std::to_string(connector.sock)),
            "SocketConnector.Connect", connector.error_msg);
      return {connector.error_code, connector.error_msg};
    }
    sock = connector.sock;

    // Check interrupt/timeout
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

    // Set non-blocking mode for handshake
    libssh2_session_set_blocking(session, 0);

    if (res_data.compression) {
      libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
      libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS,
                                  "zlib@openssh.com,zlib,none");
    }

    // Non-blocking handshake
    while (true) {
      rcr = libssh2_session_handshake(session, sock);
      wr =
          wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(interrupt_flag),
                          start_time, timeout_ms);
      if (wr != WaitResult::Ready) {
        goto interrupted_or_sock_error;
      }
      if (rcr != LIBSSH2_ERROR_EAGAIN) {
        break;
      }
    }
    rcm = ErrorRecord(
        rcr, TraceLevel::Critical,
        AMStr::amfmt("socket {}", std::to_string(static_cast<size_t>(sock))),
        "libssh2_session_handshake");
    if (rcm.first != EC::Success) {
      goto interrupted_or_sock_error;
    }

    rcm = VerifyKnownHostFingerprint();
    if (rcm.first != EC::Success) {
      trace(TraceLevel::Error, rcm.first, res_data.hostname,
            "VerifyKnownHostFingerprint", rcm.second);
      libssh2_session_set_blocking(session, 1);
      Disconnect();
      return rcm;
    }

    // Get auth list (non-blocking)

    while ((auth_list =
                libssh2_userauth_list(session, res_data.username.c_str(),
                                      res_data.username.length())) == nullptr &&
           libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
      wr =
          wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(interrupt_flag),
                          start_time, timeout_ms);
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
          AMStr::amfmt("Authentication methods: {}", auth_list));

    // ========== Enter authentication stage; stop timeout checks ==========
    // Switch to blocking mode to simplify auth flow (auth may involve user interaction)
    libssh2_session_set_blocking(session, 1);

    password_auth = (strstr(auth_list, "password") != nullptr);

    // Dedicated private key auth
    if (!res_data.keyfile.empty()) {
      // Check interrupt (without timeout check)
      if (interrupt_flag && interrupt_flag->check()) {
        return {EC::Terminate, "Authentication interrupted"};
      }
      rcr = libssh2_userauth_publickey_fromfile(
          session, res_data.username.c_str(), nullptr, res_data.keyfile.c_str(),
          nullptr);
      if (rcr == 0) {
        trace(TraceLevel::Info, EC::Success, "Success",
              "PrivatedKeyAuthorizeResult",
              AMStr::amfmt("Dedicated private key \"{}\" authorize success",
                           res_data.keyfile));
        NotifyAuth(false, "", true);
        goto OK;
      } else {
        trace(TraceLevel::Debug, EC::PublickeyAuthFailed, res_data.keyfile,
              "DedicatedPrivateKeyAuthorizeResult",
              AMStr::amfmt("Dedicated private key \"{}\" authorize failed",
                           res_data.keyfile));
        NotifyAuth(false, "", false);
      }
    }

    // Password authentication
    if (!stored_password_enc.empty() && password_auth) {
      if (interrupt_flag && interrupt_flag->check()) {
        return {EC::Terminate, "Authentication interrupted"};
      }
      std::string plain_password = AMAuth::DecryptPassword(stored_password_enc);
      rcr = libssh2_userauth_password(session, res_data.username.c_str(),
                                      plain_password.c_str());
      AMAuth::SecureZero(plain_password);
      if (rcr == 0) {
        trace(TraceLevel::Info, EC::Success, "Success",
              "PasswordAuthorizeResult", "Password authorize success");
        res_data.password = stored_password_enc;
        NotifyAuth(false, stored_password_enc, true);
        goto OK;
      } else {
        trace(TraceLevel::Debug, EC::AuthFailed, "password", "PasswordAuth",
              "Password authentication failed");
        NotifyAuth(false, stored_password_enc, false);
      }
    }

    // Shared private key authentication
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
                AMStr::amfmt("Shared private key \"{}\" authorize success",
                             private_key));
          NotifyAuth(false, "", true);
          goto OK;
        } else {
          trace(TraceLevel::Debug, EC::PrivateKeyAuthFailed, "Failed",
                "PrivatedKeyAuthorizeResult", rcm.second);
          NotifyAuth(false, "", false);
        }
      }
    }

    // Interactive password authentication callback
    if (password_auth_cb && password_auth) {
      trace(TraceLevel::Info, EC::Success, "Interactive", "PasswordAuthorize",
            "Using password authentication callback to get another password");
      int trial_times = 0;
      while (trial_times < 2) {
        if (interrupt_flag && interrupt_flag->check()) {
          return {EC::Terminate, "Authentication interrupted"};
        }
        auto [password_opt, cb_ecm] =
            CallCallbackSafeRet<std::optional<std::string>>(
                auth_cb, AuthCBInfo(true, res_data, "", false));
        if (cb_ecm.first != EC::Success) {
          trace(TraceLevel::Error, cb_ecm.first, "AuthCB", "Call",
                cb_ecm.second);
          break;
        }
        if (password_opt.has_value()) {
          password_tmp = *password_opt;
        } else {
          password_tmp.clear();
        }
        if (password_tmp.empty()) {
          break;
        }
        const std::string password_enc = AMAuth::EncryptPassword(password_tmp);
        rcr = libssh2_userauth_password(session, res_data.username.c_str(),
                                        password_tmp.c_str());
        AMAuth::SecureZero(password_tmp);
        trial_times++;
        if (rcr == 0) {
          trace(TraceLevel::Info, EC::Success, "Success",
                "PasswordAuthorizeResult", "Password authorize success");
          res_data.password = password_enc;
          NotifyAuth(false, password_enc, true);
          goto OK;
        } else {
          trace(TraceLevel::Debug, EC::AuthFailed, "Failed",
                "PasswordAuthorizeResult", "Wrong password");
          NotifyAuth(false, password_enc, false);
        }
      }
    }
    rcm.first = EC::AuthFailed;
    rcm.second = "All authorize methods failed";

  OK:
    // Check interrupt
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

    has_connected.store(true, std::memory_order_relaxed);
    libssh2_session_set_blocking(session, 0);
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
      return IntToEC(ori_code);
    } else {
      if (!sftp) {
        return EC::NoConnection;
      }
      int ori_code2 = libssh2_sftp_last_error(sftp);
      return IntToEC(ori_code2);
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
      if (!errmsg || errmsg_len <= 0) {
        return "Unknown SSH error";
      }
      return std::string(errmsg, static_cast<size_t>(errmsg_len));
    } else {
      if (!sftp) {
        return "SFTP not initialized";
      }
      return SSHCodeToString(libssh2_sftp_last_error(sftp));
    }
  }

  void SetAuthCallback(AuthCallback auth_cb = {}) {
    this->auth_cb = std::move(auth_cb);
    this->password_auth_cb = static_cast<bool>(this->auth_cb);
  }
  /**
   * @brief Set callback to verify or record known host fingerprints.
   */
  void SetKnownHostCallback(KnownHostCallback cb = {}) {
    this->known_host_cb = std::move(cb);
  }
};

class AMBaseTerminal {
public:
  using TerminalOutputCallback = std::function<void(const std::string &)>;
  virtual ~AMBaseTerminal() = default;

  virtual ECM Connect(bool force = false, amf interrupt_flag = nullptr,
                      int timeout_ms = -1, int64_t start_time = -1) = 0;
  virtual ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
                    int64_t start_time = -1) = 0;
  virtual void PauseReading() = 0;
  virtual void ResumeReading() = 0;
  virtual void
  SetTerminalOutputCallback(TerminalOutputCallback output_cb = {}) = 0;
  virtual ECM SetTerminalWindowInfo(const TerminalWindowInfo &window,
                                    amf interrupt_flag = nullptr,
                                    int timeout_ms = -1,
                                    int64_t start_time = -1) = 0;
  virtual ECM TerminalWrite(const std::string &msg,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) = 0;
  virtual ECM TerminalClose() = 0;
  virtual void SetReaderWaitTimeoutMs(int timeout_ms) = 0;
};

class AMSFTPTerminal : public AMSession, public AMBaseTerminal {
public:
  using TerminalOutputCallback = AMBaseTerminal::TerminalOutputCallback;

private:
  std::unique_ptr<SafeChannel> terminal_channel;
  std::atomic<bool> reader_running{false};
  std::atomic<bool> reader_paused{false};
  std::atomic<int> reader_wait_timeout_ms{200};
  std::thread reader_thread;
  std::condition_variable reader_cv;
  std::mutex reader_cv_mtx;
  std::mutex terminal_cb_mtx;

  void StartReader() {
    if (reader_running.load(std::memory_order_relaxed)) {
      return;
    }
    bool has_cb = false;
    {
      std::lock_guard<std::mutex> lock(terminal_cb_mtx);
      has_cb = static_cast<bool>(terminal_output_cb);
    }
    reader_running.store(true, std::memory_order_relaxed);
    reader_paused.store(!has_cb, std::memory_order_relaxed);
    reader_thread = std::thread([this]() { ReaderLoop(); });
  }

  void StopReader() {
    if (!reader_running.load(std::memory_order_relaxed) &&
        !reader_thread.joinable()) {
      return;
    }
    reader_running.store(false, std::memory_order_relaxed);
    reader_paused.store(false, std::memory_order_relaxed);
    reader_cv.notify_all();
    if (reader_thread.joinable()) {
      reader_thread.join();
    }
  }

  bool IsTerminalAlive() {
    if (!terminal_channel || !terminal_channel->channel) {
      return false;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (libssh2_channel_eof(terminal_channel->channel) != 0) {
      return false;
    }
    return true;
  }

  void ReaderLoop() {
    std::array<char, 4096> buffer;
    while (reader_running.load(std::memory_order_relaxed)) {
      if (reader_paused.load(std::memory_order_relaxed)) {
        std::unique_lock<std::mutex> lock(reader_cv_mtx);
        reader_cv.wait(lock, [this]() {
          return !reader_paused.load(std::memory_order_relaxed) ||
                 !reader_running.load(std::memory_order_relaxed);
        });
        continue;
      }

      if (terminal_interrupt_flag && terminal_interrupt_flag->check()) {
        reader_running.store(false, std::memory_order_relaxed);
        break;
      }

      if (!terminal_channel || !terminal_channel->channel || !session) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        continue;
      }

      int64_t start_time = am_ms();
      int wait_timeout = reader_wait_timeout_ms.load(std::memory_order_relaxed);
      WaitResult wr = wait_for_socket(SocketWaitType::Read,
                                      MakeInterruptCb(terminal_interrupt_flag),
                                      start_time, wait_timeout);
      if (wr == WaitResult::Timeout) {
        continue;
      }
      if (wr == WaitResult::Interrupted) {
        reader_running.store(false, std::memory_order_relaxed);
        break;
      }
      if (wr == WaitResult::Error) {
        continue;
      }

      std::string output;
      {
        std::lock_guard<std::recursive_mutex> lock(mtx);
        libssh2_session_set_blocking(session, 0);
        while (true) {
          ssize_t nbytes =
              libssh2_channel_read(terminal_channel->channel, buffer.data(),
                                   static_cast<size_t>(buffer.size()));
          if (nbytes > 0) {
            output.append(buffer.data(), static_cast<size_t>(nbytes));
            continue;
          }
          if (nbytes == 0) {
            terminal_channel->close();
            terminal_channel.reset();
            reader_running.store(false, std::memory_order_relaxed);
            break;
          }
          if (nbytes == LIBSSH2_ERROR_EAGAIN) {
            break;
          }
          terminal_channel->close();
          terminal_channel.reset();
          reader_running.store(false, std::memory_order_relaxed);
          break;
        }
      }

      if (!output.empty()) {
        TerminalOutputCallback cb;
        {
          std::lock_guard<std::mutex> lock(terminal_cb_mtx);
          cb = terminal_output_cb;
        }
        if (cb) {
          CallCallbackSafe(cb, output);
        }
      }
    }
  }

  ECM TerminalInitInternal(const TerminalWindowInfo &window,
                           TerminalOutputCallback output_cb = {},
                           amf interrupt_flag = nullptr, int timeout_ms = -1,
                           int64_t start_time = -1) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!session) {
      return {EC::NoSession, "Session not initialized"};
    }

    terminal_window = window;
    if (output_cb) {
      std::lock_guard<std::mutex> cb_lock(terminal_cb_mtx);
      terminal_output_cb = std::move(output_cb);
    }

    amf flag = interrupt_flag ? interrupt_flag : terminal_interrupt_flag;
    start_time = start_time == -1 ? am_ms() : start_time;
    if (flag && flag->check()) {
      terminal_channel.reset();
      return {EC::Terminate, "Terminal init interrupted"};
    }

    terminal_channel.reset();
    terminal_channel = std::make_unique<SafeChannel>(session);
    if (!terminal_channel->channel) {
      terminal_channel.reset();
      return {EC::NoConnection, "Terminal channel not initialized"};
    }

    libssh2_session_set_blocking(session, 0);

    int rc = 0;
    WaitResult wr = WaitResult::Ready;
    while ((rc = libssh2_channel_request_pty_ex(
                terminal_channel->channel, terminal_window.term.c_str(),
                static_cast<unsigned int>(terminal_window.term.size()), nullptr,
                0, terminal_window.cols, terminal_window.rows,
                terminal_window.width, terminal_window.height)) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag),
                           start_time, timeout_ms);
      if (wr != WaitResult::Ready) {
        goto cleanup;
      }
    }
    if (rc != 0) {
      terminal_channel.reset();
      return {GetLastEC(), AMStr::amfmt("Terminal request pty failed: {}",
                                        GetLastErrorMsg())};
    }

    while ((rc = libssh2_channel_shell(terminal_channel->channel)) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag),
                           start_time, timeout_ms);
      if (wr != WaitResult::Ready) {
        goto cleanup;
      }
    }
    if (rc != 0) {
      terminal_channel.reset();
      return {GetLastEC(), AMStr::amfmt("Terminal start shell failed: {}",
                                        GetLastErrorMsg())};
    }

    libssh2_session_set_blocking(session, 0);
    return {EC::Success, ""};

  cleanup:
    terminal_channel.reset();
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Terminal init timed out"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Terminal init interrupted"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during terminal init"};
    default:
      return {EC::UnknownError, "Terminal init failed"};
    }
  }

public:
  TerminalWindowInfo terminal_window = {};
  amf terminal_interrupt_flag = std::make_shared<InterruptFlag>();
  TerminalOutputCallback terminal_output_cb = {};

  AMSFTPTerminal(const ConRequst &request,
                 const std::vector<std::string> &keys = {},
                 unsigned int tracer_capacity = 10, TraceCallback trace_cb = {},
                 AuthCallback auth_cb = {})
      : AMSession(request, keys, tracer_capacity, std::move(trace_cb),
                  std::move(auth_cb)) {
    this->PROTOCOL = ClientProtocol::Base;
  }

  ~AMSFTPTerminal() override {
    StopReader();
    TerminalClose();
  }

  ECM Connect(bool force = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1) override {
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;

    if (has_connected.load(std::memory_order_relaxed) && session && !force) {
      ECM chk = Check(interrupt_flag, timeout_ms, start_time);
      if (chk.first == EC::Success) {
        return chk;
      }
      if (session && !IsTerminalAlive()) {
        TerminalOutputCallback cb;
        {
          std::lock_guard<std::mutex> lock(terminal_cb_mtx);
          cb = terminal_output_cb;
        }
        ECM term_rcm = TerminalInitInternal(terminal_window, cb, interrupt_flag,
                                            timeout_ms, start_time);
        if (term_rcm.first == EC::Success) {
          StartReader();
        }
        return term_rcm;
      }
    }

    StopReader();
    TerminalClose();
    ECM ecm = BaseConnect(true, interrupt_flag, start_time, timeout_ms);
    if (ecm.first != EC::Success) {
      return ecm;
    }
    TerminalOutputCallback cb;
    {
      std::lock_guard<std::mutex> lock(terminal_cb_mtx);
      cb = terminal_output_cb;
    }
    ECM term_rcm = TerminalInitInternal(terminal_window, cb, interrupt_flag,
                                        timeout_ms, start_time);
    if (term_rcm.first == EC::Success) {
      StartReader();
    }
    return term_rcm;
  }

  ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
            int64_t start_time = -1) override {
    amf flag = interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    if (flag && flag->check()) {
      ECM rcm = {EC::Terminate, "Check interrupted"};
      SetState(rcm);
      return rcm;
    }
    (void)timeout_ms;
    (void)start_time;
    if (!session || sock == INVALID_SOCKET ||
        !has_connected.load(std::memory_order_relaxed)) {
      ECM rcm = {EC::NoConnection, "Session not connected"};
      SetState(rcm);
      return rcm;
    }

    if (!IsTerminalAlive()) {
      ECM rcm = {EC::NoConnection, "Terminal not initialized"};
      SetState(rcm);
      return rcm;
    }

    SetState({EC::Success, ""});
    return {EC::Success, ""};
  }

  void PauseReading() override {
    reader_paused.store(true, std::memory_order_relaxed);
  }

  void ResumeReading() override {
    reader_paused.store(false, std::memory_order_relaxed);
    reader_cv.notify_all();
  }

  void
  SetTerminalOutputCallback(TerminalOutputCallback output_cb = {}) override {
    {
      std::lock_guard<std::mutex> lock(terminal_cb_mtx);
      terminal_output_cb = std::move(output_cb);
    }
    if (terminal_output_cb) {
      ResumeReading();
    } else {
      PauseReading();
    }
  }

  void SetReaderWaitTimeoutMs(int timeout_ms) override {
    if (timeout_ms < 1) {
      timeout_ms = 1;
    }
    reader_wait_timeout_ms.store(timeout_ms, std::memory_order_relaxed);
  }

  ECM SetTerminalWindowInfo(const TerminalWindowInfo &window,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) override {
    terminal_window = window;
    if (!terminal_channel || !terminal_channel->channel) {
      return {EC::Success, ""};
    }

    amf flag = interrupt_flag ? interrupt_flag : terminal_interrupt_flag;
    start_time = start_time == -1 ? am_ms() : start_time;
    int rc = 0;
    WaitResult wr = WaitResult::Ready;

    PauseReading();
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      libssh2_session_set_blocking(session, 0);
      while ((rc = libssh2_channel_request_pty_size_ex(
                  terminal_channel->channel, terminal_window.cols,
                  terminal_window.rows, terminal_window.width,
                  terminal_window.height)) == LIBSSH2_ERROR_EAGAIN) {
        wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag),
                             start_time, timeout_ms);
        if (wr != WaitResult::Ready) {
          goto cleanup;
        }
      }
    }

    ResumeReading();
    if (rc != 0) {
      return {GetLastEC(),
              AMStr::amfmt("Terminal resize failed: {}", GetLastErrorMsg())};
    }
    return {EC::Success, ""};

  cleanup:
    ResumeReading();
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Terminal resize timed out"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Terminal resize interrupted"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during terminal resize"};
    default:
      return {EC::UnknownError, "Terminal resize failed"};
    }
  }

  ECM TerminalWrite(const std::string &msg, amf interrupt_flag = nullptr,
                    int timeout_ms = -1, int64_t start_time = -1) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!terminal_channel || !terminal_channel->channel) {
      return {EC::NoConnection, "Terminal not initialized"};
    }

    amf flag = interrupt_flag ? interrupt_flag : this->terminal_interrupt_flag;
    start_time = start_time == -1 ? am_ms() : start_time;
    if (flag && flag->check()) {
      return {EC::Terminate, "Terminal interrupted"};
    }

    libssh2_session_set_blocking(session, 0);
    size_t offset = 0;
    WaitResult wr = WaitResult::Ready;
    while (offset < msg.size()) {
      if (flag && flag->check()) {
        wr = WaitResult::Interrupted;
        goto cleanup;
      }
      ssize_t rc =
          libssh2_channel_write(terminal_channel->channel, msg.data() + offset,
                                static_cast<int>(msg.size() - offset));
      if (rc > 0) {
        offset += static_cast<size_t>(rc);
        continue;
      }
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        wr = wait_for_socket(SocketWaitType::Write, MakeInterruptCb(flag),
                             start_time, timeout_ms);
        if (wr != WaitResult::Ready) {
          goto cleanup;
        }
        continue;
      }
      return {GetLastEC(),
              AMStr::amfmt("Terminal write failed: {}", GetLastErrorMsg())};
    }

    return {EC::Success, ""};

  cleanup:
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Terminal write timed out"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Terminal interrupted"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during terminal write"};
    default:
      return {EC::UnknownError, "Terminal write failed"};
    }
  }

  ECM TerminalClose() override {
    StopReader();
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!terminal_channel || !terminal_channel->channel) {
      return {EC::Success, ""};
    }
    libssh2_session_set_blocking(session, 1);
    terminal_channel->close();
    terminal_channel.reset();
    libssh2_session_set_blocking(session, 0);
    return {EC::Success, ""};
  }
};

class LocalTerminal : public AMBaseTerminal {
public:
  using TerminalOutputCallback = AMBaseTerminal::TerminalOutputCallback;

private:
  std::atomic<bool> paused{false};
  std::atomic<bool> closed{false};
  std::atomic<int> reader_wait_timeout_ms{200};
  TerminalOutputCallback terminal_output_cb = {};
  std::mutex terminal_cb_mtx;

#ifdef _WIN32
  static FILE *OpenPipe(const std::string &cmd) {
    return _popen(cmd.c_str(), "r");
  }
  static int ClosePipe(FILE *pipe) { return _pclose(pipe); }
#else
  static FILE *OpenPipe(const std::string &cmd) {
    return popen(cmd.c_str(), "r");
  }
  static int ClosePipe(FILE *pipe) { return pclose(pipe); }
#endif

public:
  ECM Connect(bool force = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1) override {
    (void)force;
    (void)interrupt_flag;
    (void)timeout_ms;
    (void)start_time;
    closed.store(false, std::memory_order_relaxed);
    return {EC::Success, ""};
  }

  ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
            int64_t start_time = -1) override {
    (void)timeout_ms;
    (void)start_time;
    if (interrupt_flag && interrupt_flag->check()) {
      return {EC::Terminate, "Check interrupted"};
    }
    if (closed.load(std::memory_order_relaxed)) {
      return {EC::NoConnection, "Terminal closed"};
    }
    return {EC::Success, ""};
  }

  void PauseReading() override {
    paused.store(true, std::memory_order_relaxed);
  }

  void ResumeReading() override {
    paused.store(false, std::memory_order_relaxed);
  }

  void
  SetTerminalOutputCallback(TerminalOutputCallback output_cb = {}) override {
    std::lock_guard<std::mutex> lock(terminal_cb_mtx);
    terminal_output_cb = std::move(output_cb);
  }

  ECM SetTerminalWindowInfo(const TerminalWindowInfo &window,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) override {
    (void)window;
    (void)interrupt_flag;
    (void)timeout_ms;
    (void)start_time;
    return {EC::Success, ""};
  }

  void SetReaderWaitTimeoutMs(int timeout_ms) override {
    if (timeout_ms < 1) {
      timeout_ms = 1;
    }
    reader_wait_timeout_ms.store(timeout_ms, std::memory_order_relaxed);
  }

  ECM TerminalWrite(const std::string &msg, amf interrupt_flag = nullptr,
                    int timeout_ms = -1, int64_t start_time = -1) override {
    if (closed.load(std::memory_order_relaxed)) {
      return {EC::NoConnection, "Terminal closed"};
    }
    if (msg.empty()) {
      return {EC::InvalidArg, "Empty command"};
    }

    std::string cmd = msg;
    while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) {
      cmd.pop_back();
    }
    if (cmd.empty()) {
      return {EC::InvalidArg, "Empty command"};
    }

    if (timeout_ms <= 0) {
      timeout_ms = reader_wait_timeout_ms.load(std::memory_order_relaxed);
    }
    start_time = start_time == -1 ? am_ms() : start_time;

    if (interrupt_flag && interrupt_flag->check()) {
      return {EC::Terminate, "Terminal interrupted"};
    }

    FILE *pipe = OpenPipe(cmd);
    if (!pipe) {
      return {EC::LocalFileOpenError, "Local terminal pipe open failed"};
    }

    std::array<char, 4096> buffer;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
      if (interrupt_flag && interrupt_flag->check()) {
        ClosePipe(pipe);
        return {EC::Terminate, "Terminal interrupted"};
      }
      if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
        ClosePipe(pipe);
        return {EC::OperationTimeout, "Terminal write timed out"};
      }

      if (!paused.load(std::memory_order_relaxed)) {
        TerminalOutputCallback cb;
        {
          std::lock_guard<std::mutex> lock(terminal_cb_mtx);
          cb = terminal_output_cb;
        }
        if (cb) {
          CallCallbackSafe(cb, std::string(buffer.data()));
        }
      }
    }

    int rc = ClosePipe(pipe);
    if (rc != 0) {
      return {EC::UnknownError, "Local command failed"};
    }
    return {EC::Success, ""};
  }

  ECM TerminalClose() override {
    closed.store(true, std::memory_order_relaxed);
    return {EC::Success, ""};
  }
};

class AMSFTPClient : public AMSession {
private:
  std::unordered_map<long, std::string> user_id_map;
  std::unique_ptr<SafeChannel> terminal_channel;
  std::vector<std::string> forbidden_cmd_tokens = {"mkfs",
                                                   "dd if=", ":(){:|:&};:"};

  bool IsCommandAllowed(const std::string &cmd,
                        std::string *reason = nullptr) const {
    std::string trimmed = AMStr::Strip(cmd);
    if (trimmed.empty()) {
      if (reason)
        *reason = "Command is empty";
      return false;
    }

    std::string lower = AMStr::lowercase(trimmed);
    for (const auto &token : forbidden_cmd_tokens) {
      if (token.empty())
        continue;
      if (lower.find(token) != std::string::npos) {
        if (reason)
          *reason = AMStr::amfmt("Command blocked by policy: {}", token);
        return false;
      }
    }
    return true;
  }

  std::string GetPathOnwer(const std::string &path,
                           const LIBSSH2_SFTP_ATTRIBUTES &attrs) {

    if (GetOSType() == OS_TYPE::Windows) {
      auto cmd_f = AMStr::amfmt("powershell -NoProfile -Command \"(Get-Acl "
                                "-LiteralPath '{}').Owner \"",
                                path);
      auto [rcm, cr] = ConductCmd(cmd_f);
      if (!isok(rcm) || cr.second != 0) {
        return "unknown";
      }
      int pos = cr.first.find_last_of("\\");
      if (pos != std::string::npos && pos + 1 < cr.first.size()) {
        return cr.first.substr(pos + 1);
      } else {
        return cr.first;
      }
    } else if (attrs.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
      long uid = attrs.uid;
      return StrUid(uid);
    } else {
      return "unknown";
    }
  }

  PathInfo FormatStat(const std::string &path,
                      const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
    PathInfo info;
    info.path = path;
    info.name = AMPathStr::basename(path);
    info.dir = AMPathStr::dirname(path);

    if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
      info.size = attrs.filesize;
    }

    if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
      info.access_time = attrs.atime;
      info.modify_time = attrs.mtime;
    }

    if (GetOSType() != OS_TYPE::Windows &&
        attrs.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
      info.owner = StrUid(attrs.uid);
    } else {
      info.owner = "";
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
      if (GetOSType() != OS_TYPE::Windows) {
        info.mode_int = mode & 0777;
        info.mode_str = AMStr::ModeTrans(info.mode_int);
      }
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
          nb_res, TraceLevel::Debug, AMStr::amfmt("{} -> {}", src, dst),
          "libssh2_sftp_rename_ex", "Rename {target} failed: {error}");
    } else {
      auto nb_res = nb_call(interrupt_flag, timeout_ms, start_time, [&] {
        return libssh2_sftp_rename_ex(
            sftp, src.c_str(), src.size(), dst.c_str(), dst.size(),
            LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_NATIVE);
      });
      return ErrorRecord(
          nb_res, TraceLevel::Debug, AMStr::amfmt("{} -> {}", src, dst),
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
                      "Open directory {target} failed: {error}");
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    sftp_handle = oepn_res.value;
    NBResult<int> read_res;

    while (true) {
      if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
        rcm = ECM{EC::OperationTimeout,
                  AMStr::amfmt("Path: {} readdir timeout", path)};
        break;
      }
      if (interrupt_flag && interrupt_flag->check()) {
        rcm = ECM{EC::Terminate,
                  AMStr::amfmt("Path: {} readdir interrupted by user", path)};
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
              WRV &result, RMR &errors, bool show_all = false,
              bool ignore_sepcial_file = true,
              AMFS::WalkErrorCallback error_callback = nullptr,
              amf interrupt_flag = nullptr, int timeout_ms = -1,
              int64_t start_time = -1) {
    // Find all deepest paths under directory for recursive transfer
    if (interrupt_flag && interrupt_flag->check()) {
      return;
    }

    const bool filter_hidden = !show_all;
    const bool filter_special = !show_all && ignore_sepcial_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };

    if (!isdir(attrs)) {
      // Add directly if not a directory
      if (filter_hidden && is_hidden_name(AMPathStr::basename(path))) {
        return;
      }
      if (!isreg(attrs) && filter_special) {
        return;
      }
      result.push_back(FormatStat(path, attrs));
      return;
    }

    auto [rcm2, attrs_list] =
        lib_listdir(path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      if (rcm2.first != EC::OperationTimeout) {
        if (error_callback && *error_callback) {
          (*error_callback)(path, rcm2);
        }
        errors.emplace_back(path, rcm2);
      }
      return;
    }

    if (attrs_list.empty()) {
      // Add leaf empty directory directly
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
      const std::string base_name = AMPathStr::basename(attrs.first);
      if (filter_hidden && is_hidden_name(base_name)) {
        continue;
      }
      _iwalk(attrs.first, attrs.second, result, errors, show_all,
             ignore_sepcial_file, error_callback, interrupt_flag, timeout_ms,
             start_time);
    }
  }

  void _walk(const std::vector<std::string> &parts, WRD &result, RMR &errors,
             int cur_depth = 0, int max_depth = -1, bool show_all = false,
             bool ignore_sepcial_file = true,
             AMFS::WalkErrorCallback error_callback = nullptr,
             amf interrupt_flag = nullptr, int timeout_ms = -1,
             int64_t start_time = -1) {
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
    const bool filter_special = !show_all && ignore_sepcial_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };
    std::vector<PathInfo> files_info = {};
    for (auto &[path, attrs] : list_info) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
        return;
      }
      const std::string base_name = AMPathStr::basename(path);
      if (filter_hidden && is_hidden_name(base_name)) {
        continue;
      }
      if (isdir(attrs)) {
        auto new_parts = parts;
        new_parts.push_back(AMPathStr::basename(path));
        _walk(new_parts, result, errors, cur_depth + 1, max_depth, show_all,
              ignore_sepcial_file, error_callback, interrupt_flag, timeout_ms,
              start_time);
      } else {
        if (filter_special && !isreg(attrs)) {
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
           RMR &errors, AMFS::WalkErrorCallback error_callback = nullptr,
           amf interrupt_flag = nullptr, int timeout_ms = -1,
           int64_t start_time = -1) {
    if (interrupt_flag && interrupt_flag->check()) {
      return;
    }
    if (!isdir(attrs)) {
      ECM ecm = lib_unlink(path, interrupt_flag, timeout_ms, start_time);
      if (ecm.first != EC::Success) {
        if (error_callback && *error_callback) {
          (*error_callback)(path, ecm);
        }
        errors.emplace_back(path, ecm);
      }
      return;
    }

    auto [rcm2, file_list] =
        lib_listdir(path, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm2);
      }
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
      _rm(file.first, file.second, errors, error_callback, interrupt_flag,
          timeout_ms, start_time);
    }

    ECM ecm = lib_rmdir(path, interrupt_flag, timeout_ms, start_time);
    if (ecm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, ecm);
      }
      errors.emplace_back(path, ecm);
    }
  }

  void _chmod(const std::string &path, size_t mode, bool recursive,
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

    size_t file_type = attrs.permissions & LIBSSH2_SFTP_S_IFMT;
    size_t new_mode_int = (mode & ~LIBSSH2_SFTP_S_IFMT) | file_type;

    attrs.permissions = new_mode_int;
    attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;

    if (((size_t)attrs.permissions & 0777) != (mode & 0777)) {
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
      return {EC::InvalidArg, AMStr::amfmt("Invalid path: {}", path)};
    }
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }
    return {EC::Success, ""};
  }

public:
  using TerminalOutputCallback = std::function<void(const std::string &)>;

  TerminalWindowInfo terminal_window = {};
  amf terminal_interrupt_flag = std::make_shared<InterruptFlag>();
  TerminalOutputCallback terminal_output_cb = {};

  AMSFTPClient(const ConRequst &request,
               const std::vector<std::string> &keys = {},
               unsigned int tracer_capacity = 10, TraceCallback trace_cb = {},
               AuthCallback auth_cb = {})
      : AMSession(request, keys, tracer_capacity, std::move(trace_cb),
                  std::move(auth_cb)) {
    this->PROTOCOL = ClientProtocol::SFTP;
    if (request.trash_dir.empty()) {
      this->trash_dir = ".AMSFTP_Trash";
    }
  }

  // Get RTT (Round Trip Time), return average (ms)
  // Measure via a simple SFTP operation
  double GetRTT(ssize_t times = 5, amf interrupt_flag = nullptr) override {
    if (times <= 0)
      times = 1;
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (!session || !sftp) {
      return -1.0;
    }

    std::vector<double> rtts;
    rtts.reserve(times);

    // Use libssh2_sftp_stat to measure RTT (minimal-overhead SFTP op)
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    amf flag = interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    libssh2_session_set_blocking(session, 0);

    for (ssize_t i = 0; i < times; i++) {
      if (flag && flag->check()) {
        break;
      }

      double start = am_s();
      int rc = 0;
      WaitResult wr = WaitResult::Ready;

      while ((rc = libssh2_sftp_stat(sftp, "/", &attrs)) ==
             LIBSSH2_ERROR_EAGAIN) {
        wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag), start,
                             -1);
        if (wr != WaitResult::Ready) {
          break;
        }
      }

      if (wr != WaitResult::Ready) {
        break;
      }

      if (rc == 0) {
        double end = am_s();
        rtts.push_back(end - start);
      }
    }

    libssh2_session_set_blocking(session, 1);

    if (rtts.empty()) {
      return -1.0;
    }

    // Compute average
    double sum = 0.0;
    for (double rtt : rtts) {
      sum += rtt;
    }
    return sum * (double)1000.0 / static_cast<double>(rtts.size());
  }

  CR ConductCmd(const std::string &cmd, int max_time_ms = 3000,
                amf interrupt_flag = nullptr) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    amf flag = interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    std::string reason;
    // if (!IsCommandAllowed(cmd, &reason)) {
    //   return {ECM{EC::InvalidArg, reason}, {"", -1}};
    // }
    if (flag && flag->check()) {
      return {ECM{EC::Terminate, "Operation aborted before command sent"},
              {"", -1}};
    }

    SafeChannel sf(session);
    if (!sf.channel) {
      return {ECM{EC::NoConnection, "Channel not initialized"}, {"", -1}};
    }

    enum class CmdStage { BeforeSend, AwaitOutput, ReadingOutput, AwaitExit };
    CmdStage stage = CmdStage::BeforeSend;

    int64_t time_start = am_ms();
    int exit_status = -1;
    bool has_output = false;
    std::string output;
    std::array<char, 4096> buffer;
    WaitResult wr = WaitResult::Ready;
    int rc = 0;

    auto terminate_and_close = [&](bool send_exit) {
      libssh2_session_set_blocking(session, 1);
      if (send_exit) {
        sf.terminate_and_close();
      } else {
        sf.close();
      }
    };

    // Set non-blocking mode
    libssh2_session_set_blocking(session, 0);

    // 1. Execute command
    while ((rc = libssh2_channel_exec(sf.channel, cmd.c_str())) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag),
                           time_start, max_time_ms);
      if (wr != WaitResult::Ready) {
        goto cleanup;
      }
    }
    if (rc < 0) {
      libssh2_session_set_blocking(session, 1);
      return {ECM{GetLastEC(),
                  AMStr::amfmt("Channel exec failed: {}", GetLastErrorMsg())},
              {"", -1}};
    }
    stage = CmdStage::AwaitOutput;

    // 2. Read output
    while (true) {
      ssize_t nbytes =
          libssh2_channel_read(sf.channel, buffer.data(), buffer.size() - 1);

      if (nbytes > 0) {
        output.append(buffer.data(), static_cast<size_t>(nbytes));
        has_output = true;
        stage = CmdStage::ReadingOutput;
      } else if (nbytes == 0) {
        stage = CmdStage::AwaitExit;
        break; // EOF
      } else if (nbytes == LIBSSH2_ERROR_EAGAIN) {
        wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag),
                             time_start, max_time_ms);
        if (wr != WaitResult::Ready) {
          goto cleanup;
        }
      } else {
        libssh2_session_set_blocking(session, 1);
        return {ECM{GetLastEC(),
                    AMStr::amfmt("Channel read failed: {}", GetLastErrorMsg())},
                {"", -1}};
      }
    }

    // 3. Trim trailing output whitespace
    while (!output.empty() &&
           (output.back() == '\n' || output.back() == '\r')) {
      output.pop_back();
    }

    // 4. Close channel non-blocking
    while ((rc = sf.close_nonblock()) == LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag),
                           time_start, max_time_ms);
      if (wr != WaitResult::Ready) {
        goto cleanup;
      }
    }

    // 5. Get exit status
    exit_status = libssh2_channel_get_exit_status(sf.channel);

    libssh2_session_set_blocking(session, 1);
    return {ECM{EC::Success, ""}, {output, exit_status}};

  cleanup:
    switch (wr) {
    case WaitResult::Interrupted:
      if (stage == CmdStage::BeforeSend) {
        terminate_and_close(false);
        return {ECM{EC::Terminate, "Operation aborted before command sent"},
                {output, -1}};
      }
      if (stage == CmdStage::AwaitOutput && !has_output) {
        terminate_and_close(true);
        return {ECM{EC::Terminate,
                    AMStr::amfmt("Command canceled before output: {}", cmd)},
                {output, -1}};
      }
      terminate_and_close(true);
      return {
          ECM{EC::Terminate,
              AMStr::amfmt("Command interrupted before exit status: {}", cmd)},
          {output, -1}};
    case WaitResult::Timeout:
      terminate_and_close(true);
      return {ECM{EC::OperationTimeout,
                  AMStr::amfmt("Command timed out (killed): {}", cmd)},
              {output, -1}};
    case WaitResult::Error:
      terminate_and_close(true);
      return {ECM{EC::SocketRecvError,
                  AMStr::amfmt("Socket error during command: {}", cmd)},
              {output, -1}};
    default:
      terminate_and_close(true);
      return {ECM{EC::UnknownError, AMStr::amfmt("Command aborted: {}", cmd)},
              {output, -1}};
    }
  }

  // Terminal Deprecated Funtions
  /*
      ECM TerminalInit(const TerminalWindowInfo &window = {},
                       TerminalOutputCallback output_cb = {},
                       amf interrupt_flag = nullptr, int timeout_ms = -1,
                       int64_t start_time = -1) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!session) {
      return {EC::NoSession, "Session not initialized"};
    }

    terminal_window = window;
    if (output_cb) {
      terminal_output_cb = std::move(output_cb);
    }

    amf flag = interrupt_flag ? interrupt_flag :
  this->terminal_interrupt_flag; start_time = start_time == -1 ? am_ms() :
  start_time; if (flag && flag->check()) { terminal_channel.reset(); return
  {EC::Terminate, "Terminal init interrupted"};
    }

    terminal_channel.reset();
    terminal_channel = std::make_unique<SafeChannel>(session);
    if (!terminal_channel->channel) {
      terminal_channel.reset();
      return {EC::NoConnection, "Terminal channel not initialized"};
    }

    libssh2_session_set_blocking(session, 0);

    int rc = 0;
    WaitResult wr = WaitResult::Ready;
    while ((rc = libssh2_channel_request_pty_ex(
                terminal_channel->channel, terminal_window.term.c_str(),
                static_cast<unsigned int>(terminal_window.term.size()),
  nullptr, 0, terminal_window.cols, terminal_window.rows,
                terminal_window.width, terminal_window.height)) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag),
  start_time, timeout_ms); if (wr != WaitResult::Ready) { goto cleanup;
      }
    }
    if (rc != 0) {
      libssh2_session_set_blocking(session, 1);
      terminal_channel.reset();
      return {GetLastEC(), AMStr::amfmt("Terminal request pty failed: {}",
                                        GetLastErrorMsg())};
    }

    while ((rc = libssh2_channel_shell(terminal_channel->channel)) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, MakeInterruptCb(flag),
  start_time, timeout_ms); if (wr != WaitResult::Ready) { goto cleanup;
      }
    }
    if (rc != 0) {
      libssh2_session_set_blocking(session, 1);
      terminal_channel.reset();
      return {GetLastEC(), AMStr::amfmt("Terminal start shell failed: {}",
                                        GetLastErrorMsg())};
    }

    libssh2_session_set_blocking(session, 1);
    return {EC::Success, ""};

  cleanup:
    libssh2_session_set_blocking(session, 1);
    terminal_channel.reset();
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Terminal init timed out"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Terminal init interrupted"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during terminal init"};
    default:
      return {EC::UnknownError, "Terminal init failed"};
    }
  }

  ECM TerminalWrite(const std::string &msg, amf interrupt_flag = nullptr,
                    int timeout_ms = -1, int64_t start_time = -1) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!terminal_channel || !terminal_channel->channel) {
      return {EC::NoConnection, "Terminal not initialized"};
    }

    amf flag = interrupt_flag ? interrupt_flag :
  this->terminal_interrupt_flag; start_time = start_time == -1 ? am_ms() :
  start_time; if (flag && flag->check()) { terminal_channel.reset(); return
  {EC::Terminate, "Terminal interrupted"};
    }

    libssh2_session_set_blocking(session, 0);
    size_t offset = 0;
    WaitResult wr = WaitResult::Ready;
    while (offset < msg.size()) {
      if (flag && flag->check()) {
        wr = WaitResult::Interrupted;
        goto cleanup;
      }
      ssize_t rc =
          libssh2_channel_write(terminal_channel->channel, msg.data() +
  offset, static_cast<int>(msg.size() - offset)); if (rc > 0) { offset +=
  static_cast<size_t>(rc); continue;
      }
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        wr = wait_for_socket(SocketWaitType::Write, MakeInterruptCb(flag),
  start_time, timeout_ms); if (wr != WaitResult::Ready) { goto cleanup;
        }
        continue;
      }
      libssh2_session_set_blocking(session, 1);
      return {GetLastEC(),
              AMStr::amfmt("Terminal write failed: {}", GetLastErrorMsg())};
    }

    libssh2_session_set_blocking(session, 1);
    return {EC::Success, ""};

  cleanup:
    libssh2_session_set_blocking(session, 1);
    terminal_channel.reset();
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Terminal write timed out"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Terminal interrupted"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during terminal write"};
    default:
      return {EC::UnknownError, "Terminal write failed"};
    }
  }

  std::pair<ECM, std::string>
  TerminalRead(amf interrupt_flag = nullptr, int timeout_ms = -1,
               int64_t start_time = -1, bool wait_for_data = true) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!terminal_channel || !terminal_channel->channel) {
      return {ECM{EC::NoConnection, "Terminal not initialized"}, ""};
    }

    amf flag = interrupt_flag ? interrupt_flag :
  this->terminal_interrupt_flag; start_time = start_time == -1 ? am_ms() :
  start_time; if (flag && flag->check()) { terminal_channel.reset(); return
  {ECM{EC::Terminate, "Terminal interrupted"}, ""};
    }

    libssh2_session_set_blocking(session, 0);

    std::string output;
    std::array<char, 4096> buffer;
    WaitResult wr = WaitResult::Ready;

    if (wait_for_data) {
      wr = wait_for_socket(SocketWaitType::Read, MakeInterruptCb(flag),
  start_time, timeout_ms); if (wr != WaitResult::Ready) { goto cleanup;
      }
    }

    while (true) {
      if (flag && flag->check()) {
        wr = WaitResult::Interrupted;
        goto cleanup;
      }
      ssize_t nbytes = libssh2_channel_read(terminal_channel->channel,
                                            buffer.data(), buffer.size());
      if (nbytes > 0) {
        std::string chunk(buffer.data(), static_cast<size_t>(nbytes));
        output += chunk;
        if (terminal_output_cb) {
          CallCallbackSafe(terminal_output_cb, chunk);
        }
        continue;
      }
      if (nbytes == 0) {
        terminal_channel->close();
        terminal_channel.reset();
        libssh2_session_set_blocking(session, 1);
        return {ECM{EC::ChannelClosed, "Terminal closed by remote"}, output};
      }
      if (nbytes == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      libssh2_session_set_blocking(session, 1);
      return {ECM{GetLastEC(),
                  AMStr::amfmt("Terminal read failed: {}",
                               GetLastErrorMsg())},
              output};
    }

    libssh2_session_set_blocking(session, 1);
    return {ECM{EC::Success, ""}, output};

  cleanup:
    libssh2_session_set_blocking(session, 1);
    switch (wr) {
    case WaitResult::Timeout:
      return {ECM{EC::OperationTimeout, "Terminal read timed out"}, ""};
    case WaitResult::Interrupted:
      terminal_channel.reset();
      return {ECM{EC::Terminate, "Terminal interrupted"}, ""};
    case WaitResult::Error:
      terminal_channel.reset();
      return {ECM{EC::SocketRecvError, "Socket error during terminal read"},
              ""};
    default:
      terminal_channel.reset();
      return {ECM{EC::UnknownError, "Terminal read failed"}, ""};
    }
  }

  std::pair<ECM, std::pair<std::string, int>>
  TerminalExec(const std::string &cmd, amf interrupt_flag = nullptr,
               int timeout_ms = -1, int64_t start_time = -1) {
    if (cmd.empty()) {
      return {ECM{EC::InvalidArg, "Empty command"}, {"", -1}};
    }
    amf flag = interrupt_flag ? interrupt_flag :
  this->terminal_interrupt_flag; start_time = start_time == -1 ? am_ms() :
  start_time;

    static std::atomic<size_t> marker_seq{0};
    const size_t seq = ++marker_seq;
    const std::string marker =
        AMStr::amfmt("__AMSFTP_DONE__{}__", std::to_string(seq));

    std::string cmd_line = cmd;
    while (!cmd_line.empty() &&
           (cmd_line.back() == '\n' || cmd_line.back() == '\r')) {
      cmd_line.pop_back();
    }
    cmd_line += AMStr::amfmt("; echo {}:$?\n", marker);

    ECM wrc = TerminalWrite(cmd_line, flag, timeout_ms, start_time);
    if (wrc.first != EC::Success) {
      return {wrc, {"", -1}};
    }

    std::string output;
    while (true) {
      auto [rcm, chunk] = TerminalRead(flag, timeout_ms, start_time, true);
      if (rcm.first != EC::Success) {
        return {rcm, {output, -1}};
      }
      if (!chunk.empty()) {
        output += chunk;
      }
      auto pos = output.find(marker);
      if (pos == std::string::npos) {
        if (flag && flag->check()) {
          return {ECM{EC::Terminate, "Terminal interrupted"}, {output, -1}};
        }
        if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
          return {ECM{EC::OperationTimeout, "Terminal exec timed out"},
                  {output, -1}};
        }
        continue;
      }

      int exit_code = -1;
      size_t code_pos = pos + marker.size();
      if (code_pos < output.size() && output[code_pos] == ':') {
        ++code_pos;
        size_t end = code_pos;
        while (end < output.size() &&
               (output[end] == '-' ||
                (output[end] >= '0' && output[end] <= '9'))) {
          ++end;
        }
        try {
          exit_code = std::stoi(output.substr(code_pos, end - code_pos));
        } catch (...) {
          exit_code = -1;
        }
      }

      std::string out_only = output.substr(0, pos);
      return {ECM{EC::Success, ""}, {out_only, exit_code}};
    }
  }

  std::pair<ECM, std::string> TerminalInput(const std::string &msg,
                                            amf interrupt_flag = nullptr,
                                            int timeout_ms = -1,
                                            int64_t start_time = -1) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!terminal_channel || !terminal_channel->channel) {
      return {ECM{EC::NoConnection, "Terminal not initialized"}, ""};
    }

    amf flag = interrupt_flag ? interrupt_flag :
  this->terminal_interrupt_flag; start_time = start_time == -1 ? am_ms() :
  start_time; if (flag && flag->check()) { terminal_channel.reset(); return
  {ECM{EC::Terminate, "Terminal interrupted"}, ""};
    }

    libssh2_session_set_blocking(session, 0);

    size_t offset = 0;
    WaitResult wr = WaitResult::Ready;
    while (offset < msg.size()) {
      if (flag && flag->check()) {
        wr = WaitResult::Interrupted;
        goto cleanup;
      }
      ssize_t rc =
          libssh2_channel_write(terminal_channel->channel, msg.data() +
  offset, static_cast<int>(msg.size() - offset)); if (rc > 0) { offset +=
  static_cast<size_t>(rc); continue;
      }
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        wr = wait_for_socket(SocketWaitType::Write, MakeInterruptCb(flag),
  start_time, timeout_ms); if (wr != WaitResult::Ready) { goto cleanup;
        }
        continue;
      }
      libssh2_session_set_blocking(session, 1);
      return {ECM{GetLastEC(),
                  AMStr::amfmt("Terminal write failed: {}",
  GetLastErrorMsg())},
              ""};
    }

    std::string output;
    std::array<char, 4096> buffer;
    while (true) {
      if (flag && flag->check()) {
        wr = WaitResult::Interrupted;
        goto cleanup;
      }
      ssize_t nbytes = libssh2_channel_read(terminal_channel->channel,
                                            buffer.data(), buffer.size());
      if (nbytes > 0) {
        std::string chunk(buffer.data(), static_cast<size_t>(nbytes));
        output += chunk;
        if (terminal_output_cb) {
          CallCallbackSafe(terminal_output_cb, chunk);
        }
        continue;
      }
      if (nbytes == 0) {
        terminal_channel->close();
        terminal_channel.reset();
        libssh2_session_set_blocking(session, 1);
        return {ECM{EC::ChannelClosed, "Terminal closed by remote"}, output};
      }
      if (nbytes == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      libssh2_session_set_blocking(session, 1);
      return {ECM{GetLastEC(),
                  AMStr::amfmt("Terminal read failed: {}",
  GetLastErrorMsg())}, output};
    }

    libssh2_session_set_blocking(session, 1);
    return {ECM{EC::Success, ""}, output};

  cleanup:
    libssh2_session_set_blocking(session, 1);
    terminal_channel.reset();
    switch (wr) {
    case WaitResult::Timeout:
      return {ECM{EC::OperationTimeout, "Terminal write timed out"}, ""};
    case WaitResult::Interrupted:
      return {ECM{EC::Terminate, "Terminal interrupted"}, ""};
    case WaitResult::Error:
      return {ECM{EC::SocketRecvError, "Socket error during terminal write"},
              ""};
    default:
      return {ECM{EC::UnknownError, "Terminal write failed"}, ""};
    }
  }

  ECM TerminalClose() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!terminal_channel || !terminal_channel->channel) {
      return {EC::Success, ""};
    }
    libssh2_session_set_blocking(session, 1);
    terminal_channel->close();
    terminal_channel.reset();
    return {EC::Success, ""};
  }
  */

  OS_TYPE GetOSType(bool update = false) override {
    if (os_type != OS_TYPE::Uncertain && !update) {
      return os_type;
    }
    auto [rcm2, out2] =
        ConductCmd("powershell -NoProfile -Command "
                   "\"[System.Environment]::OSVersion.VersionString\"",
                   3000);
    int code = out2.second;
    std::string out_str = out2.first;
    if (out_str.find("Windows") != std::string::npos) {
      os_type = OS_TYPE::Windows;
      return os_type;
    }

    auto [rcm, out] = ConductCmd("uname -s", 3000);
    if (rcm.first != EC::Success) {
      os_type = OS_TYPE::Uncertain;
      return os_type;
    }
    code = out.second;
    if (code == 0) {
      out_str = AMStr::lowercase(out.first);
      if (out_str.find("cygwin") != std::string::npos) {
        os_type = OS_TYPE::Windows;
      } else if (out_str.find("darwin") != std::string::npos) {
        os_type = OS_TYPE::MacOS;
      } else if (out_str.find("linux") != std::string::npos) {
        os_type = OS_TYPE::Linux;
      } else if (out_str.find("mingw") != std::string::npos) {
        os_type = OS_TYPE::Windows;
      } else if (out_str.find("msys") != std::string::npos) {
        os_type = OS_TYPE::Windows;
      } else if (out_str.find("freebsd") != std::string::npos) {
        os_type = OS_TYPE::FreeBSD;
      } else {
        os_type = OS_TYPE::Unix;
      }
      return os_type;
    }

    return OS_TYPE::Unknown;
  }

  std::string StrUid(const long &uid) override {
    if (user_id_map.find(uid) != user_id_map.end()) {
      return user_id_map[uid];
    }

    std::string cmd = AMStr::amfmt("id -un {}", std::to_string(uid));
    auto [rcm, cr] = ConductCmd(cmd, 3000);
    if (rcm.first != EC::Success) {
      return "unknown";
    }
    if (cr.second != 0) {
      return "unknown";
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
    ECM ecm = BaseConnect(force, interrupt_flag, start_time, timeout_ms);
    if (!not_init && isok(ecm)) {
      GetOSType();
      GetHomeDir();
    }
    return ecm;
  }

  // Parse and return absolute path,
  // ~ is resolved in client; .. and . are resolved by server; such symbols require path to exist
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
      // Resolve ~ symbol
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
      // Windows server may prepend / or \ to path; remove it
      return {rcm2, path_t.substr(1)};
    }
    return {rcm2, path_t};
  }

  std::pair<ECM, std::unordered_map<std::string, ECM>>
  chmod(const std::string &path, std::variant<std::string, size_t> mode,
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
    size_t mode_int;
    if (std::holds_alternative<std::string>(mode)) {
      if (!AMStr::IsModeValid(std::get<std::string>(mode))) {
        return {ECM{EC::InvalidArg, AMStr::amfmt("Invalid mode: {}",
                                                 std::get<std::string>(mode))},
                {}};
      }
      mode_int = AMStr::ModeTrans(std::get<std::string>(mode));
    } else if (std::holds_alternative<size_t>(mode)) {
      if (!AMStr::IsModeValid(std::get<size_t>(mode))) {
        return {ECM{EC::InvalidArg,
                    AMStr::amfmt("Invalid mode: {}",
                                 std::to_string(std::get<size_t>(mode)))},
                {}};
      }
      mode_int = std::get<size_t>(mode);
    } else {
      return {ECM{EC::InvalidArg, AMStr::amfmt("Invalid mode data type")}, {}};
    }
    _chmod(path, mode_int, recursive, ecm_map, attrs, interrupt_flag,
           timeout_ms, start_time);
    return {ECM{EC::Success, ""}, ecm_map};
  }

  // Get path info (with AMFS::abspath)
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

  // Create one-level directory (with AMFS::abspath)
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
                AMStr::amfmt("Path exists and is not a directory: {}", path)};
      }
    }
    return lib_mkdir(path, interrupt_flag, timeout_ms, start_time);
  }

  // Recursively create nested directories until error (with AMFS::abspath)
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
              AMStr::amfmt("Path split failed, get empty parts: {}", path)};
    } else if (parts.size() == 1) {
      return lib_mkdir(path, interrupt_flag, timeout_ms, start_time);
    }

    std::string current_path = parts.front();
    for (size_t i = 1; i < parts.size(); i++) {
      current_path = AMPathStr::join(current_path, parts[i], SepType::Unix);
      auto [rcm2, attrs] = lib_getstat(current_path, false, interrupt_flag,
                                       timeout_ms, start_time);
      if (rcm2.first == EC::Success) {
        if (isdir(attrs)) {
          continue;
        } else {
          return {EC::PathAlreadyExists,
                  AMStr::amfmt("Path exists and is not a directory: {}",
                               current_path)};
        }
      }
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

  // Delete file or directory (with AMFS::abspath)
  std::pair<ECM, RMR> remove(const std::string &path,
                             AMFS::WalkErrorCallback error_callback = nullptr,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) override {
    ECM rcm0 = _precheck(path);
    if (rcm0.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm0);
      }
      return {rcm0, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    RMR errors = {};
    auto [rcm, sr] =
        lib_getstat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      return {rcm, {}};
    }
    _rm(path, sr, errors, error_callback, interrupt_flag, timeout_ms,
        start_time);
    return {ECM{EC::Success, ""}, errors};
  }

  // Rename original path to new path (with AMFS::abspath)
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

  // Safely delete file/dir by moving into trash_dir
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

    // Get current time in format 2026-01-01-19-06
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

  // Move source path to destination folder

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
                            AMStr::amfmt("Invalid path: {} or {}", srcf,
  dstf));
    }
    auto [rcm, br] = exists(srcf);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (!br) {
      return {EC::PathNotExist, AMStr::amfmt("Src not exists: {}", srcf)};
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
                  AMStr::amfmt("Dst dir not exists: {}", dstf)};
        }
      }
    } else if (!br2) {
      return {EC::NotADirectory,
              AMStr::amfmt("Dst exists but not a directory: {}", dstf)};
    }

    std::string dst_path = AMPathStr::join(dstf, AMPathStr::basename(srcf));
    auto [rcm0, sbr0] = exists(dst_path);

    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    if (sbr0) {
      return {EC::PathAlreadyExists,
              AMStr::amfmt("Dst {} already has path named {}", dstf,
                          AMPathStr::basename(srcf))};
    }

    std::string command = "cp -r \"" + srcf + "\" \"" + dstf + "\"";

    auto [rcm3, resp] = ConductCmd(command);

    if (rcm3.first != EC::Success) {
      return rcm3;
    }

    if (resp.second != 0) {
      std::string msg =
          AMStr::amfmt("Copy cmd conducted failed with exit code: {}, error:
  {}", resp.second, resp.first); trace(TraceLevel::Error,
  EC::InhostCopyFailed, AMStr::amfmt("{}@{}->{}", res_data.nickname, srcf,
  dstf), "Copy", msg); return {EC::InhostCopyFailed, msg};
    }

    return {EC::Success, ""};
  }*/

  // Recursively walk all files and nested dirs under a path, return vector<PathInfo>
  std::pair<ECM, WRI> iwalk(const std::string &path, bool show_all = false,
                            bool ignore_sepcial_file = true,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) override {
    ECM rcm = _precheck(path);
    RMR errors = {};
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      return {rcm, {WRV{}, errors}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    auto [rcm2, attrs] =
        lib_getstat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm2);
      }
      errors.emplace_back(path, rcm2);
      return {rcm2, {WRV{}, errors}};
    }
    if (!isdir(attrs)) {
      if (!show_all && ignore_sepcial_file && !isreg(attrs)) {
        return {ECM{EC::Success, ""}, {WRV{}, errors}};
      }
      return {ECM{EC::Success, ""}, {WRV{FormatStat(path, attrs)}, errors}};
    }
    // get all files and deepest folders
    WRV result = {};
    _iwalk(path, attrs, result, errors, show_all, ignore_sepcial_file,
           error_callback, interrupt_flag, timeout_ms, start_time);
    if (interrupt_flag && interrupt_flag->check()) {
      ECM out = {EC::Terminate, "Interrupted by user"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      return {out, {result, errors}};
    }
    return {ECM{EC::Success, ""}, {result, errors}};
  }

  // Actual walk function, returns vector of ([root_path, part1, part2, ...], PathInfo)
  std::pair<ECM, WRDR> walk(const std::string &path, int max_depth = -1,
                            bool show_all = false,
                            bool ignore_special_file = false,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) override {
    ECM rcm0 = _precheck(path);
    RMR errors = {};
    if (rcm0.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm0);
      }
      return {rcm0, {WRD{}, errors}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    interrupt_flag =
        interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    start_time = start_time == -1 ? am_ms() : start_time;
    auto [rcm, br] = stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      errors.emplace_back(path, rcm);
      return {rcm, {WRD{}, errors}};
    } else if (br.type != PathType::DIR) {
      ECM out = {EC::NotADirectory, "Path is not a directory"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
      return {out, {WRD{}, errors}};
    }
    WRD result_dict = {};
    std::vector<std::string> parts = {path};
    _walk(parts, result_dict, errors, 0, max_depth, show_all,
          ignore_special_file, error_callback, interrupt_flag, timeout_ms,
          start_time);
    // Print type of result_dict
    if (interrupt_flag && interrupt_flag->check()) {
      ECM out = {EC::Terminate, "Interrupted by user, no action conducted"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      return {out, {result_dict, errors}};
    }
    return {ECM{EC::Success, ""}, {result_dict, errors}};
  }
};
