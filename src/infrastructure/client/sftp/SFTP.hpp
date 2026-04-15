#pragma once
// standard library
#include "domain/client/ClientModel.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/core/Enum.hpp"
#include "foundation/tools/string.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#define _WINSOCKAPI_
#include <shlobj.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#ifdef __linux__
#include <sys/eventfd.h>
#endif
#include <unistd.h>
#endif

// project headers
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/auth.hpp"
#include "infrastructure/client/common/Base.hpp"
#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#ifndef _WIN32
using SOCKET = int;
constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
inline int closesocket(SOCKET s) { return close(s); }
#endif

namespace AMInfra::client::SFTP {
namespace detail {
// Socket wait direction
enum class SocketWaitType {
  Read,        // Wait for socket readable
  Write,       // Wait for socket writable
  ReadWrite,   // Wait for both readable and writable
  ReadOrWrite, // Wait for readable or writable, returns ReadReady/WriteReady
  Auto         // Determine from libssh2_session_block_directions
};

class DeathClockProtocol {
public:
  explicit DeathClockProtocol(
      const AMDomain::client::ClientControlComponent &control,
      int death_clock_timeout_ms = AMDomain::client::kFilesystemOpGraceWaitMs)
      : control_(control), death_start_(AMTime::SteadyNow()),
        death_clock_timeout_ms_(
            death_clock_timeout_ms > 0
                ? death_clock_timeout_ms
                : AMDomain::client::kFilesystemOpGraceWaitMs) {
    Refresh();
  }

  void Refresh() {
    if (activated_) {
      return;
    }
    if (control_.IsInterrupted()) {
      death_start_ = AMTime::SteadyNow();
      activated_ = true;
      reason_ = WaitResult::Interrupted;
      return;
    }
    if (control_.IsTimeout()) {
      death_start_ = AMTime::SteadyNow();
      activated_ = true;
      reason_ = WaitResult::Timeout;
    }
  }

  [[nodiscard]] bool IsActivated() const { return activated_; }

  [[nodiscard]] WaitResult Reason() const { return reason_; }

  [[nodiscard]] const AMDomain::client::ClientControlComponent &
  Control() const {
    return control_;
  }

  [[nodiscard]] std::optional<WaitResult> Check() {
    Refresh();
    if (!activated_) {
      return std::nullopt;
    }
    if (death_clock_timeout_ms_ <= 0) {
      return reason_;
    }
    if (AMTime::IntervalMS(death_start_, AMTime::SteadyNow()) >=
        static_cast<double>(death_clock_timeout_ms_)) {
      return reason_;
    }
    return std::nullopt;
  }

  [[nodiscard]] int ResolveTimeoutMs() {
    Refresh();
    if (activated_) {
      return RemainingDeathTimeoutMs_();
    }
    const auto remain_opt = control_.RemainingTimeMs();
    if (!remain_opt.has_value()) {
      return -1;
    }
    const unsigned int remain = *remain_opt;
    const auto max_int =
        static_cast<unsigned int>((std::numeric_limits<int>::max)());
    return remain > max_int ? static_cast<int>(max_int)
                            : static_cast<int>(remain);
  }

  [[nodiscard]] int BuildDeathTimeoutMs() const {
    return death_clock_timeout_ms_ > 0 ? death_clock_timeout_ms_ : 1;
  }

private:
  const AMDomain::client::ClientControlComponent &control_;
  std::chrono::steady_clock::time_point death_start_;
  int death_clock_timeout_ms_ = AMDomain::client::kFilesystemOpGraceWaitMs;
  bool activated_ = false;
  WaitResult reason_ = WaitResult::Interrupted;

  [[nodiscard]] int RemainingDeathTimeoutMs_() const {
    if (death_clock_timeout_ms_ <= 0) {
      return 0;
    }
    const double elapsed_ms =
        AMTime::IntervalMS(death_start_, AMTime::SteadyNow());
    const int elapsed = elapsed_ms <= 0.0 ? 0 : static_cast<int>(elapsed_ms);
    const int remaining = death_clock_timeout_ms_ - elapsed;
    return remaining > 0 ? remaining : 0;
  }
};

// Cross-platform socket connector
class SocketConnector {
public:
  SOCKET sock = INVALID_SOCKET;
  std::string error_msg = "";
  EC error_code = EC::Success;

  SocketConnector() = default;

  ~SocketConnector() = default;

  bool Connect(const std::string &hostname, int port,
               const AMDomain::client::ClientControlComponent &control = {},
               std::function<void(const std::string &, const std::string &)>
                   state_cb = {}) {
    static constexpr int64_t kDefaultConnectTimeoutMs = 6000;
    const int64_t connect_start_ms = AMTime::miliseconds();

    auto update_state = [&](const std::string &state_info,
                            const std::string &target) {
      if (state_cb) {
        (void)CallCallbackSafe(state_cb, state_info, target);
      }
    };
    auto mark_interrupted = [&]() -> bool {
      error_code = EC::Terminate;
      error_msg = "Connection interrupted";
      return false;
    };
    auto mark_timeout = [&]() -> bool {
      error_code = EC::OperationTimeout;
      error_msg = "Connection timed out";
      return false;
    };
    auto check_stop = [&]() -> bool {
      if (control.IsInterrupted()) {
        return mark_interrupted();
      }
      if (control.IsTimeout()) {
        return mark_timeout();
      }
      return true;
    };
    auto remaining_ms = [&]() -> int64_t {
      if (const auto remain_opt = control.RemainingTimeMs();
          remain_opt.has_value()) {
        return static_cast<int64_t>(*remain_opt);
      }
      return kDefaultConnectTimeoutMs -
             (AMTime::miliseconds() - connect_start_ms);
    };

    if (!check_stop()) {
      return false;
    }

    update_state(AMStr::fmt("resolving hostname: {}", hostname), hostname);

    // 1. DNS resolve - use AF_UNSPEC for IPv4/IPv6
    addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC; // support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int dns_err = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(),
                              &hints, &result);
    if (dns_err != 0) {
#ifdef _WIN32
      const wchar_t *dns_err_w = gai_strerrorW(dns_err);
      auto dns_err_str =
          dns_err_w != nullptr ? AMStr::wstr(dns_err_w) : std::string{};
      error_msg = dns_err_str.empty() ? "DNS resolve failed" : dns_err_str;
#else
      auto dns_err_str = gai_strerror(dns_err);
      error_msg = dns_err_str == nullptr ? "DNS resolve failed"
                                         : std::string(dns_err_str);
#endif
      error_code = EC::DNSResolveError;
      return false;
    }

    if (!check_stop()) {
      freeaddrinfo(result);
      return false;
    }

    // 2. Try connecting all resolved addresses (IPv4/IPv6 dual-stack)
    addrinfo *rp = nullptr;
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
      const std::string endpoint = SockAddrToEndpoint_(rp->ai_addr, port);
      const std::string connect_target =
          endpoint.empty() ? AMStr::fmt("{}:{}", hostname, port) : endpoint;
      update_state(AMStr::fmt("creating TCP connect to: {}", connect_target),
                   connect_target);
      if (!check_stop()) {
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

      if (!check_stop()) {
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
        if (!check_stop()) {
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
      int select_result = 0;
      bool timed_out = false;

      while (true) {
        if (!check_stop()) {
          closesocket(sock);
          sock = INVALID_SOCKET;
          freeaddrinfo(result);
          return false;
        }

        const int64_t current_remaining_ms = remaining_ms();
        if (current_remaining_ms <= 0) {
          timed_out = true;
          break;
        }

        const int64_t wait_ms = current_remaining_ms > 100
                                    ? static_cast<int64_t>(100)
                                    : current_remaining_ms;

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
      if (!check_stop()) {
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
  [[nodiscard]] static std::string SockAddrToEndpoint_(const sockaddr *addr,
                                                       int fallback_port) {
    if (addr == nullptr) {
      return "";
    }
    char ip_buffer[INET6_ADDRSTRLEN] = {0};
    std::string ip = "";
    int endpoint_port = fallback_port;
    if (addr->sa_family == AF_INET) {
      auto *addr4 = reinterpret_cast<const sockaddr_in *>(addr);
      const char *ip_ptr = inet_ntop(AF_INET, &(addr4->sin_addr), ip_buffer,
                                     static_cast<socklen_t>(sizeof(ip_buffer)));
      if (ip_ptr != nullptr) {
        ip = ip_ptr;
      }
      if (addr4->sin_port != 0) {
        endpoint_port = static_cast<int>(ntohs(addr4->sin_port));
      }
    } else if (addr->sa_family == AF_INET6) {
      auto *addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
      const char *ip_ptr = inet_ntop(AF_INET6, &(addr6->sin6_addr), ip_buffer,
                                     static_cast<socklen_t>(sizeof(ip_buffer)));
      if (ip_ptr != nullptr) {
        ip = ip_ptr;
      }
      if (addr6->sin6_port != 0) {
        endpoint_port = static_cast<int>(ntohs(addr6->sin6_port));
      }
    }
    if (ip.empty()) {
      return "";
    }
    return AMStr::fmt("{}:{}", ip, endpoint_port);
  }

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

#ifdef _WIN32
inline static std::atomic<bool> is_wsa_initialized(false);
inline void cleanup_wsa() {
  // Cleanup WSA if initialized
  if (is_wsa_initialized.load(std::memory_order_relaxed)) {
    WSACleanup();
    is_wsa_initialized.store(false, std::memory_order_relaxed);
  }
}
inline void AMInitWSA() {
  if (is_wsa_initialized.load(std::memory_order_relaxed)) {
    return;
  }
  WSADATA wsaData;
  int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (result != 0) {
    throw std::runtime_error("WSAStartup failed");
  }
  is_wsa_initialized.store(true, std::memory_order_relaxed);
  std::atexit(cleanup_wsa);
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
  static const std::vector<std::string> private_key_headers = {
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

inline bool IsWouldBlockSocketError_() {
#ifdef _WIN32
  return WSAGetLastError() == WSAEWOULDBLOCK;
#else
  return errno == EWOULDBLOCK || errno == EAGAIN;
#endif
}

inline void CloseSocketSafe_(SOCKET &fd) {
  if (fd == INVALID_SOCKET) {
    return;
  }
  closesocket(fd);
  fd = INVALID_SOCKET;
}

inline bool SetSocketNonBlocking_(SOCKET fd) {
#ifdef _WIN32
  u_long mode = 1;
  return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

class InterruptWakeBridge {
public:
  enum class Backend { None, SocketPair, Pipe, EventFd };

  ~InterruptWakeBridge() { Close(); }

  bool Ensure() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (read_sock_ != INVALID_SOCKET && write_sock_ != INVALID_SOCKET) {
      return true;
    }
    CloseUnlocked_();
    return CreateUnlocked_();
  }

  [[nodiscard]] SOCKET ReadSocket() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return read_sock_;
  }

  void Close() {
    std::lock_guard<std::mutex> lock(mtx_);
    CloseUnlocked_();
  }

  void Signal() {
    SOCKET wake_sock = INVALID_SOCKET;
    Backend backend = Backend::None;
    {
      std::lock_guard<std::mutex> lock(mtx_);
      wake_sock = write_sock_;
      backend = backend_;
    }
    if (wake_sock == INVALID_SOCKET) {
      return;
    }

#ifdef _WIN32
    const char c = 1;
    int rc = send(wake_sock, &c, 1, 0);
    if (rc == SOCKET_ERROR && !IsWouldBlockSocketError_()) {
      return;
    }
#else
    if (backend == Backend::EventFd) {
      uint64_t one = 1;
      ssize_t rc = ::write(wake_sock, &one, sizeof(one));
      if (rc < 0 && !IsWouldBlockSocketError_()) {
        return;
      }
      return;
    }
    const char c = 1;
    ssize_t rc = ::write(wake_sock, &c, 1);
    if (rc < 0 && !IsWouldBlockSocketError_()) {
      return;
    }
#endif
  }

  void Drain() {
    auto wake_sock = INVALID_SOCKET;
    Backend backend = Backend::None;
    {
      std::lock_guard<std::mutex> lock(mtx_);
      wake_sock = read_sock_;
      backend = backend_;
    }
    if (wake_sock == INVALID_SOCKET) {
      return;
    }

#ifdef _WIN32
    char buffer[64];
    while (true) {
      int rc = recv(wake_sock, buffer, sizeof(buffer), 0);
      if (rc > 0) {
        if (rc < static_cast<int>(sizeof(buffer))) {
          return;
        }
        continue;
      }
      if (rc == 0) {
        return;
      }
      if (rc == SOCKET_ERROR && IsWouldBlockSocketError_()) {
        return;
      }
      return;
    }
#else
    if (backend == Backend::EventFd) {
      uint64_t value = 0;
      while (true) {
        ssize_t rc = ::read(wake_sock, &value, sizeof(value));
        if (rc == static_cast<ssize_t>(sizeof(value))) {
          continue;
        }
        if (rc < 0 && IsWouldBlockSocketError_()) {
          return;
        }
        return;
      }
    }
    char buffer[64];
    while (true) {
      ssize_t rc = ::read(wake_sock, buffer, sizeof(buffer));
      if (rc > 0) {
        if (rc < static_cast<ssize_t>(sizeof(buffer))) {
          return;
        }
        continue;
      }
      if (rc == 0) {
        return;
      }
      if (rc < 0 && IsWouldBlockSocketError_()) {
        return;
      }
      return;
    }
#endif
  }

private:
  bool CreateUnlocked_() {
    SOCKET read_sock = INVALID_SOCKET;
    SOCKET write_sock = INVALID_SOCKET;
    Backend backend = Backend::None;
#ifdef _WIN32
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
      return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listen_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ==
        SOCKET_ERROR) {
      CloseSocketSafe_(listen_sock);
      return false;
    }
    if (listen(listen_sock, 1) == SOCKET_ERROR) {
      CloseSocketSafe_(listen_sock);
      return false;
    }

    int addr_len = sizeof(addr);
    if (getsockname(listen_sock, reinterpret_cast<sockaddr *>(&addr),
                    &addr_len) == SOCKET_ERROR) {
      CloseSocketSafe_(listen_sock);
      return false;
    }

    write_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (write_sock == INVALID_SOCKET) {
      CloseSocketSafe_(listen_sock);
      return false;
    }
    if (connect(write_sock, reinterpret_cast<sockaddr *>(&addr),
                sizeof(addr)) == SOCKET_ERROR) {
      CloseSocketSafe_(listen_sock);
      CloseSocketSafe_(write_sock);
      return false;
    }

    read_sock = accept(listen_sock, nullptr, nullptr);
    CloseSocketSafe_(listen_sock);
    if (read_sock == INVALID_SOCKET) {
      CloseSocketSafe_(write_sock);
      return false;
    }
    backend = Backend::SocketPair;
#else
#ifdef __linux__
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (efd >= 0) {
      read_sock = static_cast<SOCKET>(efd);
      write_sock = static_cast<SOCKET>(efd);
      backend = Backend::EventFd;
    }
#endif
    if (backend == Backend::None) {
      int pfd[2] = {-1, -1};
      if (::pipe(pfd) != 0) {
        return false;
      }
      read_sock = static_cast<SOCKET>(pfd[0]);
      write_sock = static_cast<SOCKET>(pfd[1]);
      backend = Backend::Pipe;
    }
#endif

    if (!SetSocketNonBlocking_(read_sock) ||
        !SetSocketNonBlocking_(write_sock)) {
      CloseSocketSafe_(read_sock);
      if (write_sock != read_sock) {
        CloseSocketSafe_(write_sock);
      }
      return false;
    }

    read_sock_ = read_sock;
    write_sock_ = write_sock;
    backend_ = backend;
    return true;
  }

  void CloseUnlocked_() {
    if (backend_ == Backend::EventFd && read_sock_ != INVALID_SOCKET) {
      CloseSocketSafe_(read_sock_);
      write_sock_ = INVALID_SOCKET;
      backend_ = Backend::None;
      return;
    }
    CloseSocketSafe_(read_sock_);
    CloseSocketSafe_(write_sock_);
    backend_ = Backend::None;
  }

  mutable std::mutex mtx_;
  SOCKET read_sock_ = INVALID_SOCKET;
  SOCKET write_sock_ = INVALID_SOCKET;
  Backend backend_ = Backend::None;
};

inline std::string Base64Encode(const unsigned char *data, size_t len) {
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

inline std::string HostKeyTypeToProtocol(int type) {
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

inline std::string BuildPrivateKeyStateInfo_(const std::string &key_path) {
  const std::string key_basename = AMPath::basename(key_path);
  return AMStr::fmt("authorize with private_key: {}",
                    key_basename.empty() ? key_path : key_basename);
}

inline int
ResolveTimeoutMs_(const AMDomain::client::ClientControlComponent &control) {
  const auto remain_opt = control.RemainingTimeMs();
  if (!remain_opt.has_value()) {
    return -1;
  }
  return static_cast<int>(std::min<unsigned int>(
      *remain_opt,
      static_cast<unsigned int>((std::numeric_limits<int>::max)())));
}

class SafeChannel {
public:
  LIBSSH2_CHANNEL *channel = nullptr;
  bool closed = false; // Mark whether it has been closed normally
  bool is_init = false;
  std::function<bool()> init_is_interrupted_cb;
  int64_t init_start_time = -1;
  int init_timeout_ms = -1;

private:
  /**
   * @brief Persist initialization context used by retryable operations.
   */
  void StoreInitContext_(std::function<bool()> is_interrupted_cb,
                         int timeout_ms, int64_t start_time) {
    init_is_interrupted_cb = std::move(is_interrupted_cb);
    init_timeout_ms = timeout_ms;
    init_start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
  }

  /**
   * @brief Check interruption/timeout state for retry operations.
   */
  ECM CheckControlState_(const std::string &action) const {
    if (init_is_interrupted_cb && init_is_interrupted_cb()) {
      return {EC::Terminate, action, "<channel>", "Interrupted"};
    }
    if (init_timeout_ms >= 0 && init_start_time >= 0 &&
        (AMTime::miliseconds() - init_start_time) >= init_timeout_ms) {
      return {EC::OperationTimeout, action, "<channel>", "Timed out"};
    }
    return OK;
  }

public:
  /**
   * @brief Update control context used by close/retry operations.
   */
  void SetControlContext(std::function<bool()> is_interrupted_cb,
                         int timeout_ms, int64_t start_time = -1) {
    StoreInitContext_(std::move(is_interrupted_cb), timeout_ms, start_time);
  }

  ~SafeChannel() {
    if (channel) {
      if (!closed) {
        // Best-effort graceful stop before releasing the channel handle.
        (void)graceful_exit(true, 50, true);
      }
      libssh2_channel_free(channel);
      channel = nullptr;
    }
    is_init = false;
  }

  // Close channel normally (blocking mode)
  // Return true on success, false on failure
  bool close() {
    if (!channel || closed) {
      is_init = false;
      return closed;
    }
    if (libssh2_channel_close(channel) == 0 &&
        libssh2_channel_wait_closed(channel) == 0) {
      closed = true;
      is_init = false;
    }
    return closed;
  }

  // Send exit signal (do not wait for close)
  void request_exit() {
    if (!channel) {
      return;
    }
    libssh2_channel_send_eof(channel);
    libssh2_channel_signal(channel, "TERM");
  }

  // Non-blocking close; use with wait_for_socket
  // Return values: 0=success, EAGAIN=wait required, <0=error
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
        is_init = false;
      }
    }
    return rc;
  }

  SafeChannel() = default;

  /**
   * @brief Construct with an existing channel and operation context.
   */
  explicit SafeChannel(LIBSSH2_CHANNEL *existing_channel,
                       std::function<bool()> is_interrupted_cb = {},
                       int timeout_ms = -1, int64_t start_time = -1) {
    channel = existing_channel;
    closed = false;
    is_init = existing_channel != nullptr;
    StoreInitContext_(std::move(is_interrupted_cb), timeout_ms, start_time);
  }

  /**
   * @brief Initialize SSH channel with retry support in non-blocking sessions.
   *
   * @param session Active libssh2 session.
   * @param is_interrupted_cb Optional interruption callback.
   * @param timeout_ms Timeout in milliseconds; negative waits forever.
   * @param start_time Start timestamp for timeout budget; -1 uses now.
   * @return ECM status describing initialization result.
   */
  ECM Init(LIBSSH2_SESSION *session,
           std::function<bool()> is_interrupted_cb = {}, int timeout_ms = -1,
           int64_t start_time = -1) {
    StoreInitContext_(std::move(is_interrupted_cb), timeout_ms, start_time);
    if (!session) {
      is_init = false;
      return {EC::NoSession, __func__, "", "Session is null"};
    }
    if (channel) {
      if (!closed) {
        (void)graceful_exit(true, 50, true);
      }
      libssh2_channel_free(channel);
      channel = nullptr;
      closed = false;
      is_init = false;
    }

    while (true) {
      ECM control_retry = CheckControlState_("Channel init");
      if (control_retry.code != EC::Success) {
        is_init = false;
        return control_retry;
      }

      channel =
          libssh2_channel_open_ex(session, "session", sizeof("session") - 1,
                                  4 * AMMB, 32 * AMKB, nullptr, 0);
      if (channel) {
        closed = false;
        is_init = true;
        return OK;
      }

      const int err = libssh2_session_last_errno(session);
      if (err != LIBSSH2_ERROR_EAGAIN) {
        is_init = false;
        return {EC::NoConnection, "channel.init", "<channel>",
                AMStr::fmt("libssh2 error {}", err),
                RawError{RawErrorSource::Libssh2, err}};
      }
      ECM control = CheckControlState_("Channel init");
      if (control.code != EC::Success) {
        is_init = false;
        return control;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  /**
   * @brief Gracefully terminate a running channel and close it.
   *
   * @param send_exit Whether to send EOF/TERM before closing.
   * @param term_wait_ms Delay after TERM signal before close attempts.
   * @param force_kill Whether to send KILL if close fails after TERM.
   * @return ECM status describing exit result.
   */
  ECM graceful_exit(bool send_exit = true, int term_wait_ms = 50,
                    bool force_kill = true) {
    if (!channel || closed) {
      is_init = false;
      return OK;
    }

    auto run_nonblocking_op = [&](auto &&op, const std::string &action) -> ECM {
      while (true) {
        const int rc = op();
        if (rc == 0) {
          return OK;
        }
        if (rc != LIBSSH2_ERROR_EAGAIN) {
          return {EC::NoConnection, action, "<channel>",
                  AMStr::fmt("libssh2 error {}", rc),
                  RawError{RawErrorSource::Libssh2, rc}};
        }
        ECM control = CheckControlState_(action);
        if (control.code != EC::Success) {
          return control;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    };

    if (send_exit) {
      ECM eof_rcm = run_nonblocking_op(
          [this]() { return libssh2_channel_send_eof(channel); },
          "channel send eof");
      if (eof_rcm.code != EC::Success && eof_rcm.code != EC::Terminate &&
          eof_rcm.code != EC::OperationTimeout) {
        return eof_rcm;
      }

      ECM term_rcm = run_nonblocking_op(
          [this]() { return libssh2_channel_signal(channel, "TERM"); },
          "channel signal TERM");
      if (term_rcm.code != EC::Success && term_rcm.code != EC::Terminate &&
          term_rcm.code != EC::OperationTimeout) {
        return term_rcm;
      }

      if (term_wait_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(term_wait_ms));
      }
    }

    ECM close_rcm = run_nonblocking_op([this]() { return close_nonblock(); },
                                       "channel close");
    if (close_rcm.code == EC::Success) {
      return close_rcm;
    }

    if (force_kill && send_exit && channel && !closed) {
      (void)run_nonblocking_op(
          [this]() { return libssh2_channel_signal(channel, "KILL"); },
          "channel signal KILL");
      close_rcm = run_nonblocking_op([this]() { return close_nonblock(); },
                                     "channel close");
    }
    return close_rcm;
  }
};

} // namespace detail

using AuthCallback =
    std::function<std::optional<std::string>(const AuthCBInfo &)>;
using TraceLevel = AMDomain::client::TraceLevel;
using KnownHostQuery = AMDomain::host::KnownHostQuery;
using KnownHostCallback = AMDomain::client::KnownHostCallback;

class SFTPSessionBase : public ClientIOBase {
protected:
  using amf = AMDomain::client::amf;
  AMAtomic<ECMData<AMDomain::filesystem::CheckResult>> &state_atomic_;
  mutable std::recursive_mutex mtx;
  detail::InterruptWakeBridge interrupt_wake_;
  SOCKET sock = INVALID_SOCKET;

  struct KeepaliveRuntime final {
    std::mutex lifecycle_mtx = {};
    std::thread worker = {};
    std::mutex wait_mtx = {};
    std::condition_variable cv = {};
    std::atomic<bool> shutdown{false};
    std::atomic<uint64_t> wake_seq{0};
    std::atomic<int> interval_s{60};
    std::atomic<int> timeout_ms{5000};
    AMAtomic<std::chrono::steady_clock::time_point> last_io_steady{
        std::chrono::steady_clock::time_point{}};
    void ShutDown() {
      {
        std::lock_guard<std::mutex> lock(lifecycle_mtx);
        shutdown.store(true, std::memory_order_release);
      }
      cv.notify_all();
      if (worker.joinable()) {
        worker.join();
      }
    }
  };

  KeepaliveRuntime keepalive_ = {};

  void trace(TraceLevel level, EC error_code, const std::string &target = "",
             const std::string &action = "",
             const std::string &msg = "") const {
    ClientIOBase::trace(TraceInfo(
        level, error_code, config_part_->GetNickname(), target, action, msg,
        config_part_->GetRequest(), AMDomain::client::TraceSource::Client));
  }

  void trace(const ECM &rcm) {
    if (!rcm) {
      ClientIOBase::trace(TraceInfo(
          TraceLevel::Error, rcm.code, config_part_->GetNickname(), rcm.target,
          rcm.operation, rcm.error, config_part_->GetRequest(),
          AMDomain::client::TraceSource::Client));
    }
  }

  void trace_connect_state(const std::string &state_info,
                           const std::string &target = "") const {
    const std::string normalized = AMStr::Strip(state_info);
    if (normalized.empty()) {
      return;
    }
    connect_state(normalized, target);
    trace(TraceLevel::Info, EC::Success, target, "connect.state", normalized);
  }

  void SetState(const ECMData<AMDomain::filesystem::CheckResult> &state) {
    state_atomic_.lock().store(state);
  }

  void MarkDeathClockStateMachineBroken_(WaitResult reason) {
    ECM rcm = {};
    switch (reason) {
    case WaitResult::Timeout:
      rcm = {EC::OperationTimeout, "wait_for_socket.death_clock", "",
             "Death clock grace timeout exceeded while waiting for socket"};
      break;
    case WaitResult::Interrupted:
      rcm = {EC::Terminate, "wait_for_socket.death_clock", "",
             "Death clock grace timeout exceeded after interrupt"};
      break;
    default:
      return;
    }
    SetState({rcm, AMDomain::client::ClientStatus::ConnectionBroken});
    trace(TraceLevel::Error, rcm.code, "", rcm.operation, rcm.error);
  }

  [[nodiscard]] ECMData<AMDomain::filesystem::CheckResult> GetState() const {
    return state_atomic_.lock().load();
  }

  void TouchLastIO_() {
    auto last_io = keepalive_.last_io_steady.lock();
    last_io.store(AMTime::SteadyNow());
  }

  void NotifyKeepaliveWakeup_() {
    (void)keepalive_.wake_seq.fetch_add(1, std::memory_order_acq_rel);
    keepalive_.cv.notify_all();
  }

  void EnsureKeepaliveWorkerStarted_() {
    std::lock_guard<std::mutex> lock(keepalive_.lifecycle_mtx);
    if (keepalive_.worker.joinable()) {
      return;
    }
    keepalive_.shutdown.store(false, std::memory_order_release);
    keepalive_.worker = std::thread(&SFTPSessionBase::KeepaliveLoop_, this);
  }

  [[nodiscard]] bool ShouldRunKeepalive_() const {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    const auto state = state_atomic_.lock().load();
    if (state.data.status != AMDomain::client::ClientStatus::OK || !state.rcm) {
      return false;
    }
    return session != nullptr && sftp != nullptr && sock != INVALID_SOCKET;
  }

  ECM KeepaliveTick_() {
    const int timeout_ms =
        std::max(1, keepalive_.timeout_ms.load(std::memory_order_acquire));
    const AMDomain::client::ClientControlComponent keepalive_control(
        nullptr, timeout_ms);
    std::lock_guard<std::recursive_mutex> lock(mtx);
    const auto state = state_atomic_.lock().load();
    if (state.data.status != AMDomain::client::ClientStatus::OK || !state.rcm ||
        session == nullptr || sftp == nullptr || sock == INVALID_SOCKET) {
      return OK;
    }

    int seconds_to_next = 0;
    auto keepalive_res = nb_call(
        keepalive_control,
        [&]() { return libssh2_keepalive_send(session, &seconds_to_next); },
        timeout_ms);
    ECM rcm =
        ErrorRecord(keepalive_res, TraceLevel::Error,
                    config_part_->GetNickname(), "libssh2_keepalive_send");
    if (!rcm) {
      SetState({rcm, AMDomain::client::ClientStatus::ConnectionBroken});
      trace(rcm);
      return rcm;
    }
    return OK;
  }

  void KeepaliveLoop_() {
    while (true) {
      if (keepalive_.shutdown.load(std::memory_order_acquire)) {
        return;
      }

      const int interval_s =
          std::max(1, keepalive_.interval_s.load(std::memory_order_acquire));
      const uint64_t wake_seq =
          keepalive_.wake_seq.load(std::memory_order_acquire);
      std::unique_lock<std::mutex> wait_lock(keepalive_.wait_mtx);
      (void)keepalive_.cv.wait_for(
          wait_lock, std::chrono::seconds(interval_s), [this, wake_seq]() {
            if (keepalive_.shutdown.load(std::memory_order_acquire)) {
              return true;
            }
            return keepalive_.wake_seq.load(std::memory_order_acquire) !=
                   wake_seq;
          });
      wait_lock.unlock();

      if (keepalive_.shutdown.load(std::memory_order_acquire)) {
        return;
      }
      if (!ShouldRunKeepalive_()) {
        continue;
      }

      const auto now = AMTime::SteadyNow();
      const auto last_io = keepalive_.last_io_steady.lock().load();
      if (last_io != std::chrono::steady_clock::time_point{}) {
        const double idle_ms = AMTime::IntervalMS(last_io, now);
        if (idle_ms >= 0.0 &&
            idle_ms < static_cast<double>(interval_s) * 1000.0) {
          continue;
        }
      }

      (void)KeepaliveTick_();
    }
  }

  [[nodiscard]] OS_TYPE GetCachedOSType_() const {
    return config_part_ ? config_part_->GetOSType() : OS_TYPE::Uncertain;
  }

  void SetCachedOSType_(OS_TYPE os_type) {
    if (config_part_) {
      config_part_->SetOSType(os_type);
    }
  }

  [[nodiscard]] std::string GetCachedHomeDir_() const {
    return config_part_ ? config_part_->GetHomeDir() : std::string{};
  }

  void SetCachedHomeDir_(const std::string &home_dir) {
    if (config_part_) {
      config_part_->SetHomeDir(home_dir);
    }
  }

  ECM ErrorRecord(int code, TraceLevel level, const std::string &taregt,
                  const std::string &action) {
    ECM rcm = OK;
    if (code >= 0) {
      return rcm;
    }
    auto ec = GetLastEC();
    auto msg = GetLastErrorMsg();
    rcm.code = ec;
    rcm.error = msg;
    rcm.target = taregt;
    rcm.operation = action;
    return rcm;
  }

  template <typename T>
  ECM ErrorRecord(const NBResult<T> &result, TraceLevel level,
                  const std::string &target, const std::string &action) {
    ECM rcm = OK;

    // 1. Timeout
    if (result.is_timeout()) {
      rcm.code = EC::OperationTimeout;
      rcm.error = "Operation timeout";
      rcm.target = target;
      rcm.operation = action;
      return rcm;
    }

    // 2. Terminate
    if (result.is_interrupted()) {
      rcm.code = EC::Terminate;
      rcm.error = "Operation interrupted";
      rcm.target = target;
      rcm.operation = action;
      return rcm;
    }

    // 4 & 5. Execution finished - check return value for errors
    // For int/ssize_t: <0 means failure (while LIBSSH2 uses 0 as success)
    // For pointers: nullptr means failure
    if constexpr (std::is_same_v<T, int> || std::is_same_v<T, ssize_t>) {
      if (result.value < 0) {
        // Execution finished but failed
        rcm.raw_error = RawError{RawErrorSource::Libssh2, 0};
        auto ec = GetLastEC(&rcm.raw_error->code);
        rcm.target = target;
        rcm.operation = action;
        auto errmsg = GetLastErrorMsg();
        rcm.code = ec;
        rcm.error = errmsg;
        return rcm;
      }
    } else if constexpr (std::is_pointer_v<T>) {
      if (result.value == nullptr) {
        rcm.raw_error = RawError{RawErrorSource::Libssh2, 0};
        auto ec = GetLastEC(&rcm.raw_error->code);
        auto errmsg = GetLastErrorMsg();
        rcm.target = target;
        rcm.operation = action;
        rcm.code = ec;
        rcm.error = errmsg;
        return rcm;
      }
    }

    // 5. Success
    return OK;
  }

private:
  bool password_auth_cb = false;
  std::vector<std::string> private_keys = {};
  AuthCallback auth_cb = {}; // optional<string>(AuthCBInfo)

  /**
   * @brief Verify the remote host key using an external callback when set.
   */
  ECM VerifyKnownHostFingerprint(const ConRequest &request) {
    ECM rcm = OK;
    auto known_host_cb = known_host_callback_.lock().load();
    if (!known_host_cb) {
      return rcm;
    }

    size_t key_len = 0;
    int key_type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    const char *key_ptr = libssh2_session_hostkey(session, &key_len, &key_type);
    if (!key_ptr || key_len == 0) {
      rcm.code = EC::HostkeyInitFailed;
      rcm.operation = "libssh2_session_hostkey";
      rcm.error = "Failed to retrieve host key from libssh2 session";
      return rcm;
    }

    const std::string actual_protocol = detail::HostKeyTypeToProtocol(key_type);
    if (actual_protocol.empty()) {
      rcm.code = EC::AlgorithmUnsupported;
      rcm.operation = "HostKeyTypeToProtocol";
      rcm.target = AMStr::ToString(key_type);
      rcm.error = "Unsupported hostkey protocol type";
      return rcm;
    }

    auto *key_bytes = reinterpret_cast<const unsigned char *>(key_ptr);

    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest;
    std::string actual_sha = "";
    if (SHA256(key_bytes, key_len, digest.data())) {
      actual_sha = detail::Base64Encode(digest.data(), SHA256_DIGEST_LENGTH);
    }

    KnownHostQuery entry{request.nickname, request.hostname, (int)request.port,
                         actual_protocol,  request.username, actual_sha};
    return known_host(entry);
  }

  void LoadDefaultPrivateKeys() {
    trace(TraceLevel::Debug, EC::Success, "~/.ssh", "LoadDefaultPrivateKeys",
          "Shared private keys not provided, loading default private keys from "
          "~/.ssh");
    auto [error, listd] = AMPath::listdir(AMPath::abspath("~/.ssh"));
    if (!error) {
      return;
    };
    for (auto &info : listd) {
      if (info.type == PathType::FILE) {
        if (detail::IsValidKey(info.path)) {
          this->private_keys.push_back(info.path);
        }
      }
    }
  }

  virtual void OnBeforeDisconnect_() {};

  void Disconnect() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    OnBeforeDisconnect_();
    interrupt_wake_.Close();
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
    ECMData<AMDomain::filesystem::CheckResult> res;
    res.data = AMDomain::filesystem::CheckResult{};
    res.rcm = {EC::NoConnection, __func__, "", "Connection closed"};
    res.data.status = AMDomain::client::ClientStatus::NoConnection;
    state_atomic_.lock().store(res);
  }

public:
  LIBSSH2_SESSION *session = nullptr;
  LIBSSH2_SFTP *sftp = nullptr;

  ~SFTPSessionBase() override {
    keepalive_.ShutDown();
    Disconnect();
  }

  /**
   * @brief Expose the transfer serialization mutex for runtime transfer
   * execution helpers.
   */
  std::recursive_mutex &TransferMutex() { return mtx; }

  SFTPSessionBase(AMDomain::client::IClientConfigPort *config_port,
                  AMDomain::client::IClientControlToken *control_port,
                  const std::vector<std::string> &private_keys,
                  TraceCallback trace_cb = {}, AuthCallback auth_cb = {},
                  AMDomain::client::KnownHostCallback known_host_cb = {})
      : ClientIOBase(config_port, control_port),
        state_atomic_((config_port != nullptr)
                          ? config_port->StateAtomic()
                          : throw std::invalid_argument(
                                "SFTPSessionBase requires non-null config "
                                "port")),
        private_keys(private_keys), auth_cb(std::move(auth_cb)) {
    if (control_port == nullptr) {
      throw std::invalid_argument(
          "SFTPSessionBase requires non-null task control port");
    }
    RegisterTraceCallback(std::move(trace_cb));
    interrupt_wake_.Ensure();
    RegisterKnownHostCallback(std::move(known_host_cb));
    if (this->auth_cb) {
      this->password_auth_cb = true;
    }
    if (private_keys.empty()) {
      LoadDefaultPrivateKeys();
    }
  }

  template <typename Func>
  auto nb_call(detail::DeathClockProtocol &death_clock, Func &&func,
               bool touch_io = true) -> NBResult<decltype(func())> {
    using RetType = decltype(func());
    if (auto stop = death_clock.Check(); stop.has_value()) {
      MarkDeathClockStateMachineBroken_(*stop);
      return {RetType{}, *stop};
    }

    RetType rc;
    while (true) {
      if (auto stop = death_clock.Check(); stop.has_value()) {
        MarkDeathClockStateMachineBroken_(*stop);
        return {RetType{}, *stop};
      }

      rc = func();

      bool should_retry = false;
      if constexpr (std::is_same_v<RetType, int> ||
                    std::is_same_v<RetType, ssize_t>) {
        should_retry = (rc == LIBSSH2_ERROR_EAGAIN);
      } else if constexpr (std::is_pointer_v<RetType>) {
        should_retry =
            (rc == nullptr && session != nullptr &&
             libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN);
      }

      if (!should_retry) {
        if (touch_io) {
          TouchLastIO_();
        }
        return {rc, WaitResult::Ready};
      }

      WaitResult wr =
          wait_for_socket(detail::SocketWaitType::Auto, death_clock);
      if (wr != WaitResult::Ready) {
        return {rc, wr};
      }
    }
  }

  template <typename Func>
  auto nb_call(
      const AMDomain::client::ClientControlComponent &control, Func &&func,
      int death_clock_timeout_ms = AMDomain::client::kFilesystemOpGraceWaitMs,
      bool touch_io = true) -> NBResult<decltype(func())> {
    detail::DeathClockProtocol death_clock(control, death_clock_timeout_ms);
    return nb_call(death_clock, std::forward<Func>(func), touch_io);
  }

  inline WaitResult wait_for_socket(
      detail::SocketWaitType wait_dir,
      const AMDomain::client::ClientControlComponent &control = {},
      int death_clock_timeout_ms = AMDomain::client::kFilesystemOpGraceWaitMs) {
    if (!session || sock == INVALID_SOCKET) {
      return WaitResult::Error;
    }
    detail::DeathClockProtocol death_clock(control, death_clock_timeout_ms);
    if (auto stop = death_clock.Check(); stop.has_value()) {
      MarkDeathClockStateMachineBroken_(*stop);
      return *stop;
    }
    return wait_for_socket(wait_dir, death_clock);
  }

  inline WaitResult wait_for_socket(detail::SocketWaitType wait_dir,
                                    detail::DeathClockProtocol &death_clock) {
    if (!session || sock == INVALID_SOCKET) {
      return WaitResult::Error;
    }
    const auto &control = death_clock.Control();
    const amf &interrupt_flag = control.ControlToken();
    if (auto stop = death_clock.Check(); stop.has_value()) {
      MarkDeathClockStateMachineBroken_(*stop);
      return *stop;
    }

    if (wait_dir == detail::SocketWaitType::Auto &&
        libssh2_session_block_directions(session) == 0) {
      return WaitResult::Ready;
    }

    bool wait_read = false;
    bool wait_write = false;
    const bool is_auto = (wait_dir == detail::SocketWaitType::Auto);
    const bool is_read_or_write =
        (wait_dir == detail::SocketWaitType::ReadOrWrite);

    if (!is_auto) {
      switch (wait_dir) {
      case detail::SocketWaitType::Read:
        wait_read = true;
        break;
      case detail::SocketWaitType::Write:
        wait_write = true;
        break;
      case detail::SocketWaitType::ReadWrite:
      case detail::SocketWaitType::ReadOrWrite:
        wait_read = true;
        wait_write = true;
        break;
      default:
        break;
      }
    }

    size_t wake_token = 0;
    SOCKET wake_read_sock = INVALID_SOCKET;
    if (interrupt_wake_.Ensure()) {
      interrupt_wake_.Drain();
      wake_read_sock = interrupt_wake_.ReadSocket();
    }

    death_clock.Refresh();
    if (!death_clock.IsActivated() && wake_read_sock != INVALID_SOCKET &&
        interrupt_flag) {
      wake_token = interrupt_flag->RegisterWakeup(
          [this]() { interrupt_wake_.Signal(); });
    }

    auto cleanup_wakeup = [&]() {
      if (wake_token != 0) {
        if (interrupt_flag) {
          interrupt_flag->UnregisterWakeup(wake_token);
        }
        wake_token = 0;
      }
    };

    auto select_once = [&](int timeout_ms, fd_set *out_readfds,
                           fd_set *out_writefds,
                           bool *out_interrupt_poll_fallback) -> int {
      fd_set local_readfds;
      fd_set local_writefds;
      FD_ZERO(&local_readfds);
      FD_ZERO(&local_writefds);

      if (is_auto) {
        const int dir = libssh2_session_block_directions(session);
        if (dir == 0) {
          if (out_readfds) {
            *out_readfds = local_readfds;
          }
          if (out_writefds) {
            *out_writefds = local_writefds;
          }
          if (out_interrupt_poll_fallback) {
            *out_interrupt_poll_fallback = false;
          }
          return 1;
        }
        if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
          FD_SET(sock, &local_readfds);
        }
        if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
          FD_SET(sock, &local_writefds);
        }
      } else {
        if (wait_read) {
          FD_SET(sock, &local_readfds);
        }
        if (wait_write) {
          FD_SET(sock, &local_writefds);
        }
      }
      if (wake_read_sock != INVALID_SOCKET) {
        FD_SET(wake_read_sock, &local_readfds);
      }

      const bool watch_socket =
          FD_ISSET(sock, &local_readfds) || FD_ISSET(sock, &local_writefds);
      const bool watch_wakeup = wake_read_sock != INVALID_SOCKET;
      if (!watch_socket && !watch_wakeup) {
        if (out_readfds) {
          *out_readfds = local_readfds;
        }
        if (out_writefds) {
          *out_writefds = local_writefds;
        }
        if (out_interrupt_poll_fallback) {
          *out_interrupt_poll_fallback = false;
        }
        return 1;
      }

      timeval tv{};
      timeval *timeout_ptr = nullptr;
      bool interrupt_poll_fallback = false;
      if (timeout_ms >= 0) {
        const int bounded_timeout = timeout_ms;
        tv.tv_sec = static_cast<long>(bounded_timeout / 1000);
        tv.tv_usec = static_cast<long>((bounded_timeout % 1000) * 1000);
        timeout_ptr = &tv;
      } else if (wake_read_sock == INVALID_SOCKET) {
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000; // 100ms polling fallback
        timeout_ptr = &tv;
        interrupt_poll_fallback = true;
      }

#ifdef _WIN32
      const int rc =
          select(0, &local_readfds, &local_writefds, nullptr, timeout_ptr);
#else
      int nfds = static_cast<int>(sock) + 1;
      if (wake_read_sock != INVALID_SOCKET) {
        nfds = std::max(nfds, static_cast<int>(wake_read_sock) + 1);
      }
      const int rc =
          select(nfds, &local_readfds, &local_writefds, nullptr, timeout_ptr);
#endif
      if (out_readfds) {
        *out_readfds = local_readfds;
      }
      if (out_writefds) {
        *out_writefds = local_writefds;
      }
      if (out_interrupt_poll_fallback) {
        *out_interrupt_poll_fallback = interrupt_poll_fallback;
      }
      return rc;
    };

    int timeout_ms = death_clock.ResolveTimeoutMs();

    fd_set selected_readfds;
    fd_set selected_writefds;
    bool interrupt_poll_fallback = false;
    int rc = select_once(timeout_ms, &selected_readfds, &selected_writefds,
                         &interrupt_poll_fallback);

    if (rc < 0) {
      if (auto stop = death_clock.Check(); stop.has_value()) {
        cleanup_wakeup();
        MarkDeathClockStateMachineBroken_(*stop);
        return *stop;
      }
      rc = select_once(death_clock.BuildDeathTimeoutMs(), &selected_readfds,
                       &selected_writefds, &interrupt_poll_fallback);
    }

    cleanup_wakeup();

    if (rc < 0) {
      if (auto stop = death_clock.Check(); stop.has_value()) {
        MarkDeathClockStateMachineBroken_(*stop);
        return *stop;
      }
      return WaitResult::Error;
    }
    if (rc == 0) {
      if (auto stop = death_clock.Check(); stop.has_value()) {
        MarkDeathClockStateMachineBroken_(*stop);
        return *stop;
      }
      if (interrupt_poll_fallback) {
        return WaitResult::Ready;
      }
      return WaitResult::Timeout;
    }

    if (wake_read_sock != INVALID_SOCKET &&
        FD_ISSET(wake_read_sock, &selected_readfds)) {
      interrupt_wake_.Drain();
      if (auto stop = death_clock.Check(); stop.has_value()) {
        MarkDeathClockStateMachineBroken_(*stop);
        return *stop;
      }
    }

    if (is_read_or_write) {
      if (FD_ISSET(sock, &selected_readfds)) {
        return WaitResult::ReadReady;
      }
      if (FD_ISSET(sock, &selected_writefds)) {
        return WaitResult::WriteReady;
      }
    }
    return WaitResult::Ready;
  }

  std::vector<std::string> GetKeys() { return this->private_keys; }

  void SetKeys(const std::vector<std::string> &keys) {
    this->private_keys = keys;
  }

  ECM BaseConnect(bool force,
                  const AMDomain::client::ClientControlComponent &control) {
    EnsureKeepaliveWorkerStarted_();
    if (control.IsTimeout()) {
      return {EC::OperationTimeout, __func__, "", "Operation timed out"};
    }
    if (control.IsInterrupted()) {
      return {EC::Terminate, __func__, "", "Interrupted by user"};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    ConRequest request = request_atomic_.lock().load();
    const ECMData<AMDomain::filesystem::CheckResult> current_state = GetState();
    const bool connected =
        (current_state.data.status == AMDomain::client::ClientStatus::OK) &&
        session != nullptr && sftp != nullptr;
    if (connected) {
      if (!force) {
        return current_state.rcm;
      }
      Disconnect();
    }

    ECM rcm = OK;
    int rcr = 0;
    WaitResult wr = WaitResult::Ready;
    bool password_auth = false;
    std::string password_tmp;
    std::string stored_password_enc = request.password;
    const char *auth_list = nullptr;
    detail::DeathClockProtocol death_clock(control);

    auto NotifyAuth = [&](bool need_password, const std::string &password_enc,
                          bool password_correct) {
      if (!auth_cb) {
        return;
      }
      ConRequest callback_request = request;
      callback_request.password = password_correct ? password_enc : "";
      CallCallbackSafe(auth_cb,
                       AuthCBInfo(need_password, std::move(callback_request),
                                  password_enc, password_correct));
    };

    detail::SocketConnector connector;
    if (!connector.Connect(
            request.hostname, static_cast<int>(request.port), control,
            [this](const std::string &state_info, const std::string &target) {
              trace_connect_state(state_info, target);
            })) {
      const std::string target =
          request.hostname + ":" + std::to_string(request.port);
      trace(TraceLevel::Critical, connector.error_code, target,
            "SocketConnector.Connect", connector.error_msg);
      return {connector.error_code, "connect.socket", target,
              connector.error_msg};
    }
    sock = connector.sock;

    if (control.IsInterrupted()) {
      return {EC::Terminate, __func__, "", "Connection interrupted"};
    }
    if (control.IsTimeout()) {
      return {EC::OperationTimeout, __func__, "", "Connection timed out"};
    }

    session = libssh2_session_init();
    if (!session) {
      trace(TraceLevel::Critical, EC::SessionCreateFailed, "",
            "libssh2_session_init", "Session initialization failed");
      return {EC::SessionCreateFailed, __func__, "",
              "Libssh2 Session initialization failed"};
    }
    libssh2_session_set_blocking(session, 0);
    libssh2_keepalive_config(
        session, 0,
        std::max(1, keepalive_.interval_s.load(std::memory_order_acquire)));

    if (request.compression) {
      libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
      libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS,
                                  "zlib@openssh.com,zlib,none");
    }

    while (true) {
      rcr = libssh2_session_handshake(session, sock);
      if (rcr != LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      wr = wait_for_socket(detail::SocketWaitType::Auto, control);
      if (wr != WaitResult::Ready) {
        Disconnect();
        switch (wr) {
        case WaitResult::Timeout:
          return {EC::OperationTimeout, __func__, "",
                  "Connection timed out during handshake"};
        case WaitResult::Interrupted:
          return {EC::Terminate, __func__, "",
                  "Connection interrupted during handshake"};
        case WaitResult::Error:
          return {EC::SocketRecvError, __func__, "",
                  "Socket error during handshake"};
        default:
          return {EC::UnknownError, __func__, "",
                  "Connection interrupted during handshake"};
        }
      }
    }

    rcm = ErrorRecord(
        rcr, TraceLevel::Critical,
        AMStr::fmt("socket {}", std::to_string(static_cast<size_t>(sock))),
        "libssh2_session_handshake");
    if (rcm.code != EC::Success) {
      trace(rcm);
      Disconnect();
      return rcm;
    }

    trace_connect_state("identify server fingerprint", request.hostname);
    rcm = VerifyKnownHostFingerprint(request);
    if (rcm.code != EC::Success) {
      trace(TraceLevel::Error, rcm.code, request.hostname,
            "VerifyKnownHostFingerprint", rcm.error);
      Disconnect();
      return rcm;
    }

    trace_connect_state("negotiate authorized methods", request.username);
    auto auth_list_res = nb_call(death_clock, [&]() {
      return libssh2_userauth_list(session, request.username.c_str(),
                                   request.username.length());
    });
    rcm = ErrorRecord(auth_list_res, TraceLevel::Critical, request.username,
                      "libssh2_userauth_list");
    if (rcm.code != EC::Success) {
      trace(rcm);
      Disconnect();
      return rcm;
    }
    auth_list = auth_list_res.value;
    if (auth_list == nullptr) {
      rcm = {EC::AuthFailed, __func__, "",
             "Failed to query supported auth methods"};
      trace(TraceLevel::Critical, rcm.code, request.username,
            "libssh2_userauth_list", rcm.error);
      Disconnect();
      return rcm;
    }

    trace(TraceLevel::Debug, EC::Success, request.username,
          "libssh2_userauth_list",
          AMStr::fmt("Authentication methods: {}", auth_list));

    password_auth = (strstr(auth_list, "password") != nullptr);

    if (!request.keyfile.empty()) {
      trace_connect_state(detail::BuildPrivateKeyStateInfo_(request.keyfile),
                          request.username);
      if (control.IsInterrupted()) {
        return {EC::Terminate, __func__, "", "Authentication interrupted"};
      }
      auto auth_res = nb_call(death_clock, [&]() {
        return libssh2_userauth_publickey_fromfile(
            session, request.username.c_str(), nullptr, request.keyfile.c_str(),
            nullptr);
      });
      if (!auth_res) {
        rcm = ErrorRecord(auth_res, TraceLevel::Error, request.username,
                          "libssh2_userauth_publickey_fromfile");
        trace(rcm);
        Disconnect();
        return rcm;
      }
      rcr = auth_res.value;
      if (rcr == 0) {
        trace(TraceLevel::Info, EC::Success, request.keyfile,
              "PrivatedKeyAuthorizeResult",
              "Dedicated private key authorize success");
        NotifyAuth(false, "", true);
        goto OK;
      }
      trace(TraceLevel::Error, EC::PublickeyAuthFailed, request.keyfile,
            "DedicatedPrivateKeyAuthorizeResult", GetLastErrorMsg());
      NotifyAuth(false, "", false);
    }

    if (!stored_password_enc.empty() && password_auth) {
      trace_connect_state("authorize with password", request.username);
      if (control.IsInterrupted()) {
        return {EC::Terminate, __func__, "", "Authentication interrupted"};
      }
      std::string plain_password = AMAuth::DecryptPassword(stored_password_enc);
      auto auth_res = nb_call(death_clock, [&]() {
        return libssh2_userauth_password(session, request.username.c_str(),
                                         plain_password.c_str());
      });
      AMAuth::SecureZero(plain_password);
      if (!auth_res) {
        rcm = ErrorRecord(auth_res, TraceLevel::Error, request.username,
                          "libssh2_userauth_password");
        trace(rcm);
        Disconnect();
        return rcm;
      }
      rcr = auth_res.value;
      if (rcr == 0) {
        trace(TraceLevel::Info, EC::Success, "Success",
              "PasswordAuthorizeResult", "Password authorize success");
        request.password = stored_password_enc;
        request_atomic_.lock().store(request);
        NotifyAuth(false, stored_password_enc, true);
        goto OK;
      }
      trace(TraceLevel::Error, EC::AuthFailed, "", "PasswordAuth",
            "Password authentication failed");
      NotifyAuth(false, stored_password_enc, false);
    }

    if (!private_keys.empty()) {
      for (const auto &private_key : private_keys) {
        if (control.IsInterrupted()) {
          return {EC::Terminate, __func__, "", "Authentication interrupted"};
        }
        if (private_key == request.keyfile) {
          continue;
        }
        trace_connect_state(detail::BuildPrivateKeyStateInfo_(private_key),
                            request.username);
        auto auth_res = nb_call(death_clock, [&]() {
          return libssh2_userauth_publickey_fromfile(
              session, request.username.c_str(), nullptr, private_key.c_str(),
              nullptr);
        });
        if (!auth_res) {
          rcm = ErrorRecord(auth_res, TraceLevel::Error, request.username,
                            "libssh2_userauth_publickey_fromfile");
          trace(rcm);
          Disconnect();
          return rcm;
        }
        rcr = auth_res.value;
        if (rcr == 0) {
          trace(TraceLevel::Info, EC::Success, private_key,
                "PrivatedKeyAuthorizeResult",
                AMStr::fmt("Shared private key \"{}\" authorize success",
                           private_key));
          NotifyAuth(false, "", true);
          goto OK;
        }
        trace(TraceLevel::Error, EC::PrivateKeyAuthFailed, private_key,
              "PrivatedKeyAuthorizeResult", rcm.error);
        NotifyAuth(false, "", false);
      }
    }

    if (password_auth_cb && password_auth) {
      trace_connect_state("authorize with password", request.username);
      trace(TraceLevel::Debug, EC::Success, "Interactive", "PasswordAuthorize",
            "Using password authentication callback to get another password");
      int trial_times = 0;
      while (trial_times < 2) {
        if (control.IsInterrupted()) {
          return {EC::Terminate, __func__, "", "Authentication interrupted"};
        }
        auto [password_opt, cb_ecm] =
            CallCallbackSafeRet<std::optional<std::string>>(
                auth_cb, AuthCBInfo(true, request, "", false));
        if (cb_ecm.code != EC::Success) {
          trace(TraceLevel::Error, cb_ecm.code, "AuthCB", "Call", cb_ecm.error);
          break;
        }
        password_tmp = password_opt.has_value() ? *password_opt : "";
        if (password_tmp.empty()) {
          break;
        }
        const std::string password_enc = AMAuth::EncryptPassword(password_tmp);
        auto auth_res = nb_call(death_clock, [&]() {
          return libssh2_userauth_password(session, request.username.c_str(),
                                           password_tmp.c_str());
        });
        AMAuth::SecureZero(password_tmp);
        if (!auth_res) {
          rcm = ErrorRecord(auth_res, TraceLevel::Error, request.username,
                            "libssh2_userauth_password");
          trace(rcm);
          Disconnect();
          return rcm;
        }
        rcr = auth_res.value;
        ++trial_times;
        if (rcr == 0) {
          trace(TraceLevel::Info, EC::Success, "Success",
                "PasswordAuthorizeResult", "Password authorize success");
          request.password = password_enc;
          request_atomic_.lock().store(request);
          NotifyAuth(false, password_enc, true);
          goto OK;
        }
        trace(TraceLevel::Error, EC::AuthFailed, "", "PasswordAuthorizeResult",
              "Wrong password");
        NotifyAuth(false, password_enc, false);
      }
    }

    rcm.code = EC::AuthFailed;
    rcm.error = "All authorize methods failed";

  OK:
    if (rcm.code != EC::Success) {
      Disconnect();
      return rcm;
    }

    trace_connect_state("create SFTP Handle", request.hostname);
    auto sftp_init_res =
        nb_call(death_clock, [&]() { return libssh2_sftp_init(session); });
    rcm = ErrorRecord(sftp_init_res, TraceLevel::Critical, "",
                      "libssh2_sftp_init");
    if (rcm.code != EC::Success) {
      trace(rcm);
      Disconnect();
      return rcm;
    }
    sftp = sftp_init_res.value;

    SetState({OK, AMDomain::client::ClientStatus::OK});
    libssh2_session_set_blocking(session, 0);
    TouchLastIO_();
    NotifyKeepaliveWakeup_();
    return OK;
  }

  EC GetLastEC(int *code = nullptr) {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!session) {
      return EC::NoSession;
    }

    int ori_code = libssh2_session_last_errno(session);
    if (code) {
      *code = ori_code;
    }
    if (ori_code != LIBSSH2_ERROR_SFTP_PROTOCOL) {
      return detail::IntToEC(ori_code);
    } else {
      if (!sftp) {
        return EC::NoConnection;
      }
      int ori_code2 = libssh2_sftp_last_error(sftp);
      return detail::IntToEC(ori_code2);
    }
  }

  std::string GetLastErrorMsg() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!session) {
      return "Session not initialized";
    }
    int ori_code = libssh2_session_last_errno(session);
    if (ori_code != LIBSSH2_ERROR_SFTP_PROTOCOL) {
      char *errmsg = nullptr;
      int errmsg_len;
      libssh2_session_last_error(session, &errmsg, &errmsg_len, 0);
      if (!errmsg || errmsg_len <= 0) {
        return "Unknown SSH error";
      }
      return {errmsg, static_cast<size_t>(errmsg_len)};
    } else {
      if (!sftp) {
        return "SFTP not initialized";
      }
      return detail::SSHCodeToString(libssh2_sftp_last_error(sftp));
    }
  }
};

class AMSFTPIOCore final : public SFTPSessionBase {
private:
  std::unordered_map<long, std::string> user_id_map;

  PathInfo FormatStat(const std::string &path,
                      const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
    PathInfo info;
    info.path = path;
    info.name = AMPath::basename(path);
    info.dir = AMPath::dirname(path);

    if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
      info.size = attrs.filesize;
    }

    if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
      info.access_time = attrs.atime;
      info.modify_time = attrs.mtime;
    }

    if (UpdateOSTypeCache_() != OS_TYPE::Windows &&
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
      if (UpdateOSTypeCache_() != OS_TYPE::Windows) {
        info.mode_int = mode & 0777;
        info.mode_str = AMStr::ModeTrans(info.mode_int);
      }
    }
    return info;
  }

protected:
  /*
   * Deprecated orchestration internals were removed from the active class
   * surface (walk/iwalk/remove/chmod helper chains).
   */

  ECM _precheck(const std::string &path,
                const AMDomain::client::ClientControlComponent &control) {
    if (path.empty()) {
      return {EC::InvalidArg, "_precheck", "<empty>", "Invalid path"};
    }
    return OK;
  }

  std::pair<ECM, std::string> ResolveRealpathCore_(
      const std::string &path,
      const AMDomain::client::ClientControlComponent &control) {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "resolve_realpath", "<empty>",
                  "Invalid empty path"},
              ""};
    }
    if (control.IsInterrupted()) {
      return {
          ECM{EC::Terminate, "resolve_realpath", path, "Interrupted by user"},
          ""};
    }
    if (control.IsTimeout()) {
      return {ECM{EC::OperationTimeout, "resolve_realpath", path,
                  "Operation timed out"},
              ""};
    }
    if (!sftp) {
      return {ECM{EC::NoConnection, "resolve_realpath", path,
                  "SFTP not initialized"},
              ""};
    }

    char path_t_buf[1024] = {0};
    detail::DeathClockProtocol death_clock(control);
    auto nb_res = nb_call(death_clock, [&] {
      return libssh2_sftp_realpath(sftp, path.c_str(), path_t_buf,
                                   sizeof(path_t_buf));
    });
    ECM rcm =
        ErrorRecord(nb_res, TraceLevel::Error, path, "libssh2_sftp_realpath");
    trace(rcm);
    if (!rcm) {
      return {rcm, ""};
    }
    std::string path_t = path_t_buf;
    if (UpdateOSTypeCache_() == OS_TYPE::Windows && !path_t.empty()) {
      path_t = path_t.substr(1);
    }
    return {rcm, path_t};
  }

public:
  AMSFTPIOCore(AMDomain::client::IClientConfigPort *config_port,
               AMDomain::client::IClientControlToken *control_port,
               const std::vector<std::string> &keys = {},
               TraceCallback trace_cb = {}, AuthCallback auth_cb = {},
               AMDomain::client::KnownHostCallback known_host_cb = {})
      : SFTPSessionBase(config_port, control_port, keys, std::move(trace_cb),
                        std::move(auth_cb), std::move(known_host_cb)) {
    if (config_port == nullptr || control_port == nullptr) {
      throw std::invalid_argument(
          "AMSFTPIOCore requires non-null config and control ports");
    }
#ifdef _WIN32
    detail::AMInitWSA();
#endif
    auto req = request_atomic_.lock();
    req->protocol = ClientProtocol::SFTP;
  }

  ~AMSFTPIOCore() override = default;

  [[nodiscard]] std::intptr_t RemoteSocketHandle() const {
    return static_cast<std::intptr_t>(sock);
  }

public:
  ECMData<AMFSI::UpdateOSTypeResult> UpdateOSType(
      const AMFSI::UpdateOSTypeArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::UpdateOSTypeResult> out = {};
    if (control.IsTimeout()) {
      out.rcm = ECM{EC::OperationTimeout, "update_os_type", "<client>",
                    "Operation timed out"};
      out.data.os_type = OS_TYPE::Unknown;
      return out;
    }
    out.data.os_type = UpdateOSTypeCache_(true);
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::UpdateHomeDirResult> UpdateHomeDir(
      const AMFSI::UpdateHomeDirArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::UpdateHomeDirResult> out = {};
    if (control.IsTimeout()) {
      out.rcm = ECM{EC::OperationTimeout, "update_home_dir", "<client>",
                    "Operation timed out"};
      out.data.home_dir = "";
      return out;
    }
    out.data.home_dir = UpdateHomeDirCache_();
    SetCachedHomeDir_(out.data.home_dir);
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::CheckResult>
  Check(const AMFSI::CheckArgs &args,
        const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::CheckResult> out = {};
    out.data.status = GetState().data.status;
    if (control.IsTimeout()) {
      out.rcm = ECM{EC::OperationTimeout, "check", ".", "Operation timed out"};
      SetState({out.rcm, AMDomain::client::ClientStatus::ConnectionBroken});
      out.data.status = AMDomain::client::ClientStatus::ConnectionBroken;
      return out;
    }
    out.rcm = stat(AMFSI::StatArgs{".", false}, control).rcm;
    AMDomain::client::ClientStatus status =
        out.rcm.code == EC::Success
            ? AMDomain::client::ClientStatus::OK
            : (out.rcm.code == EC::NotInitialized
                   ? AMDomain::client::ClientStatus::NotInitialized
                   : (out.rcm.code == EC::NoConnection
                          ? AMDomain::client::ClientStatus::NoConnection
                          : AMDomain::client::ClientStatus::ConnectionBroken));
    SetState({out.rcm, status});
    out.data.status = status;
    return out;
  }

  ECMData<AMFSI::ConnectResult>
  Connect(const AMFSI::ConnectArgs &args,
          const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::ConnectResult> out = {};
    out.data.status = GetState().data.status;
    if (control.IsTimeout()) {
      out.rcm = ECM{EC::OperationTimeout, "connect", "<client>",
                    "Operation timed out"};
      return out;
    }
    const ECMData<AMDomain::filesystem::CheckResult> prev_state = GetState();
    out.rcm = BaseConnect(args.force, control);
    if (out.rcm &&
        prev_state.data.status != AMDomain::client::ClientStatus::OK) {
      (void)UpdateOSType({}, control);
      (void)UpdateHomeDir({}, control);
    }
    AMDomain::client::ClientStatus status =
        out.rcm.code == EC::Success
            ? AMDomain::client::ClientStatus::OK
            : (out.rcm.code == EC::NotInitialized
                   ? AMDomain::client::ClientStatus::NotInitialized
                   : (out.rcm.code == EC::NoConnection
                          ? AMDomain::client::ClientStatus::NoConnection
                          : AMDomain::client::ClientStatus::ConnectionBroken));
    SetState({out.rcm, status});
    out.data.status = status;
    return out;
  }

  ECMData<AMFSI::RTTResult>
  GetRTT(const AMFSI::GetRTTArgs &args,
         const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {{-1.0}, std::move(rcm)};
    }

    ssize_t times = args.times <= 0 ? 1 : args.times;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!session || !sftp) {
      return {{-1.0},
              ECM{EC::OperationUnsupported, "get_rtt", "/", "Not supported"}};
    }

    std::vector<double> rtts = {};
    rtts.reserve(static_cast<size_t>(times));

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_session_set_blocking(session, 0);
    detail::DeathClockProtocol death_clock(control);

    for (ssize_t i = 0; i < times; i++) {
      if (control.CheckStop(rcm)) {
        return {{-1.0}, std::move(rcm)};
      }

      const double t0 = static_cast<double>(AMTime::miliseconds()) / 1000.0;
      auto stat_res = nb_call(
          death_clock, [&] { return libssh2_sftp_stat(sftp, "/", &attrs); });
      rcm = ErrorRecord(stat_res, TraceLevel::Error, "/", "libssh2_sftp_stat");
      trace(rcm);
      if (!rcm) {
        return {{-1.0}, std::move(rcm)};
      }
      if (stat_res.value == 0) {
        const double t1 = static_cast<double>(AMTime::miliseconds()) / 1000.0;
        rtts.push_back((t1 - t0) * 1000.0);
      }
    }

    if (rtts.empty()) {
      return {{-1.0},
              ECM{EC::OperationUnsupported, "get_rtt", "/", "Not supported"}};
    }
    double sum = 0.0;
    for (double v : rtts) {
      sum += v;
    }
    return {{sum / static_cast<double>(rtts.size())}, std::move(rcm)};
  }

  ECMData<AMFSI::RunResult>
  ConductCmd(const AMFSI::ConductCmdArgs &args,
             const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::RunResult> out = {};
    const CR cmd_result = ConductCmdCore_(args.cmd, control, args.processor);
    out.rcm = cmd_result.first;
    out.data.output = cmd_result.second.first;
    out.data.exit_code = cmd_result.second.second;
    return out;
  }

  ECMData<AMFSI::StatResult>
  stat(const AMFSI::StatArgs &args,
       const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {std::move(rcm)};
    }
    rcm = _precheck(args.path, control);
    if (rcm.code != EC::Success) {
      return {std::move(rcm)};
    }

    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!sftp) {
      return {ECM{EC::NoConnection, __func__, "", "SFTP not initialized"}};
    }
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    NBResult<int> stat_res;
    detail::DeathClockProtocol death_clock(control);
    if (args.trace_link) {
      stat_res = nb_call(death_clock, [&] {
        return libssh2_sftp_stat(sftp, args.path.c_str(), &attrs);
      });
    } else {
      stat_res = nb_call(death_clock, [&] {
        return libssh2_sftp_lstat(sftp, args.path.c_str(), &attrs);
      });
    }
    rcm = ErrorRecord(stat_res, TraceLevel::Error, args.path,
                      "libssh2_sftp_stat");
    trace(rcm);
    if (!rcm) {
      return {std::move(rcm)};
    }
    return {{FormatStat(args.path, attrs)}, std::move(rcm)};
  }

  ECMData<AMFSI::ListResult>
  listdir(const AMFSI::ListdirArgs &args,
          const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {std::move(rcm)};
    }

    rcm = _precheck(args.path, control);
    if (rcm.code != EC::Success) {
      return {std::move(rcm)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!sftp) {
      return {ECM{EC::NoConnection, __func__, "", "SFTP not initialized"}};
    }

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    std::vector<std::pair<std::string, LIBSSH2_SFTP_ATTRIBUTES>> raw_list = {};
    LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
    std::string name;
    const size_t buffer_size = 4096;
    std::vector<char> filename_buffer(buffer_size, 0);
    detail::DeathClockProtocol death_clock(control);

    auto open_res = nb_call(death_clock, [&] {
      return libssh2_sftp_open_ex(sftp, args.path.c_str(), args.path.size(), 0,
                                  LIBSSH2_SFTP_OPENDIR, LIBSSH2_FXF_READ);
    });
    rcm = ErrorRecord(open_res, TraceLevel::Error, args.path,
                      "libssh2_sftp_open_ex");

    if (!rcm) {
      if (rcm.code == EC::FileNotExist || rcm.code == EC::PathNotExist) {
        auto stat_res = stat(AMFSI::StatArgs{args.path, false}, control);
        if (stat_res.rcm.code == EC::Success) {
          if (stat_res.data.info.type != PathType::DIR) {
            rcm = {EC::NotADirectory, "listdir", args.path,
                   "Target exists but is not a directory"};
          }
        } else if (stat_res.rcm.code == EC::FileNotExist ||
                   stat_res.rcm.code == EC::PathNotExist) {
          rcm = {EC::PathNotExist, "listdir", args.path,
                 "Directory does not exist"};
        }
      }
      trace(rcm);
      return {std::move(rcm)};
    }
    sftp_handle = open_res.value;

    while (true) {
      auto read_res = nb_call(death_clock, [&] {
        return libssh2_sftp_readdir_ex(sftp_handle, filename_buffer.data(),
                                       buffer_size, nullptr, 0, &attrs);
      });
      rcm = ErrorRecord(read_res, TraceLevel::Error, args.path,
                        "libssh2_sftp_readdir_ex");
      if (!rcm) {
        if (rcm.code == EC::PermissionDenied) {
          continue;
        }
        trace(rcm);
        break;
      }
      if (read_res.value == 0) {
        break;
      }

      name.assign(filename_buffer.data(), static_cast<size_t>(read_res.value));
      if (name == "." || name == ".." || name.empty()) {
        continue;
      }
      raw_list.emplace_back(AMPath::join(args.path, name), attrs);
    }

    if (sftp_handle) {
      detail::DeathClockProtocol close_death_clock(
          control, AMDomain::client::kHandleCloseGraceWaitMs);
      (void)nb_call(close_death_clock,
                    [&]() { return libssh2_sftp_close_handle(sftp_handle); });
    }
    if (!rcm) {
      return {std::move(rcm)};
    }

    std::vector<PathInfo> entries(raw_list.size());
    for (size_t i = 0; i < raw_list.size(); i++) {
      entries[i] = FormatStat(raw_list[i].first, raw_list[i].second);
    }
    return {{std::move(entries)}, std::move(rcm)};
  }

  ECMData<AMFSI::ListNamesResult>
  listnames(const AMFSI::ListNamesArgs &args,
            const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {std::move(rcm)};
    }

    rcm = _precheck(args.path, control);
    if (rcm.code != EC::Success) {
      return {std::move(rcm)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!sftp) {
      return {ECM{EC::NoConnection, __func__, "", "SFTP not initialized"}};
    }

    LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
    std::string name;
    const size_t buffer_size = 4096;
    std::vector<char> filename_buffer(buffer_size, 0);
    std::vector<std::string> names = {};
    detail::DeathClockProtocol death_clock(control);

    auto open_res = nb_call(death_clock, [&] {
      return libssh2_sftp_open_ex(sftp, args.path.c_str(), args.path.size(), 0,
                                  LIBSSH2_SFTP_OPENDIR, LIBSSH2_FXF_READ);
    });
    rcm = ErrorRecord(open_res, TraceLevel::Error, args.path,
                      "libssh2_sftp_open_ex");
    if (!rcm) {
      if (rcm.code == EC::FileNotExist || rcm.code == EC::PathNotExist) {
        auto stat_res = stat(AMFSI::StatArgs{args.path, false}, control);
        if (stat_res.rcm.code == EC::Success) {
          if (stat_res.data.info.type != PathType::DIR) {
            rcm = {EC::NotADirectory, "listnames", args.path,
                   "Target exists but is not a directory"};
          }
        } else if (stat_res.rcm.code == EC::FileNotExist ||
                   stat_res.rcm.code == EC::PathNotExist) {
          rcm = {EC::PathNotExist, "listnames", args.path,
                 "Directory does not exist"};
        }
      }
      trace(rcm);
      return {std::move(rcm)};
    }
    sftp_handle = open_res.value;

    while (true) {
      auto read_res = nb_call(death_clock, [&] {
        return libssh2_sftp_readdir_ex(sftp_handle, filename_buffer.data(),
                                       buffer_size, nullptr, 0, nullptr);
      });
      rcm = ErrorRecord(read_res, TraceLevel::Error, args.path,
                        "libssh2_sftp_readdir_ex");
      if (!rcm) {
        if (rcm.code == EC::PermissionDenied) {
          continue;
        }
        trace(rcm);
        break;
      }
      if (read_res.value == 0) {
        break;
      }

      name.assign(filename_buffer.data(), static_cast<size_t>(read_res.value));
      if (name == "." || name == ".." || name.empty()) {
        continue;
      }
      names.push_back(name);
    }

    if (sftp_handle) {
      detail::DeathClockProtocol close_death_clock(
          control, AMDomain::client::kHandleCloseGraceWaitMs);
      (void)nb_call(close_death_clock,
                    [&]() { return libssh2_sftp_close_handle(sftp_handle); });
    }
    if (!rcm) {
      return {std::move(rcm)};
    }
    return {{std::move(names)}, std::move(rcm)};
  }

  ECMData<AMFSI::MkdirResult>
  mkdir(const AMFSI::MkdirArgs &args,
        const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {std::move(rcm)};
    }
    rcm = _precheck(args.path, control);
    if (rcm.code != EC::Success) {
      return {std::move(rcm)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!sftp) {
      return {ECM{EC::NoConnection, __func__, "", "SFTP not initialized"}};
    }
    detail::DeathClockProtocol death_clock(control);
    auto nb_res = nb_call(death_clock, [&] {
      return libssh2_sftp_mkdir_ex(sftp, args.path.c_str(), args.path.size(),
                                   0740);
    });
    if (nb_res && nb_res.value >= 0) {
      return {{}, std::move(rcm)};
    }
    rcm = ErrorRecord(nb_res, TraceLevel::Error, args.path,
                      "libssh2_sftp_mkdir_ex");
    if (rcm.code == EC::Terminate || rcm.code == EC::OperationTimeout) {
      trace(rcm);
      return {std::move(rcm)};
    }

    auto stat_res = stat(AMFSI::StatArgs{args.path, false}, control);
    if (stat_res.rcm.code == EC::Success) {
      if (stat_res.data.info.type == PathType::DIR) {
        return {{}, OK};
      }
      rcm = {EC::PathAlreadyExists, "libssh2_sftp_mkdir_ex", args.path,
             "Path exists and is not a directory"};
      trace(rcm);
      return {std::move(rcm)};
    }
    if (stat_res.rcm.code == EC::Terminate ||
        stat_res.rcm.code == EC::OperationTimeout) {
      trace(stat_res.rcm);
      return {std::move(stat_res.rcm)};
    }

    trace(rcm);
    return {std::move(rcm)};
  }

  ECMData<AMFSI::MkdirsResult>
  mkdirs(const AMFSI::MkdirsArgs &args,
         const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {std::move(rcm)};
    }
    rcm = _precheck(args.path, control);
    if (rcm.code != EC::Success) {
      return {std::move(rcm)};
    }
    std::vector<std::string> parts = AMPath::split(args.path);
    if (parts.empty()) {
      return {ECM{EC::InvalidArg, "AMPath::split", args.path,
                  "Path split failed (empty parts)"}};
    }

    std::string current_path = "";
    for (const auto &part : parts) {
      if (part.empty() || part == ".") {
        continue;
      }
      if (part == "/") {
        current_path = "/";
        continue;
      }
      if (control.CheckStop(rcm)) {
        return {std::move(rcm)};
      }

      if (current_path.empty()) {
        current_path = part;
      } else {
        current_path = AMPath::join(current_path, part, SepType::Unix);
      }

      auto mk_res = mkdir(AMFSI::MkdirArgs{current_path}, control);
      if (mk_res.rcm.code != EC::Success) {
        return {std::move(mk_res.rcm)};
      }
    }
    return {{}, std::move(rcm)};
  }

  ECMData<AMFSI::RMResult>
  rmdir(const AMFSI::RmdirArgs &args,
        const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {std::move(rcm)};
    }
    rcm = _precheck(args.path, control);
    if (rcm.code != EC::Success) {
      return {std::move(rcm)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!sftp) {
      return {ECM{EC::NoConnection, __func__, "", "SFTP not initialized"}};
    }
    detail::DeathClockProtocol death_clock(control);
    auto nb_res = nb_call(death_clock, [&] {
      return libssh2_sftp_rmdir(sftp, args.path.c_str());
    });
    rcm =
        ErrorRecord(nb_res, TraceLevel::Error, args.path, "libssh2_sftp_rmdir");
    trace(rcm);
    return {{}, std::move(rcm)};
  }

  ECMData<AMFSI::RMResult>
  rmfile(const AMFSI::RmfileArgs &args,
         const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {std::move(rcm)};
    }
    rcm = _precheck(args.path, control);
    if (rcm.code != EC::Success) {
      return {std::move(rcm)};
    }

    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!sftp) {
      return {ECM{EC::NoConnection, __func__, "", "SFTP not initialized"}};
    }
    detail::DeathClockProtocol death_clock(control);
    auto nb_res = nb_call(death_clock, [&] {
      return libssh2_sftp_unlink(sftp, args.path.c_str());
    });
    rcm = ErrorRecord(nb_res, TraceLevel::Error, args.path,
                      "libssh2_sftp_unlink");
    trace(rcm);
    return {{}, std::move(rcm)};
  }

  ECMData<AMFSI::MoveResult>
  rename(const AMFSI::RenameArgs &args,
         const AMDomain::client::ClientControlComponent &control) override {
    ECM rcm = OK;
    if (control.CheckStop(rcm)) {
      return {std::move(rcm)};
    }
    ECM rcm0 = _precheck(args.src, control);
    if (rcm0.code != EC::Success) {
      return {std::move(rcm0)};
    }
    ECM rcm1 = _precheck(args.dst, control);
    if (rcm1.code != EC::Success) {
      return {std::move(rcm1)};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (args.mkdir) {
      auto mk_res =
          mkdirs(AMFSI::MkdirsArgs{AMPath::dirname(args.dst)}, control);
      if (mk_res.rcm.code != EC::Success) {
        return {std::move(mk_res.rcm)};
      }
    }
    if (!sftp) {
      return {ECM{EC::NoConnection, __func__, "", "SFTP not initialized"}};
    }
    detail::DeathClockProtocol death_clock(control);
    auto nb_res = nb_call(death_clock, [&] {
      return libssh2_sftp_rename_ex(
          sftp, args.src.c_str(), args.src.size(), args.dst.c_str(),
          args.dst.size(),
          args.overwrite
              ? (LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_NATIVE)
              : LIBSSH2_SFTP_RENAME_NATIVE);
    });
    rcm = ErrorRecord(nb_res, TraceLevel::Error,
                      AMStr::fmt("{} -> {}", args.src, args.dst),
                      "libssh2_sftp_rename_ex");
    trace(rcm);
    return {{}, std::move(rcm)};
  }

  CR ConductCmdCore_(
      const std::string &cmd,
      const AMDomain::client::ClientControlComponent &control,
      const AMFSI::ConductCmdArgs::OutputProcessor &processor = {}) {
    const int max_time_ms = detail::ResolveTimeoutMs_(control);
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (control.IsInterrupted()) {
      return {ECM{EC::Terminate, "command.exec", cmd,
                  "Aborted before command sent"},
              {"", -1}};
    }
    if (control.IsTimeout()) {
      return {ECM{EC::OperationTimeout, "command.exec", cmd, "Timed out"},
              {"", -1}};
    }

    enum class CmdStage { BeforeSend, AwaitOutput, ReadingOutput, AwaitExit };
    CmdStage stage = CmdStage::BeforeSend;

    int64_t time_start = AMTime::miliseconds();
    int exit_status = -1;
    bool has_output = false;
    std::string output;
    std::array<char, 32 * AMKB> buffer;
    WaitResult wr = WaitResult::Ready;
    ssize_t nbytes = 0;
    NBResult<int> exec_res{0, WaitResult::Ready};
    NBResult<ssize_t> read_res{0, WaitResult::Ready};
    NBResult<int> close_res{0, WaitResult::Ready};
    detail::DeathClockProtocol death_clock(control);

    // Set non-blocking mode
    libssh2_session_set_blocking(session, 0);

    detail::SafeChannel sf;
    ECM init_rcm = sf.Init(
        session, [&control]() { return control.IsInterrupted(); }, max_time_ms,
        time_start);
    if (init_rcm.code != EC::Success) {
      return {std::move(init_rcm), {"", -1}};
    }

    auto graceful_exit = [&](bool send_exit) {
      (void)sf.graceful_exit(send_exit, 50, true);
    };

    // 1. Execute command
    exec_res = nb_call(death_clock, [&] {
      return libssh2_channel_exec(sf.channel, cmd.c_str());
    });
    if (!exec_res) {
      wr = exec_res.status;
      goto cleanup;
    }
    if (exec_res.value < 0) {
      return {ECM{GetLastEC(), "channel.exec", cmd, GetLastErrorMsg()},
              {"", -1}};
    }
    stage = CmdStage::AwaitOutput;
    // 2. Read output
    while (true) {
      read_res = nb_call(death_clock, [&] {
        return libssh2_channel_read(sf.channel, buffer.data(),
                                    buffer.size() - 1);
      });
      if (!read_res) {
        wr = read_res.status;
        goto cleanup;
      }
      nbytes = read_res.value;

      if (nbytes > 0) {
        const std::string chunk(buffer.data(), static_cast<size_t>(nbytes));
        output.append(chunk);
        if (processor) {
          (void)CallCallbackSafe(processor, std::string_view(chunk));
        }
        has_output = true;
        stage = CmdStage::ReadingOutput;
      } else if (nbytes == 0) {
        stage = CmdStage::AwaitExit;
        break; // EOF
      } else {
        return {ECM{GetLastEC(), "channel.read", cmd, GetLastErrorMsg()},
                {"", -1}};
      }
    }

    // 3. Trim trailing output whitespace
    while (!output.empty() &&
           (output.back() == '\n' || output.back() == '\r')) {
      output.pop_back();
    }

    // 4. Close channel non-blocking
    close_res = nb_call(death_clock, [&] { return sf.close_nonblock(); });

    if (!close_res) {
      wr = close_res.status;
      goto cleanup;
    }

    if (close_res.value < 0) {
      return {ECM{GetLastEC(), "channel.close", cmd, GetLastErrorMsg()},
              {output, -1}};
    }

    // 5. Get exit status
    exit_status = libssh2_channel_get_exit_status(sf.channel);

    return {OK, {output, exit_status}};

  cleanup:
    switch (wr) {
    case WaitResult::Interrupted:
      if (stage == CmdStage::BeforeSend) {
        graceful_exit(false);
        return {ECM{EC::Terminate, "command.exec", cmd,
                    "Operation aborted before command sent"},
                {output, -1}};
      }
      if (stage == CmdStage::AwaitOutput && !has_output) {
        graceful_exit(true);
        return {
            ECM{EC::Terminate, "command.exec", cmd, "Canceled before output"},
            {output, -1}};
      }
      graceful_exit(true);
      return {ECM{EC::Terminate, "command.exec", cmd,
                  "Interrupted before exit status"},
              {output, -1}};
    case WaitResult::Timeout:
      graceful_exit(true);
      return {ECM{EC::OperationTimeout, "command.exec", cmd, "Timed out"},
              {output, -1}};
    case WaitResult::Error:
      graceful_exit(true);
      return {ECM{EC::SocketRecvError, "command.exec", cmd,
                  "Socket error during command"},
              {output, -1}};
    default:
      graceful_exit(true);
      return {ECM{EC::UnknownError, "command.exec", cmd, "Command aborted"},
              {output, -1}};
    }
  }

  OS_TYPE UpdateOSTypeCache_(bool force_refresh = false) {
    OS_TYPE cached = GetCachedOSType_();
    if (!force_refresh && cached != OS_TYPE::Uncertain &&
        cached != OS_TYPE::Unknown) {
      return cached;
    }
    const auto win_control =
        AMDomain::client::ClientControlComponent(nullptr, 3000);
    auto [win_ecm, win_out] =
        ConductCmdCore_("powershell -NoProfile -Command "
                        "\"[System.Environment]::OSVersion.VersionString\"",
                        win_control);
    int code = win_out.second;
    std::string out_str = win_out.first;
    if (win_ecm.code == EC::Success &&
        out_str.find("Windows") != std::string::npos) {
      SetCachedOSType_(OS_TYPE::Windows);
      return OS_TYPE::Windows;
    }

    const auto uname_control =
        AMDomain::client::ClientControlComponent(nullptr, 3000);
    auto [uname_ecm, uname_out] = ConductCmdCore_("uname -s", uname_control);
    if (uname_ecm.code != EC::Success) {
      SetCachedOSType_(OS_TYPE::Uncertain);
      return OS_TYPE::Uncertain;
    }
    code = uname_out.second;
    if (code == 0) {
      out_str = AMStr::lowercase(uname_out.first);
      if (out_str.find("cygwin") != std::string::npos) {
        cached = OS_TYPE::Windows;
      } else if (out_str.find("darwin") != std::string::npos) {
        cached = OS_TYPE::MacOS;
      } else if (out_str.find("linux") != std::string::npos) {
        cached = OS_TYPE::Linux;
      } else if (out_str.find("mingw") != std::string::npos) {
        cached = OS_TYPE::Windows;
      } else if (out_str.find("msys") != std::string::npos) {
        cached = OS_TYPE::Windows;
      } else if (out_str.find("freebsd") != std::string::npos) {
        cached = OS_TYPE::FreeBSD;
      } else {
        cached = OS_TYPE::Unix;
      }
      SetCachedOSType_(cached);
      return cached;
    }

    SetCachedOSType_(OS_TYPE::Unknown);
    return OS_TYPE::Unknown;
  }

  std::string StrUid(const long &uid) {
    if (user_id_map.find(uid) != user_id_map.end()) {
      return user_id_map[uid];
    }

    std::string cmd = AMStr::fmt("id -un {}", std::to_string(uid));
    const auto control =
        AMDomain::client::ClientControlComponent(nullptr, 3000);
    auto [rcm, cr] = ConductCmdCore_(cmd, control);
    if (rcm.code != EC::Success) {
      return "unknown";
    }
    if (cr.second != 0) {
      return "unknown";
    } else {
      user_id_map[uid] = cr.first;
      return cr.first;
    }
  }

  std::string UpdateHomeDirCache_() {
    std::string cached_home_dir = GetCachedHomeDir_();
    if (!cached_home_dir.empty()) {
      return cached_home_dir;
    }
    const auto control =
        AMDomain::client::ClientControlComponent(nullptr, 3000);
    auto [rcm, path_obj] = ResolveRealpathCore_(".", control);
    if (rcm.code == EC::Success) {
      SetCachedHomeDir_(path_obj);
      return path_obj;
    }
    const ConRequest request = request_atomic_.lock().load();
    switch (UpdateOSTypeCache_()) {
    case OS_TYPE::Windows:
      return "C:\\Users\\" + request.username;
    case OS_TYPE::Linux:
      return "/home/" + request.username;
    case OS_TYPE::MacOS:
      return "/Users/" + request.username;
    case OS_TYPE::FreeBSD:
      return "/usr/home/" + request.username;
    case OS_TYPE::Unix:
      return "/home/" + request.username;
    default:
      return "C:\\Users\\" + request.username;
    }
  }
};
} // namespace AMInfra::client::SFTP
