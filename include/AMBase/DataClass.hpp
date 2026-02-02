#pragma once
// 标准库
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdint> // 用于int64_t类型
#include <fcntl.h>
#include <iomanip>
#include <mutex>
#include <optional>
#include <random>

#include <exception>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// 标准库

// 自身依赖
#include "AMBase/CommonTools.hpp"
#include "AMBase/Enum.hpp"

// 自身依赖

// 第三方库
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// 第三方库

using EC = ErrorCode;
using result_map = std::unordered_map<std::string, ErrorCode>;
using ECM = std::pair<EC, std::string>;

enum class AMTokenType {
  Common,
  Module,
  Command,
  VarName,
  VarValue,
  Nickname,
  String,
  Option,
  AtSign,
  DollarSign,
  EqualSign,
  VarNameMissing,
  EscapeSign
};

struct AMTokenSpan {
  size_t start = 0;
  size_t end = 0;
  AMTokenType type = AMTokenType::Common;
};

template <typename Fn, typename... Args>
inline ECM CallCallbackSafe(const Fn &fn, Args &&...args) {
  if (!fn) {
    return {EC::Success, ""};
  }
  try {
    fn(std::forward<Args>(args)...);
    return {EC::Success, ""};
  } catch (const std::exception &e) {
    return {EC::PyCBError, e.what()};
  } catch (...) {
    return {EC::PyCBError, "Unknown callback error"};
  }
}

template <typename Ret, typename Fn, typename... Args>
inline std::pair<Ret, ECM> CallCallbackSafeRet(const Fn &fn, Args &&...args) {
  if (!fn) {
    return {Ret{}, {EC::Success, ""}};
  }
  try {
    return {fn(std::forward<Args>(args)...), {EC::Success, ""}};
  } catch (const std::exception &e) {
    return {Ret{}, {EC::PyCBError, e.what()}};
  } catch (...) {
    return {Ret{}, {EC::PyCBError, "Unknown callback error"}};
  }
}

inline std::array<char, 32> AMcharset = {'2', '3', '4', '5', '6', '7', '8', '9',
                                         'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                         'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'S',
                                         'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
constexpr size_t AMbase = sizeof(AMcharset) - 1;

inline uint64_t GenerateUIDInt() {
  try {
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    return dist(eng);
  } catch (...) {
    // fallback: time + counter
    static std::atomic<uint64_t> counter{0};
    uint64_t t = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    return t ^ (++counter * 0x9e3779b97f4a7c15ULL);
  }
}

inline std::string GenerateUID(int length = 10) {
  length = length < 1 ? 1 : length;
  length = length > 32 ? 32 : length;
  uint64_t uid = GenerateUIDInt();
  // 用AMcharset生成一个字符串
  std::string uid_str;
  uid_str.reserve(static_cast<size_t>(length));
  for (int i = 0; i < length; i++) {
    uid_str += AMcharset[static_cast<size_t>(uid % AMbase)];
    uid /= AMbase;
  }
  std::reverse(uid_str.begin(), uid_str.end());
  return uid_str;
}

inline double timenow() {
  // 获取unix参考时间，以秒为单位返回double
  return std::chrono::duration<double>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
  return std::chrono::duration<double>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// 获取从steady_clock纪元到当前的毫秒数（整数）
inline std::int64_t am_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
inline double am_s() {
  return std::chrono::duration<double>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
inline std::string FormatTime(const uint64_t &time,
                              const std::string &format = "%Y-%m-%d %H:%M:%S") {
  time_t timeT = static_cast<time_t>(time);

  struct tm timeInfo;
  {
#ifdef _WIN32

    localtime_s(&timeInfo, &timeT);
#else
    localtime_r(&timeT, &timeInfo);
#endif

    std::ostringstream oss;
    oss << std::put_time(&timeInfo, format.c_str());

    return oss.str();
  };
}

class InterruptFlag {
private:
  std::atomic<bool> is_interrupted = false;
  std::atomic<bool> is_killed = false;

public:
  /**
   * @brief Return true if the interrupt flag has been marked as killed.
   */
  inline bool iskill() const { return is_killed.load(); }
  inline bool check() { return is_interrupted.load(); }
  inline void set(bool value) { is_interrupted.store(value); }
  inline void reset() { is_interrupted.store(false); }
  inline void kill() {
    is_interrupted.store(true);
    is_killed.store(true);
  }
};

// 非阻塞调用结果
template <typename T> struct NBResult {
  T value;           // 函数返回值
  WaitResult status; // 等待状态

  bool ok() const { return status == WaitResult::Ready; }
  bool is_timeout() const { return status == WaitResult::Timeout; }
  bool is_interrupted() const { return status == WaitResult::Interrupted; }
  bool is_error() const { return status == WaitResult::Error; }
};

struct MemoryStruct {
  char *memory;
  size_t size;
};

class PathInfo {
public:
  std::string name;
  std::string path;
  std::string dir;
  std::string owner;
  uint64_t size = 0;
  double create_time = 0;
  double access_time = 0;
  double modify_time = 0;
  PathType type = PathType::FILE;
  uint64_t mode_int = 0777;
  std::string mode_str = "r--------";
  PathInfo() : name(""), path(""), dir(""), owner("") {}

  PathInfo(std::string name, std::string path, std::string dir,
           std::string owner, uint64_t size, double create_time,
           double access_time, double modify_time, PathType type,
           uint64_t mode_int, std::string mode_str)
      : name(name), path(path), dir(dir), owner(owner), size(size),
        create_time(create_time), access_time(access_time),
        modify_time(modify_time), type(type), mode_int(mode_int),
        mode_str(mode_str) {}
};

// 跨平台Socket连接器
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

    // 1. DNS解析 - 使用 AF_UNSPEC 支持 IPv4 和 IPv6
    addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC; // 支持 IPv4 和 IPv6
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

    // 2. 遍历所有地址尝试连接（支持 IPv4/IPv6 双栈）
    addrinfo *rp = nullptr;
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
      if (is_interrupted()) {
        mark_interrupted();
        freeaddrinfo(result);
        return false;
      }

      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock == INVALID_SOCKET) {
        continue; // 尝试下一个地址
      }

      // 3. 设置非阻塞模式
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

      // 4. 发起连接
      int conn_result = connect(sock, rp->ai_addr, (int)rp->ai_addrlen);

#ifdef _WIN32
      bool in_progress =
          (conn_result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
#else
      bool in_progress = (conn_result == -1 && errno == EINPROGRESS);
#endif

      if (conn_result == 0) {
        // 立即成功（本地连接可能发生）
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
        continue; // 尝试下一个地址
      }

      // 5. 使用select等待连接完成
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
        continue; // 尝试下一个地址
      }

      // 6. 检查socket错误
      int sock_error = 0;
      socklen_t len = sizeof(sock_error);
      if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&sock_error, &len) <
              0 ||
          sock_error != 0) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue; // 尝试下一个地址
      }

      // 7. 恢复阻塞模式，连接成功
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

    // 所有地址都尝试失败
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

struct ConRequst {
  std::string nickname;
  std::string hostname;
  std::string username;
  std::string password;
  std::string keyfile;
  bool compression;
  int port;
  std::string trash_dir = "";
  ConRequst()
      : nickname(""), hostname(""), username(""), password(""), keyfile(""),
        compression(false), port(22), trash_dir("") {}
  ConRequst(std::string nickname, std::string hostname, std::string username,
            int port = 22, std::string password = "", std::string keyfile = "",
            bool compression = false, std::string trash_dir = "")
      : nickname(std::move(nickname)), hostname(std::move(hostname)),
        username(std::move(username)), password(std::move(password)),
        keyfile(std::move(keyfile)), compression(compression), port(port),
        trash_dir(std::move(trash_dir)) {}
};

struct ProgressCBInfo {
  std::string src;
  std::string dst;
  std::string src_host;
  std::string dst_host;
  uint64_t this_size;
  uint64_t file_size;
  uint64_t accumulated_size;
  uint64_t total_size;
  ProgressCBInfo(const std::string &src, const std::string &dst,
                 const std::string &src_host, const std::string &dst_host,
                 uint64_t this_size, uint64_t file_size,
                 const uint64_t &accumulated_size, const uint64_t &total_size)
      : src(src), dst(dst), src_host(src_host), dst_host(dst_host),
        this_size(this_size), file_size(file_size),
        accumulated_size(accumulated_size), total_size(total_size) {}
};

class StreamRingBuffer {
private:
  /**
   * @brief Backing storage for the ring buffer.
   *
   * This uses std::array to replace the raw char[] buffer. The effective
   * capacity is clamped to the requested size at construction time.
   */
  std::array<char, static_cast<size_t>(AMMaxBufferSize)> buffer_{};
  size_t capacity_ = 0;
  std::atomic<size_t> head_{0}; // 消费者读取位置
  std::atomic<size_t> tail_{0}; // 生产者写入位置

public:
  /**
   * @brief Construct a ring buffer with a requested capacity.
   *
   * @param size Requested buffer size in bytes. The actual capacity is clamped
   *             to the maximum std::array size.
   */
  explicit StreamRingBuffer(size_t size)
      : capacity_(std::min<size_t>(size, buffer_.size())) {}

  /**
   * @brief Get the amount of readable data in the buffer.
   */
  size_t available() const {
    return tail_.load(std::memory_order_acquire) -
           head_.load(std::memory_order_relaxed);
  }

  /**
   * @brief Get the amount of writable space remaining in the buffer.
   */
  size_t writable() const { return capacity_ - available(); }

  /**
   * @brief Get the write pointer and maximum contiguous writable length.
   */
  std::pair<char *, size_t> get_write_ptr() {
    size_t t = tail_.load(std::memory_order_relaxed);
    size_t h = head_.load(std::memory_order_acquire);
    size_t pos = t % capacity_;
    size_t used = t - h;
    size_t free_space = capacity_ - used;
    // 连续可写 = min(到末尾的距离, 空闲空间)
    size_t contig = capacity_ - pos > free_space ? free_space : capacity_ - pos;
    return {buffer_.data() + pos, contig};
  }

  /**
   * @brief Commit a number of bytes as written to the buffer.
   */
  void commit_write(size_t len) {
    tail_.fetch_add(len, std::memory_order_release);
  }

  /**
   * @brief Get the read pointer and maximum contiguous readable length.
   */
  std::pair<char *, size_t> get_read_ptr() {
    size_t h = head_.load(std::memory_order_relaxed);
    size_t t = tail_.load(std::memory_order_acquire);
    size_t pos = h % capacity_;
    size_t avail = t - h;
    // 连续可读 = min(到末尾的距离, 可用数据)
    size_t contig = capacity_ - pos > avail ? avail : capacity_ - pos;
    return {buffer_.data() + pos, contig};
  }

  /**
   * @brief Commit a number of bytes as consumed from the buffer.
   */
  void commit_read(size_t len) {
    head_.fetch_add(len, std::memory_order_release);
  }

  /**
   * @brief Check whether the buffer has no readable data.
   */
  bool empty() const { return available() == 0; }

  /**
   * @brief Check whether the buffer has no writable space.
   */
  bool full() const { return writable() == 0; }

  /**
   * @brief Get the effective capacity of the buffer.
   */
  size_t get_capacity() const { return capacity_; }
};

class UserTransferSet {
public:
  /**
   * @brief The list of user-provided source paths.
   */
  std::vector<std::string> srcs;
  /**
   * @brief The destination path for all sources in this set.
   */
  std::string dst;

  /**
   * @brief Whether to create missing destination directories.
   */
  bool mkdir = true;

  /**
   * @brief Whether to overwrite existing targets.
   */
  bool overwrite = false;

  bool clone = false;

  /**
   * @brief Whether to ignore special files during traversal.
   */
  bool ignore_special_file = true;

  /**
   * @brief Construct an empty transfer set with default flags.
   */
  UserTransferSet() = default;

  /**
   * @brief Construct a transfer set from sources, destination, and flags.
   */
  UserTransferSet(std::vector<std::string> srcs, std::string dst, bool mkdir,
                  bool overwrite, bool ignore_special_file)
      : srcs(std::move(srcs)), dst(std::move(dst)), mkdir(mkdir),
        overwrite(overwrite), ignore_special_file(ignore_special_file) {}
};

struct ErrorCBInfo {
  std::pair<ErrorCode, std::string> ecm;
  std::string src;
  std::string dst;
  std::string src_host;
  std::string dst_host;
  ErrorCBInfo(std::pair<ErrorCode, std::string> ecm, std::string src,
              std::string dst, std::string src_host, std::string dst_host)
      : ecm(ecm), src(src), dst(dst), src_host(src_host), dst_host(dst_host) {}
};

namespace AMAuth {
/**
 * @brief Fixed compile-time key used for password obfuscation at rest.
 */
inline constexpr std::string_view kPasswordKey =
    "AMSFTP::FixedCompileTimeKey::DoNotReuse";

/**
 * @brief Prefix marking encrypted password payloads.
 */
inline constexpr std::string_view kEncryptedPrefix = "enc:";

/**
 * @brief Securely zero a string's underlying storage.
 */
inline void SecureZero(std::string &value) {
  std::fill(value.begin(), value.end(), '\0');
  value.clear();
  value.shrink_to_fit();
}

/**
 * @brief Check whether a password string is already encrypted.
 */
inline bool IsEncrypted(const std::string &value) {
  return value.rfind(std::string(kEncryptedPrefix), 0) == 0;
}

/**
 * @brief Hex-encode a byte buffer.
 */
inline std::string HexEncode(const std::string &bytes) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.resize(bytes.size() * 2);
  for (size_t i = 0; i < bytes.size(); ++i) {
    const unsigned char b = static_cast<unsigned char>(bytes[i]);
    out[i * 2] = kHex[(b >> 4) & 0x0F];
    out[i * 2 + 1] = kHex[b & 0x0F];
  }
  return out;
}

/**
 * @brief Decode a hex string into raw bytes. Returns empty on invalid input.
 */
inline std::string HexDecode(const std::string &hex) {
  auto hex_to_val = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'A' && c <= 'F')
      return 10 + (c - 'A');
    if (c >= 'a' && c <= 'f')
      return 10 + (c - 'a');
    return -1;
  };

  if (hex.size() % 2 != 0) {
    return {};
  }

  std::string out;
  out.resize(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int hi = hex_to_val(hex[i]);
    const int lo = hex_to_val(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return {};
    }
    out[i / 2] = static_cast<char>((hi << 4) | lo);
  }
  return out;
}

/**
 * @brief XOR-obfuscate bytes using the fixed compile-time key.
 */
inline std::string XorWithKey(const std::string &input) {
  if (input.empty()) {
    return {};
  }
  std::string out = input;
  for (size_t i = 0; i < out.size(); ++i) {
    const char key_ch = kPasswordKey[i % kPasswordKey.size()];
    out[i] = static_cast<char>(out[i] ^ key_ch);
  }
  return out;
}

/**
 * @brief Encrypt a plaintext password for storage.
 */
inline std::string EncryptPassword(const std::string &plain) {
  if (plain.empty()) {
    return {};
  }
  if (IsEncrypted(plain)) {
    return plain;
  }
  const std::string xored = XorWithKey(plain);
  const std::string encoded = HexEncode(xored);
  return std::string(kEncryptedPrefix) + encoded;
}

/**
 * @brief Decrypt a stored password. Returns input if not encrypted.
 */
inline std::string DecryptPassword(const std::string &stored) {
  if (stored.empty() || !IsEncrypted(stored)) {
    return stored;
  }
  const std::string payload =
      stored.substr(std::string(kEncryptedPrefix).size());
  std::string decoded = HexDecode(payload);
  if (decoded.empty() && !payload.empty()) {
    return {};
  }
  decoded = XorWithKey(decoded);
  return decoded;
}
} // namespace AMAuth

struct AuthCBInfo {
  /**
   * @brief Whether a password is required for authentication.
   */
  bool NeedPassword = false;

  /**
   * @brief Connection request context for the callback.
   */
  ConRequst request;

  /**
   * @brief The password being used in this authentication step (encrypted).
   */
  std::string password_n;

  /**
   * @brief Whether the provided password is correct.
   */
  bool iscorrect = false;

  /**
   * @brief Construct a callback info payload.
   */
  AuthCBInfo(bool need_password, ConRequst request, std::string password_n,
             bool iscorrect)
      : NeedPassword(need_password), request(std::move(request)),
        password_n(std::move(password_n)), iscorrect(iscorrect) {}
};

struct TraceInfo {
  TraceLevel level;
  ErrorCode error_code;
  std::string nickname;
  std::string target;
  std::string action;
  std::string message;
  double timestamp;

  TraceInfo()
      : level(TraceLevel::Info), error_code(EC::Success), nickname(""),
        target(""), action(""), message("") {}
  TraceInfo(TraceLevel level, ErrorCode error_code, std::string nickname,
            std::string target, std::string action, std::string message)
      : level(level), error_code(error_code), nickname(nickname),
        target(target), action(action), message(message), timestamp(timenow()) {
  }
};

struct TransferCallback {
  using ErrorCallback = std::function<void(const ErrorCBInfo &)>;
  using ProgressCallback =
      std::function<std::optional<TransferControl>(const ProgressCBInfo &)>;
  using TotalSizeCallback = std::function<void(uint64_t)>;

  bool need_error_cb = false;
  bool need_progress_cb = false;
  bool need_total_size_cb = false;
  ErrorCallback error_cb = {}; // void(ErrorCBInfo)
  ProgressCallback progress_cb =
      {}; // optional<TransferControl>(ProgressCBInfo)
  TotalSizeCallback total_size_cb = {}; // void(uint64_t)
  float cb_interval_s = 0.1f;           // Callback interval in seconds

  TransferCallback(TotalSizeCallback total_size = {}, ErrorCallback error = {},
                   ProgressCallback progress = {}, float cb_interval_s = 0.1f)
      : error_cb(std::move(error)), progress_cb(std::move(progress)),
        total_size_cb(std::move(total_size)), cb_interval_s(cb_interval_s) {
    need_total_size_cb = static_cast<bool>(total_size_cb);
    need_error_cb = static_cast<bool>(error_cb);
    need_progress_cb = static_cast<bool>(progress_cb);
  }

  void SetErrorCB(ErrorCallback cb = {}) {
    error_cb = std::move(cb);
    need_error_cb = static_cast<bool>(error_cb);
  }

  void SetProgressCB(ProgressCallback cb = {}) {
    progress_cb = std::move(cb);
    need_progress_cb = static_cast<bool>(progress_cb);
  };

  void SetTotalSizeCB(TotalSizeCallback cb = {}) {
    total_size_cb = std::move(cb);
    need_total_size_cb = static_cast<bool>(total_size_cb);
  }

  ECM CallError(const ErrorCBInfo &info) const {
    return CallCallbackSafe(error_cb, info);
  }

  ECM CallTotalSize(uint64_t total_size) const {
    return CallCallbackSafe(total_size_cb, total_size);
  }

  std::optional<TransferControl> CallProgress(const ProgressCBInfo &info,
                                              ECM *cb_error = nullptr) const {
    if (cb_error) {
      *cb_error = {EC::Success, ""};
    }
    if (!progress_cb) {
      return std::nullopt;
    }
    try {
      return progress_cb(info);
    } catch (const std::exception &e) {
      if (cb_error) {
        *cb_error = {EC::PyCBError, e.what()};
      }
      return TransferControl::Terminate;
    } catch (...) {
      if (cb_error) {
        *cb_error = {EC::PyCBError, "Unknown progress callback error"};
      }
      return TransferControl::Terminate;
    }
  }
};

struct TransferTask {
  std::string src;
  std::string src_host;
  std::string dst;
  std::string dst_host;
  uint64_t size;
  PathType path_type = PathType::FILE;
  bool IsFinished = false;
  ECM rcm = ECM(EC::Success, "");
  uint64_t transferred = 0; // Current file transferred size
  TransferTask() : src(""), src_host(""), dst(""), dst_host(""), size(0) {}
  TransferTask(std::string src, std::string dst, std::string src_host,
               std::string dst_host, uint64_t size,
               PathType path_type = PathType::FILE)
      : src(std::move(src)), src_host(std::move(src_host)), dst(std::move(dst)),
        dst_host(std::move(dst_host)), size(size), path_type(path_type) {}
};

using TASKS = std::vector<TransferTask>;
class UnimplementedMethodException : public std::exception {
public:
  UnimplementedMethodException(std::string message)
      : message(std::move(message)) {}
  const char *what() const noexcept override { return message.c_str(); }

private:
  std::string message;
};

struct TerminalWindowInfo {
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
  std::string term = "xterm-256color";
};

struct TaskInfo;        // Forward declaration
class ClientMaintainer; // Forward declaration
// New ProgressData that holds weak_ptr to TaskInfo to avoid cycle reference
// Reads/writes directly on TaskInfo for progress tracking
struct WkProgressData {
  std::weak_ptr<TaskInfo> task_info;
  std::atomic<int> control_sign{0}; // 0=Running, 1=Pause, 2=Terminate
  double cb_time = timenow();
  std::shared_ptr<StreamRingBuffer> ring_buffer = nullptr;
  std::function<void(bool)> inner_callback = {};

  WkProgressData() = default;
  explicit WkProgressData(std::shared_ptr<TaskInfo> ti) : task_info(ti) {}

  // Control signal helpers
  bool is_terminate() const {
    return control_sign.load() == static_cast<int>(ControlSignal::Terminate);
  }
  bool is_pause() const {
    return control_sign.load() == static_cast<int>(ControlSignal::Pause);
  }
  bool is_running() const {
    return control_sign.load() == static_cast<int>(ControlSignal::Running);
  }

  void set_terminate() {
    control_sign.store(static_cast<int>(ControlSignal::Terminate));
  }
  void set_pause() {
    control_sign.store(static_cast<int>(ControlSignal::Pause));
  }
  void set_running() {
    control_sign.store(static_cast<int>(ControlSignal::Running));
  }

  void CallInnerCallback(bool force = false) {
    if (inner_callback) {
      inner_callback(force);
    }
  }
};

/**
 * @brief Task assignment type for scheduler bookkeeping.
 */
enum class TaskAssignType { Affinity, Public };

struct TaskInfo {
  /**
   * @brief Callback invoked when the task completes.
   */
  using ResultCallback = std::function<void(std::shared_ptr<TaskInfo>)>;

  /**
   * @brief Internal mutex guarding non-atomic state changes.
   */
  mutable std::mutex mtx;

  /**
   * @brief Unique task identifier.
   */
  std::string id = "";

  /**
   * @brief Submission timestamp.
   */
  std::atomic<double> submit_time{0};

  /**
   * @brief Start timestamp.
   */
  std::atomic<double> start_time{0};

  /**
   * @brief Finished timestamp.
   */
  std::atomic<double> finished_time{0};

  /**
   * @brief Current task status.
   */
  std::atomic<TaskStatus> status{TaskStatus::Pending};

  /**
   * @brief Result code and message.
   */
  ECM rcm = {EC::Success, ""};

  /**
   * @brief Current task being transferred.
   */
  TransferTask *cur_task = nullptr;

  /**
   * @brief Progress tracking: accumulated transferred bytes.
   */
  std::atomic<uint64_t> total_transferred_size{0};

  /**
   * @brief Progress tracking: total bytes planned.
   */
  std::atomic<uint64_t> total_size{0};

  /**
   * @brief Progress tracking: transferred bytes for the current task.
   */
  std::atomic<uint64_t> this_task_transferred_size{0};

  /**
   * @brief Task list.
   */
  std::shared_ptr<TASKS> tasks = nullptr;

  /**
   * @brief Original user transfer configurations.
   */
  std::shared_ptr<std::vector<UserTransferSet>> transfer_sets = nullptr;

  /**
   * @brief Whether to suppress output (immutable after construction).
   */
  bool quiet = false;

  /**
   * @brief Completion callback (if provided).
   */
  ResultCallback result_callback = {};

  /**
   * @brief Requested logical thread affinity ID (-1 means public/unassigned).
   *
   * Thread 0 is intrinsic and cannot be removed.
   */
  std::atomic<int> affinity_thread{-1};

  /**
   * @brief Scheduler assignment type (public queue or affinity queue).
   */
  std::atomic<TaskAssignType> assign_type{TaskAssignType::Public};

  /**
   * @brief Logical thread ID currently executing this task (-1 otherwise).
   */
  std::atomic<int> OnWhichThread{-1};

  /**
   * @brief Transfer callbacks.
   */
  TransferCallback callback;

  /**
   * @brief Host maintainer reference.
   */
  std::weak_ptr<ClientMaintainer> hostm;

  /**
   * @brief Requested ring buffer size.
   */
  std::atomic<ssize_t> buffer_size{-1};

  /**
   * @brief Shared progress data for control signals.
   */
  std::shared_ptr<WkProgressData> pd;

  /**
   * @brief Construct a task info with optional quiet flag.
   */
  explicit TaskInfo(bool quiet_mode = false) : quiet(quiet_mode) {}

  TaskInfo(const TaskInfo &) = delete;
  TaskInfo &operator=(const TaskInfo &) = delete;
  TaskInfo(TaskInfo &&) = delete;
  TaskInfo &operator=(TaskInfo &&) = delete;

  /**
   * @brief Safely update the task status.
   */
  void SetStatus(TaskStatus new_status) { status.store(new_status); }

  /**
   * @brief Safely read the task status.
   */
  TaskStatus GetStatus() const { return status.load(); }

  /**
   * @brief Safely set the current task pointer.
   */
  void SetCurrentTask(TransferTask *task_ptr) {
    std::lock_guard<std::mutex> lock(mtx);
    cur_task = task_ptr;
  }

  /**
   * @brief Safely read the current task pointer.
   */
  TransferTask GetCurrentTask() const {
    std::lock_guard<std::mutex> lock(mtx);
    auto task_copy = *cur_task;
    return task_copy;
  }

  /**
   * @brief Safely update the result code and message.
   */
  void SetResult(const ECM &result) {
    std::lock_guard<std::mutex> lock(mtx);
    rcm = result;
  }

  /**
   * @brief Safely read the result code and message.
   */
  ECM GetResult() const {
    std::lock_guard<std::mutex> lock(mtx);
    return rcm;
  }
};

namespace AMTree {
struct TreeNode {
  std::vector<std::string> children;
  std::vector<PathInfo> files;
};

using TreeNodeMap = std::unordered_map<std::string, TreeNode>;
using JoinPartsFn =
    std::function<std::string(const std::vector<std::string> &)>;
using JoinPairFn =
    std::function<std::string(const std::string &, const std::string &)>;

/**
 * @brief Build tree nodes from walk structure data.
 */
inline void BuildTreeNodes(
    const std::string &root,
    const std::vector<
        std::pair<std::vector<std::string>, std::vector<PathInfo>>> &structure,
    TreeNodeMap *nodes, const JoinPartsFn &join_parts,
    const JoinPairFn &join_pair) {
  (void)join_pair;
  if (!nodes) {
    return;
  }
  nodes->clear();
  std::unordered_set<std::string> child_set;

  auto ensure_node = [&](const std::string &dir_path) {
    if (nodes->find(dir_path) == nodes->end()) {
      (*nodes)[dir_path] = TreeNode{};
    }
  };

  auto add_child = [&](const std::string &parent, const std::string &name) {
    std::string key = parent + "\n" + name;
    if (child_set.find(key) != child_set.end()) {
      return;
    }
    child_set.insert(key);
    (*nodes)[parent].children.push_back(name);
  };

  ensure_node(root);
  for (const auto &entry : structure) {
    const auto &parts = entry.first;
    const auto &files = entry.second;
    if (parts.empty()) {
      continue;
    }
    std::string dir_path = join_parts ? join_parts(parts) : root;
    ensure_node(dir_path);
    if (!files.empty()) {
      auto &list = (*nodes)[dir_path].files;
      list.insert(list.end(), files.begin(), files.end());
    }
    if (parts.size() > 1) {
      std::vector<std::string> parent_parts(parts.begin(), parts.end() - 1);
      std::string parent_path = join_parts ? join_parts(parent_parts) : root;
      ensure_node(parent_path);
      add_child(parent_path, parts.back());
    }
  }
}

/**
 * @brief Sort tree node children and files by case-insensitive name.
 */
inline void SortTreeNodes(TreeNodeMap *nodes) {
  if (!nodes) {
    return;
  }
  for (auto &[dir, node] : *nodes) {
    (void)dir;
    std::sort(node.children.begin(), node.children.end(),
              [&](const std::string &a, const std::string &b) {
                return AMStr::lowercase(a) < AMStr::lowercase(b);
              });
    std::sort(node.files.begin(), node.files.end(),
              [&](const PathInfo &a, const PathInfo &b) {
                return AMStr::lowercase(a.name) < AMStr::lowercase(b.name);
              });
  }
}

/**
 * @brief Print a tree using a style callback and line printer.
 */
inline void PrintTree(
    const std::string &root, const TreeNodeMap &nodes,
    const std::function<std::string(const PathInfo &, const std::string &)>
        &style_path,
    const std::function<void(const std::string &)> &print_line,
    const JoinPairFn &join_pair) {
  if (!print_line) {
    return;
  }
  PathInfo dir_info;
  dir_info.type = PathType::DIR;
  const std::string root_line = style_path ? style_path(dir_info, root) : root;
  print_line(root_line);

  std::function<void(const std::string &, const std::string &)> walk_tree =
      [&](const std::string &dir_path, const std::string &prefix) {
        auto it = nodes.find(dir_path);
        if (it == nodes.end()) {
          return;
        }
        const auto &children = it->second.children;
        const auto &files = it->second.files;
        const size_t dir_count = children.size();
        const size_t file_count = files.size();

        for (size_t i = 0; i < dir_count; ++i) {
          const bool last = (i + 1 == dir_count && file_count == 0);
          const std::string connector = last ? "`-- " : "|-- ";
          const std::string next_prefix = prefix + (last ? "    " : "|   ");
          const std::string child_name = children[i];
          const std::string styled =
              style_path ? style_path(dir_info, child_name) : child_name;
          print_line(prefix + connector + styled);
          if (join_pair) {
            const std::string child_path = join_pair(dir_path, child_name);
            walk_tree(child_path, next_prefix);
          }
        }

        for (size_t i = 0; i < file_count; ++i) {
          const bool last = (i + 1 == file_count);
          (void)last;
          const std::string connector = (i + 1 == file_count) ? "`-- " : "|-- ";
          const auto &info = files[i];
          const std::string styled =
              style_path ? style_path(info, info.name) : info.name;
          print_line(prefix + connector + styled);
        }
      };

  walk_tree(root, "");
}
} // namespace AMTree
