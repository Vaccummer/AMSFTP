#pragma once
// 标准库
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdint> // 用于int64_t类型
#include <fcntl.h>
#include <iomanip>
#include <optional>
#include <random>

#include <exception>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

// 标准库

// 自身依赖
#include "AMEnum.hpp"
// 自身依赖

// 第三方库
#include <fmt/core.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// 第三方库

using EC = ErrorCode;
using result_map = std::unordered_map<std::string, ErrorCode>;
using ECM = std::pair<EC, std::string>;

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

inline uint64_t GenerateUID() {
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
  std::string repr() {
    return fmt::format(
        "PathInfo(name={}, path={}, dir={}, owner={}, size={}, "
        "create_time={}, "
        "access_time={}, modify_time={}, type={}, mode_int={}, mode_str={})",
        name, path, dir, owner, size, FormatTime(create_time),
        FormatTime(access_time), FormatTime(modify_time),
        magic_enum::enum_name(type), mode_int, mode_str);
  }
};

// 跨平台Socket连接器
class SocketConnector {
public:
  SOCKET sock = INVALID_SOCKET;
  std::string error_msg = "";
  EC error_code = EC::Success;

  SocketConnector() = default;

  ~SocketConnector() {}

  // 连接到指定主机，返回是否成功

  bool Connect(const std::string &hostname, int port, int timeout_ms) {
    // 1. DNS解析 - 使用 AF_UNSPEC 支持 IPv4 和 IPv6
    addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC; // 支持 IPv4 和 IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int dns_err = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(),
                              &hints, &result);
    if (dns_err != 0) {
#ifdef _WIN32
      error_msg = fmt::format("DNS resolve failed: {} (hostname={})",
                              gai_strerrorA(dns_err), hostname);
#else
      error_msg = fmt::format("DNS resolve failed: {} (hostname={})",
                              gai_strerror(dns_err), hostname);
#endif
      error_code = EC::DNSResolveError;
      return false;
    }

    // 2. 遍历所有地址尝试连接（支持 IPv4/IPv6 双栈）
    addrinfo *rp = nullptr;
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
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
      fd_set write_fds, error_fds;
      FD_ZERO(&write_fds);
      FD_ZERO(&error_fds);
      FD_SET(sock, &write_fds);
      FD_SET(sock, &error_fds);

      timeval timeout;
      if (timeout_ms > 0) {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
      } else {
        timeout.tv_sec = 6;
        timeout.tv_usec = 0;
      }

      int select_result =
          select((int)sock + 1, nullptr, &write_fds, &error_fds, &timeout);

      if (select_result <= 0 || FD_ISSET(sock, &error_fds)) {
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
  std::unique_ptr<char[]> buffer;
  size_t capacity;
  std::atomic<size_t> head{0}; // 消费者读取位置
  std::atomic<size_t> tail{0}; // 生产者写入位置

public:
  StreamRingBuffer(size_t size)
      : buffer(std::make_unique<char[]>(size)), capacity(size) {}

  // 获取可读数据量
  size_t available() const {
    return tail.load(std::memory_order_acquire) -
           head.load(std::memory_order_relaxed);
  }

  // 获取可写空间
  size_t writable() const { return capacity - available(); }

  // 获取写入指针和最大连续可写长度
  std::pair<char *, size_t> get_write_ptr() {
    size_t t = tail.load(std::memory_order_relaxed);
    size_t h = head.load(std::memory_order_acquire);
    size_t pos = t % capacity;
    size_t used = t - h;
    size_t free_space = capacity - used;
    // 连续可写 = min(到末尾的距离, 空闲空间)
    size_t contig = capacity - pos > free_space ? free_space : capacity - pos;
    return {buffer.get() + pos, contig};
  }

  // 提交写入的数据量
  void commit_write(size_t len) {
    tail.fetch_add(len, std::memory_order_release);
  }

  // 获取读取指针和最大连续可读长度
  std::pair<char *, size_t> get_read_ptr() {
    size_t h = head.load(std::memory_order_relaxed);
    size_t t = tail.load(std::memory_order_acquire);
    size_t pos = h % capacity;
    size_t avail = t - h;
    // 连续可读 = min(到末尾的距离, 可用数据)
    size_t contig = capacity - pos > avail ? avail : capacity - pos;
    return {buffer.get() + pos, contig};
  }

  // 提交读取消费的数据量
  void commit_read(size_t len) {
    head.fetch_add(len, std::memory_order_release);
  }

  bool empty() const { return available() == 0; }
  bool full() const { return writable() == 0; }
  size_t get_capacity() const { return capacity; }
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

struct AuthCBInfo {
  bool NeedPassword; // if true, python password callback need to return
                     // password, if false, callback function just tells you
                     // the password is wrong
  ConRequst request;
  int trial_times;
  AuthCBInfo(bool NeedPassword, ConRequst request, int trial_times)
      : NeedPassword(NeedPassword), request(request), trial_times(trial_times) {
  }
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

// Control signal values for transfer control
// 0 = Running, 1 = Pause, 2 = Terminate

class UnimplementedMethodException : public std::exception {
public:
  UnimplementedMethodException(std::string message)
      : message(std::move(message)) {}
  const char *what() const noexcept override { return message.c_str(); }

private:
  std::string message;
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
struct TaskInfo {
  std::string id = "";
  double submit_time = 0;
  double start_time = 0;
  TaskStatus status = TaskStatus::Pending;
  double finished_time = 0;
  ECM rcm = {EC::Success, ""};

  // Current task being transferred - weak pointer to task in tasks vector
  TransferTask *cur_task = nullptr;

  // Progress tracking (directly in TaskInfo)
  uint64_t total_transferred_size = 0;
  uint64_t total_size = 0;

  // Task list
  std::vector<TransferTask> tasks;

  // Configuration
  TransferCallback callback;
  std::weak_ptr<ClientMaintainer> hostm;
  ssize_t buffer_size = -1;

  // Control - managed by WkProgressData's control_sign
  std::shared_ptr<WkProgressData> pd; // Shared progress data for control
};

/*
class BaseFileMapper {
public:
  char *file_ptr = nullptr;
  uint64_t file_size = 0;
  virtual ~BaseFileMapper() = default; // 虚析构函数，确保派生类析构被调用
};

#ifdef _WIN32
class WindowsFileMapper : public BaseFileMapper {
public:
  HANDLE hFile;
  HANDLE hMap;
  LPVOID addr;
  LARGE_INTEGER file_size_ptr;

  ~WindowsFileMapper() {
    UnmapViewOfFile(addr);

    CloseHandle(hMap);

    CloseHandle(hFile);
    file_ptr = nullptr;
  }

  WindowsFileMapper() {
    this->hFile = nullptr;
    this->hMap = nullptr;
    this->addr = nullptr;
    this->file_ptr = nullptr;
  }

  WindowsFileMapper(const std::string &file_path, MapType map_type,
                    std::string &error_msg, uint64_t file_size = 0) {
    LARGE_INTEGER li;
    li.QuadPart = file_size;
    bool is_ok = false;

    if (map_type == MapType::Read) {
      this->hFile = CreateFileW(AMStr::wstr(file_path).c_str(), GENERIC_READ,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
      if (this->hFile == INVALID_HANDLE_VALUE) {
        goto DONE;
      }

      GetFileSizeEx(this->hFile, &file_size_ptr);
      this->file_size = file_size_ptr.QuadPart;
      this->hMap =
          CreateFileMapping(this->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
      if (!this->hMap) {
        goto DONE;
      }
      this->addr = MapViewOfFile(this->hMap, FILE_MAP_READ, 0, 0, 0);
      if (!this->addr) {
        goto DONE;
      }
      this->file_ptr = (char *)this->addr;
      is_ok = true;
      goto DONE;
    }

    this->hFile = CreateFileW(AMStr::wstr(file_path).c_str(),
                              GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (this->hFile == INVALID_HANDLE_VALUE) {
      goto DONE;
    }

    if (!SetFilePointerEx(this->hFile, li, NULL, FILE_BEGIN)) {
      goto DONE;
    }

    if (!SetEndOfFile(this->hFile)) {
      goto DONE;
    }
    this->hMap = CreateFileMapping(this->hFile, NULL, PAGE_READWRITE,
                                   li.HighPart, li.LowPart, NULL);

    if (!this->hMap) {
      goto DONE;
    }
    this->addr = MapViewOfFile(this->hMap, FILE_MAP_WRITE, 0, 0, 0);

    if (!this->addr) {
      goto DONE;
    }
    this->file_ptr = (char *)this->addr;
    is_ok = true;
  DONE:
    if (!is_ok) {
      DWORD err = GetLastError();
      LPSTR errMsg = nullptr;
      FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                         FORMAT_MESSAGE_FROM_SYSTEM,
                     NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     (LPSTR)&errMsg, 0, NULL);
      error_msg = errMsg;
      LocalFree(errMsg);
      this->file_ptr = nullptr;
      return;
    }
  }
};
#else
class UnixFileMapper : public BaseFileMapper {
private:
  int fd;                // 文件描述符
  void *addr;            // 映射内存地址
  struct stat file_stat; // 文件状态信息

public:
  ~UnixFileMapper() {
    // 解除内存映射
    if (addr != MAP_FAILED && addr != nullptr) {
      munmap(addr, file_size);
    }

    // 关闭文件描述符
    if (fd != -1) {
      close(fd);
    }

    file_ptr = nullptr;
  }

  UnixFileMapper() : fd(-1), addr(nullptr), file_ptr(nullptr), file_size(0) {}

  UnixFileMapper(const std::string &file_path, MapType map_type,
                 std::string &error_msg, uint64_t file_size = 0)
      : fd(-1), addr(nullptr), file_ptr(nullptr), file_size(0) {
    bool is_ok = false;
    int open_flags = 0;
    int prot_flags = 0;
    int map_flags = MAP_SHARED;

    try {
      if (map_type == MapType::Read) {
        // 只读模式
        open_flags = O_RDONLY;
        prot_flags = PROT_READ;

        // 打开文件
        fd = open(file_path.c_str(), open_flags);
        if (fd == -1) {
          throw std::string("Failed to open file: ") + strerror(errno);
        }

        // 获取文件大小
        if (fstat(fd, &file_stat) == -1) {
          throw std::string("Failed to get file status: ") + strerror(errno);
        }
        this->file_size = file_stat.st_size;

        // 映射文件到内存
        addr = mmap(nullptr, this->file_size, prot_flags, map_flags, fd, 0);
        if (addr == MAP_FAILED) {
          throw std::string("Failed to map file to memory: ") +
strerror(errno);
        }

        file_ptr = static_cast<char *>(addr);
        is_ok = true;
      } else {
        // 写入模式
        open_flags = O_RDWR | O_CREAT | O_TRUNC; // 创建并截断文件
        prot_flags = PROT_READ | PROT_WRITE;
        mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // 权限: 644

        // 打开文件
        fd = open(file_path.c_str(), open_flags, file_mode);
        if (fd == -1) {
          throw std::string("Failed to create/open file: ") + strerror(errno);
        }

        // 设置文件大小
        this->file_size = file_size;
        if (ftruncate(fd, this->file_size) == -1) {
          throw std::string("Failed to set file size: ") + strerror(errno);
        }

        // 映射文件到内存
        addr = mmap(nullptr, this->file_size, prot_flags, map_flags, fd, 0);
        if (addr == MAP_FAILED) {
          throw std::string("Failed to map file to memory: ") +
strerror(errno);
        }

        file_ptr = static_cast<char *>(addr);
        is_ok = true;
      }
    } catch (const std::string &err) {
      error_msg = err;

      // 清理已分配的资源
      if (addr != MAP_FAILED && addr != nullptr) {
        munmap(addr, file_size);
        addr = nullptr;
      }
      if (fd != -1) {
        close(fd);
        fd = -1;
      }
      file_ptr = nullptr;
      file_size = 0;
    }
  }

  // 同步内存映射到文件
  bool sync() {
    if (addr == nullptr || addr == MAP_FAILED || file_size == 0) {
      return false;
    }
    return msync(addr, file_size, MS_SYNC) == 0;
  }
};
#endif

class FileMapper {
private:
  std::shared_ptr<BaseFileMapper> ori_mapper;

public:
  char *file_ptr;     // 映射文件数据指针
  uint64_t file_size; // 文件大小
  FileMapper() : file_ptr(nullptr), file_size(0) {}
  FileMapper(const std::string &file_path, MapType map_type,
             std::string &error_msg, uint64_t file_size = 0) {
#ifdef _WIN32
    this->ori_mapper = std::make_shared<WindowsFileMapper>(
        file_path, map_type, error_msg, file_size);
    this->file_ptr = this->ori_mapper->file_ptr;
    this->file_size = this->ori_mapper->file_size;
#else
    this->ori_mapper = std::make_shared<UnixFileMapper>(file_path, map_type,
                                                        error_msg, file_size);
    this->file_ptr = unix_mapper->file_ptr;
    this->file_size = unix_mapper->file_size;
#endif
  }
  // 禁止拷贝构造和赋值
  FileMapper(const FileMapper &) = delete;
  FileMapper &operator=(const FileMapper &) = delete;
};

struct SingleBuffer {
  std::shared_ptr<char[]> bufferptr_origin;
  char *bufferptr = nullptr;
  BufferStatus status = BufferStatus::write_done;
  uint64_t written = 0;
  uint64_t read = 0;
  uint64_t write_order = 0;
  uint64_t read_order = 0;
  SingleBuffer() {}
  SingleBuffer(size_t buffer_size)
      : bufferptr_origin(new char[buffer_size],
std::default_delete<char[]>()), bufferptr(bufferptr_origin.get()) {}
};

struct TransferContext {
  std::unordered_map<int, SingleBuffer> bufferd;
  TransferContext(size_t buffer_size) {
    bufferd[0] = SingleBuffer(buffer_size);
    bufferd[1] = SingleBuffer(buffer_size);
  }

  int get_write_buffer() {
    if (bufferd[0].status == BufferStatus::is_writing) {
      return 0;
    } else if (bufferd[1].status == BufferStatus::is_writing) {
      return 1;
    } else if (bufferd[0].status == BufferStatus::read_done) {
      if (bufferd[1].status == BufferStatus::read_done &&
          bufferd[0].read_order > bufferd[1].read_order) {
        bufferd[1].status = BufferStatus::is_writing;
        return 1;
      } else {
        bufferd[0].status = BufferStatus::is_writing;
        return 0;
      }
    }

    else if (bufferd[1].status == BufferStatus::read_done) {
      bufferd[1].status = BufferStatus::is_writing;
      return 1;
    } else {
      return -1;
    }
  }

  int get_read_buffer() {
    if (bufferd[0].status == BufferStatus::is_reading) {
      return 0;
    } else if (bufferd[1].status == BufferStatus::is_reading) {
      return 1;
    } else if (bufferd[0].status == BufferStatus::write_done) {
      if (bufferd[1].status == BufferStatus::write_done &&
          bufferd[0].write_order > bufferd[1].write_order) {
        bufferd[1].status = BufferStatus::is_reading;
        return 1;
      } else {
        bufferd[0].status = BufferStatus::is_reading;
        return 0;
      }
    } else if (bufferd[1].status == BufferStatus::write_done) {
      bufferd[1].status = BufferStatus::is_reading;
      return 1;
    } else {
      return -1;
    }
  }

  void finish_write(int buffer_name, uint64_t order) {
    bufferd[buffer_name].status = BufferStatus::write_done;
    bufferd[buffer_name].written = 0;
    bufferd[buffer_name].read = 0;
    bufferd[buffer_name].write_order = order;
  }

  void finish_read(int buffer_name, uint64_t order) {
    bufferd[buffer_name].status = BufferStatus::read_done;
    bufferd[buffer_name].written = 0;
    bufferd[buffer_name].read_order = order;
  }
};

class CircularBuffer {
private:
  std::vector<TraceInfo> buffer = {};
  size_t capacity = 10;

public:
  CircularBuffer() {}

  CircularBuffer(unsigned int buffer_capacity) {
    if (buffer_capacity <= 0) {
      capacity = 10;
    } else {
      capacity = buffer_capacity;
    }
  }

  void push(const TraceInfo value) {
    if (buffer.size() < capacity) {
      buffer.push_back(value);
    } else {
      buffer.erase(buffer.begin());
      buffer.push_back(value);
    }
  }

  size_t GetTracerSize() const { return buffer.size(); }

  size_t GetTracerCapacity() const { return capacity; }

  std::optional<TraceInfo> LastTraceError() {
    if (buffer.empty()) {
      return std::nullopt;
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
};
*/
