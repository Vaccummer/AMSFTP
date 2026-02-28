#pragma once
// standard library
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// project header
#include "AMBase/Enum.hpp"

// 3rd party library
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>

struct TransferTask;    // Forward declaration
class TaskControlToken; // Forward declaration

using EC = ErrorCode;
using result_map = std::unordered_map<std::string, ErrorCode>;
using ECM = std::pair<EC, std::string>;
using TASKS = std::vector<TransferTask>;
using amf = std::shared_ptr<TaskControlToken>;
namespace fs = std::filesystem;

template <typename T> struct NBResult {
  T value;           // Function return value
  WaitResult status; // Wait state

  [[nodiscard]] bool ok() const { return status == WaitResult::Ready; }
  [[nodiscard]] bool is_timeout() const {
    return status == WaitResult::Timeout;
  }
  [[nodiscard]] bool is_interrupted() const {
    return status == WaitResult::Interrupted;
  }
  [[nodiscard]] bool is_error() const { return status == WaitResult::Error; }
};

struct AMTokenSpan {
  size_t start = 0;
  size_t end = 0;
  AMTokenType type = AMTokenType::Common;
};

enum class ControlSignal : int {
  Running = 0,
  Pause = 1,
  Interrupt = SIGINT,
#ifdef SIGTERM
  Kill = SIGTERM,
#else
  Kill = SIGINT + 1,
#endif
};

enum class TaskControlSignal : int {
  SigInt = SIGINT,
#ifdef SIGTERM
  SigTerm = SIGTERM,
#endif
};

template <typename Fn, typename... Args>
inline ECM CallCallbackSafe(const Fn &fn, Args &&...args) {
  if (!fn) {
    return {};
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

inline double timenow() {
  // Get Unix reference time and return it as seconds in double
  return std::chrono::duration<double>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
  return std::chrono::duration<double>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// Get milliseconds from steady_clock epoch to now (integer)
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
inline std::string FormatTime(const size_t &time,
                              const std::string &format = "%Y-%m-%d %H:%M:%S") {
  auto timeT = static_cast<time_t>(time);

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

/**
 * @brief Format a unix timestamp as "HH:MM".
 */
inline std::string FormatTimeHM(double timestamp) {
  if (timestamp <= 0.0) {
    return "-";
  }
  return FormatTime(static_cast<size_t>(timestamp), "%H:%M");
}

inline bool isok(const ECM &ecm) { return ecm.first == EC::Success; }

/** @brief Return a success ECM. */
inline ECM Ok() {
  const static ECM ok_instance{EC::Success, ""};
  return ok_instance;
}

/** @brief Build an error ECM with message. */
inline ECM Err(EC code, const std::string &msg) { return {code, msg}; }

inline PathType cast_fs_type(const fs::file_type &type) {
  switch (type) {
  case fs::file_type::directory:
    return PathType::DIR;
  case fs::file_type::symlink:
    return PathType::SYMLINK;
  case fs::file_type::regular:
    return PathType::FILE;
  case fs::file_type::block:
    return PathType::BlockDevice;
  case fs::file_type::character:
    return PathType::CharacterDevice;
  case fs::file_type::fifo:
    return PathType::FIFO;
  case fs::file_type::socket:
    return PathType::Socket;
  case fs::file_type::unknown:
    return PathType::Unknown;
  default:
    return PathType::Unknown;
  }
}

// turn std::error_code to ErrorCode
inline EC fec(const std::error_code &ec) {
  if (!ec)
    return EC::Success;
  // Use std::errc for cross-platform mapping
  auto errc = static_cast<std::errc>(ec.value());

  switch (errc) {
  case std::errc::no_such_file_or_directory:
    return EC::FileNotExist;
  case std::errc::permission_denied:
    return EC::PermissionDenied;
  case std::errc::file_exists:
    return EC::PathAlreadyExists;
  case std::errc::not_a_directory:
    return EC::NotADirectory;
  case std::errc::is_a_directory:
    return EC::NotAFile;
  case std::errc::directory_not_empty:
    return EC::DirNotEmpty;
  case std::errc::no_space_on_device:
    return EC::FilesystemNoSpace;
  case std::errc::read_only_file_system:
    return EC::FileWriteProtected;
  case std::errc::too_many_symbolic_link_levels:
    return EC::SymlinkLoop;
  case std::errc::filename_too_long:
    return EC::InvalidFilename;
  case std::errc::invalid_argument:
    return EC::InvalidArg;
  case std::errc::io_error:
    return EC::LocalFileError;
  case std::errc::not_supported:
  case std::errc::operation_not_supported:
    return EC::OperationUnsupported;
  case std::errc::timed_out:
    return EC::OperationTimeout;
  case std::errc::connection_refused:
  case std::errc::network_unreachable:
  case std::errc::host_unreachable:
    return EC::NoConnection;
  case std::errc::connection_reset:
    return EC::ConnectionLost;
  default:
    return EC::UnknownError;
  }
}

// Custom std::error_code to ECM
inline ECM fecm(const std::error_code &ec) {
  if (!ec)
    return {EC::Success, ""};
  return {fec(ec), ec.message()};
}

/**
 * @brief Unified task control token for async transfer pause/terminate flow.
 */
class TaskControlToken {
public:
  using HookFunc =
      std::function<void(ControlSignal, std::optional<TaskControlSignal>)>;

  /**
   * @brief Lightweight hook metadata returned by temporary hook guards.
   */
  struct HookInfo {
    size_t id = 0;
    ControlSignal threshold = ControlSignal::Running;
    int priority = 0;
  };

  /**
   * @brief RAII guard for temporary hook registration.
   *
   * When the guard is destroyed, the associated hook is automatically
   * unregistered.
   */
  class TmpHookMutex {
  public:
    TmpHookMutex() = default;

    /**
     * @brief Construct a guard for one registered hook.
     */
    TmpHookMutex(TaskControlToken *owner, const HookInfo &info)
        : owner_(owner), info_(info) {}

    TmpHookMutex(const TmpHookMutex &) = delete;
    TmpHookMutex &operator=(const TmpHookMutex &) = delete;

    /**
     * @brief Move constructor; transfers ownership of hook registration.
     */
    TmpHookMutex(TmpHookMutex &&other) noexcept
        : owner_(other.owner_), info_(other.info_) {
      other.owner_ = nullptr;
      other.info_.id = 0;
    }

    /**
     * @brief Move assignment; releases current hook then adopts source hook.
     */
    TmpHookMutex &operator=(TmpHookMutex &&other) noexcept {
      if (this == &other) {
        return *this;
      }
      unlock();
      owner_ = other.owner_;
      info_ = other.info_;
      other.owner_ = nullptr;
      other.info_.id = 0;
      return *this;
    }

    /**
     * @brief Destructor that unregisters the guarded hook.
     */
    ~TmpHookMutex() { unlock(); }

    /**
     * @brief Explicitly unregister the guarded hook.
     */
    void unlock() {
      if (owner_ && info_.id != 0) {
        (void)owner_->UnregisterHook(info_.id);
        owner_ = nullptr;
        info_.id = 0;
      }
    }

    /**
     * @brief Return true if this guard currently owns a valid hook.
     */
    [[nodiscard]] bool owns_lock() const {
      return owner_ != nullptr && info_.id != 0;
    }

    /**
     * @brief Return hook metadata tracked by this guard.
     */
    [[nodiscard]] HookInfo info() const { return info_; }

  private:
    TaskControlToken *owner_ = nullptr;
    HookInfo info_ = {};
  };

private:
  struct HookEntry {
    HookFunc func;
    ControlSignal threshold = ControlSignal::Running;
    int priority = 0;
    size_t id = 0;
  };

  std::atomic<int> signal_{static_cast<int>(ControlSignal::Running)};
  std::atomic<size_t> wake_token_seed_{1};
  std::mutex wake_cb_mtx_;
  std::unordered_map<size_t, std::function<void()>> wake_callbacks_;
  std::atomic<size_t> hook_seed_{1};
  std::mutex hooks_mtx_;
  std::unordered_map<size_t, HookEntry> hooks_;

  /**
   * @brief Notify all registered wake-up callbacks.
   */
  inline void NotifyWakeCallbacks_() {
    std::vector<std::function<void()>> callbacks;
    {
      std::lock_guard<std::mutex> lock(wake_cb_mtx_);
      callbacks.reserve(wake_callbacks_.size());
      for (const auto &[_, cb] : wake_callbacks_) {
        if (cb) {
          callbacks.push_back(cb);
        }
      }
    }
    for (auto &cb : callbacks) {
      cb();
    }
  }

  /**
   * @brief Convert a raw state value into optional task signal metadata.
   */
  static std::optional<TaskControlSignal> CastSignal_(int signal_value) {
    if (signal_value == static_cast<int>(ControlSignal::Interrupt)) {
      return TaskControlSignal::SigInt;
    }
#ifdef SIGTERM
    if (signal_value == static_cast<int>(ControlSignal::Kill)) {
      return TaskControlSignal::SigTerm;
    }
#endif
    return std::nullopt;
  }

  /**
   * @brief Trigger hooks whose threshold is met by the new state.
   */
  void TriggerHooks_(ControlSignal new_state) {
    std::vector<HookEntry> pending;
    {
      std::lock_guard<std::mutex> lock(hooks_mtx_);
      pending.reserve(hooks_.size());
      for (const auto &[_, hook] : hooks_) {
        if (static_cast<int>(new_state) >= static_cast<int>(hook.threshold)) {
          pending.push_back(hook);
        }
      }
    }

    std::sort(pending.begin(), pending.end(),
              [](const HookEntry &a, const HookEntry &b) {
                const int a_level = static_cast<int>(a.threshold);
                const int b_level = static_cast<int>(b.threshold);
                if (a_level != b_level) {
                  return a_level > b_level;
                }
                if (a.priority != b.priority) {
                  return a.priority > b.priority;
                }
                return a.id < b.id;
              });

    const auto current_signal =
        CastSignal_(signal_.load(std::memory_order_acquire));
    for (auto &hook : pending) {
      (void)CallCallbackSafe(hook.func, new_state, current_signal);
    }
  }

public:
  TaskControlToken() = default;

  /**
   * @brief Request pause state for async transfer execution.
   */
  bool Pause() {
    if (!IsRunning()) {
      return false;
    }
    return SetStatus(ControlSignal::Pause);
  }

  /**
   * @brief Set current control status.
   *
   * @param status Target control status.
   * @return True if status changed.
   */
  bool SetStatus(ControlSignal status) {
    const int target = static_cast<int>(status);
    const int current = signal_.exchange(target, std::memory_order_acq_rel);
    if (current == target) {
      return false;
    }
    if (status != ControlSignal::Running) {
      NotifyWakeCallbacks_();
      TriggerHooks_(status);
    }
    return true;
  }

  /**
   * @brief Request terminate state with an optional source signal.
   */
  bool Terminate(std::optional<TaskControlSignal> signal = std::nullopt) {
    if (signal.has_value()) {
      if (*signal == TaskControlSignal::SigInt) {
        return SetStatus(ControlSignal::Interrupt);
      }
#ifdef SIGTERM
      if (*signal == TaskControlSignal::SigTerm) {
        return SetStatus(ControlSignal::Kill);
      }
#endif
    }
    return SetStatus(ControlSignal::Interrupt);
  }

  /**
   * @brief Return current control status.
   */
  [[nodiscard]] ControlSignal GetStatus() const {
    const int current = signal_.load(std::memory_order_acquire);
    switch (current) {
    case static_cast<int>(ControlSignal::Running):
      return ControlSignal::Running;
    case static_cast<int>(ControlSignal::Pause):
      return ControlSignal::Pause;
    case static_cast<int>(ControlSignal::Interrupt):
      return ControlSignal::Interrupt;
    case static_cast<int>(ControlSignal::Kill):
      return ControlSignal::Kill;
    default:
      return ControlSignal::Running;
    }
  }

  /**
   * @brief Return true when token control state is running.
   */
  [[nodiscard]] bool IsRunning() const {
    return signal_.load(std::memory_order_acquire) ==
           static_cast<int>(ControlSignal::Running);
  }

  /**
   * @brief Return true when token state is killed.
   */
  [[nodiscard]] bool IsKill() const {
    return GetStatus() == ControlSignal::Kill;
  }

  /**
   * @brief Reset state and signal back to running/no-signal.
   */
  bool Reset() {
    return SetStatus(ControlSignal::Running);
  }

  /**
   * @brief Force killed termination.
   */
  bool Kill(std::optional<TaskControlSignal> signal = std::nullopt) {
    if (signal.has_value() && *signal == TaskControlSignal::SigInt) {
      return SetStatus(ControlSignal::Interrupt);
    }
    return SetStatus(ControlSignal::Kill);
  }

  /**
   * @brief Register one state hook with threshold and priority.
   *
   * @return Unique hook id; 0 means invalid callback.
   */
  size_t RegisterHook(HookFunc func,
                      ControlSignal threshold = ControlSignal::Running,
                      int priority = 0) {
    if (!func) {
      return 0;
    }
    const size_t id = hook_seed_.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(hooks_mtx_);
    hooks_[id] = HookEntry{std::move(func), threshold, priority, id};
    return id;
  }

  /**
   * @brief Unregister hook by unique id.
   */
  bool UnregisterHook(size_t id) {
    if (id == 0) {
      return false;
    }
    std::lock_guard<std::mutex> lock(hooks_mtx_);
    return hooks_.erase(id) > 0;
  }

  /**
   * @brief Register a temporary hook with RAII-based auto-unregister.
   */
  TmpHookMutex TmpHook(HookFunc func,
                       ControlSignal threshold = ControlSignal::Running,
                       int priority = 0) {
    const size_t id = RegisterHook(std::move(func), threshold, priority);
    return TmpHookMutex(this, HookInfo{id, threshold, priority});
  }

  /**
   * @brief Register a callback used to wake blocking waiters when interrupted.
   *
   * @param wake_cb Wake callback to invoke on interrupt.
   * @return Callback token for unregister.
   */
  inline size_t RegisterWakeup(std::function<void()> wake_cb) {
    if (!wake_cb) {
      return 0;
    }
    size_t token = wake_token_seed_.fetch_add(1, std::memory_order_relaxed);
    {
      std::lock_guard<std::mutex> lock(wake_cb_mtx_);
      wake_callbacks_[token] = std::move(wake_cb);
    }
    if (!IsRunning()) {
      std::function<void()> cb;
      {
        std::lock_guard<std::mutex> lock(wake_cb_mtx_);
        auto it = wake_callbacks_.find(token);
        if (it != wake_callbacks_.end()) {
          cb = it->second;
        }
      }
      if (cb) {
        cb();
      }
    }
    return token;
  }

  /**
   * @brief Remove a previously registered wake callback.
   *
   * @param token Token from RegisterWakeup.
   */
  inline void UnregisterWakeup(size_t token) {
    if (token == 0) {
      return;
    }
    std::lock_guard<std::mutex> lock(wake_cb_mtx_);
    wake_callbacks_.erase(token);
  }
};

inline std::shared_ptr<TaskControlToken> amgif =
    std::make_shared<TaskControlToken>();

class PathInfo {
public:
  std::string name;
  std::string path;
  std::string dir;
  std::string owner;
  size_t size = 0;
  double create_time = 0;
  double access_time = 0;
  double modify_time = 0;
  PathType type = PathType::FILE;
  size_t mode_int = 00;
  std::string mode_str = "r--------";
  PathInfo() : name(""), path(""), dir(""), owner(""), mode_int(0) {}

  PathInfo(std::string name, std::string path, std::string dir,
           std::string owner, size_t size, double create_time,
           double access_time, double modify_time, PathType type,
           size_t mode_int, std::string mode_str)
      : name(std::move(name)), path(std::move(path)), dir(std::move(dir)),
        owner(std::move(owner)), size(std::move(size)),
        create_time(std::move(create_time)),
        access_time(std::move(access_time)),
        modify_time(std::move(modify_time)), type(std::move(type)),
        mode_int(std::move(mode_int)), mode_str(std::move(mode_str)) {}
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
  [[nodiscard]] bool IsValid() const {
    return !nickname.empty() && !hostname.empty() && !username.empty() &&
           port > 0 && port <= 65535;
  }
};

/** @brief Canonical alias of the connection request type used by tracing. */
using ConRequest = ConRequst;

struct ProgressCBInfo {
  std::string src;
  std::string dst;
  std::string src_host;
  std::string dst_host;
  size_t this_size;
  size_t file_size;
  size_t accumulated_size;
  size_t total_size;
  ProgressCBInfo(const std::string &src, const std::string &dst,
                 const std::string &src_host, const std::string &dst_host,
                 size_t this_size, size_t file_size,
                 const size_t &accumulated_size, const size_t &total_size)
      : src(src), dst(dst), src_host(src_host), dst_host(dst_host),
        this_size(this_size), file_size(file_size),
        accumulated_size(accumulated_size), total_size(total_size) {}
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
   * @brief Whether to resume from an existing destination breakpoint.
   */
  bool resume = false;

  /**
   * @brief Construct an empty transfer set with default flags.
   */
  UserTransferSet() = default;

  /**
   * @brief Construct a transfer set from sources, destination, and flags.
   */
  UserTransferSet(std::vector<std::string> srcs, std::string dst, bool mkdir,
                  bool overwrite, bool ignore_special_file, bool resume = false)
      : srcs(std::move(srcs)), dst(std::move(dst)), mkdir(mkdir),
        overwrite(overwrite), ignore_special_file(ignore_special_file),
        resume(resume) {}
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
  TraceSource source = TraceSource::Client;
  TraceLevel level;
  ErrorCode error_code;
  std::string nickname;
  std::string target;
  std::string action;
  std::string message;
  std::optional<ConRequest> request = std::nullopt;
  double timestamp;

  TraceInfo()
      : level(TraceLevel::Info), error_code(EC::Success), nickname(""),
        target(""), action(""), message(""), request(std::nullopt),
        timestamp(timenow()) {}
  TraceInfo(TraceLevel level, ErrorCode error_code, std::string nickname,
            std::string target, std::string action, std::string message,
            std::optional<ConRequest> request = std::nullopt,
            TraceSource source = TraceSource::Client)
      : source(source), level(std::move(level)),
        error_code(std::move(error_code)), nickname(std::move(nickname)),
        target(std::move(target)), action(std::move(action)),
        message(std::move(message)), request(std::move(request)),
        timestamp(timenow()) {}
};

struct TransferCallback {
  using ErrorCallback = std::function<void(const ErrorCBInfo &)>;
  using ProgressCallback =
      std::function<std::optional<TransferControl>(const ProgressCBInfo &)>;
  using TotalSizeCallback = std::function<void(size_t)>;

  bool need_error_cb = false;
  bool need_progress_cb = false;
  bool need_total_size_cb = false;
  ErrorCallback error_cb = {}; // void(ErrorCBInfo)
  ProgressCallback progress_cb =
      {}; // optional<TransferControl>(ProgressCBInfo)
  TotalSizeCallback total_size_cb = {}; // void(size_t)
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

  ECM CallTotalSize(size_t total_size) const {
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
  size_t size;
  PathType path_type = PathType::FILE;
  bool IsFinished = false;
  ECM rcm = ECM(EC::Success, "");
  size_t transferred = 0; // Current file transferred size
  TransferTask() : src(""), src_host(""), dst(""), dst_host(""), size(0) {}
  TransferTask(std::string src, std::string dst, std::string src_host,
               std::string dst_host, size_t size,
               PathType path_type = PathType::FILE)
      : src(std::move(src)), src_host(std::move(src_host)), dst(std::move(dst)),
        dst_host(std::move(dst_host)), size(size), path_type(path_type) {}
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
  std::atomic<size_t> head_{0}; // Consumer read position
  std::atomic<size_t> tail_{0}; // Producer write position

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
    // Contiguous writable = min(distance to end, free space)
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
    // Contiguous readable = min(distance to end, available data)
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

struct TaskInfo; // Forward declaration
                 //

class ClientMaintainer; // Forward declaration
// New ProgressData that holds weak_ptr to TaskInfo to avoid cycle reference
// Reads/writes directly on TaskInfo for progress tracking

class WkProgressData;

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
   * @brief Mutex/condition variable pair for waiting on status transitions.
   */
  mutable std::mutex status_wait_mtx;
  mutable std::condition_variable status_cv;

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
   * @brief Preserve start_time when resuming from pause.
   */
  std::atomic<bool> keep_start_time{false};

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
  std::atomic<size_t> total_transferred_size{0};

  /**
   * @brief Progress tracking: total bytes planned.
   */
  std::atomic<size_t> total_size{0};

  /**
   * @brief Total number of files in this task.
   */
  std::atomic<size_t> filenum{0};

  /**
   * @brief Number of successfully transferred files.
   */
  std::atomic<size_t> success_filenum{0};

  /**
   * @brief Progress tracking: transferred bytes for the current task.
   */
  std::atomic<size_t> this_task_transferred_size{0};

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
   * @brief Guard to ensure completion dispatch/callback runs only once.
   */
  std::atomic<bool> completion_dispatched{false};

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
  std::shared_ptr<ClientMaintainer> hostm;

  /**
   * @brief Cached client nicknames for display and resume.
   */
  std::vector<std::string> nicknames;

  /**
   * @brief Requested ring buffer size.
   */
  std::atomic<ssize_t> buffer_size{-1};

  /**
   * @brief Shared progress data for control signals.
   */
  std::shared_ptr<WkProgressData> pd;

  /**
   * @brief Unified control token for this task.
   */
  amf control_token = nullptr;

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
  void SetStatus(TaskStatus new_status) {
    status.store(new_status, std::memory_order_release);
    status_cv.notify_all();
  }

  /**
   * @brief Safely read the task status.
   */
  TaskStatus GetStatus() const {
    return status.load(std::memory_order_acquire);
  }

  /**
   * @brief Wait until the task reaches Finished status.
   *
   * @param timeout_ms Timeout in milliseconds. Negative waits forever.
   * @return True if task is finished before timeout, otherwise false.
   */
  bool WaitFinished(int timeout_ms = -1) const {
    if (GetStatus() == TaskStatus::Finished) {
      return true;
    }
    std::unique_lock<std::mutex> lock(status_wait_mtx);
    if (timeout_ms < 0) {
      status_cv.wait(lock,
                     [this]() { return GetStatus() == TaskStatus::Finished; });
      return true;
    }
    return status_cv.wait_for(
        lock, std::chrono::milliseconds(timeout_ms),
        [this]() { return GetStatus() == TaskStatus::Finished; });
  }

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

  /**
   * @brief Calculate and update total size from tasks when needed.
   *
   * @param force Recalculate even if total_size is already set.
   * @return Updated total size.
   */
  size_t CalTotalSize(bool force = false) {
    const size_t current = total_size.load(std::memory_order_relaxed);
    if (!force && current != 0) {
      return current;
    }
    std::shared_ptr<TASKS> local_tasks;
    {
      std::lock_guard<std::mutex> lock(mtx);
      local_tasks = tasks;
    }
    if (!local_tasks) {
      return current;
    }
    size_t sum = 0;
    for (const auto &task : *local_tasks) {
      sum += task.size;
    }
    total_size.store(sum, std::memory_order_relaxed);
    return sum;
  }

  /**
   * @brief Calculate and update file count from tasks when needed.
   *
   * @param force Recalculate even if filenum is already set.
   * @return Updated file count.
   */
  size_t CalFileNum(bool force = false) {
    const size_t current = filenum.load(std::memory_order_relaxed);
    if (!force && current != 0) {
      return current;
    }
    std::shared_ptr<TASKS> local_tasks;
    {
      std::lock_guard<std::mutex> lock(mtx);
      local_tasks = tasks;
    }
    if (!local_tasks) {
      return current;
    }
    const size_t count = local_tasks->size();
    filenum.store(count, std::memory_order_relaxed);
    return count;
  }

  void DeleteProgressData() {
    std::lock_guard<std::mutex> lock(mtx);
    this->pd = nullptr;
  }

  /**
   * @brief Mark completion dispatch state and return true only for first call.
   */
  bool TryMarkCompletionDispatched() {
    bool expected = false;
    return completion_dispatched.compare_exchange_strong(
        expected, true, std::memory_order_acq_rel);
  }

  /**
   * @brief Reset completion dispatch state before resubmitting the task.
   */
  void ResetCompletionDispatch() {
    completion_dispatched.store(false, std::memory_order_release);
  }
};

struct WkProgressData {
  std::weak_ptr<TaskInfo> task_info;
  double cb_time = timenow();
  std::shared_ptr<StreamRingBuffer> ring_buffer = nullptr;
  mutable amf interrupt_flag = nullptr;
  std::function<void(bool)> inner_callback = {};

  explicit WkProgressData(std::shared_ptr<TaskInfo> ti) : task_info(ti) {
    if (ti) {
      interrupt_flag = ti->control_token;
    }
  }

private:
  /**
   * @brief Resolve control token from owning TaskInfo.
   */
  amf ResolveInterruptFlag_() const {
    auto ti = task_info.lock();
    if (ti) {
      if (interrupt_flag != ti->control_token) {
        interrupt_flag = ti->control_token;
      }
    }
    return interrupt_flag;
  }

public:
  /**
   * @brief Sync cached interrupt token pointer from owning TaskInfo.
   */
  void SyncInterruptFlagFromTaskInfo() { (void)ResolveInterruptFlag_(); }

  // Control signal helpers
  bool is_terminate() const {
    auto flag = ResolveInterruptFlag_();
    if (!flag) {
      return false;
    }
    return !flag->IsRunning();
  }
  bool is_terminate_only() const {
    auto flag = ResolveInterruptFlag_();
    if (!flag) {
      return false;
    }
    const auto status = flag->GetStatus();
    return status == ControlSignal::Interrupt ||
           status == ControlSignal::Kill;
  }
  bool is_pause_only() const {
    auto flag = ResolveInterruptFlag_();
    if (!flag) {
      return false;
    }
    return flag->GetStatus() == ControlSignal::Pause;
  }
  bool is_pause() const { return is_pause_only(); }
  bool is_running() const {
    auto flag = ResolveInterruptFlag_();
    if (!flag) {
      return true;
    }
    return flag->IsRunning();
  }

  void set_terminate() {
    auto interrupt_flag = ResolveInterruptFlag_();
    if (interrupt_flag) {
      (void)interrupt_flag->SetStatus(ControlSignal::Interrupt);
    }
  }
  void set_pause() {
    auto interrupt_flag = ResolveInterruptFlag_();
    if (interrupt_flag) {
      (void)interrupt_flag->Pause();
    }
  }
  void set_running() {
    auto interrupt_flag = ResolveInterruptFlag_();
    if (interrupt_flag) {
      (void)interrupt_flag->Reset();
    }
  }

  /**
   * @brief Return the interrupt flag used by blocking I/O waits.
   */
  amf GetInterruptFlag() const { return ResolveInterruptFlag_(); }

  /**
   * @brief Translate interrupt to pause/terminate error according to state.
   */
  ECM InterruptECM(
      const std::string &pause_msg = "Task paused by user",
      const std::string &terminate_msg = "Task terminated by user") const {
    if (is_pause_only()) {
      return {EC::TransferPause, pause_msg};
    }
    return {EC::Terminate, terminate_msg};
  }

  void CallInnerCallback(bool force = false) {
    if (inner_callback) {
      inner_callback(force);
    }
  }
};

struct NonCopyableNonMovable {
public:
  NonCopyableNonMovable() = default;
  virtual ~NonCopyableNonMovable() = default;
  NonCopyableNonMovable(const NonCopyableNonMovable &) = delete;
  NonCopyableNonMovable &operator=(const NonCopyableNonMovable &) = delete;
  NonCopyableNonMovable(NonCopyableNonMovable &&) = delete;
  NonCopyableNonMovable &operator=(NonCopyableNonMovable &&) = delete;

  virtual ECM Init() { return {EC::Success, ""}; }
};
