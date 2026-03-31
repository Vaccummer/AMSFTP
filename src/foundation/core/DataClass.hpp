#pragma once
// standard library
#include <algorithm>
#include <csignal>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>
#include <utility>

// project header
#include "foundation/core/Enum.hpp"

// 3rd party library
#include <libssh2.h>
#include <libssh2_sftp.h>

template <typename T> using sptr = std::shared_ptr<T>;

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

template <typename Key, typename Value>
using OrderDict = std::vector<std::pair<Key, Value>>;

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
ECM CallCallbackSafe(const Fn &fn, Args &&...args) {
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
std::pair<Ret, ECM> CallCallbackSafeRet(const Fn &fn, Args &&...args) {
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

template <class T> class AMAtomic {
public:
  using value_type = T;
  using mutex_type = std::mutex;

  AMAtomic() = default;

  template <class... Args,
            class = std::enable_if_t<std::is_constructible_v<T, Args...>>>
  explicit AMAtomic(Args &&...args) : value_(std::forward<Args>(args)...) {}

  AMAtomic(const AMAtomic &) = delete;
  AMAtomic &operator=(const AMAtomic &) = delete;
  AMAtomic(AMAtomic &&) = delete;
  AMAtomic &operator=(AMAtomic &&) = delete;

  class Guard {
  public:
    Guard(T &value, mutex_type &mutex) : value_(value), lock_(mutex) {}

    Guard(const Guard &) = delete;
    Guard &operator=(const Guard &) = delete;
    Guard(Guard &&) noexcept = default;
    Guard &operator=(Guard &&) noexcept = default;
    ~Guard() = default;

    T *operator->() noexcept { return &value_; }

    const T *operator->() const noexcept { return &value_; }

    T &operator*() & noexcept { return value_; }

    const T &operator*() const & noexcept { return value_; }

    T &operator*() && = delete;
    const T &operator*() const && = delete;

    T &get() & noexcept { return value_; }

    const T &get() const & noexcept { return value_; }

    T &get() && = delete;
    const T &get() const && = delete;

    bool owns_lock() const noexcept { return lock_.owns_lock(); }

    void lock() { lock_.lock(); }

    void unlock() { lock_.unlock(); }

    T load() const { return value_; }

    void store(const T &value) { value_ = value; }

    void store(T &&value) { value_ = std::move(value); }

  private:
    T &value_;
    std::unique_lock<mutex_type> lock_;
  };

  [[nodiscard]] Guard lock() { return Guard(value_, mutex_); }

private:
  mutex_type mutex_;
  T value_{};
};

// TaskControlToken is removed. Use AMDomain::client::IClientControlToken.
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
  [[nodiscard]] bool is_dir() const { return type == PathType::DIR; }
  [[nodiscard]] bool is_file() const { return type != PathType::DIR; }
  [[nodiscard]] bool is_symlink() const { return type == PathType::SYMLINK; }
  [[nodiscard]] bool is_special() const {
    return type != PathType::DIR && type != PathType::FILE;
  }
  [[nodiscard]] bool is_regular() const { return type == PathType::FILE; }
};

class NonCopyable {
public:
  NonCopyable() = default;
  NonCopyable(const NonCopyable &) = delete;
  NonCopyable &operator=(const NonCopyable &) = delete;
  virtual ~NonCopyable() = default;
};

class NonMovable {
public:
  NonMovable() = default;
  NonMovable(NonMovable &&) = delete;
  NonMovable &operator=(NonMovable &&) = delete;
  virtual ~NonMovable() = default;
};

class NonCopyableNonMovable : NonCopyable, NonMovable {
public:
  ~NonCopyableNonMovable() override = default;
  NonCopyableNonMovable() = default;
};

struct ECMResult {
  ECMResult() = default;
  ECMResult(ECM result) : rcm(std::move(result)) {}

  /**
   * @brief Result status code and detail message.
   */
  ECM rcm = {EC::Success, ""};

  /**
   * @brief Return true when status is success.
   */
  [[nodiscard]] bool ok() const { return rcm.first == EC::Success; }

  operator bool() const { return ok(); }
  operator ECM() const { return rcm; }
};

template <typename T> struct ECMData : ECMResult {
  ECMData() = default;
  ECMData(T data, ECM result = {EC::Success, ""})
      : ECMResult(std::move(result)), data(std::move(data)) {}
  T data;
};
