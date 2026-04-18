#pragma once
// standard library
#include <algorithm>
#include <atomic>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// project header
#include "foundation/core/Enum.hpp"
#include "foundation/tools/time.hpp"

// 3rd party library
#include <libssh2.h>
#include <libssh2_sftp.h>
class InterruptControl;
template <typename T> using sptr = std::shared_ptr<T>;
using amf = sptr<InterruptControl>;

template <typename Key, typename Value>
using OrderDict = std::vector<std::pair<Key, Value>>;

template <typename Fn, typename... Args>
ECM CallCallbackSafe(const Fn &fn, Args &&...args) {
  if (!fn) {
    return {};
  }
  try {
    fn(std::forward<Args>(args)...);
    return OK;
  } catch (const std::exception &e) {
    return {EC::PyCBError, "callback.invoke", "<callback>", e.what()};
  } catch (...) {
    return {EC::PyCBError, "callback.invoke", "<callback>",
            "Unknown callback error"};
  }
}

template <typename Ret, typename Fn, typename... Args>
std::pair<Ret, ECM> CallCallbackSafeRet(const Fn &fn, Args &&...args) {
  if (!fn) {
    return {Ret{}, OK};
  }
  try {
    return {fn(std::forward<Args>(args)...), OK};
  } catch (const std::exception &e) {
    return {Ret{}, {EC::PyCBError, "callback.invoke", "<callback>", e.what()}};
  } catch (...) {
    return {Ret{},
            {EC::PyCBError, "callback.invoke", "<callback>",
             "Unknown callback error"}};
  }
}

template <class T> class AMAtomic {
public:
  using value_type = T;
  using mutex_type = std::mutex;

  AMAtomic() = default;

  template <class... Args>
    requires std::constructible_from<T, Args...>
  explicit AMAtomic(Args &&...args) : value_(std::forward<Args>(args)...) {}

  AMAtomic(const AMAtomic &) = delete;
  AMAtomic &operator=(const AMAtomic &) = delete;
  AMAtomic(AMAtomic &&) = delete;
  AMAtomic &operator=(AMAtomic &&) = delete;

  class Guard {
  public:
    Guard(T &value, mutex_type &mutex) : value_(value), lock_(mutex) {}
    Guard(T &value, mutex_type &mutex, std::defer_lock_t)
        : value_(value), lock_(mutex, std::defer_lock) {}

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

    bool try_lock() { return lock_.try_lock(); }

    void unlock() { lock_.unlock(); }

    T load() const { return value_; }

    void store(const T &value) { value_ = value; }

    void store(T &&value) { value_ = std::move(value); }

  private:
    T &value_;
    std::unique_lock<mutex_type> lock_;
  };

  [[nodiscard]] Guard lock() { return Guard(value_, mutex_); }

  [[nodiscard]] std::optional<Guard> try_lock() {
    Guard guard(value_, mutex_, std::defer_lock);
    if (!guard.try_lock()) {
      return std::nullopt;
    }
    return std::optional<Guard>(std::move(guard));
  }

private:
  mutex_type mutex_;
  T value_{};
};

class InterruptControl {
public:
  enum class State : std::uint8_t {
    Running = 0,
    InterruptRequested = 1,
  };

private:
  std::atomic<State> state_{State::Running};
  std::atomic<size_t> grace_period_ms_{0};
  std::atomic<std::chrono::steady_clock::time_point> interrupt_request_clock_{
      std::chrono::steady_clock::time_point{}};
  std::atomic<size_t> wake_seed_{1};
  mutable AMAtomic<std::map<size_t, std::function<void()>>> wakeups_;

  void NotifyWakeups_() {
    std::vector<std::function<void()>> callbacks;
    {
      auto wakeups = wakeups_.lock();
      callbacks.reserve(wakeups->size());
      for (const auto &[_, cb] : *wakeups) {
        if (cb) {
          callbacks.push_back(cb);
        }
      }
    }
    for (auto &cb : callbacks) {
      cb();
    }
  }

public:
  [[nodiscard]] bool IsInterruptRequest() const {
    return state_.load(std::memory_order_acquire) == State::InterruptRequested;
  }

  [[nodiscard]] bool IsInterrupt() const {
    if (!IsInterruptRequest()) {
      return false;
    }
    return AMTime::IntervalMS(
               interrupt_request_clock_.load(std::memory_order_acquire),
               std::chrono::steady_clock::now()) >=
           grace_period_ms_.load(std::memory_order_acquire);
  }

  [[nodiscard]] bool IsInterrupted() const { return IsInterruptRequest(); }

  void RequestInterrupt(size_t grace_period_ms = 0) {
    grace_period_ms_.store(grace_period_ms, std::memory_order_release);
    interrupt_request_clock_.store(std::chrono::steady_clock::now(),
                                   std::memory_order_release);
    const State prev =
        state_.exchange(State::InterruptRequested, std::memory_order_acq_rel);
    if (prev == State::InterruptRequested) {
      return;
    }
    NotifyWakeups_();
  }

  void ClearInterrupt() {
    (void)state_.exchange(State::Running, std::memory_order_acq_rel);
    grace_period_ms_.store(0, std::memory_order_release);
    interrupt_request_clock_.store(std::chrono::steady_clock::time_point{},
                                   std::memory_order_release);
  }

  size_t RegisterWakeup(std::function<void()> wake_cb) {
    if (!wake_cb) {
      return 0;
    }
    const size_t id = wake_seed_.fetch_add(1, std::memory_order_relaxed);
    auto wakeups = wakeups_.lock();
    (*wakeups)[id] = std::move(wake_cb);
    return id;
  }

  bool UnregisterWakeup(size_t token) {
    if (token == 0) {
      return false;
    }
    auto wakeups = wakeups_.lock();
    return wakeups->erase(token) > 0;
  }
};

inline amf CreateInterruptControl() {
  return std::make_shared<InterruptControl>();
};

class InterruptWakeupSafeGuard {
private:
  std::shared_ptr<InterruptControl> control_owner_ = nullptr;
  InterruptControl *control_ = nullptr;
  size_t token_ = 0;

  void Unbind_() {
    if (!control_) {
      control_owner_.reset();
      control_ = nullptr;
      token_ = 0;
      return;
    }
    (void)control_->UnregisterWakeup(token_);
    control_owner_.reset();
    control_ = nullptr;
    token_ = 0;
  }

public:
  InterruptWakeupSafeGuard() = default;

  InterruptWakeupSafeGuard(const std::shared_ptr<InterruptControl> &control,
                           std::function<void()> wake_cb) {
    Bind(control, std::move(wake_cb));
  }

  InterruptWakeupSafeGuard(InterruptControl *control,
                           std::function<void()> wake_cb) {
    Bind(control, std::move(wake_cb));
  }

  InterruptWakeupSafeGuard(const InterruptWakeupSafeGuard &) = delete;
  InterruptWakeupSafeGuard &
  operator=(const InterruptWakeupSafeGuard &) = delete;

  InterruptWakeupSafeGuard(InterruptWakeupSafeGuard &&other) noexcept
      : control_owner_(std::move(other.control_owner_)),
        control_(other.control_), token_(other.token_) {
    other.control_ = nullptr;
    other.token_ = 0;
  }

  InterruptWakeupSafeGuard &
  operator=(InterruptWakeupSafeGuard &&other) noexcept {
    if (this == &other) {
      return *this;
    }
    Unbind_();
    control_owner_ = std::move(other.control_owner_);
    control_ = other.control_;
    token_ = other.token_;
    other.control_ = nullptr;
    other.token_ = 0;
    return *this;
  }

  ~InterruptWakeupSafeGuard() { Unbind_(); }

  bool Bind(const std::shared_ptr<InterruptControl> &control,
            std::function<void()> wake_cb) {
    Unbind_();
    if (!control || !wake_cb) {
      return false;
    }
    const size_t token = control->RegisterWakeup(std::move(wake_cb));
    if (token == 0) {
      return false;
    }
    control_owner_ = control;
    control_ = control.get();
    token_ = token;
    return true;
  }

  bool Bind(InterruptControl *control, std::function<void()> wake_cb) {
    Unbind_();
    if (!control || !wake_cb) {
      return false;
    }
    const size_t token = control->RegisterWakeup(std::move(wake_cb));
    if (token == 0) {
      return false;
    }
    control_ = control;
    token_ = token;
    return true;
  }

  void Reset() { Unbind_(); }

  [[nodiscard]] bool Bound() const {
    return control_ != nullptr && token_ != 0;
  }
};

namespace AMDomain::client {
using InterruptWakeupSafeGuard = ::InterruptWakeupSafeGuard;
}

class TimeoutControl {
private:
  static constexpr size_t kUnlimitedTimeoutMs = 0;
  std::atomic<size_t> timeout_ms_{kUnlimitedTimeoutMs};
  std::atomic<std::chrono::steady_clock::time_point> timeout_create_clock_{
      std::chrono::steady_clock::time_point{}};
  std::atomic<size_t> grace_period_ms_{0};

public:
  explicit TimeoutControl(size_t timeout_ms = kUnlimitedTimeoutMs,
                          size_t grace_period_ms = 0)
      : timeout_ms_(timeout_ms), grace_period_ms_(grace_period_ms) {
    timeout_create_clock_.store(std::chrono::steady_clock::now(),
                                std::memory_order_release);
  }

  [[nodiscard]] bool IsTimeoutRequest() const {
    const size_t timeout_ms = timeout_ms_.load(std::memory_order_acquire);
    if (timeout_ms == kUnlimitedTimeoutMs) {
      return false;
    }
    const auto create_clock =
        timeout_create_clock_.load(std::memory_order_acquire);
    return AMTime::IntervalMS(create_clock, std::chrono::steady_clock::now()) >=
           timeout_ms;
  }

  [[nodiscard]] bool IsTimeout() const {
    const size_t timeout_ms = timeout_ms_.load(std::memory_order_acquire);
    if (timeout_ms == kUnlimitedTimeoutMs) {
      return false;
    }
    const auto create_clock =
        timeout_create_clock_.load(std::memory_order_acquire);
    return AMTime::IntervalMS(create_clock, std::chrono::steady_clock::now()) >=
           timeout_ms + grace_period_ms_.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::optional<size_t> RemainTime_ms() const {
    const size_t timeout_ms = timeout_ms_.load(std::memory_order_acquire);
    if (timeout_ms == kUnlimitedTimeoutMs) {
      return std::nullopt;
    }
    const auto create_clock =
        timeout_create_clock_.load(std::memory_order_acquire);
    const size_t elapsed_ms =
        AMTime::IntervalMS(create_clock, std::chrono::steady_clock::now());
    const size_t deadline_ms =
        timeout_ms + grace_period_ms_.load(std::memory_order_acquire);
    return elapsed_ms >= deadline_ms ? 0 : deadline_ms - elapsed_ms;
  }

  [[nodiscard]] std::optional<size_t> RemainRequestTime_ms() const {
    const size_t timeout_ms = timeout_ms_.load(std::memory_order_acquire);
    if (timeout_ms == kUnlimitedTimeoutMs) {
      return std::nullopt;
    }
    const auto create_clock =
        timeout_create_clock_.load(std::memory_order_acquire);
    const size_t elapsed_ms =
        AMTime::IntervalMS(create_clock, std::chrono::steady_clock::now());
    if (elapsed_ms >= timeout_ms) {
      return 0;
    }
    return timeout_ms - elapsed_ms;
  };
};

class ControlComponent {
private:
  sptr<InterruptControl> interrupt_control_ = nullptr;
  sptr<TimeoutControl> timeout_control_ = nullptr;

  static constexpr size_t NormalizeTimeoutMs_(int timeout_ms) {
    return timeout_ms > 0 ? static_cast<size_t>(timeout_ms) : size_t{0};
  }

public:
  ControlComponent() = default;

  explicit ControlComponent(sptr<InterruptControl> interrupt_control)
      : interrupt_control_(std::move(interrupt_control)) {}

  ControlComponent(sptr<InterruptControl> interrupt_control,
                   sptr<TimeoutControl> timeout_control)
      : interrupt_control_(std::move(interrupt_control)),
        timeout_control_(std::move(timeout_control)) {}

  ControlComponent(sptr<InterruptControl> interrupt_control, size_t timeout_ms,
                   size_t grace_period_ms = 0)
      : interrupt_control_(std::move(interrupt_control)),
        timeout_control_(
            std::make_shared<TimeoutControl>(timeout_ms, grace_period_ms)) {}

  ControlComponent(sptr<InterruptControl> interrupt_control, int timeout_ms,
                   size_t grace_period_ms = 0)
      : interrupt_control_(std::move(interrupt_control)),
        timeout_control_(std::make_shared<TimeoutControl>(
            NormalizeTimeoutMs_(timeout_ms), grace_period_ms)) {}

  [[nodiscard]] bool ShouldStop() const {
    return (interrupt_control_ && interrupt_control_->IsInterruptRequest()) ||
           (timeout_control_ && timeout_control_->IsTimeoutRequest());
  }

  [[nodiscard]] bool IsInterrupted() const {
    return interrupt_control_ && interrupt_control_->IsInterrupted();
  }

  [[nodiscard]] bool IsTimeout() const {
    return timeout_control_ && timeout_control_->IsTimeout();
  }

  [[nodiscard]] std::optional<size_t> RemainTime_ms() const {
    if (!timeout_control_) {
      return std::nullopt;
    }
    return timeout_control_->RemainTime_ms();
  }

  [[nodiscard]] std::optional<size_t> RemainRequestTime_ms() const {
    if (!timeout_control_) {
      return std::nullopt;
    }
    return timeout_control_->RemainRequestTime_ms();
  }

  [[nodiscard]] std::optional<size_t> RemainingTimeMs() const {
    return RemainTime_ms();
  }

  [[nodiscard]] std::optional<size_t> RemainingRequestTimeMs() const {
    return RemainRequestTime_ms();
  }

  [[nodiscard]] std::optional<ECM>
  BuildECM(const std::string &operation = "",
           const std::string &target = "") const {
    if (interrupt_control_ && interrupt_control_->IsInterrupt()) {
      return ECM{EC::Terminate, operation, target,
                 "Operation interrupted by user"};
    }
    if (timeout_control_ && timeout_control_->IsTimeout()) {
      return ECM{EC::OperationTimeout, operation, target,
                 "Operation timed out"};
    }
    return std::nullopt;
  }

  [[nodiscard]] std::optional<ECM>
  BuildRequestECM(const std::string &operation = "",
                  const std::string &target = "") const {
    if (interrupt_control_ && interrupt_control_->IsInterruptRequest()) {
      return ECM{EC::Terminate, operation, target,
                 "Operation interrupted by user"};
    }
    if (timeout_control_ && timeout_control_->IsTimeoutRequest()) {
      return ECM{EC::OperationTimeout, std::move(operation), std::move(target),
                 "Operation timed out"};
    }
    return std::nullopt;
  }

  [[nodiscard]] sptr<InterruptControl> InterruptRaw() const {
    return interrupt_control_;
  }

  [[nodiscard]] sptr<InterruptControl> ControlToken() const {
    return InterruptRaw();
  }

  [[nodiscard]] sptr<TimeoutControl> TimeoutRaw() const {
    return timeout_control_;
  }
};

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
  PathInfo() : name(""), path(""), dir(""), owner("") {}

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

template <typename T>
concept HasECMMemberRcm = requires {
  std::declval<T>().rcm;
} && std::same_as<std::decay_t<decltype(std::declval<T>().rcm)>, ECM>;

template <typename T> struct ECMData {
  T data;
  ECM rcm = {};
  ECMData() = default;
  ECMData(ECM result) : data(), rcm(std::move(result)) {}
  ECMData(ECM result, T data) : data(std::move(data)), rcm(std::move(result)) {}
  ECMData(T data, ECM result = {})
      : data(std::move(data)), rcm(std::move(result)) {
    if constexpr (HasECMMemberRcm<T>) {
      if (rcm.code == EC::Success && this->data.rcm.code != EC::Success) {
        rcm = this->data.rcm;
      }
    }
  }

  [[nodiscard]] bool ok() const { return rcm.code == EC::Success; }
  static ECMData OK(T v) { return ECMData(std::move(v), ECM{}); }
  operator bool() const { return ok(); }
  operator ECM() const { return rcm; }
  T &operator*() const { return data; }
};
