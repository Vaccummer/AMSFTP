#pragma once

#include "foundation/core/DataClass.hpp"
#include <functional>
#include <memory>
#include <string>

namespace AMDomain::signal {
using SignalCallback = std::function<void(int)>;
struct SignalHook {
  SignalCallback callback;
  bool is_silenced = false;
  /** Higher values run first. */
  int priority = 0;
  /** Stop propagation to lower-priority hooks when set. */
  bool consume = false;
};

/**
 * @brief Domain port for CLI signal monitor hook orchestration.
 */
class SignalMonitor : public NonCopyableNonMovable {
public:
  /**
   * @brief Hook container for one signal subscriber.
   */

  ~SignalMonitor() override = default;

  /**
   * @brief Install handlers and start monitor worker.
   */
  virtual ECM Init() = 0;

  /**
   * @brief Stop monitor worker.
   */
  virtual void Stop() = 0;

  /**
   * @brief Return last consumed signal value.
   */
  [[nodiscard]] virtual int LastSignal() const = 0;

  /**
   * @brief Register one named hook. Name must be unique.
   */
  virtual bool RegisterHook(const std::string &name,
                            const SignalHook &hook) = 0;

  /**
   * @brief Unregister one named hook.
   */
  virtual bool UnregisterHook(const std::string &name) = 0;

  /**
   * @brief Silence one named hook.
   */
  virtual bool SilenceHook(const std::string &name) = 0;

  /**
   * @brief Resume one silenced hook.
   */
  virtual bool ResumeHook(const std::string &name) = 0;

  /**
   * @brief Update one hook priority.
   */
  virtual bool SetHookPriority(const std::string &name, int priority) = 0;
};

/**
 * @brief Build the default signal-monitor port implementation.
 */
std::unique_ptr<SignalMonitor> BuildSignalMonitorPort();
} // namespace AMDomain::signal

/**
 * @brief Backward-compatible global alias.
 */
using SignalMonitor = AMDomain::signal::SignalMonitor;
using AMSignalMonitorPort = AMDomain::signal::SignalMonitor;
