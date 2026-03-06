#pragma once

#include "domain/config/AsyncWriteSchedulerPort.hpp"
#include "domain/log/LoggerPort.hpp"
#include "foundation/DataClass.hpp"
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace AMDomain::log {
/**
 * @brief Domain logger manager with business logic and async scheduling.
 */
class AMLoggerManager : public NonCopyableNonMovable {
public:
  using WriterPtr = std::shared_ptr<AMLoggerWritePort>;
  using ErrorReporter = std::function<void(const TraceInfo &, const ECM &)>;

  /**
   * @brief Construct manager with optional shared async scheduler.
   */
  explicit AMLoggerManager(
      std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler = nullptr);

  /**
   * @brief Destroy logger manager instance.
   */
  ~AMLoggerManager() override = default;

  /**
   * @brief Bind or replace async scheduler reference.
   */
  void SetScheduler(std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler);

  /**
   * @brief Return current shared async scheduler.
   */
  [[nodiscard]] std::shared_ptr<AMAsyncWriteSchedulerPort> Scheduler() const;

  /**
   * @brief Register or replace one concrete writer by logger key.
   */
  bool SetLogger(int logger_key, WriterPtr writer);

  /**
   * @brief Remove one writer by logger key.
   */
  bool RemoveLogger(int logger_key);

  /**
   * @brief Return whether one writer is registered.
   */
  [[nodiscard]] bool HasLogger(int logger_key) const;

  /**
   * @brief Remove all writers and per-logger trace-level settings.
   */
  void ClearLoggers();

  /**
   * @brief Set one manager-level error callback for trace write failures.
   */
  void SetErrorReporter(ErrorReporter reporter);

  /**
   * @brief Get trace level for one logger key (default is 4).
   */
  [[nodiscard]] int GetTraceLevel(int logger_key) const;

  /**
   * @brief Set trace level for one logger key and return clamped value.
   */
  int SetTraceLevel(int logger_key, int value);

  /**
   * @brief Submit one structured trace through logger business workflow.
   */
  ECM Trace(int logger_key, const TraceInfo &info);

  /**
   * @brief Build one trace and submit through logger business workflow.
   */
  ECM Trace(int logger_key, TraceLevel level, EC error_code,
            const std::string &nickname = "",
            const std::string &target = "",
            const std::string &action = "", const std::string &msg = "",
            std::optional<ConRequest> request = std::nullopt);

  /**
   * @brief Return callback helper that writes traces to one logger key.
   */
  [[nodiscard]] std::function<void(const TraceInfo &)>
  TraceCallbackFunc(int logger_key);

  /**
   * @brief Clamp trace level to valid range [-1, 4].
   */
  static int ClampTraceLevel(int value);

  /**
   * @brief Convert enum trace level into comparable integer severity.
   */
  static int ToLevelInt(enum TraceLevel level);

private:
  /**
   * @brief Resolve default source by logger key.
   */
  static TraceSource ResolveSource_(int logger_key);

  /**
   * @brief Build one log line text from structured trace info.
   */
  static std::string BuildLogLine_(const TraceInfo &info);

  /**
   * @brief Invoke manager-level error callback when set.
   */
  static void ReportError_(const ErrorReporter &reporter,
                           const TraceInfo &info, const ECM &rcm);

  mutable std::mutex mtx_;
  std::unordered_map<int, WriterPtr> logger_map_;
  std::unordered_map<int, int> trace_levels_;
  std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler_ = nullptr;
  ErrorReporter error_reporter_ = {};
};
} // namespace AMDomain::log

/**
 * @brief Backward-compatible global alias for gradual migration.
 */
using AMLoggerManager = AMDomain::log::AMLoggerManager;
