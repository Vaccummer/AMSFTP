#pragma once
#include "domain/log/LoggerModel.hpp"
#include "domain/log/LoggerPorts.hpp"
#include "domain/writer/AsyncWriteSchedulerPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/enum_related.hpp"
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
class AMLoggerManager : public AMLoggerManagerPort,
                        public NonCopyableNonMovable {
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
  void
  SetScheduler(std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler) override;

  /**
   * @brief Return current shared async scheduler.
   */
  [[nodiscard]] std::shared_ptr<AMAsyncWriteSchedulerPort>
  Scheduler() const override;

  /**
   * @brief Register or replace one concrete writer by logger type.
   */
  bool SetLogger(LoggerType logger_type, WriterPtr writer) override;

  /**
   * @brief Remove one writer by logger type.
   */
  bool RemoveLogger(LoggerType logger_type) override;

  /**
   * @brief Return whether one writer is registered.
   */
  [[nodiscard]] bool HasLogger(LoggerType logger_type) const override;

  /**
   * @brief Remove all writers and per-logger trace-level settings.
   */
  void ClearLoggers() override;

  /**
   * @brief Set one manager-level error callback for trace write failures.
   */
  void SetErrorReporter(ErrorReporter reporter) override;

  /**
   * @brief Get trace level for one logger type (default is 4).
   */
  [[nodiscard]] int GetTraceLevel(LoggerType logger_type) const override;

  /**
   * @brief Set trace level for one logger type and return clamped value.
   */
  int SetTraceLevel(LoggerType logger_type, int value) override;

  /**
   * @brief Submit one structured trace through logger business workflow.
   */
  ECM Trace(LoggerType logger_type, const TraceInfo &info) override;

  /**
   * @brief Build one trace and submit through logger business workflow.
   */
  ECM Trace(LoggerType logger_type, TraceLevel level, EC error_code,
            const std::string &nickname = "", const std::string &target = "",
            const std::string &action = "", const std::string &msg = "",
            std::optional<ConRequest> request = std::nullopt) override;

  /**
   * @brief Submit one raw text line directly to target logger.
   */
  ECM WriteLine(LoggerType logger_type, const std::string &line) override;

  /**
   * @brief Return callback helper that writes traces to one logger type.
   */
  [[nodiscard]] std::function<void(const TraceInfo &)>
  TraceCallbackFunc(LoggerType logger_type) override;

  /**
   * @brief Return callback helper that writes raw lines to one logger type.
   */
  [[nodiscard]] std::function<void(const std::string &)>
  WriteLineCallbackFunc(LoggerType logger_type) override;

private:
  /**
   * @brief Invoke manager-level error callback when set.
   */
  static void ReportError_(const ErrorReporter &reporter, const TraceInfo &info,
                           const ECM &rcm);

  mutable std::mutex mtx_;
  std::unordered_map<LoggerType, WriterPtr> logger_map_;
  std::unordered_map<LoggerType, int> trace_levels_;
  std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler_ = nullptr;
  ErrorReporter error_reporter_ = {};
};
} // namespace AMDomain::log

/**
 * @brief Backward-compatible global alias for gradual migration.
 */
using AMLoggerManager = AMDomain::log::AMLoggerManager;
