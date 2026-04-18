#pragma once

#include "domain/log/LoggerModel.hpp"
#include "domain/log/LoggerPorts.hpp"
#include "domain/writer/IWriteSchedulerPort.hpp"
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace AMApplication::log {
using AMDomain::writer::IWriteSchedulerPort;
/**
 * @brief Logger application service with async scheduling and writer
 * routing.
 */
class LoggerAppService final : public NonCopyableNonMovable {
public:
  using WriterPtr = std::shared_ptr<AMDomain::log::ILoggerWritePort>;
  using ErrorReporter =
      std::function<void(const AMDomain::log::TraceInfo &, const ECM &)>;

  /**
   * @brief Construct service with optional shared async scheduler.
   */
  explicit LoggerAppService(
      std::shared_ptr<IWriteSchedulerPort> scheduler = nullptr);
  ~LoggerAppService() override = default;

  /**
   * @brief Bind or replace async scheduler reference.
   */
  void SetScheduler(std::shared_ptr<IWriteSchedulerPort> scheduler);

  /**
   * @brief Return current shared async scheduler.
   */
  [[nodiscard]] std::shared_ptr<IWriteSchedulerPort> Scheduler() const;

  /**
   * @brief Register or replace one concrete writer by logger type.
   */
  bool SetLogger(AMDomain::log::LoggerType logger_type, WriterPtr writer);

  /**
   * @brief Remove one writer by logger type.
   */
  bool RemoveLogger(AMDomain::log::LoggerType logger_type);

  /**
   * @brief Return whether one writer is registered.
   */
  [[nodiscard]] bool HasLogger(AMDomain::log::LoggerType logger_type) const;

  /**
   * @brief Remove all writers and per-logger trace-level settings.
   */
  void ClearLoggers();

  /**
   * @brief Set one manager-level error callback for trace write failures.
   */
  void SetErrorReporter(ErrorReporter reporter);

  /**
   * @brief Get trace level for one logger type (default is 4).
   */
  [[nodiscard]] int GetTraceLevel(AMDomain::log::LoggerType logger_type) const;

  /**
   * @brief Set trace level for one logger type and return clamped value.
   */
  int SetTraceLevel(AMDomain::log::LoggerType logger_type, int value);

  /**
   * @brief Submit one structured trace through logger business workflow.
   */
  ECM Trace(AMDomain::log::LoggerType logger_type,
            const AMDomain::log::TraceInfo &info);

  /**
   * @brief Build one trace and submit through logger business workflow.
   */
  ECM Trace(AMDomain::log::LoggerType logger_type,
            AMDomain::log::TraceLevel level, EC error_code,
            const std::string &nickname = "", const std::string &target = "",
            const std::string &action = "", const std::string &msg = "",
            std::optional<AMDomain::log::ConRequest> request = std::nullopt);

  /**
   * @brief Submit one raw text line directly to target logger.
   */
  ECM WriteLine(AMDomain::log::LoggerType logger_type, const std::string &line);

  /**
   * @brief Return callback helper that writes traces to one logger type.
   */
  [[nodiscard]] std::function<void(const AMDomain::log::TraceInfo &)>
  TraceCallbackFunc(AMDomain::log::LoggerType logger_type);

  /**
   * @brief Return callback helper that writes raw lines to one logger type.
   */
  [[nodiscard]] std::function<void(const std::string &)>
  WriteLineCallbackFunc(AMDomain::log::LoggerType logger_type);

private:
  /**
   * @brief Build one log line text from structured trace info.
   */
  [[nodiscard]] static std::string
  BuildLogLine_(const AMDomain::log::TraceInfo &info);

  /**
   * @brief Invoke manager-level error callback when set.
   */
  static void ReportError_(const ErrorReporter &reporter,
                           const AMDomain::log::TraceInfo &info,
                           const ECM &rcm);

private:
  mutable std::mutex mtx_;
  std::unordered_map<AMDomain::log::LoggerType, WriterPtr> logger_map_;
  std::unordered_map<AMDomain::log::LoggerType, int> trace_levels_;
  std::shared_ptr<IWriteSchedulerPort> scheduler_ = nullptr;
  ErrorReporter error_reporter_ = {};
};

} // namespace AMApplication::log
