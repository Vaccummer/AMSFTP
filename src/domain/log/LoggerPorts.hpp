#pragma once

#include "domain/log/LoggerModel.hpp"
#include "domain/writer/AsyncWriteSchedulerPort.hpp"
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace AMDomain::log {

/**
 * @brief Domain port for concrete logger writers in infrastructure.
 */
class AMLoggerWritePort : public NonCopyableNonMovable {
public:
  using ErrorReporter = std::function<void(const ECM &)>;

  /**
   * @brief Destroy writer port instance.
   */
  virtual ~AMLoggerWritePort() = default;

  /**
   * @brief Bind one output path used by this writer.
   */
  virtual ECM SetPath(const std::filesystem::path &path) = 0;

  /**
   * @brief Return writer output path.
   */
  [[nodiscard]] virtual std::filesystem::path Path() const = 0;

  /**
   * @brief Write one line into underlying output stream.
   */
  virtual ECM Write(const std::string &line) = 0;

  /**
   * @brief Write one raw line without any logger-side formatting.
   */
  virtual ECM WriteLine(const std::string &line) { return Write(line); }

  /**
   * @brief Bind callback for writer-level I/O errors.
   */
  virtual void SetErrorReporter(ErrorReporter reporter) = 0;

  /**
   * @brief Close underlying stream resources.
   */
  virtual void Close() = 0;

  /**
   * @brief Return last writer-level ECM state.
   */
  [[nodiscard]] ECM LastError() const {
    std::lock_guard<std::mutex> lock(error_mtx_);
    return last_error_;
  }

  /**
   * @brief Clear last writer-level ECM state to success.
   */
  void ClearLastError() { SetLastError_({EC::Success, ""}); }

protected:
  /**
   * @brief Update last writer-level ECM state.
   */
  void SetLastError_(const ECM &error) {
    std::lock_guard<std::mutex> lock(error_mtx_);
    last_error_ = error;
  }

private:
  mutable std::mutex error_mtx_;
  ECM last_error_ = {EC::Success, ""};
};

/**
 * @brief Domain port contract for logger-manager orchestration operations.
 */
class AMLoggerManagerPort {
public:
  using WriterPtr = std::shared_ptr<AMLoggerWritePort>;
  using ErrorReporter = std::function<void(const TraceInfo &, const ECM &)>;

  /**
   * @brief Destroy manager port instance.
   */
  virtual ~AMLoggerManagerPort() = default;

  /**
   * @brief Bind or replace async scheduler reference.
   */
  virtual void
  SetScheduler(std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler) = 0;

  /**
   * @brief Return current shared async scheduler.
   */
  [[nodiscard]] virtual std::shared_ptr<AMAsyncWriteSchedulerPort>
  Scheduler() const = 0;

  /**
   * @brief Register or replace one concrete writer by logger type.
   */
  virtual bool SetLogger(LoggerType logger_type, WriterPtr writer) = 0;

  /**
   * @brief Remove one writer by logger type.
   */
  virtual bool RemoveLogger(LoggerType logger_type) = 0;

  /**
   * @brief Return whether one writer is registered.
   */
  [[nodiscard]] virtual bool HasLogger(LoggerType logger_type) const = 0;

  /**
   * @brief Remove all writers and per-logger trace-level settings.
   */
  virtual void ClearLoggers() = 0;

  /**
   * @brief Set one manager-level error callback for trace write failures.
   */
  virtual void SetErrorReporter(ErrorReporter reporter) = 0;

  /**
   * @brief Get trace level for one logger type (default is 4).
   */
  [[nodiscard]] virtual int GetTraceLevel(LoggerType logger_type) const = 0;

  /**
   * @brief Set trace level for one logger type and return clamped value.
   */
  virtual int SetTraceLevel(LoggerType logger_type, int value) = 0;

  /**
   * @brief Submit one structured trace through logger business workflow.
   */
  virtual ECM Trace(LoggerType logger_type, const TraceInfo &info) = 0;

  /**
   * @brief Build one trace and submit through logger business workflow.
   */
  virtual ECM Trace(LoggerType logger_type, TraceLevel level, EC error_code,
                    const std::string &nickname = "",
                    const std::string &target = "",
                    const std::string &action = "", const std::string &msg = "",
                    std::optional<ConRequest> request = std::nullopt) = 0;

  /**
   * @brief Submit one raw text line directly to target logger.
   */
  virtual ECM WriteLine(LoggerType logger_type, const std::string &line) = 0;

  /**
   * @brief Return callback helper that writes traces to one logger type.
   */
  [[nodiscard]] virtual std::function<void(const TraceInfo &)>
  TraceCallbackFunc(LoggerType logger_type) = 0;

  /**
   * @brief Return callback helper that writes raw lines to one logger type.
   */
  [[nodiscard]] virtual std::function<void(const std::string &)>
  WriteLineCallbackFunc(LoggerType logger_type) = 0;
};
} // namespace AMDomain::log

/**
 * @brief Backward-compatible global alias for gradual migration.
 */
using AMLoggerWritePort = AMDomain::log::AMLoggerWritePort;

/**
 * @brief Backward-compatible global alias for gradual migration.
 */
using AMLoggerManagerPort = AMDomain::log::AMLoggerManagerPort;
