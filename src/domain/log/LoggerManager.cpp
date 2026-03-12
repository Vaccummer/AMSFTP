#include "domain/log/LoggerManager.hpp"
#include "domain/log/LoggerDomainService.hpp"
#include "foundation/tools/string.hpp"
#include <utility>

namespace AMDomain::log {
namespace {
/**
 * @brief Return default trace level when one logger key has no explicit value.
 */
constexpr int kDefaultTraceLevel = 4;
} // namespace

/**
 * @brief Construct manager with optional shared async scheduler.
 */
AMLoggerManager::AMLoggerManager(
    std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler)
    : scheduler_(std::move(scheduler)) {}

/**
 * @brief Bind or replace async scheduler reference.
 */
void AMLoggerManager::SetScheduler(
    std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler) {
  std::lock_guard<std::mutex> lock(mtx_);
  scheduler_ = std::move(scheduler);
}

/**
 * @brief Return current shared async scheduler.
 */
std::shared_ptr<AMAsyncWriteSchedulerPort> AMLoggerManager::Scheduler() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return scheduler_;
}

/**
 * @brief Register or replace one concrete writer by logger key.
 */
bool AMLoggerManager::SetLogger(LoggerType logger_type, WriterPtr writer) {
  if (!writer) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  logger_map_[logger_type] = std::move(writer);
  if (trace_levels_.find(logger_type) == trace_levels_.end()) {
    trace_levels_[logger_type] = kDefaultTraceLevel;
  }
  return true;
}

/**
 * @brief Remove one writer by logger key.
 */
bool AMLoggerManager::RemoveLogger(LoggerType logger_type) {
  std::lock_guard<std::mutex> lock(mtx_);
  const bool removed = logger_map_.erase(logger_type) > 0;
  trace_levels_.erase(logger_type);
  return removed;
}

/**
 * @brief Return whether one writer is registered.
 */
bool AMLoggerManager::HasLogger(LoggerType logger_type) const {
  std::lock_guard<std::mutex> lock(mtx_);
  return logger_map_.find(logger_type) != logger_map_.end();
}

/**
 * @brief Remove all writers and per-logger trace-level settings.
 */
void AMLoggerManager::ClearLoggers() {
  std::lock_guard<std::mutex> lock(mtx_);
  logger_map_.clear();
  trace_levels_.clear();
}

/**
 * @brief Set one manager-level error callback for trace write failures.
 */
void AMLoggerManager::SetErrorReporter(ErrorReporter reporter) {
  std::lock_guard<std::mutex> lock(mtx_);
  error_reporter_ = std::move(reporter);
}

/**
 * @brief Get trace level for one logger key (default is 4).
 */
int AMLoggerManager::GetTraceLevel(LoggerType logger_type) const {
  std::lock_guard<std::mutex> lock(mtx_);
  auto iter = trace_levels_.find(logger_type);
  if (iter == trace_levels_.end()) {
    return kDefaultTraceLevel;
  }
  return iter->second;
}

/**
 * @brief Set trace level for one logger key and return clamped value.
 */
int AMLoggerManager::SetTraceLevel(LoggerType logger_type, int value) {
  const int clamped = LoggerDomainService::ClampTraceLevel(value);
  std::lock_guard<std::mutex> lock(mtx_);
  trace_levels_[logger_type] = clamped;
  return clamped;
}

/**
 * @brief Submit one structured trace through logger business workflow.
 */
ECM AMLoggerManager::Trace(LoggerType logger_type, const TraceInfo &info) {
  WriterPtr writer = nullptr;
  std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler = nullptr;
  ErrorReporter reporter = {};
  int trace_level = kDefaultTraceLevel;
  {
    std::lock_guard<std::mutex> lock(mtx_);
    auto writer_iter = logger_map_.find(logger_type);
    if (writer_iter == logger_map_.end() || !writer_iter->second) {
      return Err(EC::InvalidArg,
                 AMStr::fmt("Logger writer {} is not registered", logger_type));
    }
    writer = writer_iter->second;
    scheduler = scheduler_;
    reporter = error_reporter_;
    auto level_iter = trace_levels_.find(logger_type);
    if (level_iter != trace_levels_.end()) {
      trace_level = level_iter->second;
    }
  }

  TraceInfo normalized = info;
  normalized.source = LoggerDomainService::ResolveSource(logger_type);
  if (LoggerDomainService::ToLevelInt(normalized.level) > trace_level) {
    return Ok();
  }
  const std::string line = LoggerDomainService::BuildLogLine(normalized);

  auto write_task = [writer, line, normalized, reporter]() {
    ECM write_rcm = writer->WriteLine(line);
    if (!isok(write_rcm)) {
      ReportError_(reporter, normalized, write_rcm);
    }
  };
  if (scheduler) {
    scheduler->Submit(std::move(write_task));
  } else {
    write_task();
  }
  return Ok();
}

/**
 * @brief Build one trace and submit through logger business workflow.
 */
ECM AMLoggerManager::Trace(LoggerType logger_type, TraceLevel level,
                           EC error_code,
                           const std::string &nickname,
                           const std::string &target,
                           const std::string &action, const std::string &msg,
                           std::optional<ConRequest> request) {
  TraceInfo trace(level, error_code, nickname, target, action, msg,
                  std::move(request),
                  LoggerDomainService::ResolveSource(logger_type));
  return Trace(logger_type, trace);
}

/**
 * @brief Submit one raw text line directly to target logger.
 */
ECM AMLoggerManager::WriteLine(LoggerType logger_type,
                               const std::string &line) {
  WriterPtr writer = nullptr;
  std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler = nullptr;
  ErrorReporter reporter = {};
  {
    std::lock_guard<std::mutex> lock(mtx_);
    auto writer_iter = logger_map_.find(logger_type);
    if (writer_iter == logger_map_.end() || !writer_iter->second) {
      return Err(EC::InvalidArg, "Logger writer is not registered");
    }
    writer = writer_iter->second;
    scheduler = scheduler_;
    reporter = error_reporter_;
  }

  TraceInfo normalized;
  normalized.source = LoggerDomainService::ResolveSource(logger_type);
  normalized.level = TraceLevel::Info;
  normalized.message = line;

  auto write_task = [writer, line, normalized, reporter]() {
    ECM write_rcm = writer->WriteLine(line);
    if (!isok(write_rcm)) {
      ReportError_(reporter, normalized, write_rcm);
    }
  };

  if (scheduler) {
    scheduler->Submit(std::move(write_task));
  } else {
    write_task();
  }
  return Ok();
}

/**
 * @brief Return callback helper that writes traces to one logger key.
 */
std::function<void(const TraceInfo &)>
AMLoggerManager::TraceCallbackFunc(LoggerType logger_type) {
  return [this, logger_type](const TraceInfo &info) {
    ECM trace_rcm = Trace(logger_type, info);
    if (!isok(trace_rcm)) {
      ErrorReporter reporter = {};
      {
        std::lock_guard<std::mutex> lock(mtx_);
        reporter = error_reporter_;
      }
      ReportError_(reporter, info, trace_rcm);
    }
  };
}

/**
 * @brief Return callback helper that writes raw lines to one logger type.
 */
std::function<void(const std::string &)>
AMLoggerManager::WriteLineCallbackFunc(LoggerType logger_type) {
  return [this, logger_type](const std::string &line) {
    ECM write_rcm = WriteLine(logger_type, line);
    if (!isok(write_rcm)) {
      ErrorReporter reporter = {};
      {
        std::lock_guard<std::mutex> lock(mtx_);
        reporter = error_reporter_;
      }
      if (!reporter) {
        return;
      }
      TraceInfo info;
      info.source = LoggerDomainService::ResolveSource(logger_type);
      info.level = TraceLevel::Info;
      info.message = line;
      ReportError_(reporter, info, write_rcm);
    }
  };
}

/**
 * @brief Invoke manager-level error callback when set.
 */
void AMLoggerManager::ReportError_(const ErrorReporter &reporter,
                                   const TraceInfo &info, const ECM &rcm) {
  if (!reporter) {
    return;
  }
  reporter(info, rcm);
}
} // namespace AMDomain::log
