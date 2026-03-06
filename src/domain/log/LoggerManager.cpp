#include "domain/log/LoggerManager.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include <sstream>
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
bool AMLoggerManager::SetLogger(LoggerKey logger_key, WriterPtr writer) {
  if (!writer) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  logger_map_[logger_key] = std::move(writer);
  if (trace_levels_.find(logger_key) == trace_levels_.end()) {
    trace_levels_[logger_key] = kDefaultTraceLevel;
  }
  return true;
}

/**
 * @brief Remove one writer by logger key.
 */
bool AMLoggerManager::RemoveLogger(LoggerKey logger_key) {
  std::lock_guard<std::mutex> lock(mtx_);
  const bool removed = logger_map_.erase(logger_key) > 0;
  trace_levels_.erase(logger_key);
  return removed;
}

/**
 * @brief Return whether one writer is registered.
 */
bool AMLoggerManager::HasLogger(LoggerKey logger_key) const {
  std::lock_guard<std::mutex> lock(mtx_);
  return logger_map_.find(logger_key) != logger_map_.end();
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
int AMLoggerManager::GetTraceLevel(LoggerKey logger_key) const {
  std::lock_guard<std::mutex> lock(mtx_);
  auto iter = trace_levels_.find(logger_key);
  if (iter == trace_levels_.end()) {
    return kDefaultTraceLevel;
  }
  return iter->second;
}

/**
 * @brief Set trace level for one logger key and return clamped value.
 */
int AMLoggerManager::SetTraceLevel(LoggerKey logger_key, int value) {
  const int clamped = ClampTraceLevel(value);
  std::lock_guard<std::mutex> lock(mtx_);
  trace_levels_[logger_key] = clamped;
  return clamped;
}

/**
 * @brief Submit one structured trace through logger business workflow.
 */
ECM AMLoggerManager::Trace(LoggerKey logger_key, const TraceInfo &info) {
  WriterPtr writer = nullptr;
  std::shared_ptr<AMAsyncWriteSchedulerPort> scheduler = nullptr;
  ErrorReporter reporter = {};
  int trace_level = kDefaultTraceLevel;
  {
    std::lock_guard<std::mutex> lock(mtx_);
    auto writer_iter = logger_map_.find(logger_key);
    if (writer_iter == logger_map_.end() || !writer_iter->second) {
      return Err(EC::InvalidArg,
                 AMStr::fmt("Logger writer {} is not registered", logger_key));
    }
    writer = writer_iter->second;
    scheduler = scheduler_;
    reporter = error_reporter_;
    auto level_iter = trace_levels_.find(logger_key);
    if (level_iter != trace_levels_.end()) {
      trace_level = level_iter->second;
    }
  }

  TraceInfo normalized = info;
  normalized.source = ResolveSource_(logger_key);
  if (ToLevelInt(normalized.level) > trace_level) {
    return Ok();
  }
  const std::string line = BuildLogLine_(normalized);

  auto write_task = [writer, line, normalized, reporter]() {
    ECM write_rcm = writer->Write(line);
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
ECM AMLoggerManager::Trace(LoggerKey logger_key, TraceLevel level,
                           EC error_code,
                           const std::string &nickname,
                           const std::string &target,
                           const std::string &action, const std::string &msg,
                           std::optional<ConRequest> request) {
  TraceInfo trace(level, error_code, nickname, target, action, msg,
                  std::move(request), ResolveSource_(logger_key));
  return Trace(logger_key, trace);
}

/**
 * @brief Return callback helper that writes traces to one logger key.
 */
std::function<void(const TraceInfo &)>
AMLoggerManager::TraceCallbackFunc(LoggerKey logger_key) {
  return [this, logger_key](const TraceInfo &info) {
    ECM trace_rcm = Trace(logger_key, info);
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
 * @brief Clamp trace level to valid range [-1, 4].
 */
int AMLoggerManager::ClampTraceLevel(int value) {
  if (value < -1) {
    return -1;
  }
  if (value > 4) {
    return 4;
  }
  return value;
}

/**
 * @brief Convert enum trace level into comparable integer severity.
 */
int AMLoggerManager::ToLevelInt(enum TraceLevel level) {
  return static_cast<int>(level);
}

/**
 * @brief Resolve default source by logger key.
 */
TraceSource AMLoggerManager::ResolveSource_(LoggerKey logger_key) {
  return logger_key == LoggerKey::Program ? TraceSource::Programm
                                          : TraceSource::Client;
}

/**
 * @brief Build one log line text from structured trace info.
 */
std::string AMLoggerManager::BuildLogLine_(const TraceInfo &info) {
  const double stamp = info.timestamp > 0 ? info.timestamp : AMTime::seconds();
  const std::string time_str =
      FormatTime(static_cast<size_t>(stamp), "%Y/%m/%d %H:%M:%S");
  std::ostringstream line;
  line << time_str << " [" << AMStr::ToString(info.source) << "]"
       << " [" << AMStr::ToString(info.level) << "]";
  if (!info.nickname.empty()) {
    line << " [nick:" << info.nickname << "]";
  }
  if (!info.action.empty()) {
    line << " [action:" << info.action << "]";
  }
  if (!info.target.empty()) {
    line << " [target:" << info.target << "]";
  }
  if (info.request.has_value() && !info.request->hostname.empty()) {
    line << " [host:" << info.request->hostname << "]";
  }
  if (!info.message.empty()) {
    line << " " << info.message;
  }
  return line.str();
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
