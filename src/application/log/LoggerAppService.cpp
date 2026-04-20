#include "application/log/LoggerAppService.hpp"
#include "domain/log/LoggerDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include <sstream>
#include <utility>

namespace AMApplication::log {
namespace {
using AMDomain::log::service::kDefaultTraceLevel;
using AMDomain::writer::IWriteSchedulerPort;
} // namespace

LoggerAppService::LoggerAppService(
    std::shared_ptr<IWriteSchedulerPort> scheduler)
    : scheduler_(std::move(scheduler)) {}

void LoggerAppService::SetScheduler(
    std::shared_ptr<IWriteSchedulerPort> scheduler) {
  std::lock_guard<std::mutex> lock(mtx_);
  scheduler_ = std::move(scheduler);
}

std::shared_ptr<IWriteSchedulerPort> LoggerAppService::Scheduler() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return scheduler_;
}

bool LoggerAppService::SetLogger(AMDomain::log::LoggerType logger_type,
                                 WriterPtr writer) {
  if (!writer) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  logger_map_[logger_type] = std::move(writer);
  if (!trace_levels_.contains(logger_type)) {
    trace_levels_[logger_type] = kDefaultTraceLevel;
  }
  return true;
}

bool LoggerAppService::RemoveLogger(AMDomain::log::LoggerType logger_type) {
  std::lock_guard<std::mutex> lock(mtx_);
  const bool removed = logger_map_.erase(logger_type) > 0;
  trace_levels_.erase(logger_type);
  return removed;
}

bool LoggerAppService::HasLogger(AMDomain::log::LoggerType logger_type) const {
  std::lock_guard<std::mutex> lock(mtx_);
  return logger_map_.contains(logger_type);
}

void LoggerAppService::ClearLoggers() {
  std::lock_guard<std::mutex> lock(mtx_);
  logger_map_.clear();
  trace_levels_.clear();
}

void LoggerAppService::SetErrorReporter(ErrorReporter reporter) {
  std::lock_guard<std::mutex> lock(mtx_);
  error_reporter_ = std::move(reporter);
}

int LoggerAppService::GetTraceLevel(
    AMDomain::log::LoggerType logger_type) const {
  std::lock_guard<std::mutex> lock(mtx_);
  auto iter = trace_levels_.find(logger_type);
  if (iter == trace_levels_.end()) {
    return kDefaultTraceLevel;
  }
  return iter->second;
}

int LoggerAppService::SetTraceLevel(AMDomain::log::LoggerType logger_type,
                                    int value) {
  const int clamped = AMDomain::log::service::ClampTraceLevel(value);
  std::lock_guard<std::mutex> lock(mtx_);
  trace_levels_[logger_type] = clamped;
  return clamped;
}

ECM LoggerAppService::Trace(AMDomain::log::LoggerType logger_type,
                            const AMDomain::log::TraceInfo &info) {
  WriterPtr writer = nullptr;
  std::shared_ptr<IWriteSchedulerPort> scheduler = nullptr;
  ErrorReporter reporter = {};
  int trace_level = kDefaultTraceLevel;
  {
    std::lock_guard<std::mutex> lock(mtx_);
    auto writer_iter = logger_map_.find(logger_type);
    if (writer_iter == logger_map_.end() || !writer_iter->second) {
      return {EC::InvalidArg, "Trace", "",
              AMStr::fmt("Logger writer {} is not registered", logger_type)};
    }
    writer = writer_iter->second;
    scheduler = scheduler_;
    reporter = error_reporter_;
    auto level_iter = trace_levels_.find(logger_type);
    if (level_iter != trace_levels_.end()) {
      trace_level = level_iter->second;
    }
  }

  AMDomain::log::TraceInfo normalized = info;
  normalized.source = AMDomain::log::service::ResolveSource(logger_type);
  if (AMDomain::log::service::ToLevelInt(normalized.level) > trace_level) {
    return OK;
  }
  const std::string line = BuildLogLine_(normalized);

  auto write_task = [writer, line, normalized, reporter]() {
    ECM write_rcm = writer->WriteLine(line);
    if (!write_rcm) {
      ReportError_(reporter, normalized, write_rcm);
    }
  };
  if (scheduler) {
    scheduler->Submit(std::move(write_task));
  } else {
    write_task();
  }
  return OK;
}

ECM LoggerAppService::Trace(AMDomain::log::LoggerType logger_type,
                            AMDomain::log::TraceLevel level, EC error_code,
                            const std::string &nickname,
                            const std::string &target,
                            const std::string &action, const std::string &msg,
                            std::optional<AMDomain::log::ConRequest> request) {
  AMDomain::log::TraceInfo trace(
      level, error_code, nickname, target, action, msg, std::move(request),
      AMDomain::log::service::ResolveSource(logger_type));
  return Trace(logger_type, trace);
}

ECM LoggerAppService::WriteLine(AMDomain::log::LoggerType logger_type,
                                const std::string &line) {
  WriterPtr writer = nullptr;
  std::shared_ptr<AMDomain::writer::IWriteSchedulerPort> scheduler = nullptr;
  ErrorReporter reporter = {};
  {
    std::lock_guard<std::mutex> lock(mtx_);
    auto writer_iter = logger_map_.find(logger_type);
    if (writer_iter == logger_map_.end() || !writer_iter->second) {
      return {EC::InvalidArg, "WriteLine", line,
              "Logger writer is not registered"};
    }
    writer = writer_iter->second;
    scheduler = scheduler_;
    reporter = error_reporter_;
  }

  AMDomain::log::TraceInfo normalized;
  normalized.source = AMDomain::log::service::ResolveSource(logger_type);
  normalized.level = AMDomain::log::TraceLevel::Info;
  normalized.message = line;

  auto write_task = [writer, line, normalized, reporter]() {
    ECM write_rcm = writer->WriteLine(line);
    if (!write_rcm) {
      ReportError_(reporter, normalized, write_rcm);
    }
  };

  if (scheduler) {
    scheduler->Submit(std::move(write_task));
  } else {
    write_task();
  }
  return OK;
}

std::function<void(const AMDomain::log::TraceInfo &)>
LoggerAppService::TraceCallbackFunc(AMDomain::log::LoggerType logger_type) {
  return [this, logger_type](const AMDomain::log::TraceInfo &info) {
    ECM trace_rcm = Trace(logger_type, info);
    if (!trace_rcm) {
      ErrorReporter reporter = {};
      {
        std::lock_guard<std::mutex> lock(mtx_);
        reporter = error_reporter_;
      }
      ReportError_(reporter, info, trace_rcm);
    }
  };
}

std::function<void(const std::string &)>
LoggerAppService::WriteLineCallbackFunc(AMDomain::log::LoggerType logger_type) {
  return [this, logger_type](const std::string &line) {
    ECM write_rcm = WriteLine(logger_type, line);
    if (!write_rcm) {
      ErrorReporter reporter = {};
      {
        std::lock_guard<std::mutex> lock(mtx_);
        reporter = error_reporter_;
      }
      if (!reporter) {
        return;
      }
      AMDomain::log::TraceInfo info;
      info.source = AMDomain::log::service::ResolveSource(logger_type);
      info.level = AMDomain::log::TraceLevel::Info;
      info.message = line;
      ReportError_(reporter, info, write_rcm);
    }
  };
}

std::string
LoggerAppService::BuildLogLine_(const AMDomain::log::TraceInfo &info) {
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

void LoggerAppService::ReportError_(const ErrorReporter &reporter,
                                    const AMDomain::log::TraceInfo &info,
                                    const ECM &rcm) {
  if (!reporter) {
    return;
  }
  reporter(info, rcm);
}

} // namespace AMApplication::log
