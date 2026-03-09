#include "domain/log/LoggerDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include <sstream>

namespace AMDomain::log {
/**
 * @brief Clamp trace level to valid range [-1, 4].
 */
int LoggerDomainService::ClampTraceLevel(int value) {
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
int LoggerDomainService::ToLevelInt(TraceLevel level) {
  return static_cast<int>(level);
}

/**
 * @brief Resolve default source by logger type.
 */
TraceSource LoggerDomainService::ResolveSource(LoggerType logger_type) {
  return logger_type == LoggerType::Program ? TraceSource::Programm
                                            : TraceSource::Client;
}

/**
 * @brief Build one log line text from structured trace info.
 */
std::string LoggerDomainService::BuildLogLine(const TraceInfo &info) {
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
} // namespace AMDomain::log
