#include "domain/log/LoggerDomainService.hpp"

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
} // namespace AMDomain::log
