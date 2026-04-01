#include "domain/log/LoggerDomainService.hpp"

namespace AMDomain::log::service {

int ClampTraceLevel(int value) {
  if (value < -1) {
    return -1;
  }
  if (value > 4) {
    return 4;
  }
  return value;
}

int ToLevelInt(TraceLevel level) { return static_cast<int>(level); }

TraceSource ResolveSource(LoggerType logger_type) {
  return logger_type == LoggerType::Program ? TraceSource::Programm
                                            : TraceSource::Client;
}

} // namespace AMDomain::log::service
