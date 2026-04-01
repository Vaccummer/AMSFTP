#pragma once
#include "domain/log/LoggerModel.hpp"

namespace AMDomain::log {

/**
 * @brief Domain service for pure logging rules and formatting behavior.
 */
class LoggerDomainService {
public:
  /**
   * @brief Clamp trace level to valid range [-1, 4].
   */
  [[nodiscard]] static int ClampTraceLevel(int value);

  /**
   * @brief Convert enum trace level into comparable integer severity.
   */
  [[nodiscard]] static int ToLevelInt(TraceLevel level);

  /**
   * @brief Resolve default source by logger type.
   */
  [[nodiscard]] static TraceSource ResolveSource(LoggerType logger_type);
};
} // namespace AMDomain::log
