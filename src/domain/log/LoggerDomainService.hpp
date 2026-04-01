#pragma once

#include "domain/log/LoggerModel.hpp"

namespace AMDomain::log::service {

/**
 * @brief Default trace level used when no per-logger value is configured.
 */
constexpr int kDefaultTraceLevel = 4;

/**
 * @brief Clamp trace level to valid range [-1, 4].
 */
[[nodiscard]] int ClampTraceLevel(int value);

/**
 * @brief Convert enum trace level into comparable integer severity.
 */
[[nodiscard]] int ToLevelInt(TraceLevel level);

/**
 * @brief Resolve default source by logger type.
 */
[[nodiscard]] TraceSource ResolveSource(LoggerType logger_type);

} // namespace AMDomain::log::service
