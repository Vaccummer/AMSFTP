#pragma once
#include "domain/client/ClientModel.hpp"

namespace AMDomain::log {
using TraceLevel = AMDomain::client::TraceLevel;
using TraceSource = AMDomain::client::TraceSource;
using TraceInfo = AMDomain::client::TraceInfo;
using ConRequest = AMDomain::host::ConRequest;

/**
 * @brief Typed logger selector for one registered writer channel.
 */
enum class LoggerType {
  Client = 0,
  Program = 1,
};

/**
 * @brief Settings payload for `Options.LogManager`.
 */
struct LogManagerArg {
  int client_trace_level = 4;
  int program_trace_level = 4;
};

} // namespace AMDomain::log
