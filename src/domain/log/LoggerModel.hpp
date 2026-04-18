#pragma once
#include "domain/client/ClientModel.hpp"
#include <string>

namespace AMDomain::log {
using AMDomain::client::TraceInfo;
using AMDomain::client::TraceLevel;
using AMDomain::client::TraceSource;
using AMDomain::host::ConRequest;

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
  std::string client_log_path = "config/log/Client.log";
  std::string program_log_path = "config/log/Program.log";
};

} // namespace AMDomain::log
