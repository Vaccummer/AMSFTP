#pragma once

#include "application/log/LoggerAppService.hpp"

#include <string>

namespace AMApplication::log {

[[nodiscard]] inline AMDomain::client::TraceLevel
ProgramTraceLevelForResult(const ECM &rcm) {
  if ((rcm)) {
    return AMDomain::client::TraceLevel::Info;
  }
  if (rcm.code == EC::Terminate || rcm.code == EC::OperationTimeout ||
      rcm.code == EC::ConfigCanceled) {
    return AMDomain::client::TraceLevel::Warning;
  }
  return AMDomain::client::TraceLevel::Error;
}

inline void ProgramTrace(LoggerAppService *logger,
                         AMDomain::client::TraceLevel level, EC code,
                         const std::string &target,
                         const std::string &action,
                         const std::string &message = {},
                         const std::string &nickname = {}) {
  if (logger == nullptr) {
    return;
  }
  (void)logger->Trace(AMDomain::log::LoggerType::Program, level, code,
                      nickname, target, action, message);
}

inline void ProgramTrace(LoggerAppService *logger, const ECM &rcm,
                         const std::string &target,
                         const std::string &action,
                         const std::string &message = {},
                         const std::string &nickname = {}) {
  ProgramTrace(logger, ProgramTraceLevelForResult(rcm), rcm.code, target,
               action, message, nickname);
}

} // namespace AMApplication::log
