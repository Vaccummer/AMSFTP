#pragma once
#include "domain/host/HostModel.hpp"
#include "foundation/tools/string.hpp"
#include <string>

namespace AMDomain::filesystem::services {

[[nodiscard]] static std::string
BuildShellCommand(const std::string &command, const std::string &cmd_prefix,
                  bool wrap_cmd) {
  return cmd_prefix.empty()
             ? command
             : (wrap_cmd ? AMStr::fmt("{}\"{}\"", cmd_prefix,
                                      AMStr::replace_all(command, "\"", "'"))
                         : AMStr::fmt("{}{}", cmd_prefix, command));
};

[[nodiscard]] static std::string
BuildShellCommand(const std::string &command,
                  const AMDomain::host::ClientMetaData &metadata) {
  return BuildShellCommand(command, metadata.cmd_prefix, metadata.wrap_cmd);
};
} // namespace AMDomain::filesystem::services
