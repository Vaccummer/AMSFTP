#pragma once
#include "ClientIOPortInterfaceArgs.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include <string>

namespace AMDomain::filesystem::services {

inline std::string NormalizePath(const std::string &path) {
  if (path.empty()) {
    return "";
  }
  std::string normalized = AMStr::Strip(path);
  return AMPath::UnifyPathSep(normalized, "/");
}

inline bool HasWildcard(const std::string &path) {
  return path.find('*') != std::string::npos ||
         (path.find('<') != std::string::npos &&
          path.find('>') != std::string::npos);
}

inline bool IsPathNotExistError(ErrorCode ec) {
  return ec == ErrorCode::PathNotExist || ec == ErrorCode::FileNotExist;
}

[[nodiscard]] static std::string
BuildShellCommand(OS_TYPE os_type, const std::string &cwd,
                  const std::string &command, const std::string &cmd_prefix,
                  bool wrap_cmd) {
  return cmd_prefix.empty()
             ? command
             : (wrap_cmd ? AMStr::fmt("{}\"{}\"", cmd_prefix,
                                      AMStr::replace_all(command, "\"", "'"))
                         : AMStr::fmt("{}{}", cmd_prefix, command));
};

} // namespace AMDomain::filesystem::services
