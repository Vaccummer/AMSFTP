#pragma once
#include "ClientIOPortInterfaceArgs.hpp"
#include "FileSystemModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include <string>
#include <vector>

namespace AMDomain::filesystem::service {

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

inline std::vector<PathTarget>
DedupPathTargets(const std::vector<PathTarget> &targets) {
  return AMStr::DedupVectorKeepOrder(targets, [](const PathTarget &target) {
    return target.nickname + "@" + target.path;
  });
}

[[maybe_unused]] [[nodiscard]] static std::string
BuildShellCommand(OS_TYPE os_type, const std::string &cwd,
                  const std::string &command,
                  const std::string &cmd_template) {
  (void)os_type;
  (void)cwd;
  if (cmd_template.empty()) {
    return command;
  }
  return AMStr::fmt("{}{}", cmd_template, command);
}

} // namespace AMDomain::filesystem::service
