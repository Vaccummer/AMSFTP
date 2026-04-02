#pragma once
#include "ClientIOPortInterfaceArgs.hpp"
#include "FileSystemModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include <string>
#include <unordered_set>
#include <vector>

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

inline std::vector<PathTarget>
DedupPathTargets(const std::vector<PathTarget> &targets) {
  std::vector<PathTarget> deduped = {};
  deduped.reserve(targets.size());
  std::unordered_set<std::string> seen = {};
  for (const auto &target : targets) {
    const std::string key = target.nickname + "@" + target.path;
    if (!seen.insert(key).second) {
      continue;
    }
    deduped.push_back(target);
  }
  return deduped;
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
