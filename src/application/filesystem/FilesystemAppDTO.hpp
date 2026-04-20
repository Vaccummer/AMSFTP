#pragma once

#include "domain/filesystem/FileSystemModel.hpp"

#include <map>
#include <string>
#include <vector>

namespace AMApplication::filesystem {
using PathTarget = AMDomain::filesystem::PathTarget;
using ResolvedPath = AMDomain::filesystem::ResolvedPath;

struct PermanentRemovePlan {
  std::map<std::string, std::vector<PathTarget>> grouped_display_paths = {};
  std::vector<ResolvedPath> ordered_delete_paths = {};
  std::vector<std::pair<PathTarget, ECM>> precheck_errors = {};
  ECM rcm = OK;
};

struct RmfilePlan {
  std::map<std::string, std::vector<PathTarget>> grouped_display_paths = {};
  std::vector<ResolvedPath> validated_targets = {};
  std::vector<std::pair<PathTarget, ECM>> precheck_errors = {};
  ECM rcm = OK;
};
} // namespace AMApplication::filesystem
