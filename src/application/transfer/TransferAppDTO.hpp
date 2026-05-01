#pragma once

#include "domain/filesystem/FileSystemModel.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "foundation/core/DataClass.hpp"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace AMApplication::transfer {
using PathTarget = AMDomain::filesystem::PathTarget;
using ResolvedPath = AMDomain::filesystem::ResolvedPath;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TASKS = std::vector<AMDomain::transfer::TransferTask>;

struct DstResolveResult {
  PathTarget target = {};
  ResolvedPath resolved_target = {};
  std::optional<PathInfo> dst_info = std::nullopt;
};

struct SourceHostResolveData {
  ResolvedPath resolved_target = {};
  std::vector<PathInfo> raw_paths = {};
  std::vector<PathInfo> paths = {};
};

struct SourceResolveResult {
  std::map<std::string, SourceHostResolveData> data = {};
  std::map<std::string, std::vector<std::pair<PathTarget, ECM>>> error_data =
      {};
};

struct BuildTransferTaskOptions {
  bool clone = false;
  bool mkdir = true;
  bool ignore_special_file = true;
  bool resume = false;
};

struct BuildTransferTaskResult {
  struct WarningItem {
    std::string src = {};
    std::string dst = {};
    ECM rcm = OK;
  };

  TASKS dir_tasks = {};
  TASKS file_tasks = {};
  std::vector<WarningItem> warnings = {};
  std::vector<WarningItem> resume_from_start = {};
};

struct HttpDownloadPlan {
  PathTarget final_target = {};
  ResolvedPath resolved_target = {};
  std::optional<PathInfo> dst_info = std::nullopt;
};
} // namespace AMApplication::transfer
