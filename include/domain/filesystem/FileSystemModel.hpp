#pragma once
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"

namespace AMDomain::filesystem {

struct SizeEntry {
  std::string raw = "";
  std::string abs_path = "";
  int64_t size = -1;
};

struct RealpathEntry {
  std::string raw = "";
  std::string abs_path = "";
};

struct ListPathPayload {
  PathInfo target = {};
  std::vector<PathInfo> entries = {};
};

struct WalkPayload {
  std::vector<PathInfo> items = {};
  ErrorList errors = {};
};

using RemoveResult = std::pair<ECM, ErrorList>;
using StatPathResult = std::pair<ECM, PathInfo>;
using ListPathResult = std::pair<ECM, ListPathPayload>;
using GetSizeEntryResult = std::pair<ECM, SizeEntry>;
using WalkQueryResult = std::pair<ECM, WalkPayload>;
using RealpathQueryResult = std::pair<ECM, RealpathEntry>;
using RttQueryResult = std::pair<ECM, double>;

} // namespace AMDomain::filesystem
