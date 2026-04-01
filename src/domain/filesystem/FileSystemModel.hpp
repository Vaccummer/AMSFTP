#pragma once
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostModel.hpp"
#include <optional>
#include <utility>

namespace AMDomain::filesystem {
using ClientNickname = AMDomain::host::ConRequest::ClientNickname;
using ClientHandle = AMDomain::client::ClientHandle;

struct FilesystemArg {
  int max_cd_history = 1;
};

struct PathTarget {
  ClientNickname nickname = "";
  std::string path = "";
};

struct ResolvedPath {
  PathTarget target = {};
  std::string abs_path = "";
  ClientHandle client = nullptr;
  bool is_wildcard = false;
  bool is_user_path = false;
};

struct PathEntry {
  ResolvedPath resolved = {};
  PathInfo info = {};
};

struct ClientPath {
  ClientNickname nickname = "";
  std::string path = "";
  std::optional<PathInfo> info = std::nullopt;
  ClientHandle client = nullptr;
  bool is_wildcard = false;
  bool userpath = false; // true if the path is a userpath (e.g. ~/foo)
  bool resolved = false;
  ECM rcm = ECM{EC::Success, ""};
};

using StatPathResult = std::pair<ECM, PathInfo>;
using RttQueryResult = std::pair<ECM, double>;
} // namespace AMDomain::filesystem
