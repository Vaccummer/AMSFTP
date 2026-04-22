#pragma once
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostModel.hpp"

namespace AMDomain::filesystem {
using AMDomain::host::ClientNickname;
using ClientHandle = AMDomain::client::ClientHandle;

struct FilesystemArg {
  int max_cd_history = 1;
  int wget_max_redirect = 5;
};

struct PathTarget {
  ClientNickname nickname = "";
  std::string path = "";
  bool is_wildcard = false;
  bool is_user_path = false;
};

struct ResolvedPath {
  PathTarget target = {};
  std::string abs_path = "";
  ClientHandle client = nullptr;
};

struct PathEntry {
  ResolvedPath resolved = {};
  PathInfo info = {};
};

} // namespace AMDomain::filesystem
