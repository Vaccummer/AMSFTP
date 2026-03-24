#pragma once
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostModel.hpp"

namespace AMDomain::filesystem {
using ClientNickname = AMDomain::host::ConRequest::ClientNickname;
using ClientHandle = AMDomain::client::ClientHandle;

struct FilesystemArg {
  int max_cd_history = 1;
};

struct ClientPath {
  ClientNickname nickname = "";
  std::string path = "";
  ClientHandle client = nullptr;
  ECM rcm = ECM{EC::Success, ""};
  bool is_wildcard = false;
  bool userpath = false; // true if the path is a userpath (e.g. ~/foo)
  bool resolved = false;
};

using StatPathResult = std::pair<ECM, PathInfo>;
using RttQueryResult = std::pair<ECM, double>;

} // namespace AMDomain::filesystem
