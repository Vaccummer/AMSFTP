#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace AMInterface::client {

struct ConnectRequest {
  std::vector<std::string> nicknames = {};
  bool force = false;
};

struct ChangeClientRequest {
  std::string nickname = "";
  bool quiet = false;
};

struct ProtocolConnectRequest {
  std::string nickname = "";
  std::string user_at_host = "";
  int64_t port = 0;
  std::string password = "";
  std::string keyfile = "";
};

struct RemoveClientsRequest {
  std::vector<std::string> nicknames = {};
};

struct ListClientsRequest {
  std::vector<std::string> nicknames = {};
  bool check = false;
  bool detail = false;
};

struct CheckClientsRequest {
  std::vector<std::string> nicknames = {};
  bool detail = false;
};

struct ClearClientsRequest {
  double timeout_s = 1.8;
};

struct ListPoolClientsRequest {
  std::vector<std::string> nicknames = {};
  bool check = false;
  bool detail = false;
};

struct CheckPoolClientsRequest {
  std::vector<std::string> nicknames = {};
  bool detail = false;
};

struct RemovePoolClientsRequest {
  std::string nickname = "";
};

struct SetHostValueRequest {
  std::string nickname = {};
  std::string attrname = {};
  std::string value = {};
  bool value_provided = false;
};

} // namespace AMInterface::client
