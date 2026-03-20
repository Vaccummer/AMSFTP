#pragma once
#include "domain/client/ClientModel.hpp"
#include "foundation/DataClass.hpp"
#include "foundation/Enum.hpp"
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace AMDomain::filesystem {

using EC = ErrorCode;
using ErrorList = std::vector<std::pair<std::string, ECM>>;
using WalkTree =
    std::vector<std::pair<std::vector<std::string>, std::vector<PathInfo>>>;
using WalkErrorCallback =
    std::shared_ptr<std::function<void(const std::string &, const ECM &)>>;
using OS_TYPE = AMDomain::client::OS_TYPE;
using ClientStatus = AMDomain::client::ClientStatus;
using CdResult = ECMResult;
using MkdirResult = ECMResult;
using MoveResult = ECMResult;
using RMResult = ECMResult;

struct StatResult : ECMResult {
  PathInfo info = {};
};

struct ListResult : ECMResult {
  std::vector<PathInfo> entries = {};
};

struct ListNamesResult : ECMResult {
  std::vector<std::string> names = {};
};

struct GetsizeResult : ECMResult {
  int64_t size = -1;
};

struct FindResult : ECMResult {
  std::vector<PathInfo> entries = {};
};

struct DeleteResult : ECMResult {
  ErrorList errors = {};
};

struct RunResult : ECMResult {
  std::string output = "";
  int exit_code = -1;
};

struct RTTResult : ECMResult {
  double rtt_ms = -1.0;
};

struct RealpathResult : ECMResult {
  std::string path = "";
};

struct ChmodResult : ECMResult {
  OrderDict<std::string, ECM> results = {};
};

struct IWalkResult : ECMResult {
  std::vector<PathInfo> entries = {};
  ErrorList errors = {};
};

struct WalkResult : ECMResult {
  WalkTree tree = {};
  ErrorList errors = {};
};

struct UpdateOSTypeResult : ECMResult {
  OS_TYPE os_type = OS_TYPE::Unknown;
  [[nodiscard]] operator OS_TYPE() const { return os_type; }
};

struct UpdateHomeDirResult : ECMResult {
  std::string home_dir = "";
  [[nodiscard]] operator std::string() const { return home_dir; }
};

struct CheckResult : ECMResult {
  ClientStatus status = ClientStatus::NotInitialized;
  [[nodiscard]] operator ECM() const { return rcm; }
};

struct ConnectResult : ECMResult {
  ClientStatus status = ClientStatus::NotInitialized;
  [[nodiscard]] operator ECM() const { return rcm; }
};

struct UpdateOSTypeArgs {};

struct UpdateHomeDirArgs {};

struct CheckArgs {};

struct ConnectArgs {
  bool force = false;
};

struct GetRTTArgs {
  ssize_t times = 5;
};

struct ConductCmdArgs {
  using OutputProcessor = std::function<void(std::string_view)>;
  std::string cmd = "";
  OutputProcessor processor = {};
};

struct RealpathArgs {
  std::string path = "";
};

struct ChmodArgs {
  std::string path = "";
  std::variant<std::string, size_t> mode = size_t(0);
  bool recursive = false;
};

struct StatArgs {
  std::string path = "";
  bool trace_link = false;
};

struct ListdirArgs {
  std::string path = "";
};

struct ListNamesArgs {
  std::string path = "";
};

struct GetsizeArgs {
  std::string path = "";
  bool ignore_special_file = true;
};

struct FindArgs {
  std::string path = "";
  SearchType type = SearchType::All;
};

struct MkdirArgs {
  std::string path = "";
};

struct MkdirsArgs {
  std::string path = "";
};

struct RmdirArgs {
  std::string path = "";
};

struct RmfileArgs {
  std::string path = "";
};

struct RenameArgs {
  std::string src = "";
  std::string dst = "";
  bool isdir = false;
  bool mkdir = true;
  bool overwrite = false;
};

struct RemoveArgs {
  std::string path = "";
  WalkErrorCallback error_callback = nullptr;
};

struct SafermArgs {
  std::string path = "";
};

struct CopyArgs {
  std::string src = "";
  std::string dst = "";
  bool need_mkdir = false;
};

struct IWalkArgs {
  std::string path = "";
  bool show_all = false;
  bool ignore_special_file = true;
  WalkErrorCallback error_callback = nullptr;
};

struct WalkArgs {
  std::string path = "";
  int max_depth = -1;
  bool show_all = false;
  bool ignore_special_file = false;
  WalkErrorCallback error_callback = nullptr;
};

} // namespace AMDomain::filesystem
