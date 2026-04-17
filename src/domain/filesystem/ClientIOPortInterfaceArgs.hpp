#pragma once
#include "domain/client/ClientModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace AMDomain::filesystem {

enum class SearchType { All = 0, File = 1, Directory = 2 };

using EC = ErrorCode;
using ErrorList = std::vector<std::pair<std::string, ECM>>;
using WalkTree =
    std::vector<std::pair<std::vector<std::string>, std::vector<PathInfo>>>;
using WalkErrorCallback =
    std::shared_ptr<std::function<void(const std::string &, const ECM &)>>;
using OS_TYPE = AMDomain::client::OS_TYPE;
using ClientStatus = AMDomain::client::ClientStatus;
using EmptyResult = std::monostate;
using CdResult = EmptyResult;
using MkdirResult = EmptyResult;
using MkdirsResult = EmptyResult;
using MoveResult = EmptyResult;
using RMResult = EmptyResult;

struct StatResult {
  PathInfo info = {};
};

struct ListResult {
  std::vector<PathInfo> entries = {};
};

struct ListNamesResult {
  std::vector<std::string> names = {};
};

struct GetsizeResult {
  int64_t size = -1;
};

struct FindResult {
  std::vector<PathInfo> entries = {};
};

struct DeleteResult {
  ErrorList errors = {};
};

struct RunResult {
  std::string output = "";
  int exit_code = -1;
};

struct TerminalOpenResult {
  bool opened = false;
};

struct TerminalReadResult {
  std::string output = "";
  bool eof = false;
};

struct TerminalWriteResult {
  size_t bytes_written = 0;
};

struct TerminalResizeResult {
  bool resized = false;
};

struct TerminalCloseResult {
  bool closed = false;
  int exit_code = -1;
};

struct TerminalStatusResult {
  bool is_supported = false;
  bool is_open = false;
  bool can_resize = false;
  ClientStatus status = ClientStatus::NotInitialized;
};

struct RTTResult {
  double rtt_ms = -1.0;
};

struct RealpathResult {
  std::string path = "";
};

struct ChmodResult {
  OrderDict<std::string, ECM> results = {};
};

struct IWalkResult {
  std::vector<PathInfo> entries = {};
  ErrorList errors = {};
};

struct WalkResult {
  WalkTree tree = {};
  ErrorList errors = {};
};

struct UpdateOSTypeResult {
  OS_TYPE os_type = OS_TYPE::Unknown;
  [[nodiscard]] operator OS_TYPE() const { return os_type; }
};

struct UpdateHomeDirResult {
  std::string home_dir = "";
  [[nodiscard]] operator std::string() const { return home_dir; }
};

struct CheckResult {
  ClientStatus status = ClientStatus::NotInitialized;
  CheckResult() = default;
  CheckResult(ClientStatus value) : status(value) {}
};

struct ConnectResult {
  ClientStatus status = ClientStatus::NotInitialized;
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

struct TerminalOpenArgs {
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
  std::string term = "xterm-256color";
};

struct TerminalReadArgs {
  size_t max_bytes = 4096;
};

struct TerminalWriteArgs {
  std::string input = "";
};

struct TerminalResizeArgs {
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
};

struct TerminalCloseArgs {
  bool force = false;
};

struct TerminalStatusArgs {};

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
