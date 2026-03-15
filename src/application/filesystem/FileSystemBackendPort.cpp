#include "application/filesystem/FileSystemBackendPort.hpp"

#include "domain/client/ClientPort.hpp"
#include "foundation/tools/enum_related.hpp"

#include <algorithm>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

namespace AMApplication::filesystem::runtime {
namespace {
using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;
using ClientHandle = AMDomain::client::ClientHandle;
using ParsedClientPath = AMDomain::client::ParsedClientPath;
using ConfirmPolicy = AMDomain::filesystem::ConfirmPolicy;
using RemoveRequest = AMDomain::filesystem::RemoveRequest;
using RemoveResult = AMDomain::filesystem::RemoveResult;
using StatPathsResult = AMDomain::filesystem::StatPathsResult;
using ListPathResult = AMDomain::filesystem::ListPathResult;
using GetSizeResult = AMDomain::filesystem::GetSizeResult;
using FindResult = AMDomain::filesystem::FindResult;
using WalkQueryResult = AMDomain::filesystem::WalkQueryResult;
using TreeQueryResult = AMDomain::filesystem::TreeQueryResult;
using RealpathQueryResult = AMDomain::filesystem::RealpathQueryResult;
using WalkPayload = AMDomain::filesystem::WalkPayload;
using ListPathPayload = AMDomain::filesystem::ListPathPayload;
using SizeEntry = AMDomain::filesystem::SizeEntry;
using RealpathEntry = AMDomain::filesystem::RealpathEntry;

/**
 * @brief Return true when the external interrupt flag is terminated.
 */
bool IsInterrupted_(const amf &interrupt_flag) {
  return interrupt_flag && !interrupt_flag->IsRunning();
}

/**
 * @brief Merge per-item operation status by keeping latest failure.
 */
ECM MergeStatus_(const ECM &current, const ECM &next) {
  return isok(next) ? current : next;
}

/**
 * @brief Port-driven filesystem backend implementation.
 */
class DefaultFileSystemBackend final : public IFileSystemBackendPort {
public:
  /**
   * @brief Construct backend from split runtime/lifecycle/path client ports.
   */
  DefaultFileSystemBackend(AMDomain::client::IClientRuntimePort &runtime_port,
                           AMDomain::client::IClientLifecyclePort &lifecycle_port,
                           AMDomain::client::IClientPathPort &path_port)
      : runtime_port_(runtime_port), lifecycle_port_(lifecycle_port),
        path_port_(path_port) {}

  ECM CheckClients(const std::vector<std::string> &nicknames, bool detail,
                   amf interrupt_flag) override {
    (void)detail;
    if (IsInterrupted_(interrupt_flag)) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    std::vector<std::string> targets = nicknames;
    if (targets.empty()) {
      targets = runtime_port_.GetClientNames();
    }
    if (targets.empty()) {
      return Err(EC::ClientNotFound, "No client to check");
    }

    ECM status = Ok();
    for (const auto &name : targets) {
      if (IsInterrupted_(interrupt_flag)) {
        return Err(EC::Terminate, "Interrupted by user");
      }
      auto [rcm, _client] =
          lifecycle_port_.CheckClient(name, true, interrupt_flag);
      status = MergeStatus_(status, rcm);
    }
    return status;
  }

  ECM ListClients(bool detail, amf interrupt_flag) override {
    return CheckClients({}, detail, interrupt_flag);
  }

  ECM DisconnectClients(const std::vector<std::string> &nicknames) override {
    if (nicknames.empty()) {
      return Err(EC::InvalidArg, "No nickname is given");
    }
    ECM status = Ok();
    for (const auto &name : nicknames) {
      status = MergeStatus_(status, lifecycle_port_.RemoveClient(name));
    }
    return status;
  }

  ECM StatPaths(const std::vector<std::string> &paths, amf interrupt_flag,
                int timeout_ms) override {
    return QueryStatPaths(paths, interrupt_flag, timeout_ms).rcm;
  }

  ECM ListPath(const std::string &path, bool list_like, bool show_all,
               amf interrupt_flag, int timeout_ms) override {
    return QueryListPath(path, list_like, show_all, interrupt_flag, timeout_ms)
        .rcm;
  }

  ECM GetSize(const std::vector<std::string> &paths, amf interrupt_flag,
              int timeout_ms) override {
    return QueryGetSize(paths, interrupt_flag, timeout_ms).rcm;
  }

  ECM Find(const std::string &path, SearchType type, amf interrupt_flag,
           int timeout_ms) override {
    return QueryFind(path, type, interrupt_flag, timeout_ms).rcm;
  }

  ECM Mkdir(const std::vector<std::string> &paths, amf interrupt_flag,
            int timeout_ms) override {
    if (paths.empty()) {
      return Err(EC::InvalidArg, "No path is given");
    }
    ECM status = Ok();
    for (const auto &raw : paths) {
      if (IsInterrupted_(interrupt_flag)) {
        return Err(EC::Terminate, "Interrupted by user");
      }
      auto [parse_rcm, client, abs_path] = ResolvePath_(raw, interrupt_flag);
      if (!isok(parse_rcm) || !client) {
        status = MergeStatus_(status, parse_rcm);
        continue;
      }
      status = MergeStatus_(status, client->IOPort().mkdirs(abs_path, timeout_ms, -1));
    }
    return status;
  }

  ECM Remove(const std::vector<std::string> &paths, bool permanent, bool force,
             bool quiet, amf interrupt_flag, int timeout_ms) override {
    RemoveRequest request = {};
    request.paths = paths;
    request.permanent = permanent;
    request.confirm_policy =
        force ? ConfirmPolicy::AutoApprove : ConfirmPolicy::RequireConfirm;
    request.quiet = quiet;
    request.timeout_ms = timeout_ms;
    return ExecuteRemove(request, interrupt_flag).rcm;
  }

  /**
   * @brief Execute remove request with explicit confirmation policy.
   */
  RemoveResult ExecuteRemove(const RemoveRequest &request,
                             amf interrupt_flag) override {
    if (request.paths.empty()) {
      return {Err(EC::InvalidArg, "No path is given"), {}};
    }
    if (request.confirm_policy == ConfirmPolicy::DenyIfConfirmNeeded) {
      return {Err(EC::ConfigCanceled, "remove denied by confirmation policy"),
              {}};
    }
    if (request.confirm_policy == ConfirmPolicy::RequireConfirm) {
      return {Err(EC::ConfigCanceled,
                  "remove requires explicit confirmation in interface layer"),
              {}};
    }
    ECM status = Ok();
    for (const auto &raw : request.paths) {
      if (IsInterrupted_(interrupt_flag)) {
        return {Err(EC::Terminate, "Interrupted by user"), {}};
      }
      auto [parse_rcm, client, abs_path] = ResolvePath_(raw, interrupt_flag);
      if (!isok(parse_rcm) || !client) {
        status = MergeStatus_(status, parse_rcm);
        continue;
      }
      if (request.permanent) {
        auto [rcm, _errors] =
            client->IOPort().remove(abs_path, nullptr, request.timeout_ms, -1);
        status = MergeStatus_(status, rcm);
      } else {
        status = MergeStatus_(
            status, client->IOPort().saferm(abs_path, request.timeout_ms, -1));
      }
    }
    return {status, {}};
  }

  ECM Walk(const std::string &path, bool only_file, bool only_dir,
           bool show_all, bool ignore_special_file, bool quiet,
           amf interrupt_flag, int timeout_ms) override {
    return QueryWalk(path, only_file, only_dir, show_all, ignore_special_file,
                     quiet, interrupt_flag, timeout_ms)
        .rcm;
  }

  ECM Tree(const std::string &path, int max_depth, bool only_dir,
           bool show_all, bool ignore_special_file, bool quiet,
           amf interrupt_flag, int timeout_ms) override {
    return QueryTree(path, max_depth, only_dir, show_all, ignore_special_file,
                     quiet, interrupt_flag, timeout_ms)
        .rcm;
  }

  ECM Realpath(const std::string &path, amf interrupt_flag,
               int timeout_ms) override {
    return QueryRealpath(path, interrupt_flag, timeout_ms).rcm;
  }

  /**
   * @brief Query stat information for multiple paths with typed payload.
   */
  StatPathsResult QueryStatPaths(const std::vector<std::string> &paths,
                                 amf interrupt_flag,
                                 int timeout_ms) override {
    if (paths.empty()) {
      return {Err(EC::InvalidArg, "No path is given"), {}};
    }
    ECM status = Ok();
    std::vector<PathInfo> items = {};
    for (const auto &raw : paths) {
      if (IsInterrupted_(interrupt_flag)) {
        return {Err(EC::Terminate, "Interrupted by user"), std::move(items)};
      }
      auto [parse_rcm, client, abs_path] = ResolvePath_(raw, interrupt_flag);
      if (!isok(parse_rcm) || !client) {
        status = MergeStatus_(status, parse_rcm);
        continue;
      }
      auto [rcm, info] = client->IOPort().stat(abs_path, false, timeout_ms, -1);
      status = MergeStatus_(status, rcm);
      if (isok(rcm)) {
        items.emplace_back(std::move(info));
      }
    }
    return {status, std::move(items)};
  }

  /**
   * @brief Query list payload for one path with target metadata and entries.
   */
  ListPathResult QueryListPath(const std::string &path, bool list_like,
                               bool show_all, amf interrupt_flag,
                               int timeout_ms) override {
    (void)list_like;
    const std::string raw = path.empty() ? "." : path;
    auto [parse_rcm, client, abs_path] = ResolvePath_(raw, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }
    auto [rcm, info] = client->IOPort().stat(abs_path, false, timeout_ms, -1);
    if (!isok(rcm)) {
      return {rcm, {}};
    }
    ListPathPayload payload = {};
    payload.target = info;
    if (info.type != PathType::DIR) {
      return {Ok(), std::move(payload)};
    }
    auto [list_rcm, entries] = client->IOPort().listdir(abs_path, timeout_ms, -1);
    if (!isok(list_rcm)) {
      return {list_rcm, std::move(payload)};
    }
    if (!show_all) {
      entries.erase(
          std::remove_if(entries.begin(), entries.end(),
                         [](const PathInfo &item) {
                           return item.name == "." || item.name == "..";
                         }),
          entries.end());
    }
    payload.entries = std::move(entries);
    return {Ok(), std::move(payload)};
  }

  /**
   * @brief Query recursive sizes for multiple paths with typed payload.
   */
  GetSizeResult QueryGetSize(const std::vector<std::string> &paths,
                             amf interrupt_flag, int timeout_ms) override {
    if (paths.empty()) {
      return {Err(EC::InvalidArg, "No path is given"), {}};
    }
    ECM status = Ok();
    std::vector<SizeEntry> items = {};
    for (const auto &raw : paths) {
      if (IsInterrupted_(interrupt_flag)) {
        return {Err(EC::Terminate, "Interrupted by user"), std::move(items)};
      }
      auto [parse_rcm, client, abs_path] = ResolvePath_(raw, interrupt_flag);
      if (!isok(parse_rcm) || !client) {
        status = MergeStatus_(status, parse_rcm);
        continue;
      }
      auto [stat_rcm, _stat_info] =
          client->IOPort().stat(abs_path, false, timeout_ms, -1);
      if (!isok(stat_rcm)) {
        status = MergeStatus_(status, stat_rcm);
        continue;
      }
      const int64_t size = client->IOPort().getsize(abs_path, true, timeout_ms, -1);
      SizeEntry item = {};
      item.raw = raw;
      item.abs_path = abs_path;
      item.size = size;
      items.emplace_back(std::move(item));
    }
    return {status, std::move(items)};
  }

  /**
   * @brief Query find records for one pattern path.
   */
  FindResult QueryFind(const std::string &path, SearchType type,
                       amf interrupt_flag, int timeout_ms) override {
    auto [parse_rcm, client, abs_path] = ResolvePath_(path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }
    auto [stat_rcm, _stat_info] =
        client->IOPort().stat(abs_path, false, timeout_ms, -1);
    if (!isok(stat_rcm)) {
      return {stat_rcm, {}};
    }
    return {Ok(), client->IOPort().find(abs_path, type, timeout_ms, -1)};
  }

  /**
   * @brief Query walk records and flatten filtered entries.
   */
  WalkQueryResult QueryWalk(const std::string &path, bool only_file,
                            bool only_dir, bool show_all,
                            bool ignore_special_file, bool quiet,
                            amf interrupt_flag, int timeout_ms) override {
    (void)quiet;
    auto [parse_rcm, client, abs_path] = ResolvePath_(path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }

    auto [rcm, walk_res] = client->IOPort().iwalk(
        abs_path, show_all, ignore_special_file, nullptr, timeout_ms, -1);
    WalkPayload payload = {};
    payload.errors = walk_res.second;
    for (const auto &info : walk_res.first) {
      if (only_file && info.type != PathType::FILE) {
        continue;
      }
      if (only_dir && info.type != PathType::DIR) {
        continue;
      }
      payload.items.emplace_back(info);
    }
    return {rcm, std::move(payload)};
  }

  /**
   * @brief Query tree records and flatten branch results.
   */
  TreeQueryResult QueryTree(const std::string &path, int max_depth,
                            bool only_dir, bool show_all,
                            bool ignore_special_file, bool quiet,
                            amf interrupt_flag, int timeout_ms) override {
    (void)quiet;
    auto [parse_rcm, client, abs_path] = ResolvePath_(path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }

    auto [rcm, walk_res] = client->IOPort().walk(abs_path, max_depth, show_all,
                                                 ignore_special_file, nullptr,
                                                 timeout_ms, -1);
    WalkPayload payload = {};
    payload.errors = walk_res.second;
    for (const auto &branch : walk_res.first) {
      for (const auto &info : branch.second) {
        if (only_dir && info.type != PathType::DIR) {
          continue;
        }
        payload.items.emplace_back(info);
      }
    }
    return {rcm, std::move(payload)};
  }

  /**
   * @brief Query realpath with typed result payload.
   */
  RealpathQueryResult QueryRealpath(const std::string &path, amf interrupt_flag,
                                    int timeout_ms) override {
    auto [parse_rcm, client, abs_path] = ResolvePath_(path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }
    auto [rcm, real] = client->IOPort().realpath(abs_path, timeout_ms, -1);
    if (!isok(rcm)) {
      return {rcm, {}};
    }
    RealpathEntry entry = {};
    entry.raw = path;
    entry.abs_path = real;
    return {Ok(), std::move(entry)};
  }

  ECM TestRtt(int times, amf interrupt_flag) override {
    if (IsInterrupted_(interrupt_flag)) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    auto client = runtime_port_.GetCurrentClient();
    if (!client) {
      return Err(EC::ClientNotFound, "Current client not found");
    }
    (void)client->IOPort().GetRTT(times);
    return Ok();
  }

  ECM Cd(const std::string &path, amf interrupt_flag,
         bool from_history) override {
    (void)from_history;
    auto [parse_rcm, client, abs_path] =
        ResolvePath_(path.empty() ? "." : path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return parse_rcm;
    }
    auto [stat_rcm, stat_info] = client->IOPort().stat(abs_path, false, -1, -1);
    if (!isok(stat_rcm)) {
      return stat_rcm;
    }
    if (stat_info.type != PathType::DIR) {
      return Err(EC::NotADirectory, "Target is not a directory");
    }

    const std::string nickname = client->ConfigPort().GetNickname();
    auto state = path_port_.GetWorkdirState(nickname);
    state.cwd = abs_path;
    auto set_rcm = path_port_.SetWorkdirState(nickname, state);
    if (!isok(set_rcm)) {
      return set_rcm;
    }
    runtime_port_.SetCurrentClient(client);
    return Ok();
  }

  std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms,
           amf interrupt_flag) override {
    if (IsInterrupted_(interrupt_flag)) {
      return {Err(EC::Terminate, "Interrupted by user"), {"", -1}};
    }
    auto client = runtime_port_.GetCurrentClient();
    if (!client) {
      return {Err(EC::ClientNotFound, "Current client not found"), {"", -1}};
    }
    return client->IOPort().ConductCmd(cmd, max_time_ms);
  }

private:
  /**
   * @brief Resolve one raw filesystem token into client handle + absolute path.
   */
  std::tuple<ECM, ClientHandle, std::string>
  ResolvePath_(const std::string &raw, amf interrupt_flag) {
    if (IsInterrupted_(interrupt_flag)) {
      return {Err(EC::Terminate, "Interrupted by user"), nullptr, ""};
    }
    ParsedClientPath parsed = path_port_.ParseScopedPath(raw, interrupt_flag);
    const ECM &parse_rcm = std::get<3>(parsed);
    if (!isok(parse_rcm)) {
      return {parse_rcm, nullptr, ""};
    }
    auto client = std::get<2>(parsed);
    if (!client) {
      return {Err(EC::ClientNotFound, "Resolved client is null"), nullptr, ""};
    }
    const std::string &relative = std::get<1>(parsed);
    const std::string abs_path = path_port_.BuildAbsolutePath(client, relative);
    return {Ok(), client, abs_path};
  }

  AMDomain::client::IClientRuntimePort &runtime_port_;
  AMDomain::client::IClientLifecyclePort &lifecycle_port_;
  AMDomain::client::IClientPathPort &path_port_;
};
} // namespace

std::shared_ptr<IFileSystemBackendPort> CreateDefaultFileSystemBackend(
    AMDomain::client::IClientRuntimePort &runtime_port,
    AMDomain::client::IClientLifecyclePort &lifecycle_port,
    AMDomain::client::IClientPathPort &path_port) {
  return std::make_shared<DefaultFileSystemBackend>(runtime_port, lifecycle_port,
                                                    path_port);
}
} // namespace AMApplication::filesystem::runtime
