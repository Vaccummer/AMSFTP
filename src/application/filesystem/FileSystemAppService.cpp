#include "application/filesystem/FilesystemAppService.hpp"
#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "application/filesystem/detail/FilesystemMatchTools.hpp"
#include "application/log/ProgramTrace.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace AMApplication::filesystem {
namespace {
using ClientHandle = AMDomain::client::ClientHandle;
using ClientMetaData = AMDomain::host::ClientMetaData;

[[nodiscard]] ECM EnsureFilesystemClientReady_(const ClientHandle &client,
                                               const char *operation) {
  return AMApplication::client::ClientAppService::EnsureTerminalInactive(
      client, operation ? std::string(operation) : std::string());
}

bool IsDescendantPath_(const std::string &candidate,
                       const std::string &ancestor) {
  if (candidate.empty() || ancestor.empty()) {
    return false;
  }
  const std::vector<std::string> candidate_parts = AMPath::split(candidate);
  const std::vector<std::string> ancestor_parts = AMPath::split(ancestor);
  if (candidate_parts.empty() || ancestor_parts.empty()) {
    return false;
  }
  if (candidate_parts.size() < ancestor_parts.size()) {
    return false;
  }
  for (size_t i = 0; i < ancestor_parts.size(); ++i) {
    if (candidate_parts[i] != ancestor_parts[i]) {
      return false;
    }
  }
  return true;
}

bool IsStopError_(ErrorCode ec) {
  return ec == ErrorCode::Terminate || ec == ErrorCode::OperationTimeout;
}

std::optional<ECM> BuildRequestStopECM_(const ControlComponent &control,
                                        std::string operation = "",
                                        std::string target = "") {
  if (operation.empty()) {
    operation = "filesystem.stop";
  }
  return control.BuildRequestECM(std::move(operation), std::move(target));
}

void AddPathError_(std::vector<std::pair<PathTarget, ECM>> *errors, ECM *status,
                   const PathTarget &path, const ECM &rcm) {
  if (errors) {
    errors->push_back({path, rcm});
  }
  if (status && !(rcm)) {
    *status = rcm;
  }
}

void AddSafermError_(std::vector<std::pair<PathTarget, ECM>> *errors,
                     ECM *status, const PathTarget &path, const ECM &rcm) {
  AddPathError_(errors, status, path, rcm);
}

std::string BuildSuffixName_(const std::string &base_name,
                             const std::string &ext_name, size_t index) {
  const std::string stem =
      (index == 0) ? base_name : AMStr::fmt("{}({})", base_name, index);
  if (ext_name.empty()) {
    return stem;
  }
  return AMStr::fmt("{}.{}", stem, ext_name);
}
} // namespace

std::vector<PathInfo> CompactMatchedPaths_(const std::vector<PathInfo> &raw) {
  std::unordered_map<std::string, PathInfo> dedup = {};
  dedup.reserve(raw.size());
  for (const auto &item : raw) {
    const std::string key = item.path;
    if (key.empty()) {
      continue;
    }
    auto it = dedup.find(key);
    if (it == dedup.end()) {
      dedup.emplace(key, item);
      continue;
    }
    if (it->second.type != PathType::DIR && item.type == PathType::DIR) {
      it->second = item;
    }
  }

  std::vector<PathInfo> candidates = {};
  candidates.reserve(dedup.size());
  for (auto &entry : dedup) {
    candidates.push_back(std::move(entry.second));
  }
  std::stable_sort(candidates.begin(), candidates.end(),
                   [](const PathInfo &lhs, const PathInfo &rhs) {
                     const size_t lhs_depth = AMPath::split(lhs.path).size();
                     const size_t rhs_depth = AMPath::split(rhs.path).size();
                     if (lhs_depth != rhs_depth) {
                       return lhs_depth < rhs_depth;
                     }
                     return lhs.path < rhs.path;
                   });

  std::vector<PathInfo> compacted = {};
  compacted.reserve(candidates.size());
  std::vector<std::string> dir_roots = {};
  for (const auto &item : candidates) {
    const std::string item_key = item.path;
    bool covered = false;
    for (const auto &root : dir_roots) {
      if (IsDescendantPath_(item_key, root)) {
        covered = true;
        break;
      }
    }
    if (covered) {
      continue;
    }
    compacted.push_back(item);
    if (item.type == PathType::DIR) {
      dir_roots.push_back(item_key);
    }
  }
  std::stable_sort(compacted.begin(), compacted.end(),
                   [](const PathInfo &lhs, const PathInfo &rhs) {
                     return lhs.path < rhs.path;
                   });
  return compacted;
}

FilesystemAppService::FilesystemAppService(
    FilesystemArg arg, ClientAppService *client_service,
    AMApplication::log::LoggerAppService *logger)
    : FilesystemAppBaseService(std::move(arg), client_service),
      logger_(logger) {}

void FilesystemAppService::ClearCache() { ClearBaseIOCache(); }

void FilesystemAppService::TraceFs_(const ECM &rcm, const PathTarget &target,
                                    const std::string &action,
                                    const std::string &message) const {
  const std::string display =
      AMStr::fmt("{}@{}",
                 target.nickname.empty() ? std::string("local")
                                         : target.nickname,
                 target.path.empty() ? std::string(".") : target.path);
  TraceFs_(rcm, display, action, message);
}

void FilesystemAppService::TraceFs_(const ECM &rcm, const std::string &target,
                                    const std::string &action,
                                    const std::string &message) const {
  std::string detail = message;
  if (!(rcm)) {
    if (!detail.empty()) {
      detail += "; ";
    }
    detail += AMStr::fmt("result={} error={}", AMStr::ToString(rcm.code),
                         rcm.msg());
  }
  AMApplication::log::ProgramTrace(
      logger_, rcm, target.empty() ? std::string("<path>") : target, action,
      detail);
}

ECMData<ClientHandle>
FilesystemAppService::GetClient(const std::string &nickname,
                                const ControlComponent &control) {
  if (!client_service_) {
    return {nullptr,
            Err(EC::InvalidHandle, "filesystem", "", "client service is null")};
  }
  if (nickname.empty()) {
    return {nullptr,
            Err(EC::InvalidArg, "filesystem", "", "Client nickname is empty")};
  }
  return client_service_->EnsureClient(nickname, control, true, false);
}

ECMData<ClientHandle>
FilesystemAppService::GetTransferClient_(const std::string &nickname) {
  if (!client_service_) {
    return {nullptr,
            Err(EC::InvalidHandle, "filesystem", "", "client service is null")};
  }
  if (nickname.empty()) {
    return {nullptr,
            Err(EC::InvalidArg, "filesystem", "", "Client nickname is empty")};
  }
  return client_service_->AcquireTransferClient(nickname);
}

ECMData<ResolvedPath>
FilesystemAppService::ResolvePath_(const PathTarget &target,
                                   const ControlComponent &control,
                                   ClientHandle preferred_client) {
  if (!client_service_) {
    return {ResolvedPath{},
            Err(EC::InvalidHandle, "filesystem", "", "client service is null")};
  }

  ResolvedPath out = {};
  out.target = target;
  if (out.target.path.empty()) {
    out.target.path = ".";
  }
  out.target.is_wildcard =
      AMDomain::filesystem::service::HasWildcard(out.target.path);
  out.target.is_user_path =
      !out.target.path.empty() && out.target.path.front() == '~';

  if (preferred_client) {
    out.client = preferred_client;
    if (out.target.nickname.empty()) {
      out.target.nickname = preferred_client->ConfigPort().GetNickname();
    }
  } else {
    if (out.target.nickname.empty()) {
      out.target.nickname = client_service_->CurrentNickname();
    }
    auto get_result = GetClient(out.target.nickname, control);
    if (!(get_result.rcm) || !get_result.data) {
      return {ResolvedPath{},
              (get_result.rcm) ? Err(EC::InvalidHandle, "filesystem", "",
                                     "Resolved client is null")
                               : get_result.rcm};
    }
    out.client = get_result.data;
  }

  auto abs_result = ResolveAbsolutePath(out.client, out.target.path, control);
  if (!(abs_result.rcm)) {
    return {ResolvedPath{}, abs_result.rcm};
  }
  out.abs_path = abs_result.data;
  out.target.path = out.abs_path;
  out.target.is_wildcard =
      AMDomain::filesystem::service::HasWildcard(out.target.path);
  out.target.is_user_path =
      !out.target.path.empty() && out.target.path.front() == '~';

  return {std::move(out), OK};
}

ECMData<std::string>
FilesystemAppService::GetClientHome(ClientHandle client,
                                    const ControlComponent &control) {
  if (!client) {
    return {"",
            Err(EC::InvalidHandle, "filesystem", "", "Client handle is null")};
  }

  std::string home = AMStr::Strip(client->ConfigPort().GetHomeDir());
  if (home.empty()) {
    auto update_result = client->IOPort().UpdateHomeDir({}, control);
    if (!(update_result.rcm)) {
      return {"", update_result.rcm};
    }
    home = AMStr::Strip(update_result.data.home_dir);
    if (home.empty()) {
      home = AMStr::Strip(client->ConfigPort().GetHomeDir());
    } else {
      client->ConfigPort().SetHomeDir(home);
    }
  }

  if (home.empty()) {
    return {"",
            Err(EC::CommonFailure, "filesystem", "",
                "Client home directory is empty")};
  }
  return {home, OK};
}

ECMData<std::string>
FilesystemAppService::GetClientCwd(const ClientHandle &client,
                                   const ControlComponent &control) {
  if (!client) {
    return {"",
            Err(EC::InvalidHandle, "filesystem", "", "Client handle is null")};
  }
  auto meta_cwd = ClientAppService::GetClientCwd(client);
  if (meta_cwd.rcm && !AMStr::Strip(meta_cwd.data).empty()) {
    const std::string normalized_cwd = AMPath::NormalizeJoinedPath(
        AMDomain::filesystem::service::NormalizePath(meta_cwd.data), "/");
    return {normalized_cwd.empty() ? meta_cwd.data : normalized_cwd, OK};
  }
  auto home_res = GetClientHome(client, control);
  if (!(home_res.rcm)) {
    return {"", home_res.rcm};
  }
  return {home_res.data, OK};
}

ECMData<std::string>
FilesystemAppService::ResolveAbsolutePath(ClientHandle client,
                                          const std::string &raw_path,
                                          const ControlComponent &control) {
  if (!client) {
    return {"",
            Err(EC::InvalidHandle, "filesystem", "", "Client handle is null")};
  }
  const ECM guard_rcm = EnsureFilesystemClientReady_(client, __func__);
  if (!(guard_rcm)) {
    return {"", guard_rcm};
  }
  auto home_result = GetClientHome(client, control);
  if (!(home_result.rcm)) {
    return {"", home_result.rcm};
  }
  auto cwd_result = GetClientCwd(client, control);
  if (!(cwd_result.rcm)) {
    return {"", cwd_result.rcm};
  }

  const std::string input = raw_path.empty() ? "." : raw_path;
  const std::string abs_path =
      AMPath::abspath(input, true, home_result.data, cwd_result.data);
  const std::string normalized_abs =
      AMDomain::filesystem::service::NormalizePath(abs_path);
  return {AMPath::NormalizeJoinedPath(normalized_abs, "/"), OK};
}

ECMData<PathTarget>
FilesystemAppService::GetCwd(const ControlComponent &control) {
  PathTarget out = {};
  if (!client_service_) {
    return {std::move(out),
            Err(EC::InvalidHandle, "filesystem", "", "client service is null")};
  }

  ClientHandle client = client_service_->GetCurrentClient();
  if (!client) {
    client = client_service_->GetLocalClient();
  }
  if (!client) {
    return {std::move(out),
            Err(EC::ClientNotFound, "filesystem", "",
                "Current client not found")};
  }
  auto res = GetClientCwd(client, control);
  if (!(res.rcm)) {
    return {std::move(out), res.rcm};
  }
  out.nickname = client->ConfigPort().GetNickname();
  out.path = res.data;
  out.is_wildcard = AMDomain::filesystem::service::HasWildcard(out.path);
  out.is_user_path = !out.path.empty() && out.path.front() == '~';
  return {std::move(out), OK};
}

ECM FilesystemAppService::EnsureClientWorkdir(ClientHandle client,
                                              const ControlComponent &control) {
  if (!client) {
    return Err(EC::InvalidHandle, "filesystem", "", "Client handle is null");
  }
  auto metadata_opt = ClientAppService::GetClientMetadata(client);
  if (!metadata_opt.has_value()) {
    return Err(EC::CommonFailure, "filesystem", "", "Client metadata not found");
  }
  ClientMetaData metadata = *metadata_opt;

  const std::string normalized_home =
      AMDomain::filesystem::service::NormalizePath(
          AMStr::Strip(client->ConfigPort().GetHomeDir()));
  const auto try_resolve_dir =
      [&](const std::string &raw_candidate) -> ECMData<std::string> {
    const std::string normalized_candidate =
        AMDomain::filesystem::service::NormalizePath(
            AMStr::Strip(raw_candidate));
    if (normalized_candidate.empty()) {
      return {"", Err(EC::InvalidArg, "filesystem", "",
                      "empty workdir candidate")};
    }
    auto absolute_result =
        ResolveAbsolutePath(client, normalized_candidate, control);
    if (!(absolute_result.rcm)) {
      return {"", absolute_result.rcm};
    }
    std::string absolute_path = AMPath::NormalizeJoinedPath(
        AMDomain::filesystem::service::NormalizePath(absolute_result.data),
        "/");
    if (absolute_path.empty()) {
      return {"", Err(EC::InvalidArg, "filesystem", "",
                      "invalid workdir candidate")};
    }

    auto stat_result = client->IOPort().stat({absolute_path, false}, control);
    if (!(stat_result.rcm)) {
      return {"", stat_result.rcm};
    }
    if (stat_result.data.info.type != PathType::DIR) {
      return {"", Err(EC::NotADirectory, "filesystem", "",
                      AMStr::fmt("Not a directory: {}", absolute_path))};
    }

    std::string resolved = AMPath::NormalizeJoinedPath(
        AMDomain::filesystem::service::NormalizePath(
            stat_result.data.info.path),
        "/");
    if (resolved.empty()) {
      resolved = absolute_path;
    }
    return {resolved, OK};
  };

  std::string resolved_workdir = {};
  if (!AMStr::Strip(metadata.cwd).empty()) {
    auto cwd_result = try_resolve_dir(metadata.cwd);
    if ((cwd_result.rcm)) {
      resolved_workdir = std::move(cwd_result.data);
    }
  }
  if (resolved_workdir.empty() && !AMStr::Strip(metadata.login_dir).empty()) {
    auto login_result = try_resolve_dir(metadata.login_dir);
    if ((login_result.rcm)) {
      resolved_workdir = std::move(login_result.data);
    }
  }
  if (resolved_workdir.empty() && !normalized_home.empty()) {
    auto home_result = try_resolve_dir(normalized_home);
    if ((home_result.rcm)) {
      resolved_workdir = std::move(home_result.data);
    }
  }

  if (resolved_workdir.empty()) {
    resolved_workdir = normalized_home.empty() ? "." : normalized_home;
  }

  metadata.cwd = resolved_workdir;
  return ClientAppService::SetClientMetadata(client, metadata);
}

ECMData<PathTarget> FilesystemAppService::PeekCdHistory() const {
  auto history = cd_history_.lock();
  auto list = history.load();
  if (list.empty()) {
    return {PathTarget{},
            Err(EC::InvalidArg, "filesystem", "", "cd history is empty")};
  }
  return {list.front(), OK};
}

ECM FilesystemAppService::ChangeDir(PathTarget path,
                                    const ControlComponent &control,
                                    bool from_history) {
  auto resolved_result = ResolvePath_(path, control);
  if (!resolved_result.rcm || !resolved_result.data.client) {
    const ECM rcm =
        (resolved_result.rcm) ? Err(EC::InvalidHandle, "filesystem", "",
                                    "Resolved client is null")
                              : resolved_result.rcm;
    TraceFs_(rcm, path, "filesystem.cd", "resolve failed");
    return rcm;
  }
  const ResolvedPath &resolved = resolved_result.data;
  ClientHandle client = resolved.client;

  auto metadata_opt = ClientAppService::GetClientMetadata(client);
  if (!metadata_opt.has_value()) {
    return {EC::CommonFailure, "filesystem", "", "Client metadata not found"};
  }
  ClientMetaData metadata = *metadata_opt;
  const std::string prev_cwd = metadata.cwd;
  const std::string abs_target = resolved.abs_path;
  auto stat_result = client->IOPort().stat({abs_target, false}, control);
  if (!stat_result.rcm) {
    TraceFs_(stat_result.rcm, resolved.target, "filesystem.cd", "stat failed");
    return stat_result.rcm;
  }
  if (stat_result.data.info.type != PathType::DIR) {
    const ECM rcm = {EC::NotADirectory, "ChangeDir", abs_target,
                     "Not a directory"};
    TraceFs_(rcm, resolved.target, "filesystem.cd");
    return rcm;
  }
  metadata.cwd = AMPath::NormalizeJoinedPath(
      AMDomain::filesystem::service::NormalizePath(stat_result.data.info.path),
      "/");
  const ECM set_meta_rcm =
      ClientAppService::SetClientMetadata(client, metadata);
  if (!set_meta_rcm) {
    TraceFs_(set_meta_rcm, resolved.target, "filesystem.cd",
             "failed to update metadata");
    return set_meta_rcm;
  }

  client_service_->SetCurrentClient(client);

  if (!from_history && !prev_cwd.empty() &&
      prev_cwd != stat_result.data.info.path) {
    auto history = cd_history_.lock();
    auto list = history.load();
    PathTarget entry = {};
    entry.nickname = client->ConfigPort().GetNickname();
    entry.path = prev_cwd;
    list.push_front(std::move(entry));
    const size_t limit =
        static_cast<size_t>(std::max(1, GetInitArg().max_cd_history));
    while (list.size() > limit) {
      list.pop_back();
    }
    history.store(std::move(list));
  }
  TraceFs_(OK, resolved.target, "filesystem.cd",
           AMStr::fmt("from={} to={}", prev_cwd, metadata.cwd));
  return OK;
}

ECMData<PathEntry> FilesystemAppService::StatEntry(
    const PathTarget &target, const ControlComponent &control, bool trace_link,
    ClientHandle preferred_client) {
  auto resolved = ResolvePath_(target, control, preferred_client);
  if (!(resolved.rcm) || !resolved.data.client) {
    return {PathEntry{},
            (resolved.rcm) ? Err(EC::InvalidHandle, "filesystem", "",
                                 "Resolved client is null")
                           : resolved.rcm};
  }

  auto stat_result =
      BaseStat(resolved.data.client, resolved.data.target.nickname,
               resolved.data.abs_path, control, trace_link);
  if (!(stat_result.rcm)) {
    return {PathEntry{}, stat_result.rcm};
  }

  PathEntry out = {};
  out.resolved = std::move(resolved.data);
  out.info = std::move(stat_result.data);
  return {std::move(out), OK};
}

ECMData<PathInfo> FilesystemAppService::Stat(const PathTarget &path,
                                             const ControlComponent &control,
                                             bool trace_link,
                                             ClientHandle preferred_client) {
  auto entry_result = StatEntry(path, control, trace_link, preferred_client);
  if (!(entry_result.rcm)) {
    return {PathInfo{}, entry_result.rcm};
  }
  return {entry_result.data.info, OK};
}

ECMData<std::vector<PathInfo>>
FilesystemAppService::Listdir(const PathTarget &path,
                              const ControlComponent &control,
                              ClientHandle preferred_client) {
  auto resolved_result = ResolvePath_(path, control, preferred_client);
  if (!(resolved_result.rcm) || !resolved_result.data.client) {
    return {{},
            (resolved_result.rcm)
                ? Err(EC::InvalidHandle, "filesystem", "",
                      "Resolved client is null")
                : resolved_result.rcm};
  }
  const auto &resolved = resolved_result.data;
  return BaseListdir(resolved.client, resolved.target.nickname,
                     resolved.abs_path, control);
}

ECMData<std::vector<std::string>>
FilesystemAppService::ListNames(const PathTarget &path,
                                const ControlComponent &control,
                                ClientHandle preferred_client) {
  auto resolved_result = ResolvePath_(path, control, preferred_client);
  if (!(resolved_result.rcm) || !resolved_result.data.client) {
    return {{},
            (resolved_result.rcm)
                ? Err(EC::InvalidHandle, "filesystem", "",
                      "Resolved client is null")
                : resolved_result.rcm};
  }
  const auto &resolved = resolved_result.data;
  return BaseListNames(resolved.client, resolved.target.nickname,
                       resolved.abs_path, control);
}

ECM FilesystemAppService::Mkdirs(const PathTarget &path,
                                 const ControlComponent &control,
                                 ClientHandle preferred_client) {
  auto resolved_result = ResolvePath_(path, control, preferred_client);
  if (!(resolved_result.rcm) || !resolved_result.data.client) {
    return (resolved_result.rcm)
               ? Err(EC::InvalidHandle, "filesystem", "",
                     "Resolved client is null")
               : resolved_result.rcm;
  }

  const auto &resolved = resolved_result.data;
  ClientHandle client = resolved.client;
  ECM rcm = client->IOPort().mkdirs({resolved.abs_path}, control).rcm;
  TraceFs_(rcm, resolved.target, "filesystem.mkdirs");
  return rcm;
}

ECMData<double> FilesystemAppService::TestRTT(const std::string &nickname,
                                              const ControlComponent &control,
                                              int times) {
  auto get_result = GetClient(nickname, control);
  if (!(get_result.rcm) || !get_result.data) {
    return {-1.0, (get_result.rcm)
                      ? Err(EC::InvalidHandle, "filesystem", "", "Client is null")
                      : get_result.rcm};
  }
  const ECM guard_rcm = EnsureFilesystemClientReady_(get_result.data, __func__);
  if (!(guard_rcm)) {
    return {-1.0, guard_rcm};
  }
  const int safe_times = std::max(1, times);
  auto rtt_result = get_result.data->IOPort().GetRTT({safe_times}, control);
  return {rtt_result.data.rtt_ms, rtt_result.rcm};
}

ECMData<PathTarget>
FilesystemAppService::ResolveTrashDir(const PathTarget &source,
                                      const ControlComponent &control,
                                      ClientHandle preferred_client) {
  auto source_resolved = ResolvePath_(source, control, preferred_client);
  if (!(source_resolved.rcm) || !source_resolved.data.client) {
    return {PathTarget{},
            (source_resolved.rcm)
                ? Err(EC::InvalidHandle, "filesystem", "",
                      "Resolved client is null")
                : source_resolved.rcm};
  }

  std::string trash_dir = {};
  auto metadata =
      ClientAppService::GetClientMetadata(source_resolved.data.client);
  if (!metadata.has_value()) {
    return {PathTarget{},
            Err(EC::CommonFailure, "filesystem", "", "Client metadata not found")};
  }
  trash_dir = AMStr::Strip(metadata->trash_dir);
  if (trash_dir.empty()) {
    trash_dir = "~/.AMSFTP_Trash";
  }

  auto abs_rcm =
      ResolveAbsolutePath(source_resolved.data.client, trash_dir, control);
  if (!(abs_rcm.rcm)) {
    return {PathTarget{}, abs_rcm.rcm};
  }

  PathTarget out = {};
  out.nickname = source_resolved.data.target.nickname;
  out.path = abs_rcm.data;
  return {std::move(out), OK};
}

ECM FilesystemAppService::Rename(const PathTarget &src, const PathTarget &dst,
                                 const ControlComponent &control, bool mkdir,
                                 bool overwrite) {
  auto src_resolved = ResolvePath_(src, control);
  if (!(src_resolved.rcm) || !src_resolved.data.client) {
    return (src_resolved.rcm) ? Err(EC::InvalidHandle, "filesystem", "",
                                    "Resolved source client is null")
                              : src_resolved.rcm;
  }
  const auto &resolved_src = src_resolved.data;

  PathTarget dst_target = dst;
  ClientHandle preferred_dst_client = nullptr;
  if (dst_target.nickname.empty()) {
    dst_target.nickname = resolved_src.target.nickname;
    preferred_dst_client = resolved_src.client;
  }
  auto dst_resolved = ResolvePath_(dst_target, control, preferred_dst_client);
  if (!(dst_resolved.rcm) || !dst_resolved.data.client) {
    return (dst_resolved.rcm) ? Err(EC::InvalidHandle, "filesystem", "",
                                    "Resolved destination client is null")
                              : dst_resolved.rcm;
  }
  const auto &resolved_dst = dst_resolved.data;

  if (resolved_src.client != resolved_dst.client ||
      resolved_src.target.nickname != resolved_dst.target.nickname) {
    return Err(EC::InvalidArg, "filesystem", "",
               "Rename across different clients is not supported");
  }
  if (resolved_src.abs_path == resolved_dst.abs_path) {
    return OK;
  }

  auto stat_result = resolved_src.client->IOPort().stat(
      {resolved_src.abs_path, false}, control);
  if (!(stat_result.rcm)) {
    return stat_result.rcm;
  }
  const bool src_is_dir = stat_result.data.info.type == PathType::DIR;

  const std::string dst_parent = AMPath::dirname(resolved_dst.abs_path);
  if (!dst_parent.empty()) {
    auto parent_stat =
        resolved_src.client->IOPort().stat({dst_parent, false}, control);
    if (!(parent_stat.rcm)) {
      if (AMDomain::filesystem::service::IsPathNotExistError(
              parent_stat.rcm.code)) {
        if (!mkdir) {
          return Err(EC::ParentDirectoryNotExist, "filesystem", "",
                     AMStr::fmt("Parent directory not found: {}", dst_parent));
        }
        auto mkdir_result =
            resolved_src.client->IOPort().mkdirs({dst_parent}, control);
        if (!(mkdir_result.rcm)) {
          return mkdir_result.rcm;
        }
      } else {
        return parent_stat.rcm;
      }
    } else if (parent_stat.data.info.type != PathType::DIR) {
      return Err(EC::NotADirectory, "filesystem", "",
                 AMStr::fmt("Not a directory: {}", dst_parent));
    }
  }

  auto dst_stat = resolved_src.client->IOPort().stat(
      {resolved_dst.abs_path, false}, control);
  if ((dst_stat.rcm)) {
    if ((dst_stat.data.info.type == PathType::DIR) != src_is_dir) {
      return Err(EC::PathAlreadyExists, "filesystem", "",
                 AMStr::fmt("Destination exists with different type: {}",
                            resolved_dst.abs_path));
    }
    if (!overwrite) {
      return Err(
          EC::PathAlreadyExists, "filesystem", "",
          AMStr::fmt("Destination already exists: {}", resolved_dst.abs_path));
    }
  } else if (!AMDomain::filesystem::service::IsPathNotExistError(
                 dst_stat.rcm.code)) {
    return dst_stat.rcm;
  }

  auto rename_result = resolved_src.client->IOPort().rename(
      {resolved_src.abs_path, resolved_dst.abs_path, src_is_dir, mkdir,
       overwrite},
      control);
  if (!(rename_result.rcm)) {
    TraceFs_(rename_result.rcm, resolved_src.target, "filesystem.rename",
             AMStr::fmt("dst={}@{}", resolved_dst.target.nickname,
                        resolved_dst.abs_path));
    return rename_result.rcm;
  }

  ClearBaseIOCacheByPath(resolved_src.target.nickname, resolved_src.abs_path);
  ClearBaseIOCacheByPath(resolved_dst.target.nickname, resolved_dst.abs_path);
  const std::string src_parent = AMPath::dirname(resolved_src.abs_path);
  if (!src_parent.empty()) {
    ClearBaseIOCacheByPath(resolved_src.target.nickname, src_parent);
  }
  const std::string dst_parent_path = AMPath::dirname(resolved_dst.abs_path);
  if (!dst_parent_path.empty()) {
    ClearBaseIOCacheByPath(resolved_dst.target.nickname, dst_parent_path);
  }
  TraceFs_(OK, resolved_src.target, "filesystem.rename",
           AMStr::fmt("dst={}@{} overwrite={}",
                      resolved_dst.target.nickname, resolved_dst.abs_path,
                      overwrite ? "true" : "false"));
  return OK;
}

ECMData<RmfilePlan>
FilesystemAppService::PrepareRmfile(std::vector<PathTarget> targets,
                                    const ControlComponent &control) {
  RmfilePlan plan = {};
  ECM status = OK;
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "filesystem", "", "No target is given");
    AddPathError_(&plan.precheck_errors, &status, PathTarget{}, rcm);
    plan.rcm = rcm;
    return {std::move(plan), rcm};
  }

  std::vector<PathTarget> expanded_targets = {};
  expanded_targets.reserve(targets.size());
  for (auto &target : targets) {
    if (auto stop_rcm = BuildRequestStopECM_(control); stop_rcm.has_value()) {
      plan.rcm = *stop_rcm;
      return {std::move(plan), *stop_rcm};
    }

    if (target.path.empty()) {
      target.path = ".";
    }

    if (AMDomain::filesystem::service::HasWildcard(target.path)) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&plan, &status](const PathTarget &error_path, ECM error_rcm) {
                 AddPathError_(&plan.precheck_errors, &status, error_path,
                               error_rcm);
               });
      if (!(find_result.rcm)) {
        AddPathError_(&plan.precheck_errors, &status, target, find_result.rcm);
        if (IsStopError_(find_result.rcm.code)) {
          plan.rcm = find_result.rcm;
          return {std::move(plan), find_result.rcm};
        }
      }
      if (find_result.data.empty()) {
        AddPathError_(
            &plan.precheck_errors, &status, target,
            Err(EC::InvalidArg, "filesystem", "",
                "Wildcard path matched no target"));
        continue;
      }
      for (const auto &entry : find_result.data) {
        PathTarget item = {};
        item.nickname = target.nickname;
        item.path = entry.path;
        if (item.path.empty()) {
          item.path = ".";
        }
        item.is_wildcard =
            AMDomain::filesystem::service::HasWildcard(item.path);
        item.is_user_path = !item.path.empty() && item.path.front() == '~';
        expanded_targets.push_back(std::move(item));
      }
      continue;
    }

    expanded_targets.push_back(target);
  }

  std::unordered_set<std::string> seen = {};
  seen.reserve(expanded_targets.size());
  for (const auto &target : expanded_targets) {
    const std::string key = AMStr::fmt("{}@{}", target.nickname, target.path);
    if (!seen.insert(key).second) {
      continue;
    }

    if (auto stop_rcm = BuildRequestStopECM_(control); stop_rcm.has_value()) {
      plan.rcm = *stop_rcm;
      return {std::move(plan), *stop_rcm};
    }

    auto resolved_result = ResolvePath_(target, control);
    if (!(resolved_result.rcm) || !resolved_result.data.client) {
      const ECM rcm =
          (resolved_result.rcm)
              ? Err(EC::InvalidHandle, "filesystem", "",
                    "Resolved client is null")
              : resolved_result.rcm;
      AddPathError_(&plan.precheck_errors, &status, target, rcm);
      if (IsStopError_(rcm.code)) {
        plan.rcm = rcm;
        return {std::move(plan), rcm};
      }
      continue;
    }

    const ResolvedPath &resolved = resolved_result.data;
    auto stat_result = BaseStat(resolved.client, resolved.target.nickname,
                                resolved.abs_path, control, false);
    if (!(stat_result.rcm)) {
      AddPathError_(&plan.precheck_errors, &status, resolved.target,
                    stat_result.rcm);
      if (IsStopError_(stat_result.rcm.code)) {
        plan.rcm = stat_result.rcm;
        return {std::move(plan), stat_result.rcm};
      }
      continue;
    }
    if (stat_result.data.type == PathType::DIR) {
      const ECM rcm = Err(EC::NotAFile, "filesystem", "",
                          AMStr::fmt("rmfile does not accept directories: {}",
                                     resolved.abs_path));
      AddPathError_(&plan.precheck_errors, &status, resolved.target, rcm);
      continue;
    }

    PathTarget display = resolved.target;
    const std::string group_key =
        display.nickname.empty() ? "local" : display.nickname;
    plan.grouped_display_paths[group_key].push_back(display);
    plan.validated_targets.push_back(resolved);
  }

  if (plan.validated_targets.empty() && (status)) {
    status = Err(EC::InvalidArg, "filesystem", "", "No valid file target");
  }
  plan.rcm = status;
  TraceFs_(status, "<rmfile>", "filesystem.rmfile.prepare",
           AMStr::fmt("targets={} valid={} precheck_errors={}",
                      targets.size(), plan.validated_targets.size(),
                      plan.precheck_errors.size()));
  return {std::move(plan), status};
}

ECMData<std::vector<std::pair<PathTarget, ECM>>>
FilesystemAppService::ExecuteRmfile(
    const RmfilePlan &plan, const ControlComponent &control,
    std::function<void(const PathTarget &, ECM)> on_error) {
  std::vector<std::pair<PathTarget, ECM>> errors = {};
  ECM status = OK;
  if (plan.validated_targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "filesystem", "", "No valid file target");
    return {std::move(errors), rcm};
  }

  for (const auto &resolved : plan.validated_targets) {
    if (auto stop_rcm = BuildRequestStopECM_(control); stop_rcm.has_value()) {
      return {std::move(errors), *stop_rcm};
    }

    PathTarget target = resolved.target;
    if (!resolved.client) {
      const ECM rcm =
          Err(EC::InvalidHandle, "filesystem", "", "Resolved client is null");
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      continue;
    }

    auto stat_result =
        resolved.client->IOPort().stat({resolved.abs_path, false}, control);
    if (!(stat_result.rcm)) {
      AddPathError_(&errors, &status, target, stat_result.rcm);
      if (on_error) {
        on_error(target, stat_result.rcm);
      }
      if (IsStopError_(stat_result.rcm.code)) {
        return {std::move(errors), stat_result.rcm};
      }
      continue;
    }
    if (stat_result.data.info.type == PathType::DIR) {
      const ECM rcm = Err(EC::NotAFile, "filesystem", "",
                          AMStr::fmt("rmfile does not accept directories: {}",
                                     resolved.abs_path));
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      continue;
    }

    auto remove_result =
        resolved.client->IOPort().rmfile({resolved.abs_path}, control);
    if (!(remove_result.rcm)) {
      AddPathError_(&errors, &status, target, remove_result.rcm);
      if (on_error) {
        on_error(target, remove_result.rcm);
      }
      if (IsStopError_(remove_result.rcm.code)) {
        return {std::move(errors), remove_result.rcm};
      }
      continue;
    }

    ClearBaseIOCacheByPath(resolved.target.nickname, resolved.abs_path);
    const std::string parent = AMPath::dirname(resolved.abs_path);
    if (!parent.empty()) {
      ClearBaseIOCacheByPath(resolved.target.nickname, parent);
    }
  }
  TraceFs_(status, "<rmfile>", "filesystem.rmfile.execute",
           AMStr::fmt("targets={} errors={}", plan.validated_targets.size(),
                      errors.size()));
  return {std::move(errors), status};
}

ECMData<std::vector<std::pair<PathTarget, ECM>>> FilesystemAppService::Rmdir(
    std::vector<PathTarget> targets, const ControlComponent &control,
    std::function<void(const PathTarget &, ECM)> on_error) {
  std::vector<std::pair<PathTarget, ECM>> errors = {};
  ECM status = OK;
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "filesystem", "", "No target is given");
    return {std::move(errors), rcm};
  }

  for (auto &target : targets) {
    if (auto stop_rcm = BuildRequestStopECM_(control); stop_rcm.has_value()) {
      return {std::move(errors), *stop_rcm};
    }

    auto resolved_result = ResolvePath_(target, control);
    if (!(resolved_result.rcm) || !resolved_result.data.client) {
      const ECM rcm =
          (resolved_result.rcm)
              ? Err(EC::InvalidHandle, "filesystem", "",
                    "Resolved client is null")
              : resolved_result.rcm;
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      if (IsStopError_(rcm.code)) {
        return {std::move(errors), rcm};
      }
      continue;
    }

    const ResolvedPath &resolved = resolved_result.data;
    PathTarget display = resolved.target;
    auto stat_result =
        resolved.client->IOPort().stat({resolved.abs_path, false}, control);
    if (!(stat_result.rcm)) {
      AddPathError_(&errors, &status, display, stat_result.rcm);
      if (on_error) {
        on_error(display, stat_result.rcm);
      }
      if (IsStopError_(stat_result.rcm.code)) {
        return {std::move(errors), stat_result.rcm};
      }
      continue;
    }
    if (stat_result.data.info.type != PathType::DIR) {
      const ECM rcm = Err(
          EC::NotADirectory, "filesystem", "",
          AMStr::fmt("rmdir only accepts directories: {}", resolved.abs_path));
      AddPathError_(&errors, &status, display, rcm);
      if (on_error) {
        on_error(display, rcm);
      }
      continue;
    }

    auto remove_result =
        resolved.client->IOPort().rmdir({resolved.abs_path}, control);
    if (!(remove_result.rcm)) {
      AddPathError_(&errors, &status, display, remove_result.rcm);
      if (on_error) {
        on_error(display, remove_result.rcm);
      }
      if (IsStopError_(remove_result.rcm.code)) {
        return {std::move(errors), remove_result.rcm};
      }
      continue;
    }

    ClearBaseIOCacheByPath(resolved.target.nickname, resolved.abs_path);
    const std::string parent = AMPath::dirname(resolved.abs_path);
    if (!parent.empty()) {
      ClearBaseIOCacheByPath(resolved.target.nickname, parent);
    }
  }
  TraceFs_(status, "<rmdir>", "filesystem.rmdir",
           AMStr::fmt("targets={} errors={}", targets.size(), errors.size()));
  return {std::move(errors), status};
}

ECMData<PermanentRemovePlan>
FilesystemAppService::PreparePermanentRemove(std::vector<PathTarget> targets,
                                             const ControlComponent &control) {
  PermanentRemovePlan plan = {};
  ECM status = OK;
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "filesystem", "", "No target is given");
    AddPathError_(&plan.precheck_errors, &status, PathTarget{}, rcm);
    plan.rcm = rcm;
    return {std::move(plan), rcm};
  }

  std::unordered_map<std::string, std::vector<PathInfo>> matched_map = {};
  for (auto &target : targets) {
    if (auto stop_rcm = BuildRequestStopECM_(control); stop_rcm.has_value()) {
      plan.rcm = *stop_rcm;
      return {std::move(plan), *stop_rcm};
    }

    if (target.path.empty()) {
      target.path = ".";
    }

    if (AMDomain::filesystem::service::HasWildcard(target.path)) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&plan, &status](const PathTarget &error_path, ECM error_rcm) {
                 AddPathError_(&plan.precheck_errors, &status, error_path,
                               error_rcm);
               });
      if (!(find_result.rcm)) {
        AddPathError_(&plan.precheck_errors, &status, target, find_result.rcm);
        if (IsStopError_(find_result.rcm.code)) {
          plan.rcm = find_result.rcm;
          return {std::move(plan), find_result.rcm};
        }
      }
      if (find_result.data.empty()) {
        AddPathError_(
            &plan.precheck_errors, &status, target,
            Err(EC::InvalidArg, "filesystem", "",
                "Wildcard path matched no target"));
        continue;
      }
      matched_map[target.nickname].insert(matched_map[target.nickname].end(),
                                          find_result.data.begin(),
                                          find_result.data.end());
      continue;
    }

    auto stat_result = Stat(target, control, false);
    if (!(stat_result.rcm)) {
      AddPathError_(&plan.precheck_errors, &status, target, stat_result.rcm);
      if (IsStopError_(stat_result.rcm.code)) {
        plan.rcm = stat_result.rcm;
        return {std::move(plan), stat_result.rcm};
      }
      continue;
    }
    matched_map[target.nickname].push_back(stat_result.data);
  }

  std::unordered_set<std::string> delete_seen = {};
  for (auto &[nickname, entries] : matched_map) {
    std::vector<PathInfo> compacted = CompactMatchedPaths_(entries);
    for (const auto &entry : compacted) {
      PathTarget root = {};
      root.nickname = nickname;
      root.path = entry.path;
      auto root_resolved = ResolvePath_(root, control);
      if (!(root_resolved.rcm) || !root_resolved.data.client) {
        const ECM rcm =
            (root_resolved.rcm)
                ? Err(EC::InvalidHandle, "filesystem", "",
                      "Resolved client is null")
                : root_resolved.rcm;
        AddPathError_(&plan.precheck_errors, &status, root, rcm);
        if (IsStopError_(rcm.code)) {
          plan.rcm = rcm;
          return {std::move(plan), rcm};
        }
        continue;
      }

      const ResolvedPath resolved_root = root_resolved.data;
      PathTarget display_root = resolved_root.target;
      const std::string group_key =
          display_root.nickname.empty()
              ? (nickname.empty() ? "local" : nickname)
              : display_root.nickname;
      plan.grouped_display_paths[group_key].push_back(display_root);

      const auto push_delete = [&](const ResolvedPath &resolved) {
        const std::string key =
            AMStr::fmt("{}@{}", resolved.target.nickname, resolved.abs_path);
        if (!delete_seen.insert(key).second) {
          return;
        }
        plan.ordered_delete_paths.push_back(resolved);
      };

      if (entry.type != PathType::DIR) {
        push_delete(resolved_root);
        continue;
      }

      struct StackFrame {
        ResolvedPath path = {};
        bool expanded = false;
      };
      std::vector<StackFrame> stack = {};
      stack.push_back({resolved_root, false});

      while (!stack.empty()) {
        if (auto stop_rcm = BuildRequestStopECM_(control); stop_rcm.has_value()) {
          plan.rcm = *stop_rcm;
          return {std::move(plan), *stop_rcm};
        }

        StackFrame frame = std::move(stack.back());
        stack.pop_back();
        ResolvedPath current = std::move(frame.path);
        PathTarget current_display = current.target;

        if (!frame.expanded) {
          auto stat_result = BaseStat(current.client, current.target.nickname,
                                      current.abs_path, control, false);
          if (!(stat_result.rcm)) {
            AddPathError_(&plan.precheck_errors, &status, current_display,
                          stat_result.rcm);
            if (IsStopError_(stat_result.rcm.code)) {
              plan.rcm = stat_result.rcm;
              return {std::move(plan), stat_result.rcm};
            }
            continue;
          }
          if (stat_result.data.type != PathType::DIR) {
            push_delete(current);
            continue;
          }

          stack.push_back({current, true});
          auto list_result =
              BaseListdir(current.client, current.target.nickname,
                          current.abs_path, control);
          if (!(list_result.rcm)) {
            AddPathError_(&plan.precheck_errors, &status, current_display,
                          list_result.rcm);
            if (IsStopError_(list_result.rcm.code)) {
              plan.rcm = list_result.rcm;
              return {std::move(plan), list_result.rcm};
            }
            continue;
          }

          std::vector<PathInfo> children = std::move(list_result.data);
          std::sort(children.begin(), children.end(),
                    [](const PathInfo &lhs, const PathInfo &rhs) {
                      return lhs.path < rhs.path;
                    });
          for (auto it = children.rbegin(); it != children.rend(); ++it) {
            ResolvedPath child = current;
            child.abs_path = it->path;
            child.target.path = child.abs_path;
            child.target.is_wildcard = false;
            child.target.is_user_path = false;
            stack.push_back({std::move(child), false});
          }
          continue;
        }

        push_delete(current);
      }
    }
  }

  if (plan.ordered_delete_paths.empty() && (status)) {
    status =
        Err(EC::InvalidArg, "filesystem", "",
            "No valid target for permanent remove");
  }
  plan.rcm = status;
  TraceFs_(status, "<rm>", "filesystem.rm.prepare",
           AMStr::fmt("targets={} ordered={} precheck_errors={}",
                      targets.size(), plan.ordered_delete_paths.size(),
                      plan.precheck_errors.size()));
  return {std::move(plan), status};
}

ECMData<std::vector<std::pair<PathTarget, ECM>>>
FilesystemAppService::ExecutePermanentRemove(
    const PermanentRemovePlan &plan, const ControlComponent &control,
    std::function<void(const PathTarget &)> on_progress,
    std::function<void(const PathTarget &, ECM)> on_error) {
  std::vector<std::pair<PathTarget, ECM>> errors = {};
  ECM status = OK;

  if (plan.ordered_delete_paths.empty()) {
    return {std::move(errors),
            Err(EC::InvalidArg, "filesystem", "",
                "No resolved path for permanent remove")};
  }

  for (const auto &item : plan.ordered_delete_paths) {
    if (auto stop_rcm = BuildRequestStopECM_(control); stop_rcm.has_value()) {
      return {std::move(errors), *stop_rcm};
    }

    PathTarget current_display = item.target;
    if (!item.client) {
      const ECM rcm =
          Err(EC::InvalidHandle, "filesystem", "", "Resolved client is null");
      AddPathError_(&errors, &status, current_display, rcm);
      if (on_error) {
        on_error(current_display, rcm);
      }
      continue;
    }

    if (on_progress) {
      on_progress(current_display);
    }

    auto stat_result =
        item.client->IOPort().stat({item.abs_path, false}, control);
    if (!(stat_result.rcm)) {
      AddPathError_(&errors, &status, current_display, stat_result.rcm);
      if (on_error) {
        on_error(current_display, stat_result.rcm);
      }
      if (IsStopError_(stat_result.rcm.code)) {
        return {std::move(errors), stat_result.rcm};
      }
      continue;
    }

    ECM remove_rcm = OK;
    if (stat_result.data.info.type == PathType::DIR) {
      auto result = item.client->IOPort().rmdir({item.abs_path}, control);
      remove_rcm = result.rcm;
    } else {
      auto result = item.client->IOPort().rmfile({item.abs_path}, control);
      remove_rcm = result.rcm;
    }

    if (!(remove_rcm)) {
      AddPathError_(&errors, &status, current_display, remove_rcm);
      if (on_error) {
        on_error(current_display, remove_rcm);
      }
      if (IsStopError_(remove_rcm.code)) {
        return {std::move(errors), remove_rcm};
      }
      continue;
    }

    ClearBaseIOCacheByPath(item.target.nickname, item.abs_path);
    const std::string parent = AMPath::dirname(item.abs_path);
    if (!parent.empty()) {
      ClearBaseIOCacheByPath(item.target.nickname, parent);
    }
  }

  TraceFs_(status, "<rm>", "filesystem.rm.execute",
           AMStr::fmt("ordered={} errors={}", plan.ordered_delete_paths.size(),
                      errors.size()));
  return {std::move(errors), status};
}

ECMData<std::vector<std::pair<PathTarget, ECM>>>
FilesystemAppService::Saferm(std::vector<PathTarget> targets,
                             const ControlComponent &control) {
  std::vector<std::pair<PathTarget, ECM>> errors = {};
  ECM status = OK;
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "filesystem", "", "No target is given");
    AddSafermError_(&errors, &status, PathTarget{}, rcm);
    return {std::move(errors), rcm};
  }

  std::unordered_map<std::string, std::vector<PathInfo>> matched_map = {};
  for (auto &target : targets) {
    if (auto stop_rcm = BuildRequestStopECM_(control); stop_rcm.has_value()) {
      return {std::move(errors), *stop_rcm};
    }

    if (target.path.empty()) {
      target.path = ".";
    }

    if (AMDomain::filesystem::service::HasWildcard(target.path)) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&errors, &status](const PathTarget &error_path, ECM error_rcm) {
                 AddSafermError_(&errors, &status, error_path, error_rcm);
               });
      if (!(find_result.rcm)) {
        AddSafermError_(&errors, &status, target, find_result.rcm);
      }
      if (find_result.data.empty()) {
        AddSafermError_(
            &errors, &status, target,
            Err(EC::InvalidArg, "filesystem", "",
                "Wildcard path matched no target"));
        continue;
      }
      matched_map[target.nickname].insert(matched_map[target.nickname].end(),
                                          find_result.data.begin(),
                                          find_result.data.end());
      continue;
    }

    auto stat_result = Stat(target, control, false);
    if (!(stat_result.rcm)) {
      AddSafermError_(&errors, &status, target, stat_result.rcm);
      continue;
    }
    matched_map[target.nickname].push_back(stat_result.data);
  }

  std::vector<PathTarget> compacted_targets = {};
  for (auto &[nickname, entries] : matched_map) {
    std::vector<PathInfo> compacted = CompactMatchedPaths_(entries);
    for (const auto &entry : compacted) {
      PathTarget item = {};
      item.nickname = nickname;
      item.path = entry.path;
      compacted_targets.push_back(std::move(item));
    }
  }
  if (compacted_targets.empty()) {
    return {std::move(errors),
            (status)
                ? Err(EC::InvalidArg, "filesystem", "",
                      "No valid target for saferm")
                : status};
  }

  const std::string bucket = AMTime::Str("%Y-%m-%d-%H-%M-%S");
  std::unordered_map<std::string, PathTarget> bucket_dir_map = {};
  std::unordered_map<std::string, ECM> bucket_rcm_map = {};

  for (const auto &source : compacted_targets) {
    auto stop_rcm = BuildRequestStopECM_(control, "saferm", source.path);
    if (stop_rcm.has_value()) {
      return {std::move(errors), *stop_rcm};
    }

    const std::string &nickname = source.nickname;
    auto bucket_state_it = bucket_rcm_map.find(nickname);
    if (bucket_state_it == bucket_rcm_map.end()) {
      ECM prepare_rcm = OK;
      auto trash_result = ResolveTrashDir(source, control);
      if (!(trash_result.rcm)) {
        prepare_rcm = trash_result.rcm;
      } else {
        PathTarget trash_dir = std::move(trash_result.data);
        auto trash_stat = Stat(trash_dir, control, false);
        if (!(trash_stat.rcm)) {
          if (AMDomain::filesystem::service::IsPathNotExistError(
                  trash_stat.rcm.code)) {
            prepare_rcm = Mkdirs(trash_dir, control);
          } else {
            prepare_rcm = trash_stat.rcm;
          }
        } else if (trash_stat.data.type != PathType::DIR) {
          prepare_rcm = Err(EC::NotADirectory, "filesystem", "",
                            AMStr::fmt("Trash path is not a directory: {}",
                                       trash_stat.data.path));
        }

        if ((prepare_rcm)) {
          PathTarget bucket_dir = trash_dir;
          bucket_dir.path = AMPath::join(trash_dir.path, bucket);
          prepare_rcm = Mkdirs(bucket_dir, control);
          if ((prepare_rcm)) {
            bucket_dir_map[nickname] = bucket_dir;
          }
        }
      }
      bucket_rcm_map[nickname] = prepare_rcm;
      if (!(prepare_rcm)) {
        AddSafermError_(&errors, &status, source, prepare_rcm);
        continue;
      }
    } else if (!(bucket_state_it->second)) {
      AddSafermError_(&errors, &status, source, bucket_state_it->second);
      continue;
    }

    auto bucket_it = bucket_dir_map.find(nickname);
    if (bucket_it == bucket_dir_map.end()) {
      AddSafermError_(
          &errors, &status, source,
          Err(EC::CommonFailure, "filesystem", "",
              "Missing prepared trash bucket"));
      continue;
    }
    const PathTarget &bucket_dir = bucket_it->second;

    const std::string basename = AMPath::basename(source.path);
    std::string base_name = basename.empty() ? "unnamed" : basename;
    std::string ext_name = {};
    auto source_stat = Stat(source, control, false);
    if (!(source_stat.rcm)) {
      AddSafermError_(&errors, &status, source, source_stat.rcm);
      continue;
    }
    if (source_stat.data.type != PathType::DIR) {
      auto split_name = AMPath::split_basename(base_name);
      base_name = split_name.first.empty() ? base_name : split_name.first;
      ext_name = split_name.second;
    }

    PathTarget dst = {};
    dst.nickname = nickname;
    bool found_unique = false;
    for (size_t index = 0; index < 100000; ++index) {
      dst.path = AMPath::join(bucket_dir.path,
                              BuildSuffixName_(base_name, ext_name, index));
      auto dst_stat = Stat(dst, control, false);
      if (!(dst_stat.rcm)) {
        if (AMDomain::filesystem::service::IsPathNotExistError(
                dst_stat.rcm.code)) {
          found_unique = true;
          break;
        }
        AddSafermError_(&errors, &status, source, dst_stat.rcm);
        break;
      }
    }
    if (!found_unique) {
      AddSafermError_(&errors, &status, source,
                      Err(EC::CommonFailure, "filesystem", "",
                          "Failed to resolve unique saferm destination"));
      continue;
    }

    ECM rename_rcm = Rename(source, dst, control, true, false);
    if (!(rename_rcm)) {
      AddSafermError_(&errors, &status, source, rename_rcm);
    }
  }

  TraceFs_(status, "<saferm>", "filesystem.saferm",
           AMStr::fmt("targets={} compacted={} errors={}", targets.size(),
                      compacted_targets.size(), errors.size()));
  return {std::move(errors), status};
}

} // namespace AMApplication::filesystem
