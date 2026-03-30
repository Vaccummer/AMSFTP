#include "application/filesystem/FilesystemAppService.hpp"
#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/enum_related.hpp"
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

bool IsDrivePart_(const std::string &part) {
  return part.size() == 2 &&
         ((part[0] >= 'A' && part[0] <= 'Z') ||
          (part[0] >= 'a' && part[0] <= 'z')) &&
         part[1] == ':';
}

std::string ResolveWorkdir_(const ClientMetaData &metadata,
                            const std::string &home_dir) {
  if (!metadata.cwd.empty()) {
    return metadata.cwd;
  }
  if (!metadata.login_dir.empty()) {
    return metadata.login_dir;
  }
  if (!home_dir.empty()) {
    return home_dir;
  }
  return ".";
}

std::string ResolveAbsolutePath_(ClientHandle client,
                                 const ClientMetaData &metadata,
                                 const std::string &raw_path) {
  const std::string input = raw_path.empty() ? "." : raw_path;
  const std::string home_dir = client ? client->ConfigPort().GetHomeDir() : "";
  const std::string cwd = ResolveWorkdir_(metadata, home_dir);
  return AMFS::abspath(input, true, home_dir, cwd);
}

std::vector<std::string> BuildMkdirTargets_(const std::string &abs_path,
                                            const std::string &sep) {
  std::vector<std::string> parts = AMPathStr::split(abs_path);
  if (parts.empty()) {
    return {};
  }

  std::vector<std::string> targets = {};
  std::string current = "";
  size_t index = 0;
  if (parts[0] == "/") {
    current = "/";
    index = 1;
  } else if (IsDrivePart_(parts[0])) {
    current = parts[0] + sep;
    index = 1;
  } else {
    current = parts[0];
    targets.push_back(current);
    index = 1;
  }

  for (; index < parts.size(); ++index) {
    if (current.empty()) {
      current = parts[index];
    } else if (current == "/") {
      current += parts[index];
    } else if (!current.empty() &&
               (current.back() == '/' || current.back() == '\\')) {
      current += parts[index];
    } else {
      current += sep + parts[index];
    }
    targets.push_back(current);
  }

  return targets;
}

std::string EscapeDoubleQuote_(const std::string &text) {
  return AMStr::replace_all(text, "\"", "\\\"");
}

std::string BuildShellRunCmd_(AMDomain::client::OS_TYPE os_type,
                              const std::string &cwd,
                              const std::string &command,
                              const std::string &cmd_prefix, bool wrap_cmd) {
  std::string final_cmd = command;
  const std::string shell_cwd = AMStr::Strip(cwd);
  if (!shell_cwd.empty()) {
    if (os_type == AMDomain::client::OS_TYPE::Windows) {
      final_cmd = AMStr::fmt("cd /d \"{}\" && {}",
                             EscapeDoubleQuote_(shell_cwd), final_cmd);
    } else {
      final_cmd = AMStr::fmt("cd \"{}\" && {}", EscapeDoubleQuote_(shell_cwd),
                             final_cmd);
    }
  }
  if (cmd_prefix.empty()) {
    return final_cmd;
  }
  return wrap_cmd ? AMStr::fmt("{}\"{}\"", cmd_prefix,
                               AMStr::replace_all(final_cmd, "\"", "'"))
                  : AMStr::fmt("{}{}", cmd_prefix, final_cmd);
}

bool IsDescendantPath_(const std::string &candidate,
                       const std::string &ancestor) {
  if (candidate.empty() || ancestor.empty()) {
    return false;
  }
  const std::vector<std::string> candidate_parts = AMPathStr::split(candidate);
  const std::vector<std::string> ancestor_parts = AMPathStr::split(ancestor);
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

void AddPathError_(std::vector<std::pair<ClientPath, ECM>> *errors, ECM *status,
                   const ClientPath &path, const ECM &rcm) {
  if (errors) {
    errors->push_back({path, rcm});
  }
  if (status && !isok(rcm)) {
    *status = rcm;
  }
}

void AddSafermError_(std::vector<std::pair<ClientPath, ECM>> *errors,
                     ECM *status, const ClientPath &path, const ECM &rcm) {
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
                     const size_t lhs_depth = AMPathStr::split(lhs.path).size();
                     const size_t rhs_depth = AMPathStr::split(rhs.path).size();
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
    FilesystemArg arg, HostAppService *host_service,
    ClientAppService *client_service)
    : FilesystemAppBaseService(arg, host_service, client_service) {}

ECMData<ClientPath>
FilesystemAppService::GetCwd(const ClientControlComponent &control) {
  ClientPath out = {};
  if (!client_service_) {
    return {std::move(out), Err(EC::InvalidHandle, "client service is null")};
  }

  ClientHandle client = client_service_->GetCurrentClient();
  if (!client) {
    client = client_service_->GetLocalClient();
  }
  if (!client) {
    return {std::move(out),
            Err(EC::ClientNotFound, "Current client not found")};
  }
  auto res = ClientOperationHelper::GetClientCwd(client, control);
  if (!isok(res.rcm)) {
    return {std::move(out), res.rcm};
  }
  out.path = res.data;
  out.client = client;
  out.rcm = Ok();
  return {std::move(out), Ok()};
}

ECMData<ClientPath> FilesystemAppService::PeekCdHistory() const {
  auto history = cd_history_.lock();
  auto list = history.load();
  if (list.empty()) {
    return {ClientPath{}, Err(EC::InvalidArg, "cd history is empty")};
  }
  return {list.front(), Ok()};
}

ECM FilesystemAppService::ChangeDir(ClientPath path,
                                    const ClientControlComponent &control,
                                    bool from_history) {
  const ECM resolve_rcm = ResolvePath(path, control);
  if (!isok(resolve_rcm) || !path.client) {
    return isok(resolve_rcm) ? Err(EC::InvalidHandle, "Resolved client is null")
                             : resolve_rcm;
  }
  ClientHandle client = path.client;

  auto meta_guard = client->MetaDataPort().GetLockGaurd();
  auto *metadata = client->MetaDataPort().QueryTypedValue<ClientMetaData>();

  if (!metadata) {
    return Err(EC::CommonFailure, "Client metadata not found");
  }
  const std::string prev_cwd = metadata->cwd;
  meta_guard.Unlock();
  const std::string abs_target = path.path;
  auto stat_result = client->IOPort().stat({abs_target, false}, control);
  if (!isok(stat_result.rcm)) {
    return stat_result.rcm;
  }
  if (stat_result.info.type != PathType::DIR) {
    return Err(EC::NotADirectory,
               AMStr::fmt("Not a directory: {}", abs_target));
  }

  meta_guard.Relock();
  metadata = client->MetaDataPort().QueryTypedValue<ClientMetaData>();
  if (!metadata) {
    return Err(EC::CommonFailure, "Client metadata not found");
  }
  metadata->cwd = abs_target;
  meta_guard.Unlock();

  client_service_->SetCurrentClient(client);

  if (!from_history && !prev_cwd.empty() && prev_cwd != abs_target) {
    auto history = CdHistory().lock();
    auto list = history.load();
    ClientPath entry = {};
    entry.nickname = AMStr::Strip(client->ConfigPort().GetNickname());
    entry.path = prev_cwd;
    entry.client = client;
    entry.rcm = Ok();
    list.push_front(std::move(entry));
    const size_t limit =
        static_cast<size_t>(std::max(1, GetInitArg().max_cd_history));
    while (list.size() > limit) {
      list.pop_back();
    }
    history.store(std::move(list));
  }
  return Ok();
}

ECMData<PathInfo> FilesystemAppService::Stat(
    ClientPath path, const ClientControlComponent &control, bool trace_link) {
  ECM resolve_rcm = ResolvePath(path, control);
  if (!isok(resolve_rcm) || !path.client) {
    return {PathInfo{}, isok(resolve_rcm)
                            ? Err(EC::InvalidHandle, "Resolved client is null")
                            : resolve_rcm};
  }
  return BaseStat(path.client, path.nickname, path.path, control, trace_link);
}

ECMData<std::vector<PathInfo>>
FilesystemAppService::Listdir(ClientPath path,
                              const ClientControlComponent &control) {
  ECM resolve_rcm = ResolvePath(path, control);
  if (!isok(resolve_rcm) || !path.client) {
    return {{},
            isok(resolve_rcm)
                ? Err(EC::InvalidHandle, "Resolved client is null")
                : resolve_rcm};
  }
  return BaseListdir(path.client, path.nickname, path.path, control);
}

ECMData<std::vector<std::string>>
FilesystemAppService::ListNames(ClientPath path,
                                const ClientControlComponent &control) {
  ECM resolve_rcm = ResolvePath(path, control);
  if (!isok(resolve_rcm) || !path.client) {
    return {{},
            isok(resolve_rcm)
                ? Err(EC::InvalidHandle, "Resolved client is null")
                : resolve_rcm};
  }
  return BaseListNames(path.client, path.nickname, path.path, control);
}

ECM FilesystemAppService::Mkdirs(ClientPath path,
                                 const ClientControlComponent &control) {
  ECM resolve_rcm = ResolvePath(path, control);
  if (!isok(resolve_rcm) || !path.client) {
    return isok(resolve_rcm) ? Err(EC::InvalidHandle, "Resolved client is null")
                             : resolve_rcm;
  }

  ClientHandle client = path.client;
  auto abs_path = ClientOperationHelper::AbsolutePath(path);
  if (!isok(abs_path)) {
    return abs_path;
  }
  const std::vector<std::string> targets = AMPathStr::split(path.path);

  for (const auto &target : targets) {
    auto stat_result = client->IOPort().stat({target, false}, control);
    if (isok(stat_result.rcm)) {
      if (stat_result.info.type != PathType::DIR) {
        return Err(EC::NotADirectory,
                   AMStr::fmt("Not a directory: {}", target));
      }
      continue;
    }
    if (!AMDomain::filesystem::services::IsPathNotExistError(
            stat_result.rcm.first)) {
      return stat_result.rcm;
    }

    auto mkdir_result = client->IOPort().mkdir({target}, control);
    if (!isok(mkdir_result.rcm)) {
      return mkdir_result.rcm;
    }
  }
  return Ok();
}

ECMData<double>
FilesystemAppService::TestRTT(const std::string &nickname,
                              const ClientControlComponent &control,
                              int times) {
  auto get_result = GetClient(nickname, control);
  if (!isok(get_result.rcm) || !get_result.data) {
    return {-1.0, isok(get_result.rcm)
                      ? Err(EC::InvalidHandle, "Client is null")
                      : get_result.rcm};
  }
  const int safe_times = std::max(1, times);
  auto rtt_result = get_result.data->IOPort().GetRTT({safe_times}, control);
  return {rtt_result.rtt_ms, rtt_result.rcm};
}

ECMData<ClientPath>
FilesystemAppService::ResolveTrashDir(ClientPath source,
                                      const ClientControlComponent &control) {
  const ECM resolve_rcm = ResolvePath(source, control);
  if (!isok(resolve_rcm) || !source.client) {
    return {ClientPath{}, isok(resolve_rcm) ? Err(EC::InvalidHandle,
                                                  "Resolved client is null")
                                            : resolve_rcm};
  }

  std::string trash_dir = {};
  {
    auto meta_guard = source.client->MetaDataPort().GetLockGaurd();
    auto *metadata =
        source.client->MetaDataPort().QueryTypedValue<ClientMetaData>();
    if (!metadata) {
      return {ClientPath{},
              Err(EC::CommonFailure, "Client metadata not found")};
    }
    trash_dir = AMStr::Strip(metadata->trash_dir);
    meta_guard.Unlock();
  }
  if (trash_dir.empty()) {
    trash_dir = "~/.AMSFTP_Trash";
  }

  ClientPath out = {};
  out.nickname = source.nickname;
  out.client = source.client;
  out.path = trash_dir;
  const ECM abs_rcm = ClientOperationHelper::AbsolutePath(out);
  if (!isok(abs_rcm)) {
    return {ClientPath{}, abs_rcm};
  }
  out.resolved = true;
  out.rcm = Ok();
  return {std::move(out), Ok()};
}

ECM FilesystemAppService::Rename(const ClientPath &src, const ClientPath &dst,
                                 const ClientControlComponent &control,
                                 bool mkdir, bool overwrite) {
  ClientPath resolved_src = src;
  const ECM src_rcm = ResolvePath(resolved_src, control);
  if (!isok(src_rcm) || !resolved_src.client) {
    return isok(src_rcm)
               ? Err(EC::InvalidHandle, "Resolved source client is null")
               : src_rcm;
  }

  ClientPath resolved_dst = dst;
  if (!resolved_dst.client && AMStr::Strip(resolved_dst.nickname).empty()) {
    resolved_dst.client = resolved_src.client;
    resolved_dst.nickname = resolved_src.nickname;
  }
  const ECM dst_rcm = ResolvePath(resolved_dst, control);
  if (!isok(dst_rcm) || !resolved_dst.client) {
    return isok(dst_rcm)
               ? Err(EC::InvalidHandle, "Resolved destination client is null")
               : dst_rcm;
  }

  if (resolved_src.client != resolved_dst.client) {
    return Err(EC::InvalidArg,
               "Rename across different clients is not supported");
  }
  if (resolved_src.path == resolved_dst.path) {
    return Ok();
  }

  auto stat_result =
      resolved_src.client->IOPort().stat({resolved_src.path, false}, control);
  if (!isok(stat_result.rcm)) {
    return stat_result.rcm;
  }
  const bool src_is_dir = stat_result.info.type == PathType::DIR;

  const std::string dst_parent = AMPathStr::dirname(resolved_dst.path);
  if (!dst_parent.empty()) {
    auto parent_stat =
        resolved_src.client->IOPort().stat({dst_parent, false}, control);
    if (!isok(parent_stat.rcm)) {
      if (AMDomain::filesystem::services::IsPathNotExistError(
              parent_stat.rcm.first)) {
        if (!mkdir) {
          return Err(EC::ParentDirectoryNotExist,
                     AMStr::fmt("Parent directory not found: {}", dst_parent));
        }
        auto mkdir_result =
            resolved_src.client->IOPort().mkdirs({dst_parent}, control);
        if (!isok(mkdir_result.rcm)) {
          return mkdir_result.rcm;
        }
      } else {
        return parent_stat.rcm;
      }
    } else if (parent_stat.info.type != PathType::DIR) {
      return Err(EC::NotADirectory,
                 AMStr::fmt("Not a directory: {}", dst_parent));
    }
  }

  auto dst_stat =
      resolved_src.client->IOPort().stat({resolved_dst.path, false}, control);
  if (isok(dst_stat.rcm)) {
    if ((dst_stat.info.type == PathType::DIR) != src_is_dir) {
      return Err(EC::PathAlreadyExists,
                 AMStr::fmt("Destination exists with different type: {}",
                            resolved_dst.path));
    }
    if (!overwrite) {
      return Err(
          EC::PathAlreadyExists,
          AMStr::fmt("Destination already exists: {}", resolved_dst.path));
    }
  } else if (!AMDomain::filesystem::services::IsPathNotExistError(
                 dst_stat.rcm.first)) {
    return dst_stat.rcm;
  }

  auto rename_result = resolved_src.client->IOPort().rename(
      {resolved_src.path, resolved_dst.path, src_is_dir, mkdir, overwrite},
      control);
  if (!isok(rename_result.rcm)) {
    return rename_result.rcm;
  }

  ClearBaseIOCacheByPath(resolved_src.nickname, resolved_src.path);
  ClearBaseIOCacheByPath(resolved_dst.nickname, resolved_dst.path);
  const std::string src_parent = AMPathStr::dirname(resolved_src.path);
  if (!src_parent.empty()) {
    ClearBaseIOCacheByPath(resolved_src.nickname, src_parent);
  }
  const std::string dst_parent_path = AMPathStr::dirname(resolved_dst.path);
  if (!dst_parent_path.empty()) {
    ClearBaseIOCacheByPath(resolved_dst.nickname, dst_parent_path);
  }
  return Ok();
}

ECMData<RmfilePlan>
FilesystemAppService::PrepareRmfile(std::vector<ClientPath> targets,
                                    const ClientControlComponent &control) {
  RmfilePlan plan = {};
  ECM status = Ok();
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    AddPathError_(&plan.precheck_errors, &status, ClientPath{}, rcm);
    plan.rcm = rcm;
    return {std::move(plan), rcm};
  }

  std::vector<ClientPath> raw_targets = {};
  raw_targets.reserve(targets.size());
  for (auto &target : targets) {
    if (control.IsInterrupted()) {
      const ECM rcm = Err(EC::Terminate, "Interrupted by user");
      plan.rcm = rcm;
      return {std::move(plan), rcm};
    }
    if (control.IsTimeout()) {
      const ECM rcm = Err(EC::OperationTimeout, "Operation timed out");
      plan.rcm = rcm;
      return {std::move(plan), rcm};
    }

    target.path = target.path.empty() ? "." : target.path;
    target.is_wildcard =
        target.is_wildcard ||
        AMDomain::filesystem::services::HasWildcard(target.path);
    target.userpath = !target.path.empty() && target.path.front() == '~';

    if (target.is_wildcard) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&plan, &status](const ClientPath &error_path, ECM error_rcm) {
                 AddPathError_(&plan.precheck_errors, &status, error_path,
                               error_rcm);
               });
      if (!isok(find_result.rcm)) {
        AddPathError_(&plan.precheck_errors, &status, target, find_result.rcm);
        if (IsStopError_(find_result.rcm.first)) {
          plan.rcm = find_result.rcm;
          return {std::move(plan), find_result.rcm};
        }
      }
      if (find_result.data.empty()) {
        AddPathError_(&plan.precheck_errors, &status, target,
                      Err(EC::InvalidArg, "Wildcard path matched no target"));
        continue;
      }
      for (const auto &entry : find_result.data) {
        ClientPath item = {};
        item.nickname = target.nickname;
        item.path = entry.path;
        item.resolved = true;
        item.rcm = Ok();
        raw_targets.push_back(std::move(item));
      }
      continue;
    }

    raw_targets.push_back(target);
  }

  std::unordered_set<std::string> seen = {};
  seen.reserve(raw_targets.size());
  for (auto &raw : raw_targets) {
    const std::string key = AMStr::fmt("{}@{}", raw.nickname, raw.path);
    if (!seen.insert(key).second) {
      continue;
    }

    if (control.IsInterrupted()) {
      const ECM rcm = Err(EC::Terminate, "Interrupted by user");
      plan.rcm = rcm;
      return {std::move(plan), rcm};
    }
    if (control.IsTimeout()) {
      const ECM rcm = Err(EC::OperationTimeout, "Operation timed out");
      plan.rcm = rcm;
      return {std::move(plan), rcm};
    }

    ClientPath target = raw;
    const ECM resolve_rcm = ResolvePath(target, control);
    if (!isok(resolve_rcm) || !target.client) {
      const ECM rcm = isok(resolve_rcm)
                          ? Err(EC::InvalidHandle, "Resolved client is null")
                          : resolve_rcm;
      AddPathError_(&plan.precheck_errors, &status, target, rcm);
      if (IsStopError_(rcm.first)) {
        plan.rcm = rcm;
        return {std::move(plan), rcm};
      }
      continue;
    }

    auto stat_result = Stat(target, control, false);
    if (!isok(stat_result.rcm)) {
      AddPathError_(&plan.precheck_errors, &status, target, stat_result.rcm);
      if (IsStopError_(stat_result.rcm.first)) {
        plan.rcm = stat_result.rcm;
        return {std::move(plan), stat_result.rcm};
      }
      continue;
    }
    if (stat_result.data.type == PathType::DIR) {
      const ECM rcm =
          Err(EC::NotAFile, AMStr::fmt("rmfile does not accept directories: {}",
                                       target.path));
      AddPathError_(&plan.precheck_errors, &status, target, rcm);
      continue;
    }

    const std::string group_key =
        target.nickname.empty() ? "local" : target.nickname;
    plan.grouped_display_paths[group_key].push_back(target);
    plan.validated_targets.push_back(std::move(target));
  }

  if (plan.validated_targets.empty() && isok(status)) {
    status = Err(EC::InvalidArg, "No valid file target");
  }
  plan.rcm = status;
  return {std::move(plan), status};
}

ECMData<std::vector<std::pair<ClientPath, ECM>>>
FilesystemAppService::ExecuteRmfile(
    const RmfilePlan &plan, const ClientControlComponent &control,
    std::function<void(const ClientPath &, ECM)> on_error) {
  std::vector<std::pair<ClientPath, ECM>> errors = {};
  ECM status = Ok();
  if (plan.validated_targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No valid file target");
    return {std::move(errors), rcm};
  }

  for (const auto &item : plan.validated_targets) {
    if (control.IsInterrupted()) {
      return {std::move(errors), Err(EC::Terminate, "Interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {std::move(errors),
              Err(EC::OperationTimeout, "Operation timed out")};
    }

    ClientPath target = item;
    const ECM resolve_rcm = ResolvePath(target, control);
    if (!isok(resolve_rcm) || !target.client) {
      const ECM rcm = isok(resolve_rcm)
                          ? Err(EC::InvalidHandle, "Resolved client is null")
                          : resolve_rcm;
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      if (IsStopError_(rcm.first)) {
        return {std::move(errors), rcm};
      }
      continue;
    }

    auto stat_result =
        target.client->IOPort().stat({target.path, false}, control);
    if (!isok(stat_result.rcm)) {
      AddPathError_(&errors, &status, target, stat_result.rcm);
      if (on_error) {
        on_error(target, stat_result.rcm);
      }
      if (IsStopError_(stat_result.rcm.first)) {
        return {std::move(errors), stat_result.rcm};
      }
      continue;
    }
    if (stat_result.info.type == PathType::DIR) {
      const ECM rcm =
          Err(EC::NotAFile, AMStr::fmt("rmfile does not accept directories: {}",
                                       target.path));
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      continue;
    }

    auto remove_result = target.client->IOPort().rmfile({target.path}, control);
    if (!isok(remove_result.rcm)) {
      AddPathError_(&errors, &status, target, remove_result.rcm);
      if (on_error) {
        on_error(target, remove_result.rcm);
      }
      if (IsStopError_(remove_result.rcm.first)) {
        return {std::move(errors), remove_result.rcm};
      }
      continue;
    }

    ClearBaseIOCacheByPath(target.nickname, target.path);
    const std::string parent = AMPathStr::dirname(target.path);
    if (!parent.empty()) {
      ClearBaseIOCacheByPath(target.nickname, parent);
    }
  }
  return {std::move(errors), status};
}

ECMData<std::vector<std::pair<ClientPath, ECM>>> FilesystemAppService::Rmdir(
    std::vector<ClientPath> targets, const ClientControlComponent &control,
    std::function<void(const ClientPath &, ECM)> on_error) {
  std::vector<std::pair<ClientPath, ECM>> errors = {};
  ECM status = Ok();
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    return {std::move(errors), rcm};
  }

  for (auto &target : targets) {
    if (control.IsInterrupted()) {
      return {std::move(errors), Err(EC::Terminate, "Interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {std::move(errors),
              Err(EC::OperationTimeout, "Operation timed out")};
    }

    const ECM resolve_rcm = ResolvePath(target, control);
    if (!isok(resolve_rcm) || !target.client) {
      const ECM rcm = isok(resolve_rcm)
                          ? Err(EC::InvalidHandle, "Resolved client is null")
                          : resolve_rcm;
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      if (IsStopError_(rcm.first)) {
        return {std::move(errors), rcm};
      }
      continue;
    }

    auto stat_result =
        target.client->IOPort().stat({target.path, false}, control);
    if (!isok(stat_result.rcm)) {
      AddPathError_(&errors, &status, target, stat_result.rcm);
      if (on_error) {
        on_error(target, stat_result.rcm);
      }
      if (IsStopError_(stat_result.rcm.first)) {
        return {std::move(errors), stat_result.rcm};
      }
      continue;
    }
    if (stat_result.info.type != PathType::DIR) {
      const ECM rcm =
          Err(EC::NotADirectory,
              AMStr::fmt("rmdir only accepts directories: {}", target.path));
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      continue;
    }

    auto remove_result = target.client->IOPort().rmdir({target.path}, control);
    if (!isok(remove_result.rcm)) {
      AddPathError_(&errors, &status, target, remove_result.rcm);
      if (on_error) {
        on_error(target, remove_result.rcm);
      }
      if (IsStopError_(remove_result.rcm.first)) {
        return {std::move(errors), remove_result.rcm};
      }
      continue;
    }

    ClearBaseIOCacheByPath(target.nickname, target.path);
    const std::string parent = AMPathStr::dirname(target.path);
    if (!parent.empty()) {
      ClearBaseIOCacheByPath(target.nickname, parent);
    }
  }
  return {std::move(errors), status};
}

ECMData<PermanentRemovePlan> FilesystemAppService::PreparePermanentRemove(
    std::vector<ClientPath> targets, const ClientControlComponent &control) {
  PermanentRemovePlan plan = {};
  ECM status = Ok();
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    AddPathError_(&plan.precheck_errors, &status, ClientPath{}, rcm);
    plan.rcm = rcm;
    return {std::move(plan), rcm};
  }

  std::unordered_map<std::string, std::vector<PathInfo>> matched_map = {};
  for (auto &target : targets) {
    if (control.IsInterrupted()) {
      const ECM rcm = Err(EC::Terminate, "Interrupted by user");
      plan.rcm = rcm;
      return {std::move(plan), rcm};
    }
    if (control.IsTimeout()) {
      const ECM rcm = Err(EC::OperationTimeout, "Operation timed out");
      plan.rcm = rcm;
      return {std::move(plan), rcm};
    }

    target.path = target.path.empty() ? "." : target.path;
    target.is_wildcard =
        target.is_wildcard ||
        AMDomain::filesystem::services::HasWildcard(target.path);
    target.userpath = !target.path.empty() && target.path.front() == '~';

    if (target.is_wildcard) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&plan, &status](const ClientPath &error_path, ECM error_rcm) {
                 AddPathError_(&plan.precheck_errors, &status, error_path,
                               error_rcm);
               });
      if (!isok(find_result.rcm)) {
        AddPathError_(&plan.precheck_errors, &status, target, find_result.rcm);
        if (IsStopError_(find_result.rcm.first)) {
          plan.rcm = find_result.rcm;
          return {std::move(plan), find_result.rcm};
        }
      }
      if (find_result.data.empty()) {
        AddPathError_(&plan.precheck_errors, &status, target,
                      Err(EC::InvalidArg, "Wildcard path matched no target"));
        continue;
      }
      matched_map[target.nickname].insert(matched_map[target.nickname].end(),
                                          find_result.data.begin(),
                                          find_result.data.end());
      continue;
    }

    auto stat_result = Stat(target, control, false);
    if (!isok(stat_result.rcm)) {
      AddPathError_(&plan.precheck_errors, &status, target, stat_result.rcm);
      if (IsStopError_(stat_result.rcm.first)) {
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
      ClientPath root = {};
      root.nickname = nickname;
      root.path = entry.path;
      root.resolved = true;
      root.rcm = Ok();
      const ECM resolve_rcm = ResolvePath(root, control);
      if (!isok(resolve_rcm) || !root.client) {
        const ECM rcm = isok(resolve_rcm)
                            ? Err(EC::InvalidHandle, "Resolved client is null")
                            : resolve_rcm;
        AddPathError_(&plan.precheck_errors, &status, root, rcm);
        if (IsStopError_(rcm.first)) {
          plan.rcm = rcm;
          return {std::move(plan), rcm};
        }
        continue;
      }

      const std::string group_key =
          root.nickname.empty() ? (nickname.empty() ? "local" : nickname)
                                : root.nickname;
      plan.grouped_display_paths[group_key].push_back(root);

      const auto push_delete = [&](const ClientPath &path) {
        const std::string key = AMStr::fmt("{}@{}", path.nickname, path.path);
        if (!delete_seen.insert(key).second) {
          return;
        }
        plan.ordered_delete_paths.push_back(path);
      };

      if (entry.type != PathType::DIR) {
        push_delete(root);
        continue;
      }

      struct StackFrame {
        ClientPath path = {};
        bool expanded = false;
      };
      std::vector<StackFrame> stack = {};
      stack.push_back({root, false});

      while (!stack.empty()) {
        if (control.IsInterrupted()) {
          const ECM rcm = Err(EC::Terminate, "Interrupted by user");
          plan.rcm = rcm;
          return {std::move(plan), rcm};
        }
        if (control.IsTimeout()) {
          const ECM rcm = Err(EC::OperationTimeout, "Operation timed out");
          plan.rcm = rcm;
          return {std::move(plan), rcm};
        }

        StackFrame frame = std::move(stack.back());
        stack.pop_back();
        ClientPath current = std::move(frame.path);

        if (!frame.expanded) {
          auto stat_result = Stat(current, control, false);
          if (!isok(stat_result.rcm)) {
            AddPathError_(&plan.precheck_errors, &status, current,
                          stat_result.rcm);
            if (IsStopError_(stat_result.rcm.first)) {
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
          auto list_result = Listdir(current, control);
          if (!isok(list_result.rcm)) {
            AddPathError_(&plan.precheck_errors, &status, current,
                          list_result.rcm);
            if (IsStopError_(list_result.rcm.first)) {
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
            ClientPath child = {};
            child.nickname = current.nickname;
            child.path = it->path;
            child.client = current.client;
            child.resolved = true;
            child.rcm = Ok();
            stack.push_back({std::move(child), false});
          }
          continue;
        }

        push_delete(current);
      }
    }
  }

  if (plan.ordered_delete_paths.empty() && isok(status)) {
    status = Err(EC::InvalidArg, "No valid target for permanent remove");
  }
  plan.rcm = status;
  return {std::move(plan), status};
}

ECMData<std::vector<std::pair<ClientPath, ECM>>>
FilesystemAppService::ExecutePermanentRemove(
    const PermanentRemovePlan &plan, const ClientControlComponent &control,
    std::function<void(const ClientPath &)> on_progress,
    std::function<void(const ClientPath &, ECM)> on_error) {
  std::vector<std::pair<ClientPath, ECM>> errors = {};
  ECM status = Ok();

  if (plan.ordered_delete_paths.empty()) {
    return {std::move(errors),
            Err(EC::InvalidArg, "No resolved path for permanent remove")};
  }

  for (const auto &item : plan.ordered_delete_paths) {
    if (control.IsInterrupted()) {
      return {std::move(errors), Err(EC::Terminate, "Interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {std::move(errors),
              Err(EC::OperationTimeout, "Operation timed out")};
    }

    ClientPath current = item;
    const ECM resolve_rcm = ResolvePath(current, control);
    if (!isok(resolve_rcm) || !current.client) {
      const ECM rcm = isok(resolve_rcm)
                          ? Err(EC::InvalidHandle, "Resolved client is null")
                          : resolve_rcm;
      AddPathError_(&errors, &status, current, rcm);
      if (on_error) {
        on_error(current, rcm);
      }
      if (IsStopError_(rcm.first)) {
        return {std::move(errors), rcm};
      }
      continue;
    }

    if (on_progress) {
      on_progress(current);
    }

    auto stat_result =
        current.client->IOPort().stat({current.path, false}, control);
    if (!isok(stat_result.rcm)) {
      AddPathError_(&errors, &status, current, stat_result.rcm);
      if (on_error) {
        on_error(current, stat_result.rcm);
      }
      if (IsStopError_(stat_result.rcm.first)) {
        return {std::move(errors), stat_result.rcm};
      }
      continue;
    }

    ECM remove_rcm = Ok();
    if (stat_result.info.type == PathType::DIR) {
      auto result = current.client->IOPort().rmdir({current.path}, control);
      remove_rcm = result.rcm;
    } else {
      auto result = current.client->IOPort().rmfile({current.path}, control);
      remove_rcm = result.rcm;
    }

    if (!isok(remove_rcm)) {
      AddPathError_(&errors, &status, current, remove_rcm);
      if (on_error) {
        on_error(current, remove_rcm);
      }
      if (IsStopError_(remove_rcm.first)) {
        return {std::move(errors), remove_rcm};
      }
      continue;
    }

    ClearBaseIOCacheByPath(current.nickname, current.path);
    const std::string parent = AMPathStr::dirname(current.path);
    if (!parent.empty()) {
      ClearBaseIOCacheByPath(current.nickname, parent);
    }
  }

  return {std::move(errors), status};
}

ECMData<std::vector<std::pair<ClientPath, ECM>>>
FilesystemAppService::Saferm(std::vector<ClientPath> targets,
                             const ClientControlComponent &control) {
  std::vector<std::pair<ClientPath, ECM>> errors = {};
  ECM status = Ok();
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    AddSafermError_(&errors, &status, ClientPath{}, rcm);
    return {std::move(errors), rcm};
  }

  std::unordered_map<std::string, std::vector<PathInfo>> matched_map = {};
  for (auto &target : targets) {
    if (control.IsInterrupted()) {
      return {std::move(errors), Err(EC::Terminate, "Interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {std::move(errors),
              Err(EC::OperationTimeout, "Operation timed out")};
    }

    target.path = target.path.empty() ? "." : target.path;
    target.is_wildcard =
        target.is_wildcard ||
        AMDomain::filesystem::services::HasWildcard(target.path);
    target.userpath = !target.path.empty() && target.path.front() == '~';

    if (target.is_wildcard) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&errors, &status](const ClientPath &error_path, ECM error_rcm) {
                 AddSafermError_(&errors, &status, error_path, error_rcm);
               });
      if (!isok(find_result.rcm)) {
        AddSafermError_(&errors, &status, target, find_result.rcm);
      }
      if (find_result.data.empty()) {
        AddSafermError_(&errors, &status, target,
                        Err(EC::InvalidArg, "Wildcard path matched no target"));
        continue;
      }
      matched_map[target.nickname].insert(matched_map[target.nickname].end(),
                                          find_result.data.begin(),
                                          find_result.data.end());
      continue;
    }

    auto stat_result = Stat(target, control, false);
    if (!isok(stat_result.rcm)) {
      AddSafermError_(&errors, &status, target, stat_result.rcm);
      continue;
    }
    matched_map[target.nickname].push_back(stat_result.data);
  }

  std::vector<ClientPath> compacted_targets = {};
  for (auto &[nickname, entries] : matched_map) {
    std::vector<PathInfo> compacted = CompactMatchedPaths_(entries);
    for (const auto &entry : compacted) {
      ClientPath item = {};
      item.nickname = nickname;
      item.path = entry.path;
      item.resolved = true;
      item.rcm = Ok();
      compacted_targets.push_back(std::move(item));
    }
  }
  if (compacted_targets.empty()) {
    return {std::move(errors),
            isok(status) ? Err(EC::InvalidArg, "No valid target for saferm")
                         : status};
  }

  const std::string bucket = AMTime::Str("%Y-%m-%d-%H-%M-%S");
  std::unordered_map<std::string, ClientPath> bucket_dir_map = {};
  std::unordered_map<std::string, ECM> bucket_rcm_map = {};

  for (const auto &source : compacted_targets) {
    if (control.IsInterrupted()) {
      return {std::move(errors), Err(EC::Terminate, "Interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {std::move(errors),
              Err(EC::OperationTimeout, "Operation timed out")};
    }

    const std::string &nickname = source.nickname;
    auto bucket_state_it = bucket_rcm_map.find(nickname);
    if (bucket_state_it == bucket_rcm_map.end()) {
      ECM prepare_rcm = Ok();
      auto trash_result = ResolveTrashDir(source, control);
      if (!isok(trash_result.rcm)) {
        prepare_rcm = trash_result.rcm;
      } else {
        ClientPath trash_dir = std::move(trash_result.data);
        auto trash_stat = Stat(trash_dir, control, false);
        if (!isok(trash_stat.rcm)) {
          if (AMDomain::filesystem::services::IsPathNotExistError(
                  trash_stat.rcm.first)) {
            prepare_rcm = Mkdirs(trash_dir, control);
          } else {
            prepare_rcm = trash_stat.rcm;
          }
        } else if (trash_stat.data.type != PathType::DIR) {
          prepare_rcm = Err(EC::NotADirectory,
                            AMStr::fmt("Trash path is not a directory: {}",
                                       trash_stat.data.path));
        }

        if (isok(prepare_rcm)) {
          ClientPath bucket_dir = trash_dir;
          bucket_dir.path = AMPathStr::join(trash_dir.path, bucket);
          prepare_rcm = Mkdirs(bucket_dir, control);
          if (isok(prepare_rcm)) {
            bucket_dir_map[nickname] = bucket_dir;
          }
        }
      }
      bucket_rcm_map[nickname] = prepare_rcm;
      if (!isok(prepare_rcm)) {
        AddSafermError_(&errors, &status, source, prepare_rcm);
        continue;
      }
    } else if (!isok(bucket_state_it->second)) {
      AddSafermError_(&errors, &status, source, bucket_state_it->second);
      continue;
    }

    auto bucket_it = bucket_dir_map.find(nickname);
    if (bucket_it == bucket_dir_map.end()) {
      AddSafermError_(&errors, &status, source,
                      Err(EC::CommonFailure, "Missing prepared trash bucket"));
      continue;
    }
    const ClientPath &bucket_dir = bucket_it->second;

    const std::string basename = AMPathStr::basename(source.path);
    std::string base_name = basename.empty() ? "unnamed" : basename;
    std::string ext_name = {};
    auto source_stat = Stat(source, control, false);
    if (!isok(source_stat.rcm)) {
      AddSafermError_(&errors, &status, source, source_stat.rcm);
      continue;
    }
    if (source_stat.data.type != PathType::DIR) {
      auto split_name = AMPathStr::split_basename(base_name);
      base_name = split_name.first.empty() ? base_name : split_name.first;
      ext_name = split_name.second;
    }

    ClientPath dst = {};
    dst.nickname = nickname;
    bool found_unique = false;
    for (size_t index = 0; index < 100000; ++index) {
      dst.path = AMPathStr::join(bucket_dir.path,
                                 BuildSuffixName_(base_name, ext_name, index));
      auto dst_stat = Stat(dst, control, false);
      if (!isok(dst_stat.rcm)) {
        if (AMDomain::filesystem::services::IsPathNotExistError(
                dst_stat.rcm.first)) {
          found_unique = true;
          break;
        }
        AddSafermError_(&errors, &status, source, dst_stat.rcm);
        break;
      }
    }
    if (!found_unique) {
      AddSafermError_(&errors, &status, source,
                      Err(EC::CommonFailure,
                          "Failed to resolve unique saferm destination"));
      continue;
    }

    ECM rename_rcm = Rename(source, dst, control, true, false);
    if (!isok(rename_rcm)) {
      AddSafermError_(&errors, &status, source, rename_rcm);
    }
  }

  return {std::move(errors), status};
}

RunResult FilesystemAppService::ShellRun(const std::string &nickname,
                                         const std::string &workdir,
                                         const std::string &cmd,
                                         const ClientControlComponent &control,
                                         std::string *final_cmd_out) {
  RunResult out = {};
  if (AMStr::Strip(cmd).empty()) {
    out.rcm = Err(EC::InvalidArg, "Command is empty");
    return out;
  }

  std::string resolved_nickname = AMStr::Strip(nickname);
  auto get_result = GetClient(resolved_nickname, control);
  if (!isok(get_result.rcm) || !get_result.data) {
    out.rcm = get_result.rcm;
    return out;
  }
  ClientHandle client = get_result.data;

  AMDomain::client::OS_TYPE os_type = client->ConfigPort().GetOSType();
  if (os_type == AMDomain::client::OS_TYPE::Unknown) {
    auto os_result = client->IOPort().UpdateOSType({}, control);
    if (!isok(os_result.rcm)) {
      out.rcm = os_result.rcm;
      return out;
    }
    os_type = os_result.os_type;
  }

  ClientMetaData metadata = {};
  {
    auto meta_guard = client->MetaDataPort().GetLockGaurd();
    auto *metadata_ptr =
        client->MetaDataPort().QueryTypedValue<ClientMetaData>();
    if (!metadata_ptr) {
      out.rcm = Err(EC::CommonFailure, "Client metadata not found");
      return out;
    }
    metadata = *metadata_ptr;
    meta_guard.Unlock();
  }

  std::string shell_cwd = AMStr::Strip(workdir);
  if (!shell_cwd.empty()) {
    shell_cwd = ResolveAbsolutePath_(client, metadata, shell_cwd);
  }

  const std::string final_cmd = BuildShellRunCmd_(
      os_type, shell_cwd, cmd, metadata.cmd_prefix, metadata.wrap_cmd);
  if (final_cmd_out != nullptr) {
    *final_cmd_out = final_cmd;
  }

  out = client->IOPort().ConductCmd({final_cmd, {}}, control);
  return out;
}

} // namespace AMApplication::filesystem
