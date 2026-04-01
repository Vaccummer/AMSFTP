#include "application/filesystem/FilesystemAppService.hpp"
#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/tools/enum_related.hpp"
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

bool IsDrivePart_(const std::string &part) {
  return part.size() == 2 &&
         ((part[0] >= 'A' && part[0] <= 'Z') ||
          (part[0] >= 'a' && part[0] <= 'z')) &&
         part[1] == ':';
}

std::string ResolveWorkdir_(const ClientMetaData &metadata,
                            const std::string &home_dir) {
  const std::string normalized_cwd =
      AMDomain::filesystem::services::NormalizePath(AMStr::Strip(metadata.cwd));
  if (!normalized_cwd.empty()) {
    return normalized_cwd;
  }

  const std::string normalized_login_dir =
      AMDomain::filesystem::services::NormalizePath(
          AMStr::Strip(metadata.login_dir));
  if (!normalized_login_dir.empty()) {
    return normalized_login_dir;
  }

  const std::string normalized_home =
      AMDomain::filesystem::services::NormalizePath(AMStr::Strip(home_dir));
  if (!normalized_home.empty()) {
    return normalized_home;
  }
  return ".";
}

std::string ResolveAbsolutePath_(ClientHandle client,
                                 const ClientMetaData &metadata,
                                 const std::string &raw_path) {
  const std::string input = raw_path.empty() ? "." : raw_path;
  const std::string home_dir = client ? client->ConfigPort().GetHomeDir() : "";
  const std::string cwd = ResolveWorkdir_(metadata, home_dir);
  return AMPath::abspath(input, true, home_dir, cwd);
}

std::vector<std::string> BuildMkdirTargets_(const std::string &abs_path,
                                            const std::string &sep) {
  std::vector<std::string> parts = AMPath::split(abs_path);
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

std::string RenderCmdTemplate_(const std::string &templ, const std::string &cmd,
                               const std::string &escaped_cmd,
                               const std::string &nickname,
                               const std::string &username,
                               const std::string &cwd) {
  std::string out;
  out.reserve(templ.size() + cmd.size());

  for (size_t i = 0; i < templ.size();) {
    const char ch = templ[i];
    if (ch == '`') {
      if (i + 1 < templ.size()) {
        out.push_back(templ[i + 1]);
        i += 2;
      } else {
        out.push_back('`');
        ++i;
      }
      continue;
    }

    if (ch == '{' && i + 1 < templ.size() && templ[i + 1] == '$') {
      size_t j = i + 2;
      std::string key;
      bool found_close = false;
      while (j < templ.size()) {
        if (templ[j] == '`') {
          if (j + 1 < templ.size()) {
            key.push_back(templ[j + 1]);
            j += 2;
            continue;
          }
          ++j;
          continue;
        }
        if (templ[j] == '}') {
          found_close = true;
          break;
        }
        key.push_back(templ[j]);
        ++j;
      }

      if (found_close) {
        const std::string norm_key = AMStr::lowercase(AMStr::Strip(key));
        if (norm_key == "cmd") {
          out += cmd;
        } else if (norm_key == "escaped_cmd") {
          out += escaped_cmd;
        } else if (norm_key == "nickname") {
          out += nickname;
        } else if (norm_key == "username") {
          out += username;
        } else if (norm_key == "cwd") {
          out += cwd;
        } else {
          out.append(templ, i, j - i + 1);
        }
        i = j + 1;
        continue;
      }
    }

    out.push_back(ch);
    ++i;
  }
  return out;
}

std::string BuildShellRunCmd_(AMDomain::client::OS_TYPE os_type,
                              const std::string &cwd,
                              const std::string &command,
                              const std::string &cmd_prefix, bool wrap_cmd,
                              const std::string &nickname,
                              const std::string &username) {
  const std::string escaped_cmd = AMStr::replace_all(command, "\"", "'");
  if (cmd_prefix.find("{$") != std::string::npos) {
    return RenderCmdTemplate_(cmd_prefix, command, escaped_cmd, nickname,
                              username, cwd);
  }

  std::string final_cmd = command;
  const std::string shell_cwd = AMStr::Strip(cwd);
  if (!shell_cwd.empty()) {
    if (os_type == AMDomain::client::OS_TYPE::Windows) {
      final_cmd =
          AMStr::fmt("cd \"{}\";{}", EscapeDoubleQuote_(shell_cwd), final_cmd);
    } else {
      final_cmd =
          AMStr::fmt("cd \"{}\"&&{}", EscapeDoubleQuote_(shell_cwd), final_cmd);
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

void AddPathError_(std::vector<std::pair<PathTarget, ECM>> *errors, ECM *status,
                   const PathTarget &path, const ECM &rcm) {
  if (errors) {
    errors->push_back({path, rcm});
  }
  if (status && !isok(rcm)) {
    *status = rcm;
  }
}

void AddSafermError_(std::vector<std::pair<PathTarget, ECM>> *errors,
                     ECM *status, const PathTarget &path, const ECM &rcm) {
  AddPathError_(errors, status, path, rcm);
}

PathTarget ToPathTarget_(const ResolvedPath &resolved) {
  PathTarget out = resolved.target;
  if (!resolved.abs_path.empty()) {
    out.path = resolved.abs_path;
  }
  return out;
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

FilesystemAppService::FilesystemAppService(FilesystemArg arg,
                                           HostAppService *host_service,
                                           ClientAppService *client_service)
    : FilesystemAppBaseService(arg, host_service, client_service) {}

ECMData<std::string>
FilesystemAppService::GetClientHome(ClientHandle client,
                                    const ClientControlComponent &control) {
  if (!client) {
    return {"", Err(EC::InvalidHandle, "Client handle is null")};
  }

  std::string home = AMStr::Strip(client->ConfigPort().GetHomeDir());
  if (home.empty()) {
    auto update_result = client->IOPort().UpdateHomeDir({}, control);
    if (!isok(update_result.rcm)) {
      return {"", update_result.rcm};
    }
    home = AMStr::Strip(update_result.home_dir);
    if (home.empty()) {
      home = AMStr::Strip(client->ConfigPort().GetHomeDir());
    } else {
      client->ConfigPort().SetHomeDir(home);
    }
  }

  if (home.empty()) {
    return {"", Err(EC::CommonFailure, "Client home directory is empty")};
  }
  return {home, Ok()};
}

ECMData<std::string>
FilesystemAppService::GetClientCwd(ClientHandle client,
                                   const ClientControlComponent &control) {
  if (!client) {
    return {"", Err(EC::InvalidHandle, "Client handle is null")};
  }
  auto meta_cwd = ClientAppService::GetClientCwd(client);
  if (isok(meta_cwd.rcm) && !AMStr::Strip(meta_cwd.data).empty()) {
    return {AMDomain::filesystem::services::NormalizePath(meta_cwd.data), Ok()};
  }
  auto home_res = GetClientHome(client, control);
  if (!isok(home_res.rcm)) {
    return {"", home_res.rcm};
  }
  return {AMDomain::filesystem::services::NormalizePath(home_res.data), Ok()};
}

ECMData<std::string> FilesystemAppService::ResolveAbsolutePath(
    ClientHandle client, const std::string &raw_path,
    const ClientControlComponent &control) {
  if (!client) {
    return {"", Err(EC::InvalidHandle, "Client handle is null")};
  }
  auto home_result = GetClientHome(client, control);
  if (!isok(home_result.rcm)) {
    return {"", home_result.rcm};
  }
  auto cwd_result = GetClientCwd(client, control);
  if (!isok(cwd_result.rcm)) {
    return {"", cwd_result.rcm};
  }

  const std::string input = raw_path.empty() ? "." : raw_path;
  const std::string abs_path =
      AMPath::abspath(input, true, home_result.data, cwd_result.data);
  return {AMDomain::filesystem::services::NormalizePath(abs_path), Ok()};
}

ECMData<PathTarget>
FilesystemAppService::GetCwd(const ClientControlComponent &control) {
  PathTarget out = {};
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
  auto res = GetClientCwd(client, control);
  if (!isok(res.rcm)) {
    return {std::move(out), res.rcm};
  }
  out.nickname = AMDomain::host::HostService::NormalizeNickname(
      client->ConfigPort().GetNickname());
  out.path = res.data;
  return {std::move(out), Ok()};
}

ECM FilesystemAppService::EnsureClientWorkdir(
    ClientHandle client, const ClientControlComponent &control) {
  if (!client) {
    return Err(EC::InvalidHandle, "Client handle is null");
  }
  auto metadata_opt = ClientAppService::GetClientMetadata(client);
  if (!metadata_opt.has_value()) {
    return Err(EC::CommonFailure, "Client metadata not found");
  }
  ClientMetaData metadata = *metadata_opt;

  const std::string normalized_home =
      AMDomain::filesystem::services::NormalizePath(
          AMStr::Strip(client->ConfigPort().GetHomeDir()));
  const auto try_resolve_dir =
      [&](const std::string &raw_candidate) -> ECMData<std::string> {
    const std::string normalized_candidate =
        AMDomain::filesystem::services::NormalizePath(
            AMStr::Strip(raw_candidate));
    if (normalized_candidate.empty()) {
      return {"", Err(EC::InvalidArg, "empty workdir candidate")};
    }
    std::string absolute_path =
        ResolveAbsolutePath_(client, metadata, normalized_candidate);
    absolute_path =
        AMDomain::filesystem::services::NormalizePath(absolute_path);
    if (absolute_path.empty()) {
      return {"", Err(EC::InvalidArg, "invalid workdir candidate")};
    }

    auto stat_result = client->IOPort().stat({absolute_path, false}, control);
    if (!isok(stat_result.rcm)) {
      return {"", stat_result.rcm};
    }
    if (stat_result.info.type != PathType::DIR) {
      return {"", Err(EC::NotADirectory,
                      AMStr::fmt("Not a directory: {}", absolute_path))};
    }

    std::string resolved =
        AMDomain::filesystem::services::NormalizePath(stat_result.info.path);
    if (resolved.empty()) {
      resolved = absolute_path;
    }
    return {resolved, Ok()};
  };

  std::string resolved_workdir = {};
  if (!AMStr::Strip(metadata.cwd).empty()) {
    auto cwd_result = try_resolve_dir(metadata.cwd);
    if (isok(cwd_result.rcm)) {
      resolved_workdir = std::move(cwd_result.data);
    }
  }
  if (resolved_workdir.empty() && !AMStr::Strip(metadata.login_dir).empty()) {
    auto login_result = try_resolve_dir(metadata.login_dir);
    if (isok(login_result.rcm)) {
      resolved_workdir = std::move(login_result.data);
    }
  }
  if (resolved_workdir.empty() && !normalized_home.empty()) {
    auto home_result = try_resolve_dir(normalized_home);
    if (isok(home_result.rcm)) {
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
    return {PathTarget{}, Err(EC::InvalidArg, "cd history is empty")};
  }
  return {list.front(), Ok()};
}

ECM FilesystemAppService::ChangeDir(PathTarget path,
                                    const ClientControlComponent &control,
                                    bool from_history) {
  auto resolved_result = ResolvePath(path, control);
  if (!isok(resolved_result.rcm) || !resolved_result.data.client) {
    return isok(resolved_result.rcm)
               ? Err(EC::InvalidHandle, "Resolved client is null")
               : resolved_result.rcm;
  }
  const ResolvedPath &resolved = resolved_result.data;
  ClientHandle client = resolved.client;

  auto metadata_opt = ClientAppService::GetClientMetadata(client);
  if (!metadata_opt.has_value()) {
    return Err(EC::CommonFailure, "Client metadata not found");
  }
  ClientMetaData metadata = *metadata_opt;
  const std::string prev_cwd = metadata.cwd;
  const std::string abs_target = resolved.abs_path;
  auto stat_result = client->IOPort().stat({abs_target, false}, control);
  if (!isok(stat_result.rcm)) {
    return stat_result.rcm;
  }
  if (stat_result.info.type != PathType::DIR) {
    return Err(EC::NotADirectory,
               AMStr::fmt("Not a directory: {}", abs_target));
  }
  std::string resolved_target =
      AMDomain::filesystem::services::NormalizePath(stat_result.info.path);
  if (resolved_target.empty()) {
    resolved_target = AMDomain::filesystem::services::NormalizePath(abs_target);
  }
  if (resolved_target.empty()) {
    resolved_target = abs_target;
  }

  metadata.cwd = resolved_target;
  const ECM set_meta_rcm =
      ClientAppService::SetClientMetadata(client, metadata);
  if (!isok(set_meta_rcm)) {
    return set_meta_rcm;
  }

  client_service_->SetCurrentClient(client);

  if (!from_history && !prev_cwd.empty() && prev_cwd != resolved_target) {
    auto history = cd_history_.lock();
    auto list = history.load();
    PathTarget entry = {};
    entry.nickname = AMStr::Strip(client->ConfigPort().GetNickname());
    entry.path = prev_cwd;
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

ECMData<PathEntry> FilesystemAppService::StatEntry(
    const PathTarget &target, const ClientControlComponent &control,
    bool trace_link, ClientHandle preferred_client) {
  auto resolved = ResolvePath(target, control, preferred_client);
  if (!isok(resolved.rcm) || !resolved.data.client) {
    return {PathEntry{}, isok(resolved.rcm)
                             ? Err(EC::InvalidHandle, "Resolved client is null")
                             : resolved.rcm};
  }

  auto stat_result =
      BaseStat(resolved.data.client, resolved.data.target.nickname,
               resolved.data.abs_path, control, trace_link);
  if (!isok(stat_result.rcm)) {
    return {PathEntry{}, stat_result.rcm};
  }

  PathEntry out = {};
  out.resolved = std::move(resolved.data);
  out.info = std::move(stat_result.data);
  return {std::move(out), Ok()};
}

ECMData<PathInfo>
FilesystemAppService::Stat(const PathTarget &path,
                           const ClientControlComponent &control,
                           bool trace_link, ClientHandle preferred_client) {
  auto entry_result = StatEntry(path, control, trace_link, preferred_client);
  if (!isok(entry_result.rcm)) {
    return {PathInfo{}, entry_result.rcm};
  }
  return {entry_result.data.info, Ok()};
}

ECMData<std::vector<PathInfo>>
FilesystemAppService::Listdir(const PathTarget &path,
                              const ClientControlComponent &control,
                              ClientHandle preferred_client) {
  auto resolved_result = ResolvePath(path, control, preferred_client);
  if (!isok(resolved_result.rcm) || !resolved_result.data.client) {
    return {{},
            isok(resolved_result.rcm)
                ? Err(EC::InvalidHandle, "Resolved client is null")
                : resolved_result.rcm};
  }
  const auto &resolved = resolved_result.data;
  return BaseListdir(resolved.client, resolved.target.nickname,
                     resolved.abs_path, control);
}

ECMData<std::vector<std::string>>
FilesystemAppService::ListNames(const PathTarget &path,
                                const ClientControlComponent &control,
                                ClientHandle preferred_client) {
  auto resolved_result = ResolvePath(path, control, preferred_client);
  if (!isok(resolved_result.rcm) || !resolved_result.data.client) {
    return {{},
            isok(resolved_result.rcm)
                ? Err(EC::InvalidHandle, "Resolved client is null")
                : resolved_result.rcm};
  }
  const auto &resolved = resolved_result.data;
  return BaseListNames(resolved.client, resolved.target.nickname,
                       resolved.abs_path, control);
}

ECM FilesystemAppService::Mkdirs(const PathTarget &path,
                                 const ClientControlComponent &control,
                                 ClientHandle preferred_client) {
  auto resolved_result = ResolvePath(path, control, preferred_client);
  if (!isok(resolved_result.rcm) || !resolved_result.data.client) {
    return isok(resolved_result.rcm)
               ? Err(EC::InvalidHandle, "Resolved client is null")
               : resolved_result.rcm;
  }

  const auto &resolved = resolved_result.data;
  ClientHandle client = resolved.client;
  const std::vector<std::string> targets = AMPath::split(resolved.abs_path);

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

ECMData<PathTarget>
FilesystemAppService::ResolveTrashDir(const PathTarget &source,
                                      const ClientControlComponent &control,
                                      ClientHandle preferred_client) {
  auto source_resolved = ResolvePath(source, control, preferred_client);
  if (!isok(source_resolved.rcm) || !source_resolved.data.client) {
    return {PathTarget{},
            isok(source_resolved.rcm)
                ? Err(EC::InvalidHandle, "Resolved client is null")
                : source_resolved.rcm};
  }

  std::string trash_dir = {};
  auto metadata =
      ClientAppService::GetClientMetadata(source_resolved.data.client);
  if (!metadata.has_value()) {
    return {PathTarget{}, Err(EC::CommonFailure, "Client metadata not found")};
  }
  trash_dir = AMStr::Strip(metadata->trash_dir);
  if (trash_dir.empty()) {
    trash_dir = "~/.AMSFTP_Trash";
  }

  auto abs_rcm =
      ResolveAbsolutePath(source_resolved.data.client, trash_dir, control);
  if (!isok(abs_rcm.rcm)) {
    return {PathTarget{}, abs_rcm.rcm};
  }

  PathTarget out = {};
  out.nickname = source_resolved.data.target.nickname;
  out.path = abs_rcm.data;
  return {std::move(out), Ok()};
}

ECM FilesystemAppService::Rename(const PathTarget &src, const PathTarget &dst,
                                 const ClientControlComponent &control,
                                 bool mkdir, bool overwrite) {
  auto src_resolved = ResolvePath(src, control);
  if (!isok(src_resolved.rcm) || !src_resolved.data.client) {
    return isok(src_resolved.rcm)
               ? Err(EC::InvalidHandle, "Resolved source client is null")
               : src_resolved.rcm;
  }
  const auto &resolved_src = src_resolved.data;

  PathTarget dst_target = dst;
  ClientHandle preferred_dst_client = nullptr;
  if (AMStr::Strip(dst_target.nickname).empty()) {
    dst_target.nickname = resolved_src.target.nickname;
    preferred_dst_client = resolved_src.client;
  }
  auto dst_resolved = ResolvePath(dst_target, control, preferred_dst_client);
  if (!isok(dst_resolved.rcm) || !dst_resolved.data.client) {
    return isok(dst_resolved.rcm)
               ? Err(EC::InvalidHandle, "Resolved destination client is null")
               : dst_resolved.rcm;
  }
  const auto &resolved_dst = dst_resolved.data;

  if (resolved_src.client != resolved_dst.client ||
      resolved_src.target.nickname != resolved_dst.target.nickname) {
    return Err(EC::InvalidArg,
               "Rename across different clients is not supported");
  }
  if (resolved_src.abs_path == resolved_dst.abs_path) {
    return Ok();
  }

  auto stat_result = resolved_src.client->IOPort().stat(
      {resolved_src.abs_path, false}, control);
  if (!isok(stat_result.rcm)) {
    return stat_result.rcm;
  }
  const bool src_is_dir = stat_result.info.type == PathType::DIR;

  const std::string dst_parent = AMPath::dirname(resolved_dst.abs_path);
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

  auto dst_stat = resolved_src.client->IOPort().stat(
      {resolved_dst.abs_path, false}, control);
  if (isok(dst_stat.rcm)) {
    if ((dst_stat.info.type == PathType::DIR) != src_is_dir) {
      return Err(EC::PathAlreadyExists,
                 AMStr::fmt("Destination exists with different type: {}",
                            resolved_dst.abs_path));
    }
    if (!overwrite) {
      return Err(
          EC::PathAlreadyExists,
          AMStr::fmt("Destination already exists: {}", resolved_dst.abs_path));
    }
  } else if (!AMDomain::filesystem::services::IsPathNotExistError(
                 dst_stat.rcm.first)) {
    return dst_stat.rcm;
  }

  auto rename_result = resolved_src.client->IOPort().rename(
      {resolved_src.abs_path, resolved_dst.abs_path, src_is_dir, mkdir,
       overwrite},
      control);
  if (!isok(rename_result.rcm)) {
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
  return Ok();
}

ECMData<RmfilePlan>
FilesystemAppService::PrepareRmfile(std::vector<PathTarget> targets,
                                    const ClientControlComponent &control) {
  RmfilePlan plan = {};
  ECM status = Ok();
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    AddPathError_(&plan.precheck_errors, &status, PathTarget{}, rcm);
    plan.rcm = rcm;
    return {std::move(plan), rcm};
  }

  std::vector<PathTarget> expanded_targets = {};
  expanded_targets.reserve(targets.size());
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

    target.nickname =
        AMDomain::host::HostService::NormalizeNickname(target.nickname);
    target.path = AMDomain::filesystem::services::NormalizePath(
        target.path.empty() ? "." : target.path);
    if (target.path.empty()) {
      target.path = ".";
    }

    if (AMDomain::filesystem::services::HasWildcard(target.path)) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&plan, &status](const PathTarget &error_path, ECM error_rcm) {
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
        PathTarget item = {};
        item.nickname = target.nickname;
        item.path = AMDomain::filesystem::services::NormalizePath(entry.path);
        if (item.path.empty()) {
          item.path = ".";
        }
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

    auto resolved_result = ResolvePath(target, control);
    if (!isok(resolved_result.rcm) || !resolved_result.data.client) {
      const ECM rcm = isok(resolved_result.rcm)
                          ? Err(EC::InvalidHandle, "Resolved client is null")
                          : resolved_result.rcm;
      AddPathError_(&plan.precheck_errors, &status, target, rcm);
      if (IsStopError_(rcm.first)) {
        plan.rcm = rcm;
        return {std::move(plan), rcm};
      }
      continue;
    }

    const ResolvedPath &resolved = resolved_result.data;
    auto stat_result = BaseStat(resolved.client, resolved.target.nickname,
                                resolved.abs_path, control, false);
    if (!isok(stat_result.rcm)) {
      AddPathError_(&plan.precheck_errors, &status, ToPathTarget_(resolved),
                    stat_result.rcm);
      if (IsStopError_(stat_result.rcm.first)) {
        plan.rcm = stat_result.rcm;
        return {std::move(plan), stat_result.rcm};
      }
      continue;
    }
    if (stat_result.data.type == PathType::DIR) {
      const ECM rcm =
          Err(EC::NotAFile, AMStr::fmt("rmfile does not accept directories: {}",
                                       resolved.abs_path));
      AddPathError_(&plan.precheck_errors, &status, ToPathTarget_(resolved),
                    rcm);
      continue;
    }

    PathTarget display = ToPathTarget_(resolved);
    const std::string group_key =
        display.nickname.empty() ? "local" : display.nickname;
    plan.grouped_display_paths[group_key].push_back(display);
    plan.validated_targets.push_back(resolved);
  }

  if (plan.validated_targets.empty() && isok(status)) {
    status = Err(EC::InvalidArg, "No valid file target");
  }
  plan.rcm = status;
  return {std::move(plan), status};
}

ECMData<std::vector<std::pair<PathTarget, ECM>>>
FilesystemAppService::ExecuteRmfile(
    const RmfilePlan &plan, const ClientControlComponent &control,
    std::function<void(const PathTarget &, ECM)> on_error) {
  std::vector<std::pair<PathTarget, ECM>> errors = {};
  ECM status = Ok();
  if (plan.validated_targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No valid file target");
    return {std::move(errors), rcm};
  }

  for (const auto &resolved : plan.validated_targets) {
    if (control.IsInterrupted()) {
      return {std::move(errors), Err(EC::Terminate, "Interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {std::move(errors),
              Err(EC::OperationTimeout, "Operation timed out")};
    }

    PathTarget target = ToPathTarget_(resolved);
    if (!resolved.client) {
      const ECM rcm = Err(EC::InvalidHandle, "Resolved client is null");
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      continue;
    }

    auto stat_result =
        resolved.client->IOPort().stat({resolved.abs_path, false}, control);
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
                                       resolved.abs_path));
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      continue;
    }

    auto remove_result =
        resolved.client->IOPort().rmfile({resolved.abs_path}, control);
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

    ClearBaseIOCacheByPath(resolved.target.nickname, resolved.abs_path);
    const std::string parent = AMPath::dirname(resolved.abs_path);
    if (!parent.empty()) {
      ClearBaseIOCacheByPath(resolved.target.nickname, parent);
    }
  }
  return {std::move(errors), status};
}

ECMData<std::vector<std::pair<PathTarget, ECM>>> FilesystemAppService::Rmdir(
    std::vector<PathTarget> targets, const ClientControlComponent &control,
    std::function<void(const PathTarget &, ECM)> on_error) {
  std::vector<std::pair<PathTarget, ECM>> errors = {};
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

    auto resolved_result = ResolvePath(target, control);
    if (!isok(resolved_result.rcm) || !resolved_result.data.client) {
      const ECM rcm = isok(resolved_result.rcm)
                          ? Err(EC::InvalidHandle, "Resolved client is null")
                          : resolved_result.rcm;
      AddPathError_(&errors, &status, target, rcm);
      if (on_error) {
        on_error(target, rcm);
      }
      if (IsStopError_(rcm.first)) {
        return {std::move(errors), rcm};
      }
      continue;
    }

    const ResolvedPath &resolved = resolved_result.data;
    PathTarget display = ToPathTarget_(resolved);
    auto stat_result =
        resolved.client->IOPort().stat({resolved.abs_path, false}, control);
    if (!isok(stat_result.rcm)) {
      AddPathError_(&errors, &status, display, stat_result.rcm);
      if (on_error) {
        on_error(display, stat_result.rcm);
      }
      if (IsStopError_(stat_result.rcm.first)) {
        return {std::move(errors), stat_result.rcm};
      }
      continue;
    }
    if (stat_result.info.type != PathType::DIR) {
      const ECM rcm = Err(
          EC::NotADirectory,
          AMStr::fmt("rmdir only accepts directories: {}", resolved.abs_path));
      AddPathError_(&errors, &status, display, rcm);
      if (on_error) {
        on_error(display, rcm);
      }
      continue;
    }

    auto remove_result =
        resolved.client->IOPort().rmdir({resolved.abs_path}, control);
    if (!isok(remove_result.rcm)) {
      AddPathError_(&errors, &status, display, remove_result.rcm);
      if (on_error) {
        on_error(display, remove_result.rcm);
      }
      if (IsStopError_(remove_result.rcm.first)) {
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
  return {std::move(errors), status};
}

ECMData<PermanentRemovePlan> FilesystemAppService::PreparePermanentRemove(
    std::vector<PathTarget> targets, const ClientControlComponent &control) {
  PermanentRemovePlan plan = {};
  ECM status = Ok();
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    AddPathError_(&plan.precheck_errors, &status, PathTarget{}, rcm);
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

    target.nickname =
        AMDomain::host::HostService::NormalizeNickname(target.nickname);
    target.path = AMDomain::filesystem::services::NormalizePath(
        target.path.empty() ? "." : target.path);
    if (target.path.empty()) {
      target.path = ".";
    }

    if (AMDomain::filesystem::services::HasWildcard(target.path)) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&plan, &status](const PathTarget &error_path, ECM error_rcm) {
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
      PathTarget root = {};
      root.nickname = nickname;
      root.path = entry.path;
      auto root_resolved = ResolvePath(root, control);
      if (!isok(root_resolved.rcm) || !root_resolved.data.client) {
        const ECM rcm = isok(root_resolved.rcm)
                            ? Err(EC::InvalidHandle, "Resolved client is null")
                            : root_resolved.rcm;
        AddPathError_(&plan.precheck_errors, &status, root, rcm);
        if (IsStopError_(rcm.first)) {
          plan.rcm = rcm;
          return {std::move(plan), rcm};
        }
        continue;
      }

      const ResolvedPath resolved_root = root_resolved.data;
      PathTarget display_root = ToPathTarget_(resolved_root);
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
        ResolvedPath current = std::move(frame.path);
        PathTarget current_display = ToPathTarget_(current);

        if (!frame.expanded) {
          auto stat_result = BaseStat(current.client, current.target.nickname,
                                      current.abs_path, control, false);
          if (!isok(stat_result.rcm)) {
            AddPathError_(&plan.precheck_errors, &status, current_display,
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
          auto list_result =
              BaseListdir(current.client, current.target.nickname,
                          current.abs_path, control);
          if (!isok(list_result.rcm)) {
            AddPathError_(&plan.precheck_errors, &status, current_display,
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
            ResolvedPath child = current;
            child.abs_path =
                AMDomain::filesystem::services::NormalizePath(it->path);
            child.target.path = child.abs_path;
            child.is_wildcard = false;
            child.is_user_path = false;
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

ECMData<std::vector<std::pair<PathTarget, ECM>>>
FilesystemAppService::ExecutePermanentRemove(
    const PermanentRemovePlan &plan, const ClientControlComponent &control,
    std::function<void(const PathTarget &)> on_progress,
    std::function<void(const PathTarget &, ECM)> on_error) {
  std::vector<std::pair<PathTarget, ECM>> errors = {};
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

    PathTarget current_display = ToPathTarget_(item);
    if (!item.client) {
      const ECM rcm = Err(EC::InvalidHandle, "Resolved client is null");
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
    if (!isok(stat_result.rcm)) {
      AddPathError_(&errors, &status, current_display, stat_result.rcm);
      if (on_error) {
        on_error(current_display, stat_result.rcm);
      }
      if (IsStopError_(stat_result.rcm.first)) {
        return {std::move(errors), stat_result.rcm};
      }
      continue;
    }

    ECM remove_rcm = Ok();
    if (stat_result.info.type == PathType::DIR) {
      auto result = item.client->IOPort().rmdir({item.abs_path}, control);
      remove_rcm = result.rcm;
    } else {
      auto result = item.client->IOPort().rmfile({item.abs_path}, control);
      remove_rcm = result.rcm;
    }

    if (!isok(remove_rcm)) {
      AddPathError_(&errors, &status, current_display, remove_rcm);
      if (on_error) {
        on_error(current_display, remove_rcm);
      }
      if (IsStopError_(remove_rcm.first)) {
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

  return {std::move(errors), status};
}

ECMData<std::vector<std::pair<PathTarget, ECM>>>
FilesystemAppService::Saferm(std::vector<PathTarget> targets,
                             const ClientControlComponent &control) {
  std::vector<std::pair<PathTarget, ECM>> errors = {};
  ECM status = Ok();
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    AddSafermError_(&errors, &status, PathTarget{}, rcm);
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

    target.nickname =
        AMDomain::host::HostService::NormalizeNickname(target.nickname);
    target.path = AMDomain::filesystem::services::NormalizePath(
        target.path.empty() ? "." : target.path);
    if (target.path.empty()) {
      target.path = ".";
    }

    if (AMDomain::filesystem::services::HasWildcard(target.path)) {
      auto find_result =
          find(target, SearchType::All, control, {},
               [&errors, &status](const PathTarget &error_path, ECM error_rcm) {
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
            isok(status) ? Err(EC::InvalidArg, "No valid target for saferm")
                         : status};
  }

  const std::string bucket = AMTime::Str("%Y-%m-%d-%H-%M-%S");
  std::unordered_map<std::string, PathTarget> bucket_dir_map = {};
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
        PathTarget trash_dir = std::move(trash_result.data);
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
          PathTarget bucket_dir = trash_dir;
          bucket_dir.path = AMPath::join(trash_dir.path, bucket);
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
    const PathTarget &bucket_dir = bucket_it->second;

    const std::string basename = AMPath::basename(source.path);
    std::string base_name = basename.empty() ? "unnamed" : basename;
    std::string ext_name = {};
    auto source_stat = Stat(source, control, false);
    if (!isok(source_stat.rcm)) {
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
    auto metadata_value = ClientAppService::GetClientMetadata(client);
    if (!metadata_value.has_value()) {
      out.rcm = Err(EC::CommonFailure, "Client metadata not found");
      return out;
    }
    metadata = *metadata_value;
  }

  std::string shell_cwd = AMStr::Strip(workdir);
  const bool template_mode =
      metadata.cmd_prefix.find("{$") != std::string::npos;
  if (!shell_cwd.empty()) {
    shell_cwd = ResolveAbsolutePath_(client, metadata, shell_cwd);
  } else if (template_mode) {
    shell_cwd = ResolveWorkdir_(metadata, client->ConfigPort().GetHomeDir());
  }

  std::string effective_nickname =
      AMStr::Strip(client->ConfigPort().GetNickname());
  if (effective_nickname.empty()) {
    effective_nickname = resolved_nickname;
  }
  const std::string effective_username =
      client->ConfigPort().GetRequest().username;
  const std::string final_cmd = BuildShellRunCmd_(
      os_type, shell_cwd, cmd, metadata.cmd_prefix, metadata.wrap_cmd,
      effective_nickname, effective_username);
  if (final_cmd_out != nullptr) {
    *final_cmd_out = final_cmd;
  }

  out = client->IOPort().ConductCmd({final_cmd, {}}, control);
  return out;
}

} // namespace AMApplication::filesystem
