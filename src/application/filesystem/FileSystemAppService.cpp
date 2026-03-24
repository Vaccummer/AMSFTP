#include "application/filesystem/FilesystemAppService.hpp"
#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <string>

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
} // namespace

FilesystemAppService::FilesystemAppService(
    FilesystemArg arg, std::shared_ptr<HostAppService> host_service,
    std::shared_ptr<ClientAppService> client_service)
    : FilesystemAppBaseService(arg, std::move(host_service),
                               std::move(client_service)) {}

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

ECMData<std::vector<PathStatItem>>
FilesystemAppService::Stat(std::vector<ClientPath> paths,
                           const ClientControlComponent &control) {
  ECM first_error = ResolvePath(paths, control, false);
  std::vector<PathStatItem> items = {};
  items.reserve(paths.size());

  for (auto &entry : paths) {
    PathStatItem item = {};
    item.target = entry;
    item.rcm = entry.rcm;
    if (!entry.client && isok(item.rcm)) {
      item.rcm = Err(EC::InvalidHandle, "Resolved client is null");
    }
    if (entry.client && isok(item.rcm)) {
      item.target.path = entry.path;
      auto stat_result =
          BaseStat(entry.client, entry.nickname, entry.path, control);
      item.rcm = stat_result.rcm;
      if (isok(item.rcm)) {
        item.info = stat_result.data;
      }
    }
    if (isok(first_error) && !isok(item.rcm)) {
      first_error = item.rcm;
    }
    items.push_back(std::move(item));
  }

  return {std::move(items), first_error};
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
                              const ClientControlComponent &control) {
  auto get_result = GetClient(nickname, control);
  if (!isok(get_result.rcm) || !get_result.data) {
    return {-1.0, isok(get_result.rcm)
                      ? Err(EC::InvalidHandle, "Client is null")
                      : get_result.rcm};
  }
  auto rtt_result = get_result.data->IOPort().GetRTT({}, control);
  return {rtt_result.rtt_ms, rtt_result.rcm};
}

ECM FilesystemAppService::Rename(const ClientPath &src, const ClientPath &dst,
                                 const ClientControlComponent &control) {
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

  auto stat_result =
      resolved_src.client->IOPort().stat({resolved_src.path, false}, control);
  if (!isok(stat_result.rcm)) {
    return stat_result.rcm;
  }

  auto rename_result = resolved_src.client->IOPort().rename(
      {resolved_src.path, resolved_dst.path,
       stat_result.info.type == PathType::DIR, true, false},
      control);
  return rename_result.rcm;
}

RunResult FilesystemAppService::ShellRun(
    const std::string &nickname, const std::string &workdir,
    const std::string &cmd, const ClientControlComponent &control) {
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

  out = client->IOPort().ConductCmd({final_cmd, {}}, control);
  return out;
}

} // namespace AMApplication::filesystem
