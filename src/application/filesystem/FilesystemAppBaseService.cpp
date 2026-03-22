#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <map>
#include <stdexcept>

namespace AMApplication::filesystem {
namespace {
using ClientHandle = AMDomain::client::ClientHandle;
using ClientMetaData = AMDomain::host::ClientMetaData;
using HostConfig = AMDomain::host::HostConfig;

bool HasWildcard(const std::string &path) {
  return path.find('*') != std::string::npos ||
         (path.find('<') != std::string::npos &&
          path.find('>') != std::string::npos);
}

bool IsLocalRequest_(const std::string &nickname, ClientHandle local_client) {
  const std::string name = AMStr::Strip(nickname);
  if (name.empty() || name == "local") {
    return true;
  }
  if (!local_client) {
    return false;
  }
  const std::string local_name =
      AMStr::Strip(local_client->ConfigPort().GetNickname());
  return !local_name.empty() && name == local_name;
}
} // namespace

namespace ClientOperationHelper {
ECMData<std::string> GetClientHome(ClientHandle client,
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

ECMData<std::string> GetClientCwd(ClientHandle client,
                                  const ClientControlComponent &control) {
  if (!client) {
    return {"", Err(EC::InvalidHandle, "Client handle is null")};
  }
  std::string cwd = "";
  {
    auto meta_guard = client->MetaDataPort().GetLockGaurd();
    auto *metadata = client->MetaDataPort().QueryTypedValue<ClientMetaData>();
    if (!metadata) {
      return {"", Err(EC::CommonFailure, "Client metadata not found")};
    }
    cwd = metadata->cwd;
  }
  if (!cwd.empty()) {
    return {cwd, Ok()};
  }
  auto home_res = GetClientHome(client, control);
  if (!isok(home_res.rcm)) {
    return {"", home_res.rcm};
  }
  const std::string home = home_res.data;
  if (home.empty()) {
    return {"", Err(EC::CommonFailure,
                    "Metadata is empty and fallback home directory is empty")};
  }
  return {home, Ok()};
}

ECM AbsolutePath(ClientPath &path) {
  if (!path.client) {
    return Err(EC::InvalidHandle, "Client handle is null");
  }

  const ClientControlComponent control = {};
  auto home_result = GetClientHome(path.client, control);
  if (!isok(home_result.rcm)) {
    return home_result.rcm;
  }

  auto cwd_result = GetClientCwd(path.client, control);
  if (!isok(cwd_result.rcm)) {
    return cwd_result.rcm;
  }

  const std::string input = path.path.empty() ? "." : path.path;
  path.path = AMFS::abspath(input, true, home_result.data, cwd_result.data);
  path.rcm = Ok();
  return Ok();
}
} // namespace ClientOperationHelper

FilesystemAppBaseService::FilesystemAppBaseService(
    FilesystemArg arg, std::shared_ptr<HostAppService> host_service,
    std::shared_ptr<ClientAppService> client_service)
    : init_arg_(arg), host_service_(std::move(host_service)),
      client_service_(std::move(client_service)),
      cd_history_(std::list<ClientPath>{}) {
  if (!host_service_) {
    throw std::invalid_argument("host_service is null");
  }
  if (!client_service_) {
    throw std::invalid_argument("client_service is null");
  }
}

ECM FilesystemAppBaseService::Init() {
  if (!host_service_ || !client_service_) {
    return Err(EC::InvalidHandle, "filesystem app base service deps are null");
  }
  const FilesystemArg arg = init_arg_.lock().load();
  if (arg.max_cd_history <= 0) {
    return Err(EC::InvalidArg, "max_cd_history must be greater than 0");
  }
  return Ok();
}

FilesystemArg FilesystemAppBaseService::GetInitArg() const {
  return init_arg_.lock().load();
}

ECMData<ClientPath>
FilesystemAppBaseService::SplitRawPath(const std::string &token) const {
  if (!client_service_) {
    return {ClientPath{}, Err(EC::InvalidHandle, "client service is null")};
  }

  ClientPath out = {};
  const size_t at_pos = token.find('@');
  if (!token.empty() && token.front() == '@') {
    out.nickname = "local";
    out.path = token.substr(1);
  } else if (at_pos == std::string::npos) {
    out.nickname = AMStr::Strip(client_service_->CurrentNickname());
    out.path = token;
  } else {
    out.nickname = AMStr::Strip(token.substr(0, at_pos));
    out.path = token.substr(at_pos + 1);
  }

  if (out.nickname.empty()) {
    const ClientHandle local_client = client_service_->GetLocalClient();
    out.nickname = local_client
                       ? AMStr::Strip(local_client->ConfigPort().GetNickname())
                       : "";
    if (out.nickname.empty()) {
      out.nickname = "local";
    }
  }
  if (out.path.empty()) {
    out.path = ".";
  }

  out.is_wildcard = HasWildcard(out.path);
  out.userpath = !out.path.empty() && out.path.front() == '~';

  return {std::move(out), Ok()};
}

ECMData<ClientHandle> FilesystemAppBaseService::GetClient(
    const std::string &nickname,
    const AMDomain::client::ClientControlComponent &control) {
  if (!host_service_ || !client_service_) {
    return {nullptr, Err(EC::InvalidHandle,
                         "filesystem app base service deps are null")};
  }

  std::string resolved_nickname = AMStr::Strip(nickname);
  if (resolved_nickname.empty()) {
    resolved_nickname = AMStr::Strip(client_service_->CurrentNickname());
  }
  const ClientHandle local_client = client_service_->GetLocalClient();
  if (resolved_nickname.empty()) {
    resolved_nickname =
        local_client ? AMStr::Strip(local_client->ConfigPort().GetNickname())
                     : "";
    if (resolved_nickname.empty()) {
      resolved_nickname = "local";
    }
  }

  const bool target_local = IsLocalRequest_(resolved_nickname, local_client);
  ClientHandle existing = target_local
                              ? local_client
                              : client_service_->GetClient(resolved_nickname);
  if (existing) {
    return {existing, Ok()};
  }

  std::pair<ECM, HostConfig> host_cfg = {};
  if (target_local) {
    host_cfg = host_service_->GetLocalConfig();
  } else {
    if (!host_service_->HostExists(resolved_nickname)) {
      return {nullptr,
              Err(EC::HostConfigNotFound,
                  AMStr::fmt("Host config not found: {}", resolved_nickname))};
    }
    host_cfg = host_service_->GetClientConfig(resolved_nickname);
  }
  if (!isok(host_cfg.first)) {
    return {nullptr, host_cfg.first};
  }

  auto create_result = client_service_->CreateClient(host_cfg.second, control);
  if (!isok(create_result.rcm) || !create_result.data) {
    return {create_result.data, create_result.rcm};
  }

  const ECM add_rcm = client_service_->AddClient(create_result.data, false);
  if (!isok(add_rcm)) {
    ClientHandle raced = target_local
                             ? client_service_->GetLocalClient()
                             : client_service_->GetClient(resolved_nickname);
    if (raced) {
      return {raced, Ok()};
    }
    return {nullptr, add_rcm};
  }

  ClientHandle resolved = target_local
                              ? client_service_->GetLocalClient()
                              : client_service_->GetClient(resolved_nickname);
  if (!resolved) {
    resolved = create_result.data;
  }
  return {resolved, Ok()};
}

ECM FilesystemAppBaseService::ResolvePath(
    ClientPath &path, const AMDomain::client::ClientControlComponent &control) {
  std::vector<ClientPath> paths = {path};
  const ECM status = ResolvePath(paths, control, true);
  if (!paths.empty()) {
    path = std::move(paths.front());
  }
  return status;
}

ECM FilesystemAppBaseService::ResolvePath(
    std::vector<ClientPath> &paths,
    const AMDomain::client::ClientControlComponent &control, bool error_stop) {
  if (!client_service_) {
    return Err(EC::InvalidHandle, "client service is null");
  }

  std::map<std::string, ClientHandle> cache = {};
  ECM status = Ok();

  for (auto &entry : paths) {
    std::string resolved_nickname = {};
    if (entry.client) {
      resolved_nickname = entry.client->ConfigPort().GetNickname();
    } else {
      resolved_nickname = entry.nickname;
    }
    if (resolved_nickname.empty()) {
      resolved_nickname = client_service_->CurrentNickname();
    }
    entry.nickname = resolved_nickname;

    if (entry.client) {
      cache[entry.nickname] = entry.client;
      if (entry.resolved) {
        return Ok();
      }
    } else {
      auto cached = cache.find(entry.nickname);
      if (cached != cache.end()) {
        entry.client = cached->second;
      } else {
        auto get_result = GetClient(entry.nickname, control);
        entry.rcm = get_result.rcm;
        if (!isok(get_result.rcm) || !get_result.data) {
          entry.client = nullptr;
          if (error_stop) {
            return get_result.rcm;
          }
          if (isok(status)) {
            status = get_result.rcm;
          }
          continue;
        }

        entry.client = get_result.data;
        cache[entry.nickname] = get_result.data;
      }
    }

    const std::string input_path = entry.path.empty() ? "." : entry.path;
    entry.is_wildcard = HasWildcard(input_path);
    entry.userpath = !input_path.empty() && input_path.front() == '~';

    entry.path = input_path;
    const ECM abs_rcm = ClientOperationHelper::AbsolutePath(entry);
    if (!isok(abs_rcm)) {
      entry.rcm = abs_rcm;
      entry.client = nullptr;
      if (error_stop) {
        return abs_rcm;
      }
      if (isok(status)) {
        status = abs_rcm;
      }
      continue;
    }
    entry.rcm = Ok();
  }

  return status;
}

AMAtomic<std::list<ClientPath>> &FilesystemAppBaseService::CdHistory() {
  return cd_history_;
}

const AMAtomic<std::list<ClientPath>> &
FilesystemAppBaseService::CdHistory() const {
  return cd_history_;
}
} // namespace AMApplication::filesystem
