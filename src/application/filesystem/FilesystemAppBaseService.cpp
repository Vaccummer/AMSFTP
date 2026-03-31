#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <stdexcept>

namespace AMApplication::filesystem {
namespace {
using ClientHandle = AMDomain::client::ClientHandle;
using ClientMetaData = AMDomain::host::ClientMetaData;
using HostConfig = AMDomain::host::HostConfig;
constexpr const char *kTransferLeaseKey = "transfer.lease";

void HashCombine_(size_t &seed, size_t value) {
  seed ^= value + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

ECM AcquireTransferLease_(const ClientHandle &client) {
  if (!client) {
    return Err(EC::InvalidHandle, "Client handle is null");
  }
  auto &meta = client->MetaDataPort();

  bool lease_acquired = false;
  bool lease_missing = false;
  bool type_mismatch = false;
  meta.MutateNamedValue<bool>(
      kTransferLeaseKey, [&](bool *leased, bool name_found, bool type_match) {
        if (!name_found) {
          lease_missing = true;
          return;
        }
        if (!type_match || !leased) {
          type_mismatch = true;
          return;
        }
        if (!*leased) {
          *leased = true;
          lease_acquired = true;
        }
      });

  if (type_mismatch) {
    return Err(EC::CommonFailure, "transfer.lease metadata type is invalid");
  }
  if (lease_acquired) {
    return Ok();
  }

  if (lease_missing) {
    if (meta.StoreNamedData(kTransferLeaseKey, std::any(true), false)) {
      return Ok();
    }
    bool retry_acquired = false;
    bool retry_type_mismatch = false;
    meta.MutateNamedValue<bool>(
        kTransferLeaseKey, [&](bool *leased, bool name_found, bool type_match) {
          if (!name_found) {
            return;
          }
          if (!type_match || !leased) {
            retry_type_mismatch = true;
            return;
          }
          if (!*leased) {
            *leased = true;
            retry_acquired = true;
          }
        });
    if (retry_type_mismatch) {
      return Err(EC::CommonFailure, "transfer.lease metadata type is invalid");
    }
    if (retry_acquired) {
      return Ok();
    }
  }

  return Err(EC::PathUsingByOthers, "Client is already leased");
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
  auto metadata = client->MetaDataPort().QueryTypedValue<ClientMetaData>();
  if (!metadata.has_value()) {
    return {"", Err(EC::CommonFailure, "Client metadata not found")};
  }
  cwd = metadata->cwd;
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
    FilesystemArg arg, HostAppService *host_service,
    ClientAppService *client_service)
    : init_arg_(arg), host_service_(host_service),
      client_service_(client_service),
      cd_history_(std::list<ClientPath>{}) {
  if (!host_service_) {
    throw std::invalid_argument("host_service is null");
  }
  if (!client_service_) {
    throw std::invalid_argument("client_service is null");
  }
}

size_t FilesystemAppBaseService::BaseIOCache::KeyHash::operator()(
    const ClientPath &key) const noexcept {
  size_t seed = 0;
  HashCombine_(seed, std::hash<std::string>{}(key.nickname));
  HashCombine_(seed, std::hash<std::string>{}(key.path));
  return seed;
}

bool FilesystemAppBaseService::BaseIOCache::KeyEq::operator()(
    const ClientPath &lhs, const ClientPath &rhs) const noexcept {
  return lhs.nickname == rhs.nickname && lhs.path == rhs.path;
}

ClientPath FilesystemAppBaseService::BuildBaseCacheKey(
    ClientHandle client, const std::string &nickname,
    const std::string &abs_path) const {
  ClientPath key = {};
  key.client = nullptr;
  key.nickname = nickname;
  if (key.nickname.empty() && client) {
    key.nickname = client->ConfigPort().GetNickname();
  }
  key.path = abs_path;
  key.rcm = Ok();
  return key;
}

std::vector<std::string> FilesystemAppBaseService::BuildBaseListNames(
    const std::vector<PathInfo> &entries) {
  std::vector<std::string> names = {};
  names.reserve(entries.size());
  for (const auto &entry : entries) {
    names.push_back(entry.name);
  }
  return names;
}

ECMData<PathInfo> FilesystemAppBaseService::BaseStat(
    ClientHandle client, const std::string &nickname,
    const std::string &abs_path, const ClientControlComponent &control,
    bool trace_link) {
  if (!client) {
    return {{}, Err(EC::InvalidHandle, "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, "Absolute path is empty")};
  }

  const ClientPath cache_key = BuildBaseCacheKey(client, nickname, abs_path);
  if (!trace_link) {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    const auto &cache = cache_guard.get();
    auto it = cache.find(cache_key);
    if (it != cache.end()) {
      return it->second;
    }
  }

  auto stat_result = client->IOPort().stat({abs_path, trace_link}, control);
  if (!isok(stat_result.rcm)) {
    return {{}, stat_result.rcm};
  }

  ECMData<PathInfo> out = {stat_result.info, stat_result.rcm};
  if (!trace_link) {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    cache_guard.get()[cache_key] = out;
  }
  return out;
}

ECMData<std::vector<PathInfo>> FilesystemAppBaseService::BaseListdir(
    ClientHandle client, const std::string &nickname,
    const std::string &abs_path, const ClientControlComponent &control) {
  if (!client) {
    return {{}, Err(EC::InvalidHandle, "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, "Absolute path is empty")};
  }

  const ClientPath cache_key = BuildBaseCacheKey(client, nickname, abs_path);
  {
    auto cache_guard = base_io_cache_.listdir_cache.lock();
    const auto &cache = cache_guard.get();
    auto it = cache.find(cache_key);
    if (it != cache.end()) {
      return it->second;
    }
  }

  auto list_result = client->IOPort().listdir({abs_path}, control);
  if (!isok(list_result.rcm)) {
    return {{}, list_result.rcm};
  }

  std::vector<std::string> names = BuildBaseListNames(list_result.entries);
  ECMData<std::vector<PathInfo>> out = {list_result.entries, list_result.rcm};
  {
    auto cache_guard = base_io_cache_.listdir_cache.lock();
    cache_guard.get()[cache_key] = out;
  }
  {
    auto cache_guard = base_io_cache_.listnames_cache.lock();
    cache_guard.get()[cache_key] = {std::move(names), Ok()};
  }
  {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    auto &cache = cache_guard.get();
    for (const auto &entry : list_result.entries) {
      if (entry.path.empty()) {
        continue;
      }
      const ClientPath child_key =
          BuildBaseCacheKey(client, nickname, entry.path);
      cache[child_key] = {entry, Ok()};
    }
  }

  return out;
}

ECMData<std::vector<std::string>> FilesystemAppBaseService::BaseListNames(
    ClientHandle client, const std::string &nickname,
    const std::string &abs_path, const ClientControlComponent &control) {
  if (!client) {
    return {{}, Err(EC::InvalidHandle, "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, "Absolute path is empty")};
  }

  const ClientPath cache_key = BuildBaseCacheKey(client, nickname, abs_path);
  {
    auto cache_guard = base_io_cache_.listnames_cache.lock();
    const auto &cache = cache_guard.get();
    auto it = cache.find(cache_key);
    if (it != cache.end()) {
      return it->second;
    }
  }
  {
    auto cache_guard = base_io_cache_.listdir_cache.lock();
    const auto &cache = cache_guard.get();
    auto it = cache.find(cache_key);
    if (it != cache.end()) {
      if (!isok(it->second.rcm)) {
        return {{}, it->second.rcm};
      }
      ECMData<std::vector<std::string>> out = {
          BuildBaseListNames(it->second.data), Ok()};
      auto names_guard = base_io_cache_.listnames_cache.lock();
      names_guard.get()[cache_key] = out;
      return out;
    }
  }

  auto list_result = client->IOPort().listnames({abs_path}, control);
  if (!isok(list_result.rcm)) {
    return {{}, list_result.rcm};
  }

  ECMData<std::vector<std::string>> out = {list_result.names, list_result.rcm};
  auto cache_guard = base_io_cache_.listnames_cache.lock();
  cache_guard.get()[cache_key] = out;
  return out;
}

void FilesystemAppBaseService::ClearBaseIOCache() {
  {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    cache_guard.get().clear();
  }
  {
    auto cache_guard = base_io_cache_.listdir_cache.lock();
    cache_guard.get().clear();
  }
  {
    auto cache_guard = base_io_cache_.listnames_cache.lock();
    cache_guard.get().clear();
  }
}

void FilesystemAppBaseService::ClearBaseIOCacheByNickname(
    const std::string &nickname) {
  if (nickname.empty()) {
    return;
  }
  {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    auto &cache = cache_guard.get();
    for (auto it = cache.begin(); it != cache.end();) {
      if (it->first.nickname == nickname) {
        it = cache.erase(it);
      } else {
        ++it;
      }
    }
  }
  {
    auto cache_guard = base_io_cache_.listdir_cache.lock();
    auto &cache = cache_guard.get();
    for (auto it = cache.begin(); it != cache.end();) {
      if (it->first.nickname == nickname) {
        it = cache.erase(it);
      } else {
        ++it;
      }
    }
  }
  {
    auto cache_guard = base_io_cache_.listnames_cache.lock();
    auto &cache = cache_guard.get();
    for (auto it = cache.begin(); it != cache.end();) {
      if (it->first.nickname == nickname) {
        it = cache.erase(it);
      } else {
        ++it;
      }
    }
  }
}

void FilesystemAppBaseService::ClearBaseIOCacheByPath(
    const std::string &nickname, const std::string &abs_path) {
  if (nickname.empty() || abs_path.empty()) {
    return;
  }
  const ClientPath key = BuildBaseCacheKey(nullptr, nickname, abs_path);
  {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    cache_guard.get().erase(key);
  }
  {
    auto cache_guard = base_io_cache_.listdir_cache.lock();
    cache_guard.get().erase(key);
  }
  {
    auto cache_guard = base_io_cache_.listnames_cache.lock();
    cache_guard.get().erase(key);
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

std::string FilesystemAppBaseService::CurrentNickname() const {
  if (!client_service_) {
    return "";
  }
  return client_service_->CurrentNickname();
}

ECMData<ClientHandle> FilesystemAppBaseService::GetClient(
    const std::string &nickname,
    const AMDomain::client::ClientControlComponent &control) {
  if (!host_service_ || !client_service_) {
    return {nullptr, Err(EC::InvalidHandle,
                         "filesystem app base service deps are null")};
  }

  if (nickname.empty()) {
    return {nullptr, Err(EC::InvalidArg, "Client nickname is empty")};
  }

  auto existing = client_service_->GetClient(nickname, true);
  if (isok(existing.rcm) && existing.data) {
    return existing;
  }

  if (!host_service_->HostExists(nickname)) {
    return {nullptr, Err(EC::HostConfigNotFound,
                         AMStr::fmt("Host config not found: {}", nickname))};
  }
  std::pair<ECM, HostConfig> host_cfg =
      host_service_->GetClientConfig(nickname);

  if (!isok(host_cfg.first)) {
    return {nullptr, host_cfg.first};
  }

  auto create_result = client_service_->CreateClient(host_cfg.second, control);
  if (!isok(create_result.rcm) || !create_result.data) {
    return {create_result.data, create_result.rcm};
  }

  const ECM add_rcm = client_service_->AddClient(create_result.data, false);
  if (!isok(add_rcm)) {
    auto raced = client_service_->GetClient(nickname, true);
    if (isok(raced.rcm) && raced.data) {
      return raced;
    }
    return {nullptr, add_rcm};
  }

  auto resolved = client_service_->GetClient(nickname, true);
  if (!isok(resolved.rcm) || !resolved.data) {
    resolved = {create_result.data, Ok()};
  }
  return resolved;
}

ECMData<ClientHandle>
FilesystemAppBaseService::GetTransferClient(const std::string &nickname) {
  if (!host_service_ || !client_service_) {
    return {nullptr, Err(EC::InvalidHandle,
                         "filesystem app base service deps are null")};
  }

  if (nickname.empty()) {
    return {nullptr, Err(EC::InvalidArg, "Client nickname is empty")};
  }

  auto public_result = client_service_->GetPublicClient(nickname);
  if (isok(public_result.rcm) && public_result.data) {
    return public_result;
  }

  if (!host_service_->HostExists(nickname)) {
    return {nullptr, Err(EC::HostConfigNotFound,
                         AMStr::fmt("Host config not found: {}", nickname))};
  }
  std::pair<ECM, HostConfig> host_cfg =
      host_service_->GetClientConfig(nickname);
  if (!isok(host_cfg.first)) {
    return {nullptr, host_cfg.first};
  }

  auto create_result =
      client_service_->CreateClient(host_cfg.second, ClientControlComponent{});
  if (!isok(create_result.rcm) || !create_result.data) {
    return {create_result.data, create_result.rcm};
  }

  {
    const ECM lease_rcm = AcquireTransferLease_(create_result.data);
    if (!isok(lease_rcm)) {
      return {nullptr, lease_rcm};
    }
  }

  const ECM add_rcm = client_service_->AddPublicClient(create_result.data);
  if (!isok(add_rcm)) {
    return {nullptr, add_rcm};
  }
  return {create_result.data, Ok()};
}

ECM FilesystemAppBaseService::ResolvePath(
    ClientPath &path, const AMDomain::client::ClientControlComponent &control) {
  if (!client_service_) {
    return Err(EC::InvalidHandle, "client service is null");
  }

  std::string resolved_nickname = {};
  if (path.client) {
    resolved_nickname = path.client->ConfigPort().GetNickname();
    if (resolved_nickname.empty()) {
      resolved_nickname = path.nickname;
    }
  } else {
    resolved_nickname = path.nickname;
    if (resolved_nickname.empty()) {
      resolved_nickname = client_service_->CurrentNickname();
    }
  }
  path.nickname = resolved_nickname;

  if (!path.client) {
    auto get_result = GetClient(path.nickname, control);
    path.rcm = get_result.rcm;
    if (!isok(get_result.rcm) || !get_result.data) {
      path.client = nullptr;
      path.resolved = false;
      return get_result.rcm;
    }
    path.client = get_result.data;
  }

  if (path.resolved) {
    path.rcm = Ok();
    return Ok();
  }

  const std::string input_path = path.path.empty() ? "." : path.path;
  path.is_wildcard = AMDomain::filesystem::services::HasWildcard(input_path);
  path.userpath = !input_path.empty() && input_path.front() == '~';
  path.path = input_path;

  const ECM abs_rcm = ClientOperationHelper::AbsolutePath(path);
  if (!isok(abs_rcm)) {
    path.rcm = abs_rcm;
    path.client = nullptr;
    path.resolved = false;
    return abs_rcm;
  }
  path.rcm = Ok();
  path.resolved = true;
  return Ok();
}

ECM FilesystemAppBaseService::ResolvePath(
    std::vector<ClientPath> &paths,
    const AMDomain::client::ClientControlComponent &control, bool error_stop) {
  ECM status = Ok();

  for (auto &entry : paths) {
    const ECM rcm = ResolvePath(entry, control);
    if (!isok(rcm)) {
      if (error_stop) {
        return rcm;
      }
      if (isok(status)) {
        status = rcm;
      }
    }
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
