#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include <chrono>
#include <thread>
#include <stdexcept>

namespace AMApplication::filesystem {
namespace {
using ClientHandle = AMDomain::client::ClientHandle;

void HashCombine_(size_t &seed, size_t value) {
  seed ^= value + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}
} // namespace

FilesystemAppBaseService::FilesystemAppBaseService(
    FilesystemArg arg, HostAppService *host_service,
    ClientAppService *client_service)
    : AMApplication::config::IConfigSyncPort(typeid(FilesystemArg)),
      init_arg_(arg), host_service_(host_service),
      client_service_(client_service), cd_history_(std::deque<PathTarget>{}) {
  if (!host_service_) {
    throw std::invalid_argument("host_service is null");
  }
  if (!client_service_) {
    throw std::invalid_argument("client_service is null");
  }
}

size_t FilesystemAppBaseService::BaseIOCache::KeyHash::operator()(
    const PathTarget &key) const noexcept {
  size_t seed = 0;
  HashCombine_(seed, std::hash<std::string>{}(key.nickname));
  HashCombine_(seed, std::hash<std::string>{}(key.path));
  return seed;
}

bool FilesystemAppBaseService::BaseIOCache::KeyEq::operator()(
    const PathTarget &lhs, const PathTarget &rhs) const noexcept {
  return lhs.nickname == rhs.nickname && lhs.path == rhs.path;
}

PathTarget
FilesystemAppBaseService::BuildBaseCacheKey(const std::string &nickname,
                                            const std::string &abs_path) const {
  PathTarget key = {};
  key.nickname = nickname;
  key.path = abs_path;
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
    return {{}, Err(EC::InvalidHandle, __func__, "", "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, __func__, "", "Absolute path is empty")};
  }

  const std::string key_nickname =
      nickname.empty() ? client->ConfigPort().GetNickname() : nickname;
  const PathTarget cache_key = BuildBaseCacheKey(key_nickname, abs_path);
  if (!trace_link) {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    const auto &cache = cache_guard.get();
    auto it = cache.find(cache_key);
    if (it != cache.end()) {
      return it->second;
    }
  }

  auto stat_result = client->IOPort().stat({abs_path, trace_link}, control);
  if (!(stat_result.rcm)) {
    return {{}, stat_result.rcm};
  }

  ECMData<PathInfo> out = {stat_result.data.info, stat_result.rcm};
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
    return {{}, Err(EC::InvalidHandle, __func__, "", "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, __func__, "", "Absolute path is empty")};
  }

  const std::string key_nickname =
      nickname.empty() ? client->ConfigPort().GetNickname() : nickname;
  const PathTarget cache_key = BuildBaseCacheKey(key_nickname, abs_path);
  {
    auto cache_guard = base_io_cache_.listdir_cache.lock();
    const auto &cache = cache_guard.get();
    auto it = cache.find(cache_key);
    if (it != cache.end()) {
      return it->second;
    }
  }

  auto list_result = client->IOPort().listdir({abs_path}, control);
  if (!(list_result.rcm)) {
    return {{}, list_result.rcm};
  }

  std::vector<std::string> names = BuildBaseListNames(list_result.data.entries);
  ECMData<std::vector<PathInfo>> out = {list_result.data.entries,
                                        list_result.rcm};
  {
    auto cache_guard = base_io_cache_.listdir_cache.lock();
    cache_guard.get()[cache_key] = out;
  }
  {
    auto cache_guard = base_io_cache_.listnames_cache.lock();
    cache_guard.get()[cache_key] = {std::move(names), OK};
  }
  {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    auto &cache = cache_guard.get();
    for (const auto &entry : list_result.data.entries) {
      if (entry.path.empty()) {
        continue;
      }
      const std::string child_nickname =
          nickname.empty() ? client->ConfigPort().GetNickname() : nickname;
      const PathTarget child_key =
          BuildBaseCacheKey(child_nickname, entry.path);
      cache[child_key] = {entry, OK};
    }
  }

  return out;
}

ECMData<std::vector<std::string>> FilesystemAppBaseService::BaseListNames(
    ClientHandle client, const std::string &nickname,
    const std::string &abs_path, const ClientControlComponent &control) {
  if (!client) {
    return {{}, Err(EC::InvalidHandle, __func__, "", "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, __func__, "", "Absolute path is empty")};
  }

  const std::string key_nickname =
      nickname.empty() ? client->ConfigPort().GetNickname() : nickname;
  const PathTarget cache_key = BuildBaseCacheKey(key_nickname, abs_path);
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
      if (!(it->second.rcm)) {
        return {{}, it->second.rcm};
      }
      ECMData<std::vector<std::string>> out = {
          BuildBaseListNames(it->second.data), OK};
      auto names_guard = base_io_cache_.listnames_cache.lock();
      names_guard.get()[cache_key] = out;
      return out;
    }
  }

  auto list_result = client->IOPort().listnames({abs_path}, control);
  if (!(list_result.rcm)) {
    return {{}, list_result.rcm};
  }

  ECMData<std::vector<std::string>> out = {list_result.data.names,
                                           list_result.rcm};
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
  const std::string normalized_nickname = nickname;
  {
    auto cache_guard = base_io_cache_.stat_cache.lock();
    auto &cache = cache_guard.get();
    for (auto it = cache.begin(); it != cache.end();) {
      if (it->first.nickname == normalized_nickname) {
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
      if (it->first.nickname == normalized_nickname) {
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
      if (it->first.nickname == normalized_nickname) {
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
  const PathTarget key = BuildBaseCacheKey(nickname, abs_path);
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
    return Err(EC::InvalidHandle, __func__, "",
               "filesystem app base service deps are null");
  }
  const FilesystemArg arg = init_arg_.lock().load();
  if (arg.max_cd_history <= 0) {
    return Err(EC::InvalidArg, __func__, "", "max_cd_history must be greater than 0");
  }
  return OK;
}

FilesystemArg FilesystemAppBaseService::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM FilesystemAppBaseService::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (config_service == nullptr) {
    return Err(EC::InvalidArg, __func__, "", "config service is null");
  }
  if (!config_service->Write<FilesystemArg>(GetInitArg())) {
    return Err(EC::ConfigDumpFailed, __func__, "",
               "failed to flush filesystem config");
  }
  return OK;
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
    return {nullptr, Err(EC::InvalidHandle, __func__, "",
                         "filesystem app base service deps are null")};
  }

  if (nickname.empty()) {
    return {nullptr, Err(EC::InvalidArg, __func__, "", "Client nickname is empty")};
  }

  auto existing = client_service_->GetClient(nickname, true);
  if ((existing.rcm) && existing.data) {
    return existing;
  }

  if (!host_service_->HostExists(nickname)) {
    return {nullptr,
            Err(EC::HostConfigNotFound, __func__, nickname, "Host not found")};
  }
  auto host_cfg = host_service_->GetClientConfig(nickname, true);
  if (!(host_cfg.rcm)) {
    return {nullptr, host_cfg.rcm};
  }

  auto create_result = client_service_->CreateClient(host_cfg.data, control);
  if (!(create_result.rcm) || !create_result.data) {
    return {create_result.data, create_result.rcm};
  }

  const ECM add_rcm = client_service_->AddClient(create_result.data, false);
  if (!(add_rcm)) {
    auto raced = client_service_->GetClient(nickname, true);
    if ((raced.rcm) && raced.data) {
      return raced;
    }
    return {nullptr, add_rcm};
  }

  auto resolved = client_service_->GetClient(nickname, true);
  if (!(resolved.rcm) || !resolved.data) {
    resolved = {create_result.data, OK};
  }
  return resolved;
}

ECMData<ClientHandle>
FilesystemAppBaseService::GetTransferClient(const std::string &nickname) {
  if (!host_service_ || !client_service_) {
    return {nullptr, Err(EC::InvalidHandle, __func__, "",
                         "filesystem app base service deps are null")};
  }

  if (nickname.empty()) {
    return {nullptr, Err(EC::InvalidArg, __func__, "", "Client nickname is empty")};
  }

  constexpr int kPublicClientLeaseRetryTimes = 8;
  constexpr int kPublicClientLeaseRetryWaitMs = 25;
  ECMData<ClientHandle> public_result = {};
  for (int attempt = 0; attempt <= kPublicClientLeaseRetryTimes; ++attempt) {
    public_result = client_service_->GetPublicClient(nickname);
    if ((public_result.rcm) && public_result.data) {
      return public_result;
    }
    if (public_result.rcm.code != EC::PathUsingByOthers) {
      break;
    }
    if (attempt >= kPublicClientLeaseRetryTimes) {
      break;
    }
    std::this_thread::sleep_for(
        std::chrono::milliseconds(kPublicClientLeaseRetryWaitMs));
  }

  if (!host_service_->HostExists(nickname)) {
    return {nullptr,
            Err(EC::HostConfigNotFound, __func__, nickname, "Host not found")};
  }
  auto host_cfg = host_service_->GetClientConfig(nickname, true);
  if (!(host_cfg.rcm)) {
    return {nullptr, host_cfg.rcm};
  }

  auto create_result =
      client_service_->CreateClient(host_cfg.data, ClientControlComponent{});
  if (!(create_result.rcm) || !create_result.data) {
    return {create_result.data, create_result.rcm};
  }

  {
    const ECM lease_rcm = ClientAppService::TryLeaseClient(create_result.data);
    if (!(lease_rcm)) {
      return {nullptr, lease_rcm};
    }
  }

  const ECM add_rcm = client_service_->AddPublicClient(create_result.data);
  if (!(add_rcm)) {
    (void)ClientAppService::TryReturnClient(create_result.data);
    return {nullptr, add_rcm};
  }
  return {create_result.data, OK};
}

ECMData<ResolvedPath>
FilesystemAppBaseService::ResolvePath(const PathTarget &target,
                                      const ClientControlComponent &control,
                                      ClientHandle preferred_client) {
  if (!client_service_) {
    return {ResolvedPath{},
            Err(EC::InvalidHandle, __func__, "", "client service is null")};
  }

  ResolvedPath out = {};
  out.target = target;
  if (out.target.path.empty()) {
    out.target.path = ".";
  }
  out.target.is_wildcard =
      AMDomain::filesystem::services::HasWildcard(out.target.path);
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
    if (!get_result.rcm || !get_result.data) {
      return {ResolvedPath{}, (get_result.rcm) ? Err(EC::InvalidHandle, __func__, "",
                                                     "Resolved client is null")
                                               : get_result.rcm};
    }
    out.client = get_result.data;
  }

  auto abs_result = FilesystemAppService::ResolveAbsolutePath(
      out.client, out.target.path, control);
  if (!(abs_result.rcm)) {
    return {ResolvedPath{}, abs_result.rcm};
  }
  out.abs_path = abs_result.data;
  out.target.path = out.abs_path;
  out.target.is_wildcard =
      AMDomain::filesystem::services::HasWildcard(out.target.path);
  out.target.is_user_path =
      !out.target.path.empty() && out.target.path.front() == '~';

  return {std::move(out), OK};
}

std::vector<ECMData<ResolvedPath>> FilesystemAppBaseService::ResolvePath(
    const std::vector<PathTarget> &targets,
    const AMDomain::client::ClientControlComponent &control) {
  std::vector<ECMData<ResolvedPath>> out = {};
  out.reserve(targets.size());
  for (const auto &target : targets) {
    if (control.IsInterrupted()) {
      out.emplace_back(ResolvedPath{},
                       Err(EC::Terminate, __func__, "", "Interrupted by user"));
      continue;
    }
    if (control.IsTimeout()) {
      out.emplace_back(ResolvedPath{}, Err(EC::OperationTimeout, __func__, "",
                                           "Operation timed out"));
      continue;
    }
    out.push_back(ResolvePath(target, control));
  }
  return out;
}
} // namespace AMApplication::filesystem
