#include "application/filesystem/FilesystemAppBaseService.hpp"
#include <stdexcept>

namespace AMApplication::filesystem {
namespace {
using ClientHandle = AMDomain::client::ClientHandle;

void HashCombine_(size_t &seed, size_t value) {
  seed ^= value + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}
} // namespace

FilesystemAppBaseService::FilesystemAppBaseService(
    FilesystemArg arg, ClientAppService *client_service)
    : AMDomain::config::IConfigSyncPort(typeid(FilesystemArg)),
      init_arg_(std::move(arg)), client_service_(client_service),
      cd_history_(std::deque<PathTarget>{}) {
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
    const std::string &abs_path, const ControlComponent &control,
    bool trace_link) {
  if (!client) {
    return {{}, Err(EC::InvalidHandle, "", "", "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, "", "", "Absolute path is empty")};
  }

  const std::string key_nickname =
      nickname.empty() ? client->ConfigPort().GetNickname() : nickname;
  const PathTarget cache_key = BuildBaseCacheKey(key_nickname, abs_path);
  if (!trace_link) {
    auto cache_guard = base_io_cache_.lock();
    const auto &cache = cache_guard->stat_cache;
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
    auto cache_guard = base_io_cache_.lock();
    cache_guard->stat_cache[cache_key] = out;
  }
  return out;
}

ECMData<std::vector<PathInfo>> FilesystemAppBaseService::BaseListdir(
    ClientHandle client, const std::string &nickname,
    const std::string &abs_path, const ControlComponent &control) {
  if (!client) {
    return {{}, Err(EC::InvalidHandle, "", "", "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, "", "", "Absolute path is empty")};
  }

  const std::string key_nickname =
      nickname.empty() ? client->ConfigPort().GetNickname() : nickname;
  const PathTarget cache_key = BuildBaseCacheKey(key_nickname, abs_path);
  {
    auto cache_guard = base_io_cache_.lock();
    const auto &cache = cache_guard->listdir_cache;
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
    auto cache_guard = base_io_cache_.lock();
    cache_guard->listdir_cache[cache_key] = out;
    cache_guard->listnames_cache[cache_key] = {std::move(names), OK};
    auto &cache = cache_guard->stat_cache;
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
    const std::string &abs_path, const ControlComponent &control) {
  if (!client) {
    return {{}, Err(EC::InvalidHandle, "", "", "Client handle is null")};
  }
  if (abs_path.empty()) {
    return {{}, Err(EC::InvalidArg, "", "", "Absolute path is empty")};
  }

  const std::string key_nickname =
      nickname.empty() ? client->ConfigPort().GetNickname() : nickname;
  const PathTarget cache_key = BuildBaseCacheKey(key_nickname, abs_path);
  {
    auto cache_guard = base_io_cache_.lock();
    const auto &cache = cache_guard->listnames_cache;
    auto it = cache.find(cache_key);
    if (it != cache.end()) {
      return it->second;
    }
    auto listdir_it = cache_guard->listdir_cache.find(cache_key);
    if (listdir_it != cache_guard->listdir_cache.end()) {
      if (!(listdir_it->second.rcm)) {
        return {{}, listdir_it->second.rcm};
      }
      ECMData<std::vector<std::string>> out = {
          BuildBaseListNames(listdir_it->second.data), OK};
      cache_guard->listnames_cache[cache_key] = out;
      return out;
    }
  }

  auto list_result = client->IOPort().listnames({abs_path}, control);
  if (!(list_result.rcm)) {
    return {{}, list_result.rcm};
  }

  ECMData<std::vector<std::string>> out = {list_result.data.names,
                                           list_result.rcm};
  auto cache_guard = base_io_cache_.lock();
  cache_guard->listnames_cache[cache_key] = out;
  return out;
}

void FilesystemAppBaseService::ClearBaseIOCache() {
  auto cache_guard = base_io_cache_.lock();
  cache_guard->stat_cache.clear();
  cache_guard->listdir_cache.clear();
  cache_guard->listnames_cache.clear();
}

void FilesystemAppBaseService::ClearBaseIOCacheByNickname(
    const std::string &nickname) {
  if (nickname.empty()) {
    return;
  }
  const std::string normalized_nickname = nickname;
  {
    auto cache_guard = base_io_cache_.lock();
    auto &cache = cache_guard->stat_cache;
    std::erase_if(cache, [&](const auto &entry) {
      return entry.first.nickname == normalized_nickname;
    });
    auto &listdir_cache = cache_guard->listdir_cache;
    std::erase_if(listdir_cache, [&](const auto &entry) {
      return entry.first.nickname == normalized_nickname;
    });
    auto &listnames_cache = cache_guard->listnames_cache;
    std::erase_if(listnames_cache, [&](const auto &entry) {
      return entry.first.nickname == normalized_nickname;
    });
  }
}

void FilesystemAppBaseService::ClearBaseIOCacheByPath(
    const std::string &nickname, const std::string &abs_path) {
  if (nickname.empty() || abs_path.empty()) {
    return;
  }
  const PathTarget key = BuildBaseCacheKey(nickname, abs_path);
  auto cache_guard = base_io_cache_.lock();
  cache_guard->stat_cache.erase(key);
  cache_guard->listdir_cache.erase(key);
  cache_guard->listnames_cache.erase(key);
}

ECM FilesystemAppBaseService::Init() {
  if (!client_service_) {
    return Err(EC::InvalidHandle, "", "", "client service is null");
  }
  const FilesystemArg arg = init_arg_.lock().load();
  if (arg.max_cd_history <= 0) {
    return Err(EC::InvalidArg, "", "", "max_cd_history must be greater than 0");
  }
  if (arg.terminal_read_timeout_ms == 0 || arg.terminal_read_timeout_ms < -1) {
    return Err(EC::InvalidArg, "", "",
               "terminal_read_timeout_ms must be -1 or > 0");
  }
  if (arg.terminal_send_timeout_ms < -1) {
    return Err(EC::InvalidArg, "", "",
               "terminal_send_timeout_ms must be -1 or >= 0");
  }
  return OK;
}

FilesystemArg FilesystemAppBaseService::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM FilesystemAppBaseService::FlushTo(
    AMDomain::config::IConfigStorePort *store) {
  if (store == nullptr) {
    return Err(EC::InvalidArg, "", "", "config store is null");
  }
  const FilesystemArg snapshot = GetInitArg();
  if (!store->Write(std::type_index(typeid(FilesystemArg)),
                    static_cast<const void *>(&snapshot))) {
    return Err(EC::ConfigDumpFailed, "", "",
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
} // namespace AMApplication::filesystem
