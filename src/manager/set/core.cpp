#include "AMManager/Set.hpp"
#include "AMManager/Config.hpp"
#include <algorithm>

using EC = ErrorCode;

/**
 * @brief Serialize path-set config into HostSet JSON shape.
 */
Json AMHostSetPathConfig::GetJson() const {
  Json jsond = Json::object();
  jsond["CompleteOption"]["Searcher"]["Path"]["use_async"] = use_async;
  jsond["CompleteOption"]["Searcher"]["Path"]["use_cache"] = use_cache;
  jsond["CompleteOption"]["Searcher"]["Path"]["cache_items_threshold"] =
      static_cast<int64_t>(cache_items_threshold);
  jsond["CompleteOption"]["Searcher"]["Path"]["cache_max_entries"] =
      static_cast<int64_t>(cache_max_entries);
  jsond["CompleteOption"]["Searcher"]["Path"]["timeout_ms"] =
      static_cast<int64_t>(timeout_ms);
  jsond["Highlight"]["Path"]["use_check"] = highlight_use_check;
  jsond["Highlight"]["Path"]["timeout_ms"] =
      static_cast<int64_t>(highlight_timeout_ms);
  return jsond;
}

/**
 * @brief Build path-set config from JSON with fallback defaults.
 */
AMHostSetPathConfig
AMHostSetPathConfig::FromJson(const Json &jsond,
                              const AMHostSetPathConfig &defaults) {
  AMHostSetPathConfig config = defaults;
  if (!jsond.is_object()) {
    return config;
  }

  bool use_async_value = config.use_async;
  if (AMJson::QueryKey(jsond, {"CompleteOption", "Searcher", "Path", "use_async"},
               &use_async_value)) {
    config.use_async = use_async_value;
  }

  bool use_cache_value = config.use_cache;
  if (AMJson::QueryKey(jsond, {"CompleteOption", "Searcher", "Path", "use_cache"},
               &use_cache_value)) {
    config.use_cache = use_cache_value;
  }

  size_t cache_items_value = config.cache_items_threshold;
  if (AMJson::QueryKey(jsond,
               {"CompleteOption", "Searcher", "Path", "cache_items_threshold"},
               &cache_items_value)) {
    config.cache_items_threshold = cache_items_value;
  }

  size_t cache_max_value = config.cache_max_entries;
  if (AMJson::QueryKey(jsond,
               {"CompleteOption", "Searcher", "Path", "cache_max_entries"},
               &cache_max_value)) {
    config.cache_max_entries = cache_max_value;
  }

  size_t timeout_value = config.timeout_ms;
  if (AMJson::QueryKey(jsond, {"CompleteOption", "Searcher", "Path", "timeout_ms"},
               &timeout_value)) {
    config.timeout_ms = timeout_value;
  }

  bool use_check_value = config.highlight_use_check;
  if (AMJson::QueryKey(jsond, {"Highlight", "Path", "use_check"}, &use_check_value)) {
    config.highlight_use_check = use_check_value;
  }

  size_t highlight_timeout_value = config.highlight_timeout_ms;
  if (AMJson::QueryKey(jsond, {"Highlight", "Path", "timeout_ms"},
               &highlight_timeout_value)) {
    config.highlight_timeout_ms = highlight_timeout_value;
  }
  return config;
}

/**
 * @brief Return the shared HostSet manager.
 */
AMSetManager &AMSetManager::Instance() { return AMSetCLI::Instance(); }

/**
 * @brief Reload HostSet from ConfigManager settings JSON.
 */
ECM AMSetManager::Reload() {
  Json host_set = AMConfigManager::Instance().ResolveArg<Json>(
      DocumentKind::Settings, {hostsetkn::kHostSetRoot}, Json::object(), {});
  if (!host_set.is_object()) {
    host_set = Json::object();
  }

  AMHostSetPathConfig default_cfg{};
  Json default_json;
  if (AMJson::QueryKey(host_set, {hostsetkn::kDefaultHost}, &default_json) &&
      default_json.is_object()) {
    default_cfg = AMHostSetPathConfig::FromJson(default_json, default_cfg);
  }

  std::unordered_map<std::string, AMHostSetPathConfig> parsed = {};
  parsed.reserve(host_set.size() + 1);
  parsed[hostsetkn::kDefaultHost] = default_cfg;

  for (auto it = host_set.begin(); it != host_set.end(); ++it) {
    if (it.key() == hostsetkn::kDefaultHost || !it.value().is_object()) {
      continue;
    }
    parsed[it.key()] = AMHostSetPathConfig::FromJson(it.value(), default_cfg);
  }

  std::lock_guard<std::mutex> lock(mtx_);
  host_sets_ = std::move(parsed);
  ready_ = true;
  dirty_ = false;
  return Ok();
}

/**
 * @brief Return a read-only copy of the cached HostSet object.
 */
Json AMSetManager::Snapshot() const {
  const_cast<AMSetManager *>(this)->EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);
  Json snapshot = Json::object();
  for (const auto &item : host_sets_) {
    snapshot[item.first] = item.second.GetJson();
  }
  return snapshot;
}

/**
 * @brief Resolve merged host set table (host overrides "*").
 */
AMHostSetTableResult AMSetManager::ResolveHostSet(const std::string &nickname) const {
  AMHostSetTableResult result{};
  auto cfg_result = ResolvePathSet(nickname);
  result.value = cfg_result.value.GetJson();
  result.fallback_to_default = cfg_result.fallback_to_default;
  return result;
}

/**
 * @brief Resolve path-related typed HostSet configuration.
 */
AMHostSetAttrResult AMSetManager::ResolvePathSet(const std::string &nickname) const {
  AMHostSetAttrResult result{};
  result.value = AMHostSetPathConfig{};
  result.fallback_to_default = true;

  const_cast<AMSetManager *>(this)->EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);

  const AMHostSetPathConfig *entry = FindHostEntryNoLock_(nickname);
  if (entry) {
    result.value = *entry;
    result.fallback_to_default = false;
    return result;
  }

  const AMHostSetPathConfig *defaults = FindDefaultEntryNoLock_();
  if (defaults) {
    result.value = *defaults;
  }
  result.fallback_to_default = true;
  return result;
}

/**
 * @brief Return whether a specific host set table exists in cache.
 */
bool AMSetManager::HasHostSet(const std::string &nickname) const {
  if (nickname.empty()) {
    return false;
  }
  const_cast<AMSetManager *>(this)->EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);
  return FindHostEntryNoLock_(nickname) != nullptr;
}

/**
 * @brief List HostSet table names.
 */
std::vector<std::string> AMSetManager::ListSetNames(bool include_default) const {
  const_cast<AMSetManager *>(this)->EnsureLoaded_();
  std::vector<std::string> names;
  std::lock_guard<std::mutex> lock(mtx_);
  names.reserve(host_sets_.size());
  for (const auto &item : host_sets_) {
    if (!include_default && item.first == hostsetkn::kDefaultHost) {
      continue;
    }
    names.push_back(item.first);
  }
  std::sort(names.begin(), names.end());
  return names;
}

/**
 * @brief Create one host set table in cache.
 */
ECM AMSetManager::CreateHostSet(const std::string &nickname,
                                const AMHostSetPathConfig &set_config,
                                bool overwrite) {
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host nickname");
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = host_sets_.find(nickname);
  if (it != host_sets_.end() && !overwrite) {
    return Err(EC::KeyAlreadyExists, "host set already exists");
  }
  host_sets_[nickname] = set_config;
  dirty_ = true;
  return Ok();
}

/**
 * @brief Replace one host set table in cache.
 */
ECM AMSetManager::ModifyHostSet(const std::string &nickname,
                                const AMHostSetPathConfig &set_config,
                                bool create_when_missing) {
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host nickname");
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = host_sets_.find(nickname);
  if (it == host_sets_.end() && !create_when_missing) {
    return Err(EC::HostConfigNotFound, "host set not found");
  }
  host_sets_[nickname] = set_config;
  dirty_ = true;
  return Ok();
}

/**
 * @brief Delete one host set table from cache.
 */
ECM AMSetManager::DeleteHostSet(const std::string &nickname) {
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host nickname");
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = host_sets_.find(nickname);
  if (it == host_sets_.end()) {
    return Err(EC::HostConfigNotFound, "host set not found");
  }
  host_sets_.erase(it);
  dirty_ = true;
  return Ok();
}

/**
 * @brief Write cached HostSet back to settings and dump settings.toml.
 */
ECM AMSetManager::Save(bool async) {
  EnsureLoaded_();
  Json snapshot = Json::object();
  {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!dirty_) {
      return Ok();
    }
    for (const auto &item : host_sets_) {
      snapshot[item.first] = item.second.GetJson();
    }
  }

  if (!AMConfigManager::Instance().SetArg(DocumentKind::Settings, {hostsetkn::kHostSetRoot},
                              snapshot)) {
    return Err(EC::CommonFailure, "failed to write HostSet into settings");
  }
  ECM rcm = AMConfigManager::Instance().Dump(DocumentKind::Settings, "", async);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  std::lock_guard<std::mutex> lock(mtx_);
  dirty_ = false;
  return Ok();
}

/**
 * @brief Ensure HostSet cache is initialized.
 */
void AMSetManager::EnsureLoaded_() {
  {
    std::lock_guard<std::mutex> lock(mtx_);
    if (ready_) {
      return;
    }
  }
  (void)Reload();
}

/**
 * @brief Return host table pointer while lock is held.
 */
const AMHostSetPathConfig *
AMSetManager::FindHostEntryNoLock_(const std::string &nickname) const {
  if (nickname.empty()) {
    return nullptr;
  }
  auto it = host_sets_.find(nickname);
  if (it == host_sets_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Return default "*" table pointer while lock is held.
 */
const AMHostSetPathConfig *AMSetManager::FindDefaultEntryNoLock_() const {
  auto it = host_sets_.find(hostsetkn::kDefaultHost);
  if (it == host_sets_.end()) {
    return nullptr;
  }
  return &it->second;
}
