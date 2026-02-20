#include "AMManager/Set.hpp"
#include <algorithm>

using EC = ErrorCode;

namespace {
/**
 * @brief Return true when a JSON value is an object.
 */
bool IsObject_(const Json &jsond) { return jsond.is_object(); }
} // namespace

/**
 * @brief Return the shared HostSet manager.
 */
AMSetManager &AMSetManager::Instance() { return AMSetCLI::Instance(); }

/**
 * @brief Reload HostSet from ConfigManager settings JSON.
 */
ECM AMSetManager::Reload() {
  Json host_set = config_manager_.ResolveArg<Json>(
      DocumentKind::Settings, {hostsetkn::kHostSetRoot}, Json::object(), {});
  if (!host_set.is_object()) {
    host_set = Json::object();
  }
  std::lock_guard<std::mutex> lock(mtx_);
  host_sets_ = std::move(host_set);
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
  return host_sets_;
}

/**
 * @brief Resolve merged host set table (host overrides "*").
 */
AMHostSetTableResult AMSetManager::ResolveHostSet(const std::string &nickname) const {
  AMHostSetTableResult result{};
  result.value = Json::object();
  result.fallback_to_default = true;

  const_cast<AMSetManager *>(this)->EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);

  const Json *default_entry = FindDefaultEntryNoLock_();
  Json merged = (default_entry && default_entry->is_object()) ? *default_entry
                                                              : Json::object();

  const Json *host_entry = FindHostEntryNoLock_(nickname);
  if (host_entry && host_entry->is_object()) {
    merged = MergeObjects_(merged, *host_entry);
    result.fallback_to_default = false;
  }

  result.value = std::move(merged);
  return result;
}

/**
 * @brief Resolve path-related typed HostSet configuration.
 */
AMHostSetPathConfig AMSetManager::ResolvePathSet(const std::string &nickname) const {
  AMHostSetPathConfig cfg{};

  const auto use_async = ResolveHostAttr<bool>(
      nickname, {"CompleteOption", "Searcher", "Path", "use_async"},
      cfg.use_async);
  cfg.use_async = use_async.value;

  const auto use_cache = ResolveHostAttr<bool>(
      nickname, {"CompleteOption", "Searcher", "Path", "use_cache"},
      cfg.use_cache);
  cfg.use_cache = use_cache.value;

  const auto cache_items = ResolveHostAttr<int64_t>(
      nickname, {"CompleteOption", "Searcher", "Path", "cache_items_threshold"},
      static_cast<int64_t>(cfg.cache_items_threshold));
  if (cache_items.value > 0) {
    cfg.cache_items_threshold = static_cast<size_t>(cache_items.value);
  }

  const auto cache_max = ResolveHostAttr<int64_t>(
      nickname, {"CompleteOption", "Searcher", "Path", "cache_max_entries"},
      static_cast<int64_t>(cfg.cache_max_entries));
  if (cache_max.value > 0) {
    cfg.cache_max_entries = static_cast<size_t>(cache_max.value);
  }

  const auto timeout_ms = ResolveHostAttr<int>(
      nickname, {"CompleteOption", "Searcher", "Path", "timeout_ms"},
      cfg.timeout_ms);
  if (timeout_ms.value > 0) {
    cfg.timeout_ms = timeout_ms.value;
  }

  const auto use_check = ResolveHostAttr<bool>(
      nickname, {"Highlight", "Path", "use_check"}, cfg.highlight_use_check);
  cfg.highlight_use_check = use_check.value;

  const auto highlight_timeout = ResolveHostAttr<int>(
      nickname, {"Highlight", "Path", "timeout_ms"}, cfg.highlight_timeout_ms);
  if (highlight_timeout.value > 0) {
    cfg.highlight_timeout_ms = highlight_timeout.value;
  }

  return cfg;
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
  if (!host_sets_.is_object()) {
    return names;
  }
  names.reserve(host_sets_.size());
  for (auto it = host_sets_.begin(); it != host_sets_.end(); ++it) {
    if (!it.value().is_object()) {
      continue;
    }
    if (!include_default && it.key() == hostsetkn::kDefaultHost) {
      continue;
    }
    names.push_back(it.key());
  }
  std::sort(names.begin(), names.end());
  return names;
}

/**
 * @brief Create one host set table in cache.
 */
ECM AMSetManager::CreateHostSet(const std::string &nickname, const Json &set_table,
                                bool overwrite) {
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host nickname");
  }
  if (!set_table.is_object()) {
    return Err(EC::InvalidArg, "host set must be an object");
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = host_sets_.find(nickname);
  if (it != host_sets_.end() && !overwrite) {
    return Err(EC::KeyAlreadyExists, "host set already exists");
  }
  host_sets_[nickname] = set_table;
  dirty_ = true;
  return Ok();
}

/**
 * @brief Replace one host set table in cache.
 */
ECM AMSetManager::ModifyHostSet(const std::string &nickname, const Json &set_table,
                                bool create_when_missing) {
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host nickname");
  }
  if (!set_table.is_object()) {
    return Err(EC::InvalidArg, "host set must be an object");
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = host_sets_.find(nickname);
  if (it == host_sets_.end() && !create_when_missing) {
    return Err(EC::HostConfigNotFound, "host set not found");
  }
  host_sets_[nickname] = set_table;
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
  if (!host_sets_.is_object()) {
    return Err(EC::HostConfigNotFound, "host set not found");
  }
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
    snapshot = host_sets_;
  }

  if (!config_manager_.SetArg(DocumentKind::Settings, {hostsetkn::kHostSetRoot},
                              snapshot)) {
    return Err(EC::CommonFailure, "failed to write HostSet into settings");
  }
  ECM rcm = config_manager_.Dump(DocumentKind::Settings, "", async);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  std::lock_guard<std::mutex> lock(mtx_);
  dirty_ = false;
  return Ok();
}

/**
 * @brief Build HostSet table JSON from typed path settings.
 */
Json AMSetManager::BuildPathSetTable_(const AMHostSetPathConfig &config) {
  Json jsond = Json::object();
  jsond["CompleteOption"]["Searcher"]["Path"]["use_async"] = config.use_async;
  jsond["CompleteOption"]["Searcher"]["Path"]["use_cache"] = config.use_cache;
  jsond["CompleteOption"]["Searcher"]["Path"]["cache_items_threshold"] =
      static_cast<int64_t>(config.cache_items_threshold);
  jsond["CompleteOption"]["Searcher"]["Path"]["cache_max_entries"] =
      static_cast<int64_t>(config.cache_max_entries);
  jsond["CompleteOption"]["Searcher"]["Path"]["timeout_ms"] = config.timeout_ms;
  jsond["Highlight"]["Path"]["use_check"] = config.highlight_use_check;
  jsond["Highlight"]["Path"]["timeout_ms"] = config.highlight_timeout_ms;
  return jsond;
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
const Json *AMSetManager::FindHostEntryNoLock_(const std::string &nickname) const {
  if (nickname.empty() || !IsObject_(host_sets_)) {
    return nullptr;
  }
  auto it = host_sets_.find(nickname);
  if (it == host_sets_.end() || !it.value().is_object()) {
    return nullptr;
  }
  return &it.value();
}

/**
 * @brief Return default "*" table pointer while lock is held.
 */
const Json *AMSetManager::FindDefaultEntryNoLock_() const {
  if (!IsObject_(host_sets_)) {
    return nullptr;
  }
  auto it = host_sets_.find(hostsetkn::kDefaultHost);
  if (it == host_sets_.end() || !it.value().is_object()) {
    return nullptr;
  }
  return &it.value();
}

/**
 * @brief Deep-merge two JSON objects.
 */
Json AMSetManager::MergeObjects_(const Json &base, const Json &overlay) {
  Json merged = base.is_object() ? base : Json::object();
  if (!overlay.is_object()) {
    return merged;
  }
  for (auto it = overlay.begin(); it != overlay.end(); ++it) {
    auto existing = merged.find(it.key());
    if (existing != merged.end() && existing->is_object() && it->is_object()) {
      merged[it.key()] = MergeObjects_(*existing, *it);
    } else {
      merged[it.key()] = *it;
    }
  }
  return merged;
}
