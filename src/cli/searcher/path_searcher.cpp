#include "AMCLI/Completer/Searcher.hpp"
#include "AMCLI/Completer/SearcherCommon.hpp"
#include "AMCLI/InteractiveLoop.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMManager/FileSystem.hpp"
#include <algorithm>

using namespace AMSearcherDetail;

/**
 * @brief Collect path candidates or async path requests.
 */
AMCompletionCollectResult
AMPathSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCollectResult result;
  if (!HasTarget(ctx, AMCompletionTarget::Path)) {
    return result;
  }

  EnsureTempCacheHookRegistered_();
  const CommandState state = ResolveCommandState(ctx);
  const bool force_path = IsPathSemanticState(state);
  const bool has_at = ctx.token_prefix.find('@') != std::string::npos;
  if (!force_path && !has_at && !IsPathLikeText(ctx.token_prefix)) {
    return result;
  }

  PathContext path = BuildPathContext_(ctx.token_prefix, force_path);
  if (!path.valid) {
    return result;
  }

  const AMPromptPathProfileArgs &path_profile =
      prompt_manager_.ResolvePromptProfileArgs(path.nickname).path;
  const int timeout_ms = ToClientTimeoutMs(path_profile.timeout_ms, 0);
  const bool use_async = path_profile.use_async;

  CacheKey key{path.nickname, path.dir_abs};
  std::vector<PathInfo> listed;
  if (LookupTempCache_(key, &listed)) {
    AppendPathCandidates_(path, listed, &result.candidates.items);
    if (!result.candidates.items.empty()) {
      SortCandidates(ctx, result.candidates.items);
      result.candidates.from_cache = true;
      return result;
    }
  }

  if (!use_async) {
    std::shared_ptr<BaseClient> client =
        path.remote ? client_manager_.Clients().GetHost(path.nickname)
                    : client_manager_.LocalClient();
    if (!client) {
      return result;
    }
    auto [rcm, items] =
        client->listdir(path.dir_abs, nullptr, timeout_ms, am_ms());
    if (rcm.first != EC::Success) {
      return result;
    }

    StoreTempCache_(key, items);
    AppendPathCandidates_(path, items, &result.candidates.items);
    if (!result.candidates.items.empty()) {
      SortCandidates(ctx, result.candidates.items);
    }
    return result;
  }

  AMCompletionAsyncRequest request;
  request.request_id = ctx.request_id;
  request.timeout_ms = timeout_ms;
  request.target = AMCompletionTarget::Path;
  auto interrupt_flag = std::make_shared<InterruptFlag>();
  request.interrupt_flag = [flag = interrupt_flag]() { return flag->check(); };
  request.interrupt_cancel = [flag = interrupt_flag]() { flag->set(true); };

  request.search = [this, path, key, interrupt_flag](
                       const AMCompletionAsyncRequest &request,
                       AMCompletionAsyncResult *out) -> bool {
    if (request.IsInterrupted()) {
      return false;
    }

    std::shared_ptr<BaseClient> client =
        path.remote ? client_manager_.Clients().GetHost(path.nickname)
                    : client_manager_.LocalClient();
    if (!client) {
      return false;
    }

    const int timeout = request.timeout_ms > 0 ? request.timeout_ms : 5000;
    auto [rcm, items] =
        client->listdir(path.dir_abs, interrupt_flag, timeout, am_ms());
    if (rcm.first != EC::Success || request.IsInterrupted()) {
      return false;
    }

    StoreTempCache_(key, items);

    std::vector<AMCompletionCandidate> candidates;
    AppendPathCandidates_(path, items, &candidates);
    if (!candidates.empty()) {
      SortCandidates(AMCompletionContext{}, candidates);
    }

    if (out) {
      out->request_id = request.request_id;
      out->target = request.target;
      out->candidates = std::move(candidates);
    }
    return true;
  };

  result.async_request = std::move(request);
  return result;
}

/**
 * @brief Sort path candidates.
 */
void AMPathSearchEngine::SortCandidates(
    const AMCompletionContext &ctx, std::vector<AMCompletionCandidate> &items) {
  (void)ctx;
  std::stable_sort(items.begin(), items.end(),
                   [](const auto &lhs, const auto &rhs) {
                     if (lhs.score != rhs.score) {
                       return lhs.score < rhs.score;
                     }
                     const int lo = PathTypeOrder(lhs.path_type);
                     const int ro = PathTypeOrder(rhs.path_type);
                     if (lo != ro) {
                       return lo < ro;
                     }
                     return lhs.insert_text < rhs.insert_text;
                   });
}

/**
 * @brief Clear internal path cache.
 */
void AMPathSearchEngine::ClearCache() { ClearCacheForAll(); }

/**
 * @brief Clear cached path entries for a specific nickname.
 */
void AMPathSearchEngine::ClearCacheForNickname(const std::string &nickname) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  cache_.erase(nickname);
  cache_order_.erase(nickname);
  temp_cache_.erase(nickname);
}

/**
 * @brief Clear cached path entries for all nicknames.
 */
void AMPathSearchEngine::ClearCacheForAll() {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  cache_.clear();
  cache_order_.clear();
  temp_cache_.clear();
}

/**
 * @brief Query cache status for a nickname.
 */
bool AMPathSearchEngine::GetCacheStatusForNickname(const std::string &nickname,
                                                   CacheStatus *status) const {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  auto it = cache_.find(nickname);
  if (it == cache_.end()) {
    return false;
  }

  CacheStatus local{};
  local.entry_count = it->second.size();
  size_t item_count = 0;
  for (const auto &entry : it->second) {
    item_count += entry.second.items.size();
  }
  local.item_count = item_count;
  if (status) {
    *status = local;
  }
  return true;
}

/**
 * @brief Query cache status for all nicknames.
 */
std::unordered_map<std::string, AMPathSearchEngine::CacheStatus>
AMPathSearchEngine::GetCacheStatusAll() const {
  std::unordered_map<std::string, CacheStatus> out;
  std::lock_guard<std::mutex> lock(cache_mtx_);
  for (const auto &bucket : cache_) {
    CacheStatus status{};
    status.entry_count = bucket.second.size();
    size_t item_count = 0;
    for (const auto &entry : bucket.second) {
      item_count += entry.second.items.size();
    }
    status.item_count = item_count;
    out.emplace(bucket.first, status);
  }
  return out;
}

/**
 * @brief Ensure the prompt-return callback is registered once.
 */
void AMPathSearchEngine::EnsureTempCacheHookRegistered_() {
  if (temp_cache_hook_registered_) {
    return;
  }
  temp_cache_clear_callback_ = [this]() { ClearTempCache_(); };
  auto &registry = AMInteractiveLoop::EventRegistry::Instance();
  registry.RegisterOnCorePromptReturn(&temp_cache_clear_callback_);
  registry.RegisterOnInteractiveLoopExit(&temp_cache_clear_callback_);
  temp_cache_hook_registered_ = true;
}

/**
 * @brief Clear temporary path cache.
 */
void AMPathSearchEngine::ClearTempCache_() {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  temp_cache_.clear();
}

/**
 * @brief Style a path entry for display.
 */
std::string
AMPathSearchEngine::FormatPathDisplay_(const PathInfo &info,
                                       const std::string &name) const {
  auto wrap_pre = [&](const std::string &styled,
                      const std::string &raw) -> std::string {
    if (styled == raw || raw.empty() ||
        styled.find("[/") == std::string::npos) {
      return styled;
    }

    const size_t pos = styled.find(raw);
    if (pos == std::string::npos) {
      return styled;
    }
    std::string result = styled;
    result.replace(pos, raw.size(), "[!pre]" + raw + "[/pre]");
    return result;
  };

  const std::string styled = filesystem_.StylePath(info, name);
  return wrap_pre(styled, name);
}

/**
 * @brief Build path context from completion token and mode.
 */
AMPathSearchEngine::PathContext
AMPathSearchEngine::BuildPathContext_(const std::string &token_prefix,
                                      bool force_path) const {
  PathContext path;
  if (token_prefix.empty() && !force_path) {
    return path;
  }

  const auto current_client = client_manager_.CurrentClient();
  const bool current_remote =
      current_client && current_client->GetProtocol() != ClientProtocol::LOCAL;

  bool force_local = false;
  std::string nickname;
  std::string path_part;
  std::string header;

  if (!token_prefix.empty() && token_prefix.front() == '@') {
    force_local = true;
    nickname = "local";
    path_part = token_prefix.substr(1);
    header = "@";
  } else {
    const size_t at_pos = token_prefix.find('@');
    if (at_pos != std::string::npos) {
      nickname = token_prefix.substr(0, at_pos);
      path_part = token_prefix.substr(at_pos + 1);
      header = nickname + "@";
      if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
        force_local = true;
        nickname = "local";
      }
    } else {
      path_part = token_prefix;
      nickname = current_client ? current_client->GetNickname() : "local";
    }
  }

  path_part = var_manager_.SubstitutePathLike(path_part);
  if (header.empty() && !force_path && !IsPathLikeText(path_part)) {
    return path;
  }

  path.remote = (!force_local && current_remote && header.empty()) ||
                (!force_local && !header.empty() &&
                 AMStr::lowercase(nickname) != "local");
  path.nickname = nickname.empty() ? "local" : nickname;
  path.header = header;
  path.raw_path = path_part;
  path.sep = DetectPathSep(path_part, path.remote);
  SplitPath(path_part, &path.dir_raw, &path.leaf_prefix, &path.trailing_sep);

  if (path_part.size() == 2 &&
      std::isalpha(static_cast<unsigned char>(path_part[0])) &&
      path_part[1] == ':') {
    path.dir_raw = path_part + path.sep;
    path.leaf_prefix.clear();
    path.trailing_sep = true;
  }
  path.base = path.header + path.dir_raw;

  std::shared_ptr<BaseClient> client =
      path.remote ? client_manager_.Clients().GetHost(path.nickname)
                  : client_manager_.LocalClient();
  if (!client) {
    return path;
  }
  path.dir_abs = client_manager_.BuildPath(client, path.dir_raw);
  path.valid = true;
  return path;
}

/**
 * @brief Append filtered path candidates from listed items.
 */
void AMPathSearchEngine::AppendPathCandidates_(
    const PathContext &path_ctx, const std::vector<PathInfo> &items,
    std::vector<AMCompletionCandidate> *out) const {
  if (!out) {
    return;
  }

  std::vector<std::string> keys;
  keys.reserve(items.size());
  for (const auto &info : items) {
    keys.push_back(info.name);
  }
  const auto matches = BuildGeneralMatch(keys, path_ctx.leaf_prefix);
  for (const auto &match : matches) {
    const auto &info = items[match.index];
    std::string name = info.name;
    const bool is_dir = info.type == PathType::DIR;

    AMCompletionCandidate candidate;
    candidate.insert_text = path_ctx.base + name;
    if (is_dir) {
      candidate.insert_text.push_back(path_ctx.sep);
    }
    const std::string display_name = is_dir ? name + path_ctx.sep : name;
    candidate.display = FormatPathDisplay_(info, display_name);
    candidate.kind = path_ctx.remote ? AMCompletionKind::PathRemote
                                     : AMCompletionKind::PathLocal;
    candidate.path_type = info.type;
    candidate.score = match.score_bias;
    out->push_back(std::move(candidate));
  }
}

/**
 * @brief Lookup path cache entries.
 */
bool AMPathSearchEngine::LookupCache_(const CacheKey &key,
                                      std::vector<PathInfo> *items) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  auto nick_it = cache_.find(key.nickname);
  if (nick_it == cache_.end()) {
    return false;
  }
  auto it = nick_it->second.find(key.dir);
  if (it == nick_it->second.end()) {
    return false;
  }
  if (items) {
    *items = it->second.items;
  }
  return true;
}

/**
 * @brief Lookup temporary path cache entries.
 */
bool AMPathSearchEngine::LookupTempCache_(const CacheKey &key,
                                          std::vector<PathInfo> *items) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  auto nick_it = temp_cache_.find(key.nickname);
  if (nick_it == temp_cache_.end()) {
    return false;
  }
  auto it = nick_it->second.find(key.dir);
  if (it == nick_it->second.end()) {
    return false;
  }
  if (items) {
    *items = it->second.items;
  }
  return true;
}

/**
 * @brief Store path cache entries and prune old entries.
 */
void AMPathSearchEngine::StoreCache_(const CacheKey &key,
                                     const std::vector<PathInfo> &items,
                                     size_t max_entries) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  if (max_entries < 1) {
    max_entries = 1;
  }

  auto &bucket = cache_[key.nickname];
  bucket[key.dir] = CacheEntry{items, std::chrono::steady_clock::now()};
  auto &order = cache_order_[key.nickname];
  order.remove(key.dir);
  order.push_back(key.dir);
  if (bucket.size() <= max_entries) {
    return;
  }

  while (bucket.size() > max_entries && !order.empty()) {
    const std::string evict = order.front();
    order.pop_front();
    auto it = bucket.find(evict);
    if (it != bucket.end()) {
      bucket.erase(it);
    }
  }
  if (bucket.empty()) {
    cache_.erase(key.nickname);
    cache_order_.erase(key.nickname);
  }
}

/**
 * @brief Store temporary path cache entries.
 */
void AMPathSearchEngine::StoreTempCache_(const CacheKey &key,
                                         const std::vector<PathInfo> &items) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  temp_cache_[key.nickname][key.dir] = TempCacheEntry{items};
}
