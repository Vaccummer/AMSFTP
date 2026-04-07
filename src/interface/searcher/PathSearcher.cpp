#include "domain/client/ClientPort.hpp"
#include "foundation/tools/string.hpp"
#include "interface/cli/InteractiveEventRegistry.hpp"
#include "interface/completion/CompletionRuntime.hpp"
#include "interface/searcher/Searcher.hpp"
#include "interface/searcher/SearcherCommon.hpp"
#include <algorithm>

using namespace AMInterface::searcher::detail;

namespace AMInterface::searcher {
namespace {
constexpr int kEventIdPathClearTempCache = 2001;

std::string TrimTrailingSep_(std::string text) {
  while (!text.empty() && (text.back() == '/' || text.back() == '\\')) {
    text.pop_back();
  }
  return text;
}

std::string LeafNameForSort_(const std::string &insert_text) {
  const std::string clean = TrimTrailingSep_(insert_text);
  if (clean.empty()) {
    return clean;
  }
  const size_t slash_pos = clean.find_last_of("/\\");
  if (slash_pos != std::string::npos) {
    return clean.substr(slash_pos + 1);
  }
  const size_t at_pos = clean.find_last_of('@');
  if (at_pos != std::string::npos) {
    return clean.substr(at_pos + 1);
  }
  return clean;
}

bool StartsWithDot_(const std::string &name) {
  return !name.empty() && name.front() == '.';
}

} // namespace

/**
 * @brief Collect path candidates.
 */
AMCompletionCandidates
AMPathSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCandidates result;
  const auto *runtime = runtime_.get();
  if (!runtime) {
    return result;
  }
  if (!HasTarget(ctx, AMCompletionTarget::Path)) {
    return result;
  }

  const CommandState state = ResolveCommandState(ctx);
  const bool force_path = IsPathSemanticState(ctx, state);
  const bool has_at = ctx.token_prefix.find('@') != std::string::npos;
  if (!force_path && !has_at && !IsPathLikeText(ctx.token_prefix)) {
    return result;
  }

  PathContext path = BuildPathContext_(ctx.token_prefix, force_path);
  if (!path.valid) {
    return result;
  }

  const int timeout_ms = ToClientTimeoutMs(
      ctx.timeout_ms > 0 ? static_cast<size_t>(ctx.timeout_ms) : 0, 0);

  CacheKey key{path.nickname, path.dir_abs};
  std::vector<PathInfo> listed;
  if (LookupTempCache_(key, &listed)) {
    AppendPathCandidates_(path, listed, &result.items);
    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
      result.from_cache = true;
      return result;
    }
  }

  AMDomain::client::ClientHandle client = runtime->GetClient(path.nickname);
  if (!client && !path.remote) {
    client = runtime->LocalClient();
  }
  if (!client) {
    return result;
  }

  auto list_result =
      client->IOPort().listdir({path.dir_abs},
                               AMDomain::client::ClientControlComponent(
                                   ctx.control_token, timeout_ms));
  if (list_result.rcm.code != EC::Success) {
    return result;
  }

  StoreTempCache_(key, list_result.data.entries);
  AppendPathCandidates_(path, list_result.data.entries, &result.items);
  if (!result.items.empty()) {
    SortCandidates(ctx, result.items);
  }
  return result;
}

std::shared_ptr<AMInterface::completer::ICompletionTask>
AMPathSearchEngine::CreateTask(const AMCompletionContext &ctx) {
  return AMCompletionSearchEngine::CreateTask(ctx);
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
                     const std::string lname =
                         LeafNameForSort_(lhs.insert_text);
                     const std::string rname =
                         LeafNameForSort_(rhs.insert_text);
                     const bool ldot = StartsWithDot_(lname);
                     const bool rdot = StartsWithDot_(rname);
                     if (ldot != rdot) {
                       return ldot;
                     }
                     if (lname != rname) {
                       return lname < rname;
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
 * @brief Register temp-cache clear callbacks for PromptCore return/exit.
 */
void AMPathSearchEngine::RegisterCacheClearOnCorePromptReturn() {
  EnsureTempCacheHookRegistered_();
}

void AMPathSearchEngine::SetInteractiveEventRegistry(
    AMInterface::cli::InteractiveEventRegistry *registry) {
  interactive_event_registry_ = registry;
}

/**
 * @brief Ensure the prompt-return callback is registered once.
 */
void AMPathSearchEngine::EnsureTempCacheHookRegistered_() {
  if (temp_cache_hook_registered_ || interactive_event_registry_ == nullptr) {
    return;
  }
  temp_cache_clear_callback_ = [this]() { ClearTempCache_(); };
  (void)interactive_event_registry_->Register(
      AMInterface::cli::InteractiveEventCategory::CorePromptReturn,
      kEventIdPathClearTempCache, temp_cache_clear_callback_);
  (void)interactive_event_registry_->Register(
      AMInterface::cli::InteractiveEventCategory::InteractiveLoopExit,
      kEventIdPathClearTempCache, temp_cache_clear_callback_);
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

  if (!runtime_) {
    return name;
  }
  const std::string styled = runtime_->FormatPath(name, &info);
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

  if (!runtime_) {
    return path;
  }

  std::string current_nickname = AMStr::Strip(runtime_->CurrentNickname());
  if (current_nickname.empty()) {
    current_nickname = "local";
  }
  AMDomain::client::ClientHandle current_client =
      runtime_->GetClient(current_nickname);
  if (!current_client && AMStr::lowercase(current_nickname) == "local") {
    current_client = runtime_->LocalClient();
  }
  bool current_remote =
      AMStr::lowercase(current_nickname) != std::string("local");
  if (current_client) {
    current_remote = current_client->ConfigPort().GetProtocol() !=
                     AMDomain::host::ClientProtocol::LOCAL;
  }

  bool force_local = false;
  std::string nickname;
  std::string path_part_raw;
  std::string header;

  if (!token_prefix.empty() && token_prefix.front() == '@') {
    force_local = true;
    nickname = "local";
    path_part_raw = token_prefix.substr(1);
    header = "@";
  } else {
    const size_t at_pos = token_prefix.find('@');
    if (at_pos != std::string::npos) {
      nickname = token_prefix.substr(0, at_pos);
      path_part_raw = token_prefix.substr(at_pos + 1);
      header = nickname + "@";
      if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
        force_local = true;
        nickname = "local";
      }
    } else {
      path_part_raw = token_prefix;
      nickname = current_nickname;
    }
  }

  const std::string path_part_resolved =
      runtime_->SubstitutePathLike(path_part_raw);
  if (header.empty() && !force_path && !IsPathLikeText(path_part_resolved)) {
    return path;
  }

  path.remote = (!force_local && current_remote && header.empty()) ||
                (!force_local && !header.empty() &&
                 AMStr::lowercase(nickname) != "local");
  path.nickname = nickname.empty() ? "local" : nickname;
  path.header = header;
  path.raw_path = path_part_raw;
  path.sep = DetectPathSep(
      path_part_raw.empty() ? path_part_resolved : path_part_raw, path.remote);

  // Keep raw base for insertion text so `$var/...` form is preserved.
  std::string resolved_dir_raw;
  SplitPath(path_part_raw, &path.dir_raw, nullptr, &path.trailing_sep);
  SplitPath(path_part_resolved, &resolved_dir_raw, &path.leaf_prefix, nullptr);

  if (path_part_raw.size() == 2 &&
      std::isalpha(static_cast<unsigned char>(path_part_raw[0])) &&
      path_part_raw[1] == ':') {
    path.dir_raw = path_part_raw + path.sep;
    path.trailing_sep = true;
  }
  if (path_part_resolved.size() == 2 &&
      std::isalpha(static_cast<unsigned char>(path_part_resolved[0])) &&
      path_part_resolved[1] == ':') {
    resolved_dir_raw = path_part_resolved + path.sep;
    path.leaf_prefix.clear();
    path.trailing_sep = true;
  }
  path.base = path.header + path.dir_raw;

  AMDomain::client::ClientHandle client = runtime_->GetClient(path.nickname);
  if (!client && !path.remote) {
    client = runtime_->LocalClient();
  }
  if (!client) {
    return path;
  }
  path.dir_abs = runtime_->BuildPath(client, resolved_dir_raw);
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

} // namespace AMInterface::searcher

namespace AMInterface::completer {
std::vector<AMSearchEngineRegistration> AMBuildDefaultSearchEngineRegistrations(
    std::shared_ptr<AMInterface::completion::ICompletionRuntime> runtime,
    AMInterface::cli::InteractiveEventRegistry *interactive_event_registry) {
  std::vector<AMSearchEngineRegistration> out;

  auto command_engine = std::make_shared<AMInterface::searcher::AMCommandSearchEngine>();
  out.push_back(
      {{AMCompletionTarget::TopCommand, AMCompletionTarget::Subcommand,
        AMCompletionTarget::LongOption, AMCompletionTarget::ShortOption},
       command_engine});

  auto internal_engine =
      std::make_shared<AMInterface::searcher::AMInternalSearchEngine>(runtime);
  out.push_back(
      {{AMCompletionTarget::VariableName, AMCompletionTarget::ClientName,
        AMCompletionTarget::HostNickname, AMCompletionTarget::HostAttr,
        AMCompletionTarget::TaskId, AMCompletionTarget::VarZone},
       internal_engine});

  auto path_engine = std::make_shared<AMInterface::searcher::AMPathSearchEngine>(runtime);
  path_engine->SetInteractiveEventRegistry(interactive_event_registry);
  path_engine->RegisterCacheClearOnCorePromptReturn();
  out.push_back({{AMCompletionTarget::Path}, path_engine});
  return out;
}

} // namespace AMInterface::completer
