#include "AMBase/CommonTools.hpp"
#include "AMManager/Prompt.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <string>
#include <vector>

namespace {
inline constexpr const char *kPromptProfileRoot = "PromptProfile";
inline constexpr const char *kDefaultPromptProfile = "*";

/**
 * @brief Normalize a profile nickname key.
 */
std::string NormalizeProfileNickname_(const std::string &nickname) {
  std::string key = AMStr::Strip(nickname);
  if (key.size() >= 2) {
    const char first = key.front();
    const char last = key.back();
    if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
      key = key.substr(1, key.size() - 2);
    }
  }
  if (key.empty()) {
    key = "local";
  }
  return key;
}

/**
 * @brief Normalize a raw profile key from settings.
 */
std::string NormalizeProfileKey_(const std::string &raw_key) {
  std::string key = AMStr::Strip(raw_key);
  if (key.size() >= 2) {
    const char first = key.front();
    const char last = key.back();
    if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
      key = key.substr(1, key.size() - 2);
    }
  }
  return key;
}

/**
 * @brief Find default profile node for `[PromptProfile."*"]`.
 */
const Json *FindDefaultProfileNode_(const Json &profile_root) {
  if (!profile_root.is_object()) {
    return nullptr;
  }

  auto direct = profile_root.find(kDefaultPromptProfile);
  if (direct != profile_root.end() && direct->is_object()) {
    return &(*direct);
  }

  for (auto it = profile_root.begin(); it != profile_root.end(); ++it) {
    if (!it.value().is_object()) {
      continue;
    }
    if (NormalizeProfileKey_(it.key()) == kDefaultPromptProfile) {
      return &it.value();
    }
  }
  return nullptr;
}

/**
 * @brief Return all isocline history records from current profile.
 */
std::vector<std::string> GetIsoRecords_() {
  long count = ic_history_count();
  if (count < 0) {
    return {};
  }
  std::vector<std::string> records;
  records.reserve(static_cast<size_t>(count));
  for (long i = 0; i < count; ++i) {
    const char *entry = ic_history_get(i);
    if (entry) {
      records.emplace_back(entry);
    }
  }
  return records;
}
} // namespace

/**
 * @brief Initialize prompt profile args from JSON with fallback defaults.
 */
void AMPromptProfileArgs::Init(const Json &jsond,
                               const AMPromptProfileArgs &defaults) {
  *this = defaults;
  if (!jsond.is_object()) {
    return;
  }

  (void)QueryKey(jsond, {"Prompt", "marker"}, &prompt.marker);
  (void)QueryKey(jsond, {"Prompt", "continuation_marker"},
                 &prompt.continuation_marker);
  (void)QueryKey(jsond, {"Prompt", "enable_muiltiline"},
                 &prompt.enable_multiline);

  (void)QueryKey(jsond, {"History", "enable"}, &history.enable);
  (void)QueryKey(jsond, {"History", "enable_duplicates"},
                 &history.enable_duplicates);
  (void)QueryKey(jsond, {"History", "max_count"}, &history.max_count);

  (void)QueryKey(jsond, {"InlineHint", "enable"}, &inline_hint.enable);
  (void)QueryKey(jsond, {"InlineHint", "delay_ms"}, &inline_hint.delay_ms);
  (void)QueryKey(jsond, {"InlineHint", "search_delay_ms"},
                 &inline_hint.search_delay_ms);
  (void)QueryKey(jsond, {"InlineHint", "Path", "enable"},
                 &inline_hint.path.enable);
  (void)QueryKey(jsond, {"InlineHint", "Path", "use_async"},
                 &inline_hint.path.use_async);
  (void)QueryKey(jsond, {"InlineHint", "Path", "timeout_ms"},
                 &inline_hint.path.timeout_ms);

  (void)QueryKey(jsond, {"Complete", "Searcher", "Path", "use_async"},
                 &complete.path.use_async);
  (void)QueryKey(jsond, {"Complete", "Searcher", "Path", "timeout_ms"},
                 &complete.path.timeout_ms);
  (void)QueryKey(jsond, {"Highlight", "delay_ms"},
                 &highlight.delay_ms);
  (void)QueryKey(jsond, {"Highlight", "Path", "enable"},
                 &highlight.path.enable);
  (void)QueryKey(jsond, {"Highlight", "Path", "timeout_ms"},
                 &highlight.path.timeout_ms);

  history.max_count = std::min(std::max(1, history.max_count), 200);
  inline_hint.delay_ms = std::max(0, inline_hint.delay_ms);
  inline_hint.search_delay_ms = std::max(0, inline_hint.search_delay_ms);
  highlight.delay_ms = std::max(0, highlight.delay_ms);

  if (inline_hint.path.timeout_ms < 1) {
    inline_hint.path.timeout_ms = defaults.inline_hint.path.timeout_ms;
  }
  if (complete.path.timeout_ms < 1) {
    complete.path.timeout_ms = defaults.complete.path.timeout_ms;
  }
  if (highlight.path.timeout_ms < 1) {
    highlight.path.timeout_ms = defaults.highlight.path.timeout_ms;
  }
}

/**
 * @brief Dump prompt profile args to JSON with the current schema.
 */
Json AMPromptProfileArgs::GetJson() const {
  Json jsond = Json::object();
  jsond["Prompt"]["marker"] = prompt.marker;
  jsond["Prompt"]["continuation_marker"] = prompt.continuation_marker;
  jsond["Prompt"]["enable_muiltiline"] = prompt.enable_multiline;

  jsond["History"]["enable"] = history.enable;
  jsond["History"]["enable_duplicates"] = history.enable_duplicates;
  jsond["History"]["max_count"] = history.max_count;

  jsond["InlineHint"]["enable"] = inline_hint.enable;
  jsond["InlineHint"]["delay_ms"] = inline_hint.delay_ms;
  jsond["InlineHint"]["search_delay_ms"] = inline_hint.search_delay_ms;
  jsond["InlineHint"]["Path"]["enable"] = inline_hint.path.enable;
  jsond["InlineHint"]["Path"]["use_async"] = inline_hint.path.use_async;
  jsond["InlineHint"]["Path"]["timeout_ms"] = inline_hint.path.timeout_ms;

  jsond["Complete"]["Searcher"]["Path"]["use_async"] = complete.path.use_async;
  jsond["Complete"]["Searcher"]["Path"]["timeout_ms"] = complete.path.timeout_ms;

  jsond["Highlight"]["delay_ms"] = highlight.delay_ms;
  jsond["Highlight"]["Path"]["enable"] = highlight.path.enable;
  jsond["Highlight"]["Path"]["timeout_ms"] = highlight.path.timeout_ms;
  return jsond;
}

/**
 * @brief Release all owned isocline profile handles.
 */
AMProfileManager::~AMProfileManager() {
  std::unordered_set<ic_profile_t *> released;
  auto release_one = [&released](AMPromptProfileArgs &profile) {
    if (!profile.ic_profile) {
      return;
    }
    if (released.insert(profile.ic_profile).second) {
      ic_profile_free(profile.ic_profile);
    }
    profile.ic_profile = nullptr;
  };

  std::lock_guard<std::mutex> lock(profile_mtx_);
  for (auto &pair : prompt_profiles_) {
    release_one(pair.second);
  }
  release_one(default_prompt_profile_args_);
}

/**
 * @brief Build profile args from one JSON object with fallback defaults.
 */
AMPromptProfileArgs AMProfileManager::BuildPromptProfileArgs_(
    const Json &jsond, const AMPromptProfileArgs &defaults) const {
  AMPromptProfileArgs out{};
  out.Init(jsond, defaults);
  return out;
}

/**
 * @brief Reload prompt profile args from settings.
 */
ECM AMProfileManager::ReloadPromptProfiles() {
  Json profile_root = config_.ResolveArg<Json>(
      DocumentKind::Settings, {kPromptProfileRoot}, Json::object(), {});
  if (!profile_root.is_object()) {
    profile_root = Json::object();
  }

  AMPromptProfileArgs builtin_defaults{};
  builtin_defaults.name = kDefaultPromptProfile;
  builtin_defaults.from_default = false;
  builtin_defaults.ic_profile = nullptr;
  AMPromptProfileArgs star_profile = builtin_defaults;
  const Json *default_node = FindDefaultProfileNode_(profile_root);
  if (default_node) {
    star_profile = BuildPromptProfileArgs_(*default_node, builtin_defaults);
  }
  star_profile.name = kDefaultPromptProfile;
  star_profile.from_default = false;
  star_profile.ic_profile = nullptr;

  std::unordered_map<std::string, AMPromptProfileArgs> parsed;
  parsed.reserve(profile_root.size() + 1);
  parsed[kDefaultPromptProfile] = star_profile;

  for (auto it = profile_root.begin(); it != profile_root.end(); ++it) {
    if (!it.value().is_object()) {
      continue;
    }
    const std::string key = NormalizeProfileKey_(it.key());
    if (key.empty() || key == kDefaultPromptProfile) {
      continue;
    }
    AMPromptProfileArgs item = BuildPromptProfileArgs_(it.value(), star_profile);
    item.name = key;
    item.from_default = false;
    item.ic_profile = nullptr;
    parsed[key] = std::move(item);
  }

  {
    std::lock_guard<std::mutex> lock(profile_mtx_);
    prompt_profiles_ = std::move(parsed);
    default_prompt_profile_args_ = star_profile;
    profiles_loaded_ = true;
  }
  return Ok();
}

/**
 * @brief Interactively edit one prompt profile and persist to settings.
 */
ECM AMProfileManager::Edit(const std::string &nickname) {
  EnsurePromptProfilesLoaded_();
  const std::string target = NormalizeProfileNickname_(nickname);
  if (target.empty()) {
    return Err(EC::InvalidArg, "empty profile nickname");
  }

  AMPromptProfileArgs working{};
  {
    std::lock_guard<std::mutex> lock(profile_mtx_);
    auto it = prompt_profiles_.find(target);
    if (it != prompt_profiles_.end()) {
      working = it->second;
    } else {
      auto star_it = prompt_profiles_.find(kDefaultPromptProfile);
      if (star_it != prompt_profiles_.end()) {
        working = star_it->second;
      } else {
        working = default_prompt_profile_args_;
      }
      working.name = target;
      working.from_default = true;
      working.ic_profile = nullptr;
    }
  }

  AMPromptManager &prompt = AMPromptManager::Instance();
  const AMPromptProfileArgs builtin_defaults{};
  const auto print_abort = [&prompt, this]() {
    prompt.Print(AMStr::amfmt("{}\n", config_.Format("Input Abort", "abort")));
  };

  const std::map<std::string, std::string> bool_literals = {
      {"true", "enable"}, {"false", "disable"}};

  auto prompt_string = [&prompt](const std::string &label, std::string *value) {
    if (!value) {
      return false;
    }
    std::string out;
    if (!prompt.Prompt(label, *value, &out)) {
      return false;
    }
    *value = out;
    return true;
  };

  auto prompt_bool = [&prompt, &bool_literals](const std::string &label,
                                               bool *value) {
    if (!value) {
      return false;
    }
    while (true) {
      std::string out;
      const std::string placeholder = (*value ? "true" : "false");
      if (!prompt.LiteralPrompt(label, placeholder, &out, bool_literals)) {
        return false;
      }
      out = AMStr::lowercase(AMStr::Strip(out));
      if (out.empty()) {
        out = placeholder;
      }
      bool parsed = *value;
      if (StrValueParse(out, &parsed)) {
        *value = parsed;
        return true;
      }
      prompt.ErrorFormat(ECM{EC::InvalidArg, "value must be true or false"});
    }
  };

  auto prompt_int64 = [&prompt](const std::string &label, int64_t min_value,
                                int64_t max_value, int64_t *value) {
    if (!value) {
      return false;
    }
    while (true) {
      const std::string placeholder = std::to_string(*value);
      std::string out;
      auto checker = [min_value, max_value,
                      placeholder](const std::string &text) -> bool {
        std::string trimmed = AMStr::Strip(text);
        if (trimmed.empty()) {
          trimmed = placeholder;
        }
        int64_t parsed = 0;
        if (!StrValueParse(trimmed, &parsed)) {
          return false;
        }
        return parsed >= min_value && parsed <= max_value;
      };
      if (!prompt.Prompt(label, placeholder, &out, checker)) {
        return false;
      }
      out = AMStr::Strip(out);
      if (out.empty()) {
        out = placeholder;
      }
      int64_t parsed = *value;
      if (!StrValueParse(out, &parsed)) {
        prompt.ErrorFormat(ECM{EC::InvalidArg, "invalid integer value"});
        continue;
      }
      if (parsed < min_value || parsed > max_value) {
        prompt.ErrorFormat(
            ECM{EC::InvalidArg, AMStr::amfmt("value out of range [{}, {}]",
                                             min_value, max_value)});
        continue;
      }
      *value = parsed;
      return true;
    }
  };

  if (!prompt_string("Prompt.marker: ", &working.prompt.marker) ||
      !prompt_string("Prompt.continuation_marker: ",
                     &working.prompt.continuation_marker)) {
    print_abort();
    return Err(EC::ConfigCanceled, "profile edit canceled");
  }
  if (!prompt_bool("Prompt.enable_multiline(true/false): ",
                   &working.prompt.enable_multiline) ||
      !prompt_bool("History.enable(true/false): ", &working.history.enable)) {
    print_abort();
    return Err(EC::ConfigCanceled, "profile edit canceled");
  }

  if (working.history.enable) {
    if (!prompt_bool("History.enable_duplicates(true/false): ",
                     &working.history.enable_duplicates)) {
      print_abort();
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    int64_t history_max = static_cast<int64_t>(working.history.max_count);
    if (!prompt_int64("History.max_count: ", 1, 200, &history_max)) {
      print_abort();
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    working.history.max_count = static_cast<int>(history_max);
  } else {
    working.history.enable_duplicates = builtin_defaults.history.enable_duplicates;
    working.history.max_count = builtin_defaults.history.max_count;
  }

  if (!prompt_bool("InlineHint.enable(true/false): ",
                   &working.inline_hint.enable)) {
    print_abort();
    return Err(EC::ConfigCanceled, "profile edit canceled");
  }

  if (working.inline_hint.enable) {
    int64_t inline_delay = static_cast<int64_t>(working.inline_hint.delay_ms);
    if (!prompt_int64("InlineHint.delay_ms: ", 0, 5000, &inline_delay)) {
      print_abort();
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    working.inline_hint.delay_ms = static_cast<int>(inline_delay);

    int64_t inline_search_delay =
        static_cast<int64_t>(working.inline_hint.search_delay_ms);
    if (!prompt_int64("InlineHint.search_delay_ms: ", 0, 5000,
                      &inline_search_delay)) {
      print_abort();
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    working.inline_hint.search_delay_ms = static_cast<int>(inline_search_delay);

    if (!prompt_bool("InlineHint.Path.enable(true/false): ",
                     &working.inline_hint.path.enable)) {
      print_abort();
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    if (working.inline_hint.path.enable) {
      if (!prompt_bool("InlineHint.Path.use_async(true/false): ",
                       &working.inline_hint.path.use_async)) {
        print_abort();
        return Err(EC::ConfigCanceled, "profile edit canceled");
      }
      if (working.inline_hint.path.use_async) {
        int64_t inline_path_timeout =
            static_cast<int64_t>(working.inline_hint.path.timeout_ms);
        if (!prompt_int64("InlineHint.Path.timeout_ms: ", 1, 300000,
                          &inline_path_timeout)) {
          print_abort();
          return Err(EC::ConfigCanceled, "profile edit canceled");
        }
        working.inline_hint.path.timeout_ms =
            static_cast<size_t>(inline_path_timeout);
      } else {
        working.inline_hint.path.timeout_ms =
            builtin_defaults.inline_hint.path.timeout_ms;
      }
    } else {
      working.inline_hint.path.use_async =
          builtin_defaults.inline_hint.path.use_async;
      working.inline_hint.path.timeout_ms =
          builtin_defaults.inline_hint.path.timeout_ms;
    }
  } else {
    working.inline_hint.delay_ms = builtin_defaults.inline_hint.delay_ms;
    working.inline_hint.search_delay_ms =
        builtin_defaults.inline_hint.search_delay_ms;
    working.inline_hint.path = builtin_defaults.inline_hint.path;
  }

  if (!prompt_bool("Complete.Searcher.Path.use_async(true/false): ",
                   &working.complete.path.use_async)) {
    print_abort();
    return Err(EC::ConfigCanceled, "profile edit canceled");
  }
  if (working.complete.path.use_async) {
    int64_t complete_path_timeout =
        static_cast<int64_t>(working.complete.path.timeout_ms);
    if (!prompt_int64("Complete.Searcher.Path.timeout_ms: ", 1, 300000,
                      &complete_path_timeout)) {
      print_abort();
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    working.complete.path.timeout_ms =
        static_cast<size_t>(complete_path_timeout);
  } else {
    working.complete.path.timeout_ms = builtin_defaults.complete.path.timeout_ms;
  }

  int64_t highlight_delay = static_cast<int64_t>(working.highlight.delay_ms);
  if (!prompt_int64("Highlight.delay_ms: ", 0, 5000, &highlight_delay) ||
      !prompt_bool("Highlight.Path.enable(true/false): ",
                   &working.highlight.path.enable)) {
    print_abort();
    return Err(EC::ConfigCanceled, "profile edit canceled");
  }
  working.highlight.delay_ms = static_cast<int>(highlight_delay);

  if (working.highlight.path.enable) {
    int64_t highlight_path_timeout =
        static_cast<int64_t>(working.highlight.path.timeout_ms);
    if (!prompt_int64("Highlight.Path.timeout_ms: ", 1, 300000,
                      &highlight_path_timeout)) {
      print_abort();
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    working.highlight.path.timeout_ms =
        static_cast<size_t>(highlight_path_timeout);
  } else {
    working.highlight.path.timeout_ms =
        builtin_defaults.highlight.path.timeout_ms;
  }

  working.name = target;
  working.from_default = false;

  {
    std::lock_guard<std::mutex> lock(profile_mtx_);
    auto existing = prompt_profiles_.find(target);
    if (existing != prompt_profiles_.end()) {
      working.ic_profile = existing->second.ic_profile;
    }
    prompt_profiles_[target] = working;

    if (target == kDefaultPromptProfile) {
      default_prompt_profile_args_ = working;
      default_prompt_profile_args_.name = kDefaultPromptProfile;
      default_prompt_profile_args_.from_default = false;
      default_prompt_profile_args_.ic_profile = nullptr;

      for (auto &pair : prompt_profiles_) {
        if (pair.first == kDefaultPromptProfile || !pair.second.from_default) {
          continue;
        }
        ic_profile_t *profile_ptr = pair.second.ic_profile;
        const std::string profile_name = pair.second.name;
        pair.second = working;
        pair.second.name = profile_name;
        pair.second.from_default = true;
        pair.second.ic_profile = profile_ptr;
      }
    }
  }

  if (!config_.SetArg(DocumentKind::Settings, {kPromptProfileRoot, target},
                      working.GetJson())) {
    return Err(EC::CommonFailure, "failed to update PromptProfile");
  }
  ECM dump_rcm = config_.Dump(DocumentKind::Settings, "", true);
  if (dump_rcm.first != EC::Success) {
    return dump_rcm;
  }

  if (!active_core_nickname_.empty()) {
    (void)UseCorePromptProfileForClient_(active_core_nickname_);
  }
  return Ok();
}

/**
 * @brief Ensure runtime profile entry exists for one client.
 */
AMPromptProfileArgs &
AMProfileManager::EnsurePromptProfileForClient_(const std::string &nickname) {
  EnsurePromptProfilesLoaded_();
  const std::string key = NormalizeProfileNickname_(nickname);
  std::lock_guard<std::mutex> lock(profile_mtx_);
  auto it = prompt_profiles_.find(key);
  if (it != prompt_profiles_.end()) {
    return it->second;
  }

  AMPromptProfileArgs created = default_prompt_profile_args_;
  auto star_it = prompt_profiles_.find(kDefaultPromptProfile);
  if (star_it != prompt_profiles_.end()) {
    created = star_it->second;
  }
  created.name = key;
  created.from_default = true;
  created.ic_profile = nullptr;

  auto [insert_it, _] = prompt_profiles_.emplace(key, std::move(created));
  return insert_it->second;
}

/**
 * @brief Resolve prompt profile args for one nickname.
 */
AMPromptProfileArgs &
AMProfileManager::ResolvePromptProfileArgs(const std::string &nickname) {
  EnsurePromptProfilesLoaded_();
  const std::string key = NormalizeProfileNickname_(nickname);
  std::lock_guard<std::mutex> lock(profile_mtx_);
  auto it = prompt_profiles_.find(key);
  if (it != prompt_profiles_.end()) {
    return it->second;
  }
  auto star_it = prompt_profiles_.find(kDefaultPromptProfile);
  if (star_it != prompt_profiles_.end()) {
    return star_it->second;
  }
  return default_prompt_profile_args_;
}

/**
 * @brief Return current active prompt profile args.
 */
AMPromptProfileArgs *AMProfileManager::GetCurrentPromptProfileArgs() {
  EnsurePromptProfilesLoaded_();
  if (active_core_nickname_.empty()) {
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(profile_mtx_);
  auto it = prompt_profiles_.find(active_core_nickname_);
  if (it == prompt_profiles_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Return current active prompt profile args (const overload).
 */
const AMPromptProfileArgs *AMProfileManager::GetCurrentPromptProfileArgs() const {
  return const_cast<AMProfileManager *>(this)->GetCurrentPromptProfileArgs();
}

/**
 * @brief Ensure prompt profiles are loaded.
 */
void AMProfileManager::EnsurePromptProfilesLoaded_() {
  {
    std::lock_guard<std::mutex> lock(profile_mtx_);
    if (profiles_loaded_) {
      return;
    }
  }
  (void)ReloadPromptProfiles();
}

/**
 * @brief Collect persisted history map from history document.
 */
void AMProfileManager::CollectHistory_() {
  history_map_.clear();
  Json jsond;
  if (!config_.GetJson(DocumentKind::History, &jsond) || !jsond.is_object()) {
    return;
  }
  for (auto it = jsond.begin(); it != jsond.end(); ++it) {
    const auto &node = it.value();
    if (!node.is_object()) {
      continue;
    }
    auto cmd_it = node.find("commands");
    if (cmd_it == node.end() || !cmd_it->is_array()) {
      continue;
    }
    std::vector<std::string> records;
    for (const auto &item : *cmd_it) {
      if (item.is_string()) {
        records.push_back(item.get<std::string>());
      }
    }
    history_map_[it.key()] = std::move(records);
  }
}

/**
 * @brief Enable or disable history for the current active client.
 */
void AMPromptManager::SetHistoryEnabled(bool enabled) {
  AMPromptProfileArgs *profile = GetCurrentPromptProfileArgs();
  if (!profile) {
    return;
  }
  profile->history.enable = enabled;
  if (!core_prompt_profile_) {
    return;
  }
  if (!ic_profile_use(core_prompt_profile_)) {
    return;
  }
  const int max_history = std::min(std::max(1, profile->history.max_count), 200);
  ic_set_history(nullptr, max_history);
  ic_enable_history_duplicates(profile->history.enable_duplicates);
  if (!enabled) {
    ic_history_clear();
  }
}

/**
 * @brief Add one history entry to the current active client.
 */
void AMPromptManager::AddHistoryEntry(const std::string &line) {
  if (line.empty()) {
    return;
  }
  AMPromptProfileArgs *profile = GetCurrentPromptProfileArgs();
  if (!profile || !profile->history.enable || !core_prompt_profile_) {
    return;
  }
  if (!ic_profile_use(core_prompt_profile_)) {
    return;
  }
  ic_history_add(line.c_str());
}

/**
 * @brief Switch CorePrompt profile/history to the specified client nickname.
 */
ECM AMPromptManager::ChangeClient(const std::string &nickname) {
  const std::string target = NormalizeProfileNickname_(nickname);
  if (active_core_nickname_ == target && core_prompt_profile_) {
    (void)UseCorePromptProfileForClient_(target);
    return Ok();
  }

  if (!UseCorePromptProfileForClient_(target)) {
    return Err(EC::UnknownError,
               "failed to switch CorePrompt profile for nickname: " + target);
  }
  return Ok();
}

/**
 * @brief Flush current history back into history document.
 */
void AMPromptManager::FlushHistory() {
  ic_profile_t *restore_profile = core_prompt_profile_;
  if (!restore_profile) {
    restore_profile = ic_profile_current();
  }

  for (auto &pair : prompt_profiles_) {
    AMPromptProfileArgs &profile = pair.second;
    if (!profile.ic_profile) {
      continue;
    }
    if (!ic_profile_use(profile.ic_profile)) {
      continue;
    }
    history_map_[pair.first] = GetIsoRecords_();
  }

  if (restore_profile) {
    (void)ic_profile_use(restore_profile);
  }

  Json jsond = Json::object();
  for (const auto &pair : history_map_) {
    jsond[pair.first]["commands"] = pair.second;
  }
  config_.SetArg(DocumentKind::History, {}, jsond);
  config_.Dump(DocumentKind::History, "", true);
}
