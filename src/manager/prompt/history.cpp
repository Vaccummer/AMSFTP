#include "AMManager/Prompt.hpp"
#include "AMBase/CommonTools.hpp"
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
  if (key.empty()) {
    key = "local";
  }
  return key;
}

/**
 * @brief Read one setting value from the first existing path.
 */
template <typename T>
void ReadProfileValue_(const Json &node,
                       const std::vector<std::vector<std::string>> &paths,
                       T *value) {
  if (!value) {
    return;
  }
  for (const auto &path : paths) {
    T candidate = *value;
    if (QueryKey(node, path, &candidate)) {
      *value = candidate;
      return;
    }
  }
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
 * @brief Enable or disable history navigation for arrow keys.
 */
void AMProfileManager::SetHistoryEnabled(bool enabled) {
  history_enabled_ = enabled;
}

/**
 * @brief Add a history entry to the readline history.
 */
void AMProfileManager::AddHistoryEntry(const std::string &line) {
  if (!history_enabled_ || line.empty()) {
    return;
  }
  ic_history_add(line.c_str());
}

/**
 * @brief Build profile args from one JSON object with fallback defaults.
 */
AMPromptProfileArgs
AMProfileManager::BuildPromptProfileArgs_(const Json &jsond,
                                          const AMPromptProfileArgs &defaults)
    const {
  AMPromptProfileArgs out = defaults;
  if (!jsond.is_object()) {
    return out;
  }

  ReadProfileValue_(jsond, {{"builtin_prompt_color"},
                            {"Input", "builtin_prompt_color"},
                            {"Options", "InputSet", "builtin_prompt_color"}},
                    &out.input.builtin_prompt_color);
  ReadProfileValue_(jsond,
                    {{"prompt_marker"},
                     {"Input", "prompt_marker"},
                     {"Options", "InputSet", "prompt_marker"}},
                    &out.input.prompt_marker);
  ReadProfileValue_(jsond, {{"continuation_prompt_marker"},
                            {"Input", "continuation_prompt_marker"},
                            {"Options", "InputSet", "continuation_prompt_marker"}},
                    &out.input.continuation_prompt_marker);
  ReadProfileValue_(jsond, {{"max_history_count"},
                            {"Input", "max_history_count"},
                            {"Options", "InputSet", "max_history_count"}},
                    &out.input.max_history_count);
  ReadProfileValue_(jsond, {{"enable_multiline"},
                            {"Input", "enable_multiline"},
                            {"Options", "InputSet", "enable_multiline"}},
                    &out.input.enable_multiline);
  ReadProfileValue_(jsond, {{"enable_history_duplicates"},
                            {"Input", "enable_history_duplicates"},
                            {"Options", "InputSet", "enable_history_duplicates"}},
                    &out.input.enable_history_duplicates);
  ReadProfileValue_(jsond, {{"hint_render_delay_ms"},
                            {"Input", "hint_render_delay_ms"},
                            {"Options", "InputSet", "hint_render_delay_ms"}},
                    &out.input.hint_render_delay_ms);
  ReadProfileValue_(jsond, {{"complete_search_delay_ms"},
                            {"Input", "complete_search_delay_ms"},
                            {"Options", "InputSet", "complete_search_delay_ms"}},
                    &out.input.complete_search_delay_ms);

  ReadProfileValue_(jsond, {{"Path", "use_async"},
                            {"CompleteOption", "Searcher", "Path", "use_async"}},
                    &out.path.use_async);
  ReadProfileValue_(jsond, {{"Path", "timeout_ms"},
                            {"CompleteOption", "Searcher", "Path", "timeout_ms"}},
                    &out.path.timeout_ms);
  ReadProfileValue_(jsond, {{"Path", "highlight_use_check"},
                            {"Highlight", "Path", "use_check"}},
                    &out.path.highlight_use_check);
  ReadProfileValue_(jsond, {{"Path", "highlight_timeout_ms"},
                            {"Highlight", "Path", "timeout_ms"}},
                    &out.path.highlight_timeout_ms);

  out.input.max_history_count =
      std::min(std::max(1, out.input.max_history_count), 150);
  out.input.hint_render_delay_ms = std::max(0, out.input.hint_render_delay_ms);
  out.input.complete_search_delay_ms =
      std::max(0, out.input.complete_search_delay_ms);
  if (out.path.timeout_ms < 1) {
    out.path.timeout_ms = defaults.path.timeout_ms;
  }
  if (out.path.highlight_timeout_ms < 1) {
    out.path.highlight_timeout_ms = defaults.path.highlight_timeout_ms;
  }
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
  AMPromptProfileArgs star_profile = builtin_defaults;
  Json star_json;
  if (QueryKey(profile_root, {kDefaultPromptProfile}, &star_json) &&
      star_json.is_object()) {
    star_profile = BuildPromptProfileArgs_(star_json, builtin_defaults);
  }

  std::unordered_map<std::string, AMPromptProfileArgs> parsed;
  parsed.reserve(profile_root.size() + 1);
  parsed[kDefaultPromptProfile] = star_profile;

  for (auto it = profile_root.begin(); it != profile_root.end(); ++it) {
    if (it.key() == kDefaultPromptProfile || !it.value().is_object()) {
      continue;
    }
    parsed[it.key()] = BuildPromptProfileArgs_(it.value(), star_profile);
  }

  {
    std::lock_guard<std::mutex> lock(profile_mtx_);
    prompt_profiles_ = std::move(parsed);
    default_prompt_profile_args_ = star_profile;
    profiles_loaded_ = true;
  }
  max_history_count_ =
      std::min(std::max(1, default_prompt_profile_args_.input.max_history_count),
               150);
  return Ok();
}

/**
 * @brief Resolve prompt profile args for one nickname.
 */
const AMPromptProfileArgs &
AMProfileManager::ResolvePromptProfileArgs(const std::string &nickname) const {
  const_cast<AMProfileManager *>(this)->EnsurePromptProfilesLoaded_();
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
  history_loaded_ = true;
  Json jsond;
  if (!config_.GetJson(DocumentKind::History, &jsond) || !jsond.is_object()) {
    return;
  }
  history_map_.clear();
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
 * @brief Capture active CorePrompt profile history back into in-memory map.
 */
void AMPromptManager::CaptureActiveCoreHistory_() {
  if (active_core_nickname_.empty()) {
    return;
  }
  auto it = core_prompt_profiles_.find(active_core_nickname_);
  if (it == core_prompt_profiles_.end() || !it->second) {
    return;
  }
  if (!ic_profile_use(it->second)) {
    return;
  }
  history_map_[active_core_nickname_] = GetIsoRecords_();
}

/**
 * @brief Seed active profile history from in-memory history map.
 */
void AMPromptManager::SeedCoreHistoryFromMap_(const std::string &nickname) {
  ic_set_history(nullptr, max_history_count_);
  ic_history_clear();
  auto it = history_map_.find(nickname);
  if (it == history_map_.end()) {
    history_map_[nickname] = {};
    return;
  }
  for (const auto &cmd : it->second) {
    ic_history_add(cmd.c_str());
  }
}

/**
 * @brief Switch CorePrompt profile/history to the specified client nickname.
 */
ECM AMPromptManager::ChangeClient(const std::string &nickname) {
  const std::string target = NormalizeProfileNickname_(nickname);
  if (active_core_nickname_ == target && core_prompt_profile_) {
    (void)UseCorePromptProfileForClient_(target);
    history_loaded_ = true;
    return Ok();
  }

  if (history_loaded_ && !active_core_nickname_.empty()) {
    CaptureActiveCoreHistory_();
  }

  const bool existed = core_prompt_profiles_.find(target) !=
                       core_prompt_profiles_.end();
  if (!UseCorePromptProfileForClient_(target)) {
    return Err(EC::UnknownError,
               "failed to switch CorePrompt profile for nickname: " + target);
  }
  if (!existed) {
    SeedCoreHistoryFromMap_(target);
  }

  history_loaded_ = true;
  return Ok();
}

/**
 * @brief Flush current history back into history document.
 */
void AMPromptManager::FlushHistory() {
  if (!history_loaded_) {
    return;
  }
  CaptureActiveCoreHistory_();
  Json jsond = Json::object();
  for (const auto &pair : history_map_) {
    jsond[pair.first]["commands"] = pair.second;
  }
  config_.SetArg(DocumentKind::History, {}, jsond);
  config_.Dump(DocumentKind::History, "", true);
}
