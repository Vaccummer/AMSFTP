#include "Isocline/isocline.h"
#include "interface/adapters/ApplicationAdapters.hpp"
#include "domain/config/ConfigModel.hpp"
#include "application/config/ConfigPayloads.hpp"
#include <sstream>
#include "domain/host/HostManager.hpp"
#include "interface/prompt/Prompt.hpp"
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
const AMApplication::config::PromptProfileSettings *
FindDefaultProfileSettings_(
    const AMApplication::config::PromptProfileDocument &profile_document) {
  auto direct = profile_document.profiles.find(kDefaultPromptProfile);
  if (direct != profile_document.profiles.end()) {
    return &direct->second;
  }

  for (const auto &[raw_key, settings] : profile_document.profiles) {
    if (NormalizeProfileKey_(raw_key) == kDefaultPromptProfile) {
      return &settings;
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


bool TryParseBool_(const std::string &text, bool *out) {
  if (!out) {
    return false;
  }
  const std::string normalized = AMStr::lowercase(AMStr::Strip(text));
  if (normalized == "true" || normalized == "1" || normalized == "yes" ||
      normalized == "y") {
    *out = true;
    return true;
  }
  if (normalized == "false" || normalized == "0" || normalized == "no" ||
      normalized == "n") {
    *out = false;
    return true;
  }
  return false;
}

bool TryParseInt64_(const std::string &text, int64_t *out) {
  if (!out) {
    return false;
  }
  const std::string trimmed = AMStr::Strip(text);
  if (trimmed.empty()) {
    return false;
  }
  try {
    size_t parsed_size = 0;
    const long long value = std::stoll(trimmed, &parsed_size, 10);
    if (parsed_size != trimmed.size()) {
      return false;
    }
    *out = static_cast<int64_t>(value);
    return true;
  } catch (...) {
    return false;
  }
}

void PrintPromptProfile_(const std::string &name, const AMPromptProfileArgs &profile) {
  AMPromptManager &prompt = AMPromptManager::Instance();
  prompt.FmtPrint("[{}]", name);
  prompt.FmtPrint("Prompt.marker: {}", profile.prompt.marker);
  prompt.FmtPrint("Prompt.continuation_marker: {}",
                  profile.prompt.continuation_marker);
  prompt.FmtPrint("Prompt.enable_multiline: {}",
                  profile.prompt.enable_multiline ? "true" : "false");
  prompt.FmtPrint("History.enable: {}",
                  profile.history.enable ? "true" : "false");
  prompt.FmtPrint("History.enable_duplicates: {}",
                  profile.history.enable_duplicates ? "true" : "false");
  prompt.FmtPrint("History.max_count: {}", profile.history.max_count);
  prompt.FmtPrint("InlineHint.enable: {}",
                  profile.inline_hint.enable ? "true" : "false");
  prompt.FmtPrint("InlineHint.render_delay_ms: {}",
                  profile.inline_hint.render_delay_ms);
  prompt.FmtPrint("InlineHint.search_delay_ms: {}",
                  profile.inline_hint.search_delay_ms);
  prompt.FmtPrint("InlineHint.Path.enable: {}",
                  profile.inline_hint.path.enable ? "true" : "false");
  prompt.FmtPrint("InlineHint.Path.use_async: {}",
                  profile.inline_hint.path.use_async ? "true" : "false");
  prompt.FmtPrint("InlineHint.Path.timeout_ms: {}",
                  profile.inline_hint.path.timeout_ms);
  prompt.FmtPrint("Complete.Searcher.Path.use_async: {}",
                  profile.complete.path.use_async ? "true" : "false");
  prompt.FmtPrint("Complete.Searcher.Path.timeout_ms: {}",
                  profile.complete.path.timeout_ms);
  prompt.FmtPrint("Highlight.delay_ms: {}", profile.highlight.delay_ms);
  prompt.FmtPrint("Highlight.Path.enable: {}",
                  profile.highlight.path.enable ? "true" : "false");
  prompt.FmtPrint("Highlight.Path.timeout_ms: {}",
                  profile.highlight.path.timeout_ms);
}
} // namespace

/**
 * @brief Initialize prompt profile args from typed settings with fallback defaults.
 */
void AMPromptProfileArgs::Init(
    const AMApplication::config::PromptProfileSettings &settings,
    const AMPromptProfileArgs &defaults) {
  *this = defaults;
  prompt.marker = settings.prompt.marker;
  prompt.continuation_marker = settings.prompt.continuation_marker;
  prompt.enable_multiline = settings.prompt.enable_multiline;

  history.enable = settings.history.enable;
  history.enable_duplicates = settings.history.enable_duplicates;
  history.max_count = settings.history.max_count;

  inline_hint.enable = settings.inline_hint.enable;
  inline_hint.render_delay_ms = settings.inline_hint.render_delay_ms;
  inline_hint.search_delay_ms = settings.inline_hint.search_delay_ms;
  inline_hint.path.enable = settings.inline_hint.path.enable;
  inline_hint.path.use_async = settings.inline_hint.path.use_async;
  inline_hint.path.timeout_ms = settings.inline_hint.path.timeout_ms;

  complete.path.use_async = settings.complete.path.use_async;
  complete.path.timeout_ms = settings.complete.path.timeout_ms;

  highlight.delay_ms = settings.highlight.delay_ms;
  highlight.path.enable = settings.highlight.path.enable;
  highlight.path.timeout_ms = settings.highlight.path.timeout_ms;

  history.max_count = std::min(std::max(1, history.max_count), 200);
  inline_hint.render_delay_ms = std::max(0, inline_hint.render_delay_ms);
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
 * @brief Convert prompt profile args into one typed config payload.
 */
AMApplication::config::PromptProfileSettings AMPromptProfileArgs::ToSettings() const {
  AMApplication::config::PromptProfileSettings out{};
  out.prompt.marker = prompt.marker;
  out.prompt.continuation_marker = prompt.continuation_marker;
  out.prompt.enable_multiline = prompt.enable_multiline;

  out.history.enable = history.enable;
  out.history.enable_duplicates = history.enable_duplicates;
  out.history.max_count = history.max_count;

  out.inline_hint.enable = inline_hint.enable;
  out.inline_hint.render_delay_ms = inline_hint.render_delay_ms;
  out.inline_hint.search_delay_ms = inline_hint.search_delay_ms;
  out.inline_hint.path.enable = inline_hint.path.enable;
  out.inline_hint.path.use_async = inline_hint.path.use_async;
  out.inline_hint.path.timeout_ms = inline_hint.path.timeout_ms;

  out.complete.path.use_async = complete.path.use_async;
  out.complete.path.timeout_ms = complete.path.timeout_ms;

  out.highlight.delay_ms = highlight.delay_ms;
  out.highlight.path.enable = highlight.path.enable;
  out.highlight.path.timeout_ms = highlight.path.timeout_ms;
  return out;
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
 * @brief Build profile args from one typed settings object with fallback defaults.
 */
AMPromptProfileArgs AMProfileManager::BuildPromptProfileArgs_(
    const AMApplication::config::PromptProfileSettings &settings,
    const AMPromptProfileArgs &defaults) const {
  AMPromptProfileArgs out{};
  out.Init(settings, defaults);
  return out;
}

/**
 * @brief Reload prompt profile args from settings.
 */
ECM AMProfileManager::ReloadPromptProfiles() {
  AMApplication::config::PromptProfileDocument profile_document = {};
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Read(
      &profile_document);

  AMPromptProfileArgs builtin_defaults{};
  builtin_defaults.name = kDefaultPromptProfile;
  builtin_defaults.from_default = false;
  builtin_defaults.ic_profile = nullptr;
  AMPromptProfileArgs star_profile = builtin_defaults;
  const auto *default_settings = FindDefaultProfileSettings_(profile_document);
  if (default_settings) {
    star_profile = BuildPromptProfileArgs_(*default_settings, builtin_defaults);
  }
  star_profile.name = kDefaultPromptProfile;
  star_profile.from_default = false;
  star_profile.ic_profile = nullptr;

  std::unordered_map<std::string, AMPromptProfileArgs> parsed;
  parsed.reserve(profile_document.profiles.size() + 1);
  parsed[kDefaultPromptProfile] = star_profile;

  for (const auto &[raw_key, settings] : profile_document.profiles) {
    const std::string key = NormalizeProfileKey_(raw_key);
    if (key.empty() || key == kDefaultPromptProfile) {
      continue;
    }
    AMPromptProfileArgs item = BuildPromptProfileArgs_(settings, star_profile);
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
    prompt.FmtPrint("{}\n",
                    AMInterface::ApplicationAdapters::Runtime::Format("Input Abort", "abort"));
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
      if (TryParseBool_(out, &parsed)) {
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
        if (!TryParseInt64_(trimmed, &parsed)) {
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
      if (!TryParseInt64_(out, &parsed)) {
        prompt.ErrorFormat(ECM{EC::InvalidArg, "invalid integer value"});
        continue;
      }
      if (parsed < min_value || parsed > max_value) {
        prompt.ErrorFormat(
            ECM{EC::InvalidArg, AMStr::fmt("value out of range [{}, {}]",
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
    working.history.enable_duplicates =
        builtin_defaults.history.enable_duplicates;
    working.history.max_count = builtin_defaults.history.max_count;
  }

  if (!prompt_bool("InlineHint.enable(true/false): ",
                   &working.inline_hint.enable)) {
    print_abort();
    return Err(EC::ConfigCanceled, "profile edit canceled");
  }

  if (working.inline_hint.enable) {
    int64_t inline_delay =
        static_cast<int64_t>(working.inline_hint.render_delay_ms);
    if (!prompt_int64("InlineHint.render_delay_ms: ", 0, 5000, &inline_delay)) {
      print_abort();
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    working.inline_hint.render_delay_ms = static_cast<int>(inline_delay);

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
    working.inline_hint.render_delay_ms =
        builtin_defaults.inline_hint.render_delay_ms;
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
    working.complete.path.timeout_ms =
        builtin_defaults.complete.path.timeout_ms;
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
    const auto release_runtime_profile = [this](AMPromptProfileArgs &profile) {
      if (profile.ic_profile) {
        if (profile.ic_profile == core_prompt_profile_) {
          core_prompt_profile_ = nullptr;
        }
        ic_profile_free(profile.ic_profile);
        profile.ic_profile = nullptr;
      }
      history_seeded_clients_.erase(profile.name);
    };

    auto existing = prompt_profiles_.find(target);
    if (existing != prompt_profiles_.end()) {
      release_runtime_profile(existing->second);
    }
    working.ic_profile = nullptr;
    prompt_profiles_[target] = working;
    history_seeded_clients_.erase(target);

    if (target == kDefaultPromptProfile) {
      default_prompt_profile_args_ = working;
      default_prompt_profile_args_.name = kDefaultPromptProfile;
      default_prompt_profile_args_.from_default = false;
      default_prompt_profile_args_.ic_profile = nullptr;

      for (auto &pair : prompt_profiles_) {
        if (pair.first == kDefaultPromptProfile || !pair.second.from_default) {
          continue;
        }
        const std::string profile_name = pair.second.name;
        release_runtime_profile(pair.second);
        pair.second = working;
        pair.second.name = profile_name;
        pair.second.from_default = true;
        pair.second.ic_profile = nullptr;
      }
    }
  }

  AMApplication::config::PromptProfileDocument profile_document = {};
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Read(
      &profile_document);
  profile_document.profiles[target] = working.ToSettings();
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Write(
          profile_document)) {
    return Err(EC::CommonFailure, "failed to update PromptProfile");
  }
  ECM dump_rcm =
      AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Dump(AMDomain::config::DocumentKind::Settings, "", true);
  if (dump_rcm.first != EC::Success) {
    return dump_rcm;
  }

  if (target != kDefaultPromptProfile) {
    (void)EnsureCorePromptProfileForClient_(target);
  }
  if (!active_core_nickname_.empty()) {
    (void)UseCorePromptProfileForClient_(active_core_nickname_);
  }
  return Ok();
}

/**
 * @brief Edit one host prompt profile for CLI usage.
 */
ECM AMProfileCLI::Edit(const std::string &nickname) {
  const std::string target = NormalizeProfileNickname_(nickname);
  if (target.empty()) {
    return Err(EC::InvalidArg, "empty profile nickname");
  }
  if (target == kDefaultPromptProfile) {
    return Err(EC::InvalidArg, "profile nickname must be a host nickname");
  }
  if (!AMInterface::ApplicationAdapters::Runtime::HostConfigManagerOrThrow().HostExists(target)) {
    return Err(EC::HostConfigNotFound,
               AMStr::fmt("host nickname not found: {}", target));
  }
  return AMProfileManager::Edit(target);
}

/**
 * @brief Query prompt profile settings for one or more host nicknames.
 */
ECM AMProfileCLI::Get(const std::vector<std::string> &nicknames) {
  if (nicknames.empty()) {
    return Err(EC::InvalidArg, "profile get requires at least one nickname");
  }

  std::vector<std::string> targets;
  targets.reserve(nicknames.size());
  for (const auto &name : nicknames) {
    const std::string target = NormalizeProfileNickname_(name);
    if (target.empty()) {
      return Err(EC::InvalidArg, "empty profile nickname");
    }
    if (target == kDefaultPromptProfile) {
      return Err(EC::InvalidArg, "profile nickname must be a host nickname");
    }
    if (!AMInterface::ApplicationAdapters::Runtime::HostConfigManagerOrThrow().HostExists(target)) {
      return Err(EC::HostConfigNotFound,
                 AMStr::fmt("host nickname not found: {}", target));
    }
    targets.push_back(target);
  }

  EnsurePromptProfilesLoaded_();
  bool first = true;
  {
    std::lock_guard<std::mutex> lock(profile_mtx_);
    for (const auto &target : targets) {
      const AMPromptProfileArgs *profile = nullptr;
      auto it = prompt_profiles_.find(target);
      if (it != prompt_profiles_.end()) {
        profile = &it->second;
      } else {
        auto star_it = prompt_profiles_.find(kDefaultPromptProfile);
        if (star_it != prompt_profiles_.end()) {
          profile = &star_it->second;
        } else {
          profile = &default_prompt_profile_args_;
        }
      }
      if (!first) {
        AMPromptManager::Instance().Print("");
      }
      first = false;
      PrintPromptProfile_(target, *profile);
    }
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
const AMPromptProfileArgs *
AMProfileManager::GetCurrentPromptProfileArgs() const {
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
  AMApplication::config::PromptHistoryDocument history_document = {};
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Read(
          &history_document)) {
    return;
  }
  history_map_.clear();
  for (const auto &[name, commands] : history_document.commands_by_profile) {
    history_map_[name] = commands;
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
  const int max_history =
      std::min(std::max(1, profile->history.max_count), 200);
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

  AMApplication::config::PromptHistoryDocument history_document = {};
  history_document.commands_by_profile.clear();
  for (const auto &[name, commands] : history_map_) {
    history_document.commands_by_profile[name] = commands;
  }
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Write(
      history_document);
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Dump(
      AMDomain::config::DocumentKind::History, "", true);
}





