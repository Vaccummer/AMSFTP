#include "interface/prompt/Prompt.hpp"
#include <string>
#include <vector>

namespace AMInterface::prompt {

namespace {
inline constexpr const char *kDefaultPromptProfile = "*";

[[maybe_unused]] void
PrintPromptProfile_(PromptIOManager &prompt, const std::string &name,
                    const AMDomain::prompt::PromptProfileSettings &profile) {
  prompt.FmtPrint("\\[{}]", name);
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

IsoclineProfileManager::IsoclineProfileManager(
    AMApplication::prompt::PromptProfileManager &profile_manager,
    AMApplication::prompt::PromptHistoryManager &history_manager,
    AMApplication::style::StyleConfigManager &style_config_manager)
    : profile_manager_(profile_manager), history_manager_(history_manager),
      style_config_manager_(style_config_manager) {}

IsoclineProfileManager::~IsoclineProfileManager() = default;

std::shared_ptr<IsoclineProfile> IsoclineProfileManager::BuildProfile_(
    const std::string &nickname, const PromptProfileSettings &profile_args,
    const AMDomain::style::StyleConfigArg &style_arg,
    const std::vector<std::string> &history_records) const {
  auto profile = std::make_shared<IsoclineProfile>(nickname, profile_args,
                                                   style_arg, history_records);
  if (!profile || !profile->IsValid()) {
    return nullptr;
  }
  return profile;
}

void IsoclineProfileManager::WriteBackCurrentProfile_() {
  std::shared_ptr<IsoclineProfile> profile;
  std::string nickname;
  {
    std::lock_guard<std::mutex> lock(profiles_mtx_);
    profile = current_profile_;
    nickname = current_nickname_;
  }
  if (!profile || !profile->IsValid() || nickname.empty()) {
    return;
  }

  auto profile_arg = profile_manager_.GetInitArg();
  (void)history_manager_.SetZoneHistory(nickname, profile->CollectHistory());
}

ECM IsoclineProfileManager::Init() {
  return ChangeClient(kDefaultPromptProfile);
}

std::shared_ptr<IsoclineProfile>
IsoclineProfileManager::CurrentProfile() const {
  std::lock_guard<std::mutex> lock(profiles_mtx_);
  if (current_profile_ && current_profile_->IsValid()) {
    return current_profile_;
  }
  auto it = profile_cache_.find(kvars::default_profile_name);
  if (it != profile_cache_.end() && it->second && it->second->IsValid()) {
    return it->second;
  }

  auto *self = const_cast<IsoclineProfileManager *>(this);
  const AMDomain::style::StyleConfigArg style_arg =
      style_config_manager_.GetStyleRef().lock().load();
  PromptProfileSettings profile_args =
      profile_manager_.GetZoneProfile(kvars::default_profile_name).profile;
  std::vector<std::string> history_records = {};
  auto history_result =
      history_manager_.GetZoneHistory(kvars::default_profile_name);
  if (history_result) {
    history_records = history_result.data.history;
  }

  auto fallback = self->BuildProfile_(kvars::default_profile_name, profile_args,
                                      style_arg, history_records);
  if (!fallback || !fallback->IsValid()) {
    return nullptr;
  }

  self->profile_cache_[kvars::default_profile_name] = fallback;
  self->current_profile_ = fallback;
  self->current_nickname_ = kvars::default_profile_name;
  self->current_profile_args_ = profile_args;
  return fallback;
}

std::string IsoclineProfileManager::CurrentNickname() const {
  std::lock_guard<std::mutex> lock(profiles_mtx_);
  return current_nickname_.empty() ? kvars::default_profile_name
                                   : current_nickname_;
}

PromptProfileSettings IsoclineProfileManager::CurrentProfileArgs() const {
  std::lock_guard<std::mutex> lock(profiles_mtx_);
  return current_profile_args_;
}

void IsoclineProfileManager::AddHistoryEntry(const std::string &line) {
  if (line.empty()) {
    return;
  }
  if (!CurrentProfileArgs().history.enable) {
    return;
  }
  auto profile = CurrentProfile();
  if (!profile) {
    return;
  }
  (void)profile->AddHistoryEntry(line);
}

void IsoclineProfileManager::RemoveLastHistoryEntry() {
  auto profile = CurrentProfile();
  if (!profile) {
    return;
  }
  (void)profile->RemoveLastHistoryEntry();
}

void IsoclineProfileManager::SyncCurrentHistory() {
  WriteBackCurrentProfile_();
}

ECM IsoclineProfileManager::ChangeClient(const std::string &nickname) {
  const AMDomain::style::StyleConfigArg style_arg =
      style_config_manager_.GetStyleRef().lock().load();

  WriteBackCurrentProfile_();

  std::string active_nickname = nickname;
  PromptProfileSettings profile_args =
      profile_manager_.GetZoneProfile(active_nickname).profile;
  std::vector<std::string> history_records = {};
  auto history_result = history_manager_.GetZoneHistory(active_nickname);
  if (history_result) {
    history_records = history_result.data.history;
  }

  std::shared_ptr<IsoclineProfile> profile =
      BuildProfile_(active_nickname, profile_args, style_arg, history_records);

  if (!profile || !profile->IsValid() || !profile->Use()) {
    active_nickname = kvars::default_profile_name;
    profile_args = profile_manager_.GetZoneProfile(active_nickname).profile;
    history_records.clear();
    history_result = history_manager_.GetZoneHistory(active_nickname);
    if (history_result) {
      history_records = history_result.data.history;
    }

    profile = BuildProfile_(active_nickname, profile_args, style_arg,
                            history_records);
    if (!profile || !profile->IsValid() || !profile->Use()) {
      return Err(EC::UnknownError, "", "",
                 "failed to switch isocline profile for nickname: " +
                     active_nickname);
    }
  }

  {
    std::lock_guard<std::mutex> lock(profiles_mtx_);
    profile_cache_[active_nickname] = profile;
    current_profile_ = profile;
    current_nickname_ = active_nickname;
    current_profile_args_ = profile_args;
  }
  return OK;
}

/*
ECM PromptIOManager::EditProfile_(const std::string &nickname) {
  const std::string target = NormalizeProfileNickname_(nickname);
  if (target.empty()) {
    return Err(EC::InvalidArg, "", "", "empty profile nickname");
  }

  AMDomain::prompt::PromptProfileSettings working =
      NormalizePromptProfileSettings_(
          isocline_profile_manager_.profile_manager_.GetZoneProfile(target)
              .profile);
  const AMDomain::prompt::PromptProfileSettings builtin_defaults{};

  auto prompt_string = [this](const std::string &label, std::string *value) {
    if (!value) {
      return false;
    }
    std::string out;
    if (!Prompt(label, *value, &out)) {
      return false;
    }
    *value = out;
    return true;
  };

  const std::vector<std::pair<std::string, std::string>> bool_literals = {
      {"true", "enable"}, {"false", "disable"}};
  auto prompt_bool = [this, &bool_literals](const std::string &label,
                                            bool *value) {
    if (!value) {
      return false;
    }
    while (true) {
      std::string out;
      const std::string placeholder = (*value ? "true" : "false");
      if (!LiteralPrompt(label, placeholder, &out, bool_literals)) {
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
      ErrorFormat(ECM{EC::InvalidArg, "value must be true or false"});
    }
  };

  auto prompt_int64 = [this](const std::string &label, int64_t min_value,
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
      if (!Prompt(label, placeholder, &out, checker)) {
        return false;
      }
      out = AMStr::Strip(out);
      if (out.empty()) {
        out = placeholder;
      }
      int64_t parsed = *value;
      if (!TryParseInt64_(out, &parsed)) {
        ErrorFormat(ECM{EC::InvalidArg, "invalid integer value"});
        continue;
      }
      if (parsed < min_value || parsed > max_value) {
        ErrorFormat(
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
    return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
  }
  if (!prompt_bool("Prompt.enable_multiline(true/false): ",
                   &working.prompt.enable_multiline) ||
      !prompt_bool("History.enable(true/false): ", &working.history.enable)) {
    return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
  }

  if (working.history.enable) {
    if (!prompt_bool("History.enable_duplicates(true/false): ",
                     &working.history.enable_duplicates)) {
      return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
    }
    int64_t history_max = static_cast<int64_t>(working.history.max_count);
    if (!prompt_int64("History.max_count: ", 1, 200, &history_max)) {
      return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
    }
    working.history.max_count = static_cast<int>(history_max);
  } else {
    working.history.enable_duplicates =
        builtin_defaults.history.enable_duplicates;
    working.history.max_count = builtin_defaults.history.max_count;
  }

  if (!prompt_bool("InlineHint.enable(true/false): ",
                   &working.inline_hint.enable)) {
    return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
  }
  if (working.inline_hint.enable) {
    int64_t inline_delay =
        static_cast<int64_t>(working.inline_hint.render_delay_ms);
    if (!prompt_int64("InlineHint.render_delay_ms: ", 0, 5000, &inline_delay)) {
      return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
    }
    working.inline_hint.render_delay_ms = static_cast<int>(inline_delay);

    int64_t inline_search_delay =
        static_cast<int64_t>(working.inline_hint.search_delay_ms);
    if (!prompt_int64("InlineHint.search_delay_ms: ", 0, 5000,
                      &inline_search_delay)) {
      return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
    }
    working.inline_hint.search_delay_ms = static_cast<int>(inline_search_delay);

    if (!prompt_bool("InlineHint.Path.enable(true/false): ",
                     &working.inline_hint.path.enable)) {
      return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
    }
    if (working.inline_hint.path.enable) {
      if (!prompt_bool("InlineHint.Path.use_async(true/false): ",
                       &working.inline_hint.path.use_async)) {
        return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
      }
      if (working.inline_hint.path.use_async) {
        int64_t timeout =
            static_cast<int64_t>(working.inline_hint.path.timeout_ms);
        if (!prompt_int64("InlineHint.Path.timeout_ms: ", 1, 300000,
                          &timeout)) {
          return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
        }
        working.inline_hint.path.timeout_ms = static_cast<size_t>(timeout);
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
    return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
  }
  if (working.complete.path.use_async) {
    int64_t timeout = static_cast<int64_t>(working.complete.path.timeout_ms);
    if (!prompt_int64("Complete.Searcher.Path.timeout_ms: ", 1, 300000,
                      &timeout)) {
      return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
    }
    working.complete.path.timeout_ms = static_cast<size_t>(timeout);
  } else {
    working.complete.path.timeout_ms =
        builtin_defaults.complete.path.timeout_ms;
  }

  int64_t highlight_delay = static_cast<int64_t>(working.highlight.delay_ms);
  if (!prompt_int64("Highlight.delay_ms: ", 0, 5000, &highlight_delay) ||
      !prompt_bool("Highlight.Path.enable(true/false): ",
                   &working.highlight.path.enable)) {
    return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
  }
  working.highlight.delay_ms = static_cast<int>(highlight_delay);
  if (working.highlight.path.enable) {
    int64_t timeout = static_cast<int64_t>(working.highlight.path.timeout_ms);
    if (!prompt_int64("Highlight.Path.timeout_ms: ", 1, 300000, &timeout)) {
      return Err(EC::ConfigCanceled, "", "", "profile edit canceled");
    }
    working.highlight.path.timeout_ms = static_cast<size_t>(timeout);
  } else {
    working.highlight.path.timeout_ms =
        builtin_defaults.highlight.path.timeout_ms;
  }

  AMDomain::prompt::PromptProfileArg profile_document = {};
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Read(
      &profile_document);
  profile_document.set[target] = working;

  if (!AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Write(
          profile_document)) {
    return Err(EC::CommonFailure, "", "", "failed to update PromptProfile");
  }
  ECM dump_rcm =
      AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Dump(
          AMDomain::config::DocumentKind::Settings, "", true);
  if (!(dump_rcm)) {
    return dump_rcm;
  }

  ECM reload_rcm = ReloadPromptProfilesFromConfig_(
      isocline_profile_manager_.profile_manager_);
  if (!(reload_rcm)) {
    return reload_rcm;
  }
  const std::string current_nickname =
      isocline_profile_manager_.CurrentNickname();
  if (!current_nickname.empty()) {
    (void)isocline_profile_manager_.ChangeClient(current_nickname);
  }
  return OK;
}

ECM PromptIOManager::Edit(const std::string &nickname) {
  const std::string target = NormalizeProfileNickname_(nickname);
  if (target.empty()) {
    return Err(EC::InvalidArg, "", "", "empty profile nickname");
  }
  if (target == kDefaultPromptProfile) {
    return Err(EC::InvalidArg, "", "", "profile nickname must be a host
nickname");
  }
  if (!AMInterface::ApplicationAdapters::Runtime::HostConfigManagerOrThrow()
           .HostExists(target)) {
    return Err(EC::HostConfigNotFound, "", "", AMStr::fmt("host nickname not
found: {}", target));
  }
  return EditProfile_(target);
}

ECM PromptIOManager::Get(const std::vector<std::string> &nicknames) {
  if (nicknames.empty()) {
    return Err(EC::InvalidArg, "", "", "profile get requires at least one
nickname");
  }

  bool first = true;
  for (const auto &name : nicknames) {
    const std::string target = NormalizeProfileNickname_(name);
    if (target.empty()) {
      return Err(EC::InvalidArg, "", "", "empty profile nickname");
    }
    if (target == kDefaultPromptProfile) {
      return Err(EC::InvalidArg, "", "", "profile nickname must be a host
nickname");
    }
    if (!AMInterface::ApplicationAdapters::Runtime::HostConfigManagerOrThrow()
             .HostExists(target)) {
      return Err(EC::HostConfigNotFound, "", "", AMStr::fmt("host nickname not
found: {}", target));
    }

    if (!first) {
      Print("");
    }
    first = false;
    PrintPromptProfile_(
        *this, target,
        NormalizePromptProfileSettings_(
            isocline_profile_manager_.profile_manager_.GetZoneProfile(target)
                .profile));
  }
  return OK;
}
*/
} // namespace AMInterface::prompt
