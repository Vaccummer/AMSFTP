#include "interface/prompt/IsoclineProfileManager.hpp"
#include <string>
#include <vector>

namespace AMInterface::prompt {

IsoclineProfileManager::IsoclineProfileManager(
    AMApplication::prompt::PromptProfileManager &profile_manager,
    AMApplication::prompt::PromptHistoryManager &history_manager,
    AMApplication::style::StyleConfigManager &style_config_manager)
    : profile_manager_(profile_manager), history_manager_(history_manager),
      style_config_manager_(style_config_manager) {}

IsoclineProfileManager::~IsoclineProfileManager() = default;

void IsoclineProfileManager::ApplyDefaultBindings_(
    const std::shared_ptr<IsoclineProfile> &profile) const {
  if (!profile || !profile->IsValid()) {
    return;
  }
  DefaultReadlineBindings bindings = {};
  {
    std::lock_guard<std::mutex> lock(bindings_mtx_);
    bindings = default_bindings_;
  }
  (void)profile->SetCompleter(bindings.completer, bindings.completer_data);
  (void)profile->SetHighlighter(bindings.highlighter, bindings.highlighter_data);
}

std::shared_ptr<IsoclineProfile> IsoclineProfileManager::BuildProfile_(
    const std::string &nickname, const PromptProfileSettings &profile_args,
    const AMDomain::style::StyleConfigArg &style_arg,
    const std::vector<std::string> &history_records) const {
  auto profile = std::make_shared<IsoclineProfile>(nickname, profile_args,
                                                   style_arg, history_records);
  if (!profile || !profile->IsValid()) {
    return nullptr;
  }
  ApplyDefaultBindings_(profile);
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
  return ChangeClient(kvars::default_profile_name);
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

std::string IsoclineProfileManager::AbortStyle() const {
  return style_config_manager_.GetInitArg().style.common.type_abort;
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

void IsoclineProfileManager::SetDefaultCompleter(ic_completer_fun_t *callback,
                                                 void *data) {
  {
    std::lock_guard<std::mutex> lock(bindings_mtx_);
    default_bindings_.completer = callback;
    default_bindings_.completer_data = data;
  }

  std::vector<std::shared_ptr<IsoclineProfile>> profiles = {};
  {
    std::lock_guard<std::mutex> lock(profiles_mtx_);
    profiles.reserve(profile_cache_.size());
    for (const auto &[_, profile] : profile_cache_) {
      if (profile) {
        profiles.push_back(profile);
      }
    }
  }
  for (const auto &profile : profiles) {
    (void)profile->SetCompleter(callback, data);
  }
}

void IsoclineProfileManager::SetDefaultHighlighter(ic_highlight_fun_t *callback,
                                                   void *data) {
  {
    std::lock_guard<std::mutex> lock(bindings_mtx_);
    default_bindings_.highlighter = callback;
    default_bindings_.highlighter_data = data;
  }

  std::vector<std::shared_ptr<IsoclineProfile>> profiles = {};
  {
    std::lock_guard<std::mutex> lock(profiles_mtx_);
    profiles.reserve(profile_cache_.size());
    for (const auto &[_, profile] : profile_cache_) {
      if (profile) {
        profiles.push_back(profile);
      }
    }
  }
  for (const auto &profile : profiles) {
    (void)profile->SetHighlighter(callback, data);
  }
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

} // namespace AMInterface::prompt
