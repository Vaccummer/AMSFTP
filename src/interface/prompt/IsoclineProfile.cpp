#include "interface/prompt/IsoclineProfile.hpp"
#include <algorithm>
#include <utility>

namespace AMInterface::prompt {
namespace {
inline constexpr const char *kDefaultPromptStyleKey = "ic-prompt";
inline constexpr const char *kValidValueStyleKey = "typein_valid_value";
inline constexpr const char *kInvalidValueStyleKey = "typein_invalid_value";
inline constexpr const char *kInlineHintStyleKey = "ic-hint";

class ScopedProfileUse {
public:
  explicit ScopedProfileUse(ic_profile_t *target)
      : previous_(ic_profile_current()),
        switched_(target != nullptr && ic_profile_use(target)) {}

  ~ScopedProfileUse() {
    if (switched_) {
      ic_profile_use(previous_);
    }
  }

  [[nodiscard]] bool Switched() const { return switched_; }

private:
  ic_profile_t *previous_ = nullptr;
  bool switched_ = false;
};

void ApplyProfileInitData_(
    IsoclineProfile *profile,
    const AMDomain::prompt::PromptProfileSettings &profile_args,
    const AMDomain::style::StyleConfigArg &style_arg,
    const std::vector<std::string> &history_records) {
  if (!profile || !profile->IsValid()) {
    return;
  }
  (void)profile->SetPromptMarker(profile_args.prompt.marker,
                                 profile_args.prompt.continuation_marker);
  (void)profile->EnableMultiline(profile_args.prompt.enable_multiline);
  (void)profile->EnableHistoryDuplicates(
      profile_args.history.enable_duplicates);
  (void)profile->EnableHint(profile_args.inline_hint.enable);
  (void)profile->SetHintDelay(profile_args.inline_hint.render_delay_ms);
  (void)profile->SetHintSearchDelay(profile_args.inline_hint.search_delay_ms);
  (void)profile->SetHighlightDelay(profile_args.highlight.delay_ms);

  (void)profile->SetHistorySearchPrompt(
      style_arg.style.cli_prompt.prompt_template.history_search_prompt);
  (void)profile->DefineStyle(
      kDefaultPromptStyleKey,
      style_arg.style.value_query_highlight.prompt_style);
  (void)profile->DefineStyle(kValidValueStyleKey,
                             style_arg.style.value_query_highlight.valid_value);
  (void)profile->DefineStyle(
      kInvalidValueStyleKey,
      style_arg.style.value_query_highlight.invalid_value);
  (void)profile->DefineStyle(kInlineHintStyleKey,
                             style_arg.style.internal_style.inline_hint);

  const int max_history =
      std::min(std::max(1, profile_args.history.max_count), 200);
  (void)profile->SetHistoryLimit(max_history);
  (void)profile->ClearHistory();
  if (profile_args.history.enable) {
    for (const auto &entry : history_records) {
      (void)profile->AddHistoryEntry(entry);
    }
  }
}

} // namespace

IsoclineProfile::IsoclineProfile(
    std::string nickname, AMDomain::prompt::PromptProfileSettings profile_args,
    const AMDomain::style::StyleConfigArg &style_arg,
    const std::vector<std::string> &history_records)
    : nickname_(std::move(nickname)), profile_args_(std::move(profile_args)) {
  if (!EnsureCreated(nickname_)) {
    return;
  }
  ApplyProfileInitData_(this, profile_args_, style_arg, history_records);
}

IsoclineProfile::IsoclineProfile(const std::string &name) {
  nickname_ = name;
  if (!name.empty()) {
    (void)EnsureCreated(name);
  }
}

IsoclineProfile::~IsoclineProfile() {
  if (owned_ && profile_ != nullptr) {
    ic_profile_free(profile_);
    profile_ = nullptr;
  }
}

IsoclineProfile::IsoclineProfile(IsoclineProfile &&other) noexcept
    : nickname_(std::move(other.nickname_)),
      profile_args_(std::move(other.profile_args_)), profile_(other.profile_),
      owned_(other.owned_) {
  other.profile_ = nullptr;
  other.owned_ = false;
}

IsoclineProfile &IsoclineProfile::operator=(IsoclineProfile &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  Reset();
  nickname_ = std::move(other.nickname_);
  profile_args_ = std::move(other.profile_args_);
  profile_ = other.profile_;
  owned_ = other.owned_;
  other.nickname_.clear();
  other.profile_args_ = {};
  other.profile_ = nullptr;
  other.owned_ = false;
  return *this;
}

IsoclineProfile::ScopedCompleterGuard::ScopedCompleterGuard(
    ic_profile_t *profile, ic_completer_fun_t *origin_completer,
    void *origin_data, bool armed)
    : profile_(profile), origin_completer_(origin_completer),
      origin_data_(origin_data), reseted_(!armed || profile == nullptr) {}

void IsoclineProfile::ScopedCompleterGuard::reset() {
  if (reseted_ || profile_ == nullptr) {
    return;
  }
  (void)ic_set_default_completer_p(profile_, origin_completer_, origin_data_);
  reseted_ = true;
}

IsoclineProfile::ScopedCompleterGuard::~ScopedCompleterGuard() { reset(); }

IsoclineProfile::ScopedCompleterGuard::ScopedCompleterGuard(
    ScopedCompleterGuard &&other) noexcept
    : profile_(other.profile_), origin_completer_(other.origin_completer_),
      origin_data_(other.origin_data_), reseted_(other.reseted_) {
  other.profile_ = nullptr;
  other.origin_completer_ = nullptr;
  other.origin_data_ = nullptr;
  other.reseted_ = true;
}

IsoclineProfile::ScopedCompleterGuard &
IsoclineProfile::ScopedCompleterGuard::operator=(
    ScopedCompleterGuard &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  reset();
  profile_ = other.profile_;
  origin_completer_ = other.origin_completer_;
  origin_data_ = other.origin_data_;
  reseted_ = other.reseted_;
  other.profile_ = nullptr;
  other.origin_completer_ = nullptr;
  other.origin_data_ = nullptr;
  other.reseted_ = true;
  return *this;
}

IsoclineProfile::ScopedHighlighterGuard::ScopedHighlighterGuard(
    ic_profile_t *profile, ic_highlight_fun_t *origin_highlighter,
    void *origin_data, bool armed)
    : profile_(profile), origin_highlighter_(origin_highlighter),
      origin_data_(origin_data), reseted_(!armed || profile == nullptr) {}

void IsoclineProfile::ScopedHighlighterGuard::reset() {
  if (reseted_ || profile_ == nullptr) {
    return;
  }
  ic_set_default_highlighter_p(profile_, origin_highlighter_, origin_data_);
  reseted_ = true;
}

IsoclineProfile::ScopedHighlighterGuard::~ScopedHighlighterGuard() { reset(); }

IsoclineProfile::ScopedHighlighterGuard::ScopedHighlighterGuard(
    ScopedHighlighterGuard &&other) noexcept
    : profile_(other.profile_), origin_highlighter_(other.origin_highlighter_),
      origin_data_(other.origin_data_), reseted_(other.reseted_) {
  other.profile_ = nullptr;
  other.origin_highlighter_ = nullptr;
  other.origin_data_ = nullptr;
  other.reseted_ = true;
}

IsoclineProfile::ScopedHighlighterGuard &
IsoclineProfile::ScopedHighlighterGuard::operator=(
    ScopedHighlighterGuard &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  reset();
  profile_ = other.profile_;
  origin_highlighter_ = other.origin_highlighter_;
  origin_data_ = other.origin_data_;
  reseted_ = other.reseted_;
  other.profile_ = nullptr;
  other.origin_highlighter_ = nullptr;
  other.origin_data_ = nullptr;
  other.reseted_ = true;
  return *this;
}

ic_profile_t *IsoclineProfile::GlobalCurrentProfile() {
  return ic_profile_current();
}

bool IsoclineProfile::UseGlobalCurrentProfile(ic_profile_t *profile) {
  return ic_profile_use(profile);
}

bool IsoclineProfile::EnsureCreated(const std::string &name) {
  if (!name.empty()) {
    nickname_ = name;
  }
  if (profile_ != nullptr) {
    if (!nickname_.empty()) {
      ic_profile_set_name(profile_, nickname_.c_str());
    }
    return true;
  }
  profile_ = ic_profile_new();
  owned_ = (profile_ != nullptr);
  if (profile_ != nullptr && !nickname_.empty()) {
    ic_profile_set_name(profile_, nickname_.c_str());
  }
  return profile_ != nullptr;
}

void IsoclineProfile::Reset(ic_profile_t *profile, bool owned) {
  if (profile == profile_) {
    owned_ = (profile_ != nullptr && owned);
    return;
  }
  if (owned_ && profile_ != nullptr) {
    ic_profile_free(profile_);
  }
  profile_ = profile;
  owned_ = (profile_ != nullptr && owned);
}

void IsoclineProfile::ReleaseOwnership() { owned_ = false; }

ic_profile_t *IsoclineProfile::NativeProfile() const { return profile_; }

bool IsoclineProfile::IsValid() const { return profile_ != nullptr; }

bool IsoclineProfile::IsOwned() const { return owned_; }

bool IsoclineProfile::Use() const {
  if (profile_ == nullptr) {
    return false;
  }
  return ic_profile_use(profile_);
}

bool IsoclineProfile::SetName(const std::string &name) {
  nickname_ = name;
  if (profile_ == nullptr) {
    return false;
  }
  ic_profile_set_name(profile_, name.c_str());
  return true;
}

const char *IsoclineProfile::Name() const {
  if (profile_ != nullptr) {
    return ic_profile_get_name(profile_);
  }
  return nickname_.c_str();
}

const std::string &IsoclineProfile::Nickname() const { return nickname_; }

bool IsoclineProfile::SetPromptMarker(
    const std::string &marker, const std::string &continuation_marker) const {
  if (profile_ == nullptr) {
    return false;
  }
  ic_set_prompt_marker_p(profile_, marker.c_str(), continuation_marker.c_str());
  profile_args_.prompt.marker = marker;
  profile_args_.prompt.continuation_marker = continuation_marker;
  return true;
}

bool IsoclineProfile::EnableMultiline(bool enabled) const {
  if (profile_ == nullptr) {
    return false;
  }
  (void)ic_enable_multiline_p(profile_, enabled);
  profile_args_.prompt.enable_multiline = enabled;
  return true;
}

bool IsoclineProfile::EnableHistoryDuplicates(bool enabled) const {
  if (profile_ == nullptr) {
    return false;
  }
  (void)ic_enable_history_duplicates_p(profile_, enabled);
  profile_args_.history.enable_duplicates = enabled;
  return true;
}

bool IsoclineProfile::EnableHint(bool enabled) const {
  if (profile_ == nullptr) {
    return false;
  }
  (void)ic_enable_hint_p(profile_, enabled);
  profile_args_.inline_hint.enable = enabled;
  return true;
}

bool IsoclineProfile::SetHintDelay(int delay_ms) const {
  if (profile_ == nullptr) {
    return false;
  }
  const int clamped = std::max(0, delay_ms);
  (void)ic_set_hint_delay_p(profile_, clamped);
  profile_args_.inline_hint.render_delay_ms = clamped;
  return true;
}

bool IsoclineProfile::SetHintSearchDelay(int delay_ms) const {
  if (profile_ == nullptr) {
    return false;
  }
  const int clamped = std::max(0, delay_ms);
  (void)ic_set_hint_search_delay_p(profile_, clamped);
  profile_args_.inline_hint.search_delay_ms = clamped;
  return true;
}

bool IsoclineProfile::SetHighlightDelay(int delay_ms) const {
  if (profile_ == nullptr) {
    return false;
  }
  const int clamped = std::max(0, delay_ms);
  (void)ic_set_highlight_delay_p(profile_, clamped);
  profile_args_.highlight.delay_ms = clamped;
  return true;
}

bool IsoclineProfile::SetHistorySearchPrompt(
    const std::string &prompt_text) const {
  if (profile_ == nullptr) {
    return false;
  }
  ic_set_history_search_prompt_p(profile_, prompt_text.c_str());
  return true;
}

bool IsoclineProfile::DefineStyle(const std::string &name,
                                  const std::string &fmt) const {
  if (profile_ == nullptr) {
    return false;
  }
  ic_style_def_p(profile_, name.c_str(), fmt.c_str());
  return true;
}

bool IsoclineProfile::SetHistoryLimit(int max_entries) const {
  if (profile_ == nullptr) {
    return false;
  }
  const int clamped = std::max(1, max_entries);
  ic_set_history_p(profile_, nullptr, clamped);
  profile_args_.history.max_count = clamped;
  return true;
}

bool IsoclineProfile::ClearHistory() const {
  if (profile_ == nullptr) {
    return false;
  }
  ic_history_clear_p(profile_);
  return true;
}

bool IsoclineProfile::AddHistoryEntry(const std::string &line) const {
  if (profile_ == nullptr || line.empty()) {
    return false;
  }
  ic_history_add_p(profile_, line.c_str());
  return true;
}

bool IsoclineProfile::RemoveLastHistoryEntry() const {
  if (profile_ == nullptr) {
    return false;
  }
  ic_history_remove_last_p(profile_);
  return true;
}

std::vector<std::string> IsoclineProfile::CollectHistory() const {
  if (profile_ == nullptr) {
    return {};
  }
  ScopedProfileUse guard(profile_);
  if (!guard.Switched()) {
    return {};
  }
  const long count = ic_history_count();
  if (count <= 0) {
    return {};
  }
  std::vector<std::string> records;
  records.reserve(static_cast<size_t>(count));
  for (long i = 0; i < count; ++i) {
    const char *entry = ic_history_get(i);
    if (entry != nullptr) {
      records.emplace_back(entry);
    }
  }
  return records;
}

IsoclineProfile::ScopedCompleterGuard IsoclineProfile::TemporarySetCompleter(
    const std::optional<ic_completer_fun_t *> &callback,
    const std::optional<void *> &data) {
  if (!callback.has_value() && !data.has_value()) {
    return {};
  }
  if (!EnsureCreated()) {
    return {};
  }
  ic_completer_fun_t *origin_callback = nullptr;
  void *origin_data = nullptr;
  if (!ic_get_default_completer_p(profile_, &origin_callback, &origin_data)) {
    return {};
  }
  ic_completer_fun_t *target_callback =
      callback.has_value() ? callback.value() : origin_callback;
  void *target_data = data.has_value() ? data.value() : origin_data;
  if (!ic_set_default_completer_p(profile_, target_callback, target_data)) {
    return {};
  }
  return {profile_, origin_callback, origin_data, true};
}

IsoclineProfile::ScopedHighlighterGuard
IsoclineProfile::TemporarySetHighlighter(
    const std::optional<ic_highlight_fun_t *> &callback,
    const std::optional<void *> &data) {
  if (!callback.has_value() && !data.has_value()) {
    return {};
  }
  if (!EnsureCreated()) {
    return {};
  }
  ic_highlight_fun_t *origin_callback = nullptr;
  void *origin_data = nullptr;
  if (!ic_get_default_highlighter_p(profile_, &origin_callback, &origin_data)) {
    return {};
  }
  ic_highlight_fun_t *target_callback =
      callback.has_value() ? callback.value() : origin_callback;
  void *target_data = data.has_value() ? data.value() : origin_data;
  ic_set_default_highlighter_p(profile_, target_callback, target_data);
  return {profile_, origin_callback, origin_data, true};
}

} // namespace AMInterface::prompt
