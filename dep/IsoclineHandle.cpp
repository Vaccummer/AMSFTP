#include "interface/prompt/IsoclineHandle.hpp"

#include <algorithm>
#include <utility>

namespace AMInterface::prompt {

IsoclineHandle::IsoclineHandle(std::string nickname)
    : nickname_(std::move(nickname)) {}

IsoclineHandle::~IsoclineHandle() {
  if (profile_ != nullptr) {
    ic_profile_free(profile_);
    profile_ = nullptr;
  }
}

bool IsoclineHandle::InitProfile() {
  if (profile_ != nullptr) {
    return true;
  }
  profile_ = CreateProfile(nickname_);
  return profile_ != nullptr;
}

bool IsoclineHandle::Use() const {
  if (profile_ == nullptr) {
    return false;
  }
  return ic_profile_use(profile_);
}

ic_profile_t *IsoclineHandle::Profile() const { return profile_; }

const std::string &IsoclineHandle::Nickname() const { return nickname_; }

void IsoclineHandle::SetNickname(std::string nickname) {
  nickname_ = std::move(nickname);
  if (profile_ != nullptr && !nickname_.empty()) {
    ic_profile_set_name(profile_, nickname_.c_str());
  }
}

const char *IsoclineHandle::ProfileName() const {
  if (profile_ == nullptr) {
    return "";
  }
  return ic_profile_get_name(profile_);
}

void IsoclineHandle::SetPromptMarker(
    const std::string &marker, const std::string &continuation_marker) const {
  ic_set_prompt_marker(marker.c_str(), continuation_marker.c_str());
}

void IsoclineHandle::EnableMultiline(bool enabled) const {
  ic_enable_multiline(enabled);
}

void IsoclineHandle::EnableHistoryDuplicates(bool enabled) const {
  ic_enable_history_duplicates(enabled);
}

void IsoclineHandle::EnableHint(bool enabled) const { ic_enable_hint(enabled); }

void IsoclineHandle::SetHintDelay(int delay_ms) const {
  ic_set_hint_delay(std::max(0, delay_ms));
}

void IsoclineHandle::SetHintSearchDelay(int delay_ms) const {
  ic_set_hint_search_delay(std::max(0, delay_ms));
}

void IsoclineHandle::SetHighlightDelay(int delay_ms) const {
  ic_set_highlight_delay(std::max(0, delay_ms));
}

void IsoclineHandle::SetHistorySearchPrompt(
    const std::string &prompt_text) const {
  ic_set_history_search_prompt(prompt_text.c_str());
}

void IsoclineHandle::DefineStyle(const std::string &name,
                                 const std::string &fmt) const {
  ic_style_def(name.c_str(), fmt.c_str());
}

void IsoclineHandle::SetHistoryLimit(int max_entries) const {
  const int clamped = std::max(1, max_entries);
  ic_set_history(nullptr, clamped);
}

void IsoclineHandle::ClearHistory() const { ic_history_clear(); }

void IsoclineHandle::AddHistoryEntry(const std::string &line) const {
  if (line.empty()) {
    return;
  }
  ic_history_add(line.c_str());
}

void IsoclineHandle::RemoveLastHistoryEntry() const {
  ic_history_remove_last();
}

std::vector<std::string> IsoclineHandle::CollectHistory() const {
  long count = ic_history_count();
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

bool IsoclineHandle::IsEditlineActive() const {
  return ic_is_editline_active();
}

bool IsoclineHandle::PrintAsync(const std::string &text) const {
  return ic_print_async(text.c_str());
}

bool IsoclineHandle::RequestRefreshAsync() const {
  return ic_request_refresh_async();
}

bool IsoclineHandle::AsyncStop() const { return ic_async_stop(); }

void IsoclineHandle::Print(const std::string &text) const {
  ic_print(text.c_str());
}

void IsoclineHandle::TermFlush() const { ic_term_flush(); }

char *IsoclineHandle::ReadlineEx(const char *prompt_text,
                                 ic_completer_fun_t *completer,
                                 void *completer_arg,
                                 ic_highlight_fun_t *highlighter,
                                 void *highlighter_arg) const {
  if (completer != nullptr || completer_arg != nullptr) {
    ic_set_default_completer(completer, completer_arg);
  }
  if (highlighter != nullptr || highlighter_arg != nullptr) {
    ic_set_default_highlighter(highlighter, highlighter_arg);
  }
  return ic_readline_ex(prompt_text, nullptr);
}

char *IsoclineHandle::ReadlineExWithInitial(const char *prompt_text,
                                            ic_completer_fun_t *completer,
                                            void *completer_arg,
                                            ic_highlight_fun_t *highlighter,
                                            void *highlighter_arg,
                                            const char *initial_text) const {
  if (completer != nullptr || completer_arg != nullptr) {
    ic_set_default_completer(completer, completer_arg);
  }
  if (highlighter != nullptr || highlighter_arg != nullptr) {
    ic_set_default_highlighter(highlighter, highlighter_arg);
  }
  return ic_readline_ex(prompt_text, initial_text);
}

void IsoclineHandle::FreeLine(char *line) const {
  if (line != nullptr) {
    ic_free(line);
  }
}

} // namespace AMInterface::prompt
