#pragma once

#include "Isocline/isocline.h"
#include "foundation/core/DataClass.hpp"
#include <string>
#include <vector>

namespace AMInterface::prompt {

class IsoclineHandle : NonCopyableNonMovable {
public:
  explicit IsoclineHandle(std::string nickname = "");
  ~IsoclineHandle() override;
  static ic_profile_t *GlobalGetProfile();
  static bool GlobalSetProfile(ic_profile_t *profile);
  static ic_profile_t *CreateProfile(const std::string &nickname = "");

  [[nodiscard]] bool InitProfile();
  [[nodiscard]] bool Use() const;
  [[nodiscard]] ic_profile_t *Profile() const;
  [[nodiscard]] const std::string &Nickname() const;
  void SetNickname(std::string nickname);
  [[nodiscard]] const char *ProfileName() const;

  void SetPromptMarker(const std::string &marker,
                       const std::string &continuation_marker) const;
  void EnableMultiline(bool enabled) const;
  void EnableHistoryDuplicates(bool enabled) const;
  void EnableHint(bool enabled) const;
  void SetHintDelay(int delay_ms) const;
  void SetHintSearchDelay(int delay_ms) const;
  void SetHighlightDelay(int delay_ms) const;
  void SetHistorySearchPrompt(const std::string &prompt_text) const;
  void DefineStyle(const std::string &name, const std::string &fmt) const;

  void SetHistoryLimit(int max_entries) const;
  void ClearHistory() const;
  void AddHistoryEntry(const std::string &line) const;
  void RemoveLastHistoryEntry() const;
  [[nodiscard]] std::vector<std::string> CollectHistory() const;

  [[nodiscard]] bool IsEditlineActive() const;
  [[nodiscard]] bool PrintAsync(const std::string &text) const;
  [[nodiscard]] bool RequestRefreshAsync() const;
  [[nodiscard]] bool AsyncStop() const;
  void Print(const std::string &text) const;
  void TermFlush() const;

  char *ReadlineEx(const char *prompt_text, ic_completer_fun_t *completer,
                   void *completer_arg, ic_highlight_fun_t *highlighter,
                   void *highlighter_arg) const;
  char *
  ReadlineExWithInitial(const char *prompt_text, ic_completer_fun_t *completer,
                        void *completer_arg, ic_highlight_fun_t *highlighter,
                        void *highlighter_arg, const char *initial_text) const;
  void FreeLine(char *line) const;

private:
  std::string nickname_;
  ic_profile_t *profile_ = nullptr;
};

inline ic_profile_t *IsoclineHandle::GlobalGetProfile() {
  return ic_profile_current();
}

inline bool IsoclineHandle::GlobalSetProfile(ic_profile_t *profile) {
  return ic_profile_use(profile);
}

inline ic_profile_t *
IsoclineHandle::CreateProfile(const std::string &nickname) {
  ic_profile_t *profile = ic_profile_new();
  if (profile != nullptr && !nickname.empty()) {
    ic_profile_set_name(profile, nickname.c_str());
  }
  return profile;
}

} // namespace AMInterface::prompt
