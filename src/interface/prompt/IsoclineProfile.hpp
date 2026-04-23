#pragma once

#include "Isocline/isocline.h"
#include "domain/prompt/PromptDomainModel.hpp"
#include "domain/style/StyleDomainModel.hpp"
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::prompt {

class IsoclineProfile {
public:
  IsoclineProfile(std::string nickname,
                  AMDomain::prompt::PromptProfileSettings profile_args,
                  const AMDomain::style::StyleConfigArg &style_arg,
                  const std::vector<std::string> &history_records = {});
  explicit IsoclineProfile(const std::string &name = "");
  ~IsoclineProfile();

  IsoclineProfile(IsoclineProfile &&other) noexcept;
  IsoclineProfile &operator=(IsoclineProfile &&other) noexcept;
  IsoclineProfile &operator=(const IsoclineProfile &) = delete;
  IsoclineProfile(const IsoclineProfile &) = delete;

  class ScopedCompleterGuard {
  public:
    ScopedCompleterGuard() = default;
    ScopedCompleterGuard(ic_profile_t *profile,
                         ic_completer_fun_t *origin_completer,
                         void *origin_data, bool armed);
    ~ScopedCompleterGuard();
    ScopedCompleterGuard(ScopedCompleterGuard &&other) noexcept;
    ScopedCompleterGuard &operator=(ScopedCompleterGuard &&other) noexcept;
    ScopedCompleterGuard(const ScopedCompleterGuard &) = delete;
    ScopedCompleterGuard &operator=(const ScopedCompleterGuard &) = delete;
    void reset();

  private:
    ic_profile_t *profile_ = nullptr;
    ic_completer_fun_t *origin_completer_ = nullptr;
    void *origin_data_ = nullptr;
    bool reseted_ = true;
  };

  class ScopedHighlighterGuard {
  public:
    ScopedHighlighterGuard() = default;
    ScopedHighlighterGuard(ic_profile_t *profile,
                           ic_highlight_fun_t *origin_highlighter,
                           void *origin_data, bool armed);
    ~ScopedHighlighterGuard();
    ScopedHighlighterGuard(ScopedHighlighterGuard &&other) noexcept;
    ScopedHighlighterGuard &operator=(ScopedHighlighterGuard &&other) noexcept;
    ScopedHighlighterGuard(const ScopedHighlighterGuard &) = delete;
    ScopedHighlighterGuard &operator=(const ScopedHighlighterGuard &) = delete;
    void reset();

  private:
    ic_profile_t *profile_ = nullptr;
    ic_highlight_fun_t *origin_highlighter_ = nullptr;
    void *origin_data_ = nullptr;
    bool reseted_ = true;
  };

  static ic_profile_t *GlobalCurrentProfile();
  static bool UseGlobalCurrentProfile(ic_profile_t *profile);

  bool EnsureCreated(const std::string &name = "");
  void Reset(ic_profile_t *profile = nullptr, bool owned = false);
  void ReleaseOwnership();

  [[nodiscard]] ic_profile_t *NativeProfile() const;
  [[nodiscard]] bool IsValid() const;
  [[nodiscard]] bool IsOwned() const;
  [[nodiscard]] bool Use() const;

  bool SetName(const std::string &name);
  [[nodiscard]] const char *Name() const;
  [[nodiscard]] const std::string &Nickname() const;

  bool SetPromptMarker(const std::string &marker,
                       const std::string &continuation_marker) const;
  bool EnableMultiline(bool enabled) const;
  bool EnableHistoryDuplicates(bool enabled) const;
  bool EnableHint(bool enabled) const;
  bool SetHintDelay(int delay_ms) const;
  bool SetHintSearchDelay(int delay_ms) const;
  bool SetHighlightDelay(int delay_ms) const;
  bool SetHistorySearchPrompt(const std::string &prompt_text) const;
  bool DefineStyle(const std::string &name, const std::string &fmt) const;

  bool SetHistoryLimit(int max_entries) const;
  bool ClearHistory() const;
  bool AddHistoryEntry(const std::string &line) const;
  bool RemoveLastHistoryEntry() const;
  bool RemoveLastHistoryEntryIfEquals(const std::string &line) const;
  [[nodiscard]] std::vector<std::string> CollectHistory() const;
  bool SetCompleter(ic_completer_fun_t *callback, void *data = nullptr) const;
  bool SetHighlighter(ic_highlight_fun_t *callback, void *data = nullptr) const;

  [[nodiscard]] ScopedCompleterGuard TemporarySetCompleter(
      const std::optional<ic_completer_fun_t *> &callback = std::nullopt,
      const std::optional<void *> &data = std::nullopt);
  [[nodiscard]] ScopedHighlighterGuard TemporarySetHighlighter(
      const std::optional<ic_highlight_fun_t *> &callback = std::nullopt,
      const std::optional<void *> &data = std::nullopt);

private:
  std::string nickname_ = "";
  mutable AMDomain::prompt::PromptProfileSettings profile_args_ = {};
  ic_profile_t *profile_ = nullptr;
  bool owned_ = false;
};

} // namespace AMInterface::prompt
