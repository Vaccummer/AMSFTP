#pragma once
#include "AMBase/DataClass.hpp"
#include "AMBase/tools/enum_related.hpp"
#include "AMBase/tools/json.hpp"
#include "AMBase/tools/string.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "Isocline/isocline.h"
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace AMPromptDetail {} // namespace AMPromptDetail

/**
 * @brief Prompt rendering arguments for one profile.
 */
struct AMPromptPromptProfileArgs {
  std::string marker = "";
  std::string continuation_marker = ">";
  bool enable_multiline = false;
};

/**
 * @brief History arguments for one profile.
 */
struct AMPromptHistoryProfileArgs {
  bool enable = true;
  bool enable_duplicates = true;
  int max_count = 30;
};

/**
 * @brief InlineHint path arguments for one profile.
 */
struct AMPromptInlineHintPathProfileArgs {
  bool enable = true;
  bool use_async = false;
  size_t timeout_ms = 600;
};

/**
 * @brief InlineHint arguments for one profile.
 */
struct AMPromptInlineHintProfileArgs {
  bool enable = true;
  int render_delay_ms = 30;
  int search_delay_ms = 0;
  AMPromptInlineHintPathProfileArgs path{};
};

/**
 * @brief Completion searcher path arguments for one profile.
 */
struct AMPromptCompletePathProfileArgs {
  bool use_async = false;
  size_t timeout_ms = 3000;
};

/**
 * @brief Completion arguments for one profile.
 */
struct AMPromptCompleteProfileArgs {
  AMPromptCompletePathProfileArgs path{};
};

/**
 * @brief Highlight path arguments for one profile.
 */
struct AMPromptHighlightPathProfileArgs {
  bool enable = true;
  size_t timeout_ms = 1000;
};

/**
 * @brief Highlight arguments for one profile.
 */
struct AMPromptHighlightProfileArgs {
  int delay_ms = 0;
  AMPromptHighlightPathProfileArgs path{};
};

/**
 * @brief Full prompt profile argument bundle.
 */
struct AMPromptProfileArgs {
  std::string name = "*";
  bool from_default = false;
  ic_profile_t *ic_profile = nullptr;
  AMPromptPromptProfileArgs prompt{};
  AMPromptHistoryProfileArgs history{};
  AMPromptInlineHintProfileArgs inline_hint{};
  AMPromptCompleteProfileArgs complete{};
  AMPromptHighlightProfileArgs highlight{};

  /**
   * @brief Initialize this profile from JSON with fallback defaults.
   *
   * The object is reset to @p defaults first, then known keys from @p jsond
   * are read and applied.
   */
  void Init(const Json &jsond, const AMPromptProfileArgs &defaults);

  /**
   * @brief Serialize this profile to JSON with the current schema layout.
   */
  [[nodiscard]] Json GetJson() const;
};

class AMProfileManager {
public:
  /**
   * @brief Reload prompt profile args from settings.
   */
  ECM ReloadPromptProfiles();
  /**
   * @brief Interactively edit one prompt profile by nickname.
   *
   * Missing profiles are initialized from the star profile and persisted as
   * explicit entries.
   */
  ECM Edit(const std::string &nickname);

  /**
   * @brief Resolve prompt profile args for a client nickname.
   *
   * Falls back to the star profile when the nickname profile is missing.
   */
  [[nodiscard]] AMPromptProfileArgs &
  ResolvePromptProfileArgs(const std::string &nickname);
  /**
   * @brief Return current active prompt profile args.
   *
   * Returns nullptr when there is no active client profile entry.
   */
  [[nodiscard]] AMPromptProfileArgs *GetCurrentPromptProfileArgs();
  /**
   * @brief Return current active prompt profile args (const overload).
   *
   * Returns nullptr when there is no active client profile entry.
   */
  [[nodiscard]] const AMPromptProfileArgs *GetCurrentPromptProfileArgs() const;

protected:
  AMProfileManager() = default;
  virtual ~AMProfileManager();

  /**
   * @brief Collect current history into a list.
   */
  void CollectHistory_();
  /**
   * @brief Ensure runtime profile entry exists for one client.
   *
   * Missing clients are created from star profile and marked `from_default`.
   */
  AMPromptProfileArgs &
  EnsurePromptProfileForClient_(const std::string &nickname);
  /**
   * @brief Ensure the specified client has a dedicated CorePrompt profile.
   */
  ic_profile_t *EnsureCorePromptProfileForClient_(const std::string &nickname);
  /**
   * @brief Switch active isocline profile to the target client CorePrompt
   * profile.
   */
  bool UseCorePromptProfileForClient_(const std::string &nickname);

  /**
   * @brief Ensure prompt profiles are loaded.
   */
  void EnsurePromptProfilesLoaded_();

  /**
   * @brief Build profile args from one JSON object with fallback defaults.
   */
  [[nodiscard]] AMPromptProfileArgs
  BuildPromptProfileArgs_(const Json &jsond,
                          const AMPromptProfileArgs &defaults) const;

  mutable std::mutex profile_mtx_;
  bool profiles_loaded_ = false;
  AMPromptProfileArgs default_prompt_profile_args_{};
  std::unordered_map<std::string, AMPromptProfileArgs> prompt_profiles_;
  std::unordered_map<std::string, std::vector<std::string>> history_map_;
  std::unordered_set<std::string> history_seeded_clients_;
  std::string active_core_nickname_ = "local";
  ic_profile_t *core_prompt_profile_ = nullptr;
};

class AMProfileCLI : public AMProfileManager {
public:
  /**
   * @brief Edit one host prompt profile for CLI usage.
   *
   * The nickname must exist in HostManager.
   */
  ECM Edit(const std::string &nickname);

  /**
   * @brief Query prompt profile JSON for one or more host nicknames.
   *
   * Every nickname must exist in HostManager.
   */
  ECM Get(const std::vector<std::string> &nicknames);

protected:
  AMProfileCLI() = default;
  ~AMProfileCLI() override = default;
};

class AMPromptManager : public AMProfileCLI, NonCopyableNonMovable {
public:
  inline static AMPromptManager &Instance() {
    static AMPromptManager instance;
    return instance;
  }

  ~AMPromptManager() override = default;

  ECM Init() override {
    CollectHistory_();
    InitIsoclineConfig();
    return Ok();
  }

  void Print(const std::string &text);

  template <typename... Args> void FmtPrint(Args &&...args) {
    std::string output = AMStr::fmt(std::forward<Args>(args)...);
    Print(output); // Print now recieve a single string, no sep or end needed
  }

  void ErrorFormat(const std::string &error_name, const std::string &error_msg,
                   bool is_exit = false, int exit_code = 0);

  void ErrorFormat(const std::pair<ErrorCode, std::string> &rcm,
                   bool is_exit = false);

  /** Prompt for a yes/no response. */
  bool PromptYesNo(const std::string &prompt, bool *canceled);

  /**
   * @brief Prompt for sensitive input with masked characters.
   */
  bool SecurePrompt(const std::string &prompt, std::string *out_input);

  void PrintTaskResult(const std::shared_ptr<TaskInfo> &task_info);

  /**
   * @brief Flush cached output collected while progress bars are active.
   */
  void FlushCachedOutput();

  /**
   * @brief Adjust print-cache lock depth.
   *
   * enabled=true  -> lock depth +1
   * enabled=false -> lock depth -1 (clamped at 0)
   */
  void SetCacheOutputOnly(bool enabled);

  /**
   * @brief Return whether Print currently caches output only.
   */
  [[nodiscard]] bool IsCacheOutputOnly() const;

  /**
   * @brief Print output immediately, bypassing cache checks.
   */
  void PrintRaw(const std::string &text, bool append_newline = true);

  /**
   * @brief Clear the terminal screen (optionally full reset).
   */
  void ClearScreen(bool clear_scrollback = false);

  /**
   * @brief Enter/leave the alternate screen buffer.
   */
  void UseAlternateScreen(bool enable);

  /**
   * @brief Prompt for one value with optional checker and completion source.
   *
   * checker: validates current input for query-mode highlighting.
   * candidates: query-mode completion source.
   */
  bool Prompt(const std::string &prompt, const std::string &placeholder,
              std::string *out_input,
              const std::function<bool(const std::string &)> &checker = {},
              const std::vector<std::string> &candidates = {});
  /**
   * @brief Prompt for one literal value using a literal->help dictionary.
   *
   * The same literal map is used for:
   * - validation/highlight (valid when input matches one literal key)
   * - completion source (insert key, show help from value)
   */
  bool LiteralPrompt(const std::string &prompt, const std::string &placeholder,
                     std::string *out_input,
                     const std::map<std::string, std::string> &literals);
  /**
   * @brief Flush current history back into ConfigManager.
   */
  void FlushHistory();
  /**
   * @brief Enable or disable history for the current active client.
   */
  void SetHistoryEnabled(bool enabled);
  /**
   * @brief Add a history entry to the current active client.
   */
  void AddHistoryEntry(const std::string &line);
  /**
   * @brief Switch CorePrompt profile/history to the specified client nickname.
   */
  ECM ChangeClient(const std::string &nickname);
  /**
   * @brief Prompt for a command line using the shared readline handle.
   */
  bool PromptCore(const std::string &prompt, std::string *out_input);

private:
  void InitIsoclineConfig();
  std::mutex print_mutex_;
  std::string cached_output_;
  std::mutex cached_output_mutex_;
  std::atomic<int> cache_output_lock_depth_{0};
};

class AMPrintLockGuard : NonCopyableNonMovable {
public:
  explicit AMPrintLockGuard() : prompt_(AMPromptManager::Instance()) {
    prompt_.SetCacheOutputOnly(true);
  }

  ~AMPrintLockGuard() override { prompt_.SetCacheOutputOnly(false); }

private:
  AMPromptManager &prompt_;
};

struct AMPromptHookGuard {
  explicit AMPromptHookGuard() {
    AMCliSignalMonitor::Instance().SilenceHook("GLOBAL");
    AMCliSignalMonitor::Instance().ResumeHook("PROMPT");
  }
  ~AMPromptHookGuard() {
    AMCliSignalMonitor::Instance().ResumeHook("GLOBAL");
    AMCliSignalMonitor::Instance().SilenceHook("PROMPT");
  }
};

inline AMPrintLockGuard PrintLock() { return AMPrintLockGuard(); }
inline AMPromptHookGuard HookLock() { return AMPromptHookGuard(); }
