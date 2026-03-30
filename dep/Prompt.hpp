#pragma once
#include "Isocline/isocline.h"
#include "application/config/ConfigPayloads.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>


#include <unordered_map>
#include <unordered_set>
#include <vector>

/**
 * @brief Full prompt profile argument bundle.
 */
struct AMPromptProfileArgs {
  /** Prompt rendering arguments for one profile. */
  struct Prompt {
    std::string marker = "";
    std::string continuation_marker = ">";
    bool enable_multiline = false;
  };

  /** History arguments for one profile. */
  struct History {
    bool enable = true;
    bool enable_duplicates = true;
    int max_count = 30;
  };

  /** InlineHint arguments for one profile. */
  struct InlineHint {
    /** InlineHint path arguments for one profile. */
    struct Path {
      bool enable = true;
      bool use_async = false;
      size_t timeout_ms = 600;
    };

    bool enable = true;
    int render_delay_ms = 30;
    int search_delay_ms = 0;
    Path path{};
  };

  /** Completion arguments for one profile. */
  struct Complete {
    /** Completion searcher path arguments for one profile. */
    struct Path {
      bool use_async = false;
      size_t timeout_ms = 3000;
    };

    Path path{};
  };

  /** Highlight arguments for one profile. */
  struct Highlight {
    /** Highlight path arguments for one profile. */
    struct Path {
      bool enable = true;
      size_t timeout_ms = 1000;
    };

    int delay_ms = 0;
    Path path{};
  };

  std::string name = "*";
  bool from_default = false;
  ic_profile_t *ic_profile = nullptr;
  Prompt prompt{};
  History history{};
  InlineHint inline_hint{};
  Complete complete{};
  Highlight highlight{};

  /**
   * @brief Initialize this profile from typed settings with fallback defaults.
   */
  void Init(const AMApplication::config::PromptProfileSettings &settings,
            const AMPromptProfileArgs &defaults);

  /**
   * @brief Convert this runtime profile into one typed config payload.
   */
  [[nodiscard]] AMApplication::config::PromptProfileSettings ToSettings() const;
};

class AMPromptProfileHistoryManager : NonCopyableNonMovable {
public:
  AMPromptProfileHistoryManager() = default;
  ~AMPromptProfileHistoryManager() override;

  ECM Init();
  /**
   * @brief Reload prompt profile args from settings.
   */
  ECM ReloadPromptProfiles();

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
   * @brief Flush current history back into ConfigManager.
   */
  void FlushHistory();

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
   * @brief Return currently active core profile pointer.
   */
  [[nodiscard]] ic_profile_t *CurrentCorePromptProfile() const {
    return core_prompt_profile_;
  }

private:
  friend class AMPromptProfileAdmin;
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
   * @brief Build profile args from one typed settings object with fallback
   * defaults.
   */
  [[nodiscard]] AMPromptProfileArgs BuildPromptProfileArgs_(
      const AMApplication::config::PromptProfileSettings &settings,
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

class AMPromptIOManager;

class AMPromptProfileAdmin : NonCopyableNonMovable {
public:
  AMPromptProfileAdmin(AMPromptProfileHistoryManager &profile_history_manager,
                       AMPromptIOManager &prompt_io_manager)
      : profile_history_manager_(profile_history_manager),
        prompt_io_manager_(prompt_io_manager) {}
  ~AMPromptProfileAdmin() override = default;

  /**
   * @brief Edit one host prompt profile for CLI usage.
   *
   * The nickname must exist in HostManager.
   */
  ECM Edit(const std::string &nickname);

  /**
   * @brief Query prompt profile settings for one or more host nicknames.
   *
   * Every nickname must exist in HostManager.
   */
  ECM Get(const std::vector<std::string> &nicknames);

private:
  ECM EditProfile_(const std::string &nickname);
  AMPromptProfileHistoryManager &profile_history_manager_;
  AMPromptIOManager &prompt_io_manager_;
};

class AMPromptIOManager : NonCopyableNonMovable {
public:
  explicit AMPromptIOManager(
      AMPromptProfileHistoryManager &profile_history_manager)
      : profile_history_manager_(profile_history_manager) {}

  ~AMPromptIOManager() override = default;

  ECM Init();

  void Print(const std::string &text);

  template <typename... Args> void FmtPrint(Args &&...args) {
    std::string output = AMStr::fmt(std::forward<Args>(args)...);
    Print(output); // Print now recieve a single string, no sep or end needed
  }

  void ErrorFormat(const std::string &error_name, const std::string &error_msg,
                   bool is_exit = false, int exit_code = 0);

  void ErrorFormat(const ECM &rcm, bool is_exit = false);

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
   * @brief Prompt for a command line using the shared readline handle.
   */
  bool PromptCore(const std::string &prompt, std::string *out_input);

private:
  void InitIsoclineConfig();
  AMPromptProfileHistoryManager &profile_history_manager_;
  std::mutex print_mutex_;
  std::string cached_output_;
  std::mutex cached_output_mutex_;
  std::atomic<int> cache_output_lock_depth_{0};
};

class AMPrintLockGuard : NonCopyableNonMovable {
public:
  static AMPrintLockGuard Lock(AMPromptIOManager &prompt) {
    return AMPrintLockGuard(prompt);
  }

  explicit AMPrintLockGuard(AMPromptIOManager &prompt) : prompt_(prompt) {
    prompt_.SetCacheOutputOnly(true);
  }

  ~AMPrintLockGuard() override { prompt_.SetCacheOutputOnly(false); }

private:
  AMPromptIOManager &prompt_;
};

struct AMPromptHookGuard {
  /**
   * @brief Silence global hooks and enable prompt-scope hook handlers.
   */
  AMPromptHookGuard();
  /**
   * @brief Restore global hook state and silence prompt-scope handlers.
   */
  ~AMPromptHookGuard();
  /**
   * @brief Return a scoped prompt hook guard.
   */
  static AMPromptHookGuard Lock() { return AMPromptHookGuard(); }
};
