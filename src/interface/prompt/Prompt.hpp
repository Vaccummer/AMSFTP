#pragma once
#include "application/prompt/PromptHistoryManager.hpp"
#include "application/prompt/PromptProfileManager.hpp"
#include "application/style/StyleAppService.hpp"
#include "domain/prompt/PromptDomainModel.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/string.hpp"
#include "interface/prompt/IsoclineProfile.hpp"
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

namespace AMInterface::parser {
class TokenTypeAnalyzer;
}

namespace AMInterface::prompt {
using AMApplication::prompt::PromptHistoryManager;
using AMApplication::prompt::PromptProfileManager;
using AMApplication::style::StyleConfigManager;
using AMDomain::prompt::PromptProfileSettings;

namespace kvars {
static const std::string inline_hint_key = "ic-hint";
static const std::string default_prompt_key = "ic-prompt";
static const std::string invalid_value_key = "typein_invalid_value";
static const std::string valid_value_key = "typein_valid_value";
static const std::string default_profile_name = "*";
} // namespace kvars

class IsoclineProfileManager : NonCopyableNonMovable {
public:
  IsoclineProfileManager(PromptProfileManager &profile_manager,
                         PromptHistoryManager &history_manager,
                         StyleConfigManager &style_config_manager);
  ~IsoclineProfileManager() override;

  ECM Init();
  void AddHistoryEntry(const std::string &line);
  void RemoveLastHistoryEntry();
  ECM ChangeClient(const std::string &nickname);
  [[nodiscard]] std::shared_ptr<IsoclineProfile> CurrentProfile() const;
  [[nodiscard]] std::string CurrentNickname() const;
  [[nodiscard]] PromptProfileSettings CurrentProfileArgs() const;

private:
  friend class PromptIOManager;

  [[nodiscard]] std::shared_ptr<IsoclineProfile>
  BuildProfile_(const std::string &nickname,
                const PromptProfileSettings &profile_args,
                const AMDomain::style::StyleConfigArg &style_arg,
                const std::vector<std::string> &history_records) const;
  void WriteBackCurrentProfile_();
  PromptProfileManager &profile_manager_;
  PromptHistoryManager &history_manager_;
  StyleConfigManager &style_config_manager_;
  mutable std::mutex profiles_mtx_;
  std::map<std::string, std::shared_ptr<IsoclineProfile>> profile_cache_ = {};
  std::shared_ptr<IsoclineProfile> current_profile_ = nullptr;
  std::string current_nickname_ = kvars::default_profile_name;
  PromptProfileSettings current_profile_args_ = {};
};

class PromptIOManager : NonCopyableNonMovable {
public:
  explicit PromptIOManager(IsoclineProfileManager &isocline_profile_manager)
      : isocline_profile_manager_(isocline_profile_manager) {}
  ~PromptIOManager() override = default;

  ECM Init() { return ChangeClient(kvars::default_profile_name); }

  ECM ChangeClient(const std::string &nickname) {
    return isocline_profile_manager_.ChangeClient(nickname);
  }

  void Print(const std::string &text);

  template <typename... Args> void FmtPrint(Args &&...args) {
    std::string output = AMStr::fmt(std::forward<Args>(args)...);
    Print(output);
  }

  void ErrorFormat(const std::string &error_name, const std::string &error_msg,
                   bool is_exit = false, int exit_code = 0);
  void ErrorFormat(const ECM &rcm, bool is_exit = false);
  void PrintTaskResult(
      const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info);

  void PrintRaw(const std::string &text);
  void RefreshBegin(int lines);
  void RefreshRender(const std::vector<std::optional<std::string>> &lines);
  void RefreshEnd();
  void ClearScreen(bool clear_scrollback = false);
  void UseAlternateScreen(bool enable);

  bool SecurePrompt(const std::string &prompt, std::string *out_input);
  bool PromptYesNo(const std::string &prompt, bool *canceled);
  bool Prompt(
      const std::string &prompt, const std::string &placeholder,
      std::string *out_input,
      const std::function<bool(const std::string &)> &checker = {},
      const std::vector<std::pair<std::string, std::string>> &candidates = {});
  bool LiteralPrompt(
      const std::string &prompt, const std::string &placeholder,
      std::string *out_input,
      const std::vector<std::pair<std::string, std::string>> &literals);
  /**
   * @brief Read one command line using a full rendered prompt string.
   *
   * When @p prompt contains newline separators, PromptCore prints all leading
   * lines and only passes the last line into readline as the editable prompt.
   */
  bool PromptCore(
      const std::string &prompt, std::string *out_input,
      AMInterface::parser::TokenTypeAnalyzer *token_type_analyzer = nullptr);

  ECM Edit(const std::string &nickname);
  ECM Get(const std::vector<std::string> &nicknames);
  void FlushCachedOutput();
  void SetCacheOutputOnly(bool enabled);
  [[nodiscard]] bool IsCacheOutputOnly() const;
  void SetRefreshDiffMode(bool enabled);
  [[nodiscard]] bool IsRefreshDiffMode() const;

private:
  struct IOState {
    std::mutex print_mutex_;
    std::string cached_output_;
    std::mutex cached_output_mutex_;
    std::atomic<int> cache_output_lock_depth_{0};
    std::atomic<int> refresh_occupied_lines_{0};
    std::atomic<bool> prompt_active_{false};
    std::atomic<bool> secure_phase_{false};
    std::atomic<bool> refresh_diff_mode_{true};
    std::atomic<bool> refresh_detached_mode_{false};
    std::string active_prompt_header_;
    std::atomic<bool> has_active_prompt_header_{false};
  };

  static std::string EnsureTrailingNewline_(const std::string &text);
  static bool IsAsciiText_(const std::string &text);
  static size_t CommonPrefixAscii_(const std::string &lhs,
                                   const std::string &rhs);
  static void AppendMoveUpRows_(std::string *frame, int rows);
  static void AppendClearRows_(std::string *frame, int rows);
  void AppendRowDiffUpdate_(std::string *frame, const std::string &old_line,
                            const std::string &new_line) const;
  void SetActivePromptHeader_(const std::string &header);
  void ClearActivePromptHeader_();
  [[nodiscard]] bool ShouldReplayPromptHeader_() const;
  [[nodiscard]] std::string BuildReplayFrame_(const std::string &msg);
  void PrintSyncLocked_(const std::string &text);
  void PrintInsertAndRepaintLocked_(const std::string &msg);
  void RepaintRefreshLocked_();
  void ClearRefreshLocked_();
  ECM EditProfile_(const std::string &nickname);

  IsoclineProfileManager &isocline_profile_manager_;
  IOState io_state_{};
  std::vector<std::string> refresh_lines_;
  std::vector<std::string> painted_refresh_lines_;
  int painted_refresh_rows_ = 0;
};

class AMPromptIOManager final : public PromptIOManager {
public:
  using PromptIOManager::PromptIOManager;
  ~AMPromptIOManager() override = default;
};

} // namespace AMInterface::prompt

