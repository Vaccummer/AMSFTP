#pragma once
#include "domain/transfer/TransferDomainModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/string.hpp"
#include "interface/prompt/IsoclineProfileManager.hpp"

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

namespace AMInterface::prompt {
class PromptIOManager : NonCopyableNonMovable {
public:
  struct PromptReadOptions {
    std::optional<ic_completer_fun_t *> completer;
    std::optional<void *> completer_data;
    std::optional<ic_highlight_fun_t *> highlighter;
    std::optional<void *> highlighter_data;

    PromptReadOptions(
        std::optional<ic_completer_fun_t *> completer = std::nullopt,
        std::optional<void *> completer_data = std::nullopt,
        std::optional<ic_highlight_fun_t *> highlighter = std::nullopt,
        std::optional<void *> highlighter_data = std::nullopt)
        : completer(completer), completer_data(completer_data),
          highlighter(highlighter), highlighter_data(highlighter_data) {}
  };

  explicit PromptIOManager(IsoclineProfileManager &isocline_profile_manager)
      : isocline_profile_manager_(isocline_profile_manager) {}
  ~PromptIOManager() override = default;

  ECM Init() { return ChangeClient(kvars::default_profile_name); }

  ECM ChangeClient(const std::string &nickname) {
    return isocline_profile_manager_.ChangeClient(nickname);
  }

  void Print(const std::string &text);

  /**
   * @brief Print text via isocline without loading/changing any prompt profile.
   *
   * This is intended for bootstrap and non-interactive paths where
   * PromptIOManager instances may not be initialized yet.
   */
  static void StaticPrint(const std::string &text, bool ensure_newline = true);

  void PrintOperationAbort();

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
  void RefreshBegin();
  void RefreshRender(const std::vector<std::optional<std::string>> &lines);
  void RefreshEnd();
  void ClearScreen(bool clear_scrollback = false);
  void UseAlternateScreen(bool enable);
  void SetCursorVisible(bool visible);
  void SyncCurrentHistory();

  std::optional<std::string> SecurePrompt(const std::string &prompt);
  bool PromptYesNo(const std::string &prompt, bool *canceled);

  std::optional<std::string> Prompt(
      const std::string &prompt, const std::string &placeholder = "",
      const std::function<bool(const std::string &)> &checker = {},
      const std::vector<std::pair<std::string, std::string>> &candidates = {},
      const PromptReadOptions &options = {});

  std::optional<std::string> LiteralPrompt(
      const std::string &prompt, const std::string &placeholder,
      const std::vector<std::pair<std::string, std::string>> &literals);
  /**
   * @brief Read one command line using a full rendered prompt string.
   *
   * When @p prompt contains newline separators, PromptCore prints all leading
   * lines and only passes the last line into readline as the editable prompt.
   */
  std::optional<std::string> PromptCore(const std::string &prompt);
  void FlushCachedOutput();
  void SetCacheOutputOnly(bool enabled);
  [[nodiscard]] bool IsCacheOutputOnly() const;

private:
  struct IOState {
    std::mutex print_mutex_;
    std::string cached_output_;
    std::mutex cached_output_mutex_;
    std::atomic<int> cache_output_lock_depth_{0};
    std::atomic<int> refresh_occupied_lines_{0};
    std::atomic<bool> prompt_active_{false};
    std::atomic<bool> secure_phase_{false};
    std::atomic<bool> refresh_detached_mode_{false};
    std::string active_prompt_header_;
    std::atomic<bool> has_active_prompt_header_{false};
    std::mutex typein_result_mutex_;
    std::string last_typein_result_;
    std::string last_typein_nickname_;
    bool has_last_typein_result_ = false;
  };

  void ResetRefreshStateLocked_();
  void AssignRefreshRowsFromRenderInputLocked_(
      const std::vector<std::optional<std::string>> &lines);
  void SetActivePromptHeader_(const std::string &header);
  void ClearActivePromptHeader_();
  [[nodiscard]] bool ShouldReplayPromptHeader_() const;
  [[nodiscard]] std::string BuildReplayFrame_(const std::string &msg);
  [[nodiscard]] bool TryCacheOutput_(const std::string &text);
  void EmitOutput_(const std::string &text, bool allow_cache = true);
  void PrintSyncLocked_(const std::string &text);
  void PrintSyncRefreshLocked_(const std::string &text);
  void PrintInsertAndRepaintLocked_(const std::string &msg);
  void RepaintRefreshLocked_();
  void ClearRefreshLocked_();

  struct RefreshRuntimeState {
    bool active = false;
    int rows_painted = 0;
    std::vector<std::string> logical_lines = {};
  };

  IsoclineProfileManager &isocline_profile_manager_;
  IOState io_state_{};
  RefreshRuntimeState refresh_state_{};
};

} // namespace AMInterface::prompt
