#pragma once
#include <memory>
#include <mutex>
#include <replxx.h>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace AMPromptDetail {
template <typename T> struct IsStringLike : std::false_type {};
template <> struct IsStringLike<std::string> : std::true_type {};
template <> struct IsStringLike<std::string_view> : std::true_type {};
template <> struct IsStringLike<const char *> : std::true_type {};
template <> struct IsStringLike<char *> : std::true_type {};

template <typename T>
inline constexpr bool IsStringLikeV = IsStringLike<std::decay_t<T>>::value;

inline std::string ToString(const std::string &value) { return value; }
inline std::string ToString(std::string_view value) {
  return std::string(value);
}
inline std::string ToString(const char *value) {
  return value ? std::string(value) : std::string();
}
inline std::string ToString(char *value) {
  return value ? std::string(value) : std::string();
}
} // namespace AMPromptDetail

struct TaskInfo;
class AMTokenTypeAnalyzer;
class AMConfigManager;

class AMPromptManager {
public:
  std::unique_ptr<AMTokenTypeAnalyzer> token_analyzer_;
  static AMPromptManager &Instance();

  AMPromptManager(const AMPromptManager &) = delete;
  AMPromptManager &operator=(const AMPromptManager &) = delete;
  AMPromptManager(AMPromptManager &&) = delete;
  AMPromptManager &operator=(AMPromptManager &&) = delete;
  ~AMPromptManager();
  static ReplxxActionResult esc_abort_handler(Replxx *rx, unsigned int code,
                                              void *ud) {
    (void)code;
    (void)ud;
    // 触发内置动作：abort line
    return replxx_invoke(rx, REPLXX_ACTION_ABORT_LINE, 0);
  }

  void Print(const std::vector<std::string> &items,
             const std::string &sep = " ", const std::string &end = "\n");

  template <typename... Args,
            typename std::enable_if_t<
                (AMPromptDetail::IsStringLikeV<Args> && ...), int> = 0>
  void Print(Args &&...args) {
    std::vector<std::string> items;
    items.reserve(sizeof...(Args));
    (items.emplace_back(AMPromptDetail::ToString(std::forward<Args>(args))),
     ...);
    Print(items);
  }

  template <typename... Args,
            typename std::enable_if_t<
                (AMPromptDetail::IsStringLikeV<Args> && ...), int> = 0>
  void PrintWith(const std::string &sep, const std::string &end,
                 Args &&...args) {
    std::vector<std::string> items;
    items.reserve(sizeof...(Args));
    (items.emplace_back(AMPromptDetail::ToString(std::forward<Args>(args))),
     ...);
    Print(items, sep, end);
  }

  void ErrorFormat(const std::string &error_name, const std::string &error_msg,
                   bool is_exit = false, int exit_code = 0,
                   const char *caller = "unknown");

  /** Prompt for a line of input with optional defaults. */
  bool PromptLine(const std::string &prompt, std::string *out,
                  const std::string &default_value, bool allow_empty,
                  bool *canceled, bool show_default = true);
  /** Prompt for a yes/no response. */
  bool PromptYesNo(const std::string &prompt, bool *canceled);

  /** Placeholder task result printer; format TBD. */
  void resultprint(const std::shared_ptr<TaskInfo> &task_info);
  /** Placeholder task metadata printer; format TBD. */
  void taskprint(const std::shared_ptr<TaskInfo> &task_info);

  void PrintTaskResult(const std::shared_ptr<TaskInfo> &task_info);

  bool Prompt(const std::string &prompt, const std::string &placeholder,
              std::string *out_input);
  /**
   * @brief Prompt for a command line using the core replxx handle.
   */
  bool PromptCore(const std::string &prompt, std::string *out_input);
  bool esc_pressed_ = false;

  /**
   * @brief Enable or disable history navigation for arrow keys.
   */
  void SetHistoryEnabled(bool enabled);

  /**
   * @brief Load history for a nickname into replxx core.
   */
  void LoadHistory(AMConfigManager &config_manager,
                   const std::string &nickname);

  /**
   * @brief Flush current replxx history back into ConfigManager.
   */
  void FlushHistory(AMConfigManager &config_manager);

  /**
   * @brief Add a history entry to replxx core history.
   */
  void AddHistoryEntry(const std::string &line);

private:
  AMPromptManager();
  std::mutex print_mutex_;
  Replxx *replxx_ = nullptr;
  Replxx *core_replxx_ = nullptr;
  std::string history_nickname_;
  bool history_enabled_ = true;
  bool history_loaded_ = false;
  int max_history_count_ = 10;

  /**
   * @brief Collect current replxx history into a list.
   */
  std::vector<std::string> CollectHistory_() const;

  /**
   * @brief Reset history navigation session state.
   */
  void ResetHistorySession_();

  /**
   * @brief Start a history navigation session from current input.
   */
  void StartHistorySession_();

  /**
   * @brief Apply a history entry to the replxx buffer.
   */
  void ApplyHistoryEntry_(const std::string &line);

  /**
   * @brief Normalize history to unique entries with max size.
   */
  std::vector<std::string> NormalizeHistory_(
      const std::vector<std::string> &input, int max_count) const;

  /**
   * @brief Handle the Up key for history or completion navigation.
   */
  static ReplxxActionResult HistoryUpHandler_(int code, void *ud);

  /**
   * @brief Handle the Down key for history or completion navigation.
   */
  static ReplxxActionResult HistoryDownHandler_(int code, void *ud);

  bool history_session_active_ = false;
  int history_session_index_ = -1;
  std::vector<std::string> history_session_entries_;
  std::string history_session_current_;
  std::string history_original_input_;
};

#define AM_PROMPT_ERROR(error_name, error_msg, is_exit, exit_code)             \
  AMPromptManager::Instance().ErrorFormat((error_name), (error_msg),           \
                                          (is_exit), (exit_code), __func__)
