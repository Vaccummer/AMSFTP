#pragma once
#include "AMBase/DataClass.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace AMPromptDetail {
template <typename T> struct IsStringLike : std::false_type {};
template <> struct IsStringLike<std::string> : std::true_type {};
template <> struct IsStringLike<std::string_view> : std::true_type {};
template <> struct IsStringLike<const char *> : std::true_type {};
template <> struct IsStringLike<char *> : std::true_type {};

template <typename T>
inline constexpr bool IsStringLikeV = IsStringLike<std::decay_t<T>>::value;

template <typename T> std::string ToString(T &&value) {
  if constexpr (IsStringLikeV<T>) {
    return std::string(std::forward<T>(value));
  } else {
    static_assert(IsStringLikeV<T>,
                  "AMPromptManager::Print only accepts string-like arguments");
    return {};
  }
}

} // namespace AMPromptDetail

class AMHistoryManager {
public:
  /**
   * @brief Enable or disable history navigation for arrow keys.
   */
  void SetHistoryEnabled(bool enabled);

  /**
   * @brief Flush current history back into ConfigManager.
   */
  void FlushHistory();

  /**
   * @brief Add a history entry to the readline history.
   */
  void AddHistoryEntry(const std::string &line);

  /**
   * @brief Load history data from .AMSFTP_History.toml into memory.
   */
  ECM LoadHistory(const std::string &nickname);

protected:
  AMHistoryManager() = default;
  ~AMHistoryManager() = default;

  /**
   * @brief Collect current history into a list.
   */
  void CollectHistory_();

  AMConfigManager &config_ = AMConfigManager::Instance();
  std::unordered_map<std::string, std::vector<std::string>> history_map_;
  std::string history_nickname_;
  bool history_enabled_ = true;
  bool history_loaded_ = false;
  int max_history_count_ = 10;
};

class AMPromptManager : public AMHistoryManager, NonCopyableNonMovable {
public:
  static AMPromptManager &Instance() {
    static AMPromptManager instance;
    return instance;
  }

  ~AMPromptManager() override = default;

  ECM Init() override {
    InitIsoclineConfig();
    CollectHistory_();
    return Ok();
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
                   bool is_exit = false, int exit_code = 0);

  void ErrorFormat(const std::pair<ErrorCode, std::string> &rcm,
                   bool is_exit = false);

  /** Prompt for a yes/no response. */
  bool PromptYesNo(const std::string &prompt, bool *canceled);

  /**
   * @brief Prompt for sensitive input with masked characters.
   */
  bool SecurePrompt(const std::string &prompt, std::string *out_input);

  // /** Placeholder task result printer; format TBD. */
  // void resultprint(const std::shared_ptr<TaskInfo> &task_info);
  // /** Placeholder task metadata printer; format TBD. */
  // void taskprint(const std::shared_ptr<TaskInfo> &task_info);

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

  bool Prompt(const std::string &prompt, const std::string &placeholder,
              std::string *out_input);
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

struct HighlightGuard {
  bool previous = true;
  explicit HighlightGuard(bool enable) {
    previous = ic_enable_highlight(enable);
  }
  ~HighlightGuard() { ic_enable_highlight(previous); }
};

inline AMPrintLockGuard PrintLock() { return AMPrintLockGuard(); }
inline AMPromptHookGuard HookLock() { return AMPromptHookGuard(); }
inline HighlightGuard HighlightLock(bool enable) {
  return HighlightGuard(enable);
}