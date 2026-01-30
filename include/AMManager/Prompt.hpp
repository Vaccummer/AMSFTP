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

class AMPromptManager {
public:
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
  bool esc_pressed_ = false;

private:
  AMPromptManager();
  std::mutex print_mutex_;
  Replxx *replxx_ = nullptr;
};

#define AM_PROMPT_ERROR(error_name, error_msg, is_exit, exit_code)             \
  AMPromptManager::Instance().ErrorFormat((error_name), (error_msg),           \
                                          (is_exit), (exit_code), __func__)


