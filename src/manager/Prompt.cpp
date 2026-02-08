#include "AMManager/Prompt.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <string>
#include <unordered_set>

namespace {
/**
 * @brief Bridge isocline highlight callbacks to the token analyzer.
 *
 * @param henv Highlight environment provided by isocline.
 * @param input Current input text.
 * @param arg Pointer to the token analyzer instance.
 */
void PromptHighlighter_(ic_highlight_env_t *henv, const char *input,
                        void *arg) {
  if (!henv || !input || !arg) {
    return;
  }
  auto *analyzer = static_cast<AMTokenTypeAnalyzer *>(arg);
  std::string formatted;
  analyzer->HighlightFormatted(input, &formatted);
  if (formatted.empty()) {
    return;
  }
  ic_highlight_formatted(henv, input, formatted.c_str());
}

/**
 * @brief No-op highlighter for prompts that should not show syntax colors.
 *
 * @param henv Highlight environment provided by isocline.
 * @param input Current input text.
 * @param arg User-provided argument (unused).
 */
void PromptNoHighlight_(ic_highlight_env_t *henv, const char *input,
                        void *arg) {
  (void)henv;
  (void)input;
  (void)arg;
}

/**
 * @brief No-op completer to silence completion during simple prompts.
 *
 * @param cenv Completion environment (unused).
 * @param prefix Current input prefix (unused).
 */
void PromptNoComplete_(ic_completion_env_t *cenv, const char *prefix) {
  (void)cenv;
  (void)prefix;
}
} // namespace

AMPromptManager &AMPromptManager::Instance() {
  static AMPromptManager instance;
  return instance;
}

AMPromptManager::AMPromptManager() {
  ic_set_prompt_marker("", "");
  /** Disable multiline input so a trailing '\' does not continue to a new line.
   */
  ic_enable_multiline(false);
  ic_set_history(nullptr, -1);
  ic_enable_history_duplicates(false);
  ic_style_def("ic-prompt", "[#FFFFFF]");

  AMCliSignalMonitor::SignalHook hook;
  hook.interrupt_flag = nullptr;
  hook.callback = [this]([[maybe_unused]] int signum) {
    (void)this;
    ic_async_stop();
  };
  hook.is_silenced = true;
  hook.priority = 100;
  hook.consume = true;
  AMCliSignalMonitor::Instance().RegisterHook("PROMPT", hook);

  AMCliSignalMonitor::SignalHook core_hook;
  core_hook.interrupt_flag = amgif;
  core_hook.callback = [this]([[maybe_unused]] int signum) {
    (void)this;
    ic_async_stop();
  };
  core_hook.is_silenced = true;
  core_hook.priority = 100;
  core_hook.consume = true;
  AMCliSignalMonitor::Instance().RegisterHook("COREPROMPT", core_hook);
}

AMPromptManager::~AMPromptManager() = default;

void AMPromptManager::Print(const std::vector<std::string> &items,
                            const std::string &sep, const std::string &end) {
  std::ostringstream oss;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i > 0) {
      oss << sep;
    }
    oss << items[i];
  }
  oss << end;

  const std::string output = oss.str();
  std::string out = output;
  if (ic_is_editline_active() &&
      (out.empty() || (out.front() != '\r' && out.front() != '\n'))) {
    // ensure we break out of the active input line before printing
    out = "\r\n" + out;
  }
  if (out.empty() || out.back() != '\n') {
    out.push_back('\n');
  }

  std::lock_guard<std::mutex> lock(print_mutex_);

  if (AMProgressBar::IsAnyBarShowing()) {
    cached_output_ += out;
    return;
  }

  ic_print("\x1b[0m");
  ic_print(out.c_str());
  ic_print("\x1b[0m");
  ic_term_flush();
  ic_request_refresh_async();
}

void AMPromptManager::ErrorFormat(const std::string &error_name,
                                  const std::string &error_msg, bool is_exit,
                                  int exit_code) {

  std::ostringstream body;
  if (error_name.empty()) {
    body << "❌ " << error_msg;
  } else {
    body << "❌ " << error_name << " : " << error_msg;
  }
  Print(body.str());

  if (is_exit) {
    ic_term_flush();
    std::exit(exit_code);
  }
}

void AMPromptManager::ErrorFormat(const std::pair<ErrorCode, std::string> &rcm,
                                  bool is_exit) {
  ErrorFormat(AM_ENUM_NAME(rcm.first), rcm.second, is_exit,
              static_cast<int>(rcm.first));
}

/** Prompt for a line of input with optional defaults. */
bool AMPromptManager::PromptLine(const std::string &prompt, std::string *out,
                                 const std::string &default_value,
                                 bool allow_empty, bool *canceled,
                                 bool show_default) {
  if (canceled)
    *canceled = false;
  if (!out)
    return false;

  std::string display_prompt = prompt;
  if (show_default && !default_value.empty()) {
    display_prompt = AMStr::amfmt("{}[!e][{}][/e] ", prompt, default_value);
  }

  std::string placeholder_value;
  if (!show_default && !default_value.empty()) {
    placeholder_value = default_value;
  }

  const bool was_canceled = Prompt(display_prompt, placeholder_value, out);
  if (was_canceled) {
    if (canceled)
      *canceled = true;
    return false;
  }

  if (out->empty() && !default_value.empty()) {
    *out = default_value;
  }

  if (!allow_empty && out->empty())
    return false;
  return true;
}

/** Prompt for a yes/no response. */
bool AMPromptManager::PromptYesNo(const std::string &prompt, bool *canceled) {
  std::string answer;
  if (!PromptLine(prompt, &answer, "", true, canceled, false))
    return false;
  AMStr::VStrip(answer);
  std::string lower = answer;
  std::transform(
      lower.begin(), lower.end(), lower.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return lower == "y" || lower == "yes";
}

/**
 * @brief Placeholder result printer entry; delegates to resultprint().
 */
void AMPromptManager::PrintTaskResult(
    const std::shared_ptr<TaskInfo> &task_info) {
  resultprint(task_info);
}

void AMPromptManager::FlushCachedOutput() {
  std::lock_guard<std::mutex> lock(print_mutex_);
  if (cached_output_.empty()) {
    return;
  }
  ic_print("\x1b[0m");
  ic_print(cached_output_.c_str());
  ic_print("\x1b[0m");
  ic_term_flush();
  ic_request_refresh_async();
  cached_output_.clear();
}

/**
 * @brief Placeholder implementation that prints task execution results.
 */
void AMPromptManager::resultprint(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info || task_info->quiet) {
    return;
  }

  TaskStatus status = task_info->GetStatus();
  const char *status_str = "Unknown";
  switch (status) {
  case TaskStatus::Pending:
    status_str = "Pending";
    break;
  case TaskStatus::Conducting:
    status_str = "Conducting";
    break;
  case TaskStatus::Finished:
    status_str = "Finished";
    break;
  default:
    break;
  }

  const double submit_time = task_info->submit_time.load();
  const double start_time = task_info->start_time.load();
  const double finished_time = task_info->finished_time.load();
  const double duration_s = (start_time > 0 && finished_time >= start_time)
                                ? (finished_time - start_time)
                                : 0.0;

  size_t total = 0;
  size_t success = 0;
  size_t failed = 0;
  size_t terminated = 0;

  ECM last_error = {EC::Success, ""};

  {
    std::lock_guard<std::mutex> lock(task_info->mtx);
    auto tasks_ptr = task_info->tasks;
    if (tasks_ptr) {
      total = tasks_ptr->size();
      for (const auto &task : *tasks_ptr) {
        if (task.rcm.first == EC::Success) {
          ++success;
        } else if (task.rcm.first == EC::Terminate) {
          ++terminated;
          last_error = task.rcm;
        } else {
          ++failed;
          last_error = task.rcm;
        }
      }
    }
  }

  std::ostringstream oss;
  oss << "[TaskResult] id=" << task_info->id << " status=" << status_str
      << " total=" << total << " success=" << success << " failed=" << failed
      << " terminated=" << terminated;
  if (duration_s > 0.0) {
    oss << " duration_s=" << duration_s;
  }
  if (submit_time > 0.0) {
    oss << " submit_time=" << submit_time;
  }
  if (last_error.first != EC::Success && !last_error.second.empty()) {
    oss << " last_error=\"" << last_error.second << "\"";
  }

  Print(oss.str());
}

/**
 * @brief Placeholder implementation that prints submitted task metadata.
 */
void AMPromptManager::taskprint(const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info || task_info->quiet) {
    return;
  }
  std::ostringstream oss;
  oss << "[TaskSubmit] id=" << task_info->id
      << " affinity_thread=" << task_info->affinity_thread.load()
      << " status=" << static_cast<int>(task_info->GetStatus());
  Print(oss.str());
}

bool AMPromptManager::Prompt(const std::string &prompt,
                             const std::string &placeholder,
                             std::string *out_input) {
  /** Guard to toggle signal hooks around input. */
  struct PromptHookGuard {
    AMCliSignalMonitor &monitor;
    /** Activate prompt hook and silence global. */
    explicit PromptHookGuard(AMCliSignalMonitor &monitor_ref)
        : monitor(monitor_ref) {
      monitor.SilenceHook("GLOBAL");
      monitor.ResumeHook("PROMPT");
    }
    /** Restore global hook and silence prompt. */
    ~PromptHookGuard() {
      monitor.ResumeHook("GLOBAL");
      monitor.SilenceHook("PROMPT");
    }
  };

  if (!out_input) {
    return true;
  }

  PromptHookGuard hook_guard(AMCliSignalMonitor::Instance());

  /** Guard to silence highlight during simple prompts. */
  struct HighlightGuard {
    bool previous = true;
    explicit HighlightGuard(bool enable) {
      previous = ic_enable_highlight(enable);
    }
    ~HighlightGuard() { ic_enable_highlight(previous); }
  };

  HighlightGuard highlight_guard(false);

  const char *initial = placeholder.empty() ? nullptr : placeholder.c_str();
  char *line =
      ic_readline_ex_with_initial(prompt.c_str(), &PromptNoComplete_, nullptr,
                                  &PromptNoHighlight_, nullptr, initial);
  if (!line) {
    return true;
  }
  ic_history_remove_last();
  *out_input = std::string(line);
  ic_free(line);
  return false;
}

/**
 * @brief Prompt for a command line using the shared readline handle.
 */
bool AMPromptManager::PromptCore(const std::string &prompt,
                                 std::string *out_input) {
  if (!out_input) {
    return true;
  }
  static AMTokenTypeAnalyzer analyzer(AMConfigManager::Instance());
  char *line = ic_readline_ex(prompt.c_str(), nullptr, nullptr,
                              &PromptHighlighter_, &analyzer);
  ic_history_remove_last();
  if (!line) {
    return true;
  }
  *out_input = std::string(line);
  ic_free(line);
  return false;
}

/**
 * @brief Enable or disable history navigation for arrow keys.
 */
void AMPromptManager::SetHistoryEnabled(bool enabled) {
  history_enabled_ = enabled;
}

/**
 * @brief Load history for a nickname into the readline history.
 */
void AMPromptManager::LoadHistory(AMConfigManager &config_manager,
                                  const std::string &nickname) {
  if (nickname.empty()) {
    return;
  }
  if (history_loaded_ && history_nickname_ == nickname) {
    return;
  }
  if (history_loaded_ && !history_nickname_.empty()) {
    FlushHistory(config_manager);
  }
  history_nickname_ = nickname;
  history_loaded_ = true;

  max_history_count_ = config_manager.ResolveMaxHistoryCount(10);
  ic_set_history(nullptr, max_history_count_);
  ic_enable_history_duplicates(false);
  ic_history_clear();

  std::vector<std::string> commands;
  ECM status = config_manager.GetHistoryCommands(nickname, &commands);
  if (status.first != ErrorCode::Success) {
    history_entries_.clear();
    ErrorFormat("HistoryLoad", status.second);
    return;
  }
  history_entries_ = NormalizeHistory_(commands, max_history_count_);
  for (const auto &cmd : history_entries_) {
    ic_history_add(cmd.c_str());
  }
  if (history_entries_ != commands) {
    (void)config_manager.SetHistoryCommands(nickname, history_entries_, true);
  }
}

/**
 * @brief Flush current history back into ConfigManager.
 */
void AMPromptManager::FlushHistory(AMConfigManager &config_manager) {
  if (!history_loaded_ || history_nickname_.empty()) {
    return;
  }
  max_history_count_ = config_manager.ResolveMaxHistoryCount(10);
  history_entries_ = NormalizeHistory_(history_entries_, max_history_count_);
  ECM status = config_manager.SetHistoryCommands(history_nickname_,
                                                 history_entries_, true);
  if (status.first != ErrorCode::Success) {
    ErrorFormat(status);
  }
}

/**
 * @brief Add a history entry to the readline history.
 */
void AMPromptManager::AddHistoryEntry(const std::string &line) {
  if (!history_enabled_) {
    return;
  }
  if (line.empty()) {
    return;
  }
  history_entries_.push_back(line);
  history_entries_ = NormalizeHistory_(history_entries_, max_history_count_);
  ic_history_add(line.c_str());
}

/**
 * @brief Collect current history into a list.
 */
std::vector<std::string> AMPromptManager::CollectHistory_() const {
  return history_entries_;
}

/**
 * @brief Normalize history to unique entries with max size.
 */
std::vector<std::string>
AMPromptManager::NormalizeHistory_(const std::vector<std::string> &input,
                                   int max_count) const {
  std::vector<std::string> reversed;
  reversed.reserve(input.size());
  std::unordered_set<std::string> seen;
  for (auto it = input.rbegin(); it != input.rend(); ++it) {
    if (it->empty()) {
      continue;
    }
    if (seen.insert(*it).second) {
      reversed.push_back(*it);
    }
  }
  std::reverse(reversed.begin(), reversed.end());
  if (max_count > 0 && reversed.size() > static_cast<size_t>(max_count)) {
    reversed.erase(reversed.begin(),
                   reversed.end() - static_cast<size_t>(max_count));
  }
  return reversed;
}
