#include "AMManager/Prompt.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <replxx.h>
#include <sstream>
#include <string>
#include <unordered_set>

namespace {
ReplxxActionResult EscAbortHandler(Replxx *rx, unsigned int, void *ud) {
  auto *self = static_cast<AMPromptManager *>(ud);
  if (self) {
    self->esc_pressed_ = true;
  }
  if (rx) {
    return replxx_invoke(rx, REPLXX_ACTION_ABORT_LINE, 0);
  }
  return REPLXX_ACTION_RESULT_BAIL;
}

void HighlightCallback(const char *input, ReplxxColor *colors, int size,
                       void *ud) {
  auto *self = static_cast<AMPromptManager *>(ud);
  if (!self) {
    return;
  }
  if (!self->token_analyzer_) {
    return;
  }
  if (!input || size <= 0) {
    return;
  }
  self->token_analyzer_->Highlight(
      std::string(input, static_cast<size_t>(size)), colors, size);
}

} // namespace

AMPromptManager &AMPromptManager::Instance() {
  static AMPromptManager instance;
  return instance;
}

AMPromptManager::AMPromptManager() {
  replxx_ = replxx_init();
  core_replxx_ = replxx_init();
  token_analyzer_ =
      std::make_unique<AMTokenTypeAnalyzer>(AMConfigManager::Instance());
  // if (replxx_) {
  //   replxx_set_highlighter_callback(replxx_, HighlightCallback, this);
  // }
  if (core_replxx_) {
    replxx_set_highlighter_callback(core_replxx_, HighlightCallback, this);
    replxx_bind_key(core_replxx_, REPLXX_KEY_UP,
                    &AMPromptManager::HistoryUpHandler_, this);
    replxx_bind_key(core_replxx_, REPLXX_KEY_DOWN,
                    &AMPromptManager::HistoryDownHandler_, this);
  }

  AMCliSignalMonitor::SignalHook hook;
  hook.interrupt_flag = nullptr;
  hook.callback = [this]([[maybe_unused]] int signum) {
    if (replxx_) {
      replxx_emulate_key_press(replxx_, REPLXX_KEY_CONTROL('D'));
    }
  };
  hook.is_silenced = true;
  hook.priority = 0;
  AMCliSignalMonitor::Instance().RegisterHook("PROMPT", hook);

  AMCliSignalMonitor::SignalHook core_hook;
  core_hook.interrupt_flag = amgif;
  core_hook.callback = [this]([[maybe_unused]] int signum) {
    if (core_replxx_) {
      replxx_emulate_key_press(core_replxx_, REPLXX_KEY_CONTROL('D'));
    }
  };
  core_hook.is_silenced = true;
  core_hook.priority = 0;
  AMCliSignalMonitor::Instance().RegisterHook("COREPROMPT", core_hook);
}

AMPromptManager::~AMPromptManager() {
  if (replxx_) {
    replxx_end(replxx_);
    replxx_ = nullptr;
  }
  if (core_replxx_) {
    replxx_end(core_replxx_);
    core_replxx_ = nullptr;
  }
}

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
  std::lock_guard<std::mutex> lock(print_mutex_);
  std::cout << output;
  std::cout.flush();
}

void AMPromptManager::ErrorFormat(const std::string &error_name,
                                  const std::string &error_msg, bool is_exit,
                                  int exit_code, const char *caller) {
  std::ostringstream header;
  header << "[Error Call from Function " << (caller ? caller : "unknown")
         << "]";
  Print(header.str());

  std::ostringstream body;
  body << "❌  " << error_name << "  :  " << error_msg;
  Print(body.str());

  if (is_exit) {
    std::cout.flush();
    std::exit(exit_code);
  }
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
    display_prompt = AMStr::amfmt("{}[{}] ", prompt, default_value);
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

  esc_pressed_ = false;

  if (!replxx_) {
    return true;
  }

  PromptHookGuard hook_guard(AMCliSignalMonitor::Instance());

  if (!placeholder.empty()) {
    replxx_set_preload_buffer(replxx_, placeholder.c_str());
  } else {
    replxx_set_preload_buffer(replxx_, "");
  }

  const char *line = replxx_input(replxx_, prompt.c_str());
  if (esc_pressed_) {
    return true;
  }
  if (!line) {
    return true;
  }
  *out_input = std::string(line);
  return esc_pressed_;
}

/**
 * @brief Prompt for a command line using the core replxx handle.
 */
bool AMPromptManager::PromptCore(const std::string &prompt,
                                 std::string *out_input) {
  if (!out_input) {
    return true;
  }

  esc_pressed_ = false;
  ResetHistorySession_();

  if (!core_replxx_) {
    return true;
  }

  replxx_set_preload_buffer(core_replxx_, "");

  const char *line = replxx_input(core_replxx_, prompt.c_str());
  if (esc_pressed_) {
    return true;
  }
  if (!line) {
    return true;
  }
  *out_input = std::string(line);
  ResetHistorySession_();
  return esc_pressed_;
}

/**
 * @brief Enable or disable history navigation for arrow keys.
 */
void AMPromptManager::SetHistoryEnabled(bool enabled) {
  history_enabled_ = enabled;
  if (!history_enabled_) {
    ResetHistorySession_();
  }
}

/**
 * @brief Load history for a nickname into replxx core.
 */
void AMPromptManager::LoadHistory(AMConfigManager &config_manager,
                                  const std::string &nickname) {
  if (!core_replxx_) {
    return;
  }
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
  replxx_set_max_history_size(core_replxx_, max_history_count_);
  replxx_set_unique_history(core_replxx_, 1);
  replxx_history_clear(core_replxx_);

  std::vector<std::string> commands;
  ECM status = config_manager.GetHistoryCommands(nickname, &commands);
  if (status.first != ErrorCode::Success) {
    ErrorFormat("HistoryLoad", status.second, false, 0, __func__);
    return;
  }
  std::vector<std::string> normalized =
      NormalizeHistory_(commands, max_history_count_);
  for (const auto &cmd : normalized) {
    replxx_history_add(core_replxx_, cmd.c_str());
  }
  if (normalized != commands) {
    (void)config_manager.SetHistoryCommands(nickname, normalized, true);
  }
}

/**
 * @brief Flush current replxx history back into ConfigManager.
 */
void AMPromptManager::FlushHistory(AMConfigManager &config_manager) {
  if (!history_loaded_ || history_nickname_.empty()) {
    return;
  }
  max_history_count_ = config_manager.ResolveMaxHistoryCount(10);
  std::vector<std::string> commands = CollectHistory_();
  std::vector<std::string> normalized =
      NormalizeHistory_(commands, max_history_count_);
  ECM status =
      config_manager.SetHistoryCommands(history_nickname_, normalized, true);
  if (status.first != ErrorCode::Success) {
    ErrorFormat("HistorySave", status.second, false, 0, __func__);
  }
}

/**
 * @brief Add a history entry to replxx core history.
 */
void AMPromptManager::AddHistoryEntry(const std::string &line) {
  if (!core_replxx_) {
    return;
  }
  if (line.empty()) {
    return;
  }
  replxx_history_add(core_replxx_, line.c_str());
}

/**
 * @brief Collect current replxx history into a list.
 */
std::vector<std::string> AMPromptManager::CollectHistory_() const {
  std::vector<std::string> out;
  if (!core_replxx_) {
    return out;
  }
  ReplxxHistoryScan *scan = replxx_history_scan_start(core_replxx_);
  if (!scan) {
    return out;
  }
  ReplxxHistoryEntry entry{};
  while (replxx_history_scan_next(core_replxx_, scan, &entry) == 0) {
    if (entry.text && entry.text[0] != '\0') {
      out.emplace_back(entry.text);
    }
  }
  replxx_history_scan_stop(core_replxx_, scan);
  return out;
}

/**
 * @brief Reset history navigation session state.
 */
void AMPromptManager::ResetHistorySession_() {
  history_session_active_ = false;
  history_session_index_ = -1;
  history_session_entries_.clear();
  history_session_current_.clear();
  history_original_input_.clear();
}

/**
 * @brief Start a history navigation session from current input.
 */
void AMPromptManager::StartHistorySession_() {
  if (!core_replxx_) {
    return;
  }
  if (history_session_active_) {
    return;
  }
  ReplxxState state{};
  replxx_get_state(core_replxx_, &state);
  history_original_input_ = state.text ? state.text : "";
  history_session_entries_ = CollectHistory_();
  const int history_count = static_cast<int>(history_session_entries_.size());
  if (!history_original_input_.empty()) {
    history_session_entries_.push_back(history_original_input_);
  }
  history_session_entries_.push_back(std::string());
  history_session_index_ = history_count;
  history_session_active_ = true;
}

/**
 * @brief Apply a history entry to the replxx buffer.
 */
void AMPromptManager::ApplyHistoryEntry_(const std::string &line) {
  if (!core_replxx_) {
    return;
  }
  history_session_current_ = line;
  ReplxxState state{};
  state.text = history_session_current_.c_str();
  state.cursorPosition = static_cast<int>(history_session_current_.size());
  replxx_set_state(core_replxx_, &state);
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
  if (max_count > 0 &&
      reversed.size() > static_cast<size_t>(max_count)) {
    reversed.erase(reversed.begin(),
                   reversed.end() - static_cast<size_t>(max_count));
  }
  return reversed;
}

/**
 * @brief Handle the Up key for history or completion navigation.
 */
ReplxxActionResult AMPromptManager::HistoryUpHandler_(int code, void *ud) {
  auto *self = static_cast<AMPromptManager *>(ud);
  if (!self || !self->core_replxx_) {
    return REPLXX_ACTION_RESULT_CONTINUE;
  }
  if (!self->history_enabled_) {
    return replxx_invoke(self->core_replxx_, REPLXX_ACTION_COMPLETE_PREVIOUS,
                         static_cast<unsigned int>(code));
  }
  if (!self->history_session_active_) {
    self->StartHistorySession_();
  }
  if (!self->history_session_active_ ||
      self->history_session_entries_.empty()) {
    return REPLXX_ACTION_RESULT_CONTINUE;
  }
  if (self->history_session_index_ > 0) {
    --self->history_session_index_;
  }
  self->ApplyHistoryEntry_(
      self->history_session_entries_[self->history_session_index_]);
  return REPLXX_ACTION_RESULT_CONTINUE;
}

/**
 * @brief Handle the Down key for history or completion navigation.
 */
ReplxxActionResult AMPromptManager::HistoryDownHandler_(int code, void *ud) {
  auto *self = static_cast<AMPromptManager *>(ud);
  if (!self || !self->core_replxx_) {
    return REPLXX_ACTION_RESULT_CONTINUE;
  }
  if (!self->history_enabled_) {
    return replxx_invoke(self->core_replxx_, REPLXX_ACTION_COMPLETE_NEXT,
                         static_cast<unsigned int>(code));
  }
  if (!self->history_session_active_) {
    return REPLXX_ACTION_RESULT_CONTINUE;
  }
  if (self->history_session_index_ + 1 <
      static_cast<int>(self->history_session_entries_.size())) {
    ++self->history_session_index_;
  }
  self->ApplyHistoryEntry_(
      self->history_session_entries_[self->history_session_index_]);
  return REPLXX_ACTION_RESULT_CONTINUE;
}
