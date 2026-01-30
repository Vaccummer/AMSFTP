#include "AMManager/Prompt.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <replxx.h>
#include <sstream>
#include <string>


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
} // namespace

AMPromptManager &AMPromptManager::Instance() {
  static AMPromptManager instance;
  return instance;
}

AMPromptManager::AMPromptManager() {
  replxx_ = replxx_init();

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
}

AMPromptManager::~AMPromptManager() {
  if (replxx_) {
    replxx_end(replxx_);
    replxx_ = nullptr;
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
