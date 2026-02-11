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
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_set>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

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
  if (out.empty() || out.back() != '\n') {
    out.push_back('\n');
  }

  if (cache_output_only_ || AMProgressBar::IsAnyBarShowing() ||
      ic_is_editline_active()) {
    std::lock_guard<std::mutex> lock(cached_output_mutex);
    cached_output_ += out;
    return;
  }
  {
    std::lock_guard<std::mutex> lock(print_mutex_);
    ic_print(out.c_str());
    ic_term_flush();
  }
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

  const bool ok = Prompt(display_prompt, placeholder_value, out);
  if (!ok) {
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

void AMPromptManager::FlushCachedOutput() {

  if (cached_output_.empty()) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(print_mutex_);
    ic_print("\x1b[0m");
    ic_print(cached_output_.c_str());
    ic_print("\x1b[0m");
    ic_term_flush();
  }
  {
    std::lock_guard<std::mutex> lock2(cached_output_mutex);
    cached_output_.clear();
  }
}

void AMPromptManager::SetCacheOutputOnly(bool enabled) {
  std::lock_guard<std::mutex> lock(cached_output_mutex);
  cache_output_only_ = enabled;
}

void AMPromptManager::PrintRaw(const std::string &text, bool append_newline) {
  std::string out = text;
  if (append_newline && (out.empty() || out.back() != '\n')) {
    out.push_back('\n');
  }
  std::lock_guard<std::mutex> lock(print_mutex_);
  ic_print(out.c_str());
  ic_term_flush();
}

void AMPromptManager::ClearScreen(bool clear_scrollback) {
  std::lock_guard<std::mutex> lock(print_mutex_);
  if (clear_scrollback) {
    ic_print("\x1b[3J");
  }
  ic_print("\x1b[2J\x1b[H");
  ic_term_flush();
}

void AMPromptManager::UseAlternateScreen(bool enable) {
  std::lock_guard<std::mutex> lock(print_mutex_);
  if (enable) {
    ic_print("\x1b[?1049h");
  } else {
    ic_print("\x1b[?1049l");
  }
  ic_term_flush();
}

bool AMPromptManager::Prompt(const std::string &prompt,
                             const std::string &placeholder,
                             std::string *out_input) {
  struct FlushGuard {
    AMPromptManager &prompt_mgr;
    ~FlushGuard() { prompt_mgr.FlushCachedOutput(); }
  };
  FlushGuard flush_guard{*this};

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
    return false;
  }
  ic_history_remove_last();
  *out_input = std::string(line);
  ic_free(line);
  return true;
}

/**
 * @brief Prompt for a command line using the shared readline handle.
 */
bool AMPromptManager::PromptCore(const std::string &prompt,
                                 std::string *out_input) {
  struct FlushGuard {
    AMPromptManager &prompt_mgr;
    ~FlushGuard() { prompt_mgr.FlushCachedOutput(); }
  };
  FlushGuard flush_guard{*this};

  if (!out_input) {
    return true;
  }
  static AMTokenTypeAnalyzer analyzer(AMConfigManager::Instance());
  char *line = ic_readline_ex(prompt.c_str(), nullptr, nullptr,
                              &PromptHighlighter_, &analyzer);
  ic_history_remove_last();
  if (!line) {
    return false;
  }
  *out_input = std::string(line);
  ic_free(line);
  return true;
}

bool AMPromptManager::SecurePrompt(const std::string &prompt,
                                   std::string *out_input) {
  struct FlushGuard {
    AMPromptManager &prompt_mgr;
    ~FlushGuard() { prompt_mgr.FlushCachedOutput(); }
  };
  FlushGuard flush_guard{*this};

  if (!out_input) {
    return true;
  }
  out_input->clear();

  struct PromptHookGuard {
    AMCliSignalMonitor &monitor;
    explicit PromptHookGuard(AMCliSignalMonitor &monitor_ref)
        : monitor(monitor_ref) {
      monitor.SilenceHook("GLOBAL");
      monitor.ResumeHook("PROMPT");
    }
    ~PromptHookGuard() {
      monitor.ResumeHook("GLOBAL");
      monitor.SilenceHook("PROMPT");
    }
  };
  PromptHookGuard hook_guard(AMCliSignalMonitor::Instance());

  std::string password;
  std::cout << prompt << std::flush;
#ifdef _WIN32
  while (true) {
    int ch = _getch();
    if (ch == 3 || (amgif && amgif->check())) {
      std::cout << "\n";
      return false;
    }
    if (ch == '\r' || ch == '\n') {
      break;
    }
    if (ch == '\b') {
      if (!password.empty()) {
        password.pop_back();
        std::cout << "\b \b" << std::flush;
      }
      continue;
    }
    if (ch == 0 || ch == 224) {
      (void)_getch();
      continue;
    }
    password.push_back(static_cast<char>(ch));
    std::cout << "*" << std::flush;
  }
#else
  termios oldt{};
  termios newt{};
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= static_cast<unsigned long>(~(ECHO | ICANON));
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  while (true) {
    int ch = ::getchar();
    if (ch == 3 || (amgif && amgif->check())) {
      tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
      std::cout << "\n";
      return false;
    }
    if (ch == '\n' || ch == '\r' || ch == EOF) {
      break;
    }
    if (ch == 127 || ch == 8) {
      if (!password.empty()) {
        password.pop_back();
        std::cout << "\b \b" << std::flush;
      }
      continue;
    }
    password.push_back(static_cast<char>(ch));
    std::cout << "*" << std::flush;
  }
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
  std::cout << "\n";
  *out_input = std::move(password);
  return true;
}

/**
 * @brief Enable or disable history navigation for arrow keys.
 */
void AMHistoryManager::SetHistoryEnabled(bool enabled) {
  history_enabled_ = enabled;
}

/**
 * @brief Load history for a nickname into the readline history.
 */
void AMHistoryManager::LoadHistory(AMConfigManager &config_manager,
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

  const int64_t resolved_max = config_manager.ResolveArg<int64_t>(
      DocumentKind::Settings, {"InternalVars", "MaxHistoryCount"},
      static_cast<int64_t>(10), [](int64_t value) -> int64_t {
        return value > 0 ? value : static_cast<int64_t>(10);
      });
  if (resolved_max > static_cast<int64_t>(std::numeric_limits<int>::max())) {
    max_history_count_ = std::numeric_limits<int>::max();
  } else {
    max_history_count_ = static_cast<int>(resolved_max);
  }
  ic_set_history(nullptr, max_history_count_);
  ic_enable_history_duplicates(false);
  ic_history_clear();

  std::vector<std::string> commands;
  ECM status = Ok();
  ECM load_status = config_manager.Load(DocumentKind::History);
  if (load_status.first != EC::Success) {
    status = load_status;
  } else {
    nlohmann::ordered_json history_json;
    if (config_manager.GetJson(DocumentKind::History, &history_json)) {
      nlohmann::ordered_json node = nlohmann::ordered_json::array();
      if (QueryKey(history_json, {nickname, "commands"}, &node) &&
          node.is_array()) {
        for (const auto &item : node) {
          if (item.is_string()) {
            commands.push_back(item.get<std::string>());
          }
        }
      }
    }
  }
  if (status.first != ErrorCode::Success) {
    history_entries_.clear();
    AMPromptManager::Instance().ErrorFormat("HistoryLoad", status.second);
    return;
  }
  history_entries_ = NormalizeHistory_(commands, max_history_count_);
  for (const auto &cmd : history_entries_) {
    ic_history_add(cmd.c_str());
  }
  if (history_entries_ != commands) {
    (void)config_manager.SetArg(DocumentKind::History, {nickname, "commands"},
                                history_entries_);
    (void)config_manager.Dump(DocumentKind::History);
  }
}

/**
 * @brief Flush current history back into ConfigManager.
 */
void AMHistoryManager::FlushHistory(AMConfigManager &config_manager) {
  if (!history_loaded_ || history_nickname_.empty()) {
    return;
  }
  const int64_t resolved_max = config_manager.ResolveArg<int64_t>(
      DocumentKind::Settings, {"InternalVars", "MaxHistoryCount"},
      static_cast<int64_t>(10), [](int64_t value) -> int64_t {
        return value > 0 ? value : static_cast<int64_t>(10);
      });
  if (resolved_max > static_cast<int64_t>(std::numeric_limits<int>::max())) {
    max_history_count_ = std::numeric_limits<int>::max();
  } else {
    max_history_count_ = static_cast<int>(resolved_max);
  }
  history_entries_ = NormalizeHistory_(history_entries_, max_history_count_);
  ECM status = Ok();
  if (!config_manager.SetArg(DocumentKind::History,
                             {history_nickname_, "commands"},
                             history_entries_)) {
    status = Err(EC::ConfigInvalid, "failed to set history commands");
  } else {
    status = config_manager.Dump(DocumentKind::History);
  }
  if (status.first != ErrorCode::Success) {
    AMPromptManager::Instance().ErrorFormat(status);
  }
}

/**
 * @brief Add a history entry to the readline history.
 */
void AMHistoryManager::AddHistoryEntry(const std::string &line) {
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
std::vector<std::string> AMHistoryManager::CollectHistory_() const {
  return history_entries_;
}

/**
 * @brief Normalize history to unique entries with max size.
 */
std::vector<std::string>
AMHistoryManager::NormalizeHistory_(const std::vector<std::string> &input,
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

/**
 * @brief Load history data from .AMSFTP_History.toml into memory.
 */
ECM AMHistoryManager::LoadHistory() {
  AMConfigManager &config_manager = AMConfigManager::Instance();
  return config_manager.Load(DocumentKind::History);
}

/**
 * @brief Fetch history commands for a nickname.
 */
ECM AMHistoryManager::GetHistoryCommands(const std::string &nickname,
                                         std::vector<std::string> *out) {
  if (!out) {
    return Err(EC::InvalidArg, "null history output");
  }
  out->clear();
  AMConfigManager &config_manager = AMConfigManager::Instance();
  ECM load_status = config_manager.Load(DocumentKind::History);
  if (load_status.first != EC::Success) {
    return load_status;
  }
  const std::string resolved = nickname.empty() ? "local" : nickname;
  nlohmann::ordered_json history_json;
  if (!config_manager.GetJson(DocumentKind::History, &history_json)) {
    return Ok();
  }
  nlohmann::ordered_json node = nlohmann::ordered_json::array();
  if (!QueryKey(history_json, {resolved, "commands"}, &node)) {
    return Ok();
  }
  if (!node.is_array()) {
    return Ok();
  }
  for (const auto &item : node) {
    if (item.is_string()) {
      out->push_back(item.get<std::string>());
    }
  }
  return Ok();
}

/**
 * @brief Store history commands for a nickname and optionally persist.
 */
ECM AMHistoryManager::SetHistoryCommands(
    const std::string &nickname, const std::vector<std::string> &commands,
    bool dump_now) {
  AMConfigManager &config_manager = AMConfigManager::Instance();
  ECM load_status = config_manager.Load(DocumentKind::History);
  if (load_status.first != EC::Success) {
    return load_status;
  }
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty history nickname");
  }
  if (!config_manager.SetArg(DocumentKind::History, {nickname, "commands"},
                             commands)) {
    return Err(EC::ConfigInvalid, "failed to set history commands");
  }
  if (dump_now) {
    return config_manager.Dump(DocumentKind::History);
  }
  return Ok();
}
