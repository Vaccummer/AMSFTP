#include "Isocline/isocline.h"
#include "interface/adapters/ApplicationAdapters.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"
#include "interface/parser/TokenTypeAnalyzer.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/stat.h>


#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {
/**
 * @brief Temporarily disable ENABLE_PROCESSED_INPUT while Prompt() reads
 * stdin on Windows.
 *
 * This limits Ctrl+C key processing suppression strictly to prompt input
 * scope and restores the previous console mode on scope exit.
 */
class ScopedPromptProcessedInputGuard_ {
public:
  /**
   * @brief Capture stdin mode and clear ENABLE_PROCESSED_INPUT when possible.
   */
  ScopedPromptProcessedInputGuard_() {
#ifdef _WIN32
    input_handle_ = GetStdHandle(STD_INPUT_HANDLE);
    if (input_handle_ == INVALID_HANDLE_VALUE || input_handle_ == nullptr) {
      return;
    }
    if (!GetConsoleMode(input_handle_, &original_mode_)) {
      return;
    }
    const DWORD desired_mode = original_mode_ & ~ENABLE_PROCESSED_INPUT;
    if (desired_mode == original_mode_) {
      return;
    }
    if (!SetConsoleMode(input_handle_, desired_mode)) {
      return;
    }
    applied_ = true;
#endif
  }

  /**
   * @brief Restore stdin console mode when this guard changed it.
   */
  ~ScopedPromptProcessedInputGuard_() {
#ifdef _WIN32
    if (!applied_) {
      return;
    }
    if (input_handle_ == INVALID_HANDLE_VALUE || input_handle_ == nullptr) {
      return;
    }
    (void)SetConsoleMode(input_handle_, original_mode_);
#endif
  }

private:
#ifdef _WIN32
  HANDLE input_handle_ = INVALID_HANDLE_VALUE;
  DWORD original_mode_ = 0;
  bool applied_ = false;
#endif
};

/**
 * @brief Bridge isocline highlight callbacks to the token analyzer.
 *
 * @param henv Highlight environment provided by isocline.
 * @param input Current input text.
 * @param arg Pointer to the token analyzer instance.
 */
// void PromptHighlighter_(ic_highlight_env_t *henv, const char *input,
//                         void *arg) {
//   if (!henv || !input || !arg) {
//     return;
//   }
//   AMTokenTypeAnalyzer &analyzer = AMTokenTypeAnalyzer::Instance();
//   std::string formatted;
//   analyzer.HighlightFormatted(input, &formatted);
//   if (formatted.empty()) {
//     return;
//   }
//   ic_highlight_formatted(henv, input, formatted.c_str());
// }

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

/**
 * @brief Query-mode prompt callback context.
 */
struct PromptValueQueryContext {
  const std::function<bool(const std::string &)> *checker = nullptr;
  const std::vector<std::string> *candidates = nullptr;
  const std::map<std::string, std::string> *literals = nullptr;
  std::string valid_tag;
  std::string invalid_tag;
};

/**
 * @brief Normalize a configured style into a bbcode opening tag.
 */
std::string NormalizeStyleTag_(const std::string &raw) {
  std::string trimmed = AMStr::Strip(raw);
  if (trimmed.empty()) {
    return "";
  }
  if (trimmed.find("[/") != std::string::npos) {
    return "";
  }
  if (trimmed.front() != '[') {
    trimmed.insert(trimmed.begin(), '[');
  }
  if (trimmed.back() != ']') {
    trimmed.push_back(']');
  }
  return trimmed;
}

/**
 * @brief Normalize prompt style for ic_style_def.
 *
 * Accepts both `#RRGGBB b` and `[#RRGGBB b]` forms.
 */
std::string NormalizePromptStyleForIc_(const std::string &raw) {
  std::string trimmed = AMStr::Strip(raw);
  if (trimmed.size() >= 2 && trimmed.front() == '[' && trimmed.back() == ']') {
    trimmed = AMStr::Strip(trimmed.substr(1, trimmed.size() - 2));
  }
  return trimmed;
}

/**
 * @brief Apply CLIPrompt shortcut styles as isocline named styles.
 */
void ApplyPromptShortcutStyles_() {
  static const std::vector<std::string> keys = {
      "un", "at", "hn", "en", "nn", "cwd", "ds", "white"};
  for (const auto &key : keys) {
    const std::string raw =
        AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
            {"Style", "CLIPrompt", "shortcut", key}, "");
    const std::string fmt = NormalizePromptStyleForIc_(raw);
    if (fmt.empty()) {
      continue;
    }
    ic_style_def(key.c_str(), fmt.c_str());
  }
}

/**
 * @brief Resolve incremental history-search prompt text from settings.
 */
std::string ResolveHistorySearchPrompt_() {
  std::string prompt =
      AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
          {"Style", "CLIPrompt", "template", "history_search_prompt"}, "");
  if (!prompt.empty()) {
    return prompt;
  }
  prompt = AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
      {"Style", "CLIPrompt", "templete", "history_search_prompt"}, "");
  if (!prompt.empty()) {
    return prompt;
  }
  return "history search";
}

/**
 * @brief Apply abort style to isocline warning channel for query prompts.
 *
 * The warning style is used by isocline diagnostics (including Ctrl+C abort
 * notices in query-mode input paths).
 */
void ApplyQueryAbortWarningStyle_() {
  std::string abort_style =
      AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
          {"Style", "InputHighlight", "abort"}, "");
  abort_style = NormalizePromptStyleForIc_(abort_style);
  if (abort_style.empty()) {
    return;
  }
  ic_style_def("warning", abort_style.c_str());
}

/**
 * @brief Escape bbcode-sensitive characters for formatted highlight output.
 */
std::string EscapeBbcodeText_(const std::string &text) {
  std::string escaped;
  escaped.reserve(text.size() * 2);
  for (char c : text) {
    if (c == '\\') {
      escaped.append("\\\\");
    } else if (c == '[') {
      escaped.append("\\[");
    } else {
      escaped.push_back(c);
    }
  }
  return escaped;
}

/**
 * @brief Query-mode highlighter that marks valid/invalid input values.
 */
void PromptValueQueryHighlight_(ic_highlight_env_t *henv, const char *input,
                                void *arg) {
  if (!henv || !input || !arg) {
    return;
  }
  const auto *ctx = static_cast<const PromptValueQueryContext *>(arg);
  if (!ctx->checker || !(*ctx->checker)) {
    return;
  }

  const std::string text(input);
  const bool is_valid = (*ctx->checker)(text);
  const std::string &tag = is_valid ? ctx->valid_tag : ctx->invalid_tag;
  if (tag.empty()) {
    return;
  }

  std::string formatted;
  formatted.reserve(text.size() + tag.size() + 4);
  formatted.append(tag);
  formatted.append(EscapeBbcodeText_(text));
  formatted.append("[/]");
  ic_highlight_formatted(henv, input, formatted.c_str());
}

/**
 * @brief Query-mode completer that uses explicit candidate strings.
 */
void PromptValueQueryComplete_(ic_completion_env_t *cenv, const char *prefix) {
  if (!cenv) {
    return;
  }
  (void)prefix;

  auto *ctx =
      static_cast<const PromptValueQueryContext *>(ic_completion_arg(cenv));
  if (!ctx) {
    return;
  }

  long cursor = 0;
  const char *input_c = ic_completion_input(cenv, &cursor);
  if (!input_c || cursor < 0) {
    return;
  }
  std::string input(input_c);
  size_t cur = static_cast<size_t>(cursor);
  if (cur > input.size()) {
    cur = input.size();
  }

  size_t token_start = cur;
  while (token_start > 0 &&
         !std::isspace(static_cast<unsigned char>(input[token_start - 1]))) {
    --token_start;
  }
  size_t token_end = cur;
  while (token_end < input.size() &&
         !std::isspace(static_cast<unsigned char>(input[token_end]))) {
    ++token_end;
  }

  const std::string token_prefix = input.substr(token_start, cur - token_start);
  const long delete_before = static_cast<long>(cur - token_start);
  const long delete_after = static_cast<long>(token_end - cur);

  if (ctx->literals && !ctx->literals->empty()) {
    for (const auto &entry : *ctx->literals) {
      const std::string &candidate = entry.first;
      if (!token_prefix.empty() && candidate.rfind(token_prefix, 0) != 0) {
        continue;
      }
      const char *help = entry.second.empty() ? nullptr : entry.second.c_str();
      ic_add_completion_prim(cenv, candidate.c_str(), nullptr, help,
                             delete_before, delete_after);
    }
    return;
  }

  if (!ctx->candidates || ctx->candidates->empty()) {
    return;
  }
  for (const auto &candidate : *ctx->candidates) {
    if (!token_prefix.empty() && candidate.rfind(token_prefix, 0) != 0) {
      continue;
    }
    ic_add_completion_prim(cenv, candidate.c_str(), nullptr, nullptr,
                           delete_before, delete_after);
  }
}

static const std::string ickey = "ic-prompt";

/**
 * @brief Apply CorePrompt profile-local isocline settings.
 */
void ApplyCoreProfileSettings_(const AMPromptProfileArgs &profile) {
  ic_set_prompt_marker(profile.prompt.marker.c_str(),
                       profile.prompt.continuation_marker.c_str());
  ApplyPromptShortcutStyles_();
  const std::string history_search_prompt = ResolveHistorySearchPrompt_();
  ic_set_history_search_prompt(history_search_prompt.c_str());
  ic_enable_multiline(profile.prompt.enable_multiline);
  ic_enable_history_duplicates(profile.history.enable_duplicates);

  ic_enable_hint(profile.inline_hint.enable);
  ic_set_hint_delay(std::max(0, profile.inline_hint.render_delay_ms));
  ic_set_hint_search_delay(std::max(0, profile.inline_hint.search_delay_ms));
  ic_set_highlight_delay(std::max(0, profile.highlight.delay_ms));
}

} // namespace

void AMPromptIOManager::PrintRaw(const std::string &text, bool append_newline) {
  std::string out = text;
  if (append_newline && (out.empty() || out.back() != '\n')) {
    out.push_back('\n');
  }
  if (ic_is_editline_active() && ic_print_async(out.c_str())) {
    return;
  }
  std::lock_guard<std::mutex> lock(print_mutex_);
  ic_print(out.c_str());
  ic_term_flush();
}

void AMPromptIOManager::Print(const std::string &text) {
  std::string output = text;
  if (output.empty() || output.back() != '\n') {
    output.push_back('\n');
  }

  if (IsCacheOutputOnly()) {
    std::lock_guard<std::mutex> lock(cached_output_mutex_);
    cached_output_ += output;
    return;
  }

  if (ic_is_editline_active() && ic_print_async(output.c_str())) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock(print_mutex_);
    ic_print(output.c_str());
    ic_term_flush();
  }
}

void AMPromptIOManager::FlushCachedOutput() {
  if (cached_output_.empty()) {
    return;
  }
  std::lock_guard<std::mutex> lock1(print_mutex_);
  std::lock_guard<std::mutex> lock2(cached_output_mutex_);
  ic_print("\x1b[0m");
  ic_print(cached_output_.c_str());
  ic_print("\x1b[0m");
  ic_term_flush();
  cached_output_.clear();
}

void AMPromptIOManager::SetCacheOutputOnly(bool enabled) {
  if (enabled) {
    cache_output_lock_depth_.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  cache_output_lock_depth_.fetch_sub(1, std::memory_order_relaxed);
  if (cache_output_lock_depth_.load(std::memory_order_relaxed) == 0) {
    FlushCachedOutput();
  }
}

bool AMPromptIOManager::IsCacheOutputOnly() const {
  return cache_output_lock_depth_.load(std::memory_order_relaxed) > 0;
}

void AMPromptIOManager::ErrorFormat(const std::string &error_name,
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

void AMPromptIOManager::ErrorFormat(const ECM &rcm, bool is_exit) {
  ErrorFormat(AMStr::ToString(rcm.first), rcm.second, is_exit,
              static_cast<int>(rcm.first));
}

/** Prompt for a yes/no response. */
bool AMPromptIOManager::PromptYesNo(const std::string &prompt, bool *canceled) {
  std::string answer;
  if (!Prompt(prompt, "", &answer)) {
    if (canceled) {
      *canceled = true;
    }
    return false;
  }
  AMStr::VStrip(answer);
  AMStr::vlowercase(answer);
  return answer == "y" || answer == "yes";
}

void AMPromptIOManager::ClearScreen(bool clear_scrollback) {
  std::lock_guard<std::mutex> lock(print_mutex_);
  if (clear_scrollback) {
    ic_print("\x1b[3J");
  }
  ic_print("\x1b[2J\x1b[H");
  ic_term_flush();
}

void AMPromptIOManager::UseAlternateScreen(bool enable) {
  std::lock_guard<std::mutex> lock(print_mutex_);
  if (enable) {
    ic_print("\x1b[?1049h");
  } else {
    ic_print("\x1b[?1049l");
  }
  ic_term_flush();
}

/** Prompt for a line of input with optional defaults.
bool AMPromptIOManager::PromptLine(const std::string &prompt, std::string *out,
                                 const std::string &default_value,
                                 bool allow_empty, bool *canceled,
                                 bool show_default) {
  if (canceled)
    *canceled = false;
  if (!out)
    return false;

  std::string display_prompt = prompt;
  if (show_default && !default_value.empty()) {
    display_prompt = AMStr::fmt("{}[!e][{}][/e] ", prompt, default_value);
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
*/

bool AMPromptIOManager::Prompt(
    const std::string &prompt, const std::string &placeholder,
    std::string *out_input,
    const std::function<bool(const std::string &)> &checker,
    const std::vector<std::string> &candidates) {

  if (!out_input) {
    return true;
  }
  const std::string target =
      active_core_nickname_.empty() ? "local" : active_core_nickname_;
  (void)profile_history_manager_.UseCorePromptProfileForClient_(target);
  const AMPromptProfileArgs *active_profile =
      profile_history_manager_.GetCurrentPromptProfileArgs();
  std::string query_prompt_style =
      AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
          {"Style", "ValueQueryHighlight", "prompt_style"}, "");
  query_prompt_style = NormalizePromptStyleForIc_(query_prompt_style);
  if (!query_prompt_style.empty()) {
    ic_style_def(ickey.c_str(), query_prompt_style.c_str());
  }
  ApplyQueryAbortWarningStyle_();

  PromptValueQueryContext query_ctx;
  query_ctx.checker = checker ? &checker : nullptr;
  query_ctx.candidates = candidates.empty() ? nullptr : &candidates;
  if (query_ctx.checker) {
    std::string valid_raw =
        AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
            {"Style", "ValueQueryHighlight", "valid_value"}, "");
    std::string invalid_raw =
        AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
            {"Style", "ValueQueryHighlight", "invalid_value"}, "");
    query_ctx.valid_tag = NormalizeStyleTag_(valid_raw);
    query_ctx.invalid_tag = NormalizeStyleTag_(invalid_raw);
  }

  ic_completer_fun_t *completer = &PromptNoComplete_;
  void *completer_arg = nullptr;
  if (query_ctx.candidates) {
    completer = &PromptValueQueryComplete_;
    completer_arg = &query_ctx;
  }
  ic_highlight_fun_t *highlighter = &PromptNoHighlight_;
  void *highlighter_arg = nullptr;
  if (query_ctx.checker) {
    highlighter = &PromptValueQueryHighlight_;
    highlighter_arg = &query_ctx;
  }

  auto lock = AMPrintLockGuard::Lock(*this);
  auto hooklock = AMPromptHookGuard::Lock();
  ScopedPromptProcessedInputGuard_ processed_input_guard;
  (void)processed_input_guard;
  const char *initial = placeholder.empty() ? nullptr : placeholder.c_str();
  ic_set_default_completer(completer, completer_arg);
  ic_set_default_highlighter(highlighter, highlighter_arg);
  char *line = ic_readline_ex(prompt.c_str(), initial);
  if (active_profile) {
    ApplyCoreProfileSettings_(*active_profile);
  }
  if (!line) {
    return false;
  }
  ic_history_remove_last();
  *out_input = std::string(line);
  ic_free(line);
  return true;
}

/**
 * @brief Prompt for one literal value using a literal->help dictionary.
 */
bool AMPromptIOManager::LiteralPrompt(
    const std::string &prompt, const std::string &placeholder,
    std::string *out_input,
    const std::map<std::string, std::string> &literals) {
  if (!out_input) {
    return true;
  }
  const std::string target =
      active_core_nickname_.empty() ? "local" : active_core_nickname_;
  (void)profile_history_manager_.UseCorePromptProfileForClient_(target);
  const AMPromptProfileArgs *active_profile =
      profile_history_manager_.GetCurrentPromptProfileArgs();
  std::string query_prompt_style =
      AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
          {"Style", "ValueQueryHighlight", "prompt_style"}, "");
  query_prompt_style = NormalizePromptStyleForIc_(query_prompt_style);
  if (!query_prompt_style.empty()) {
    ic_style_def(ickey.c_str(), query_prompt_style.c_str());
  }
  ApplyQueryAbortWarningStyle_();

  std::function<bool(const std::string &)> literal_checker;
  if (!literals.empty()) {
    literal_checker = [&literals](const std::string &text) {
      return literals.find(AMStr::Strip(text)) != literals.end();
    };
  }

  PromptValueQueryContext query_ctx;
  query_ctx.checker = literal_checker ? &literal_checker : nullptr;
  query_ctx.literals = literals.empty() ? nullptr : &literals;
  if (query_ctx.checker) {
    std::string valid_raw =
        AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
            {"Style", "ValueQueryHighlight", "valid_value"}, "");
    std::string invalid_raw =
        AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
            {"Style", "ValueQueryHighlight", "invalid_value"}, "");
    query_ctx.valid_tag = NormalizeStyleTag_(valid_raw);
    query_ctx.invalid_tag = NormalizeStyleTag_(invalid_raw);
  }

  ic_completer_fun_t *completer = &PromptNoComplete_;
  void *completer_arg = nullptr;
  if (query_ctx.literals) {
    completer = &PromptValueQueryComplete_;
    completer_arg = &query_ctx;
  }
  ic_highlight_fun_t *highlighter = &PromptNoHighlight_;
  void *highlighter_arg = nullptr;
  if (query_ctx.checker) {
    highlighter = &PromptValueQueryHighlight_;
    highlighter_arg = &query_ctx;
  }

  auto lock = AMPrintLockGuard::Lock(*this);
  auto hooklock = AMPromptHookGuard::Lock();
  const char *initial = placeholder.empty() ? nullptr : placeholder.c_str();
  ic_set_default_completer(completer, completer_arg);
  ic_set_default_highlighter(highlighter, highlighter_arg);
  char *line = ic_readline_ex(prompt.c_str(), initial);
  if (active_profile) {
    ApplyCoreProfileSettings_(*active_profile);
  }
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
bool AMPromptIOManager::PromptCore(const std::string &prompt,
                                 std::string *out_input) {
  AMPromptHookGuard::Lock();

  if (!out_input) {
    return true;
  }
  const std::string target =
      active_core_nickname_.empty() ? "local" : active_core_nickname_;
  (void)profile_history_manager_.UseCorePromptProfileForClient_(target);
  auto lock = AMPrintLockGuard::Lock(*this);
  auto hooklock = AMPromptHookGuard::Lock();
  ic_set_default_highlighter(&AMTokenTypeAnalyzer::PromptHighlighter_, nullptr);
  char *line = ic_readline_ex(prompt.c_str(), nullptr);
  ic_history_remove_last();
  if (!line) {

    return false;
  }
  *out_input = std::string(line);
  ic_free(line);

  return true;
}

bool AMPromptIOManager::SecurePrompt(const std::string &prompt,
                                   std::string *out_input) {

  if (!out_input) {
    return true;
  }
  out_input->clear();
  auto lock = AMPrintLockGuard::Lock(*this);
  auto hooklock = AMPromptHookGuard::Lock();
  std::string password;
  std::cout << prompt << std::flush;
#ifdef _WIN32
  while (true) {
    int ch = _getch();
    if (ch == 3 || (TaskControlToken::Instance() &&
                    !TaskControlToken::Instance()->IsRunning())) {
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
    if (ch == 3 || (TaskControlToken::Instance() &&
                    !TaskControlToken::Instance()->IsRunning())) {
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


