#include "AMManager/Prompt.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMCLI/Completer/Proxy.hpp"
#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/stat.h>

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

static const std::string ickey = "ic-prompt";

/**
 * @brief Apply CorePrompt profile-local isocline settings.
 */
void ApplyCoreProfileSettings_(const AMPromptProfileArgs &profile) {
  ic_set_prompt_marker(profile.prompt.marker.c_str(),
                       profile.prompt.continuation_marker.c_str());
  ic_style_def(ickey.c_str(), profile.prompt.default_style.c_str());
  ic_enable_multiline(profile.prompt.enable_multiline);
  ic_enable_history_duplicates(profile.history.enable_duplicates);

  int max_history = std::min(std::max(1, profile.history.max_count), 200);
  ic_set_history(nullptr, max_history);
  ic_enable_hint(profile.inline_hint.enable);
  ic_set_hint_delay(std::max(0, profile.inline_hint.delay_ms));
  ic_set_hint_search_delay(std::max(0, profile.inline_hint.search_delay_ms));
}

} // namespace

/**
 * @brief Ensure the specified client has a dedicated CorePrompt profile.
 */
ic_profile_t *AMProfileManager::EnsureCorePromptProfileForClient_(
    const std::string &nickname) {
  AMPromptProfileArgs &profile_args = EnsurePromptProfileForClient_(nickname);
  if (profile_args.ic_profile) {
    return profile_args.ic_profile;
  }

  ic_profile_t *profile = ic_profile_new();
  if (!profile) {
    return nullptr;
  }
  if (!ic_profile_use(profile)) {
    ic_profile_free(profile);
    return nullptr;
  }
  profile_args.ic_profile = profile;

  ApplyCoreProfileSettings_(profile_args);
  if (history_seeded_clients_.insert(profile_args.name).second) {
    const int max_history =
        std::min(std::max(1, profile_args.history.max_count), 200);
    ic_set_history(nullptr, max_history);
    ic_history_clear();
    if (profile_args.history.enable) {
      auto hist_it = history_map_.find(profile_args.name);
      if (hist_it != history_map_.end()) {
        for (const auto &cmd : hist_it->second) {
          ic_history_add(cmd.c_str());
        }
      }
    }
  }

  auto *active_completer = AMCompleter::Active();
  if (active_completer) {
    active_completer->Install();
    ic_set_default_completer(&AMCompleter::IsoclineCompleter, nullptr);
  }

  core_prompt_profile_ = profile_args.ic_profile;
  return profile_args.ic_profile;
}

/**
 * @brief Switch active isocline profile to the target client CorePrompt
 * profile.
 */
bool AMProfileManager::UseCorePromptProfileForClient_(
    const std::string &nickname) {
  AMPromptProfileArgs &profile_args = EnsurePromptProfileForClient_(nickname);
  core_prompt_profile_ = EnsureCorePromptProfileForClient_(profile_args.name);
  if (!core_prompt_profile_) {
    return false;
  }
  if (!ic_profile_use(core_prompt_profile_)) {
    return false;
  }
  ApplyCoreProfileSettings_(profile_args);
  if (!profile_args.history.enable) {
    ic_history_clear();
  }

  auto *active_completer = AMCompleter::Active();
  if (active_completer) {
    ic_set_default_completer(&AMCompleter::IsoclineCompleter, nullptr);
  }
  active_core_nickname_ = profile_args.name;
  return true;
}

void AMPromptManager::InitIsoclineConfig() {
  EnsurePromptProfilesLoaded_();
  (void)ChangeClient("local");
  const AMPromptProfileArgs &default_profile = ResolvePromptProfileArgs("*");
  ApplyCoreProfileSettings_(default_profile);

  AMCliSignalMonitor::SignalHook hook;
  hook.interrupt_flag = nullptr;
  hook.callback = [this]([[maybe_unused]] int signum) {
    (void)this;
    // ic_async_stop();
  };
  hook.is_silenced = true;
  hook.priority = 100;
  hook.consume = true;
  AMCliSignalMonitor::Instance().RegisterHook("PROMPT", hook);

  AMCliSignalMonitor::SignalHook core_hook;
  core_hook.interrupt_flag = amgif;
  core_hook.callback = [this]([[maybe_unused]] int signum) {
    (void)this;
    // ic_async_stop();
  };
  core_hook.is_silenced = true;
  core_hook.priority = 100;
  core_hook.consume = true;
  AMCliSignalMonitor::Instance().RegisterHook("COREPROMPT", core_hook);
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

  if (IsCacheOutputOnly()) {
    std::lock_guard<std::mutex> lock(cached_output_mutex_);
    cached_output_ += output;
    return;
  }

  {
    std::lock_guard<std::mutex> lock(print_mutex_);
    ic_print(output.c_str());
    ic_term_flush();
  }
}

void AMPromptManager::FlushCachedOutput() {
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

void AMPromptManager::SetCacheOutputOnly(bool enabled) {
  if (enabled) {
    cache_output_lock_depth_.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  cache_output_lock_depth_.fetch_sub(1, std::memory_order_relaxed);
  if (cache_output_lock_depth_.load(std::memory_order_relaxed) == 0) {
    FlushCachedOutput();
  }
}

bool AMPromptManager::IsCacheOutputOnly() const {
  return cache_output_lock_depth_.load(std::memory_order_relaxed) > 0;
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

/** Prompt for a yes/no response. */
bool AMPromptManager::PromptYesNo(const std::string &prompt, bool *canceled) {
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

/** Prompt for a line of input with optional defaults.
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
*/

bool AMPromptManager::Prompt(const std::string &prompt,
                             const std::string &placeholder,
                             std::string *out_input) {

  if (!out_input) {
    return true;
  }
  const std::string target =
      active_core_nickname_.empty() ? "local" : active_core_nickname_;
  (void)UseCorePromptProfileForClient_(target);
  auto lock = PrintLock();
  auto hooklock = HookLock();
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

  if (!out_input) {
    return true;
  }
  const std::string target =
      active_core_nickname_.empty() ? "local" : active_core_nickname_;
  (void)UseCorePromptProfileForClient_(target);
  auto lock = PrintLock();
  auto hooklock = HookLock();
  char *line =
      ic_readline_ex(prompt.c_str(), nullptr, nullptr,
                     &AMTokenTypeAnalyzer::PromptHighlighter_, nullptr);
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

  if (!out_input) {
    return true;
  }
  out_input->clear();
  auto lock = PrintLock();
  auto hooklock = HookLock();
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
