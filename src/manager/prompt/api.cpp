#include "AMBase/tools/auth.hpp"
#include "AMBase/tools/bar.hpp"
#include "AMBase/tools/json.hpp"
#include "AMBase/tools/time.hpp"
#include "AMCLI/Completer/Proxy.hpp"
#include "AMManager/Prompt.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
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
  ic_enable_multiline(profile.prompt.enable_multiline);
  ic_enable_history_duplicates(profile.history.enable_duplicates);

  ic_enable_hint(profile.inline_hint.enable);
  ic_set_hint_delay(std::max(0, profile.inline_hint.delay_ms));
  ic_set_hint_search_delay(std::max(0, profile.inline_hint.search_delay_ms));
  ic_set_highlight_delay(std::max(0, profile.highlight.delay_ms));
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
  hook.callback = [this]([[maybe_unused]] int signum) {
    (void)this;
    // ic_async_stop();
  };
  hook.is_silenced = true;
  hook.priority = 100;
  hook.consume = true;
  AMCliSignalMonitor::Instance().RegisterHook("PROMPT", hook);

  AMCliSignalMonitor::SignalHook core_hook;
  core_hook.callback = [this]([[maybe_unused]] int signum) {
    (void)this;
    // ic_async_stop();
  };
  core_hook.is_silenced = true;
  core_hook.priority = 100;
  core_hook.consume = true;
  AMCliSignalMonitor::Instance().RegisterHook("COREPROMPT", core_hook);
}

