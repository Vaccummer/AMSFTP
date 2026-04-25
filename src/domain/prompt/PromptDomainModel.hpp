#pragma once

#include <cstddef>
#include <map>
#include <string>

namespace AMDomain::prompt {
inline constexpr const char *kPromptProfileRoot = "PromptProfile";
inline constexpr const char *kPromptProfileDefault = "*";

struct PromptProfilePromptSettings {
  std::string marker = "";
  std::string continuation_marker = ">";
  bool enable_multiline = false;
};

struct PromptProfileHistorySettings {
  bool enable = true;
  bool enable_duplicates = true;
  int max_count = 30;
};

struct PromptProfileInlineHintPathSettings {
  bool enable = true;
  bool use_async = false;
  size_t timeout_ms = 600;
};

struct PromptProfileInlineHintSettings {
  bool enable = true;
  int render_delay_ms = 30;
  int search_delay_ms = 0;
  PromptProfileInlineHintPathSettings path = {};
};

struct PromptProfileCompletePathSettings {
  bool use_async = false;
  size_t timeout_ms = 3000;
};

struct PromptProfileCompleteSettings {
  PromptProfileCompletePathSettings path = {};
};

struct PromptProfileHighlightPathSettings {
  bool enable = true;
  size_t timeout_ms = 1000;
};

struct PromptProfileHighlightSettings {
  int delay_ms = 0;
  PromptProfileHighlightPathSettings path = {};
};

struct PromptProfileSettings {
  PromptProfilePromptSettings prompt = {};
  PromptProfileHistorySettings history = {};
  PromptProfileInlineHintSettings inline_hint = {};
  PromptProfileCompleteSettings complete = {};
  PromptProfileHighlightSettings highlight = {};
};

using PromptProfileSet = std::map<std::string, PromptProfileSettings>;

// Arg for Settings.PromptProfile with unstable profile keys ("*", nickname,
// etc.)
struct PromptProfileArg {
  PromptProfileSet set = {};
};

// Arg for Options.PromptHistoryManager.
struct PromptHistoryArg {
  std::string history_dir = "./history";
  bool allow_continuous_duplicates = false;
  int max_count = 50;
};
} // namespace AMDomain::prompt
