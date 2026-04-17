#include "domain/prompt/PromptDomainService.hpp"

#include <algorithm>

namespace AMDomain::prompt::service {
namespace {

template <typename T>
[[nodiscard]] T Clamp_(T value, T min_value, T max_value) {
  if (min_value > max_value) {
    std::swap(min_value, max_value);
  }
  return std::max<T>(min_value, std::min<T>(value, max_value));
}

} // namespace

void NormalizePromptSettings(PromptProfilePromptSettings *settings) {
  if (!settings) {
    return;
  }
  const PromptProfilePromptSettings defaults = {};
  if (settings->continuation_marker.empty()) {
    settings->continuation_marker = defaults.continuation_marker;
  }
}

void NormalizeHistorySettings(PromptProfileHistorySettings *settings) {
  if (!settings) {
    return;
  }
  settings->max_count = Clamp_<int>(settings->max_count, 1, 200);
}

void NormalizeInlineHintPathSettings(PromptProfileInlineHintPathSettings *settings) {
  if (!settings) {
    return;
  }
  const PromptProfileInlineHintPathSettings defaults = {};
  if (settings->timeout_ms < 1) {
    settings->timeout_ms = defaults.timeout_ms;
  }
}

void NormalizeInlineHintSettings(PromptProfileInlineHintSettings *settings) {
  if (!settings) {
    return;
  }
  settings->render_delay_ms = std::max(0, settings->render_delay_ms);
  settings->search_delay_ms = std::max(0, settings->search_delay_ms);
  NormalizeInlineHintPathSettings(&settings->path);
}

void NormalizeCompletePathSettings(PromptProfileCompletePathSettings *settings) {
  if (!settings) {
    return;
  }
  const PromptProfileCompletePathSettings defaults = {};
  if (settings->timeout_ms < 1) {
    settings->timeout_ms = defaults.timeout_ms;
  }
}

void NormalizeCompleteSettings(PromptProfileCompleteSettings *settings) {
  if (!settings) {
    return;
  }
  NormalizeCompletePathSettings(&settings->path);
}

void NormalizeHighlightPathSettings(PromptProfileHighlightPathSettings *settings) {
  if (!settings) {
    return;
  }
  const PromptProfileHighlightPathSettings defaults = {};
  if (settings->timeout_ms < 1) {
    settings->timeout_ms = defaults.timeout_ms;
  }
}

void NormalizeHighlightSettings(PromptProfileHighlightSettings *settings) {
  if (!settings) {
    return;
  }
  settings->delay_ms = std::max(0, settings->delay_ms);
  NormalizeHighlightPathSettings(&settings->path);
}

void NormalizePromptProfileSettings(PromptProfileSettings *settings) {
  if (!settings) {
    return;
  }
  NormalizePromptSettings(&settings->prompt);
  NormalizeHistorySettings(&settings->history);
  NormalizeInlineHintSettings(&settings->inline_hint);
  NormalizeCompleteSettings(&settings->complete);
  NormalizeHighlightSettings(&settings->highlight);
}

void NormalizePromptProfileSet(PromptProfileSet *set) {
  if (!set) {
    return;
  }
  for (auto &[name, settings] : *set) {
    (void)name;
    NormalizePromptProfileSettings(&settings);
  }
}

void NormalizePromptProfileArg(PromptProfileArg *arg) {
  if (!arg) {
    return;
  }
  NormalizePromptProfileSet(&arg->set);
}

} // namespace AMDomain::prompt::service

