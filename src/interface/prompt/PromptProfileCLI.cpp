#include "domain/host/HostDomainService.hpp"
#include "domain/prompt/PromptDomainService.hpp"
#include "interface/prompt/Prompt.hpp"
#include <sstream>
#include <unordered_set>

namespace AMInterface::prompt {
namespace {
using AMDomain::host::HostService::IsLocalNickname;
using AMDomain::host::HostService::NormalizeNickname;
using AMDomain::prompt::PromptProfileSettings;

std::string NormalizeProfileNickname_(const std::string &nickname) {
  const std::string stripped = AMStr::Strip(nickname);
  if (stripped.empty()) {
    return "";
  }
  std::string normalized = NormalizeNickname(stripped);
  if (IsLocalNickname(normalized)) {
    normalized = AMDomain::host::klocalname;
  }
  return normalized;
}

bool TryParseInt64Strict_(const std::string &text, int64_t *out) {
  if (!out) {
    return false;
  }
  const std::string trimmed = AMStr::Strip(text);
  if (trimmed.empty()) {
    return false;
  }
  std::istringstream iss(trimmed);
  int64_t value = 0;
  char extra = '\0';
  if (!(iss >> value)) {
    return false;
  }
  if (iss >> extra) {
    return false;
  }
  *out = value;
  return true;
}

void PrintPromptProfile_(PromptIOManager &prompt, const std::string &name,
                         const PromptProfileSettings &profile) {
  prompt.FmtPrint("\\[{}]", name);
  prompt.FmtPrint("Prompt.marker: {}", profile.prompt.marker);
  prompt.FmtPrint("Prompt.continuation_marker: {}",
                  profile.prompt.continuation_marker);
  prompt.FmtPrint("Prompt.enable_multiline: {}",
                  profile.prompt.enable_multiline ? "true" : "false");
  prompt.FmtPrint("History.enable: {}",
                  profile.history.enable ? "true" : "false");
  prompt.FmtPrint("History.enable_duplicates: {}",
                  profile.history.enable_duplicates ? "true" : "false");
  prompt.FmtPrint("History.max_count: {}", profile.history.max_count);
  prompt.FmtPrint("InlineHint.enable: {}",
                  profile.inline_hint.enable ? "true" : "false");
  prompt.FmtPrint("InlineHint.render_delay_ms: {}",
                  profile.inline_hint.render_delay_ms);
  prompt.FmtPrint("InlineHint.search_delay_ms: {}",
                  profile.inline_hint.search_delay_ms);
  prompt.FmtPrint("InlineHint.Path.enable: {}",
                  profile.inline_hint.path.enable ? "true" : "false");
  prompt.FmtPrint("InlineHint.Path.use_async: {}",
                  profile.inline_hint.path.use_async ? "true" : "false");
  prompt.FmtPrint("InlineHint.Path.timeout_ms: {}",
                  profile.inline_hint.path.timeout_ms);
  prompt.FmtPrint("Complete.Searcher.Path.use_async: {}",
                  profile.complete.path.use_async ? "true" : "false");
  prompt.FmtPrint("Complete.Searcher.Path.timeout_ms: {}",
                  profile.complete.path.timeout_ms);
  prompt.FmtPrint("Highlight.delay_ms: {}", profile.highlight.delay_ms);
  prompt.FmtPrint("Highlight.Path.enable: {}",
                  profile.highlight.path.enable ? "true" : "false");
  prompt.FmtPrint("Highlight.Path.timeout_ms: {}",
                  profile.highlight.path.timeout_ms);
}

} // namespace

void PromptIOManager::PrintTaskResult(
    const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) {
  (void)task_info;
}

ECM PromptIOManager::Edit(const std::string &nickname) {
  const std::string target = NormalizeProfileNickname_(nickname);
  if (target.empty()) {
    return Err(EC::InvalidArg, __func__, "<context>", "empty profile nickname");
  }
  if (target == AMDomain::prompt::kPromptProfileDefault) {
    return Err(EC::InvalidArg, __func__, "<context>",
               "profile nickname must be a host nickname");
  }
  const ECM rcm = EditProfile_(target);
  if (!(rcm) && rcm.code == EC::ConfigCanceled) {
    const std::string abort_style =
        isocline_profile_manager_.style_config_manager_.GetInitArg()
            .style.input_highlight.abort;
    if (abort_style.empty()) {
      Print("Profile edit aborted.");
    } else {
      Print(abort_style + AMStr::BBCEscape("Profile edit aborted.") + "[/]");
    }
  }
  return rcm;
}

ECM PromptIOManager::Get(const std::vector<std::string> &nicknames) {
  if (nicknames.empty()) {
    return Err(EC::InvalidArg, __func__, "<context>",
               "profile get requires at least one nickname");
  }

  std::vector<std::string> targets = {};
  std::unordered_set<std::string> seen = {};
  targets.reserve(nicknames.size());
  for (const auto &name : nicknames) {
    const std::string target = NormalizeProfileNickname_(name);
    if (target.empty()) {
      return Err(EC::InvalidArg, __func__, "<context>", "empty profile nickname");
    }
    if (target == AMDomain::prompt::kPromptProfileDefault) {
      return Err(EC::InvalidArg, __func__, "<context>",
                 "profile nickname must be a host nickname");
    }
    if (seen.insert(target).second) {
      targets.push_back(target);
    }
  }

  bool first = true;
  for (const auto &target : targets) {
    const auto profile_query =
        isocline_profile_manager_.profile_manager_.GetZoneProfile(target);
    PromptProfileSettings profile = profile_query.profile;
    AMDomain::prompt::services::NormalizePromptProfileSettings(&profile);
    if (!first) {
      Print("");
    }
    first = false;
    PrintPromptProfile_(*this, target, profile);
  }

  return OK;
}

ECM PromptIOManager::EditProfile_(const std::string &nickname) {
  const std::string target = NormalizeProfileNickname_(nickname);
  if (target.empty()) {
    return Err(EC::InvalidArg, __func__, "<context>", "empty profile nickname");
  }

  PromptProfileSettings working =
      isocline_profile_manager_.profile_manager_.GetZoneProfile(target).profile;
  AMDomain::prompt::services::NormalizePromptProfileSettings(&working);

  PromptProfileSettings defaults = {};
  AMDomain::prompt::services::NormalizePromptProfileSettings(&defaults);

  const auto prompt_string = [this](const std::string &label,
                                    std::string *value) -> bool {
    if (!value) {
      return false;
    }
    auto out = Prompt(label, *value);
    if (!out.has_value()) {
      return false;
    }
    *value = *out;
    return true;
  };

  const std::vector<std::pair<std::string, std::string>> bool_literals = {
      {"true", "enable"}, {"false", "disable"}};
  const auto prompt_bool = [this, &bool_literals](const std::string &label,
                                                  bool *value) -> bool {
    if (!value) {
      return false;
    }
    while (true) {
      const std::string placeholder = *value ? "true" : "false";
      auto out = LiteralPrompt(label, placeholder, bool_literals);
      if (!out.has_value()) {
        return false;
      }
      bool parsed = false;
      if (AMStr::GetBool(*out, &parsed)) {
        *value = parsed;
        return true;
      }
      ErrorFormat(Err(EC::InvalidArg, __func__, "<context>", "value must be true or false"));
    }
  };

  const auto prompt_int64 = [this](const std::string &label, int64_t min_value,
                                   int64_t max_value, int64_t *value) -> bool {
    if (!value) {
      return false;
    }
    while (true) {
      const std::string placeholder = std::to_string(*value);
      auto checker = [min_value, max_value,
                      placeholder](const std::string &text) -> bool {
        std::string trimmed = AMStr::Strip(text);
        if (trimmed.empty()) {
          trimmed = placeholder;
        }
        int64_t parsed = 0;
        if (!TryParseInt64Strict_(trimmed, &parsed)) {
          return false;
        }
        return parsed >= min_value && parsed <= max_value;
      };
      auto out = Prompt(label, placeholder, checker);
      if (!out.has_value()) {
        return false;
      }
      std::string trimmed = AMStr::Strip(*out);
      if (trimmed.empty()) {
        trimmed = placeholder;
      }
      int64_t parsed = *value;
      if (!TryParseInt64Strict_(trimmed, &parsed)) {
        ErrorFormat(Err(EC::InvalidArg, __func__, "<context>", "invalid integer value"));
        continue;
      }
      if (parsed < min_value || parsed > max_value) {
        ErrorFormat(Err(
            EC::InvalidArg, __func__, "<context>",
            AMStr::fmt("value out of range [{}, {}]", min_value, max_value)));
        continue;
      }
      *value = parsed;
      return true;
    }
  };

  if (!prompt_string("Prompt.marker: ", &working.prompt.marker) ||
      !prompt_string("Prompt.continuation_marker: ",
                     &working.prompt.continuation_marker)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
  }
  if (!prompt_bool("Prompt.enable_multiline(true/false): ",
                   &working.prompt.enable_multiline) ||
      !prompt_bool("History.enable(true/false): ", &working.history.enable)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
  }

  if (working.history.enable) {
    if (!prompt_bool("History.enable_duplicates(true/false): ",
                     &working.history.enable_duplicates)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
    }
    int64_t history_max = static_cast<int64_t>(working.history.max_count);
    if (!prompt_int64("History.max_count: ", 1, 200, &history_max)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
    }
    working.history.max_count = static_cast<int>(history_max);
  } else {
    working.history.enable_duplicates = defaults.history.enable_duplicates;
    working.history.max_count = defaults.history.max_count;
  }

  if (!prompt_bool("InlineHint.enable(true/false): ",
                   &working.inline_hint.enable)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
  }
  if (working.inline_hint.enable) {
    int64_t render_delay =
        static_cast<int64_t>(working.inline_hint.render_delay_ms);
    if (!prompt_int64("InlineHint.render_delay_ms: ", 0, 5000, &render_delay)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
    }
    working.inline_hint.render_delay_ms = static_cast<int>(render_delay);

    int64_t search_delay =
        static_cast<int64_t>(working.inline_hint.search_delay_ms);
    if (!prompt_int64("InlineHint.search_delay_ms: ", 0, 5000, &search_delay)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
    }
    working.inline_hint.search_delay_ms = static_cast<int>(search_delay);

    if (!prompt_bool("InlineHint.Path.enable(true/false): ",
                     &working.inline_hint.path.enable)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
    }
    if (working.inline_hint.path.enable) {
      if (!prompt_bool("InlineHint.Path.use_async(true/false): ",
                       &working.inline_hint.path.use_async)) {
        return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
      }
      if (working.inline_hint.path.use_async) {
        int64_t timeout =
            static_cast<int64_t>(working.inline_hint.path.timeout_ms);
        if (!prompt_int64("InlineHint.Path.timeout_ms: ", 1, 300000,
                          &timeout)) {
          return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
        }
        working.inline_hint.path.timeout_ms = static_cast<size_t>(timeout);
      } else {
        working.inline_hint.path.timeout_ms =
            defaults.inline_hint.path.timeout_ms;
      }
    } else {
      working.inline_hint.path = defaults.inline_hint.path;
    }
  } else {
    working.inline_hint = defaults.inline_hint;
  }

  if (!prompt_bool("Complete.Searcher.Path.use_async(true/false): ",
                   &working.complete.path.use_async)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
  }
  if (working.complete.path.use_async) {
    int64_t timeout = static_cast<int64_t>(working.complete.path.timeout_ms);
    if (!prompt_int64("Complete.Searcher.Path.timeout_ms: ", 1, 300000,
                      &timeout)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
    }
    working.complete.path.timeout_ms = static_cast<size_t>(timeout);
  } else {
    working.complete.path.timeout_ms = defaults.complete.path.timeout_ms;
  }

  int64_t highlight_delay = static_cast<int64_t>(working.highlight.delay_ms);
  if (!prompt_int64("Highlight.delay_ms: ", 0, 5000, &highlight_delay) ||
      !prompt_bool("Highlight.Path.enable(true/false): ",
                   &working.highlight.path.enable)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
  }
  working.highlight.delay_ms = static_cast<int>(highlight_delay);
  if (working.highlight.path.enable) {
    int64_t timeout = static_cast<int64_t>(working.highlight.path.timeout_ms);
    if (!prompt_int64("Highlight.Path.timeout_ms: ", 1, 300000, &timeout)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "profile edit canceled");
    }
    working.highlight.path.timeout_ms = static_cast<size_t>(timeout);
  } else {
    working.highlight.path.timeout_ms = defaults.highlight.path.timeout_ms;
  }

  auto profile_document =
      isocline_profile_manager_.profile_manager_.GetInitArg();
  profile_document.set[target] = working;
  AMDomain::prompt::services::NormalizePromptProfileArg(&profile_document);
  isocline_profile_manager_.profile_manager_.SetInitArg(
      std::move(profile_document));

  const std::string current_nickname =
      NormalizeProfileNickname_(isocline_profile_manager_.CurrentNickname());
  if (!current_nickname.empty() && current_nickname == target) {
    return isocline_profile_manager_.ChangeClient(current_nickname);
  }
  return OK;
}

} // namespace AMInterface::prompt

