#include "AMManager/Set.hpp"
#include "AMManager/Host.hpp"
#include <sstream>

using EC = ErrorCode;

namespace {
/**
 * @brief Split a whitespace-separated token list.
 */
std::vector<std::string> SplitTokens_(const std::string &text) {
  std::istringstream iss(text);
  std::vector<std::string> out;
  std::string token;
  while (iss >> token) {
    if (!token.empty()) {
      out.push_back(token);
    }
  }
  return out;
}

/**
 * @brief Return true if nickname is valid for HostSet host entries.
 */
bool ValidateHostSetNickname_(const std::string &nickname) {
  if (nickname.empty() || nickname == hostsetkn::kDefaultHost) {
    return false;
  }
  return configkn::ValidateNickname(nickname);
}

/**
 * @brief Return true if the host name is known by HostManager or is local.
 */
bool HostKnown_(const std::string &nickname) {
  if (AMStr::lowercase(AMStr::Strip(nickname)) == "local") {
    return true;
  }
  return AMHostManager::Instance().HostExists(nickname);
}

/**
 * @brief Prompt and parse one bool value.
 */
bool PromptBool_(AMPromptManager &prompt, const std::string &label,
                 bool current, bool *out_value) {
  if (!out_value) {
    return false;
  }
  while (true) {
    std::string input = current ? "true" : "false";
    if (!prompt.Prompt(label, input, &input)) {
      return false;
    }
    input = AMStr::Strip(input);
    if (input.empty()) {
      *out_value = current;
      return true;
    }
    bool parsed = false;
    if (!StrValueParse(input, &parsed)) {
      prompt.ErrorFormat(Err(EC::InvalidArg, "value must be true/false"));
      continue;
    }
    *out_value = parsed;
    return true;
  }
}

/**
 * @brief Prompt and parse one positive size_t value.
 */
bool PromptPositiveSizeT_(AMPromptManager &prompt, const std::string &label,
                          size_t current, size_t *out_value) {
  if (!out_value) {
    return false;
  }
  while (true) {
    std::string input = std::to_string(current);
    if (!prompt.Prompt(label, input, &input)) {
      return false;
    }
    input = AMStr::Strip(input);
    if (input.empty()) {
      if (current == 0) {
        prompt.ErrorFormat(
            Err(EC::InvalidArg, "value must be a positive integer"));
        continue;
      }
      *out_value = current;
      return true;
    }
    int64_t parsed = 0;
    if (!StrValueParse(input, &parsed) || parsed <= 0) {
      prompt.ErrorFormat(
          Err(EC::InvalidArg, "value must be a positive integer"));
      continue;
    }
    *out_value = static_cast<size_t>(parsed);
    return true;
  }
}
} // namespace

/**
 * @brief Prompt a full typed path-set payload.
 */
ECM AMSetCLI::PromptPathSet_(const std::string &nickname,
                             const AMHostSetPathConfig &base,
                             AMHostSetPathConfig *output) const {
  if (!output) {
    return Err(EC::InvalidArg, "null output config");
  }
  output->use_async = base.use_async;
  output->use_cache = base.use_cache;
  output->cache_items_threshold = base.cache_items_threshold;
  output->cache_max_entries = base.cache_max_entries;
  output->timeout_ms = base.timeout_ms;
  output->highlight_use_check = base.highlight_use_check;
  output->highlight_timeout_ms = base.highlight_timeout_ms;

  auto print_abort = [this]() {
    prompt_.Print(AMConfigManager::Instance().Format("Input Abort", "abort"));
  };

  prompt_.Print(AMStr::amfmt("HostSet ({})",
                             AMConfigManager::Instance().Format(nickname, "nickname")));
  if (!PromptBool_(prompt_, "CompleteOption.Searcher.Path.use_async: ",
                   output->use_async, &output->use_async)) {
    print_abort();
    return Err(EC::ConfigCanceled, "set prompt canceled");
  }
  if (!PromptBool_(prompt_, "CompleteOption.Searcher.Path.use_cache: ",
                   output->use_cache, &output->use_cache)) {
    print_abort();
    return Err(EC::ConfigCanceled, "set prompt canceled");
  }

  if (!PromptPositiveSizeT_(
          prompt_, "CompleteOption.Searcher.Path.cache_items_threshold: ",
          output->cache_items_threshold, &output->cache_items_threshold)) {
    print_abort();
    return Err(EC::ConfigCanceled, "set prompt canceled");
  }

  if (!PromptPositiveSizeT_(
          prompt_, "CompleteOption.Searcher.Path.cache_max_entries: ",
          output->cache_max_entries, &output->cache_max_entries)) {
    print_abort();
    return Err(EC::ConfigCanceled, "set prompt canceled");
  }

  if (!PromptPositiveSizeT_(prompt_, "CompleteOption.Searcher.Path.timeout_ms: ",
                            output->timeout_ms, &output->timeout_ms)) {
    print_abort();
    return Err(EC::ConfigCanceled, "set prompt canceled");
  }
  if (!PromptBool_(prompt_, "Highlight.Path.use_check: ",
                   output->highlight_use_check, &output->highlight_use_check)) {
    print_abort();
    return Err(EC::ConfigCanceled, "set prompt canceled");
  }
  if (!PromptPositiveSizeT_(prompt_, "Highlight.Path.timeout_ms: ",
                            output->highlight_timeout_ms,
                            &output->highlight_timeout_ms)) {
    print_abort();
    return Err(EC::ConfigCanceled, "set prompt canceled");
  }
  return Ok();
}

/**
 * @brief Create one host set using interactive prompts.
 */
ECM AMSetCLI::Add(const std::string &nickname) {
  const std::string target = AMStr::Strip(nickname);
  if (!ValidateHostSetNickname_(target)) {
    return Err(EC::InvalidArg, "invalid host nickname");
  }
  if (!HostKnown_(target)) {
    return Err(EC::HostConfigNotFound, "host nickname not found");
  }
  if (HasHostSet(target)) {
    return Err(EC::KeyAlreadyExists, "host set already exists");
  }

  AMHostSetPathConfig cfg = ResolvePathSet(target).value;
  ECM rcm = PromptPathSet_(target, cfg, &cfg);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  rcm = CreateHostSet(target, cfg, false);
  if (rcm.first != EC::Success) {
    prompt_.ErrorFormat(rcm);
    return rcm;
  }
  rcm = SaveSettings();
  if (rcm.first != EC::Success) {
    prompt_.ErrorFormat(rcm);
    return rcm;
  }
  prompt_.Print(AMStr::amfmt("hostset added: {}",
                             AMConfigManager::Instance().Format(target, "nickname")));
  return Ok();
}

/**
 * @brief Modify one host set using interactive prompts.
 */
ECM AMSetCLI::Modify(const std::string &nickname) {
  const std::string target = AMStr::Strip(nickname);
  if (!ValidateHostSetNickname_(target)) {
    return Err(EC::InvalidArg, "invalid host nickname");
  }
  if (!HasHostSet(target)) {
    return Err(EC::HostConfigNotFound, "host set not found");
  }

  AMHostSetPathConfig cfg = ResolvePathSet(target).value;
  ECM rcm = PromptPathSet_(target, cfg, &cfg);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  rcm = ModifyHostSet(target, cfg, false);
  if (rcm.first != EC::Success) {
    prompt_.ErrorFormat(rcm);
    return rcm;
  }
  rcm = SaveSettings();
  if (rcm.first != EC::Success) {
    prompt_.ErrorFormat(rcm);
    return rcm;
  }
  prompt_.Print(
      AMStr::amfmt("hostset updated: {}",
                   AMConfigManager::Instance().Format(target, "nickname")));
  return Ok();
}

/**
 * @brief Delete one host set entry.
 */
ECM AMSetCLI::Delete(const std::string &nickname) {
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host nickname");
  }
  return Delete(SplitTokens_(nickname));
}

/**
 * @brief Delete multiple host set entries.
 */
ECM AMSetCLI::Delete(const std::vector<std::string> &targets) {
  std::vector<std::string> deduped = VectorDedup(targets);
  std::vector<std::string> valid_targets;
  valid_targets.reserve(deduped.size());
  ECM last = Ok();

  for (const std::string &raw : deduped) {
    const std::string target = AMStr::Strip(raw);
    if (!ValidateHostSetNickname_(target)) {
      last = Err(EC::InvalidArg, AMStr::amfmt("invalid host nickname: {}", raw));
      prompt_.ErrorFormat(last);
      continue;
    }
    if (!HasHostSet(target)) {
      last = Err(EC::HostConfigNotFound,
                 AMStr::amfmt("host set not found: {}", target));
      prompt_.ErrorFormat(last);
      continue;
    }
    valid_targets.push_back(target);
  }

  if (valid_targets.empty()) {
    return last;
  }

  std::string listing;
  for (size_t i = 0; i < valid_targets.size(); ++i) {
    if (i > 0) {
      listing += ", ";
    }
    listing += AMConfigManager::Instance().Format(valid_targets[i], "nickname");
  }

  bool canceled = false;
  bool confirmed = prompt_.PromptYesNo(
      AMStr::amfmt("Delete {} hostset(s): {} ? (y/N): ", valid_targets.size(),
                   listing),
      &canceled);
  if (canceled || !confirmed) {
    prompt_.Print("Delete aborted.");
    return Ok();
  }

  bool changed = false;
  for (const std::string &target : valid_targets) {
    ECM rcm = DeleteHostSet(target);
    if (rcm.first != EC::Success) {
      prompt_.ErrorFormat(rcm);
      last = rcm;
      continue;
    }
    changed = true;
  }

  if (!changed) {
    return last;
  }
  ECM save_rcm = SaveSettings();
  if (save_rcm.first != EC::Success) {
    prompt_.ErrorFormat(save_rcm);
    return save_rcm;
  }
  return last;
}

/**
 * @brief Persist cached HostSet data to settings.toml.
 */
ECM AMSetCLI::SaveSettings() { return Save(true); }
