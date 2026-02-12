#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include "Isocline/isocline.h"
#include <string>

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

/**
 * @brief Enable or disable history navigation for arrow keys.
 */
void AMHistoryManager::SetHistoryEnabled(bool enabled) {
  history_enabled_ = enabled;
}

/**
 * @brief Collect current history into a list.
 */
void AMHistoryManager::CollectHistory_() {
  Json jsond;
  if (!config_.GetJson(DocumentKind::History, &jsond)) {
    return;
  }
  if (!jsond.is_object()) {
    return;
  }
  for (auto it = jsond.begin(); it != jsond.end(); ++it) {
    const std::string &nickname = it.key();
    const auto &node = it.value();
    if (!node.is_object()) {
      continue;
    }
    auto cmd_it = node.find("commands");
    if (cmd_it == node.end() || !cmd_it->is_array()) {
      continue;
    }
    history_map_[nickname] = std::vector<std::string>{};
    for (const auto &item : *cmd_it) {
      if (item.is_string()) {
        history_map_[nickname].push_back(item.get<std::string>());
      }
    }
  }
}

/**
 * @brief Load history for a nickname into the readline history.
 */
ECM AMHistoryManager::LoadHistory(const std::string &nickname) {
  if (nickname.empty()) {
    return {EC::InvalidArg, "empty history nickname"};
  }

  if (history_loaded_ && history_nickname_ == nickname) {
    return Ok();
  }
  history_map_[nickname] = GetIsoRecords();
  ic_set_history(nullptr, max_history_count_);
  ic_enable_history_duplicates(true);
  ic_history_clear();

  history_nickname_ = nickname;

  if (history_map_.find(nickname) == history_map_.end()) {
    return Err(EC::HostConfigNotFound,
               "input history not found for nickname: " + nickname);
  }

  for (const auto &cmd : history_map_[nickname]) {
    ic_history_add(cmd.c_str());
  }
  return Ok();
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
  ic_history_add(line.c_str());
}

/**
 * @brief Flush current history back into TOML File.
 */
void AMHistoryManager::FlushHistory() {
  if (!history_loaded_) {
    return;
  }
  if (!history_nickname_.empty()) {
    history_map_[history_nickname_] = std::move(GetIsoRecords());
  }
  Json jsond = Json::object();
  for (const auto &pair : history_map_) {
    jsond[pair.first]["commands"] = pair.second;
  }
  config_.SetArg(DocumentKind::History, {}, jsond);
  config_.Dump(DocumentKind::History, "", true);
}
