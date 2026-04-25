#pragma once

#include "application/prompt/PromptHistoryManager.hpp"
#include "application/prompt/PromptProfileManager.hpp"
#include "application/style/StyleAppService.hpp"
#include "domain/prompt/PromptDomainModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/prompt/IsoclineProfile.hpp"

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace AMInterface::prompt {
using AMApplication::prompt::PromptHistoryManager;
using AMApplication::prompt::PromptProfileManager;
using AMApplication::style::StyleConfigManager;
using AMDomain::prompt::PromptProfileSettings;

namespace kvars {
static const std::string inline_hint_key = "ic-hint";
static const std::string default_prompt_key = "ic-prompt";
static const std::string invalid_value_key = "typein_invalid_value";
static const std::string valid_value_key = "typein_valid_value";
static const std::string operation_abort_text = "Operation Abort !";
static const std::string default_profile_name = "*";
} // namespace kvars

class IsoclineProfileManager : NonCopyableNonMovable {
public:
  IsoclineProfileManager(PromptProfileManager &profile_manager,
                         PromptHistoryManager &history_manager,
                         StyleConfigManager &style_config_manager);
  ~IsoclineProfileManager() override;

  ECM Init();
  void AddHistoryEntry(const std::string &line);
  void PersistHistoryEntry(const std::string &line);
  void RemoveLastHistoryEntry();
  void SyncCurrentHistory();
  ECM ChangeClient(const std::string &nickname);
  void SetDefaultCompleter(ic_completer_fun_t *callback,
                           void *data = nullptr);
  void SetDefaultHighlighter(ic_highlight_fun_t *callback,
                             void *data = nullptr);
  [[nodiscard]] std::shared_ptr<IsoclineProfile> CurrentProfile() const;
  [[nodiscard]] std::string CurrentNickname() const;
  [[nodiscard]] PromptProfileSettings CurrentProfileArgs() const;
  [[nodiscard]] std::string AbortStyle() const;

private:
  [[nodiscard]] std::shared_ptr<IsoclineProfile>
  BuildProfile_(const std::string &nickname,
                const PromptProfileSettings &profile_args,
                const AMDomain::style::StyleConfigArg &style_arg,
                const std::vector<std::string> &history_records) const;
  void
  ApplyDefaultBindings_(const std::shared_ptr<IsoclineProfile> &profile) const;

  struct DefaultReadlineBindings {
    ic_completer_fun_t *completer = nullptr;
    void *completer_data = nullptr;
    ic_highlight_fun_t *highlighter = nullptr;
    void *highlighter_data = nullptr;
  };

  PromptProfileManager &profile_manager_;
  PromptHistoryManager &history_manager_;
  StyleConfigManager &style_config_manager_;
  mutable std::mutex profiles_mtx_;
  mutable std::mutex bindings_mtx_;
  std::map<std::string, std::shared_ptr<IsoclineProfile>> profile_cache_ = {};
  std::shared_ptr<IsoclineProfile> current_profile_ = nullptr;
  std::string current_nickname_ = kvars::default_profile_name;
  PromptProfileSettings current_profile_args_ = {};
  DefaultReadlineBindings default_bindings_ = {};
};

} // namespace AMInterface::prompt
