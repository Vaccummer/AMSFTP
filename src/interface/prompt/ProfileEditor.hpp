#pragma once

#include "interface/prompt/Prompt.hpp"

namespace AMInterface::prompt {

class PromptProfileEditor final : public NonCopyableNonMovable {
public:
  PromptProfileEditor(PromptIOManager &prompt_io_manager,
                      PromptProfileManager &prompt_profile_manager,
                      IsoclineProfileManager &profile_runtime_manager)
      : prompt_io_manager_(prompt_io_manager),
        prompt_profile_manager_(prompt_profile_manager),
        profile_runtime_manager_(profile_runtime_manager) {}
  ~PromptProfileEditor() override = default;

  [[nodiscard]] ECM Edit(const std::string &nickname);
  [[nodiscard]] ECM Get(const std::vector<std::string> &nicknames);

private:
  [[nodiscard]] ECM EditProfile_(const std::string &nickname);

  PromptIOManager &prompt_io_manager_;
  PromptProfileManager &prompt_profile_manager_;
  IsoclineProfileManager &profile_runtime_manager_;
};

} // namespace AMInterface::prompt
