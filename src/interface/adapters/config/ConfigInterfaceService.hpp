#pragma once

#include "application/config/ConfigAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/prompt/ProfileEditor.hpp"
#include "interface/prompt/Prompt.hpp"

namespace AMInterface::config {

class ConfigInterfaceService final : public NonCopyableNonMovable {
public:
  ConfigInterfaceService(
      AMApplication::config::ConfigAppService &config_service,
      AMApplication::host::HostAppService &host_service,
      AMInterface::prompt::PromptIOManager &prompt_io_manager,
      AMApplication::prompt::PromptProfileManager &prompt_profile_manager,
      AMInterface::prompt::IsoclineProfileManager
          &prompt_profile_history_manager);
  ~ConfigInterfaceService() override = default;

  [[nodiscard]] ECM PrintPaths() const;
  [[nodiscard]] ECM CheckLock() const;
  [[nodiscard]] ECM BackupAll() const;
  [[nodiscard]] ECM Export(const std::string &path) const;
  [[nodiscard]] ECM ExportSchema(const std::string &export_dir) const;
  [[nodiscard]] ECM EditProfile(const std::string &nickname);
  [[nodiscard]] ECM GetProfile(const std::vector<std::string> &nicknames);
  [[nodiscard]] ECM CleanProfile();

private:
  AMApplication::config::ConfigAppService &config_service_;
  AMApplication::host::HostAppService &host_service_;
  AMInterface::prompt::PromptIOManager &prompt_io_manager_;
  AMApplication::prompt::PromptProfileManager &prompt_profile_manager_;
  AMInterface::prompt::IsoclineProfileManager &prompt_profile_history_manager_;
  AMInterface::prompt::PromptProfileEditor prompt_profile_editor_;
};

} // namespace AMInterface::config
