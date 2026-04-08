#pragma once

#include "application/config/ConfigAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/prompt/Prompt.hpp"

namespace AMInterface::config {

class ConfigInterfaceService final : public NonCopyableNonMovable {
public:
  ConfigInterfaceService(
      AMApplication::config::ConfigAppService &config_service,
      AMApplication::host::HostAppService &host_service,
      AMInterface::prompt::AMPromptIOManager &prompt_io_manager);
  ~ConfigInterfaceService() override = default;

  ECM PrintPaths() const;
  ECM SaveAll() const;
  ECM BackupAll() const;
  ECM Export(const std::string &path) const;
  ECM EditProfile(const std::string &nickname) const;
  ECM GetProfile(const std::vector<std::string> &nicknames) const;

private:
  AMApplication::config::ConfigAppService &config_service_;
  AMApplication::host::HostAppService &host_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
};

} // namespace AMInterface::config
