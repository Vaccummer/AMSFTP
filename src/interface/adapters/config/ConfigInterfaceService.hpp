#pragma once

#include "application/config/ConfigAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/prompt/Prompt.hpp"

namespace AMInterface::config {

class ConfigInterfaceService final : public NonCopyableNonMovable {
public:
  ConfigInterfaceService(AMApplication::config::ConfigAppService &config_service,
                         AMInterface::prompt::AMPromptIOManager &prompt_io_manager);
  ~ConfigInterfaceService() override = default;

  ECM PrintPaths() const;
  ECM SaveAll() const;
  ECM BackupAll() const;

private:
  AMApplication::config::ConfigAppService &config_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
};

} // namespace AMInterface::config
