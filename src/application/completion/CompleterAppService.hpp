#pragma once

#include "application/config/ConfigAppService.hpp"
#include "domain/completion/CompletionModel.hpp"

namespace AMApplication::completion {

using CompleterArg = AMDomain::completion::CompleterArg;

class CompleterConfigManager final : public AMApplication::config::IConfigSyncPort {
public:
  explicit CompleterConfigManager(CompleterArg arg = {});
  ~CompleterConfigManager() override = default;

  ECM Init();
  [[nodiscard]] CompleterArg GetInitArg() const;
  void SetInitArg(CompleterArg arg);

  ECM FlushTo(AMApplication::config::ConfigAppService *config_service) override;
  [[nodiscard]] CompleterArg ExportConfigSnapshot() const;

private:
  mutable AMAtomic<CompleterArg> init_arg_ = {};
};

} // namespace AMApplication::completion

