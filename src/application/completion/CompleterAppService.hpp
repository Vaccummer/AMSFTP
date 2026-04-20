#pragma once

#include "domain/config/ConfigSyncPort.hpp"
#include "domain/completion/CompletionModel.hpp"

namespace AMApplication::completion {

using CompleterArg = AMDomain::completion::CompleterArg;

class CompleterConfigManager final : public AMDomain::config::IConfigSyncPort {
public:
  explicit CompleterConfigManager(CompleterArg arg = {});
  ~CompleterConfigManager() override = default;

  ECM Init();
  [[nodiscard]] CompleterArg GetInitArg() const;
  void SetInitArg(CompleterArg arg);

  ECM FlushTo(AMDomain::config::IConfigStorePort *store) override;

private:
  mutable AMAtomic<CompleterArg> init_arg_ = {};
};

} // namespace AMApplication::completion
