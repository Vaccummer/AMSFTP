#pragma once

#include "domain/config/ConfigSyncPort.hpp"
#include "domain/prompt/PromptDomainModel.hpp"
#include "foundation/core/DataClass.hpp"

namespace AMApplication::prompt {
using PromptProfileArg = AMDomain::prompt::PromptProfileArg;
using PromptProfileSettings = AMDomain::prompt::PromptProfileSettings;

struct PromptProfileQueryResult {
  std::string request_zone = {};
  std::string resolved_zone = {};
  bool from_fallback = false;
  PromptProfileSettings profile = {};
};

class PromptProfileManager : public AMDomain::config::IConfigSyncPort {
public:
  explicit PromptProfileManager(PromptProfileArg arg = {});
  ~PromptProfileManager() override = default;

  ECM Init();

  [[nodiscard]] PromptProfileArg GetInitArg() const;
  ECM FlushTo(AMDomain::config::IConfigStorePort *store) override;

  void SetInitArg(PromptProfileArg arg);

  [[nodiscard]] PromptProfileQueryResult
  GetZoneProfile(const std::string &zone) const;

private:
  mutable AMAtomic<PromptProfileArg> init_arg_ = {};
};
} // namespace AMApplication::prompt
