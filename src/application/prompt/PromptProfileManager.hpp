#pragma once

#include "domain/prompt/PromptDomainModel.hpp"
#include "application/config/ConfigAppService.hpp"
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

class PromptProfileManager : public AMApplication::config::IConfigSyncPort {
public:
  explicit PromptProfileManager(PromptProfileArg arg = {});
  ~PromptProfileManager() override = default;

  ECM Init();

  [[nodiscard]] PromptProfileArg GetInitArg() const;
  ECM FlushTo(AMApplication::config::ConfigAppService *config_service) override;
  [[nodiscard]] PromptProfileArg ExportConfigSnapshot() const;

  void SetInitArg(PromptProfileArg arg);

  [[nodiscard]] PromptProfileQueryResult
  GetZoneProfile(const std::string &zone) const;

private:
  mutable AMAtomic<PromptProfileArg> init_arg_ = {};
};
} // namespace AMApplication::prompt
