#pragma once

#include "domain/prompt/PromptDomainModel.hpp"
#include "application/config/ConfigAppService.hpp"
#include "foundation/core/DataClass.hpp"

namespace AMApplication::prompt {
using PromptHistoryArg = AMDomain::prompt::PromptHistoryArg;

struct PromptHistoryQueryResult {
  std::string request_zone = {};
  std::string resolved_zone = {};
  bool from_fallback = false;
  std::vector<std::string> history = {};
};

class PromptHistoryManager : public AMApplication::config::IConfigSyncPort {
public:
  explicit PromptHistoryManager(PromptHistoryArg arg = {});
  ~PromptHistoryManager() override = default;

  ECM Init();

  [[nodiscard]] PromptHistoryArg GetInitArg() const;
  ECM FlushTo(AMApplication::config::ConfigAppService *config_service) override;
  [[nodiscard]] PromptHistoryArg ExportConfigSnapshot() const;

  void SetInitArg(PromptHistoryArg arg);

  [[nodiscard]] ECMData<PromptHistoryQueryResult>
  GetZoneHistory(const std::string &zone) const;

  ECM SetZoneHistory(const std::string &zone, std::vector<std::string> history);

  ECM AppendZoneHistory(const std::string &zone, const std::string &entry);

  ECM ClearZoneHistory(const std::string &zone);

private:
  mutable AMAtomic<PromptHistoryArg> init_arg_ = {};
};
} // namespace AMApplication::prompt
