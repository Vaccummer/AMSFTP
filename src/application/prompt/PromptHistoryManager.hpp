#pragma once

#include "domain/config/ConfigSyncPort.hpp"
#include "domain/prompt/PromptDomainModel.hpp"
#include "foundation/core/DataClass.hpp"


namespace AMApplication::prompt {
using PromptHistoryArg = AMDomain::prompt::PromptHistoryArg;

struct PromptHistoryQueryResult {
  std::string request_zone = {};
  std::string resolved_zone = {};
  bool from_fallback = false;
  std::vector<std::string> history = {};
};

class PromptHistoryManager : public AMDomain::config::IConfigSyncPort {
public:
  explicit PromptHistoryManager(PromptHistoryArg arg = {});
  ~PromptHistoryManager() override = default;

  ECM Init();

  [[nodiscard]] PromptHistoryArg GetInitArg() const;
  ECM FlushTo(AMDomain::config::IConfigStorePort *store) override;

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
