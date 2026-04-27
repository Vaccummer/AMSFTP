#pragma once

#include "domain/prompt/PromptDomainModel.hpp"
#include "foundation/core/DataClass.hpp"

#include <filesystem>

namespace AMApplication::prompt {
using PromptHistoryArg = AMDomain::prompt::PromptHistoryArg;

struct PromptHistoryQueryResult {
  std::string request_zone = {};
  std::string resolved_zone = {};
  bool from_fallback = false;
  bool allow_continuous_duplicates = false;
  int max_count = 50;
  std::vector<std::string> history = {};
};

class PromptHistoryManager : public NonCopyableNonMovable {
public:
  explicit PromptHistoryManager(PromptHistoryArg arg = {},
                                std::filesystem::path project_root = {});
  ~PromptHistoryManager() override = default;

  ECM Init();

  [[nodiscard]] PromptHistoryArg GetInitArg() const;

  void SetInitArg(PromptHistoryArg arg);

  [[nodiscard]] ECMData<PromptHistoryQueryResult>
  GetZoneHistory(const std::string &zone) const;

  ECM SetZoneHistory(const std::string &zone, std::vector<std::string> history);

  ECM AppendZoneHistory(const std::string &zone, const std::string &entry);

  ECM ClearZoneHistory(const std::string &zone);

private:
  [[nodiscard]] std::filesystem::path
  ResolveHistoryPath_(const std::string &zone) const;

  mutable AMAtomic<PromptHistoryArg> init_arg_ = {};
  std::filesystem::path project_root_ = {};
};
} // namespace AMApplication::prompt
