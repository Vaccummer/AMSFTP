#pragma once

#include "foundation/core/DataClass.hpp"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::prompt {

using PromptVarMap = std::map<std::string, std::optional<std::string>>;

struct PromptTemplateDiagnostic {
  size_t offset = 0;
  std::string message = "";
};

struct PromptTemplateDiagnostics {
  std::vector<PromptTemplateDiagnostic> items = {};

  [[nodiscard]] bool HasError() const { return !items.empty(); }
};

struct PromptTemplateContext {
  std::string source = {};
};

struct PromptTemplateParseResult {
  PromptTemplateContext context = {};
  PromptVarMap required_vars = {};
  PromptTemplateDiagnostics diagnostics = {};
};

class PromptTemplateInterpreter final : public NonCopyableNonMovable {
public:
  PromptTemplateInterpreter() = default;
  ~PromptTemplateInterpreter() override = default;

  [[nodiscard]] ECMData<PromptTemplateParseResult>
  Parse(const std::string &input) const;

  [[nodiscard]] ECMData<std::string>
  Render(const PromptTemplateContext &context, const PromptVarMap &vars) const;
};

} // namespace AMInterface::prompt
