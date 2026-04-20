#pragma once

#include "foundation/core/DataClass.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <variant>

namespace AMInterface::prompt {

using PromptVarValue =
    std::variant<std::monostate, std::string, bool, int64_t, double>;
using PromptVarMap = std::map<std::string, PromptVarValue>;

struct PromptTemplateContext {
  std::string source = {};
};

[[nodiscard]] ECMData<std::string>
LUARender(const PromptTemplateContext &context, const PromptVarMap &vars);

} // namespace AMInterface::prompt
