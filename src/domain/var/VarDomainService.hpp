#pragma once
#include "foundation/core/Enum.hpp"
#include <string>

namespace AMDomain::var {
using ECM = std::pair<ErrorCode, std::string>;

inline bool IsValidVarname(std::string_view varname) {
  if (varname.empty()) {
    return false;
  }
  for (const auto &ch : varname) {
    if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_') {
      continue;
    }
    return false;
  }
  return true;
}

} // namespace AMDomain::var
