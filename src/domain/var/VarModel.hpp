#pragma once
#include "foundation/core/Enum.hpp"
#include <map>
#include <string>

namespace AMDomain::var {
using VarSet = std::map<std::string, std::map<std::string, std::string>>;
inline constexpr const char *kRoot = "UserVars";
inline constexpr const char *kPublic = "*";

/**
 * @brief Single variable record identified by domain + var name.
 */
struct VarInfo {
  std::string domain = "";
  std::string varname = "";
  std::string varvalue = "";

  /**
   * @brief Return true when this variable belongs to public domain.
   */
  [[nodiscard]] bool IsPublic() const { return domain == kPublic; }
};

struct VarSetArg {
  VarSet set = {};
};

/**
 * @brief Parsed variable token model shared by interface/domain utilities.
 */
struct ParsedVarToken {
  bool valid = false;
  bool explicit_domain = false;
  bool braced = false;
  std::string domain = "";
  std::string varname = "";
};

using VarRef = ParsedVarToken;
} // namespace AMDomain::var
