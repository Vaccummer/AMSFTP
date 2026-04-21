#pragma once
#include <map>
#include <string>

namespace AMDomain::var {
struct ParsedVarToken;
using VarSet = std::map<std::string, std::map<std::string, std::string>>;
using VarRef = ParsedVarToken;
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

} // namespace AMDomain::var
