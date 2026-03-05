#include "application/var/VarWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"

namespace AMApplication::VarWorkflow {
/**
 * @brief Execute `var get` workflow.
 */
ECM ExecuteVarGet(const IVarGateway &gateway, const std::string &varname) {
  return gateway.QueryByName(varname);
}

/**
 * @brief Execute `var def` workflow.
 */
ECM ExecuteVarDef(const IVarGateway &gateway, bool global,
                  const std::string &varname, const std::string &value) {
  return gateway.DefineVar(global, varname, value);
}

/**
 * @brief Execute `var del` workflow.
 */
ECM ExecuteVarDel(const IVarGateway &gateway, bool all,
                  const std::vector<std::string> &tokens) {
  std::string section = "";
  std::string varname = "";
  if (tokens.size() == 1) {
    varname = tokens[0];
  } else if (tokens.size() == 2) {
    section = tokens[0];
    varname = tokens[1];
  } else {
    return Err(EC::InvalidArg, "var del requires: [$section] $varname");
  }
  return gateway.DeleteVarByCli(all, section, varname);
}

/**
 * @brief Execute `var ls` workflow.
 */
ECM ExecuteVarLs(const IVarGateway &gateway,
                 const std::vector<std::string> &sections) {
  return gateway.ListVars(sections);
}
} // namespace AMApplication::VarWorkflow
