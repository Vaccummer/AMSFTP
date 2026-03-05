#pragma once

#include "foundation/DataClass.hpp"
#include <string>
#include <vector>

namespace AMApplication::VarWorkflow {
/**
 * @brief Application port for variable-related command operations.
 */
class IVarGateway {
public:
  /**
   * @brief Virtual destructor for polymorphic gateway.
   */
  virtual ~IVarGateway() = default;

  /**
   * @brief Query one variable by token name.
   */
  virtual ECM QueryByName(const std::string &token_name) const = 0;

  /**
   * @brief Define one variable.
   */
  virtual ECM DefineVar(bool global, const std::string &name,
                        const std::string &value) const = 0;

  /**
   * @brief Delete one variable by CLI parameters.
   */
  virtual ECM DeleteVarByCli(bool all, const std::string &section,
                             const std::string &varname) const = 0;

  /**
   * @brief List variables by domain filters.
   */
  virtual ECM ListVars(const std::vector<std::string> &domains) const = 0;
};

/**
 * @brief Execute `var get` workflow.
 */
ECM ExecuteVarGet(const IVarGateway &gateway, const std::string &varname);

/**
 * @brief Execute `var def` workflow.
 */
ECM ExecuteVarDef(const IVarGateway &gateway, bool global,
                  const std::string &varname, const std::string &value);

/**
 * @brief Execute `var del` workflow.
 */
ECM ExecuteVarDel(const IVarGateway &gateway, bool all,
                  const std::vector<std::string> &tokens);

/**
 * @brief Execute `var ls` workflow.
 */
ECM ExecuteVarLs(const IVarGateway &gateway,
                 const std::vector<std::string> &sections);
} // namespace AMApplication::VarWorkflow
