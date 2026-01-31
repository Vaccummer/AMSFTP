#pragma once
#include "AMBase/Enum.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Var.hpp"
#include <string>
#include <utility>

class AMCommandPreprocessor {
public:
  using ECM = std::pair<ErrorCode, std::string>;

  enum class Action { NoOp, Shell, Cli, Handled };

  struct Result {
    ECM rcm = {ErrorCode::Success, ""};
    Action action = Action::NoOp;
    std::string command;
    bool async = false;
  };

  /**
   * @brief Construct a command preprocessor bound to a config manager.
   */
  explicit AMCommandPreprocessor(AMConfigManager &config_manager);

  /**
   * @brief Preprocess a raw interactive command line according to rules.
   */
  Result Preprocess(const std::string &input);

private:
  AMVarManager &var_manager_;
};
