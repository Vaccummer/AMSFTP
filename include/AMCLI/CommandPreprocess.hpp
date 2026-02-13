#pragma once
#include "AMBase/Enum.hpp"
#include "AMManager/Var.hpp"
#include <string>
#include <utility>
#include <vector>

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

  AMCommandPreprocessor() = default;

  static AMCommandPreprocessor &Instance() {
    static AMCommandPreprocessor instance;
    return instance;
  }

  /**
   * @brief Preprocess a raw interactive command line according to rules.
   */
  Result Preprocess(const std::string &input);

  /**
   * @brief Split an interactive command line into CLI argument tokens.
   */
  static std::vector<std::string> SplitCliTokens(const std::string &input);

private:
  AMVarManager &var_manager_ = AMVarManager::Instance();
};
