#pragma once

#include "interface/token_analyser/model/RawToken.hpp"
#include <string>
#include <vector>

namespace AMInterface::parser::lexer {

class ShellTokenLexer {
public:
  /**
   * @brief Split input with whitespace/quote/backtick shell rules.
   */
  static std::vector<AMInterface::parser::model::RawToken>
  Split(const std::string &input);
};

} // namespace AMInterface::parser::lexer


