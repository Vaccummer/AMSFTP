#pragma once

#include "interface/token_analyser/model/RawToken.hpp"
#include <memory>
#include <string>
#include <vector>

namespace AMInterface::parser {
class CommandNode;
class ITokenAnalyzerRuntime;
}

namespace AMInterface::parser::semantic {

class SemanticAnalyzer {
public:
  inline SemanticAnalyzer(
      const AMInterface::parser::CommandNode *command_tree,
      std::shared_ptr<AMInterface::parser::ITokenAnalyzerRuntime> runtime)
      : command_tree_(command_tree), runtime_(std::move(runtime)) {}

  [[nodiscard]] std::vector<AMInterface::parser::model::RawToken>
  Classify(const std::string &input,
           const std::vector<AMInterface::parser::model::RawToken>
               &split_tokens) const;

private:
  const AMInterface::parser::CommandNode *command_tree_ = nullptr;
  std::shared_ptr<AMInterface::parser::ITokenAnalyzerRuntime> runtime_ =
      nullptr;
};

} // namespace AMInterface::parser::semantic


