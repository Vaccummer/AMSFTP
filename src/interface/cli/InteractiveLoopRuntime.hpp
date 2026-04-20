#pragma once

#include "foundation/core/DataClass.hpp"
#include "interface/token_analyser/TokenTypeAnalyzer.hpp"

#include <memory>

struct ic_completion_env_s;
using ic_completion_env_t = ic_completion_env_s;

namespace AMInterface::completion {
class CompletionRuntimeAdapter;
class ICompletionRuntime;
} // namespace AMInterface::completion

namespace AMInterface::completer {
class AMCompleteEngine;
} // namespace AMInterface::completer

namespace AMInterface::parser {
class CommandNode;
class TokenAnalyzerRuntimeAdapter;
} // namespace AMInterface::parser

namespace AMInterface::cli {

struct CLIServices;

class InteractiveLoopRuntime final : public NonCopyableNonMovable {
public:
  InteractiveLoopRuntime();
  ~InteractiveLoopRuntime() override;

  ECM Setup(AMInterface::parser::CommandNode &command_tree,
            const CLIServices &managers);

  [[nodiscard]] AMInterface::parser::TokenTypeAnalyzer &TokenAnalyzer() {
    return token_type_analyzer_;
  }

  [[nodiscard]] AMInterface::completer::AMCompleteEngine &CompletionEngine() {
    return *completion_engine_;
  }

private:
  AMInterface::parser::CommandNode *bound_command_tree_ = nullptr;
  std::shared_ptr<AMInterface::parser::TokenAnalyzerRuntimeAdapter>
      analyzer_runtime_ = nullptr;
  std::shared_ptr<AMInterface::completion::CompletionRuntimeAdapter>
      completion_runtime_ = nullptr;
  AMInterface::parser::TokenTypeAnalyzer token_type_analyzer_ = {};
  std::unique_ptr<AMInterface::completer::AMCompleteEngine> completion_engine_ =
      nullptr;
};

} // namespace AMInterface::cli
