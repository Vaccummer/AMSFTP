#pragma once

#include "foundation/core/DataClass.hpp"
#include "interface/highlight/InputHighlighter.hpp"
#include "interface/input_analysis/InputAnalyzer.hpp"

#include <memory>

struct ic_completion_env_s;
using ic_completion_env_t = ic_completion_env_s;

namespace AMInterface::completer {
class AMCompleteEngine;
} // namespace AMInterface::completer

namespace AMInterface::input {
class InputSemanticRuntimeAdapter;
}
namespace AMInterface::parser {
class CommandNode;
}

namespace AMInterface::cli {

struct CLIServices;

class InteractiveLoopRuntime final : public NonCopyableNonMovable {
public:
  InteractiveLoopRuntime();
  ~InteractiveLoopRuntime() override;

  ECM Setup(AMInterface::parser::CommandNode &command_tree,
            const CLIServices &managers);

  [[nodiscard]] AMInterface::input::InputAnalyzer &Analyzer() {
    return input_analyzer_;
  }

  [[nodiscard]] AMInterface::completer::AMCompleteEngine &CompletionEngine() {
    return *completion_engine_;
  }

private:
  AMInterface::parser::CommandNode *bound_command_tree_ = nullptr;
  std::shared_ptr<AMInterface::input::InputSemanticRuntimeAdapter> runtime_ =
      nullptr;
  AMInterface::input::InputAnalyzer input_analyzer_ = {};
  AMInterface::highlight::InputHighlighter input_highlighter_ = {};
  std::unique_ptr<AMInterface::completer::AMCompleteEngine> completion_engine_ =
      nullptr;
};

} // namespace AMInterface::cli
