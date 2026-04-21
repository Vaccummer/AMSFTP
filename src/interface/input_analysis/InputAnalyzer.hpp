#pragma once

#include "foundation/core/DataClass.hpp"
#include "interface/input_analysis/InputAnalysis.hpp"
#include "interface/input_analysis/runtime/InputSemanticRuntime.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace AMInterface::parser {
class CommandNode;
}

namespace AMInterface::input {

class InputAnalyzer final : public NonCopyableNonMovable {
public:
  using RawToken = AMInterface::input::model::RawToken;

  InputAnalyzer() = default;
  explicit InputAnalyzer(InputSemanticRuntimePtr runtime)
      : runtime_(std::move(runtime)) {}
  ~InputAnalyzer() override = default;

  void SetCommandTree(const AMInterface::parser::CommandNode *command_tree) {
    command_tree_ = command_tree;
  }
  [[nodiscard]] const AMInterface::parser::CommandNode *CommandTree() const {
    return command_tree_;
  }

  void SetRuntime(InputSemanticRuntimePtr runtime) {
    runtime_ = std::move(runtime);
  }
  [[nodiscard]] InputSemanticRuntimePtr Runtime() const { return runtime_; }

  [[nodiscard]] std::vector<RawToken>
  SplitTokens(const std::string &input) const;
  [[nodiscard]] InputAnalysis Analyze(const std::string &input) const;
  void ClearTokenCache();

private:
  const AMInterface::parser::CommandNode *command_tree_ = nullptr;
  InputSemanticRuntimePtr runtime_ = nullptr;
  mutable AMAtomic<std::unordered_map<std::string, std::vector<RawToken>>>
      split_token_cache_ = {};
};

} // namespace AMInterface::input
