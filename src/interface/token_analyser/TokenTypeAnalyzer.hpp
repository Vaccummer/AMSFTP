#pragma once
#include "Isocline/isocline.h"
#include "foundation/core/DataClass.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntime.hpp"
#include "interface/token_analyser/model/RawToken.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace AMInterface::parser {

class CommandNode;

class TokenTypeAnalyzer : public NonCopyableNonMovable {
public:
  using AMToken = AMInterface::parser::model::RawToken;

  ~TokenTypeAnalyzer() override = default;
  TokenTypeAnalyzer() = default;
  explicit TokenTypeAnalyzer(std::shared_ptr<ITokenAnalyzerRuntime> runtime)
      : runtime_(std::move(runtime)) {}

  /**
   * @brief Set command tree used by highlight/semantic routing.
   */
  inline void SetCommandTree(const CommandNode *command_tree) {
    command_tree_ = command_tree;
  }
  [[nodiscard]] inline const CommandNode *CommandTree() const {
    return command_tree_;
  }
  inline void SetRuntime(std::shared_ptr<ITokenAnalyzerRuntime> runtime) {
    runtime_ = std::move(runtime);
  }
  [[nodiscard]] inline std::shared_ptr<ITokenAnalyzerRuntime> Runtime() const {
    return runtime_;
  }

  /**
   * @brief Build a bbcode-formatted string for isocline highlighting.
   */
  void HighlightFormatted(const std::string &input, std::string *formatted);

  static void PromptHighlighter_(ic_highlight_env_t *henv, const char *input,
                                 void *arg);

  /**
   * @brief Split input into shell-level tokens (whitespace/quotes only).
   *
   * This function does not perform style/semantic classification.
   */
  [[nodiscard]] std::vector<AMToken> SplitToken(const std::string &input) const;

  /**
   * @brief Clear tokenizer caches.
   */
  void ClearTokenCache();

private:
  const CommandNode *command_tree_ = nullptr;
  std::shared_ptr<ITokenAnalyzerRuntime> runtime_ = nullptr;
  mutable AMAtomic<std::unordered_map<std::string, std::vector<AMToken>>>
      split_token_cache_ = {};
};

} // namespace AMInterface::parser
