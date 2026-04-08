#pragma once
#include "foundation/core/DataClass.hpp"
#include "Isocline/isocline.h"
#include "interface/token_analyser/TokenAnalyzerRuntime.hpp"
#include "interface/token_analyser/model/RawToken.hpp"
#include <functional>
#include <memory>
#include <string>
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
  void SetCommandTree(const CommandNode *command_tree) {
    command_tree_ = command_tree;
  }
  void SetRuntime(std::shared_ptr<ITokenAnalyzerRuntime> runtime) {
    runtime_ = std::move(runtime);
  }
  [[nodiscard]] std::shared_ptr<ITokenAnalyzerRuntime> Runtime() const {
    return runtime_;
  }

  /**
   * @brief Build a bbcode-formatted string for isocline highlighting.
   */
  void HighlightFormatted(const std::string &input, std::string *formatted);

  /**
   * @brief Deprecated no-op; nickname checks are realtime.
   */
  void RefreshNicknameCache();

  static void PromptHighlighter_(ic_highlight_env_t *henv, const char *input,
                                 void *arg);

  /**
   * @brief Split input into shell-level tokens (whitespace/quotes only).
   *
   * This function does not perform style/semantic classification.
   */
  std::vector<AMToken> SplitToken(const std::string &input) const;

  /**
   * @brief Clear SplitToken/TokenizeStyle caches.
   */
  static void ClearTokenCache();

private:
  std::vector<AMToken> TokenizeStyle(const std::string &input);
  bool ParseVarTokenAt(const std::string &input, size_t pos, size_t limit,
                       size_t *out_end) const;
  bool ParseVarTokenText(const std::string &token,
                         std::string *out_name = nullptr) const;

  [[nodiscard]] AMTokenType VarNameTypeFor(const std::string &name) const;

  bool IsValidOptionToken(const std::string &token,
                          const CommandNode *node) const;
  [[nodiscard]] int PriorityForType(AMTokenType type) const;

  const CommandNode *command_tree_ = nullptr;
  std::shared_ptr<ITokenAnalyzerRuntime> runtime_ = nullptr;
};

} // namespace AMInterface::parser

