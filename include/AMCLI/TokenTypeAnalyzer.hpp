#pragma once
#include "AMBase/DataClass.hpp"
#include "Isocline/isocline.h"
#include <string>
#include <vector>

class CommandNode;

class AMTokenTypeAnalyzer : public NonCopyableNonMovable {
public:
  /**
   * @brief Token parsed from input split stage.
   */
  struct AMToken {
    size_t start = 0;
    size_t end = 0;
    size_t content_start = 0;
    size_t content_end = 0;
    bool quoted = false;
    AMTokenType type = AMTokenType::Unset;
  };

  /**
   * @brief Construct a token analyzer bound to the config manager.
   */
  static AMTokenTypeAnalyzer &Instance() {
    static AMTokenTypeAnalyzer ins;
    return ins;
  }

  ~AMTokenTypeAnalyzer() override = default;

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
  static std::vector<AMToken> SplitToken(const std::string &input);

  /**
   * @brief Clear SplitToken/TokenizeStyle caches.
   */
  static void ClearTokenCache();

private:
  AMTokenTypeAnalyzer() = default;

  void EnsureCliCache();
  void BuildCliCache();

  std::vector<AMToken> TokenizeStyle(const std::string &input);
  bool ParseVarTokenAt(const std::string &input, size_t pos, size_t limit,
                       size_t *out_end) const;
  bool ParseVarTokenText(const std::string &token,
                         std::string *out_name = nullptr) const;

  [[nodiscard]] AMTokenType VarNameTypeFor(const std::string &name) const;

  bool IsValidOptionToken(const std::string &token,
                          const CommandNode *node) const;
  [[nodiscard]] int PriorityForType(AMTokenType type) const;

  bool cli_cache_ready_ = false;
};
