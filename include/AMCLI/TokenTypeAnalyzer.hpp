#pragma once
#include "AMBase/DataClass.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Var.hpp"
#include <string>
#include <unordered_set>
#include <vector>

class AMTokenTypeAnalyzer : public NonCopyableNonMovable {
public:
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
   * @brief Refresh nickname cache from host manager.
   */
  void RefreshNicknameCache();

  static void PromptHighlighter_(ic_highlight_env_t *henv, const char *input,
                                 void *arg);

private:
  struct Token {
    size_t start = 0;
    size_t end = 0;
    bool quoted = false;
  };

  using CommandNode = CommandTree::CommandNode;

  AMTokenTypeAnalyzer() = default;

  void EnsureCliCache();
  void BuildCliCache();

  std::vector<Token> Tokenize(const std::string &input) const;
  bool ParseVarTokenAt(const std::string &input, size_t pos, size_t limit,
                       size_t *out_end) const;
  bool ParseVarTokenText(const std::string &token) const;
  bool ParseVarTokenText(const std::string &token, std::string *out_name) const;

  AMTokenType VarNameTypeFor(const std::string &name) const;

  bool IsValidOptionToken(const std::string &token,
                          const CommandNode *node) const;
  int PriorityForType(AMTokenType type) const;

  AMConfigManager &config_manager_ = AMConfigManager::Instance();
  AMVarManager &var_manager_ = AMVarManager::Instance();
  bool cli_cache_ready_ = false;
  std::shared_ptr<CommandTree> command_tree_ = g_command_tree;
  std::unordered_set<std::string> nicknames_;
};
