#pragma once
#include "AMBase/DataClass.hpp"
#include "AMManager/Config.hpp"
#include <replxx.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace CLI {
class App;
}

class AMTokenTypeAnalyzer {
public:
  /**
   * @brief Construct a token analyzer bound to the config manager.
   */
  explicit AMTokenTypeAnalyzer(AMConfigManager &config_manager);

  /**
   * @brief Apply syntax highlighting colors to the input.
   */
  void Highlight(const std::string &input, ReplxxColor *colors, int size);

  /**
   * @brief Build a bbcode-formatted string for isocline highlighting.
   */
  void HighlightFormatted(const std::string &input, std::string *formatted);

  /**
   * @brief Refresh nickname cache from config.
   */
  void RefreshNicknameCache();

private:
  struct CommandNode {
    std::unordered_set<std::string> subcommands;
    std::unordered_set<std::string> long_options;
    std::unordered_set<char> short_options;
  };

  struct Token {
    size_t start = 0;
    size_t end = 0;
    bool quoted = false;
  };

  void EnsureCliCache();
  void BuildCliCache();
  void BuildCliNode(CLI::App *app, const std::string &path, bool is_root);
  const CommandNode *FindNode(const std::string &path) const;

  void ApplyColor(const AMTokenSpan &span, ReplxxColor *colors,
                  std::vector<int> &priorities, int size) const;
  void ApplyRange(size_t start, size_t end, AMTokenType type,
                  ReplxxColor *colors, std::vector<int> &priorities,
                  int size) const;

  std::vector<Token> Tokenize(const std::string &input) const;
  bool ParseVarTokenAt(const std::string &input, size_t pos, size_t limit,
                       size_t *out_end) const;
  bool ParseVarTokenText(const std::string &token) const;
  bool ParseVarTokenText(const std::string &token, std::string *out_name) const;

  void HighlightVarToken(const std::string &input, size_t token_start,
                         size_t token_end, ReplxxColor *colors,
                         std::vector<int> &priorities, int size) const;

  void HighlightVarReferences(const std::string &input,
                              const std::vector<Token> &tokens,
                              ReplxxColor *colors, std::vector<int> &priorities,
                              int size) const;

  void HighlightEscapeSigns(const std::string &input, ReplxxColor *colors,
                            std::vector<int> &priorities, int size) const;

  void HighlightNicknameAtSign(const std::string &input,
                               const std::vector<Token> &tokens,
                               ReplxxColor *colors,
                               std::vector<int> &priorities, int size) const;

  void HighlightCommandsAndOptions(const std::string &input,
                                   const std::vector<Token> &tokens,
                                   ReplxxColor *colors,
                                   std::vector<int> &priorities, int size,
                                   const CommandNode **out_node,
                                   size_t *out_command_tokens) const;

  void HighlightVarCommand(const std::string &input,
                           const std::vector<Token> &tokens,
                           ReplxxColor *colors, std::vector<int> &priorities,
                           int size, bool *handled) const;

  AMTokenType VarNameTypeFor(const std::string &name) const;
  bool VarExists(const std::string &name) const;

  bool IsValidOptionToken(const std::string &token,
                          const CommandNode *node) const;
  ReplxxColor ColorForType(AMTokenType type) const;
  int PriorityForType(AMTokenType type) const;

  AMConfigManager &config_manager_;
  bool cli_cache_ready_ = false;
  std::unordered_set<std::string> modules_;
  std::unordered_set<std::string> top_commands_;
  std::unordered_map<std::string, CommandNode> command_nodes_;
  std::unordered_set<std::string> nicknames_;
};
