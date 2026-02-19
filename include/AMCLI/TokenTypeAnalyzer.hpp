#pragma once
#include "AMBase/DataClass.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Var.hpp"
#include <mutex>
#include <string>
#include <unordered_map>
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

  /**
   * @brief Token parsed from input, optionally annotated with type.
   */
  struct AMToken {
    size_t start = 0;
    size_t end = 0;
    bool quoted = false;
    AMTokenType type = AMTokenType::Unset;
  };

  /**
   * @brief Per-nickname path engine configuration loaded from HostSet.
   */
  struct PathEngineConfig {
    bool use_async = false;
    bool use_cache = false;
    size_t cache_items_threshold = 50;
    size_t cache_max_entries = 15;
    int timeout_ms = 3000;
    bool highlight_use_check = true;
    int highlight_timeout_ms = 1000;
  };

  /**
   * @brief Reload HostSet configuration from settings.
   */
  void RefreshHostSet();

  /**
   * @brief Resolve path engine config for a nickname (private overrides "*").
   */
  [[nodiscard]] PathEngineConfig ResolvePathEngineConfig(
      const std::string &nickname);

private:
  using CommandNode = CommandTree::CommandNode;

  AMTokenTypeAnalyzer() = default;

  void EnsureCliCache();
  void BuildCliCache();

  std::vector<AMToken> Tokenize(const std::string &input,
                                bool analyse_type = false);
  bool ParseVarTokenAt(const std::string &input, size_t pos, size_t limit,
                       size_t *out_end) const;
  bool ParseVarTokenText(const std::string &token,
                         std::string *out_name = nullptr) const;

  [[nodiscard]] AMTokenType VarNameTypeFor(const std::string &name) const;

  bool IsValidOptionToken(const std::string &token,
                          const CommandNode *node) const;
  int PriorityForType(AMTokenType type) const;

  void EnsureHostSetLoaded_();

  AMConfigManager &config_manager_ = AMConfigManager::Instance();
  AMVarManager &var_manager_ = AMVarManager::Instance();
  bool cli_cache_ready_ = false;
  std::shared_ptr<CommandTree> command_tree_ = g_command_tree;
  std::unordered_set<std::string> nicknames_;
  std::mutex hostset_mtx_;
  bool hostset_ready_ = false;
  std::unordered_map<std::string, PathEngineConfig> hostset_path_;
  PathEngineConfig hostset_default_{};
};
