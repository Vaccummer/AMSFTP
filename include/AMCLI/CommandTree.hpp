#pragma once
#include "AMBase/DataClass.hpp"
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace CLI {
class App;
}

/**
 * @brief Semantic type for command argument completion/highlight routing.
 */
enum class AMCommandArgSemantic {
  None = 0,
  Path,
  HostNickname,
  HostAttr,
  ClientName,
  TaskId,
  VariableName,
};

/**
 * @brief CLI command tree used for completion and highlighting.
 */
class CommandTree : public NonCopyableNonMovable {
public:
  using CommandPath = std::vector<std::string>;

  /**
   * @brief Positional-argument completion rule.
   */
  struct PositionalRule {
    size_t index = 0;
    AMCommandArgSemantic semantic = AMCommandArgSemantic::None;
    bool repeat_tail = false;
  };

  /**
   * @brief Option-value completion rule.
   */
  struct OptionValueRule {
    std::string long_option;
    char short_option = '\0';
    AMCommandArgSemantic semantic = AMCommandArgSemantic::None;
    size_t value_count = 1;
    bool repeat_tail = false;
  };

  /**
   * @brief Chain node used for completion lookups.
   */
  struct CommandNode {
    std::string name;
    std::string help;
    std::unordered_map<std::string, std::shared_ptr<CommandNode>> subcommands;
    std::unordered_map<std::string, std::string> long_options;
    std::unordered_map<char, std::string> short_options;
    std::vector<PositionalRule> positional_rules;
    std::vector<OptionValueRule> option_value_rules;

    /**
     * @brief Add one positional semantic rule on this node.
     */
    void AddPositionalRule(size_t index, AMCommandArgSemantic semantic,
                           bool repeat_tail);

    /**
     * @brief Add one option-value semantic rule on this node.
     */
    void AddOptionValueRule(const std::string &long_name, char short_name,
                            AMCommandArgSemantic semantic, size_t value_count,
                            bool repeat_tail);

    /**
     * @brief Resolve positional semantic at a given argument index.
     */
    [[nodiscard]] std::optional<AMCommandArgSemantic>
    ResolvePositionalSemantic(size_t index) const;

    /**
     * @brief Resolve option-value rule for a concrete option token.
     */
    [[nodiscard]] std::optional<OptionValueRule>
    ResolveOptionValueRule(const std::string &long_name, char short_name,
                           size_t value_index) const;
  };

  /**
   * @brief Return the singleton command tree instance.
   */
  static CommandTree &Instance();

  /**
   * @brief Build tree structure from CLI metadata.
   */
  void Build(CLI::App &app);

  /**
   * @brief Return true when name is a top-level command.
   */
  [[nodiscard]] bool IsTopCommand(const std::string &name) const;

  /**
   * @brief Return true when name is a module (has subcommands).
   */
  [[nodiscard]] bool IsModule(const std::string &name) const;

  /**
   * @brief Find a node by command path string.
   */
  [[nodiscard]] const CommandNode *FindNode(const std::string &path) const;

  /**
   * @brief Find a node by command path components.
   */
  [[nodiscard]] const CommandNode *FindNode(const CommandPath &path) const;

  /**
   * @brief List top-level commands with help text.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListTopCommands() const;

  /**
   * @brief List subcommands for a command path string.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListSubcommands(const std::string &path) const;

  /**
   * @brief List subcommands for a command path.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListSubcommands(const CommandPath &path) const;

  /**
   * @brief List long options for a command path string.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListLongOptions(const std::string &path) const;

  /**
   * @brief List short options for a command path string.
   */
  [[nodiscard]] std::vector<std::pair<char, std::string>>
  ListShortOptions(const std::string &path) const;

  /**
   * @brief Add one positional semantic rule for a command path string.
   */
  void AddPositionalRule(const std::string &path, size_t index,
                         AMCommandArgSemantic semantic, bool repeat_tail);

  /**
   * @brief Add one positional semantic rule for a command path.
   */
  void AddPositionalRule(const CommandPath &path, size_t index,
                         AMCommandArgSemantic semantic, bool repeat_tail);

  /**
   * @brief Add one option-value semantic rule for a command path string.
   */
  void AddOptionValueRule(const std::string &path, const std::string &long_name,
                          char short_name, AMCommandArgSemantic semantic,
                          size_t value_count, bool repeat_tail);

  /**
   * @brief Add one option-value semantic rule for a command path.
   */
  void AddOptionValueRule(const CommandPath &path, const std::string &long_name,
                          char short_name, AMCommandArgSemantic semantic,
                          size_t value_count, bool repeat_tail);

  /**
   * @brief Resolve positional semantic at a given argument index.
   */
  [[nodiscard]] std::optional<AMCommandArgSemantic>
  ResolvePositionalSemantic(const std::string &path, size_t index) const;

  /**
   * @brief Resolve positional semantic at a given argument index.
   */
  [[nodiscard]] std::optional<AMCommandArgSemantic>
  ResolvePositionalSemantic(const CommandPath &path, size_t index) const;

  /**
   * @brief Resolve option-value rule for a concrete option token.
   */
  [[nodiscard]] std::optional<OptionValueRule>
  ResolveOptionValueRule(const std::string &path, const std::string &long_name,
                         char short_name, size_t value_index) const;

  /**
   * @brief Resolve option-value rule for a concrete option token.
   */
  [[nodiscard]] std::optional<OptionValueRule>
  ResolveOptionValueRule(const CommandPath &path, const std::string &long_name,
                         char short_name, size_t value_index) const;

private:
  CommandTree() = default;

  /**
   * @brief Split whitespace-delimited command path into components.
   */
  static CommandPath SplitPath_(const std::string &path);

  /**
   * @brief Find a mutable node by command path.
   */
  CommandNode *FindNodeMutable_(const CommandPath &path);

  /**
   * @brief Find a node by command path.
   */
  [[nodiscard]] const CommandNode *FindNode_(const CommandPath &path) const;

  /**
   * @brief Register top-level command metadata.
   */
  std::shared_ptr<CommandNode> RegisterTopCommand_(const std::string &name,
                                                   const std::string &help);

  std::unordered_map<std::string, std::shared_ptr<CommandNode>> nodes_;
  std::unordered_set<std::string> modules_;
};
