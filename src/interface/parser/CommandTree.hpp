#pragma once
#include "CLI/App.hpp"
#include "interface/cli/CLIArg.hpp"
#include <algorithm>
#include <cstddef>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace AMInterface::parser {

/**
 * @brief Semantic type for command argument completion/highlight routing.
 */
enum class AMCommandArgSemantic {
  None = 0,
  Path,
  FindPattern,
  Url,
  ShellCmd,
  HostNickname,
  HostNicknameNew,
  TerminalName,
  TermTargetExisting,
  TermTargetNew,
  SshTermTarget,
  HostAttr,
  HostAttrValue,
  ClientName,
  PoolName,
  TaskId,
  PausedTaskId,
  VariableName,
  VarZone,
};

/**
 * @brief Chained CLI command node used for completion and binding.
 */
class CommandNode {
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
   * @brief Initialize node tree from CLI11 root app.
   */
  void Init(CLI::App &app);

  /**
   * @brief Compatibility wrapper for previous API.
   */
  void Build(CLI::App &app) { Init(app); }

  /**
   * @brief Add one subcommand and return the child node.
   */
  CommandNode *AddFunction(const std::string &name, const std::string &help);

  /**
   * @brief Add one subcommand, configure it immediately, and return the child.
   */
  template <typename Configure>
  CommandNode *AddFunction(const std::string &name, const std::string &help,
                           Configure &&configure) {
    CommandNode *child = AddFunction(name, help);
    if (!child) {
      return child;
    }
    std::forward<Configure>(configure)(*child);
    return child;
  }

  /**
   * @brief Add one subcommand, bind callback selection, and return child node.
   */
  template <typename T>
  CommandNode *AddFunction(const std::string &name, const std::string &help,
                           AMInterface::cli::CliArgsPool &args,
                           T AMInterface::cli::CliArgsPool::*member) {
    CommandNode *child = AddFunction(name, help);
    if (!child || !child->app) {
      return child;
    }
    child->app->callback(
        [&args, member]() { args.SetActive(&(args.*member)); });
    return child;
  }

  /**
   * @brief Add one bound subcommand, configure it immediately, and return
   * child.
   */
  template <typename T, typename Configure>
  CommandNode *AddFunction(const std::string &name, const std::string &help,
                           AMInterface::cli::CliArgsPool &args,
                           T AMInterface::cli::CliArgsPool::*member,
                           Configure &&configure) {
    CommandNode *child = AddFunction(name, help, args, member);
    if (!child) {
      return child;
    }
    std::forward<Configure>(configure)(*child);
    return child;
  }

  /**
   * @brief Add one subcommand and bind callback to grouped CliArgsPool member.
   */
  template <typename Group, typename T>
  CommandNode *AddFunction(const std::string &name, const std::string &help,
                           AMInterface::cli::CliArgsPool &args,
                           Group AMInterface::cli::CliArgsPool::*group_member,
                           T Group::*member) {
    CommandNode *child = AddFunction(name, help);
    if (!child || !child->app) {
      return child;
    }
    child->app->callback([&args, group_member, member]() {
      auto &group = args.*group_member;
      args.SetActive(&(group.*member));
    });
    return child;
  }

  /**
   * @brief Add one grouped bound subcommand, configure it immediately, and
   * return child.
   */
  template <typename Group, typename T, typename Configure>
  CommandNode *AddFunction(const std::string &name, const std::string &help,
                           AMInterface::cli::CliArgsPool &args,
                           Group AMInterface::cli::CliArgsPool::*group_member,
                           T Group::*member, Configure &&configure) {
    CommandNode *child = AddFunction(name, help, args, group_member, member);
    if (!child) {
      return child;
    }
    std::forward<Configure>(configure)(*child);
    return child;
  }

  /**
   * @brief Add one flag to both CLI11 app and completion metadata.
   */
  CommandNode *AddFlag(const std::string &short_name,
                       const std::string &long_name, bool &value,
                       const std::string &help);

  /**
   * @brief Add one option to both CLI11 app and completion metadata.
   */
  template <typename T>
  CommandNode *AddOption(const std::string &short_name,
                         const std::string &long_name, T &value, size_t min_num,
                         size_t max_num, AMCommandArgSemantic semantic,
                         const std::string &help = "", bool required = false) {
    if (!app) {
      return nullptr;
    }
    const char short_opt = NormalizeShortName_(short_name);
    const std::string long_opt = NormalizeLongName_(long_name);
    if (short_opt == '\0' && long_opt.empty()) {
      return nullptr;
    }
    const std::string spec = BuildOptionSpec_(short_name, long_name);
    if (!spec.empty()) {
      auto *opt = app->add_option(spec, value, help);
      if (opt) {
        ConfigureOption_(opt, min_num, max_num, required);
      }
    }

    if (short_opt != '\0') {
      short_options[short_opt] = help;
    }
    if (!long_opt.empty()) {
      long_options[long_opt] = help;
    }
    const bool repeat_tail = max_num == std::numeric_limits<size_t>::max();
    const size_t value_count = repeat_tail ? std::max<size_t>(1, min_num)
                                           : std::max<size_t>(1, max_num);
    AddOptionValueRule(long_opt, short_opt, semantic, value_count, repeat_tail);
    return this;
  }

  /**
   * @brief Add one positional option to CLI11 app.
   */
  template <typename T>
  CommandNode *AddOption(const std::string &name, T &value, size_t min_num,
                         size_t max_num, const std::string &help = "",
                         bool required = false) {
    if (!app || name.empty()) {
      return nullptr;
    }
    auto *opt = app->add_option(name, value, help);
    if (opt) {
      ConfigureOption_(opt, min_num, max_num, required);
    }
    return this;
  }

  /**
   * @brief Find node by path string.
   */
  CommandNode *Find(const std::string &path);

  /**
   * @brief Find node by path components.
   */
  CommandNode *Find(const CommandPath &path);

  /**
   * @brief Find node by path string (const).
   */
  const CommandNode *Find(const std::string &path) const;

  /**
   * @brief Find node by path components (const).
   */
  const CommandNode *Find(const CommandPath &path) const;

  /**
   * @brief Compatibility wrapper for previous API.
   */
  CommandNode *CreateNode(const std::string &path,
                          const std::string &help = "");

  /**
   * @brief Compatibility wrapper for previous API.
   */
  CommandNode *CreateNode(const CommandPath &path,
                          const std::string &help = "");

  /**
   * @brief Return true when name is top-level command.
   */
  [[nodiscard]] bool IsTopCommand(const std::string &name) const;

  /**
   * @brief Return true when name is module (top-level with subcommands).
   */
  [[nodiscard]] bool IsModule(const std::string &name) const;

  /**
   * @brief Compatibility wrapper.
   */
  [[nodiscard]] const CommandNode *FindNode(const std::string &path) const {
    return Find(path);
  }

  /**
   * @brief Compatibility wrapper.
   */
  [[nodiscard]] const CommandNode *FindNode(const CommandPath &path) const {
    return Find(path);
  }

  /**
   * @brief List top-level commands with help text.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListTopCommands() const;

  /**
   * @brief List subcommands for one command path.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListSubcommands(const std::string &path) const;

  /**
   * @brief List subcommands for one command path.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListSubcommands(const CommandPath &path) const;

  /**
   * @brief List long options for one command path.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListLongOptions(const std::string &path) const;

  /**
   * @brief List short options for one command path.
   */
  [[nodiscard]] std::vector<std::pair<char, std::string>>
  ListShortOptions(const std::string &path) const;

  /**
   * @brief Add positional rule by path.
   */
  void AddPositionalRule(const std::string &path, size_t index,
                         AMCommandArgSemantic semantic, bool repeat_tail);

  /**
   * @brief Add positional rule on current node.
   */
  void AddPositionalRule(size_t index, AMCommandArgSemantic semantic,
                         bool repeat_tail);

  /**
   * @brief Add option-value rule by path.
   */
  void AddOptionValueRule(const std::string &path, const std::string &long_name,
                          char short_name, AMCommandArgSemantic semantic,
                          size_t value_count, bool repeat_tail);

  /**
   * @brief Add option-value rule on current node.
   */
  void AddOptionValueRule(const std::string &long_name, char short_name,
                          AMCommandArgSemantic semantic, size_t value_count,
                          bool repeat_tail);

  /**
   * @brief Resolve positional semantic by path.
   */
  [[nodiscard]] std::optional<AMCommandArgSemantic>
  ResolvePositionalSemantic(const std::string &path, size_t index) const;

  /**
   * @brief Resolve positional semantic on current node.
   */
  [[nodiscard]] std::optional<AMCommandArgSemantic>
  ResolvePositionalSemantic(size_t index) const;

  /**
   * @brief Return true if positional index is legal by explicit or tail rule.
   */
  [[nodiscard]] bool HasPositionalRule(const std::string &path,
                                       size_t index) const;

  /**
   * @brief Return true if positional index is legal on current node.
   */
  [[nodiscard]] bool HasPositionalRule(size_t index) const;

  /**
   * @brief Resolve option-value rule by path.
   */
  [[nodiscard]] std::optional<OptionValueRule>
  ResolveOptionValueRule(const std::string &path, const std::string &long_name,
                         char short_name, size_t value_index) const;

  /**
   * @brief Resolve option-value rule on current node.
   */
  [[nodiscard]] std::optional<OptionValueRule>
  ResolveOptionValueRule(const std::string &long_name, char short_name,
                         size_t value_index) const;

  std::string name;
  std::string parent_func_name;
  std::string help;
  bool top_level = false;
  CLI::App *app = nullptr;
  std::unordered_map<std::string, std::shared_ptr<CommandNode>> subcommands;
  std::unordered_map<std::string, std::string> long_options;
  std::unordered_map<char, std::string> short_options;
  std::vector<PositionalRule> positional_rules;
  std::vector<OptionValueRule> option_value_rules;

private:
  /**
   * @brief Parse path string into components.
   */
  static CommandPath SplitPath_(const std::string &path);

  /**
   * @brief Build CLI11 option spec from short and long names.
   */
  static std::string BuildOptionSpec_(const std::string &short_name,
                                      const std::string &long_name);

  /**
   * @brief Apply shared CLI11 option cardinality and required settings.
   */
  static void ConfigureOption_(CLI::Option *opt, size_t min_num, size_t max_num,
                               bool required);

  /**
   * @brief Normalize short option to single character.
   */
  static char NormalizeShortName_(const std::string &short_name);

  /**
   * @brief Normalize long option to `--name` format.
   */
  static std::string NormalizeLongName_(const std::string &long_name);

  /**
   * @brief Import one CLI11 subtree into one command node.
   */
  void ImportFromApp_(CLI::App *node_app);

  /**
   * @brief Find child by name for one node.
   */
  const CommandNode *FindChild_(const std::string &child) const;

  /**
   * @brief Find mutable child by name for one node.
   */
  CommandNode *FindChild_(const std::string &child);

  /**
   * @brief Root CLI11 app (valid on root node).
   */
  CLI::App *root_app_ = nullptr;
};

/**
 * @brief Match command tokens against one command tree and return one
 * subcommand.
 *
 * Returns the deepest exact-match subcommand when the token path is valid. When
 * the first unknown command token is hit, returns the best fuzzy-matched
 * subcommand under the current tree level. Option-like tokens stop traversal.
 */
[[nodiscard]] const CommandNode *
MatchSubcommand(const std::vector<std::string> &tokens,
                const CommandNode &command_tree,
                std::string *invalid_token = nullptr);

} // namespace AMInterface::parser
