#include "AMCLI/CommandTree.hpp"
#include "CLI/CLI.hpp"
#include <functional>
#include <utility>

namespace {
/**
 * @brief Combine hash values.
 */
inline size_t HashCombine_(size_t seed, size_t value) {
  return seed ^ (value + 0x9e3779b97f4a7c15ULL + (seed << 6U) + (seed >> 2U));
}
} // namespace

/**
 * @brief Hash a command path using a simple combine strategy.
 */
size_t CommandTree::CommandPathHash::operator()(
    const CommandPath &path) const noexcept {
  size_t seed = path.size();
  for (const auto &part : path) {
    seed = HashCombine_(seed, std::hash<std::string>{}(part));
  }
  return seed;
}

/**
 * @brief Return the singleton command tree instance.
 */
CommandTree &CommandTree::Instance() {
  static CommandTree instance;
  return instance;
}

/**
 * @brief Build tree structure from CLI metadata.
 */
void CommandTree::Build(CLI::App &app) {
  nodes_.clear();
  top_commands_.clear();
  modules_.clear();

  auto root_subs = app.get_subcommands([](CLI::App *) { return true; });

  auto build_node = [&](auto &&self, CLI::App *node_app,
                        CommandPath path) -> void {
    if (!node_app || path.empty()) {
      return;
    }

    CommandNode *node = EnsureNode_(path);
    if (!node) {
      return;
    }
    node->help = node_app->get_description();
    node->subcommands.clear();
    node->long_options.clear();
    node->short_options.clear();
    node->positional_rules.clear();
    node->option_value_rules.clear();

    for (auto *opt : node_app->get_options()) {
      if (!opt) {
        continue;
      }
      const std::string desc = opt->get_description();
      for (const auto &lname : opt->get_lnames()) {
        if (!lname.empty()) {
          node->long_options.emplace("--" + lname, desc);
        }
      }
      for (const auto &sname : opt->get_snames()) {
        if (!sname.empty()) {
          node->short_options.emplace(sname[0], desc);
        }
      }
    }

    auto subs = node_app->get_subcommands([](CLI::App *) { return true; });
    for (auto *sub : subs) {
      if (!sub) {
        continue;
      }
      const std::string sub_name = sub->get_name();
      node->subcommands.insert(sub_name);
      CommandPath child_path = path;
      child_path.push_back(sub_name);
      CommandNode *child = EnsureNode_(child_path);
      if (child) {
        child->help = sub->get_description();
      }
      self(self, sub, std::move(child_path));
    }
  };

  for (auto *sub : root_subs) {
    if (!sub) {
      continue;
    }
    const std::string name = sub->get_name();
    RegisterTopCommand_(name, sub->get_description());
    auto nested = sub->get_subcommands([](CLI::App *) { return true; });
    if (!nested.empty()) {
      modules_.insert(name);
    }
    build_node(build_node, sub, CommandPath{name});
  }
}

/**
 * @brief Return true when name is a top-level command.
 */
bool CommandTree::IsTopCommand(const std::string &name) const {
  return top_commands_.find(name) != top_commands_.end();
}

/**
 * @brief Return true when name is a module (has subcommands).
 */
bool CommandTree::IsModule(const std::string &name) const {
  return modules_.find(name) != modules_.end();
}

/**
 * @brief Find a node by command path string.
 */
const CommandTree::CommandNode *
CommandTree::FindNode(const std::string &path) const {
  return FindNode_(SplitPath_(path));
}

/**
 * @brief Find a node by command path components.
 */
const CommandTree::CommandNode *
CommandTree::FindNode(const CommandPath &path) const {
  return FindNode_(path);
}

/**
 * @brief List top-level commands with help text.
 */
std::vector<std::pair<std::string, std::string>> CommandTree::ListTopCommands()
    const {
  std::vector<std::pair<std::string, std::string>> out;
  out.reserve(top_commands_.size());
  for (const auto &name : top_commands_) {
    const auto *node = FindNode_(CommandPath{name});
    out.emplace_back(name, node ? node->help : "");
  }
  return out;
}

/**
 * @brief List subcommands for a command path string.
 */
std::vector<std::pair<std::string, std::string>>
CommandTree::ListSubcommands(const std::string &path) const {
  return ListSubcommands(SplitPath_(path));
}

/**
 * @brief List subcommands for a command path.
 */
std::vector<std::pair<std::string, std::string>>
CommandTree::ListSubcommands(const CommandPath &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  const auto *node = FindNode_(path);
  if (!node) {
    return out;
  }

  out.reserve(node->subcommands.size());
  for (const auto &sub : node->subcommands) {
    CommandPath child = path;
    child.push_back(sub);
    const auto *child_node = FindNode_(child);
    out.emplace_back(sub, child_node ? child_node->help : "");
  }
  return out;
}

/**
 * @brief List long options for a command path string.
 */
std::vector<std::pair<std::string, std::string>>
CommandTree::ListLongOptions(const std::string &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  const auto *node = FindNode_(SplitPath_(path));
  if (!node) {
    return out;
  }
  out.reserve(node->long_options.size());
  for (const auto &entry : node->long_options) {
    out.emplace_back(entry.first, entry.second);
  }
  return out;
}

/**
 * @brief List short options for a command path string.
 */
std::vector<std::pair<char, std::string>>
CommandTree::ListShortOptions(const std::string &path) const {
  std::vector<std::pair<char, std::string>> out;
  const auto *node = FindNode_(SplitPath_(path));
  if (!node) {
    return out;
  }
  out.reserve(node->short_options.size());
  for (const auto &entry : node->short_options) {
    out.emplace_back(entry.first, entry.second);
  }
  return out;
}

/**
 * @brief Add one positional semantic rule for a command path string.
 */
void CommandTree::AddPositionalRule(const std::string &path, size_t index,
                                    AMCommandArgSemantic semantic,
                                    bool repeat_tail) {
  AddPositionalRule(SplitPath_(path), index, semantic, repeat_tail);
}

/**
 * @brief Add one positional semantic rule for a command path.
 */
void CommandTree::AddPositionalRule(const CommandPath &path, size_t index,
                                    AMCommandArgSemantic semantic,
                                    bool repeat_tail) {
  if (path.empty() || semantic == AMCommandArgSemantic::None) {
    return;
  }
  CommandNode *node = FindNodeMutable_(path);
  if (!node) {
    return;
  }
  auto &rules = node->positional_rules;
  for (auto &rule : rules) {
    if (rule.index == index && rule.repeat_tail == repeat_tail) {
      rule.semantic = semantic;
      return;
    }
  }
  rules.push_back({index, semantic, repeat_tail});
}

/**
 * @brief Add one option-value semantic rule for a command path string.
 */
void CommandTree::AddOptionValueRule(const std::string &path,
                                     const std::string &long_name,
                                     char short_name,
                                     AMCommandArgSemantic semantic,
                                     size_t value_count, bool repeat_tail) {
  AddOptionValueRule(SplitPath_(path), long_name, short_name, semantic,
                     value_count, repeat_tail);
}

/**
 * @brief Add one option-value semantic rule for a command path.
 */
void CommandTree::AddOptionValueRule(const CommandPath &path,
                                     const std::string &long_name,
                                     char short_name,
                                     AMCommandArgSemantic semantic,
                                     size_t value_count, bool repeat_tail) {
  if (path.empty() || semantic == AMCommandArgSemantic::None) {
    return;
  }
  CommandNode *node = FindNodeMutable_(path);
  if (!node) {
    return;
  }
  const std::string normalized_long = NormalizeLongOptionName_(long_name);
  if (normalized_long.empty() && short_name == '\0') {
    return;
  }
  if (value_count == 0) {
    value_count = 1;
  }
  auto &rules = node->option_value_rules;
  for (auto &rule : rules) {
    if (rule.long_option == normalized_long &&
        rule.short_option == short_name) {
      rule.semantic = semantic;
      rule.value_count = value_count;
      rule.repeat_tail = repeat_tail;
      return;
    }
  }
  rules.push_back(
      {normalized_long, short_name, semantic, value_count, repeat_tail});
}

/**
 * @brief Resolve positional semantic at a given argument index.
 */
std::optional<AMCommandArgSemantic>
CommandTree::ResolvePositionalSemantic(const std::string &path,
                                       size_t index) const {
  return ResolvePositionalSemantic(SplitPath_(path), index);
}

/**
 * @brief Resolve positional semantic at a given argument index.
 */
std::optional<AMCommandArgSemantic>
CommandTree::ResolvePositionalSemantic(const CommandPath &path,
                                       size_t index) const {
  const auto *node = FindNode_(path);
  if (!node) {
    return std::nullopt;
  }
  const auto &rules = node->positional_rules;
  size_t best_tail_index = 0;
  std::optional<AMCommandArgSemantic> best_tail;
  for (const auto &rule : rules) {
    if (rule.semantic == AMCommandArgSemantic::None) {
      continue;
    }
    if (rule.index == index) {
      return rule.semantic;
    }
    if (rule.repeat_tail && rule.index <= index &&
        (!best_tail.has_value() || rule.index >= best_tail_index)) {
      best_tail = rule.semantic;
      best_tail_index = rule.index;
    }
  }
  return best_tail;
}

/**
 * @brief Resolve option-value rule for a concrete option token.
 */
std::optional<CommandTree::OptionValueRule>
CommandTree::ResolveOptionValueRule(const std::string &path,
                                    const std::string &long_name,
                                    char short_name, size_t value_index) const {
  return ResolveOptionValueRule(SplitPath_(path), long_name, short_name,
                                value_index);
}

/**
 * @brief Resolve option-value rule for a concrete option token.
 */
std::optional<CommandTree::OptionValueRule>
CommandTree::ResolveOptionValueRule(const CommandPath &path,
                                    const std::string &long_name,
                                    char short_name, size_t value_index) const {
  const auto *node = FindNode_(path);
  if (!node) {
    return std::nullopt;
  }
  const std::string normalized_long = NormalizeLongOptionName_(long_name);
  const auto &rules = node->option_value_rules;
  for (const auto &rule : rules) {
    bool matched = false;
    if (!normalized_long.empty() && rule.long_option == normalized_long) {
      matched = true;
    }
    if (short_name != '\0' && rule.short_option == short_name) {
      matched = true;
    }
    if (!matched || rule.semantic == AMCommandArgSemantic::None) {
      continue;
    }
    if (value_index < rule.value_count || rule.repeat_tail) {
      return rule;
    }
  }
  return std::nullopt;
}

/**
 * @brief Split whitespace-delimited command path into components.
 */
CommandTree::CommandPath CommandTree::SplitPath_(const std::string &path) {
  CommandPath parts;
  std::string current;
  current.reserve(path.size());
  for (char ch : path) {
    const bool is_space =
        ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' ||
        ch == '\v';
    if (is_space) {
      if (!current.empty()) {
        parts.push_back(current);
        current.clear();
      }
      continue;
    }
    current.push_back(ch);
  }
  if (!current.empty()) {
    parts.push_back(std::move(current));
  }
  return parts;
}

/**
 * @brief Normalize a long option name to `--name` format.
 */
std::string CommandTree::NormalizeLongOptionName_(const std::string &name) {
  if (name.empty()) {
    return "";
  }
  if (name.rfind("--", 0) == 0) {
    return name;
  }
  if (name.size() >= 2 && name[0] == '-' && name[1] != '-') {
    return "--" + name.substr(1);
  }
  return "--" + name;
}

/**
 * @brief Find a mutable node by command path.
 */
CommandTree::CommandNode *
CommandTree::FindNodeMutable_(const CommandPath &path) {
  auto it = nodes_.find(path);
  if (it == nodes_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Ensure a node exists for command path and return it.
 */
CommandTree::CommandNode *CommandTree::EnsureNode_(const CommandPath &path) {
  if (path.empty()) {
    return nullptr;
  }
  return &nodes_[path];
}

/**
 * @brief Find a node by command path.
 */
const CommandTree::CommandNode *
CommandTree::FindNode_(const CommandPath &path) const {
  auto it = nodes_.find(path);
  if (it == nodes_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Register top-level command metadata.
 */
void CommandTree::RegisterTopCommand_(const std::string &name,
                                      const std::string &help) {
  if (name.empty()) {
    return;
  }
  top_commands_.insert(name);
  CommandNode *node = EnsureNode_(CommandPath{name});
  if (node) {
    node->help = help;
  }
}
