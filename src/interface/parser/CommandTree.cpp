#include "interface/parser/CommandTree.hpp"
#include "CLI/CLI.hpp"
#include <utility>

namespace AMInterface::parser {

/**
 * @brief Initialize node tree from CLI11 root app.
 */
void CommandNode::Init(CLI::App &app_root) {
  root_app_ = &app_root;
  name.clear();
  parent_func_name.clear();
  help = app_root.get_description();
  top_level = false;
  app = &app_root;
  subcommands.clear();
  long_options.clear();
  short_options.clear();
  positional_rules.clear();
  option_value_rules.clear();

  auto roots = app_root.get_subcommands([](CLI::App *) { return true; });
  for (auto *sub : roots) {
    if (!sub) {
      continue;
    }
    auto node = std::make_shared<CommandNode>();
    node->name = sub->get_name();
    node->parent_func_name = "";
    node->help = sub->get_description();
    node->top_level = true;
    node->app = sub;
    node->root_app_ = nullptr;
    node->ImportFromApp_(sub);
    subcommands[node->name] = node;
  }
}

/**
 * @brief Add one subcommand and return the child node.
 */
CommandNode *CommandNode::AddFunction(const std::string &child_name,
                                      const std::string &child_help) {
  if (!app || child_name.empty()) {
    return nullptr;
  }

  auto child = std::make_shared<CommandNode>();
  child->name = child_name;
  child->parent_func_name = name;
  child->help = child_help;
  child->top_level = (root_app_ != nullptr);
  child->app = app->add_subcommand(child_name, child_help);
  child->root_app_ = nullptr;
  subcommands[child_name] = child;

  return child.get();
}

/**
 * @brief Add one flag to both CLI11 app and completion metadata.
 */
CommandNode *CommandNode::AddFlag(const std::string &short_name,
                                  const std::string &long_name, bool &value,
                                  const std::string &flag_help) {
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
    app->add_flag(spec, value, flag_help);
  }
  if (short_opt != '\0') {
    short_options[short_opt] = flag_help;
  }
  if (!long_opt.empty()) {
    long_options[long_opt] = flag_help;
  }
  return this;
}

/**
 * @brief Find node by path string.
 */
CommandNode *CommandNode::Find(const std::string &path) {
  return const_cast<CommandNode *>(
      static_cast<const CommandNode *>(this)->Find(path));
}

/**
 * @brief Find node by path components.
 */
CommandNode *CommandNode::Find(const CommandPath &path) {
  return const_cast<CommandNode *>(
      static_cast<const CommandNode *>(this)->Find(path));
}

/**
 * @brief Find node by path string (const).
 */
const CommandNode *CommandNode::Find(const std::string &path) const {
  return Find(SplitPath_(path));
}

/**
 * @brief Find node by path components (const).
 */
const CommandNode *CommandNode::Find(const CommandPath &path) const {
  if (path.empty()) {
    return this;
  }
  const CommandNode *current = this;
  for (const auto &part : path) {
    if (!current) {
      return nullptr;
    }
    current = current->FindChild_(part);
  }
  return current;
}

/**
 * @brief Compatibility wrapper for previous API.
 */
CommandNode *CommandNode::CreateNode(const std::string &path,
                                     const std::string &node_help) {
  return CreateNode(SplitPath_(path), node_help);
}

/**
 * @brief Compatibility wrapper for previous API.
 */
CommandNode *CommandNode::CreateNode(const CommandPath &path,
                                     const std::string &node_help) {
  if (path.empty()) {
    return this;
  }
  CommandNode *current = this;
  for (size_t i = 0; i < path.size(); ++i) {
    const bool is_last = (i + 1 == path.size());
    auto it = current->subcommands.find(path[i]);
    if (it != current->subcommands.end() && it->second) {
      current = it->second.get();
      if (is_last && !node_help.empty()) {
        current->help = node_help;
      }
      continue;
    }

    const std::string child_help = is_last ? node_help : "";
    current = current->AddFunction(path[i], child_help);
    if (!current) {
      return nullptr;
    }
  }
  return current;
}

/**
 * @brief Return true when name is top-level command.
 */
bool CommandNode::IsTopCommand(const std::string &command) const {
  return subcommands.find(command) != subcommands.end();
}

/**
 * @brief Return true when name is module (top-level with subcommands).
 */
bool CommandNode::IsModule(const std::string &command) const {
  auto it = subcommands.find(command);
  if (it == subcommands.end() || !it->second) {
    return false;
  }
  return !it->second->subcommands.empty();
}

/**
 * @brief List top-level commands with help text.
 */
std::vector<std::pair<std::string, std::string>> CommandNode::ListTopCommands()
    const {
  std::vector<std::pair<std::string, std::string>> out;
  out.reserve(subcommands.size());
  for (const auto &entry : subcommands) {
    out.emplace_back(entry.first, entry.second ? entry.second->help : "");
  }
  return out;
}

/**
 * @brief List subcommands for one command path.
 */
std::vector<std::pair<std::string, std::string>>
CommandNode::ListSubcommands(const std::string &path) const {
  return ListSubcommands(SplitPath_(path));
}

/**
 * @brief List subcommands for one command path.
 */
std::vector<std::pair<std::string, std::string>>
CommandNode::ListSubcommands(const CommandPath &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  const auto *node = Find(path);
  if (!node) {
    return out;
  }
  out.reserve(node->subcommands.size());
  for (const auto &entry : node->subcommands) {
    out.emplace_back(entry.first, entry.second ? entry.second->help : "");
  }
  return out;
}

/**
 * @brief List long options for one command path.
 */
std::vector<std::pair<std::string, std::string>>
CommandNode::ListLongOptions(const std::string &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  const auto *node = Find(path);
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
 * @brief List short options for one command path.
 */
std::vector<std::pair<char, std::string>>
CommandNode::ListShortOptions(const std::string &path) const {
  std::vector<std::pair<char, std::string>> out;
  const auto *node = Find(path);
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
 * @brief Add positional rule by path.
 */
void CommandNode::AddPositionalRule(const std::string &path, size_t index,
                                    AMCommandArgSemantic semantic,
                                    bool repeat_tail) {
  auto *node = Find(path);
  if (!node) {
    return;
  }
  node->AddPositionalRule(index, semantic, repeat_tail);
}

/**
 * @brief Add positional rule on current node.
 */
void CommandNode::AddPositionalRule(size_t index, AMCommandArgSemantic semantic,
                                    bool repeat_tail) {
  for (auto &rule : positional_rules) {
    if (rule.index == index && rule.repeat_tail == repeat_tail) {
      rule.semantic = semantic;
      return;
    }
  }
  positional_rules.push_back({index, semantic, repeat_tail});
}

/**
 * @brief Add option-value rule by path.
 */
void CommandNode::AddOptionValueRule(const std::string &path,
                                     const std::string &long_name,
                                     char short_name,
                                     AMCommandArgSemantic semantic,
                                     size_t value_count, bool repeat_tail) {
  auto *node = Find(path);
  if (!node) {
    return;
  }
  node->AddOptionValueRule(long_name, short_name, semantic, value_count,
                           repeat_tail);
}

/**
 * @brief Add option-value rule on current node.
 */
void CommandNode::AddOptionValueRule(const std::string &long_name,
                                     char short_name,
                                     AMCommandArgSemantic semantic,
                                     size_t value_count, bool repeat_tail) {
  const std::string normalized_long = NormalizeLongName_(long_name);
  if (normalized_long.empty() && short_name == '\0') {
    return;
  }
  if (value_count == 0) {
    value_count = 1;
  }
  for (auto &rule : option_value_rules) {
    if (rule.long_option == normalized_long &&
        rule.short_option == short_name) {
      rule.semantic = semantic;
      rule.value_count = value_count;
      rule.repeat_tail = repeat_tail;
      return;
    }
  }
  option_value_rules.push_back(
      {normalized_long, short_name, semantic, value_count, repeat_tail});
}

/**
 * @brief Resolve positional semantic by path.
 */
std::optional<AMCommandArgSemantic>
CommandNode::ResolvePositionalSemantic(const std::string &path,
                                       size_t index) const {
  const auto *node = Find(path);
  if (!node) {
    return std::nullopt;
  }
  return node->ResolvePositionalSemantic(index);
}

/**
 * @brief Resolve positional semantic on current node.
 */
std::optional<AMCommandArgSemantic>
CommandNode::ResolvePositionalSemantic(size_t index) const {
  size_t best_tail_index = 0;
  std::optional<AMCommandArgSemantic> best_tail;
  for (const auto &rule : positional_rules) {
    if (rule.index == index) {
      if (rule.semantic == AMCommandArgSemantic::None) {
        return std::nullopt;
      }
      return rule.semantic;
    }
    if (rule.repeat_tail && rule.index <= index &&
        (!best_tail.has_value() || rule.index >= best_tail_index)) {
      if (rule.semantic == AMCommandArgSemantic::None) {
        best_tail.reset();
      } else {
        best_tail = rule.semantic;
      }
      best_tail_index = rule.index;
    }
  }
  return best_tail;
}

bool CommandNode::HasPositionalRule(const std::string &path, size_t index) const {
  const auto *node = Find(path);
  if (!node) {
    return false;
  }
  return node->HasPositionalRule(index);
}

bool CommandNode::HasPositionalRule(size_t index) const {
  for (const auto &rule : positional_rules) {
    if (rule.index == index) {
      return true;
    }
    if (rule.repeat_tail && rule.index <= index) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Resolve option-value rule by path.
 */
std::optional<CommandNode::OptionValueRule>
CommandNode::ResolveOptionValueRule(const std::string &path,
                                    const std::string &long_name,
                                    char short_name, size_t value_index) const {
  const auto *node = Find(path);
  if (!node) {
    return std::nullopt;
  }
  return node->ResolveOptionValueRule(long_name, short_name, value_index);
}

/**
 * @brief Resolve option-value rule on current node.
 */
std::optional<CommandNode::OptionValueRule>
CommandNode::ResolveOptionValueRule(const std::string &long_name,
                                    char short_name, size_t value_index) const {
  const std::string normalized_long = NormalizeLongName_(long_name);
  for (const auto &rule : option_value_rules) {
    bool matched = false;
    if (!normalized_long.empty() && rule.long_option == normalized_long) {
      matched = true;
    }
    if (short_name != '\0' && rule.short_option == short_name) {
      matched = true;
    }
    if (!matched) {
      continue;
    }
    if (value_index < rule.value_count || rule.repeat_tail) {
      return rule;
    }
  }
  return std::nullopt;
}

/**
 * @brief Parse path string into components.
 */
CommandNode::CommandPath CommandNode::SplitPath_(const std::string &path) {
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
 * @brief Build CLI11 option spec from short and long names.
 */
std::string CommandNode::BuildOptionSpec_(const std::string &short_name,
                                          const std::string &long_name) {
  const char short_opt = NormalizeShortName_(short_name);
  const std::string long_opt = NormalizeLongName_(long_name);
  std::string spec;
  if (short_opt != '\0') {
    spec = std::string("-") + short_opt;
  }
  if (!long_opt.empty()) {
    if (!spec.empty()) {
      spec += ",";
    }
    spec += long_opt;
  }
  return spec;
}

/**
 * @brief Normalize short option to single character.
 */
char CommandNode::NormalizeShortName_(const std::string &short_name) {
  if (short_name.empty()) {
    return '\0';
  }
  if (short_name.size() == 1) {
    return short_name[0];
  }
  if (short_name.size() == 2 && short_name[0] == '-') {
    return short_name[1];
  }
  return '\0';
}

/**
 * @brief Normalize long option to `--name` format.
 */
std::string CommandNode::NormalizeLongName_(const std::string &long_name) {
  if (long_name.empty()) {
    return "";
  }
  if (long_name.rfind("--", 0) == 0) {
    return long_name;
  }
  if (long_name.size() >= 2 && long_name[0] == '-' && long_name[1] != '-') {
    return "--" + long_name.substr(1);
  }
  return "--" + long_name;
}

/**
 * @brief Import one CLI11 subtree into one command node.
 */
void CommandNode::ImportFromApp_(CLI::App *node_app) {
  if (!node_app) {
    return;
  }

  auto options = node_app->get_options();
  for (auto *opt : options) {
    if (!opt) {
      continue;
    }
    const std::string desc = opt->get_description();
    for (const auto &lname : opt->get_lnames()) {
      if (!lname.empty()) {
        long_options.emplace("--" + lname, desc);
      }
    }
    for (const auto &sname : opt->get_snames()) {
      if (!sname.empty()) {
        short_options.emplace(sname[0], desc);
      }
    }
  }

  auto subs = node_app->get_subcommands([](CLI::App *) { return true; });
  for (auto *sub : subs) {
    if (!sub) {
      continue;
    }
    auto child = std::make_shared<CommandNode>();
    child->name = sub->get_name();
    child->parent_func_name = name;
    child->help = sub->get_description();
    child->top_level = false;
    child->app = sub;
    child->root_app_ = nullptr;
    child->ImportFromApp_(sub);
    subcommands[child->name] = child;
  }
}

/**
 * @brief Find child by name for one node.
 */
const CommandNode *CommandNode::FindChild_(const std::string &child) const {
  auto it = subcommands.find(child);
  if (it == subcommands.end() || !it->second) {
    return nullptr;
  }
  return it->second.get();
}

/**
 * @brief Find mutable child by name for one node.
 */
CommandNode *CommandNode::FindChild_(const std::string &child) {
  auto it = subcommands.find(child);
  if (it == subcommands.end() || !it->second) {
    return nullptr;
  }
  return it->second.get();
}

} // namespace AMInterface::parser
