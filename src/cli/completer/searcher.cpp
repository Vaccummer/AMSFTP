#include "AMBase/CommonTools.hpp"
#include "AMCLI/CLIBind.hpp"
#include "AMCLI/Completer/Searcher.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/FileSystem.hpp"
#include "CLI/CLI.hpp"
#include <algorithm>
#include <cctype>
#include <utility>

namespace {
/**
 * @brief Escape bbcode special characters in display text.
 */
std::string EscapeBbcodeText_(const std::string &text) {
  std::string escaped;
  escaped.reserve(text.size() * 2);
  for (char c : text) {
    if (c == '\\') {
      escaped.append("\\\\");
    } else if (c == '[') {
      escaped.append("\\[");
    } else {
      escaped.push_back(c);
    }
  }
  return escaped;
}

/**
 * @brief Unescape backtick-escaped sequences.
 */
std::string UnescapeBackticks_(const std::string &text) {
  if (text.empty()) {
    return text;
  }
  std::string out;
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '`' && i + 1 < text.size()) {
      const char next = text[i + 1];
      if (next == '$' || next == '"' || next == '\'' || next == '`') {
        out.push_back(next);
        ++i;
        continue;
      }
    }
    out.push_back(text[i]);
  }
  return out;
}

/**
 * @brief Return true if string begins with an unescaped '$'.
 */
bool StartsWithUnescapedDollar_(const std::string &raw_prefix,
                                const std::string &raw_token) {
  const std::string &text = raw_prefix.empty() ? raw_token : raw_prefix;
  if (text.size() >= 2 && text[0] == '`' && text[1] == '$') {
    return false;
  }
  return !text.empty() && text[0] == '$';
}

/**
 * @brief Return true if string begins with "--".
 */
bool StartsWithLongOption_(const std::string &text) {
  return text.size() >= 2 && text[0] == '-' && text[1] == '-';
}

/**
 * @brief Return true if string begins with "-" but not "--".
 */
bool StartsWithShortOption_(const std::string &text) {
  return text.size() >= 1 && text[0] == '-' &&
         !(text.size() >= 2 && text[1] == '-');
}

/**
 * @brief Return true when text looks like path input.
 */
bool IsPathLikeText_(const std::string &text) {
  if (text.empty()) {
    return false;
  }
  if (text[0] == '/' || text[0] == '\\' || text[0] == '~') {
    return true;
  }
  if (text.size() >= 2 && std::isalpha(static_cast<unsigned char>(text[0])) &&
      text[1] == ':') {
    return true;
  }
  return text.find('/') != std::string::npos ||
         text.find('\\') != std::string::npos;
}

/**
 * @brief Return true if a command expects path input at the given arg index.
 */
bool IsPathArgumentCommand_(const std::string &command_path, size_t arg_index) {
  if (command_path == "cd" || command_path == "ls" ||
      command_path == "realpath") {
    return arg_index == 0;
  }
  if (command_path == "find" || command_path == "walk" ||
      command_path == "tree") {
    return arg_index == 0;
  }
  if (command_path == "stat" || command_path == "size" ||
      command_path == "mkdir" || command_path == "rm" || command_path == "cp") {
    return true;
  }
  return false;
}

/**
 * @brief Detect path separator for completion output.
 */
char DetectPathSep_(const std::string &path, bool remote) {
  (void)path;
  (void)remote;
  return '/';
}

/**
 * @brief Split path into directory and leaf prefix components.
 */
void SplitPath_(const std::string &path, std::string *dir, std::string *leaf,
                bool *trailing_sep) {
  if (dir) {
    dir->clear();
  }
  if (leaf) {
    leaf->clear();
  }
  if (trailing_sep) {
    *trailing_sep = false;
  }
  if (path.empty()) {
    return;
  }

  const size_t last_sep = path.find_last_of("/\\");
  if (last_sep == std::string::npos) {
    if (leaf) {
      *leaf = path;
    }
    return;
  }

  if (dir) {
    *dir = path.substr(0, last_sep + 1);
  }
  if (leaf && last_sep + 1 < path.size()) {
    *leaf = path.substr(last_sep + 1);
  }
  if (trailing_sep) {
    *trailing_sep = (last_sep + 1 == path.size());
  }
}

/**
 * @brief Return path-type ordering rank.
 */
int PathTypeOrder_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return 0;
  case PathType::DIR:
    return 1;
  case PathType::SYMLINK:
    return 2;
  default:
    return 3;
  }
}

/**
 * @brief Static host configuration fields for completion.
 */
const std::vector<std::string> kHostConfigFields = {
    "hostname",  "username", "port",        "keyfile",  "password",
    "trash_dir", "protocol", "buffer_size", "login_dir"};

/**
 * @brief Resolve a token text by index from completion context.
 */
std::string ExtractTokenText_(const AMCompletionContext &ctx, size_t index) {
  if (index >= ctx.tokens.size()) {
    return "";
  }
  const auto &token = ctx.tokens[index];
  if (token.content_end <= token.content_start ||
      token.content_end > ctx.input.size()) {
    return "";
  }
  return UnescapeBackticks_(ctx.input.substr(
      token.content_start, token.content_end - token.content_start));
}

/**
 * @brief Return true when command name is a module command.
 */
bool IsModuleCommand_(const std::string &name) {
  return name == "config" || name == "client" || name == "task";
}

/**
 * @brief Parsed command/argument state from tokens before cursor.
 */
struct CommandState {
  std::string command_path;
  size_t command_tokens = 0;
  size_t arg_index = 0;
};

/**
 * @brief Resolve command path and positional arg index from token context.
 */
CommandState ResolveCommandState_(const AMCompletionContext &ctx) {
  CommandState state;
  std::vector<std::string> before;
  before.reserve(ctx.token_index);

  for (size_t i = 0; i < ctx.tokens.size() && i < ctx.token_index; ++i) {
    std::string text = ExtractTokenText_(ctx, i);
    if (!text.empty()) {
      before.push_back(std::move(text));
    }
  }

  if (before.empty()) {
    return state;
  }

  state.command_path = before[0];
  state.command_tokens = 1;
  if (before.size() >= 2 && IsModuleCommand_(before[0]) &&
      !StartsWithLongOption_(before[1]) && !StartsWithShortOption_(before[1])) {
    state.command_path += " " + before[1];
    state.command_tokens = 2;
  }

  for (size_t i = state.command_tokens; i < before.size(); ++i) {
    if (StartsWithLongOption_(before[i]) || StartsWithShortOption_(before[i])) {
      continue;
    }
    ++state.arg_index;
  }
  return state;
}
} // namespace
/**
 * @brief Construct command search engine.
 */

/**
 * @brief Collect command-related candidates.
 */
AMCompletionCollectResult
AMCommandSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCollectResult result;
  const std::string prefix = ctx.token_prefix;

  std::string command_path;
  const CommandNode *node = nullptr;
  size_t command_tokens = 0;
  ParseCommandPath_(ctx, &command_path, &node, &command_tokens);

  const bool wants_top =
      ctx.target == AMCompletionTarget::TopCommand ||
      (ctx.target == AMCompletionTarget::None && ctx.token_index == 0);

  if (wants_top) {
    struct ItemInfo {
      std::string name;
      std::string help;
      bool is_module = false;
    };
    std::vector<ItemInfo> items;
    auto tops = command_tree_.ListTopCommands();
    for (const auto &item : tops) {
      if (!prefix.empty() && item.first.rfind(prefix, 0) != 0) {
        continue;
      }
      items.push_back(
          {item.first, item.second, command_tree_.IsModule(item.first)});
    }

    size_t max_len = 0;
    for (const auto &item : items) {
      max_len = std::max(max_len, item.name.size());
    }

    for (const auto &item : items) {
      AMCompletionCandidate candidate;
      candidate.insert_text = item.name;
      candidate.display = FormatCommandDisplay_(
          item.name, item.is_module ? "module" : "command", max_len, ctx.args);
      candidate.help = item.help;
      candidate.kind =
          item.is_module ? AMCompletionKind::Module : AMCompletionKind::Command;
      candidate.score = item.is_module ? 0 : 1;
      result.candidates.push_back(std::move(candidate));
    }
  }

  const bool wants_subcommand = ctx.target == AMCompletionTarget::Subcommand ||
                                ctx.target == AMCompletionTarget::None;
  if (wants_subcommand && node && !node->subcommands.empty() &&
      ctx.token_index == command_tokens) {
    struct ItemInfo {
      std::string name;
      std::string help;
    };
    std::vector<ItemInfo> items;
    auto subs = command_tree_.ListSubcommands(command_path);
    for (const auto &item : subs) {
      if (!prefix.empty() && item.first.rfind(prefix, 0) != 0) {
        continue;
      }
      items.push_back({item.first, item.second});
    }

    size_t max_len = 0;
    for (const auto &item : items) {
      max_len = std::max(max_len, item.name.size());
    }

    for (const auto &item : items) {
      AMCompletionCandidate candidate;
      candidate.insert_text = item.name;
      candidate.display =
          FormatCommandDisplay_(item.name, "command", max_len, ctx.args);
      candidate.help = item.help;
      candidate.kind = AMCompletionKind::Command;
      result.candidates.push_back(std::move(candidate));
    }
  }

  const bool wants_long_option =
      ctx.target == AMCompletionTarget::LongOption ||
      (ctx.target == AMCompletionTarget::None && StartsWithLongOption_(prefix));
  if (wants_long_option && node) {
    auto options = command_tree_.ListLongOptions(command_path);
    for (const auto &item : options) {
      if (!prefix.empty() && item.first.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompletionCandidate candidate;
      candidate.insert_text = item.first;
      candidate.display = item.first;
      candidate.help = item.second;
      candidate.kind = AMCompletionKind::Option;
      result.candidates.push_back(std::move(candidate));
    }
  }

  const bool wants_short_option =
      ctx.target == AMCompletionTarget::ShortOption ||
      (ctx.target == AMCompletionTarget::None &&
       StartsWithShortOption_(prefix));
  if (wants_short_option && node) {
    auto options = command_tree_.ListShortOptions(command_path);
    for (const auto &item : options) {
      const std::string name = std::string("-") + item.first;
      if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompletionCandidate candidate;
      candidate.insert_text = name;
      candidate.display = name;
      candidate.help = item.second;
      candidate.kind = AMCompletionKind::Option;
      result.candidates.push_back(std::move(candidate));
    }
  }

  return result;
}

/**
 * @brief Sort command-related candidates.
 */
void AMCommandSearchEngine::SortCandidates(
    const AMCompletionContext &ctx, std::vector<AMCompletionCandidate> &items) {
  (void)ctx;
  std::stable_sort(items.begin(), items.end(),
                   [](const auto &lhs, const auto &rhs) {
                     if (lhs.score != rhs.score) {
                       return lhs.score < rhs.score;
                     }
                     return lhs.insert_text < rhs.insert_text;
                   });
}

/**
 * @brief Build styled command/module display text.
 */
std::string AMCommandSearchEngine::FormatCommandDisplay_(
    const std::string &name, const std::string &style_key, size_t pad_width,
    const AMCompletionArgs *args) const {
  const std::string command_tag = args ? args->input_tag_command : "";
  const std::string module_tag = args ? args->input_tag_module : "";
  const std::string tag = style_key == "module" ? module_tag : command_tag;

  const std::string escaped = EscapeBbcodeText_(name);
  std::string display = tag.empty() ? escaped : tag + escaped + "[/]";
  if (pad_width > name.size()) {
    display.append(pad_width - name.size(), ' ');
  }
  return display;
}

/**
 * @brief Parse command path from tokens before cursor.
 */
void AMCommandSearchEngine::ParseCommandPath_(const AMCompletionContext &ctx,
                                              std::string *out_path,
                                              const CommandNode **out_node,
                                              size_t *out_consumed) const {
  std::string path;
  const CommandNode *node = nullptr;
  size_t consumed = 0;

  for (size_t i = 0; i < ctx.tokens.size() && i < ctx.token_index; ++i) {
    const auto &token = ctx.tokens[i];
    if (token.quoted) {
      break;
    }

    std::string text = ExtractTokenText_(ctx, i);
    if (text.empty()) {
      break;
    }

    if (path.empty()) {
      if (command_tree_.IsModule(text) || command_tree_.IsTopCommand(text)) {
        path = text;
        node = command_tree_.FindNode(path);
        consumed = i + 1;
        continue;
      }
      break;
    }

    if (node && node->subcommands.find(text) != node->subcommands.end()) {
      path += " " + text;
      node = command_tree_.FindNode(path);
      consumed = i + 1;
      continue;
    }

    break;
  }

  if (out_path) {
    *out_path = path;
  }
  if (out_node) {
    *out_node = node;
  }
  if (out_consumed) {
    *out_consumed = consumed;
  }
}

/**
 * @brief Construct and build the command tree.
 */
AMCommandSearchEngine::CommandTree::CommandTree() { Build(); }

/**
 * @brief Return true when name is a top-level command.
 */
bool AMCommandSearchEngine::CommandTree::IsTopCommand(
    const std::string &name) const {
  return top_commands_.find(name) != top_commands_.end();
}

/**
 * @brief Return true when name is a module (has subcommands).
 */
bool AMCommandSearchEngine::CommandTree::IsModule(
    const std::string &name) const {
  return modules_.find(name) != modules_.end();
}

/**
 * @brief Find a node by command path.
 */
const AMCommandSearchEngine::CommandNode *
AMCommandSearchEngine::CommandTree::FindNode(const std::string &path) const {
  auto it = nodes_.find(path);
  if (it == nodes_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief List top-level commands with help text.
 */
std::vector<std::pair<std::string, std::string>>
AMCommandSearchEngine::CommandTree::ListTopCommands() const {
  std::vector<std::pair<std::string, std::string>> out;
  out.reserve(top_commands_.size());
  for (const auto &item : top_commands_) {
    auto it = top_help_.find(item);
    out.emplace_back(item, it == top_help_.end() ? "" : it->second);
  }
  std::sort(out.begin(), out.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  return out;
}

/**
 * @brief List subcommands for a command path.
 */
std::vector<std::pair<std::string, std::string>>
AMCommandSearchEngine::CommandTree::ListSubcommands(
    const std::string &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  const auto *node = FindNode(path);
  if (!node) {
    return out;
  }

  out.reserve(node->subcommands.size());
  for (const auto &item : node->subcommands) {
    out.emplace_back(item.first, item.second);
  }
  std::sort(out.begin(), out.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  return out;
}
/**
 * @brief List long options for a command path.
 */
std::vector<std::pair<std::string, std::string>>
AMCommandSearchEngine::CommandTree::ListLongOptions(
    const std::string &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  const auto *node = FindNode(path);
  if (!node) {
    return out;
  }

  out.reserve(node->long_options.size());
  for (const auto &item : node->long_options) {
    out.emplace_back(item.first, item.second);
  }
  std::sort(out.begin(), out.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  return out;
}

/**
 * @brief List short options for a command path.
 */
std::vector<std::pair<char, std::string>>
AMCommandSearchEngine::CommandTree::ListShortOptions(
    const std::string &path) const {
  std::vector<std::pair<char, std::string>> out;
  const auto *node = FindNode(path);
  if (!node) {
    return out;
  }

  out.reserve(node->short_options.size());
  for (const auto &item : node->short_options) {
    out.emplace_back(item.first, item.second);
  }
  std::sort(out.begin(), out.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  return out;
}

/**
 * @brief Build tree structure from CLI metadata.
 */
void AMCommandSearchEngine::CommandTree::Build() {
  CLI::App app;
  CliArgsPool args_pool;
  (void)BindCliOptions(app, args_pool);

  auto build_node = [&](auto &&self, CLI::App *node,
                        const std::string &path) -> void {
    CommandNode info;
    auto options = node->get_options();
    for (auto *opt : options) {
      const std::string desc = opt ? opt->get_description() : "";
      for (const auto &lname : opt->get_lnames()) {
        if (!lname.empty()) {
          info.long_options["--" + lname] = desc;
        }
      }
      for (const auto &sname : opt->get_snames()) {
        if (!sname.empty()) {
          info.short_options[sname[0]] = desc;
        }
      }
    }

    auto subs = node->get_subcommands([](CLI::App *) { return true; });
    for (auto *sub : subs) {
      if (sub) {
        info.subcommands[sub->get_name()] = sub->get_description();
      }
    }

    nodes_[path] = info;
    if (path.find(' ') == std::string::npos && !info.subcommands.empty()) {
      modules_.insert(path);
    }

    for (auto *sub : subs) {
      if (!sub) {
        continue;
      }
      const std::string next =
          path.empty() ? sub->get_name() : path + " " + sub->get_name();
      self(self, sub, next);
    }
  };

  auto subs = app.get_subcommands([](CLI::App *) { return true; });
  for (auto *sub : subs) {
    if (!sub) {
      continue;
    }
    const std::string name = sub->get_name();
    RegisterCommand_(name, sub->get_description());
    build_node(build_node, sub, name);
  }
}

/**
 * @brief Register a command path as top-level command.
 */
void AMCommandSearchEngine::CommandTree::RegisterCommand_(
    const std::string &path, const std::string &help) {
  if (path.empty()) {
    return;
  }
  top_commands_.insert(path);
  if (!help.empty()) {
    top_help_[path] = help;
  }
}

/**
 * @brief Collect internal-value candidates.
 */
AMCompletionCollectResult
AMInternalSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCollectResult result;

  AMCompletionTarget target = AMCompletionTarget::None;
  if (ctx.target == AMCompletionTarget::VariableName ||
      StartsWithUnescapedDollar_(ctx.token_prefix_raw, ctx.token_raw)) {
    target = AMCompletionTarget::VariableName;
  } else {
    const CommandState state = ResolveCommandState_(ctx);

    if (state.command_path == "config get" ||
        state.command_path == "config edit" ||
        state.command_path == "config rm") {
      target = AMCompletionTarget::HostNickname;
    } else if (state.command_path == "config rn" && state.arg_index == 0) {
      target = AMCompletionTarget::HostNickname;
    } else if (state.command_path == "config set") {
      if (state.arg_index == 0) {
        target = AMCompletionTarget::HostNickname;
      } else if (state.arg_index == 1) {
        target = AMCompletionTarget::HostAttr;
      }
    } else if (state.command_path == "connect" && state.arg_index == 0) {
      target = AMCompletionTarget::HostNickname;
    } else if (state.command_path == "client check" ||
               state.command_path == "client rm") {
      target = AMCompletionTarget::ClientName;
    } else if (state.command_path == "ch" && state.arg_index == 0) {
      target = AMCompletionTarget::ClientName;
    } else if (state.command_path == "task show" ||
               state.command_path == "task inspect" ||
               state.command_path == "task terminate" ||
               state.command_path == "task pause") {
      target = AMCompletionTarget::TaskId;
    } else if ((state.command_path == "task retry" ||
                state.command_path == "retry") &&
               state.arg_index == 0) {
      target = AMCompletionTarget::TaskId;
    }
  }

  const std::string prefix = ctx.token_prefix;
  if (target == AMCompletionTarget::VariableName) {
    AMVarManager &var_manager = AMVarManager::Instance();
    auto names = var_manager.ListNames();
    for (const auto &name : names) {
      const std::string full = "$" + name;
      if (!prefix.empty() && full.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompletionCandidate candidate;
      candidate.insert_text = full;
      candidate.display = full;
      candidate.kind = AMCompletionKind::VariableName;
      result.candidates.push_back(std::move(candidate));
    }
    return result;
  }

  if (target == AMCompletionTarget::ClientName) {
    auto names = client_manager_.GetClientNames();
    for (const auto &name : names) {
      if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompletionCandidate candidate;
      candidate.insert_text = name;
      candidate.display = name;
      candidate.kind = AMCompletionKind::ClientName;
      result.candidates.push_back(std::move(candidate));
    }
    return result;
  }

  if (target == AMCompletionTarget::HostNickname) {
    auto names = host_manager_.ListNames();
    for (const auto &name : names) {
      if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompletionCandidate candidate;
      candidate.insert_text = name;
      candidate.display = name;
      candidate.kind = AMCompletionKind::HostNickname;
      result.candidates.push_back(std::move(candidate));
    }
    return result;
  }

  if (target == AMCompletionTarget::HostAttr) {
    for (const auto &field : kHostConfigFields) {
      if (!prefix.empty() && field.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompletionCandidate candidate;
      candidate.insert_text = field;
      candidate.display = field;
      candidate.kind = AMCompletionKind::HostAttr;
      result.candidates.push_back(std::move(candidate));
    }
    return result;
  }

  if (target == AMCompletionTarget::TaskId) {
    auto ids = transfer_manager_.ListTaskIds();
    for (const auto &id : ids) {
      if (!prefix.empty() && id.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompletionCandidate candidate;
      candidate.insert_text = id;
      candidate.display = id;
      candidate.kind = AMCompletionKind::TaskId;
      result.candidates.push_back(std::move(candidate));
    }
  }

  return result;
}

/**
 * @brief Sort internal-value candidates.
 */
void AMInternalSearchEngine::SortCandidates(
    const AMCompletionContext &ctx, std::vector<AMCompletionCandidate> &items) {
  (void)ctx;
  std::stable_sort(items.begin(), items.end(),
                   [](const auto &lhs, const auto &rhs) {
                     if (lhs.score != rhs.score) {
                       return lhs.score < rhs.score;
                     }
                     return lhs.insert_text < rhs.insert_text;
                   });
}
/**
 * @brief Construct path search engine.
 */
AMPathSearchEngine::AMPathSearchEngine()
    : config_manager_(AMConfigManager::Instance()),
      client_manager_(AMClientManager::Instance()),
      filesystem_(AMFileSystem::Instance()) {}

/**
 * @brief Collect path candidates or async path requests.
 */
AMCompletionCollectResult
AMPathSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCollectResult result;
  if (ctx.target != AMCompletionTarget::Path &&
      ctx.target != AMCompletionTarget::None) {
    return result;
  }

  const CommandState state = ResolveCommandState_(ctx);
  const bool force_path =
      IsPathArgumentCommand_(state.command_path, state.arg_index);
  const bool has_at = ctx.token_prefix.find('@') != std::string::npos;
  if (!force_path && !has_at && !IsPathLikeText_(ctx.token_prefix)) {
    return result;
  }

  PathContext path = BuildPathContext_(ctx.token_prefix, force_path);
  if (!path.valid) {
    return result;
  }

  CacheKey key{path.nickname, path.dir_abs};
  std::vector<PathInfo> listed;
  if (LookupCache_(key, &listed)) {
    AppendPathCandidates_(path, listed, &result.candidates);
    return result;
  }

  const int timeout_ms = config_manager_.ResolveArg<int>(
      DocumentKind::Settings, {"CompleteOption", "timeout_ms"}, 5000,
      [](int value) { return value > 0 ? value : 5000; });
  const size_t cache_min =
      ctx.args ? ctx.args->cache_min_items : static_cast<size_t>(100);
  const size_t cache_max =
      ctx.args ? ctx.args->cache_max_entries : static_cast<size_t>(64);

  if (!path.remote) {
    auto client = client_manager_.LocalClientBase();
    if (!client) {
      return result;
    }

    auto [rcm, items] =
        client->listdir(path.dir_abs, nullptr, timeout_ms, am_ms());
    if (rcm.first != EC::Success) {
      return result;
    }

    if (items.size() >= cache_min) {
      StoreCache_(key, items, cache_max);
    }
    AppendPathCandidates_(path, items, &result.candidates);
    return result;
  }

  AMCompletionAsyncRequest request;
  request.request_id = ctx.request_id;
  request.timeout_ms = timeout_ms;
  request.target = ctx.target;
  request.interrupt_flag = std::make_shared<std::atomic<bool>>(false);

  request.search = [this, path, cache_min,
                    cache_max](const AMCompletionAsyncRequest &request,
                               AMCompletionAsyncResult *out) -> bool {
    if (request.interrupt_flag &&
        request.interrupt_flag->load(std::memory_order_relaxed)) {
      return false;
    }

    auto client = client_manager_.Clients().GetHost(path.nickname);
    if (!client) {
      return false;
    }

    const int timeout = request.timeout_ms > 0 ? request.timeout_ms : 5000;
    auto [rcm, items] =
        client->listdir(path.dir_abs, nullptr, timeout, am_ms());
    if (rcm.first != EC::Success) {
      return false;
    }

    if (request.interrupt_flag &&
        request.interrupt_flag->load(std::memory_order_relaxed)) {
      return false;
    }

    if (items.size() >= cache_min) {
      CacheKey key{path.nickname, path.dir_abs};
      StoreCache_(key, items, cache_max);
    }

    std::vector<AMCompletionCandidate> candidates;
    AppendPathCandidates_(path, items, &candidates);

    if (out) {
      out->request_id = request.request_id;
      out->target = request.target;
      out->candidates = std::move(candidates);
    }
    return true;
  };

  result.async_request = std::move(request);
  return result;
}

/**
 * @brief Sort path candidates.
 */
void AMPathSearchEngine::SortCandidates(
    const AMCompletionContext &ctx, std::vector<AMCompletionCandidate> &items) {
  (void)ctx;
  std::stable_sort(items.begin(), items.end(),
                   [](const auto &lhs, const auto &rhs) {
                     if (lhs.score != rhs.score) {
                       return lhs.score < rhs.score;
                     }
                     const int lo = PathTypeOrder_(lhs.path_type);
                     const int ro = PathTypeOrder_(rhs.path_type);
                     if (lo != ro) {
                       return lo < ro;
                     }
                     return lhs.insert_text < rhs.insert_text;
                   });
}

/**
 * @brief Clear internal path cache.
 */
void AMPathSearchEngine::ClearCache() {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  cache_.clear();
}

/**
 * @brief Style a path entry for display.
 */
std::string
AMPathSearchEngine::FormatPathDisplay_(const PathInfo &info,
                                       const std::string &name) const {
  auto wrap_pre = [&](const std::string &styled,
                      const std::string &raw) -> std::string {
    if (styled == raw || raw.empty() ||
        styled.find("[/") == std::string::npos) {
      return styled;
    }

    const size_t pos = styled.find(raw);
    if (pos == std::string::npos) {
      return styled;
    }

    std::string result = styled;
    result.replace(pos, raw.size(), "[!pre]" + raw + "[/pre]");
    return result;
  };

  const std::string styled = filesystem_.StylePath(info, name);
  return wrap_pre(styled, name);
}

/**
 * @brief Build path context from completion token and mode.
 */
AMPathSearchEngine::PathContext
AMPathSearchEngine::BuildPathContext_(const std::string &token_prefix,
                                      bool force_path) const {
  PathContext path;
  if (token_prefix.empty() && !force_path) {
    return path;
  }

  const auto current_client = client_manager_.CurrentClient()
                                  ? client_manager_.CurrentClient()
                                  : client_manager_.LocalClientBase();
  const bool current_remote =
      current_client && current_client->GetProtocol() != ClientProtocol::LOCAL;

  bool force_local = false;
  std::string nickname;
  std::string path_part;
  std::string header;

  if (!token_prefix.empty() && token_prefix.front() == '@') {
    force_local = true;
    nickname = "local";
    path_part = token_prefix.substr(1);
    header = "@";
  } else {
    const size_t at_pos = token_prefix.find('@');
    if (at_pos != std::string::npos) {
      nickname = token_prefix.substr(0, at_pos);
      path_part = token_prefix.substr(at_pos + 1);
      header = nickname + "@";
      if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
        force_local = true;
        nickname = "local";
      }
    } else {
      path_part = token_prefix;
      if (current_remote && current_client) {
        nickname = current_client->GetNickname();
      } else {
        nickname = "local";
      }
    }
  }

  if (header.empty() && !force_path && !IsPathLikeText_(path_part)) {
    return path;
  }

  path.remote = (!force_local && current_remote && header.empty()) ||
                (!force_local && !header.empty() &&
                 AMStr::lowercase(nickname) != "local");
  path.nickname = nickname.empty() ? "local" : nickname;
  path.header = header;
  path.raw_path = path_part;
  path.sep = DetectPathSep_(path_part, path.remote);

  SplitPath_(path_part, &path.dir_raw, &path.leaf_prefix, &path.trailing_sep);

  if (path_part.size() == 2 &&
      std::isalpha(static_cast<unsigned char>(path_part[0])) &&
      path_part[1] == ':') {
    path.dir_raw = path_part + path.sep;
    path.leaf_prefix.clear();
    path.trailing_sep = true;
  }

  path.base = path.header + path.dir_raw;

  std::shared_ptr<BaseClient> client;
  if (path.remote) {
    client = client_manager_.Clients().GetHost(path.nickname);
  } else {
    client = client_manager_.LocalClientBase();
  }
  if (!client) {
    return path;
  }

  path.dir_abs = client_manager_.BuildPath(client, path.dir_raw);
  path.valid = true;
  return path;
}

/**
 * @brief Append filtered path candidates from listed items.
 */
void AMPathSearchEngine::AppendPathCandidates_(
    const PathContext &path_ctx, const std::vector<PathInfo> &items,
    std::vector<AMCompletionCandidate> *out) const {
  if (!out) {
    return;
  }

  const std::string &prefix = path_ctx.leaf_prefix;
  bool has_case_match = false;
  if (!prefix.empty()) {
    for (const auto &info : items) {
      if (info.name.rfind(prefix, 0) == 0) {
        has_case_match = true;
        break;
      }
    }
  }

  const std::string prefix_lower =
      prefix.empty() ? std::string() : AMStr::lowercase(prefix);

  for (const auto &info : items) {
    std::string name = info.name;
    if (!prefix.empty()) {
      if (has_case_match) {
        if (name.rfind(prefix, 0) != 0) {
          continue;
        }
      } else {
        if (AMStr::lowercase(name).rfind(prefix_lower, 0) != 0) {
          continue;
        }
      }
    }

    AMCompletionCandidate candidate;
    const bool is_dir = info.type == PathType::DIR;
    candidate.insert_text = path_ctx.base + name;
    if (is_dir) {
      candidate.insert_text.push_back(path_ctx.sep);
    }

    const std::string display_name = is_dir ? name + path_ctx.sep : name;
    candidate.display = FormatPathDisplay_(info, display_name);
    candidate.kind = path_ctx.remote ? AMCompletionKind::PathRemote
                                     : AMCompletionKind::PathLocal;
    candidate.path_type = info.type;
    out->push_back(std::move(candidate));
  }
}

/**
 * @brief Lookup path cache entries.
 */
bool AMPathSearchEngine::LookupCache_(const CacheKey &key,
                                      std::vector<PathInfo> *items) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  auto it = cache_.find(key);
  if (it == cache_.end()) {
    return false;
  }
  if (items) {
    *items = it->second.items;
  }
  return true;
}

/**
 * @brief Store path cache entries and prune old entries.
 */
void AMPathSearchEngine::StoreCache_(const CacheKey &key,
                                     const std::vector<PathInfo> &items,
                                     size_t max_entries) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  cache_[key] = CacheEntry{items, std::chrono::steady_clock::now()};
  if (cache_.size() <= max_entries) {
    return;
  }

  while (cache_.size() > max_entries) {
    auto oldest = cache_.begin();
    for (auto iter = cache_.begin(); iter != cache_.end(); ++iter) {
      if (iter->second.timestamp < oldest->second.timestamp) {
        oldest = iter;
      }
    }
    cache_.erase(oldest);
  }
}

/**
 * @brief Build the default completion search-engine registration set.
 */
std::vector<AMSearchEngineRegistration>
AMBuildDefaultSearchEngineRegistrations() {
  std::vector<AMSearchEngineRegistration> out;

  auto command_engine = std::make_shared<AMCommandSearchEngine>();
  out.push_back(
      {{AMCompletionTarget::TopCommand, AMCompletionTarget::Subcommand,
        AMCompletionTarget::LongOption, AMCompletionTarget::ShortOption,
        AMCompletionTarget::None},
       command_engine});

  auto internal_engine = std::make_shared<AMInternalSearchEngine>();
  out.push_back({{AMCompletionTarget::VariableName, AMCompletionTarget::None},
                 internal_engine});

  auto path_engine = std::make_shared<AMPathSearchEngine>();
  out.push_back(
      {{AMCompletionTarget::Path, AMCompletionTarget::None}, path_engine});

  return out;
}

void AMCompleteEngine::Init() {
  auto registrations = AMBuildDefaultSearchEngineRegistrations();
  for (const auto &entry : registrations) {
    RegisterSearchEngine(entry.targets, entry.engine);
  }
}
