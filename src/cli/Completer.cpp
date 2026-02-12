#include "AMCLI/Completer.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/Path.hpp"
#include "AMCLI/CLIBind.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Var.hpp"
#include "CLI/CLI.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {
std::atomic<AMCompleter *> g_active_completer{nullptr};
/**
 * @brief Normalize a configured style into a bbcode opening tag.
 */
std::string NormalizeStyleTag_(const std::string &raw) {
  std::string trimmed = AMStr::Strip(raw);
  if (trimmed.empty()) {
    return "";
  }
  if (trimmed.find("[/") != std::string::npos) {
    return "";
  }
  if (trimmed.front() != '[') {
    trimmed.insert(trimmed.begin(), '[');
  }
  if (trimmed.back() != ']') {
    trimmed.push_back(']');
  }
  return trimmed;
}

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
 * @brief Token span for completion parsing.
 */
struct CompletionToken {
  size_t start = 0;
  size_t end = 0;
  size_t content_start = 0;
  size_t content_end = 0;
  bool quoted = false;
};

/**
 * @brief Completion target classification.
 */
enum class CompletionTarget {
  None,
  Disabled,
  TopCommand,
  Subcommand,
  LongOption,
  ShortOption,
  VariableName,
  ClientName,
  HostNickname,
  HostAttr,
  TaskId,
  Path,
};

/**
 * @brief Candidate kind metadata.
 */
enum class CompletionKind {
  Module,
  Command,
  Option,
  VariableName,
  ClientName,
  HostNickname,
  HostAttr,
  TaskId,
  PathLocal,
  PathRemote,
};

/**
 * @brief Single completion candidate.
 */
struct CompletionCandidate {
  std::string insert_text;
  std::string display;
  std::string help;
  CompletionKind kind = CompletionKind::Command;
  int score = 0;
  PathType path_type = PathType::Unknown;
};

/**
 * @brief Parsed path completion context.
 */
struct PathContext {
  bool valid = false;
  bool remote = false;
  std::string nickname;
  std::string header;
  std::string raw_path;
  std::string dir_raw;
  std::string leaf_prefix;
  std::string base;
  std::string dir_abs;
  char sep = '/';
  bool trailing_sep = false;
};

/**
 * @brief Parsed completion context.
 */
struct CompletionContext {
  std::string input;
  size_t cursor = 0;
  uint64_t request_id = 0;
  bool has_token = false;
  CompletionToken token;
  std::string token_raw;
  std::string token_text;
  std::string token_prefix_raw;
  std::string token_prefix;
  bool token_quoted = false;
  std::string command_path;
  size_t command_tokens = 0;
  size_t arg_index = 0;
  const void *command_node = nullptr;
  CompletionTarget target = CompletionTarget::None;
  PathContext path;
};

/**
 * @brief Command tree node for completion.
 */
struct CommandNode {
  std::unordered_map<std::string, std::string> subcommands;
  std::unordered_map<std::string, std::string> long_options;
  std::unordered_map<char, std::string> short_options;
};

/**
 * @brief CLI command tree used for completion lookups.
 */
class CommandTree {
public:
  /**
   * @brief Construct and build the command tree.
   */
  CommandTree() { Build(); }

  /**
   * @brief Return true when name is a top-level command.
   */
  bool IsTopCommand(const std::string &name) const {
    return top_commands_.find(name) != top_commands_.end();
  }

  /**
   * @brief Return true when name is a module (has subcommands).
   */
  bool IsModule(const std::string &name) const {
    return modules_.find(name) != modules_.end();
  }

  /**
   * @brief Find a node by its command path.
   */
  const CommandNode *FindNode(const std::string &path) const {
    auto it = nodes_.find(path);
    if (it == nodes_.end()) {
      return nullptr;
    }
    return &it->second;
  }

  /**
   * @brief List top-level commands with help text.
   */
  std::vector<std::pair<std::string, std::string>> ListTopCommands() const {
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
  ListSubcommands(const std::string &path) const {
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
  ListLongOptions(const std::string &path) const {
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
  ListShortOptions(const std::string &path) const {
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

private:
  /**
   * @brief Build the command tree from CLI11 bindings.
   */
  void Build() {
    CLI::App app{"AMSFTP CLI", "amsftp"};
    CliArgsPool args_pool;
    (void)BindCliOptions(app, args_pool);

    auto subs = app.get_subcommands([](CLI::App *) { return true; });
    for (auto *sub : subs) {
      top_commands_.insert(sub->get_name());
      top_help_[sub->get_name()] = sub->get_description();
    }
    top_commands_.insert("var");
    top_help_["var"] = "Variable manager";
    top_commands_.insert("del");
    top_help_["del"] = "Delete variables";
    for (auto *sub : subs) {
      auto nested = sub->get_subcommands([](CLI::App *) { return true; });
      if (!nested.empty()) {
        modules_.insert(sub->get_name());
      }
    }

    BuildNode(&app, "", true);
  }

  /**
   * @brief Build a command node for a CLI path.
   */
  void BuildNode(CLI::App *app, const std::string &path, bool is_root) {
    CommandNode node;
    auto options = app->get_options();
    for (auto *opt : options) {
      const std::string desc = opt ? opt->get_description() : "";
      for (const auto &lname : opt->get_lnames()) {
        if (!lname.empty()) {
          node.long_options["--" + lname] = desc;
        }
      }
      for (const auto &sname : opt->get_snames()) {
        if (!sname.empty()) {
          node.short_options[sname[0]] = desc;
        }
      }
    }

    auto subs = app->get_subcommands([](CLI::App *) { return true; });
    for (auto *sub : subs) {
      if (sub) {
        node.subcommands[sub->get_name()] = sub->get_description();
      }
    }

    if (!is_root) {
      nodes_[path] = node;
    }

    for (auto *sub : subs) {
      std::string next =
          path.empty() ? sub->get_name() : path + " " + sub->get_name();
      BuildNode(sub, next, false);
    }
  }

  std::unordered_set<std::string> top_commands_;
  std::unordered_set<std::string> modules_;
  std::unordered_map<std::string, std::string> top_help_;
  std::unordered_map<std::string, CommandNode> nodes_;
};

/**
 * @brief Cache key for path completions.
 */
struct CacheKey {
  std::string nickname;
  std::string dir;

  /**
   * @brief Compare two cache keys.
   */
  bool operator==(const CacheKey &other) const {
    return nickname == other.nickname && dir == other.dir;
  }
};

/**
 * @brief Hash for CacheKey.
 */
struct CacheKeyHash {
  /**
   * @brief Hash a cache key for unordered_map usage.
   */
  std::size_t operator()(const CacheKey &key) const {
    return std::hash<std::string>()(key.nickname) ^
           (std::hash<std::string>()(key.dir) << 1);
  }
};

/**
 * @brief Cache entry for path results.
 */
struct CacheEntry {
  std::vector<PathInfo> items;
  std::chrono::steady_clock::time_point timestamp;
};

/**
 * @brief Async path completion request.
 */
struct AsyncRequest {
  uint64_t request_id = 0;
  CacheKey key;
  std::string base;
  std::string leaf_prefix;
  char sep = '/';
  bool remote = false;
};

/**
 * @brief Async path completion result.
 */
struct AsyncResult {
  uint64_t request_id = 0;
  CacheKey key;
  std::string base;
  std::string leaf_prefix;
  char sep = '/';
  bool remote = false;
  std::vector<PathInfo> items;
};

/**
 * @brief Return true if character is a quote.
 */
bool IsQuoteChar(char c) { return c == '"' || c == '\''; }

/**
 * @brief Unescape backtick-escaped sequences.
 */
std::string UnescapeBackticks(const std::string &text) {
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
 * @brief Tokenize input into completion tokens.
 */
std::vector<CompletionToken> TokenizeInput(const std::string &input) {
  std::vector<CompletionToken> tokens;
  size_t i = 0;
  while (i < input.size()) {
    while (i < input.size() &&
           std::isspace(static_cast<unsigned char>(input[i])) != 0) {
      ++i;
    }
    if (i >= input.size()) {
      break;
    }
    const size_t start = i;
    if (IsQuoteChar(input[i])) {
      const char quote = input[i];
      ++i;
      const size_t content_start = i;
      while (i < input.size()) {
        if (input[i] == '`' && i + 1 < input.size() && input[i + 1] == quote) {
          i += 2;
          continue;
        }
        if (input[i] == quote) {
          break;
        }
        ++i;
      }
      const size_t content_end = i;
      if (i < input.size() && input[i] == quote) {
        ++i;
      }
      const size_t end = i;
      tokens.push_back({start, end, content_start, content_end, true});
      continue;
    }
    while (i < input.size() &&
           std::isspace(static_cast<unsigned char>(input[i])) == 0) {
      ++i;
    }
    const size_t end = i;
    tokens.push_back({start, end, start, end, false});
  }
  return tokens;
}

/**
 * @brief Find the token that owns the cursor.
 */
bool FindTokenAtCursor(const std::vector<CompletionToken> &tokens,
                       size_t cursor, CompletionToken *out, size_t *out_index) {
  for (size_t i = 0; i < tokens.size(); ++i) {
    const auto &tok = tokens[i];
    const size_t begin = tok.quoted ? tok.content_start : tok.start;
    const size_t end = tok.quoted ? tok.content_end : tok.end;
    if (cursor >= begin && cursor <= end) {
      if (out) {
        *out = tok;
      }
      if (out_index) {
        *out_index = i;
      }
      return true;
    }
  }
  return false;
}

/**
 * @brief Return true if string begins with an unescaped '$'.
 */
bool StartsWithUnescapedDollar(const std::string &raw_prefix,
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
bool StartsWithLongOption(const std::string &text) {
  return text.size() >= 2 && text[0] == '-' && text[1] == '-';
}

/**
 * @brief Return true if string begins with "-" but not "--".
 */
bool StartsWithShortOption(const std::string &text) {
  return text.size() >= 1 && text[0] == '-' &&
         !(text.size() >= 2 && text[1] == '-');
}

/**
 * @brief Return true if text looks like a path input.
 */
bool IsPathLikeText(const std::string &text) {
  if (text.empty()) {
    return false;
  }
  if (text[0] == '/' || text[0] == '\\') {
    return true;
  }
  if (text[0] == '~') {
    return true;
  }
  if (text.size() >= 2 && std::isalpha(static_cast<unsigned char>(text[0])) &&
      text[1] == ':') {
    return true;
  }
  if (text.find('/') != std::string::npos ||
      text.find('\\') != std::string::npos) {
    return true;
  }
  return false;
}

/**
 * @brief Return true if a command expects path input at the given arg index.
 */
bool IsPathArgumentCommand(const std::string &command_path, size_t arg_index) {
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
char DetectPathSep(const std::string &path, bool remote) {
  (void)path;
  (void)remote;
  return '/';
}

/**
 * @brief Split path into directory and leaf prefix components.
 */
void SplitPath(const std::string &path, std::string *dir, std::string *leaf,
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
  if (leaf) {
    if (last_sep + 1 < path.size()) {
      *leaf = path.substr(last_sep + 1);
    }
  }
  if (trailing_sep) {
    *trailing_sep = (last_sep + 1 == path.size());
  }
}

/**
 * @brief Order path types per completion sorting rules.
 */
int PathTypeOrder(PathType type) {
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
 * @brief Return true when candidate is a path type.
 */
bool IsPathCandidate(CompletionKind kind) {
  return kind == CompletionKind::PathLocal ||
         kind == CompletionKind::PathRemote;
}

/**
 * @brief Static host configuration fields for completion.
 */
const std::vector<std::string> kHostConfigFields = {
    "hostname",  "username", "port",        "keyfile",  "password",
    "trash_dir", "protocol", "buffer_size", "login_dir"};
} // namespace

/**
 * @brief Runtime state for AMCompleter implementation.
 */
struct AMCompleterImpl::State {
  /**
   * @brief Construct the implementation with required managers.
   */
  explicit State(AMCompleterImpl *owner) : owner_(owner) { StartAsyncWorker(); }

  /**
   * @brief Stop the async worker on destruction.
   */
  ~State() { StopAsyncWorker(); }

  /**
   * @brief Install the completer into isocline.
   */
  void Install(void *completion_arg) {
    ic_set_default_completer(&AMCompleter::IsoclineCompleter, completion_arg);
    ic_enable_completion_sort(false);
    ic_enable_completion_preview(true);
    const int max_items = owner_->complete_max_items_;
    if (max_items > 0) {
      ic_set_completion_max_items(max_items);
    }
    ic_set_completion_max_rows(owner_->complete_max_rows_);
    ic_enable_completion_number_pick(owner_->complete_number_pick_);
    ic_enable_completion_auto_fill(owner_->complete_auto_fill_);
    const std::string &select_sign = owner_->complete_select_sign_;
    if (select_sign.empty()) {
      ic_set_completion_select_sign(nullptr);
    } else {
      ic_set_completion_select_sign(select_sign.c_str());
    }
  }

  /**
   * @brief Clear completion caches.
   */
  void ClearCache() {
    {
      std::lock_guard<std::mutex> lock(cache_mtx_);
      cache_.clear();
    }
    {
      std::lock_guard<std::mutex> lock(async_result_mtx_);
      async_result_.reset();
    }
  }

  /**
   * @brief Handle a completion request from isocline.
   */
  void HandleCompletion(ic_completion_env_t *cenv, const std::string &input,
                        size_t cursor) {
    const uint64_t request_id = NextRequestId_(input, cursor);
    CompletionContext ctx = BuildContext_(input, cursor, request_id);
    if (ctx.target == CompletionTarget::Disabled ||
        ctx.target == CompletionTarget::None) {
      return;
    }

    std::vector<CompletionCandidate> candidates;
    switch (ctx.target) {
    case CompletionTarget::TopCommand:
    case CompletionTarget::Subcommand:
    case CompletionTarget::LongOption:
    case CompletionTarget::ShortOption:
      CollectCommandCandidates_(ctx, candidates);
      break;
    case CompletionTarget::VariableName:
    case CompletionTarget::ClientName:
    case CompletionTarget::HostNickname:
    case CompletionTarget::HostAttr:
    case CompletionTarget::TaskId:
      CollectInternalCandidates_(ctx, candidates);
      break;
    case CompletionTarget::Path:
      CollectPathCandidates_(ctx, candidates);
      break;
    default:
      break;
    }

    if (candidates.empty()) {
      return;
    }
    SortCandidates_(candidates);
    EmitCandidates_(cenv, ctx, candidates);
  }

private:
  /**
   * @brief Return true if any client nickname matches the prefix.
   */
  bool HasClientPrefixMatch_(const std::string &prefix) const {
    if (prefix.empty()) {
      return false;
    }
    auto names = client_manager_.GetClientNames();
    for (const auto &name : names) {
      if (name.rfind(prefix, 0) == 0) {
        return true;
      }
    }
    return false;
  }

  /**
   * @brief Generate or reuse request ID for the input.
   */
  uint64_t NextRequestId_(const std::string &input, size_t cursor) {
    std::lock_guard<std::mutex> lock(request_mtx_);
    if (input == last_input_ && cursor == last_cursor_) {
      return last_request_id_;
    }
    last_input_ = input;
    last_cursor_ = cursor;
    last_request_id_ =
        request_counter_.fetch_add(1, std::memory_order_relaxed) + 1;
    current_request_id_.store(last_request_id_, std::memory_order_relaxed);
    {
      std::lock_guard<std::mutex> res_lock(async_result_mtx_);
      async_result_.reset();
    }
    return last_request_id_;
  }

  /**
   * @brief Parse the command path from tokens before the cursor.
   */
  void ParseCommandPath_(const std::vector<CompletionToken> &tokens,
                         const std::string &input, size_t current_index,
                         std::string *out_path, const CommandNode **out_node,
                         size_t *out_consumed) {
    std::string path;
    const CommandNode *node = nullptr;
    size_t consumed = 0;

    for (size_t i = 0; i < tokens.size() && i < current_index; ++i) {
      const auto &token = tokens[i];
      if (token.quoted) {
        break;
      }
      if (token.content_end <= token.content_start) {
        break;
      }
      const std::string raw = input.substr(
          token.content_start, token.content_end - token.content_start);
      const std::string text = UnescapeBackticks(raw);
      if (text.empty()) {
        break;
      }

      if (path.empty()) {
        if (command_tree_.IsModule(text)) {
          path = text;
          node = command_tree_.FindNode(path);
          consumed = i + 1;
          continue;
        }
        if (command_tree_.IsTopCommand(text)) {
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
   * @brief Compute positional argument index for the current token.
   */
  size_t ComputeArgIndex_(const std::vector<CompletionToken> &tokens,
                          const std::string &input, size_t command_tokens,
                          size_t current_index) {
    size_t index = 0;
    for (size_t i = command_tokens; i < tokens.size() && i < current_index;
         ++i) {
      const auto &token = tokens[i];
      if (token.content_end <= token.content_start) {
        continue;
      }
      const std::string raw = input.substr(
          token.content_start, token.content_end - token.content_start);
      const std::string text = UnescapeBackticks(raw);
      if (StartsWithLongOption(text) || StartsWithShortOption(text)) {
        continue;
      }
      index++;
    }
    return index;
  }

  /**
   * @brief Build the completion context for the current input.
   */
  CompletionContext BuildContext_(const std::string &input, size_t cursor,
                                  uint64_t request_id) {
    CompletionContext ctx;
    ctx.input = input;
    ctx.cursor = cursor;
    ctx.request_id = request_id;

    std::string trimmed = AMStr::Strip(input);
    if (!trimmed.empty() && trimmed.front() == '!') {
      ctx.target = CompletionTarget::Disabled;
      return ctx;
    }

    std::vector<CompletionToken> tokens = TokenizeInput(input);
    CompletionToken token;
    size_t token_index = tokens.size();
    ctx.has_token = FindTokenAtCursor(tokens, cursor, &token, &token_index);
    if (!ctx.has_token) {
      token = {cursor, cursor, cursor, cursor, false};
    }
    ctx.token = token;
    ctx.token_quoted = token.quoted;

    if (token.content_end >= token.content_start &&
        token.content_end <= input.size() &&
        token.content_start <= input.size()) {
      ctx.token_raw = input.substr(token.content_start,
                                   token.content_end - token.content_start);
    }
    if (cursor >= token.content_start && cursor <= token.content_end &&
        token.content_start <= input.size()) {
      ctx.token_prefix_raw =
          input.substr(token.content_start, cursor - token.content_start);
    }
    ctx.token_text = UnescapeBackticks(ctx.token_raw);
    ctx.token_prefix = UnescapeBackticks(ctx.token_prefix_raw);

    const CommandNode *node = nullptr;
    size_t command_tokens = 0;
    ParseCommandPath_(tokens, input, token_index, &ctx.command_path, &node,
                      &command_tokens);
    ctx.command_node = node;
    ctx.command_tokens = command_tokens;
    ctx.arg_index =
        ComputeArgIndex_(tokens, input, command_tokens, token_index);

    if (ctx.command_path.empty()) {
      if (token_index == 0 || tokens.empty()) {
        ctx.target = CompletionTarget::TopCommand;
      } else {
        ctx.target = CompletionTarget::None;
      }
      return ctx;
    }

    if (node && !node->subcommands.empty() && token_index == command_tokens) {
      ctx.target = CompletionTarget::Subcommand;
      return ctx;
    }

    if (StartsWithUnescapedDollar(ctx.token_prefix_raw, ctx.token_raw)) {
      ctx.target = CompletionTarget::VariableName;
      return ctx;
    }

    if (StartsWithLongOption(ctx.token_prefix)) {
      ctx.target = CompletionTarget::LongOption;
      return ctx;
    }
    if (StartsWithShortOption(ctx.token_prefix)) {
      ctx.target = CompletionTarget::ShortOption;
      return ctx;
    }

    if (ctx.command_path == "config get" || ctx.command_path == "config edit" ||
        ctx.command_path == "config rm") {
      ctx.target = CompletionTarget::HostNickname;
      return ctx;
    }
    if (ctx.command_path == "config rn") {
      if (ctx.arg_index == 0) {
        ctx.target = CompletionTarget::HostNickname;
        return ctx;
      }
    }
    if (ctx.command_path == "config set") {
      if (ctx.arg_index == 0) {
        ctx.target = CompletionTarget::HostNickname;
        return ctx;
      }
      if (ctx.arg_index == 1) {
        ctx.target = CompletionTarget::HostAttr;
        return ctx;
      }
    }
    if (ctx.command_path == "connect") {
      if (ctx.arg_index == 0) {
        ctx.target = CompletionTarget::HostNickname;
        return ctx;
      }
    }
    if (ctx.command_path == "client check" || ctx.command_path == "client rm") {
      ctx.target = CompletionTarget::ClientName;
      return ctx;
    }
    if (ctx.command_path == "ch") {
      if (ctx.arg_index == 0) {
        ctx.target = CompletionTarget::ClientName;
        return ctx;
      }
    }
    if (ctx.command_path == "task show" || ctx.command_path == "task inspect" ||
        ctx.command_path == "task terminate" ||
        ctx.command_path == "task pause") {
      ctx.target = CompletionTarget::TaskId;
      return ctx;
    }
    if (ctx.command_path == "task retry" || ctx.command_path == "retry") {
      if (ctx.arg_index == 0) {
        ctx.target = CompletionTarget::TaskId;
        return ctx;
      }
    }

    if (IsPathArgumentCommand(ctx.command_path, ctx.arg_index)) {
      const std::string &text = ctx.token_prefix;
      const bool has_at = (text.find('@') != std::string::npos);
      if (text.empty()) {
        ctx.path = BuildPathContext_(ctx, true);
        if (ctx.path.valid) {
          ctx.target = CompletionTarget::Path;
          return ctx;
        }
        ctx.target = CompletionTarget::None;
        return ctx;
      }
      if (has_at) {
        ctx.path = BuildPathContext_(ctx, true);
        if (ctx.path.valid) {
          ctx.target = CompletionTarget::Path;
        } else {
          ctx.target = CompletionTarget::None;
        }
        return ctx;
      }
      if (!IsPathLikeText(text)) {
        if (HasClientPrefixMatch_(text)) {
          ctx.target = CompletionTarget::ClientName;
          return ctx;
        }
        ctx.path = BuildPathContext_(ctx, true);
        if (ctx.path.valid) {
          ctx.target = CompletionTarget::Path;
          return ctx;
        }
        ctx.target = CompletionTarget::None;
        return ctx;
      }
      ctx.path = BuildPathContext_(ctx, true);
      if (ctx.path.valid) {
        ctx.target = CompletionTarget::Path;
        return ctx;
      }
      ctx.target = CompletionTarget::None;
      return ctx;
    }

    ctx.path = BuildPathContext_(ctx, false);
    if (ctx.path.valid) {
      ctx.target = CompletionTarget::Path;
      return ctx;
    }

    ctx.target = CompletionTarget::None;
    return ctx;
  }

  /**
   * @brief Build path-specific context from the token.
   */
  PathContext BuildPathContext_(const CompletionContext &ctx, bool force_path) {
    PathContext path;
    const std::string text = ctx.token_prefix;
    if (text.empty() && !force_path) {
      return path;
    }

    const auto current_client = client_manager_.CurrentClient()
                                    ? client_manager_.CurrentClient()
                                    : client_manager_.LocalClientBase();
    const bool current_remote =
        current_client &&
        current_client->GetProtocol() != ClientProtocol::LOCAL;

    bool force_local = false;
    std::string nickname;
    std::string path_part;
    std::string header;

    if (!text.empty() && text.front() == '@') {
      force_local = true;
      nickname = "local";
      path_part = text.substr(1);
      header = "@";
    } else {
      const size_t at_pos = text.find('@');
      if (at_pos != std::string::npos) {
        nickname = text.substr(0, at_pos);
        path_part = text.substr(at_pos + 1);
        header = nickname + "@";
        if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
          force_local = true;
          nickname = "local";
        }
      } else {
        path_part = text;
        if (current_remote && current_client) {
          nickname = current_client->GetNickname();
        } else {
          nickname = "local";
        }
      }
    }

    if (header.empty() && !force_path && !IsPathLikeText(path_part)) {
      return path;
    }

    path.remote = (!force_local && current_remote && header.empty()) ||
                  (!force_local && !header.empty() &&
                   AMStr::lowercase(nickname) != "local");
    path.nickname = nickname.empty() ? "local" : nickname;
    path.header = header;
    path.raw_path = path_part;
    path.sep = DetectPathSep(path_part, path.remote);

    SplitPath(path_part, &path.dir_raw, &path.leaf_prefix, &path.trailing_sep);

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
   * @brief Build a styled and padded command/module display string.
   */
  std::string FormatCommandDisplay_(const std::string &name,
                                    const std::string &style_key,
                                    size_t pad_width) const {
    const std::string tag = style_key == "module" ? owner_->input_tag_module_
                                                  : owner_->input_tag_command_;
    const std::string escaped = EscapeBbcodeText_(name);
    std::string display = tag.empty() ? escaped : tag + escaped + "[/]";
    if (pad_width > name.size()) {
      display.append(pad_width - name.size(), ' ');
    }
    return display;
  }

  /**
   * @brief Collect command/option candidates.
   */
  void CollectCommandCandidates_(const CompletionContext &ctx,
                                 std::vector<CompletionCandidate> &out) {
    const std::string prefix = ctx.token_prefix;

    if (ctx.target == CompletionTarget::TopCommand) {
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
      if (items.empty()) {
        return;
      }
      size_t max_len = 0;
      for (const auto &item : items) {
        max_len = std::max(max_len, item.name.size());
      }
      for (const auto &item : items) {
        CompletionCandidate cand;
        cand.insert_text = item.name;
        cand.display = FormatCommandDisplay_(
            item.name, item.is_module ? "module" : "command", max_len);
        cand.help = item.help;
        cand.kind =
            item.is_module ? CompletionKind::Module : CompletionKind::Command;
        cand.score = item.is_module ? 0 : 1;
        out.push_back(std::move(cand));
      }
      return;
    }

    if (ctx.target == CompletionTarget::Subcommand) {
      struct ItemInfo {
        std::string name;
        std::string help;
      };
      std::vector<ItemInfo> items;
      auto subs = command_tree_.ListSubcommands(ctx.command_path);
      for (const auto &item : subs) {
        if (!prefix.empty() && item.first.rfind(prefix, 0) != 0) {
          continue;
        }
        items.push_back({item.first, item.second});
      }
      if (items.empty()) {
        return;
      }
      size_t max_len = 0;
      for (const auto &item : items) {
        max_len = std::max(max_len, item.name.size());
      }
      for (const auto &item : items) {
        CompletionCandidate cand;
        cand.insert_text = item.name;
        cand.display = FormatCommandDisplay_(item.name, "command", max_len);
        cand.help = item.help;
        cand.kind = CompletionKind::Command;
        out.push_back(std::move(cand));
      }
      return;
    }

    if (ctx.target == CompletionTarget::LongOption) {
      auto longs = command_tree_.ListLongOptions(ctx.command_path);
      for (const auto &item : longs) {
        if (!prefix.empty() && item.first.rfind(prefix, 0) != 0) {
          continue;
        }
        CompletionCandidate cand;
        cand.insert_text = item.first;
        cand.display = item.first;
        cand.help = item.second;
        cand.kind = CompletionKind::Option;
        out.push_back(std::move(cand));
      }
      return;
    }

    if (ctx.target == CompletionTarget::ShortOption) {
      auto shorts = command_tree_.ListShortOptions(ctx.command_path);
      for (const auto &item : shorts) {
        const std::string name = std::string("-") + item.first;
        if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
          continue;
        }
        CompletionCandidate cand;
        cand.insert_text = name;
        cand.display = name;
        cand.help = item.second;
        cand.kind = CompletionKind::Option;
        out.push_back(std::move(cand));
      }
    }
  }

  /**
   * @brief Collect internal candidates (vars, hosts, clients, tasks).
   */
  void CollectInternalCandidates_(const CompletionContext &ctx,
                                  std::vector<CompletionCandidate> &out) {
    const std::string prefix = ctx.token_prefix;

    if (ctx.target == CompletionTarget::VariableName) {
      AMVarManager &var_manager = AMVarManager::Instance(config_manager_);
      auto names = var_manager.ListNames();
      for (const auto &name : names) {
        const std::string full = "$" + name;
        if (!prefix.empty() && full.rfind(prefix, 0) != 0) {
          continue;
        }
        CompletionCandidate cand;
        cand.insert_text = full;
        cand.display = full;
        cand.kind = CompletionKind::VariableName;
        out.push_back(std::move(cand));
      }
      return;
    }

    if (ctx.target == CompletionTarget::ClientName) {
      auto names = client_manager_.GetClientNames();
      for (const auto &name : names) {
        if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
          continue;
        }
        CompletionCandidate cand;
        cand.insert_text = name;
        cand.display = name;
        cand.kind = CompletionKind::ClientName;
        out.push_back(std::move(cand));
      }
      return;
    }

    if (ctx.target == CompletionTarget::HostNickname) {
      auto names = config_manager_.ListHostnames();
      for (const auto &name : names) {
        if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
          continue;
        }
        CompletionCandidate cand;
        cand.insert_text = name;
        cand.display = name;
        cand.kind = CompletionKind::HostNickname;
        out.push_back(std::move(cand));
      }
      return;
    }

    if (ctx.target == CompletionTarget::HostAttr) {
      for (const auto &field : kHostConfigFields) {
        if (!prefix.empty() && field.rfind(prefix, 0) != 0) {
          continue;
        }
        CompletionCandidate cand;
        cand.insert_text = field;
        cand.display = field;
        cand.kind = CompletionKind::HostAttr;
        out.push_back(std::move(cand));
      }
      return;
    }

    if (ctx.target == CompletionTarget::TaskId) {
      auto ids = transfer_manager_.ListTaskIds();
      for (const auto &id : ids) {
        if (!prefix.empty() && id.rfind(prefix, 0) != 0) {
          continue;
        }
        CompletionCandidate cand;
        cand.insert_text = id;
        cand.display = id;
        cand.kind = CompletionKind::TaskId;
        out.push_back(std::move(cand));
      }
    }
  }

  /**
   * @brief Style a path entry for display.
   */
  std::string FormatPathDisplay_(const PathInfo &info,
                                 const std::string &name) const {
    auto wrap_pre = [&](const std::string &styled,
                        const std::string &raw) -> std::string {
      if (styled == raw) {
        return styled;
      }
      if (raw.empty()) {
        return styled;
      }
      if (styled.find("[/") == std::string::npos) {
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

    switch (info.type) {
    case PathType::DIR: {
      const std::string styled = filesystem_.StylePath(info, name);
      return wrap_pre(styled, name);
    }
    case PathType::SYMLINK: {
      const std::string styled = filesystem_.StylePath(info, name);
      return wrap_pre(styled, name);
    }
    case PathType::FILE: {
      const std::string styled = filesystem_.StylePath(info, name);
      return wrap_pre(styled, name);
    }
    default: {
      const std::string styled = filesystem_.StylePath(info, name);
      return wrap_pre(styled, name);
    }
    }
  }

  /**
   * @brief Filter and append path candidates from a list.
   */
  void AppendPathCandidates_(const CompletionContext &ctx,
                             const std::vector<PathInfo> &items,
                             std::vector<CompletionCandidate> &out) {
    const std::string &prefix = ctx.path.leaf_prefix;
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
      CompletionCandidate cand;
      const bool is_dir = info.type == PathType::DIR;
      cand.insert_text = ctx.path.base + name;
      if (is_dir) {
        cand.insert_text.push_back(ctx.path.sep);
      }
      const std::string display_name = is_dir ? name + ctx.path.sep : name;
      cand.display = FormatPathDisplay_(info, display_name);
      cand.kind = ctx.path.remote ? CompletionKind::PathRemote
                                  : CompletionKind::PathLocal;
      cand.path_type = info.type;
      out.push_back(std::move(cand));
    }
  }

  /**
   * @brief Lookup cache entries for a path key.
   */
  bool LookupCache_(const CacheKey &key, std::vector<PathInfo> *items) {
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
   * @brief Store cache entries and prune if needed.
   */
  void StoreCache_(const CacheKey &key, const std::vector<PathInfo> &items) {
    std::lock_guard<std::mutex> lock(cache_mtx_);
    cache_[key] = CacheEntry{items, std::chrono::steady_clock::now()};
    const size_t max_entries = owner_->cache_max_entries_;
    if (cache_.size() <= max_entries) {
      return;
    }
    while (cache_.size() > max_entries) {
      auto oldest = cache_.begin();
      for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->second.timestamp < oldest->second.timestamp) {
          oldest = it;
        }
      }
      cache_.erase(oldest);
    }
  }

  /**
   * @brief Attempt to use async results for the current request.
   */
  bool TryConsumeAsyncResult_(const CompletionContext &ctx,
                              std::vector<PathInfo> *items) {
    std::lock_guard<std::mutex> lock(async_result_mtx_);
    if (!async_result_ || async_result_->request_id != ctx.request_id) {
      return false;
    }
    if (async_result_->key.nickname != ctx.path.nickname ||
        async_result_->key.dir != ctx.path.dir_abs ||
        async_result_->base != ctx.path.base ||
        async_result_->leaf_prefix != ctx.path.leaf_prefix ||
        async_result_->sep != ctx.path.sep) {
      return false;
    }
    if (items) {
      *items = async_result_->items;
    }
    async_result_.reset();
    return true;
  }

  /**
   * @brief Collect path candidates.
   */
  void CollectPathCandidates_(const CompletionContext &ctx,
                              std::vector<CompletionCandidate> &out) {
    if (!ctx.path.valid) {
      return;
    }

    CacheKey key{ctx.path.nickname, ctx.path.dir_abs};
    std::vector<PathInfo> items;
    if (ctx.path.remote) {
      if (LookupCache_(key, &items)) {
        AppendPathCandidates_(ctx, items, out);
        return;
      }
      if (TryConsumeAsyncResult_(ctx, &items)) {
        const size_t cache_min = owner_->cache_min_items_;
        if (items.size() >= cache_min) {
          StoreCache_(key, items);
        }
        AppendPathCandidates_(ctx, items, out);
        return;
      }
      ScheduleAsyncRequest_(ctx);
      return;
    }

    if (LookupCache_(key, &items)) {
      AppendPathCandidates_(ctx, items, out);
      return;
    }

    auto client = client_manager_.LocalClientBase();
    if (!client) {
      return;
    }
    const int timeout_ms = config_manager_.ResolveArg<int>(
        DocumentKind::Settings, {"CompleteOption", "timeout_ms"}, 5000,
        [](int v) { return v > 0 ? v : 5000; });
    auto [rcm, listed] =
        client->listdir(ctx.path.dir_abs, nullptr, timeout_ms, am_ms());
    if (rcm.first != EC::Success) {
      return;
    }
    const size_t cache_min = owner_->cache_min_items_;
    if (listed.size() >= cache_min) {
      StoreCache_(key, listed);
    }
    AppendPathCandidates_(ctx, listed, out);
  }

  /**
   * @brief Sort candidates by prefix and path type rules.
   */
  void SortCandidates_(std::vector<CompletionCandidate> &items) {
    std::stable_sort(
        items.begin(), items.end(),
        [](const CompletionCandidate &a, const CompletionCandidate &b) {
          if (a.score != b.score) {
            return a.score < b.score;
          }
          const bool a_path = IsPathCandidate(a.kind);
          const bool b_path = IsPathCandidate(b.kind);
          if (a_path && b_path) {
            const int ao = PathTypeOrder(a.path_type);
            const int bo = PathTypeOrder(b.path_type);
            if (ao != bo) {
              return ao < bo;
            }
          }
          return a.insert_text < b.insert_text;
        });
  }

  /**
   * @brief Emit candidates to isocline with delete ranges.
   */
  void EmitCandidates_(ic_completion_env_t *cenv, const CompletionContext &ctx,
                       const std::vector<CompletionCandidate> &items) {
    if (!cenv) {
      return;
    }
    long delete_before = 0;
    long delete_after = 0;
    if (ctx.has_token && ctx.cursor >= ctx.token.content_start &&
        ctx.cursor <= ctx.token.content_end) {
      delete_before = static_cast<long>(ctx.cursor - ctx.token.content_start);
      delete_after = static_cast<long>(ctx.token.content_end - ctx.cursor);
    }

    for (const auto &cand : items) {
      const char *display =
          cand.display.empty() ? nullptr : cand.display.c_str();
      const char *help = cand.help.empty() ? nullptr : cand.help.c_str();
      ic_add_completion_prim(cenv, cand.insert_text.c_str(), display, help,
                             delete_before, delete_after);
    }
  }

  /**
   * @brief Schedule a remote async completion request.
   */
  void ScheduleAsyncRequest_(const CompletionContext &ctx) {
    AsyncRequest req;
    req.request_id = ctx.request_id;
    req.key = {ctx.path.nickname, ctx.path.dir_abs};
    req.base = ctx.path.base;
    req.leaf_prefix = ctx.path.leaf_prefix;
    req.sep = ctx.path.sep;
    req.remote = ctx.path.remote;

    {
      std::lock_guard<std::mutex> lock(async_mtx_);
      pending_request_ = req;
    }
    async_cv_.notify_all();
  }

  /**
   * @brief Start the async worker thread.
   */
  void StartAsyncWorker() {
    async_thread_ = std::thread([this]() { AsyncWorkerLoop_(); });
  }

  /**
   * @brief Stop the async worker thread.
   */
  void StopAsyncWorker() {
    async_stop_.store(true, std::memory_order_relaxed);
    async_cv_.notify_all();
    if (async_thread_.joinable()) {
      async_thread_.join();
    }
  }

  /**
   * @brief Run the async worker loop.
   */
  void AsyncWorkerLoop_() {
    while (true) {
      AsyncRequest request;
      {
        std::unique_lock<std::mutex> lock(async_mtx_);
        async_cv_.wait(lock, [this]() {
          return async_stop_.load(std::memory_order_relaxed) ||
                 pending_request_.has_value();
        });
        if (async_stop_.load(std::memory_order_relaxed)) {
          break;
        }
        request = *pending_request_;
        pending_request_.reset();

        const int delay_ms = owner_->complete_delay_ms_;
        if (delay_ms > 0) {
          auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(delay_ms);
          while (!async_stop_.load(std::memory_order_relaxed)) {
            if (async_cv_.wait_until(lock, deadline, [this]() {
                  return async_stop_.load(std::memory_order_relaxed) ||
                         pending_request_.has_value();
                })) {
              if (async_stop_.load(std::memory_order_relaxed)) {
                break;
              }
              request = *pending_request_;
              pending_request_.reset();
              deadline = std::chrono::steady_clock::now() +
                         std::chrono::milliseconds(delay_ms);
              continue;
            }
            break;
          }
        }
        if (async_stop_.load(std::memory_order_relaxed)) {
          break;
        }
      }

      if (request.request_id !=
          current_request_id_.load(std::memory_order_relaxed)) {
        continue;
      }

      auto client = client_manager_.Clients().GetHost(request.key.nickname);
      if (!client) {
        continue;
      }
      const int timeout_ms = config_manager_.ResolveArg<int>(
          DocumentKind::Settings, {"CompleteOption", "timeout_ms"}, 5000,
          [](int v) { return v > 0 ? v : 5000; });
      auto [rcm, listed] =
          client->listdir(request.key.dir, nullptr, timeout_ms, am_ms());
      if (rcm.first != EC::Success) {
        continue;
      }

      {
        std::lock_guard<std::mutex> lock(async_result_mtx_);
        async_result_ =
            AsyncResult{request.request_id,  request.key, request.base,
                        request.leaf_prefix, request.sep, request.remote,
                        std::move(listed)};
      }

      if (request.request_id !=
          current_request_id_.load(std::memory_order_relaxed)) {
        continue;
      }

      /* Completion menu is opened explicitly via Tab; do not auto-open here. */
    }
  }

private:
  AMCompleterImpl *owner_ = nullptr;
  AMConfigManager &config_manager_ = AMConfigManager::Instance();
  AMClientManage::Manager &client_manager_ =
      AMClientManage::Manager::Instance();
  AMFileSystem &filesystem_ = AMFileSystem::Instance();
  AMTransferManager &transfer_manager_ = AMTransferManager::Instance();
  CommandTree command_tree_;

  std::mutex cache_mtx_;
  std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> cache_;

  std::atomic<bool> async_stop_{false};
  std::thread async_thread_;
  std::mutex async_mtx_;
  std::condition_variable async_cv_;
  std::optional<AsyncRequest> pending_request_;

  std::atomic<uint64_t> request_counter_{0};
  std::atomic<uint64_t> current_request_id_{0};
  std::mutex request_mtx_;
  std::string last_input_;
  size_t last_cursor_ = 0;
  uint64_t last_request_id_ = 0;

  std::mutex async_result_mtx_;
  std::optional<AsyncResult> async_result_;
};

/**
 * @brief Construct completer implementation state.
 */
AMCompleterImpl::AMCompleterImpl() : state_(std::make_unique<State>(this)) {}

/**
 * @brief Destroy completer implementation state.
 */
AMCompleterImpl::~AMCompleterImpl() = default;

/**
 * @brief Load completion configuration from settings.
 */
void AMCompleterImpl::LoadConfig() {
  AMConfigManager &config = AMConfigManager::Instance();

  int max_items = config.ResolveArg<int>(DocumentKind::Settings,
                                         {"CompleteOption", "maxnum"}, -1, {});
  if (max_items <= 0) {
    max_items = -1;
  }
  complete_max_items_ = max_items;

  int max_rows = config.ResolveArg<int>(
      DocumentKind::Settings, {"CompleteOption", "maxrows_perpage"}, 9, {});
  if (max_rows == 0) {
    max_rows = 9;
  }
  if (max_rows > 0 && max_rows < 3) {
    max_rows = 3;
  }
  complete_max_rows_ = static_cast<long>(max_rows);

  auto read_bool = [&config](const std::vector<std::string> &path,
                             bool default_value) {
    std::string value = config.ResolveArg<std::string>(
        DocumentKind::Settings, path, default_value ? "true" : "false", {});
    value = AMStr::lowercase(AMStr::Strip(value));
    if (value == "true" || value == "1" || value == "yes" || value == "on") {
      return true;
    }
    if (value == "false" || value == "0" || value == "no" || value == "off") {
      return false;
    }
    return default_value;
  };

  complete_number_pick_ = read_bool({"CompleteOption", "number_pick"}, true);
  complete_auto_fill_ = read_bool({"CompleteOption", "auto_fillin"}, true);
  complete_select_sign_ = config.ResolveArg<std::string>(
      DocumentKind::Settings, {"CompleteOption", "item_select_sign"}, "", {});

  complete_delay_ms_ = config.ResolveArg<int>(
      DocumentKind::Settings, {"CompleteOption", "complete_delay_ms"}, 100,
      [](int v) { return v < 0 ? 0 : v; });

  cache_min_items_ = config.ResolveArg<size_t>(
      DocumentKind::Settings, {"CompleteOption", "cache_min_items"},
      static_cast<size_t>(100),
      [](size_t v) { return static_cast<size_t>(v); });

  int max_entries = config.ResolveArg<int>(
      DocumentKind::Settings, {"CompleteOption", "cache_max_entries"}, 64, {});
  if (max_entries < 1) {
    max_entries = 1;
  }
  cache_max_entries_ = static_cast<size_t>(max_entries);

  std::string command_tag = "";
  config.ResolveArg(DocumentKind::Settings,
                    {"style", "InputHighlight", "command"}, &command_tag);
  input_tag_command_ = NormalizeStyleTag_(command_tag);

  std::string module_tag = "";
  config.ResolveArg(DocumentKind::Settings,
                    {"style", "InputHighlight", "module"}, &module_tag);
  input_tag_module_ = NormalizeStyleTag_(module_tag);
}

/**
 * @brief Install completer callback and apply current configuration.
 */
void AMCompleterImpl::Install(void *completion_arg) {
  LoadConfig();
  if (state_) {
    state_->Install(completion_arg);
  }
}

/**
 * @brief Clear completion caches.
 */
void AMCompleterImpl::ClearCache() {
  if (state_) {
    state_->ClearCache();
  }
}

/**
 * @brief Forward completion handling into runtime state.
 */
void AMCompleterImpl::HandleCompletion(ic_completion_env_t *cenv,
                                       const std::string &input,
                                       size_t cursor) {
  if (state_) {
    state_->HandleCompletion(cenv, input, cursor);
  }
}

/**
 * @brief Clear any cached completion results.
 */
void AMCompleter::ClearCache() { AMCompleterImpl::ClearCache(); }

/**
 * @brief Return the currently active completer instance.
 */
AMCompleter *AMCompleter::Active() {
  return g_active_completer.load(std::memory_order_relaxed);
}

/**
 * @brief Set the active completer instance.
 */
void AMCompleter::SetActive(AMCompleter *instance) {
  g_active_completer.store(instance, std::memory_order_relaxed);
}

/**
 * @brief Isocline callback entrypoint for completion.
 */
void AMCompleter::IsoclineCompleter(ic_completion_env_t *cenv,
                                    const char *prefix) {
  (void)prefix;
  if (!cenv) {
    return;
  }
  auto *self = static_cast<AMCompleter *>(ic_completion_arg(cenv));
  if (!self) {
    return;
  }
  long cursor = 0;
  const char *input = ic_completion_input(cenv, &cursor);
  if (!input || cursor < 0) {
    return;
  }
  self->HandleCompletion(cenv, std::string(input), static_cast<size_t>(cursor));
}
