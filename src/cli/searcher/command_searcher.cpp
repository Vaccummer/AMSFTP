#include "AMCLI/Completer/Searcher.hpp"
#include "AMCLI/Completer/SearcherCommon.hpp"
#include <algorithm>

using namespace AMSearcherDetail;

/**
 * @brief Collect command-related candidates.
 */
AMCompletionCollectResult
AMCommandSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCollectResult result;
  CommandNode &command_tree = CommandNode::Instance();
  const std::string prefix = ctx.token_prefix;

  std::string command_path;
  const CommandNode *node = nullptr;
  size_t command_tokens = 0;
  ParseCommandPath_(ctx, &command_path, &node, &command_tokens);

  if (HasTarget(ctx, AMCompletionTarget::TopCommand)) {
    struct ItemInfo {
      std::string name;
      std::string help;
      bool is_module = false;
    };
    std::vector<ItemInfo> items;
    std::vector<std::string> keys;
    auto tops = command_tree.ListTopCommands();
    items.reserve(tops.size());
    keys.reserve(tops.size());
    for (const auto &item : tops) {
      items.push_back(
          {item.first, item.second, command_tree.IsModule(item.first)});
      keys.push_back(item.first);
    }

    const auto matches = BuildGeneralMatch(keys, prefix);

    for (const auto &match : matches) {
      const auto &item = items[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = item.name;
      candidate.display = FormatCommandDisplay_(
          item.name, item.is_module ? "module" : "command", 0,
          ctx.completion_args);
      candidate.help = item.help;
      candidate.kind =
          item.is_module ? AMCompletionKind::Module : AMCompletionKind::Command;
      candidate.score = (item.is_module ? 0 : 1) + match.score_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
  }

  if (HasTarget(ctx, AMCompletionTarget::Subcommand) && node &&
      !node->subcommands.empty() && ctx.token_index == command_tokens) {
    struct ItemInfo {
      std::string name;
      std::string help;
    };
    std::vector<ItemInfo> items;
    std::vector<std::string> keys;
    auto subs = command_tree.ListSubcommands(command_path);
    items.reserve(subs.size());
    keys.reserve(subs.size());
    for (const auto &item : subs) {
      items.push_back({item.first, item.second});
      keys.push_back(item.first);
    }

    const auto matches = BuildGeneralMatch(keys, prefix);

    for (const auto &match : matches) {
      const auto &item = items[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = item.name;
      candidate.display =
          FormatCommandDisplay_(item.name, "command", 0, ctx.completion_args);
      candidate.help = item.help;
      candidate.kind = AMCompletionKind::Command;
      candidate.score = match.score_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
  }

  if (HasTarget(ctx, AMCompletionTarget::LongOption) && node) {
    struct ItemInfo {
      std::string name;
      std::string help;
    };
    std::vector<ItemInfo> items;
    std::vector<std::string> keys;
    auto options = command_tree.ListLongOptions(command_path);
    items.reserve(options.size());
    keys.reserve(options.size());
    for (const auto &item : options) {
      items.push_back({item.first, item.second});
      keys.push_back(item.first);
    }
    for (const auto &match : BuildGeneralMatch(keys, prefix)) {
      const auto &item = items[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = item.name;
      candidate.display = item.name;
      candidate.help = item.help;
      candidate.kind = AMCompletionKind::Option;
      candidate.score = match.score_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
  }

  if (HasTarget(ctx, AMCompletionTarget::ShortOption) && node) {
    struct ItemInfo {
      std::string name;
      std::string help;
    };
    std::vector<ItemInfo> items;
    std::vector<std::string> keys;
    auto options = command_tree.ListShortOptions(command_path);
    items.reserve(options.size());
    keys.reserve(options.size());
    for (const auto &item : options) {
      const std::string name = std::string("-") + item.first;
      items.push_back({name, item.second});
      keys.push_back(name);
    }
    for (const auto &match : BuildGeneralMatch(keys, prefix)) {
      const auto &item = items[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = item.name;
      candidate.display = item.name;
      candidate.help = item.help;
      candidate.kind = AMCompletionKind::Option;
      candidate.score = match.score_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
  }

  if (!result.candidates.items.empty()) {
    SortCandidates(ctx, result.candidates.items);
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
  (void)pad_width;
  const std::string command_tag = args ? args->input_tag_command : "";
  const std::string module_tag = args ? args->input_tag_module : "";
  const std::string tag = style_key == "module" ? module_tag : command_tag;
  const std::string escaped = EscapeBbcodeText(name);
  return tag.empty() ? escaped : tag + escaped + "[/]";
}

/**
 * @brief Parse command path from tokens before cursor.
 */
void AMCommandSearchEngine::ParseCommandPath_(const AMCompletionContext &ctx,
                                              std::string *out_path,
                                              const CommandNode **out_node,
                                              size_t *out_consumed) const {
  CommandNode &command_tree = CommandNode::Instance();

  std::string path;
  const CommandNode *node = nullptr;
  size_t consumed = 0;

  for (size_t i = 0; i < ctx.tokens.size() && i < ctx.token_index; ++i) {
    const auto &token = ctx.tokens[i];
    if (token.quoted) {
      break;
    }

    const std::string text = ExtractTokenText(ctx, i);
    if (text.empty()) {
      break;
    }
    if (path.empty()) {
      if (command_tree.IsModule(text) || command_tree.IsTopCommand(text)) {
        path = text;
        node = command_tree.FindNode(path);
        consumed = i + 1;
        continue;
      }
      break;
    }
    if (node && node->subcommands.find(text) != node->subcommands.end()) {
      path += " " + text;
      node = command_tree.FindNode(path);
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
