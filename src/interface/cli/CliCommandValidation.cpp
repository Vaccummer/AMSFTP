#include "interface/cli/CliCommandValidation.hpp"

#include "foundation/tools/string.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace AMInterface::cli {
namespace {

struct SuggestedCommand_ {
  std::string name = {};
  bool is_module = false;
};

bool IsOptionLikeToken_(const std::string &token) {
  return token.size() >= 2 && token.front() == '-';
}

size_t EditDistance_(const std::string &lhs, const std::string &rhs) {
  const std::string left = AMStr::lowercase(AMStr::Strip(lhs));
  const std::string right = AMStr::lowercase(AMStr::Strip(rhs));
  if (left == right) {
    return 0;
  }
  if (left.empty()) {
    return right.size();
  }
  if (right.empty()) {
    return left.size();
  }

  std::vector<size_t> prev(right.size() + 1, 0);
  std::vector<size_t> curr(right.size() + 1, 0);
  for (size_t j = 0; j <= right.size(); ++j) {
    prev[j] = j;
  }
  for (size_t i = 1; i <= left.size(); ++i) {
    curr[0] = i;
    for (size_t j = 1; j <= right.size(); ++j) {
      const size_t substitution_cost = (left[i - 1] == right[j - 1]) ? 0 : 1;
      curr[j] = std::min({prev[j] + 1, curr[j - 1] + 1,
                          prev[j - 1] + substitution_cost});
    }
    prev.swap(curr);
  }
  return prev[right.size()];
}

std::optional<SuggestedCommand_>
FindBestSuggestion_(const std::string &invalid_token,
                    const std::vector<SuggestedCommand_> &candidates) {
  if (invalid_token.empty() || candidates.empty()) {
    return std::nullopt;
  }
  const std::string invalid = AMStr::lowercase(AMStr::Strip(invalid_token));
  if (invalid.empty()) {
    return std::nullopt;
  }

  size_t best_score = std::numeric_limits<size_t>::max();
  std::optional<SuggestedCommand_> best = std::nullopt;
  for (const auto &candidate : candidates) {
    if (candidate.name.empty()) {
      continue;
    }
    const std::string candidate_name =
        AMStr::lowercase(AMStr::Strip(candidate.name));
    if (candidate_name.empty()) {
      continue;
    }
    size_t score = EditDistance_(invalid, candidate_name);
    if (candidate_name.starts_with(invalid) || invalid.starts_with(candidate_name)) {
      score = (score == 0) ? 0 : score - 1;
    }
    if (score < best_score) {
      best_score = score;
      best = candidate;
    }
  }
  if (!best.has_value()) {
    return std::nullopt;
  }
  const size_t threshold =
      std::max<size_t>(2, (invalid.size() + best->name.size()) / 3);
  if (best_score > threshold) {
    return std::nullopt;
  }
  return best;
}

std::string BuildInvalidMessage_(
    const std::string &invalid_token,
    const std::optional<SuggestedCommand_> &suggestion,
    const AMInterface::style::AMStyleService &style_service) {
  const std::string invalid =
      style_service.Format(invalid_token, AMInterface::style::StyleIndex::IllegalCommand);
  if (!suggestion.has_value()) {
    return AMStr::fmt("❌ InvalidArg \"{}\" is not a valid module or command",
                      invalid);
  }

  const bool is_module = suggestion->is_module;
  const auto kind_style = is_module ? AMInterface::style::StyleIndex::Module
                                    : AMInterface::style::StyleIndex::Command;
  const std::string kind_text = is_module ? "module" : "command";
  const std::string kind = style_service.Format(kind_text, kind_style);
  const std::string name = style_service.Format(suggestion->name, kind_style);
  const std::string colon =
      style_service.Format(":", AMInterface::style::StyleIndex::AtSign);
  return AMStr::fmt(
      "❌ InvalidArg \"{}\" is not a valid module or command, did you mean {}{} "
      "\"{}\"",
      invalid, kind, colon, name);
}

std::vector<SuggestedCommand_>
CollectTopLevelCandidates_(const AMInterface::parser::CommandNode &command_tree) {
  std::vector<SuggestedCommand_> candidates = {};
  candidates.reserve(command_tree.subcommands.size());
  for (const auto &[name, node] : command_tree.subcommands) {
    if (name.empty() || !node) {
      continue;
    }
    candidates.push_back({name, !node->subcommands.empty()});
  }
  return candidates;
}

std::vector<SuggestedCommand_>
CollectSubcommandCandidates_(const AMInterface::parser::CommandNode *node) {
  std::vector<SuggestedCommand_> candidates = {};
  if (!node) {
    return candidates;
  }
  candidates.reserve(node->subcommands.size());
  for (const auto &[name, child] : node->subcommands) {
    if (name.empty() || !child) {
      continue;
    }
    candidates.push_back({name, !child->subcommands.empty()});
  }
  return candidates;
}

} // namespace

std::optional<std::string>
BuildUnknownCommandError(const std::vector<std::string> &tokens,
                         const AMInterface::parser::CommandNode &command_tree,
                         const AMInterface::style::AMStyleService &style_service) {
  const AMInterface::parser::CommandNode *node = nullptr;
  bool resolved_any = false;

  for (size_t idx = 0; idx < tokens.size(); ++idx) {
    const std::string token = AMStr::Strip(tokens[idx]);
    if (token.empty()) {
      continue;
    }

    if (!resolved_any) {
      if (token == "--" || IsOptionLikeToken_(token)) {
        return std::nullopt;
      }
      if (!command_tree.IsTopCommand(token)) {
        const auto candidates = CollectTopLevelCandidates_(command_tree);
        const auto suggestion = FindBestSuggestion_(token, candidates);
        return BuildInvalidMessage_(token, suggestion, style_service);
      }
      node = command_tree.Find(token);
      resolved_any = true;
      continue;
    }

    if (!node || node->subcommands.empty()) {
      return std::nullopt;
    }
    if (token == "--" || IsOptionLikeToken_(token)) {
      return std::nullopt;
    }
    const auto child_it = node->subcommands.find(token);
    if (child_it != node->subcommands.end() && child_it->second) {
      node = child_it->second.get();
      continue;
    }
    const auto candidates = CollectSubcommandCandidates_(node);
    const auto suggestion = FindBestSuggestion_(token, candidates);
    return BuildInvalidMessage_(token, suggestion, style_service);
  }
  return std::nullopt;
}

} // namespace AMInterface::cli

