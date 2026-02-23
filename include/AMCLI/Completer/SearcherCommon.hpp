#pragma once
#include "AMBase/CommonTools.hpp"
#include "AMCLI/Completer/Searcher.hpp"
#include <algorithm>
#include <cctype>
#include <limits>
#include <unordered_set>

namespace AMSearcherDetail {
/**
 * @brief Match result entry containing source index and score bias.
 */
struct GeneralMatchEntry {
  size_t index = 0;
  int score_bias = 0;
};

/**
 * @brief Escape bbcode special characters in display text.
 */
inline std::string EscapeBbcodeText(const std::string &text) {
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
inline std::string UnescapeBackticks(const std::string &text) {
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
inline bool StartsWithUnescapedDollar(const std::string &raw_prefix,
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
inline bool StartsWithLongOption(const std::string &text) {
  return text.size() >= 2 && text[0] == '-' && text[1] == '-';
}

/**
 * @brief Return true if string begins with "-" but not "--".
 */
inline bool StartsWithShortOption(const std::string &text) {
  return text.size() >= 1 && text[0] == '-' &&
         !(text.size() >= 2 && text[1] == '-');
}

/**
 * @brief Return true when text looks like path input.
 */
inline bool IsPathLikeText(const std::string &text) {
  if (text.empty()) {
    return false;
  }
  if (text[0] == '/' || text[0] == '\\' || text[0] == '~' || text[0] == '.') {
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
 * @brief Return true when semantic value indicates a path.
 */
inline bool IsPathSemantic(AMCommandArgSemantic semantic) {
  return semantic == AMCommandArgSemantic::Path;
}

/**
 * @brief Detect path separator for completion output.
 */
inline char DetectPathSep(const std::string &path, bool remote) {
  (void)path;
  (void)remote;
  return '/';
}

/**
 * @brief Split path into directory and leaf prefix components.
 */
inline void SplitPath(const std::string &path, std::string *dir,
                      std::string *leaf, bool *trailing_sep) {
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
inline int PathTypeOrder(PathType type) {
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
 * @brief Resolve a token text by index from completion context.
 */
inline std::string ExtractTokenText(const AMCompletionContext &ctx,
                                    size_t index) {
  if (index >= ctx.tokens.size()) {
    return "";
  }
  const auto &token = ctx.tokens[index];
  if (token.content_end <= token.content_start ||
      token.content_end > ctx.input.size()) {
    return "";
  }
  return UnescapeBackticks(ctx.input.substr(token.content_start,
                                            token.content_end -
                                                token.content_start));
}

/**
 * @brief Return true when completion context contains target.
 */
inline bool HasTarget(const AMCompletionContext &ctx, AMCompletionTarget target) {
  return std::find(ctx.targets.begin(), ctx.targets.end(), target) !=
         ctx.targets.end();
}

/**
 * @brief Convert timeout value to int for client API calls.
 */
inline int ToClientTimeoutMs(size_t timeout_ms, int fallback_ms) {
  if (timeout_ms == 0) {
    return fallback_ms;
  }
  constexpr size_t kIntMax =
      static_cast<size_t>(std::numeric_limits<int>::max());
  if (timeout_ms > kIntMax) {
    return std::numeric_limits<int>::max();
  }
  return static_cast<int>(timeout_ms);
}

/**
 * @brief Build ordered matches using the configured general matching rule.
 */
inline std::vector<GeneralMatchEntry>
BuildGeneralMatch(const std::vector<std::string> &keys,
                  const std::string &prefix) {
  std::vector<GeneralMatchEntry> out;
  out.reserve(keys.size());
  if (prefix.empty()) {
    for (size_t i = 0; i < keys.size(); ++i) {
      out.push_back({i, 0});
    }
    return out;
  }

  std::unordered_set<size_t> seen;
  auto push_if = [&](auto &&pred, int bias) {
    for (size_t i = 0; i < keys.size(); ++i) {
      if (seen.find(i) != seen.end()) {
        continue;
      }
      if (!pred(keys[i])) {
        continue;
      }
      seen.insert(i);
      out.push_back({i, bias});
    }
  };

  push_if([&](const std::string &key) { return key.rfind(prefix, 0) == 0; }, 0);
  push_if([&](const std::string &key) {
    return key.find(prefix) != std::string::npos;
  },
          10);
  if (!out.empty()) {
    return out;
  }

  const std::string lower_prefix = AMStr::lowercase(prefix);
  push_if([&](const std::string &key) {
    return AMStr::lowercase(key).rfind(lower_prefix, 0) == 0;
  },
          20);
  push_if([&](const std::string &key) {
    return AMStr::lowercase(key).find(lower_prefix) != std::string::npos;
  },
          30);
  return out;
}

/**
 * @brief Parsed command/argument state from tokens before cursor.
 */
struct CommandState {
  std::string command_path;
  size_t command_tokens = 0;
  size_t arg_index = 0;
  std::optional<CommandTree::OptionValueRule> pending_value_rule;
  size_t pending_value_index = 0;
};

/**
 * @brief Resolve command path and positional arg index from token context.
 */
inline CommandState ResolveCommandState(const AMCompletionContext &ctx) {
  CommandState state;
  CommandTree &command_tree = CommandTree::Instance();
  std::vector<std::string> before;
  before.reserve(ctx.token_index);
  for (size_t i = 0; i < ctx.tokens.size() && i < ctx.token_index; ++i) {
    const std::string text = ExtractTokenText(ctx, i);
    if (!text.empty()) {
      before.push_back(text);
    }
  }
  if (before.empty()) {
    return state;
  }

  state.command_path = before[0];
  state.command_tokens = 1;
  if (before.size() >= 2 && command_tree.IsModule(before[0]) &&
      !StartsWithLongOption(before[1]) && !StartsWithShortOption(before[1])) {
    state.command_path += " " + before[1];
    state.command_tokens = 2;
  }

  auto consume_option_value = [&]() {
    if (!state.pending_value_rule.has_value()) {
      return false;
    }
    ++state.pending_value_index;
    if (!state.pending_value_rule->repeat_tail &&
        state.pending_value_index >= state.pending_value_rule->value_count) {
      state.pending_value_rule.reset();
      state.pending_value_index = 0;
    }
    return true;
  };
  auto set_pending_option_value = [&](const CommandTree::OptionValueRule &rule,
                                      size_t consumed) {
    if (!rule.repeat_tail && consumed >= rule.value_count) {
      state.pending_value_rule.reset();
      state.pending_value_index = 0;
      return;
    }
    state.pending_value_rule = rule;
    state.pending_value_index = consumed;
  };

  for (size_t i = state.command_tokens; i < before.size(); ++i) {
    const std::string &token = before[i];
    if (consume_option_value()) {
      continue;
    }
    if (state.command_path.empty()) {
      if (StartsWithLongOption(token) || StartsWithShortOption(token)) {
        continue;
      }
      ++state.arg_index;
      continue;
    }
    if (StartsWithLongOption(token)) {
      const size_t eq_pos = token.find('=');
      const std::string option_name =
          eq_pos == std::string::npos ? token : token.substr(0, eq_pos);
      const auto rule = command_tree.ResolveOptionValueRule(
          state.command_path, option_name, '\0', 0);
      if (rule.has_value()) {
        set_pending_option_value(*rule,
                                 eq_pos != std::string::npos && eq_pos + 1 < token.size()
                                     ? 1
                                     : 0);
      }
      continue;
    }
    if (StartsWithShortOption(token)) {
      const std::string body = token.substr(1);
      if (!body.empty()) {
        for (size_t cidx = 0; cidx < body.size(); ++cidx) {
          const auto rule = command_tree.ResolveOptionValueRule(
              state.command_path, "", body[cidx], 0);
          if (!rule.has_value()) {
            continue;
          }
          set_pending_option_value(*rule, cidx + 1 < body.size() ? 1 : 0);
          break;
        }
        continue;
      }
    }
    ++state.arg_index;
  }
  return state;
}

/**
 * @brief Return true when current argument state expects a path value.
 */
inline bool IsPathSemanticState(const CommandState &state) {
  if (state.command_path.empty()) {
    return false;
  }
  CommandTree &command_tree = CommandTree::Instance();
  if (state.pending_value_rule.has_value()) {
    return IsPathSemantic(state.pending_value_rule->semantic);
  }
  const auto semantic =
      command_tree.ResolvePositionalSemantic(state.command_path,
                                             state.arg_index);
  return semantic.has_value() && IsPathSemantic(*semantic);
}

} // namespace AMSearcherDetail
