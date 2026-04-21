#pragma once
#include "foundation/tools/string.hpp"
#include "interface/completion/Engine.hpp"
#include "interface/input_analysis/rules/InputTextRules.hpp"
#include "interface/parser/CommandTree.hpp"
#include <algorithm>
#include <cctype>
#include <limits>

namespace AMInterface::searcher::detail {
using AMInterface::completer::AMCompletionContext;
using AMInterface::completer::AMCompletionTarget;
using AMInterface::parser::AMCommandArgSemantic;
using AMInterface::parser::CommandNode;

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
  return AMInterface::input::rules::UnescapeBackticks(text, false);
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
  return AMInterface::input::rules::IsPathLikeText(text, true);
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
  case PathType::DIR:
    return 0;
  case PathType::FILE:
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
  const auto &token = ctx.tokens[index].raw;
  if (token.content_end <= token.content_start ||
      token.content_end > ctx.input.size()) {
    return "";
  }
  return UnescapeBackticks(ctx.input.substr(
      token.content_start, token.content_end - token.content_start));
}

/**
 * @brief Return true when completion context contains target.
 */
inline bool HasTarget(const AMCompletionContext &ctx,
                      AMCompletionTarget target) {
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
  constexpr auto kIntMax = static_cast<size_t>(std::numeric_limits<int>::max());
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
  // Keep contains-match logic behind a single switch so it can be restored
  // quickly without touching call sites.
  constexpr bool kEnableContainsFallback = false;
  std::vector<GeneralMatchEntry> out;
  out.reserve(keys.size());
  if (prefix.empty()) {
    for (size_t i = 0; i < keys.size(); ++i) {
      out.push_back({i, 0});
    }
    return out;
  }

  auto collect_if = [&](auto &&pred, int bias) {
    std::vector<GeneralMatchEntry> matches;
    matches.reserve(keys.size());
    for (size_t i = 0; i < keys.size(); ++i) {
      if (!pred(keys[i])) {
        continue;
      }
      matches.push_back({i, bias});
    }
    return matches;
  };

  // Case-sensitive: prefix-starts-with first.
  out = collect_if(
      [&](const std::string &key) { return key.starts_with(prefix); }, 0);
  if (!out.empty()) {
    return out;
  }

  if constexpr (kEnableContainsFallback) {
    // Case-sensitive: contains only when starts-with is empty.
    out = collect_if(
        [&](const std::string &key) {
          return key.find(prefix) != std::string::npos;
        },
        10);
    if (!out.empty()) {
      return out;
    }
  }

  // No-case matching is enabled only when case-sensitive starts-with is empty.
  const std::string lower_prefix = AMStr::lowercase(prefix);
  out = collect_if(
      [&](const std::string &key) {
        return AMStr::lowercase(key).starts_with(lower_prefix);
      },
      20);
  if (!out.empty()) {
    return out;
  }

  if constexpr (kEnableContainsFallback) {
    // No-case contains only when no-case starts-with is empty.
    out = collect_if(
        [&](const std::string &key) {
          return AMStr::lowercase(key).find(lower_prefix) != std::string::npos;
        },
        30);
  }
  return out;
}

} // namespace AMInterface::searcher::detail
