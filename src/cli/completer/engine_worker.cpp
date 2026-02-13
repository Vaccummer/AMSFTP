#include "AMCLI/Completer/Engine.hpp"
#include "AMBase/CommonTools.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <cctype>
#include <iterator>

namespace {
/**
 * @brief Return true if character is a quote.
 */
bool IsQuoteChar(char c) { return c == '"' || c == '\''; }

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
 * @brief Return true if text looks like path input.
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
 * @brief Return path-type ordering rank used by merged sorting.
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
 * @brief Return true if candidate kind represents a path entry.
 */
bool IsPathCandidate_(AMCompletionKind kind) {
  return kind == AMCompletionKind::PathLocal ||
         kind == AMCompletionKind::PathRemote;
}
} // namespace

/**
 * @brief Tokenize input into completion tokens.
 */
std::vector<AMCompletionToken>
AMCompleteEngine::TokenizeInput_(const std::string &input) const {
  std::vector<AMCompletionToken> tokens;
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
bool AMCompleteEngine::FindTokenAtCursor_(
    const std::vector<AMCompletionToken> &tokens, size_t cursor,
    AMCompletionToken *out, size_t *out_index) const {
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
 * @brief Build the completion context for the current input.
 */
AMCompletionContext
AMCompleteEngine::BuildContext_(const AMCompletionRequest &request) const {
  AMCompletionContext ctx;
  ctx.input = request.input;
  ctx.cursor = request.cursor;
  ctx.request_id = request.request_id;
  ctx.args = &args_;

  std::string trimmed = AMStr::Strip(request.input);
  if (!trimmed.empty() && trimmed.front() == '!') {
    ctx.target = AMCompletionTarget::Disabled;
    return ctx;
  }

  ctx.tokens = TokenizeInput_(request.input);

  AMCompletionToken token;
  size_t token_index = ctx.tokens.size();
  ctx.has_token = FindTokenAtCursor_(ctx.tokens, request.cursor, &token,
                                     &token_index);
  if (!ctx.has_token) {
    token = {request.cursor, request.cursor, request.cursor, request.cursor,
             false};
  }
  ctx.token = token;
  ctx.token_index = token_index;
  ctx.token_quoted = token.quoted;

  if (token.content_end >= token.content_start &&
      token.content_end <= request.input.size() &&
      token.content_start <= request.input.size()) {
    ctx.token_raw = request.input.substr(token.content_start,
                                         token.content_end - token.content_start);
  }
  if (request.cursor >= token.content_start && request.cursor <= token.content_end &&
      token.content_start <= request.input.size()) {
    ctx.token_prefix_raw = request.input.substr(token.content_start,
                                                request.cursor - token.content_start);
  }
  ctx.token_text = UnescapeBackticks_(ctx.token_raw);
  ctx.token_prefix = UnescapeBackticks_(ctx.token_prefix_raw);

  if (ctx.token_index == 0) {
    ctx.target = AMCompletionTarget::TopCommand;
    return ctx;
  }
  if (StartsWithUnescapedDollar_(ctx.token_prefix_raw, ctx.token_raw)) {
    ctx.target = AMCompletionTarget::VariableName;
    return ctx;
  }
  if (StartsWithLongOption_(ctx.token_prefix)) {
    ctx.target = AMCompletionTarget::LongOption;
    return ctx;
  }
  if (StartsWithShortOption_(ctx.token_prefix)) {
    ctx.target = AMCompletionTarget::ShortOption;
    return ctx;
  }
  if (ctx.token_prefix.find('@') != std::string::npos ||
      IsPathLikeText_(ctx.token_prefix)) {
    ctx.target = AMCompletionTarget::Path;
    return ctx;
  }

  ctx.target = AMCompletionTarget::None;
  return ctx;
}

/**
 * @brief Dispatch completion requests to registered search engines.
 */
void AMCompleteEngine::DispatchCandidates_(
    const AMCompletionContext &ctx, std::vector<AMCompletionCandidate> &out) {
  ConsumeAsyncResults_(ctx, out);

  auto engines = ResolveSearchEngines_(ctx.target);
  for (const auto &engine : engines) {
    if (!engine) {
      continue;
    }

    AMCompletionCollectResult collected = engine->CollectCandidates(ctx);
    if (!collected.candidates.empty()) {
      engine->SortCandidates(ctx, collected.candidates);
      out.insert(out.end(),
                 std::make_move_iterator(collected.candidates.begin()),
                 std::make_move_iterator(collected.candidates.end()));
    }

    if (collected.async_request.has_value()) {
      AMCompletionAsyncRequest request = std::move(*collected.async_request);
      request.request_id = ctx.request_id;
      request.source_engine = engine;
      if (request.target == AMCompletionTarget::Disabled) {
        continue;
      }
      if (!request.interrupt_flag) {
        request.interrupt_flag = std::make_shared<std::atomic<bool>>(false);
      }
      ScheduleAsyncRequest_(std::move(request));
    }
  }

  ConsumeAsyncResults_(ctx, out);
}

/**
 * @brief Sort merged candidates after collection.
 */
void AMCompleteEngine::SortCandidates_(std::vector<AMCompletionCandidate> &items) {
  std::stable_sort(items.begin(), items.end(),
                   [](const AMCompletionCandidate &a,
                      const AMCompletionCandidate &b) {
                     if (a.score != b.score) {
                       return a.score < b.score;
                     }

                     const bool a_path = IsPathCandidate_(a.kind);
                     const bool b_path = IsPathCandidate_(b.kind);
                     if (a_path && b_path) {
                       const int ao = PathTypeOrder_(a.path_type);
                       const int bo = PathTypeOrder_(b.path_type);
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
void AMCompleteEngine::EmitCandidates_(
    ic_completion_env_t *cenv, const AMCompletionContext &ctx,
    const std::vector<AMCompletionCandidate> &items) {
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

  for (const auto &candidate : items) {
    const char *display =
        candidate.display.empty() ? nullptr : candidate.display.c_str();
    const char *help = candidate.help.empty() ? nullptr : candidate.help.c_str();
    ic_add_completion_prim(cenv, candidate.insert_text.c_str(), display, help,
                           delete_before, delete_after);
  }
}



