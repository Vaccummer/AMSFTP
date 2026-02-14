#include "AMBase/CommonTools.hpp"
#include "AMCLI/Completer/Engine.hpp"
#include "Isocline/isocline.h"
#include <cctype>
#include <iterator>
#include <unordered_set>

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
    ctx.targets = {AMCompletionTarget::Disabled};
    return ctx;
  }

  ctx.tokens = TokenizeInput_(request.input);

  AMCompletionToken token;
  size_t token_index = ctx.tokens.size();
  ctx.has_token =
      FindTokenAtCursor_(ctx.tokens, request.cursor, &token, &token_index);
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
    ctx.token_raw = request.input.substr(
        token.content_start, token.content_end - token.content_start);
  }
  if (request.cursor >= token.content_start &&
      request.cursor <= token.content_end &&
      token.content_start <= request.input.size()) {
    ctx.token_prefix_raw = request.input.substr(
        token.content_start, request.cursor - token.content_start);
  }
  ctx.token_text = UnescapeBackticks_(ctx.token_raw);
  ctx.token_prefix = UnescapeBackticks_(ctx.token_prefix_raw);

  if (ctx.token_index == 0) {
    ctx.targets = {AMCompletionTarget::TopCommand};
    return ctx;
  }
  if (StartsWithUnescapedDollar_(ctx.token_prefix_raw, ctx.token_raw)) {
    ctx.targets = {AMCompletionTarget::VariableName};
    return ctx;
  }
  if (StartsWithLongOption_(ctx.token_prefix)) {
    ctx.targets = {AMCompletionTarget::LongOption};
    return ctx;
  }
  if (StartsWithShortOption_(ctx.token_prefix)) {
    ctx.targets = {AMCompletionTarget::ShortOption};
    return ctx;
  }

  const CommandState state = ResolveCommandState_(ctx);
  std::optional<AMCompletionTarget> internal_target;
  if (state.command_path == "config get" ||
      state.command_path == "config edit" ||
      state.command_path == "config rm") {
    internal_target = AMCompletionTarget::HostNickname;
  } else if (state.command_path == "config rn" && state.arg_index == 0) {
    internal_target = AMCompletionTarget::HostNickname;
  } else if (state.command_path == "config set") {
    if (state.arg_index == 0) {
      internal_target = AMCompletionTarget::HostNickname;
    } else if (state.arg_index == 1) {
      internal_target = AMCompletionTarget::HostAttr;
    }
  } else if (state.command_path == "connect" && state.arg_index == 0) {
    internal_target = AMCompletionTarget::HostNickname;
  } else if (state.command_path == "client check" ||
             state.command_path == "client rm") {
    internal_target = AMCompletionTarget::ClientName;
  } else if (state.command_path == "ch" && state.arg_index == 0) {
    internal_target = AMCompletionTarget::ClientName;
  } else if (state.command_path == "task show" ||
             state.command_path == "task inspect" ||
             state.command_path == "task terminate" ||
             state.command_path == "task pause") {
    internal_target = AMCompletionTarget::TaskId;
  } else if ((state.command_path == "task retry" ||
              state.command_path == "retry") &&
             state.arg_index == 0) {
    internal_target = AMCompletionTarget::TaskId;
  }

  if (internal_target.has_value()) {
    ctx.targets.push_back(*internal_target);
  }

  const bool has_at = ctx.token_prefix.find('@') != std::string::npos;
  const bool force_path =
      IsPathArgumentCommand_(state.command_path, state.arg_index);
  if (force_path || has_at || IsPathLikeText_(ctx.token_prefix)) {
    ctx.targets.push_back(AMCompletionTarget::Path);
  }

  if (ctx.targets.empty()) {
    ctx.targets = {AMCompletionTarget::Subcommand};
  }
  return ctx;
}

/**
 * @brief Dispatch completion requests to registered search engines.
 */
void AMCompleteEngine::DispatchCandidates_(
    const AMCompletionContext &ctx, std::vector<AMCompletionCandidate> &out) {
  if (ctx.targets.empty()) {
    return;
  }
  for (const auto &target : ctx.targets) {
    if (target == AMCompletionTarget::Disabled) {
      return;
    }
  }
  ConsumeAsyncResults_(ctx, out);
  if (!out.empty()) {
    return;
  }

  std::unordered_set<const AMCompletionSearchEngine *> used_engines;
  for (const auto &target : ctx.targets) {
    auto engine = ResolveSearchEngine_(target);
    if (!engine) {
      continue;
    }
    const auto *engine_ptr = engine.get();
    if (!used_engines.insert(engine_ptr).second) {
      continue;
    }

    AMCompletionContext scoped = ctx;
    scoped.targets.clear();
    scoped.targets.push_back(target);

    AMCompletionCollectResult collected = engine->CollectCandidates(scoped);
    if (!collected.candidates.empty()) {
      out.insert(out.end(),
                 std::make_move_iterator(collected.candidates.begin()),
                 std::make_move_iterator(collected.candidates.end()));
      last_result_from_cache_ = collected.from_cache;
      ConsumeAsyncResults_(scoped, out);
      return;
    }

    if (collected.async_request.has_value()) {
      AMCompletionAsyncRequest request = std::move(*collected.async_request);
      request.request_id = ctx.request_id;
      request.source_engine = engine;
      if (request.target == AMCompletionTarget::Disabled) {
        request.target = target;
      }
      if (request.target == AMCompletionTarget::Disabled || !request.search) {
        continue;
      }
      ScheduleAsyncRequest_(std::move(request));
    }
  }
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

  ic_set_completion_page_marker(last_result_from_cache_ ? "(cache)" : nullptr);

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
    const char *help =
        candidate.help.empty() ? nullptr : candidate.help.c_str();
    ic_add_completion_prim(cenv, candidate.insert_text.c_str(), display, help,
                           delete_before, delete_after);
  }
}
