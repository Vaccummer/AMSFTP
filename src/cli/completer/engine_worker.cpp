#include "AMBase/CommonTools.hpp"
#include "AMCLI/Completer/Engine.hpp"
#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMManager/Var.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <cctype>
#include <iterator>
#include <unordered_set>

namespace {
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
 * @brief Return true when a raw token starts with escaped dollar syntax.
 */
bool StartsWithEscapedDollar_(const std::string &raw_token) {
  return raw_token.size() >= 2 && raw_token[0] == '`' && raw_token[1] == '$';
}

/**
 * @brief Parse one shorthand variable token and normalize it as `$name`.
 */
bool ParseShortcutVarToken_(const std::string &raw_token,
                            const std::string &token_text,
                            std::string *normalized_token) {
  if (StartsWithEscapedDollar_(raw_token)) {
    return false;
  }
  std::string trimmed = AMStr::Strip(token_text);
  if (trimmed.empty() || trimmed.front() != '$' || trimmed.size() < 2) {
    return false;
  }

  std::string name;
  if (trimmed.size() >= 3 && trimmed[1] == '{' && trimmed.back() == '}') {
    name = AMStr::Strip(trimmed.substr(2, trimmed.size() - 3));
  } else {
    name = trimmed.substr(1);
  }
  if (!varsetkn::IsValidVarname(name)) {
    return false;
  }
  if (normalized_token) {
    *normalized_token = "$" + name;
  }
  return true;
}

/**
 * @brief Resolve a raw token text by index from completion context.
 */
std::string ExtractTokenRaw_(const AMCompletionContext &ctx, size_t index) {
  if (index >= ctx.tokens.size()) {
    return "";
  }
  const auto &token = ctx.tokens[index];
  if (token.content_end <= token.content_start ||
      token.content_end > ctx.input.size()) {
    return "";
  }
  return ctx.input.substr(token.content_start,
                          token.content_end - token.content_start);
}

/**
 * @brief Shortcut mode for `$var` / `$var=...` parsing.
 */
enum class VarShortcutMode { None, Query, Define };

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
  return g_command_tree && g_command_tree->IsModule(name);
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
 * @brief Detect whether the input is a variable shorthand query/define form.
 */
VarShortcutMode DetectVarShortcutMode_(const AMCompletionContext &ctx) {
  if (ctx.tokens.empty()) {
    return VarShortcutMode::None;
  }

  const std::string first_raw = ExtractTokenRaw_(ctx, 0);
  const std::string first_text = ExtractTokenText_(ctx, 0);
  if (first_text.empty()) {
    return VarShortcutMode::None;
  }

  const size_t first_eq = first_text.find('=');
  if (first_eq != std::string::npos) {
    const std::string lhs = first_text.substr(0, first_eq);
    return ParseShortcutVarToken_(first_raw, lhs, nullptr)
               ? VarShortcutMode::Define
               : VarShortcutMode::None;
  }

  if (!ParseShortcutVarToken_(first_raw, first_text, nullptr)) {
    return VarShortcutMode::None;
  }
  if (ctx.tokens.size() == 1) {
    return VarShortcutMode::Query;
  }

  const std::string second_text = ExtractTokenText_(ctx, 1);
  if (second_text == "=" ||
      (!second_text.empty() && second_text.front() == '=')) {
    return VarShortcutMode::Define;
  }
  return VarShortcutMode::None;
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

    if (!g_command_tree || state.command_path.empty()) {
      if (StartsWithLongOption_(token) || StartsWithShortOption_(token)) {
        continue;
      }
      ++state.arg_index;
      continue;
    }

    if (StartsWithLongOption_(token)) {
      const size_t eq_pos = token.find('=');
      const std::string option_name =
          eq_pos == std::string::npos ? token : token.substr(0, eq_pos);
      const auto rule = g_command_tree->ResolveOptionValueRule(
          state.command_path, option_name, '\0', 0);
      if (rule.has_value()) {
        if (eq_pos == std::string::npos) {
          set_pending_option_value(*rule, 0);
        } else if (eq_pos + 1 < token.size()) {
          set_pending_option_value(*rule, 1);
        } else {
          set_pending_option_value(*rule, 0);
        }
        continue;
      }
      continue;
    }

    if (StartsWithShortOption_(token)) {
      bool option_like = true;
      const std::string body = token.substr(1);
      if (body.empty()) {
        option_like = false;
      } else {
        for (size_t cidx = 0; cidx < body.size(); ++cidx) {
          const auto rule = g_command_tree->ResolveOptionValueRule(
              state.command_path, "", body[cidx], 0);
          if (!rule.has_value()) {
            continue;
          }
          if (cidx + 1 < body.size()) {
            set_pending_option_value(*rule, 1);
          } else {
            set_pending_option_value(*rule, 0);
          }
          break;
        }
      }
      if (option_like) {
        continue;
      }
    }

    ++state.arg_index;
  }
  return state;
}

/**
 * @brief Map command argument semantic to completion target.
 */
std::optional<AMCompletionTarget>
MapSemanticToTarget_(AMCommandArgSemantic semantic) {
  switch (semantic) {
  case AMCommandArgSemantic::Path:
    return AMCompletionTarget::Path;
  case AMCommandArgSemantic::HostNickname:
    return AMCompletionTarget::HostNickname;
  case AMCommandArgSemantic::HostAttr:
    return AMCompletionTarget::HostAttr;
  case AMCommandArgSemantic::ClientName:
    return AMCompletionTarget::ClientName;
  case AMCommandArgSemantic::TaskId:
    return AMCompletionTarget::TaskId;
  case AMCommandArgSemantic::VariableName:
    return AMCompletionTarget::VariableName;
  case AMCommandArgSemantic::None:
  default:
    return std::nullopt;
  }
}

/**
 * @brief Resolve semantic for the current token from command-state context.
 */
std::optional<AMCommandArgSemantic>
ResolveCurrentSemantic_(const CommandState &state) {
  if (!g_command_tree || state.command_path.empty()) {
    return std::nullopt;
  }
  if (state.pending_value_rule.has_value()) {
    return state.pending_value_rule->semantic;
  }
  return g_command_tree->ResolvePositionalSemantic(state.command_path,
                                                   state.arg_index);
}

} // namespace

/**
 * @brief Tokenize input into completion tokens.
 */
std::vector<AMCompletionToken>
AMCompleteEngine::TokenizeInput_(const std::string &input) const {
  std::vector<AMCompletionToken> tokens;
  std::vector<AMTokenTypeAnalyzer::AMToken> split =
      AMTokenTypeAnalyzer::SplitToken(input);
  tokens.reserve(split.size());
  for (const auto &item : split) {
    tokens.push_back({item.start, item.end, item.content_start,
                      item.content_end, item.quoted});
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

  const VarShortcutMode shortcut_mode = DetectVarShortcutMode_(ctx);
  const bool starts_with_unescaped_dollar =
      StartsWithUnescapedDollar_(ctx.token_prefix_raw, ctx.token_raw);
  if (starts_with_unescaped_dollar) {
    if (shortcut_mode == VarShortcutMode::Define) {
      const size_t eq = ctx.token_prefix.find('=');
      if (eq != std::string::npos && eq + 1 <= ctx.token_prefix.size()) {
        const std::string rhs_prefix = ctx.token_prefix.substr(eq + 1);
        const bool rhs_has_at = rhs_prefix.find('@') != std::string::npos;
        if (rhs_has_at || IsPathLikeText_(rhs_prefix)) {
          ctx.targets = {AMCompletionTarget::Path};
        } else {
          ctx.targets = {AMCompletionTarget::Disabled};
        }
        return ctx;
      }
    }
    ctx.targets = {AMCompletionTarget::VariableName};
    return ctx;
  }

  if (shortcut_mode == VarShortcutMode::Query) {
    ctx.targets = {AMCompletionTarget::Disabled};
    return ctx;
  }
  if (shortcut_mode == VarShortcutMode::Define) {
    const bool has_at = ctx.token_prefix.find('@') != std::string::npos;
    if (has_at || IsPathLikeText_(ctx.token_prefix)) {
      ctx.targets = {AMCompletionTarget::Path};
    } else {
      ctx.targets = {AMCompletionTarget::Disabled};
    }
    return ctx;
  }

  const CommandState state = ResolveCommandState_(ctx);
  if (ctx.token_index == 0) {
    ctx.targets = {AMCompletionTarget::TopCommand};
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

  const auto semantic = ResolveCurrentSemantic_(state);
  const auto semantic_target = semantic.has_value()
                                   ? MapSemanticToTarget_(*semantic)
                                   : std::nullopt;
  auto push_target = [&](AMCompletionTarget target) {
    if (std::find(ctx.targets.begin(), ctx.targets.end(), target) ==
        ctx.targets.end()) {
      ctx.targets.push_back(target);
    }
  };
  if (semantic_target.has_value() &&
      *semantic_target != AMCompletionTarget::Path) {
    push_target(*semantic_target);
  }

  const bool has_at = ctx.token_prefix.find('@') != std::string::npos;
  const bool semantic_path = semantic_target.has_value() &&
                             *semantic_target == AMCompletionTarget::Path;
  if (semantic_path || has_at || IsPathLikeText_(ctx.token_prefix)) {
    push_target(AMCompletionTarget::Path);
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
