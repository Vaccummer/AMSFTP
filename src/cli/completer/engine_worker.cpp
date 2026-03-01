#include "AMCLI/CommandTree.hpp"
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
 * @brief Return true when text contains at least one whitespace character.
 */
bool HasWhitespace_(const std::string &text) {
  for (const char c : text) {
    if (std::isspace(static_cast<unsigned char>(c))) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Escape one string for insertion inside double quotes.
 *
 * Use backtick escapes to match the CLI tokenizer behavior.
 */
std::string EscapeForDoubleQuote_(const std::string &text) {
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    if (c == '"' || c == '`') {
      out.push_back('`');
    }
    out.push_back(c);
  }
  return out;
}

/**
 * @brief Return true when cursor token already starts with a quote delimiter.
 */
bool InPureQuotedToken_(const AMCompletionContext &ctx) {
  if (!ctx.has_token || ctx.token.start >= ctx.input.size()) {
    return false;
  }
  const char c = ctx.input[ctx.token.start];
  return c == '"' || c == '\'';
}

/**
 * @brief Quote path insert text when it contains spaces.
 *
 * For `nickname@path` forms, only the path part is wrapped:
 * `nickname@"path with spaces"`.
 */
std::string QuotePathInsertTextIfNeeded_(const std::string &insert_text) {
  if (insert_text.empty() || !HasWhitespace_(insert_text)) {
    return insert_text;
  }

  auto wrap_path = [&](const std::string &header,
                       const std::string &path) -> std::string {
    if (path.empty()) {
      return insert_text;
    }
    if (path.size() >= 2 && path.front() == '"' && path.back() == '"') {
      return header + path;
    }
    return header + "\"" + EscapeForDoubleQuote_(path) + "\"";
  };

  if (insert_text.front() == '@') {
    return wrap_path("@", insert_text.substr(1));
  }

  const size_t first_sep = insert_text.find_first_of("/\\");
  const size_t at_pos = insert_text.find('@');
  if (at_pos != std::string::npos &&
      (first_sep == std::string::npos || at_pos < first_sep)) {
    return wrap_path(insert_text.substr(0, at_pos + 1),
                     insert_text.substr(at_pos + 1));
  }

  return wrap_path("", insert_text);
}

/**
 * @brief Resolve final insert text for one completion candidate.
 */
std::string BuildCandidateInsertText_(const AMCompletionContext &ctx,
                                      const AMCompletionCandidate &candidate) {
  const bool is_path_candidate =
      candidate.kind == AMCompletionKind::PathLocal ||
      candidate.kind == AMCompletionKind::PathRemote;
  if (!is_path_candidate || InPureQuotedToken_(ctx)) {
    return candidate.insert_text;
  }
  return QuotePathInsertTextIfNeeded_(candidate.insert_text);
}

/**
 * @brief Return true when completion context contains target.
 */
bool ContextHasTarget_(const AMCompletionContext &ctx,
                       AMCompletionTarget target) {
  return std::find(ctx.targets.begin(), ctx.targets.end(), target) !=
         ctx.targets.end();
}

/**
 * @brief Return true when a raw token starts with escaped dollar syntax.
 */
bool StartsWithEscapedDollar_(const std::string &raw_token) {
  return raw_token.size() >= 2 && raw_token[0] == '`' && raw_token[1] == '$';
}

/**
 * @brief Parse one shorthand variable token and normalize it as canonical form.
 */
bool ParseShortcutVarToken_(const std::string &raw_token,
                            const std::string &token_text,
                            std::string *normalized_token) {
  if (StartsWithEscapedDollar_(raw_token)) {
    return false;
  }
  const std::string trimmed = AMStr::Strip(token_text);
  if (trimmed.empty()) {
    return false;
  }
  varsetkn::VarRef ref{};
  if (!varsetkn::ParseVarToken(trimmed, &ref) || !ref.valid) {
    return false;
  }
  if (normalized_token) {
    *normalized_token = varsetkn::BuildVarToken(ref);
  }
  return true;
}

/**
 * @brief Parse leading variable token prefix and return parsed ref/boundary.
 *
 * Accepts both complete and incomplete braced prefixes, for example:
 * `$name`, `$zone:name`, `${name`, `${zone:name`.
 */
bool ParseLeadingVarRef_(const std::string &text, size_t *out_end,
                         varsetkn::VarRef *out_ref) {
  if (text.empty() || text.front() != '$') {
    return false;
  }
  size_t parsed_end = 0;
  varsetkn::VarRef ref{};
  if (!varsetkn::ParseVarRefAt(text, 0, text.size(), true, true, &parsed_end,
                               &ref) ||
      !ref.valid) {
    return false;
  }
  if (out_end) {
    *out_end = parsed_end;
  }
  if (out_ref) {
    *out_ref = std::move(ref);
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
 * @brief Parsed command/argument state from tokens before cursor.
 */
struct CommandState {
  std::string module;
  std::string cmd;
  std::string command_path;
  size_t command_tokens = 0;
  size_t arg_index = 0;
  std::optional<CommandNode::OptionValueRule> pending_value_rule;
  size_t pending_value_index = 0;
  bool has_module = false;
  bool has_cmd = false;
  bool unknown_before_command = false;
  std::vector<std::string> options;
  std::vector<std::string> args;
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
  CommandNode &command_tree = CommandNode::Instance();
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

  const CommandNode *node = nullptr;
  for (size_t i = 0; i < before.size(); ++i) {
    const std::string &text = before[i];
    if (text.empty()) {
      continue;
    }
    if (state.command_path.empty()) {
      if (command_tree.IsModule(text)) {
        state.module = text;
        state.has_module = true;
        state.command_path = text;
        state.command_tokens = i + 1;
        node = command_tree.FindNode(state.command_path);
        continue;
      }
      if (command_tree.IsTopCommand(text)) {
        state.cmd = text;
        state.has_cmd = true;
        state.command_path = text;
        state.command_tokens = i + 1;
        node = command_tree.FindNode(state.command_path);
        continue;
      }
      state.unknown_before_command = true;
      return state;
    }

    if (node && node->subcommands.find(text) != node->subcommands.end()) {
      state.command_path += " " + text;
      state.cmd = state.command_path;
      state.has_cmd = true;
      state.command_tokens = i + 1;
      node = command_tree.FindNode(state.command_path);
      continue;
    }

    if (state.has_module && !state.has_cmd) {
      state.unknown_before_command = true;
      return state;
    }
    break;
  }

  if (!state.has_cmd) {
    return state;
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

  auto set_pending_option_value = [&](const CommandNode::OptionValueRule &rule,
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
      state.args.push_back(token);
      continue;
    }

    if (token == "--") {
      state.args.push_back(token);
      ++state.arg_index;
      continue;
    }

    if (StartsWithLongOption_(token)) {
      const size_t eq_pos = token.find('=');
      const std::string option_name =
          eq_pos == std::string::npos ? token : token.substr(0, eq_pos);
      const bool option_exists = node && node->long_options.find(option_name) !=
                                             node->long_options.end();
      if (!option_exists) {
        state.args.push_back(token);
        ++state.arg_index;
        continue;
      }
      const auto value_rule = command_tree.ResolveOptionValueRule(
          state.command_path, option_name, '\0', 0);
      if (eq_pos != std::string::npos) {
        if (!value_rule.has_value()) {
          state.args.push_back(token);
          ++state.arg_index;
          continue;
        }
        state.options.push_back(option_name);
        continue;
      }

      state.options.push_back(option_name);
      if (value_rule.has_value()) {
        set_pending_option_value(*value_rule, 0);
        continue;
      }
      continue;
    }

    if (StartsWithShortOption_(token)) {
      const std::string body = token.substr(1);
      if (body.empty()) {
        state.args.push_back(token);
        ++state.arg_index;
        continue;
      }

      bool all_known = true;
      bool any_value_rule = false;
      for (char c : body) {
        if (!node || node->short_options.find(c) == node->short_options.end()) {
          all_known = false;
          break;
        }
        const auto rule =
            command_tree.ResolveOptionValueRule(state.command_path, "", c, 0);
        if (rule.has_value()) {
          any_value_rule = true;
        }
      }

      if (!all_known) {
        state.args.push_back(token);
        ++state.arg_index;
        continue;
      }

      if (body.size() == 1) {
        const auto rule = command_tree.ResolveOptionValueRule(
            state.command_path, "", body[0], 0);
        state.options.push_back(std::string("-") + body[0]);
        if (rule.has_value()) {
          set_pending_option_value(*rule, 0);
        }
        continue;
      }

      if (!any_value_rule) {
        for (char c : body) {
          state.options.push_back(std::string("-") + c);
        }
        continue;
      }

      state.args.push_back(token);
      ++state.arg_index;
      continue;
    }

    state.args.push_back(token);
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
  case AMCommandArgSemantic::ShellCmd:
    return std::nullopt;
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
  case AMCommandArgSemantic::VarZone:
    return AMCompletionTarget::VarZone;
  case AMCommandArgSemantic::None:
  default:
    return std::nullopt;
  }
}

} // namespace

/**
 * @brief Find the token that owns the cursor.
 */
bool AMCompleteEngine::FindTokenAtCursor_(
    const std::vector<AMTokenTypeAnalyzer::AMToken> &tokens, size_t cursor,
    AMTokenTypeAnalyzer::AMToken *out, size_t *out_index) const {
  for (size_t i = 0; i < tokens.size(); ++i) {
    const auto &tok = tokens[i];
    const size_t begin = tok.quoted ? tok.content_start : tok.start;
    const size_t end = tok.quoted ? tok.content_end : tok.end;
    const bool in_token_body = cursor > begin && cursor < end;
    const bool at_token_end = cursor == end;
    if (in_token_body || at_token_end) {
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
  CommandNode &command_tree = CommandNode::Instance();
  ctx.input = request.input;
  ctx.cursor = request.cursor;
  ctx.request_id = request.request_id;
  ctx.source = (request.source == AMCompletionSource::Unknown)
                   ? AMCompletionSource::Tab
                   : request.source;
  ctx.completion_args = &args_;

  std::string trimmed = AMStr::Strip(request.input);
  if (!trimmed.empty() && trimmed.front() == '!') {
    ctx.targets = {AMCompletionTarget::Disabled};
    return ctx;
  }

  const std::vector<AMTokenTypeAnalyzer::AMToken> all_tokens =
      AMTokenTypeAnalyzer::SplitToken(request.input);
  AMTokenTypeAnalyzer::AMToken token;
  size_t token_index = all_tokens.size();
  const bool has_token =
      FindTokenAtCursor_(all_tokens, request.cursor, &token, &token_index);
  if (!has_token) {
    token_index = all_tokens.size();
    for (size_t i = 0; i < all_tokens.size(); ++i) {
      const auto &tok = all_tokens[i];
      const size_t begin = tok.quoted ? tok.content_start : tok.start;
      if (request.cursor <= begin) {
        token_index = i;
        break;
      }
    }
  }
  const size_t keep_count = has_token
                                ? std::min(all_tokens.size(), token_index + 1)
                                : std::min(all_tokens.size(), token_index);
  ctx.tokens.assign(all_tokens.begin(), all_tokens.begin() + keep_count);

  ctx.has_token = has_token;
  ctx.cursor_in_token = has_token;
  if (!has_token) {
    token.start = request.cursor;
    token.end = request.cursor;
    token.content_start = request.cursor;
    token.content_end = request.cursor;
    token.quoted = false;
    token.type = AMTokenType::Unset;
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
    ctx.token_postfix_raw = request.input.substr(
        request.cursor, token.content_end - request.cursor);
  }
  ctx.token_text = UnescapeBackticks_(ctx.token_raw);
  ctx.token_prefix = UnescapeBackticks_(ctx.token_prefix_raw);
  ctx.token_postfix = UnescapeBackticks_(ctx.token_postfix_raw);

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
    const bool prefix_has_colon =
        ctx.token_prefix.find(':') != std::string::npos;
    const bool postfix_has_colon =
        ctx.token_postfix.find(':') != std::string::npos;

    // Rule:
    // - if prefix has ':' OR postfix has no ':' -> complete varname
    // - else -> complete zone name
    if (!prefix_has_colon && postfix_has_colon) {
      ctx.targets = {AMCompletionTarget::VarZone};
      return ctx;
    }

    if (ctx.token_prefix == "$" || ctx.token_prefix == "${") {
      ctx.targets = {AMCompletionTarget::VariableName};
      return ctx;
    }

    size_t var_end = 0;
    if (ParseLeadingVarRef_(ctx.token_prefix, &var_end, nullptr) &&
        var_end == ctx.token_prefix.size()) {
      ctx.targets = {AMCompletionTarget::VariableName};
      return ctx;
    }
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

  CommandState state = ResolveCommandState_(ctx);
  const std::string current_prefix = ctx.has_token ? ctx.token_prefix : "";
  if (!current_prefix.empty() && ctx.token_index == state.command_tokens) {
    if (!state.has_module && !state.has_cmd) {
      if (command_tree.IsModule(current_prefix)) {
        state.module = current_prefix;
        state.has_module = true;
        state.command_path = current_prefix;
        state.command_tokens = ctx.token_index + 1;
      } else if (command_tree.IsTopCommand(current_prefix)) {
        state.cmd = current_prefix;
        state.has_cmd = true;
        state.command_path = current_prefix;
        state.command_tokens = ctx.token_index + 1;
      }
    } else if (state.has_module && !state.has_cmd) {
      const auto *node = command_tree.FindNode(state.command_path);
      if (node &&
          node->subcommands.find(current_prefix) != node->subcommands.end()) {
        state.command_path += " " + current_prefix;
        state.cmd = state.command_path;
        state.has_cmd = true;
        state.command_tokens = ctx.token_index + 1;
      }
    }
  }
  ctx.module = state.module;
  ctx.cmd = state.cmd;
  ctx.options = state.options;
  ctx.args = state.args;

  if (state.unknown_before_command) {
    ctx.targets = {AMCompletionTarget::Disabled};
    return ctx;
  }
  if (!state.has_module && !state.has_cmd) {
    ctx.targets = {AMCompletionTarget::TopCommand};
    return ctx;
  }
  if (state.has_module && !state.has_cmd) {
    ctx.targets = {AMCompletionTarget::Subcommand};
    return ctx;
  }

  const auto *cmd_node = command_tree.FindNode(state.command_path);
  const bool cursor_is_bare_dashdash =
      ctx.has_token && ctx.token_prefix == "--";
  const bool cursor_is_long_option_prefix =
      ctx.has_token && !cursor_is_bare_dashdash &&
      StartsWithLongOption_(ctx.token_prefix);
  const bool cursor_is_short_option_prefix =
      ctx.has_token && StartsWithShortOption_(ctx.token_prefix);

  bool cursor_valid_long_option = false;
  bool cursor_long_has_inline_value = false;
  std::string cursor_long_name;
  std::optional<CommandNode::OptionValueRule> cursor_long_value_rule;
  bool cursor_valid_short_option = false;
  bool cursor_short_bundle = false;
  char cursor_short_name = '\0';

  if (cursor_is_long_option_prefix) {
    const size_t eq_pos = ctx.token_prefix.find('=');
    cursor_long_has_inline_value = eq_pos != std::string::npos;
    cursor_long_name = eq_pos == std::string::npos
                           ? ctx.token_prefix
                           : ctx.token_prefix.substr(0, eq_pos);
    cursor_valid_long_option =
        cmd_node && cmd_node->long_options.find(cursor_long_name) !=
                        cmd_node->long_options.end();
    if (cursor_valid_long_option) {
      cursor_long_value_rule = command_tree.ResolveOptionValueRule(
          state.command_path, cursor_long_name, '\0', 0);
      if (cursor_long_has_inline_value && !cursor_long_value_rule.has_value()) {
        cursor_valid_long_option = false;
      }
    }
  }

  if (cursor_is_short_option_prefix) {
    const std::string body = ctx.token_prefix.substr(1);
    if (body.empty()) {
      cursor_valid_short_option = true;
    } else if (body.size() == 1) {
      cursor_short_name = body[0];
      cursor_valid_short_option =
          cmd_node && cmd_node->short_options.find(cursor_short_name) !=
                          cmd_node->short_options.end();
    } else {
      bool all_known = true;
      bool any_value_rule = false;
      for (char c : body) {
        if (!cmd_node ||
            cmd_node->short_options.find(c) == cmd_node->short_options.end()) {
          all_known = false;
          break;
        }
        const auto rule =
            command_tree.ResolveOptionValueRule(state.command_path, "", c, 0);
        if (rule.has_value()) {
          any_value_rule = true;
        }
      }
      if (all_known && !any_value_rule) {
        cursor_valid_short_option = true;
        cursor_short_bundle = true;
      }
    }
  }

  const bool cursor_as_option =
      (cursor_is_long_option_prefix && cursor_valid_long_option) ||
      (cursor_is_short_option_prefix && cursor_valid_short_option);
  if (ctx.has_token && !ctx.token_prefix.empty() &&
      ctx.token_index >= state.command_tokens) {
    if (cursor_as_option) {
      if (cursor_is_long_option_prefix) {
        ctx.options.push_back(cursor_long_name);
      } else if (!cursor_short_bundle) {
        ctx.options.push_back(std::string("-") + cursor_short_name);
      } else {
        for (char c : ctx.token_prefix.substr(1)) {
          ctx.options.push_back(std::string("-") + c);
        }
      }
    } else {
      ctx.args.push_back(ctx.token_prefix);
    }
  }

  std::optional<AMCommandArgSemantic> semantic;
  if (state.pending_value_rule.has_value()) {
    semantic = state.pending_value_rule->semantic;
  }
  if (!semantic.has_value() && cursor_is_long_option_prefix &&
      cursor_valid_long_option) {
    if (cursor_long_has_inline_value) {
      if (cursor_long_value_rule.has_value()) {
        semantic = cursor_long_value_rule->semantic;
      }
    } else {
      ctx.targets = {AMCompletionTarget::LongOption};
      return ctx;
    }
  }
  if (!semantic.has_value() && cursor_is_short_option_prefix &&
      cursor_valid_short_option) {
    ctx.targets = {AMCompletionTarget::ShortOption};
    return ctx;
  }
  if (!semantic.has_value() && !state.command_path.empty()) {
    semantic = command_tree.ResolvePositionalSemantic(state.command_path,
                                                      state.arg_index);
  }

  const auto semantic_target =
      semantic.has_value() ? MapSemanticToTarget_(*semantic) : std::nullopt;
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

  const bool prefix_starts_with_path_sign =
      !ctx.token_prefix.empty() &&
      (ctx.token_prefix.front() == '@' || ctx.token_prefix.front() == '~' ||
       ctx.token_prefix.front() == '/' || ctx.token_prefix.front() == '\\' ||
       ctx.token_prefix.front() == '.');
  const bool has_at = ctx.token_prefix.find('@') != std::string::npos;
  const bool semantic_path = semantic_target.has_value() &&
                             *semantic_target == AMCompletionTarget::Path;
  const bool prefix_has_path_sign = prefix_starts_with_path_sign || has_at ||
                                    IsPathLikeText_(ctx.token_prefix);
  if (semantic_path) {
    if (ctx.token_prefix.empty()) {
      push_target(AMCompletionTarget::ClientName);
      push_target(AMCompletionTarget::Path);
    } else if (prefix_has_path_sign) {
      push_target(AMCompletionTarget::Path);
    } else {
      push_target(AMCompletionTarget::ClientName);
      push_target(AMCompletionTarget::Path);
    }
  } else if (has_at || IsPathLikeText_(ctx.token_prefix)) {
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
void AMCompleteEngine::DispatchCandidates_(const AMCompletionContext &ctx,
                                           AMCompletionCandidates &out) {
  if (ctx.targets.empty()) {
    return;
  }
  for (const auto &target : ctx.targets) {
    if (target == AMCompletionTarget::Disabled) {
      return;
    }
  }
  ConsumeAsyncResults_(ctx, out);
  if (!out.items.empty()) {
    return;
  }
  const bool force_sync = (ctx.source == AMCompletionSource::InlineHint);

  std::unordered_set<const AMCompletionSearchEngine *> used_engines;
  for (const auto &target : ctx.targets) {
    auto engine = ResolveSearchEngine_(target);
    if (!engine) {
      continue;
    }
    if (!used_engines.insert(engine.get()).second) {
      continue;
    }

    AMCompletionContext scoped = ctx;
    scoped.targets.clear();
    scoped.targets.push_back(target);
    if ((target == AMCompletionTarget::ClientName ||
         target == AMCompletionTarget::HostNickname) &&
        ContextHasTarget_(ctx, AMCompletionTarget::Path)) {
      scoped.targets.push_back(AMCompletionTarget::Path);
    }

    AMCompletionCollectResult collected = engine->CollectCandidates(scoped);
    if (!collected.candidates.items.empty()) {
      out.items.insert(
          out.items.end(),
          std::make_move_iterator(collected.candidates.items.begin()),
          std::make_move_iterator(collected.candidates.items.end()));
      out.from_cache = collected.candidates.from_cache;
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
      if (force_sync) {
        AMCompletionAsyncResult sync_result;
        sync_result.request_id = request.request_id;
        sync_result.target = request.target;
        sync_result.source_engine = engine;
        if (request.Search(&sync_result) && !sync_result.candidates.empty()) {
          out.items.insert(
              out.items.end(),
              std::make_move_iterator(sync_result.candidates.begin()),
              std::make_move_iterator(sync_result.candidates.end()));
          return;
        }
        continue;
      }
      ScheduleAsyncRequest_(std::move(request));
      return;
    }
  }
}

/**
 * @brief Emit candidates to isocline with delete ranges.
 */
void AMCompleteEngine::EmitCandidates_(ic_completion_env_t *cenv,
                                       const AMCompletionContext &ctx,
                                       const AMCompletionCandidates &items) {
  if (!cenv) {
    return;
  }

  ic_set_completion_page_marker(items.from_cache ? "(cache)" : nullptr);

  long delete_before = 0;
  long delete_after = 0;
  if (ctx.has_token && ctx.cursor >= ctx.token.content_start &&
      ctx.cursor <= ctx.token.content_end) {
    delete_before = static_cast<long>(ctx.cursor - ctx.token.content_start);
    delete_after = static_cast<long>(ctx.token.content_end - ctx.cursor);
  }

  for (const auto &candidate : items.items) {
    const std::string insert_text = BuildCandidateInsertText_(ctx, candidate);
    const char *display =
        candidate.display.empty() ? nullptr : candidate.display.c_str();
    const char *help =
        candidate.help.empty() ? nullptr : candidate.help.c_str();
    ic_add_completion_prim(cenv, insert_text.c_str(), display, help,
                           delete_before, delete_after);
  }
}
