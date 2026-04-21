#include "interface/completion/Engine.hpp"

#include "domain/var/VarDomainService.hpp"
#include "interface/input_analysis/rules/InputTextRules.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace AMInterface::completer {
namespace {

using AMInterface::input::AnalyzedToken;
using AMInterface::input::InputAnalysis;
using AMInterface::input::InputAnalyzer;
using AMInterface::input::IInputSemanticRuntime;
using AMInterface::input::rules::IsPathLikeText;
using AMInterface::input::rules::UnescapeBackticks;
using AMInterface::parser::AMCommandArgSemantic;
using AMInterface::parser::CommandNode;

std::string UnescapeBackticks_(const std::string &text) {
  return UnescapeBackticks(text, false);
}

bool StartsWithLongOption_(const std::string &text) {
  return text.size() >= 2 && text[0] == '-' && text[1] == '-';
}

bool StartsWithShortOption_(const std::string &text) {
  return text.size() >= 1 && text[0] == '-' &&
         !(text.size() >= 2 && text[1] == '-');
}

bool HasWhitespace_(const std::string &text) {
  for (const char c : text) {
    if (std::isspace(static_cast<unsigned char>(c))) {
      return true;
    }
  }
  return false;
}

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

bool InPureQuotedToken_(const AMCompletionContext &ctx) {
  if (!ctx.has_token || ctx.token.raw.start >= ctx.input.size()) {
    return false;
  }
  const char c = ctx.input[ctx.token.raw.start];
  return c == '"' || c == '\'';
}

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

bool ContextHasTarget_(const AMCompletionContext &ctx,
                       AMCompletionTarget target) {
  return std::find(ctx.targets.begin(), ctx.targets.end(), target) !=
         ctx.targets.end();
}

bool StartsWithEscapedDollar_(const std::string &raw_token) {
  return raw_token.size() >= 2 && raw_token[0] == '`' && raw_token[1] == '$';
}

bool StartsWithUnescapedDollar_(const std::string &raw_prefix,
                                const std::string &raw_token) {
  const std::string &text = raw_prefix.empty() ? raw_token : raw_prefix;
  return !StartsWithEscapedDollar_(text) && !text.empty() && text.front() == '$';
}

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
  AMDomain::var::VarRef ref{};
  if (!AMDomain::var::ParseVarToken(trimmed, &ref) || !ref.valid) {
    return false;
  }
  if (normalized_token) {
    *normalized_token = AMDomain::var::BuildVarToken(ref);
  }
  return true;
}

bool ParseLeadingVarRef_(const std::string &text, size_t *out_end,
                         AMDomain::var::VarRef *out_ref) {
  if (text.empty() || text.front() != '$') {
    return false;
  }
  size_t parsed_end = 0;
  AMDomain::var::VarRef ref{};
  if (!AMDomain::var::ParseVarRefAt(text, 0, text.size(), true, true,
                                    &parsed_end, &ref) ||
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

std::string ExtractTokenRaw_(const AMCompletionContext &ctx, size_t index) {
  if (index >= ctx.tokens.size()) {
    return "";
  }
  const auto &token = ctx.tokens[index].raw;
  if (token.content_end <= token.content_start ||
      token.content_end > ctx.input.size()) {
    return "";
  }
  return ctx.input.substr(token.content_start, token.content_end - token.content_start);
}

std::string ExtractTokenText_(const AMCompletionContext &ctx, size_t index) {
  if (index >= ctx.tokens.size()) {
    return "";
  }
  const auto &token = ctx.tokens[index].raw;
  if (token.content_end <= token.content_start ||
      token.content_end > ctx.input.size()) {
    return "";
  }
  return UnescapeBackticks_(
      ctx.input.substr(token.content_start, token.content_end - token.content_start));
}

enum class VarShortcutMode { None, Query, Define };

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

std::optional<AMCompletionTarget>
MapSemanticToTarget_(AMCommandArgSemantic semantic) {
  switch (semantic) {
  case AMCommandArgSemantic::Path:
    return AMCompletionTarget::Path;
  case AMCommandArgSemantic::ShellCmd:
    return std::nullopt;
  case AMCommandArgSemantic::HostNickname:
    return AMCompletionTarget::HostNickname;
  case AMCommandArgSemantic::HostNicknameNew:
    return AMCompletionTarget::Disabled;
  case AMCommandArgSemantic::TerminalName:
    return AMCompletionTarget::TerminalName;
  case AMCommandArgSemantic::ChannelTargetExisting:
    return AMCompletionTarget::ChannelTargetExisting;
  case AMCommandArgSemantic::ChannelTargetNew:
    return AMCompletionTarget::ChannelTargetNew;
  case AMCommandArgSemantic::SshChannelTarget:
    return AMCompletionTarget::SshChannelTarget;
  case AMCommandArgSemantic::HostAttr:
    return AMCompletionTarget::HostAttr;
  case AMCommandArgSemantic::HostAttrValue:
    return AMCompletionTarget::Disabled;
  case AMCommandArgSemantic::ClientName:
    return AMCompletionTarget::ClientName;
  case AMCommandArgSemantic::PoolName:
    return AMCompletionTarget::PoolName;
  case AMCommandArgSemantic::TaskId:
    return AMCompletionTarget::TaskId;
  case AMCommandArgSemantic::PausedTaskId:
    return AMCompletionTarget::PausedTaskId;
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

bool AMCompleteEngine::FindTokenAtCursor_(
    const std::vector<AnalyzedToken> &tokens, size_t cursor, AnalyzedToken *out,
    size_t *out_index) const {
  for (size_t i = 0; i < tokens.size(); ++i) {
    const auto &tok = tokens[i].raw;
    const size_t begin = tok.quoted ? tok.content_start : tok.start;
    const size_t end = tok.quoted ? tok.content_end : tok.end;
    const bool in_token_body = cursor > begin && cursor < end;
    const bool at_token_end = cursor == end;
    if (in_token_body || at_token_end) {
      if (out) {
        *out = tokens[i];
      }
      if (out_index) {
        *out_index = i;
      }
      return true;
    }
  }
  return false;
}

AMCompletionContext
AMCompleteEngine::BuildContext_(const AMCompletionRequest &request) const {
  AMCompletionContext ctx = {};
  ctx.input = request.input;
  ctx.cursor = request.cursor;
  ctx.request_id = request.request_id;
  ctx.mode = request.mode;
  ctx.command_tree = command_tree_;
  ctx.completion_args = &args_;
  ctx.style_service = style_service_;

  const std::string trimmed = AMStr::Strip(request.input);
  if (!trimmed.empty() && trimmed.front() == '!') {
    ctx.targets = {AMCompletionTarget::Disabled};
    return ctx;
  }
  if (!input_analyzer_) {
    ctx.targets = {AMCompletionTarget::Disabled};
    return ctx;
  }

  ctx.analysis = input_analyzer_->Analyze(request.input);
  InputAnalysis prefix_analysis = {};
  if (request.cursor <= request.input.size()) {
    prefix_analysis = input_analyzer_->Analyze(request.input.substr(0, request.cursor));
  }

  const auto &all_tokens = ctx.analysis.tokens;
  AnalyzedToken token = {};
  size_t token_index = all_tokens.size();
  const bool has_token =
      FindTokenAtCursor_(all_tokens, request.cursor, &token, &token_index);
  if (!has_token) {
    token_index = all_tokens.size();
    for (size_t i = 0; i < all_tokens.size(); ++i) {
      const auto &tok = all_tokens[i].raw;
      const size_t begin = tok.quoted ? tok.content_start : tok.start;
      if (request.cursor <= begin) {
        token_index = i;
        break;
      }
    }
  }

  const size_t keep_count =
      has_token ? std::min(all_tokens.size(), token_index + 1)
                : std::min(all_tokens.size(), token_index);
  ctx.tokens.assign(all_tokens.begin(), all_tokens.begin() + keep_count);

  ctx.has_token = has_token;
  ctx.cursor_in_token = has_token;
  if (!has_token) {
    token.raw.start = request.cursor;
    token.raw.end = request.cursor;
    token.raw.content_start = request.cursor;
    token.raw.content_end = request.cursor;
    token.raw.quoted = false;
  }
  ctx.token = token;
  ctx.token_index = token_index;
  ctx.token_quoted = token.raw.quoted;

  if (token.raw.content_end >= token.raw.content_start &&
      token.raw.content_end <= request.input.size() &&
      token.raw.content_start <= request.input.size()) {
    ctx.token_raw = request.input.substr(
        token.raw.content_start, token.raw.content_end - token.raw.content_start);
  }
  if (request.cursor >= token.raw.content_start &&
      request.cursor <= token.raw.content_end &&
      token.raw.content_start <= request.input.size()) {
    ctx.token_prefix_raw = request.input.substr(
        token.raw.content_start, request.cursor - token.raw.content_start);
    ctx.token_postfix_raw = request.input.substr(
        request.cursor, token.raw.content_end - request.cursor);
  }
  ctx.token_text = UnescapeBackticks_(ctx.token_raw);
  ctx.token_prefix = UnescapeBackticks_(ctx.token_prefix_raw);
  ctx.token_postfix = UnescapeBackticks_(ctx.token_postfix_raw);

  ctx.module = prefix_analysis.command.module;
  ctx.command_path = prefix_analysis.command.command_path;
  ctx.command_node = prefix_analysis.command.node;
  ctx.command_tokens = prefix_analysis.command.command_tokens;
  ctx.cmd = prefix_analysis.command.command_path;
  ctx.options = prefix_analysis.command.options;
  ctx.args = prefix_analysis.command.args;

  const VarShortcutMode shortcut_mode = DetectVarShortcutMode_(ctx);
  if (StartsWithUnescapedDollar_(ctx.token_prefix_raw, ctx.token_raw)) {
    if (shortcut_mode == VarShortcutMode::Define) {
      const size_t eq = ctx.token_prefix.find('=');
      if (eq != std::string::npos && eq + 1 <= ctx.token_prefix.size()) {
        const std::string rhs_prefix = ctx.token_prefix.substr(eq + 1);
        const bool rhs_has_at = rhs_prefix.find('@') != std::string::npos;
        if (rhs_has_at || IsPathLikeText(rhs_prefix, false)) {
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
    if (has_at || IsPathLikeText(ctx.token_prefix, false)) {
      ctx.targets = {AMCompletionTarget::Path};
    } else {
      ctx.targets = {AMCompletionTarget::Disabled};
    }
    return ctx;
  }

  const bool completing_unknown_root_token =
      prefix_analysis.command.unknown_before_command && ctx.has_token &&
      ctx.token_index == 0 && prefix_analysis.command.command_tokens == 0;
  if (prefix_analysis.command.unknown_before_command &&
      !completing_unknown_root_token) {
    ctx.targets = {AMCompletionTarget::Disabled};
    return ctx;
  }
  if (!prefix_analysis.command.has_module && !prefix_analysis.command.has_command) {
    const bool prefix_starts_with_path_sign =
        !ctx.token_prefix.empty() &&
        (ctx.token_prefix.front() == '@' || ctx.token_prefix.front() == '~' ||
         ctx.token_prefix.front() == '/' || ctx.token_prefix.front() == '\\' ||
         ctx.token_prefix.front() == '.');
    const bool has_at = ctx.token_prefix.find('@') != std::string::npos;
    const bool prefix_has_path_sign =
        prefix_starts_with_path_sign || has_at || IsPathLikeText(ctx.token_prefix, false);
    if (prefix_has_path_sign) {
      ctx.targets = {AMCompletionTarget::Path};
    } else {
      ctx.targets = {AMCompletionTarget::TopCommand};
    }
    return ctx;
  }
  if (prefix_analysis.command.has_module && !prefix_analysis.command.has_command) {
    ctx.targets = {AMCompletionTarget::Subcommand,
                   AMCompletionTarget::LongOption,
                   AMCompletionTarget::ShortOption};
    return ctx;
  }
  if (!command_tree_) {
    ctx.targets = {AMCompletionTarget::Disabled};
    return ctx;
  }

  const auto *cmd_node = prefix_analysis.command.node;
  const bool cursor_is_bare_dashdash =
      ctx.has_token && ctx.token_prefix == "--";
  const bool cursor_is_long_option_prefix =
      ctx.has_token && !cursor_is_bare_dashdash &&
      StartsWithLongOption_(ctx.token_prefix);
  const bool cursor_is_short_option_prefix =
      ctx.has_token && StartsWithShortOption_(ctx.token_prefix);

  bool cursor_valid_long_option = false;
  bool cursor_long_has_inline_value = false;
  std::string cursor_long_name = {};
  std::optional<CommandNode::OptionValueRule> cursor_long_value_rule =
      std::nullopt;
  bool cursor_valid_short_option = false;
  char cursor_short_name = '\0';

  if (cursor_is_long_option_prefix) {
    const size_t eq_pos = ctx.token_prefix.find('=');
    cursor_long_has_inline_value = eq_pos != std::string::npos;
    cursor_long_name = eq_pos == std::string::npos
                           ? ctx.token_prefix
                           : ctx.token_prefix.substr(0, eq_pos);
    cursor_valid_long_option =
        cmd_node && cmd_node->long_options.contains(cursor_long_name);
    if (cursor_valid_long_option) {
      cursor_long_value_rule = command_tree_->ResolveOptionValueRule(
          prefix_analysis.command.command_path, cursor_long_name, '\0', 0);
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
          cmd_node && cmd_node->short_options.contains(cursor_short_name);
    } else {
      bool all_known = true;
      bool any_value_rule = false;
      for (char c : body) {
        if (!cmd_node || !cmd_node->short_options.contains(c)) {
          all_known = false;
          break;
        }
        const auto rule = command_tree_->ResolveOptionValueRule(
            prefix_analysis.command.command_path, "", c, 0);
        if (rule.has_value()) {
          any_value_rule = true;
        }
      }
      if (all_known && !any_value_rule) {
        cursor_valid_short_option = true;
      }
    }
  }

  std::optional<AMCommandArgSemantic> semantic = std::nullopt;
  if (!prefix_analysis.tokens.empty() && ctx.has_token &&
      ctx.token_index < prefix_analysis.tokens.size()) {
    semantic = prefix_analysis.tokens.back().semantic_hint;
  }
  if (!semantic.has_value() && prefix_analysis.command.pending_value_rule.has_value()) {
    semantic = prefix_analysis.command.pending_value_rule->semantic;
  }
  if (!semantic.has_value() && cursor_is_long_option_prefix &&
      cursor_valid_long_option) {
    if (cursor_long_has_inline_value && cursor_long_value_rule.has_value()) {
      semantic = cursor_long_value_rule->semantic;
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
  if (!semantic.has_value() && !prefix_analysis.command.command_path.empty()) {
    semantic = command_tree_->ResolvePositionalSemantic(
        prefix_analysis.command.command_path, prefix_analysis.command.next_arg_index);
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
  const bool semantic_terminal_channel =
      semantic_target.has_value() &&
      (*semantic_target == AMCompletionTarget::TerminalName ||
       *semantic_target == AMCompletionTarget::ChannelTargetExisting ||
       *semantic_target == AMCompletionTarget::ChannelTargetNew ||
       *semantic_target == AMCompletionTarget::SshChannelTarget);
  const bool semantic_path =
      semantic_target.has_value() && *semantic_target == AMCompletionTarget::Path;
  const bool prefix_has_path_sign =
      prefix_starts_with_path_sign || has_at || IsPathLikeText(ctx.token_prefix, false);
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
  } else if (!semantic_terminal_channel &&
             (has_at || IsPathLikeText(ctx.token_prefix, false))) {
    push_target(AMCompletionTarget::Path);
  }

  if (ctx.targets.empty()) {
    ctx.targets = {AMCompletionTarget::Subcommand};
  }
  return ctx;
}

AMCompleteEngine::CompletionModePolicy
AMCompleteEngine::ResolveModePolicy_(const AMCompletionContext &ctx,
                                     AMCompletionTarget target) const {
  CompletionModePolicy out = {};
  out.enabled = true;
  out.use_async = false;
  out.timeout_ms = 0;
  out.search_delay_ms =
      (ctx.mode == AMCompletionMode::Complete) ? args_.complete_delay_ms : 0;

  if (!runtime_) {
    return out;
  }

  const auto options =
      runtime_->ResolvePromptPathOptions(ResolvePolicyNickname_(ctx));
  const auto &mode = (ctx.mode == AMCompletionMode::InlineHint)
                         ? options.inline_hint
                         : options.complete;
  out.enabled = mode.enable;
  out.use_async = mode.use_async;
  if (mode.timeout_ms == 0) {
    out.timeout_ms = 0;
  } else if (mode.timeout_ms >
             static_cast<size_t>(std::numeric_limits<int>::max())) {
    out.timeout_ms = std::numeric_limits<int>::max();
  } else {
    out.timeout_ms = static_cast<int>(mode.timeout_ms);
  }
  if (ctx.mode == AMCompletionMode::InlineHint) {
    out.search_delay_ms = std::max(0, mode.delay_ms);
  } else if (mode.delay_ms > 0) {
    out.search_delay_ms = mode.delay_ms;
  }
  if (target != AMCompletionTarget::Path) {
    out.use_async = false;
    out.timeout_ms = 0;
  }
  return out;
}

std::string
AMCompleteEngine::ResolvePolicyNickname_(const AMCompletionContext &ctx) const {
  const size_t at_pos = ctx.token_prefix.find('@');
  if (at_pos != std::string::npos) {
    if (at_pos == 0) {
      return "local";
    }
    std::string inline_nickname =
        AMStr::Strip(ctx.token_prefix.substr(0, at_pos));
    if (!inline_nickname.empty()) {
      return inline_nickname;
    }
  }
  if (!runtime_) {
    return "local";
  }
  std::string nickname = AMStr::Strip(runtime_->CurrentNickname());
  if (nickname.empty()) {
    nickname = "local";
  }
  return nickname;
}

bool IsPathKind_(AMCompletionKind kind) {
  return kind == AMCompletionKind::PathLocal ||
         kind == AMCompletionKind::PathRemote;
}

std::string TrimTrailingSep_(std::string text) {
  while (!text.empty() && (text.back() == '/' || text.back() == '\\')) {
    text.pop_back();
  }
  return text;
}

std::string LeafNameForPathSort_(const std::string &insert_text) {
  const std::string clean = TrimTrailingSep_(insert_text);
  if (clean.empty()) {
    return clean;
  }
  const size_t slash_pos = clean.find_last_of("/\\");
  if (slash_pos != std::string::npos) {
    return clean.substr(slash_pos + 1);
  }
  const size_t at_pos = clean.find_last_of('@');
  if (at_pos != std::string::npos) {
    return clean.substr(at_pos + 1);
  }
  return clean;
}

bool StartsWithDot_(const std::string &name) {
  return !name.empty() && name.front() == '.';
}

int PathTypeOrder_(PathType type) {
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

void AMCompleteEngine::FinalizeCandidates_(const AMCompletionContext &ctx,
                                           AMCompletionCandidates *out) const {
  if (!out || out->items.empty()) {
    return;
  }

  auto &items = out->items;
  std::stable_sort(
      items.begin(), items.end(), [](const auto &lhs, const auto &rhs) {
        if (lhs.score != rhs.score) {
          return lhs.score < rhs.score;
        }
        if (lhs.kind != rhs.kind) {
          return static_cast<int>(lhs.kind) < static_cast<int>(rhs.kind);
        }
        if (IsPathKind_(lhs.kind) && IsPathKind_(rhs.kind)) {
          const int lo = PathTypeOrder_(lhs.path_type);
          const int ro = PathTypeOrder_(rhs.path_type);
          if (lo != ro) {
            return lo < ro;
          }
          const std::string lname = LeafNameForPathSort_(lhs.insert_text);
          const std::string rname = LeafNameForPathSort_(rhs.insert_text);
          const bool ldot = StartsWithDot_(lname);
          const bool rdot = StartsWithDot_(rname);
          if (ldot != rdot) {
            return ldot;
          }
          if (lname != rname) {
            return lname < rname;
          }
        }
        if (lhs.insert_text != rhs.insert_text) {
          return lhs.insert_text < rhs.insert_text;
        }
        if (lhs.display != rhs.display) {
          return lhs.display < rhs.display;
        }
        return lhs.help < rhs.help;
      });

  std::unordered_set<std::string> seen;
  std::vector<AMCompletionCandidate> deduped;
  deduped.reserve(items.size());
  for (auto &item : items) {
    const std::string key =
        AMStr::fmt("{}|{}|{}|{}", static_cast<int>(item.kind), item.insert_text,
                   item.display, item.help);
    if (!seen.insert(key).second) {
      continue;
    }
    deduped.push_back(std::move(item));
  }
  items = std::move(deduped);

  if (ctx.mode == AMCompletionMode::InlineHint && items.size() != 1) {
    items.clear();
  }
}

void AMCompleteEngine::DispatchCandidates_(const AMCompletionContext &ctx,
                                           AMCompletionCandidates &out) {
  if (ctx.targets.empty()) {
    return;
  }
  for (auto target : ctx.targets) {
    if (target == AMCompletionTarget::Disabled) {
      return;
    }
  }

  ConsumeAsyncResults_(ctx, out);

  std::vector<std::pair<std::shared_ptr<AMCompletionSearchEngine>,
                        std::vector<AMCompletionTarget>>>
      grouped_engines;
  std::unordered_map<const AMCompletionSearchEngine *, size_t> grouped_index;
  for (auto target : ctx.targets) {
    auto engine = ResolveSearchEngine_(target);
    if (!engine) {
      continue;
    }
    auto it = grouped_index.find(engine.get());
    if (it == grouped_index.end()) {
      grouped_index[engine.get()] = grouped_engines.size();
      grouped_engines.push_back({engine, {target}});
      continue;
    }
    grouped_engines[it->second].second.push_back(target);
  }

  bool scheduled_async = false;
  for (auto &entry : grouped_engines) {
    auto engine = entry.first;
    auto targets = entry.second;
    if (!engine || targets.empty()) {
      continue;
    }

    AMCompletionContext scoped = ctx;
    scoped.targets = std::move(targets);
    if ((ContextHasTarget_(scoped, AMCompletionTarget::ClientName) ||
         ContextHasTarget_(scoped, AMCompletionTarget::HostNickname)) &&
        ContextHasTarget_(ctx, AMCompletionTarget::Path) &&
        !ContextHasTarget_(scoped, AMCompletionTarget::Path)) {
      scoped.targets.push_back(AMCompletionTarget::Path);
    }

    const CompletionModePolicy policy =
        ResolveModePolicy_(ctx, scoped.targets.front());
    if (ctx.mode == AMCompletionMode::InlineHint && !policy.enabled) {
      continue;
    }
    scoped.timeout_ms = policy.timeout_ms;
    scoped.search_delay_ms = policy.search_delay_ms;

    if (policy.use_async) {
      scoped.control_token = CreateInterruptControl();
      scoped.async_search = true;
      auto task = engine->CreateTask(scoped);
      if (task) {
        const AMCompletionTarget async_target = scoped.targets.front();
        TerminateOnAirTask_(async_target);
        AMCompletionAsyncTask request = {};
        request.request_id = ctx.request_id;
        request.mode = ctx.mode;
        request.target = async_target;
        request.task = std::move(task);
        request.source_engine = engine;
        ScheduleAsyncTask_(std::move(request));
        scheduled_async = true;
        continue;
      }
    }

    scoped.control_token = nullptr;
    scoped.async_search = false;
    AMCompletionCandidates collected = engine->CollectCandidates(scoped);
    if (!collected.items.empty()) {
      engine->SortCandidates(scoped, collected.items);
      out.from_cache = out.from_cache || collected.from_cache;
      out.items.insert(out.items.end(),
                       std::make_move_iterator(collected.items.begin()),
                       std::make_move_iterator(collected.items.end()));
    }
  }

  if (!out.items.empty()) {
    FinalizeCandidates_(ctx, &out);
    return;
  }

  if (!scheduled_async) {
    return;
  }
}

void AMCompleteEngine::EmitCandidates_(ic_completion_env_t *cenv,
                                       const AMCompletionContext &ctx,
                                       const AMCompletionCandidates &items) {
  if (!cenv) {
    return;
  }

  ic_set_completion_page_marker(items.from_cache ? "(cache)" : nullptr);

  long delete_before = 0;
  long delete_after = 0;
  if (ctx.has_token && ctx.cursor >= ctx.token.raw.content_start &&
      ctx.cursor <= ctx.token.raw.content_end) {
    delete_before = static_cast<long>(ctx.cursor - ctx.token.raw.content_start);
    delete_after = static_cast<long>(ctx.token.raw.content_end - ctx.cursor);
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

} // namespace AMInterface::completer
