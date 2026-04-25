#include "interface/input_analysis/InputAnalyzer.hpp"

#include "domain/host/HostDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/url.hpp"
#include "interface/input_analysis/lexer/ShellTokenLexer.hpp"
#include "interface/input_analysis/rules/InputTextRules.hpp"
#include "interface/parser/CommandTree.hpp"

#include <limits>
#include <optional>

namespace AMInterface::input {
namespace {

using AMInterface::parser::AMCommandArgSemantic;
using AMInterface::parser::CommandNode;
using rules::FindUnescapedChar;
using rules::HasClearPathSign;
using rules::IsPathLikeText;
using rules::UnescapeBackticks;

bool StartsWithLongOption_(const std::string &text) {
  return text.size() >= 2 && text[0] == '-' && text[1] == '-';
}

bool StartsWithShortOption_(const std::string &text) {
  return text.size() >= 1 && text[0] == '-' &&
         !(text.size() >= 2 && text[1] == '-');
}

bool IsPathSemantic_(AMCommandArgSemantic semantic) {
  return semantic == AMCommandArgSemantic::Path;
}

bool IsTerminalSemantic_(AMCommandArgSemantic semantic) {
  return semantic == AMCommandArgSemantic::TerminalName ||
         semantic == AMCommandArgSemantic::TermTargetExisting ||
         semantic == AMCommandArgSemantic::TermTargetNew ||
         semantic == AMCommandArgSemantic::SshTermTarget;
}

TokenShape DetectTokenShape_(const std::string &raw, bool quoted) {
  if (quoted) {
    return TokenShape::Quoted;
  }
  if (raw.empty()) {
    return TokenShape::Plain;
  }
  if (raw[0] == '`' && raw.size() >= 2 &&
      (raw[1] == '$' || raw[1] == '@' || raw[1] == '"' || raw[1] == '\'' ||
       raw[1] == '`' || raw[1] == '!')) {
    return TokenShape::EscapeLike;
  }
  if (raw[0] == '$') {
    return TokenShape::VarLike;
  }
  if (raw[0] == '!') {
    return TokenShape::ShellBangLike;
  }
  if (StartsWithLongOption_(raw) || StartsWithShortOption_(raw)) {
    return TokenShape::OptionLike;
  }
  if (FindUnescapedChar(raw, '@') != std::string::npos) {
    return TokenShape::AtStructuredLike;
  }
  if (IsPathLikeText(UnescapeBackticks(raw, true), true)) {
    return TokenShape::PathLike;
  }
  return TokenShape::Plain;
}

TokenState TerminalStateToTokenState_(
    IInputSemanticRuntime::TerminalNameState state) {
  switch (state) {
  case IInputSemanticRuntime::TerminalNameState::OK:
    return TokenState::Valid;
  case IInputSemanticRuntime::TerminalNameState::Disconnected:
    return TokenState::Disconnected;
  case IInputSemanticRuntime::TerminalNameState::Unestablished:
    return TokenState::Unestablished;
  case IInputSemanticRuntime::TerminalNameState::Nonexistent:
    return TokenState::Nonexistent;
  case IInputSemanticRuntime::TerminalNameState::ValidNew:
    return TokenState::NewValid;
  case IInputSemanticRuntime::TerminalNameState::InvalidNew:
  default:
    return TokenState::NewInvalid;
  }
}

TokenState NicknameState_(
    const std::shared_ptr<IInputSemanticRuntime> &runtime,
    const std::string &nickname_raw) {
  const std::string nickname = AMStr::Strip(nickname_raw);
  if (AMDomain::host::HostService::IsLocalNickname(nickname)) {
    return TokenState::Valid;
  }
  if (!runtime) {
    return TokenState::Nonexistent;
  }
  if (auto client = runtime->GetClient(nickname); client) {
    const auto state = client->ConfigPort().GetState();
    if (state.data.status == AMDomain::client::ClientStatus::OK) {
      return TokenState::Valid;
    }
    return TokenState::Disconnected;
  }
  if (runtime->HostExists(nickname)) {
    return TokenState::Unestablished;
  }
  return TokenState::Nonexistent;
}

TokenState VarZoneState_(const std::shared_ptr<IInputSemanticRuntime> &runtime,
                         const std::string &zone_raw) {
  const std::string zone = AMStr::Strip(zone_raw);
  if (zone.empty()) {
    return TokenState::Nonexistent;
  }
  if (zone == AMDomain::var::kPublic) {
    return TokenState::Valid;
  }
  if (!runtime) {
    return TokenState::Nonexistent;
  }
  if (runtime->HasVarDomain(zone)) {
    return TokenState::Valid;
  }
  if (runtime->HostExists(zone)) {
    return TokenState::Unestablished;
  }
  return TokenState::Nonexistent;
}

TokenState VarNameState_(const std::shared_ptr<IInputSemanticRuntime> &runtime,
                         const std::string &name) {
  if (!runtime) {
    return TokenState::Missing;
  }
  const std::string domain = runtime->CurrentVarDomain();
  auto scoped = runtime->GetVar(domain, name);
  if ((scoped.rcm)) {
    return TokenState::Valid;
  }
  auto pub = runtime->GetVar(AMDomain::var::kPublic, name);
  return (pub.rcm) ? TokenState::Valid : TokenState::Missing;
}

struct ParsedTermTarget_ {
  std::string client_name = "local";
  std::string term_name = {};
  bool explicit_client = false;
};

ParsedTermTarget_ ParseTermTarget_(const std::string &token,
                                   const std::string &default_client_name) {
  ParsedTermTarget_ out = {};
  out.client_name =
      AMDomain::host::HostService::NormalizeNickname(default_client_name);
  if (out.client_name.empty()) {
    out.client_name = "local";
  }

  const std::string text = AMStr::Strip(token);
  if (text.empty()) {
    return out;
  }

  const size_t at_pos = FindUnescapedChar(text, '@');
  if (at_pos == std::string::npos) {
    out.term_name = AMStr::Strip(UnescapeBackticks(text, true));
    return out;
  }

  out.explicit_client = true;
  const std::string client_part =
      AMStr::Strip(UnescapeBackticks(text.substr(0, at_pos), true));
  if (!client_part.empty()) {
    out.client_name =
        AMDomain::host::HostService::NormalizeNickname(client_part);
  }
  out.term_name = AMStr::Strip(UnescapeBackticks(text.substr(at_pos + 1), true));
  return out;
}

bool IsVarShortcutDefineToken_(const std::string &raw_text) {
  if (raw_text.size() >= 2 && raw_text[0] == '`' && raw_text[1] == '$') {
    return false;
  }
  const std::string text = UnescapeBackticks(raw_text, true);
  if (text.size() < 3 || text.front() != '$') {
    return false;
  }
  const size_t eq = text.find('=');
  if (eq == std::string::npos || eq <= 1) {
    return false;
  }
  const std::string lhs = text.substr(0, eq);
  return AMDomain::var::ParseVarToken(lhs);
}

bool StartsWithUnescapedDollar_(const std::string &raw_text) {
  return !raw_text.empty() && raw_text.front() == '$';
}

bool ParseVariablePrefix_(const std::string &raw_text,
                          AMDomain::var::VarRef *out_ref) {
  if (!StartsWithUnescapedDollar_(raw_text)) {
    return false;
  }
  if (raw_text == "$") {
    if (out_ref) {
      *out_ref = {.valid = true};
    }
    return true;
  }
  if (raw_text == "${") {
    if (out_ref) {
      *out_ref = {.valid = true, .braced = true};
    }
    return true;
  }

  size_t end = 0;
  AMDomain::var::VarRef ref = {};
  if (!AMDomain::var::ParseVarRefAt(raw_text, 0, raw_text.size(), true, true,
                                    &end, &ref) ||
      !ref.valid || end != raw_text.size()) {
    return false;
  }
  if (out_ref) {
    *out_ref = std::move(ref);
  }
  return true;
}

TokenState VariableRefState_(const std::shared_ptr<IInputSemanticRuntime> &runtime,
                             const AMDomain::var::VarRef &ref) {
  if (!ref.valid || ref.varname.empty()) {
    if (ref.explicit_domain) {
      return VarZoneState_(runtime, ref.domain);
    }
    return TokenState::Valid;
  }
  if (ref.explicit_domain) {
    if (!runtime) {
      return TokenState::Missing;
    }
    auto scoped = runtime->GetVar(ref.domain, ref.varname);
    return (scoped.rcm) ? TokenState::Valid : TokenState::Missing;
  }
  return VarNameState_(runtime, ref.varname);
}

bool IsIntegerLiteral_(const std::string &raw_text) {
  const std::string text = AMStr::Strip(raw_text);
  if (text.empty()) {
    return false;
  }

  size_t begin = 0;
  if (text[0] == '+' || text[0] == '-') {
    if (text.size() == 1) {
      return false;
    }
    begin = 1;
  }
  for (size_t idx = begin; idx < text.size(); ++idx) {
    if (text[idx] < '0' || text[idx] > '9') {
      return false;
    }
  }
  return true;
}

PathKind ToPathKind_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return PathKind::File;
  case PathType::DIR:
    return PathKind::Directory;
  case PathType::SYMLINK:
    return PathKind::Symlink;
  default:
    return PathKind::Special;
  }
}

int ToClientTimeoutMs_(size_t timeout_ms, int fallback_ms) {
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

struct RuntimeContext_ {
  AMDomain::client::ClientHandle current_client = nullptr;
  std::string current_nickname = "local";
};

struct TokenSemanticHint_ {
  bool positional_consumed = false;
  bool option_definition = false;
  bool option_value_token = false;
  bool positional_rule_exists = false;
  std::optional<AMCommandArgSemantic> semantic = std::nullopt;
};

struct PathTarget_ {
  std::string nickname_for_cfg = "local";
  std::string nickname_for_lookup = "local";
  std::string path_part_raw = {};
  bool explicit_target = false;
  bool explicit_local = false;
};

void SetTokenClassification_(AnalyzedToken *token, TokenRole role,
                             TokenState state = TokenState::Neutral,
                             PathKind path_kind = PathKind::None) {
  if (!token) {
    return;
  }
  token->role = role;
  token->state = state;
  token->qualifier_state = TokenState::Neutral;
  token->path_kind = path_kind;
}

void SetTermTargetClassification_(
    AnalyzedToken *token, const ParsedTermTarget_ &target, bool allow_new,
    const std::shared_ptr<IInputSemanticRuntime> &runtime) {
  if (!token) {
    return;
  }
  const auto missing = IInputSemanticRuntime::TerminalNameState::Nonexistent;
  const auto client_state =
      runtime ? runtime->QueryTerminalClientNameState(target.client_name)
              : missing;
  const auto term_state =
      runtime ? runtime->QueryTermNameState(target.client_name,
                                            target.term_name, allow_new)
              : missing;
  token->role = TokenRole::TerminalName;
  token->qualifier_state = TerminalStateToTokenState_(client_state);
  token->state = TerminalStateToTokenState_(term_state);
  token->path_kind = PathKind::None;
}

std::vector<std::string>
BuildTokenTexts_(const std::string &input,
                 const std::vector<AnalyzedToken> &tokens) {
  std::vector<std::string> texts = {};
  texts.reserve(tokens.size());
  for (const auto &token : tokens) {
    texts.push_back(input.substr(token.raw.content_start,
                                 token.raw.content_end -
                                     token.raw.content_start));
  }
  return texts;
}

void InitializeTokens_(std::vector<AnalyzedToken> *tokens) {
  if (!tokens) {
    return;
  }
  for (auto &token : *tokens) {
    token.role =
        token.raw.quoted ? TokenRole::StringLiteral : TokenRole::None;
    token.state = TokenState::Neutral;
    token.path_kind = PathKind::None;
    token.shape = DetectTokenShape_("", token.raw.quoted);
  }
}

void ApplyShapes_(const std::string &input, std::vector<AnalyzedToken> *tokens) {
  if (!tokens) {
    return;
  }
  for (auto &token : *tokens) {
    if (token.raw.content_end <= token.raw.content_start ||
        token.raw.content_end > input.size()) {
      continue;
    }
    const std::string raw =
        input.substr(token.raw.content_start,
                     token.raw.content_end - token.raw.content_start);
    token.shape = DetectTokenShape_(raw, token.raw.quoted);
  }
}

void ConsumePositionalArg_(CommandContext *state, bool positional_consumed) {
  if (state && positional_consumed) {
    ++state->next_arg_index;
  }
}

std::optional<AMCommandArgSemantic>
ConsumePendingOptionValue_(CommandContext *state) {
  if (!state || !state->pending_value_rule.has_value()) {
    return std::nullopt;
  }

  const AMCommandArgSemantic semantic = state->pending_value_rule->semantic;
  ++state->pending_value_index;
  if (!state->pending_value_rule->repeat_tail &&
      state->pending_value_index >= state->pending_value_rule->value_count) {
    state->pending_value_rule.reset();
    state->pending_value_index = 0;
  }
  return semantic;
}

void SetPendingOptionValue_(CommandContext *state,
                            const CommandNode::OptionValueRule &rule,
                            size_t consumed) {
  if (!state) {
    return;
  }
  if (!rule.repeat_tail && consumed >= rule.value_count) {
    state->pending_value_rule.reset();
    state->pending_value_index = 0;
    return;
  }
  state->pending_value_rule = InputOptionValueRule{
      .long_option = rule.long_option,
      .short_option = rule.short_option,
      .semantic = rule.semantic,
      .value_count = rule.value_count,
      .repeat_tail = rule.repeat_tail,
  };
  state->pending_value_index = consumed;
}

RuntimeContext_ BuildRuntimeContext_(
    const std::shared_ptr<IInputSemanticRuntime> &runtime) {
  RuntimeContext_ context = {};
  context.current_client = runtime ? runtime->CurrentClient() : nullptr;
  context.current_nickname =
      runtime ? runtime->CurrentNickname() : std::string("local");
  if (context.current_nickname.empty()) {
    context.current_nickname = "local";
  }
  return context;
}

struct CommandScanResult_ {
  const CommandNode *node = nullptr;
  std::string command_path = {};
  size_t command_tokens = 0;
  std::string module = {};
  bool has_module = false;
  bool has_command = false;
  bool unknown_before_command = false;
};

CommandScanResult_ ScanCommandPrefix_(
    const CommandNode *command_tree, std::vector<AnalyzedToken> *tokens,
    const std::vector<std::string> &texts) {
  CommandScanResult_ result = {};
  if (!command_tree || !tokens) {
    return result;
  }

  bool parsing = true;
  for (size_t idx = 0; idx < tokens->size(); ++idx) {
    auto &token = (*tokens)[idx];
    if (token.raw.quoted) {
      continue;
    }

    const std::string &text = texts[idx];
    if (text.empty()) {
      continue;
    }
    if (!parsing) {
      continue;
    }

    if (result.command_path.empty()) {
      if (command_tree->IsModule(text)) {
        SetTokenClassification_(&token, TokenRole::Module);
        result.module = text;
        result.has_module = true;
        result.command_path = text;
        result.node = command_tree->FindNode(result.command_path);
        result.command_tokens = idx + 1;
        continue;
      }
      if (command_tree->IsTopCommand(text)) {
        SetTokenClassification_(&token, TokenRole::Command);
        result.has_command = true;
        result.command_path = text;
        result.node = command_tree->FindNode(result.command_path);
        result.command_tokens = idx + 1;
        if (!result.node || result.node->subcommands.empty()) {
          parsing = false;
        }
        continue;
      }

      const bool should_mark_illegal =
          (idx == 0) && !text.empty() && text.front() != '!' &&
          !StartsWithLongOption_(text) && !StartsWithShortOption_(text) &&
          !IsVarShortcutDefineToken_(text) &&
          !ParseVariablePrefix_(text, nullptr);
      if (should_mark_illegal) {
        SetTokenClassification_(&token, TokenRole::IllegalCommand,
                                TokenState::Invalid);
        result.unknown_before_command = true;
      }
      parsing = false;
      continue;
    }

    if (result.node && result.node->subcommands.contains(text)) {
      SetTokenClassification_(&token, TokenRole::Command);
      result.command_path += " " + text;
      result.has_command = true;
      result.node = command_tree->FindNode(result.command_path);
      result.command_tokens = idx + 1;
      if (!result.node || result.node->subcommands.empty()) {
        parsing = false;
      }
      continue;
    }

    if (result.node && !result.node->subcommands.empty() &&
        !StartsWithLongOption_(text) && !StartsWithShortOption_(text)) {
      SetTokenClassification_(&token, TokenRole::IllegalCommand,
                              TokenState::Invalid);
    }
    parsing = false;
  }

  return result;
}

void MarkIllegalCommandGaps_(const CommandNode *command_tree,
                             std::vector<AnalyzedToken> *tokens,
                             const std::vector<std::string> &texts) {
  if (!command_tree || !tokens) {
    return;
  }

  std::vector<size_t> legal_indexes = {};
  legal_indexes.reserve(tokens->size());
  const CommandNode *scan_node = nullptr;
  std::string scan_path = {};

  for (size_t idx = 0; idx < tokens->size(); ++idx) {
    if ((*tokens)[idx].raw.quoted) {
      continue;
    }

    const std::string &text = texts[idx];
    if (text.empty()) {
      continue;
    }

    if (scan_path.empty()) {
      if (command_tree->IsModule(text) || command_tree->IsTopCommand(text)) {
        legal_indexes.push_back(idx);
        scan_path = text;
        scan_node = command_tree->FindNode(scan_path);
      }
      continue;
    }

    if (scan_node && scan_node->subcommands.contains(text)) {
      legal_indexes.push_back(idx);
      scan_path += " " + text;
      scan_node = command_tree->FindNode(scan_path);
    }
  }

  if (legal_indexes.empty()) {
    return;
  }

  size_t segment_begin = 0;
  for (size_t legal_index : legal_indexes) {
    for (size_t idx = segment_begin; idx < legal_index; ++idx) {
      auto &token = (*tokens)[idx];
      if (token.raw.quoted || token.role != TokenRole::None) {
        continue;
      }
      if (IsVarShortcutDefineToken_(texts[idx])) {
        continue;
      }
      if (ParseVariablePrefix_(texts[idx], nullptr)) {
        continue;
      }
      SetTokenClassification_(&token, TokenRole::IllegalCommand,
                              TokenState::Invalid);
    }
    segment_begin = legal_index + 1;
  }
}

void MarkIllegalRootTail_(std::vector<AnalyzedToken> *tokens,
                          const std::vector<std::string> &texts) {
  if (!tokens) {
    return;
  }
  bool root_illegal_seen = false;
  for (size_t idx = 0; idx < tokens->size(); ++idx) {
    auto &token = (*tokens)[idx];
    if (token.raw.quoted || texts[idx].empty()) {
      continue;
    }
    if (!root_illegal_seen) {
      root_illegal_seen = token.role == TokenRole::IllegalCommand;
      continue;
    }
    if (token.role == TokenRole::None) {
      SetTokenClassification_(&token, TokenRole::IllegalCommand,
                              TokenState::Invalid);
    }
  }
}

void MarkOptions_(std::vector<AnalyzedToken> *tokens,
                  const std::vector<std::string> &texts,
                  const CommandNode *node) {
  if (!node || !tokens) {
    return;
  }

  for (size_t idx = 0; idx < tokens->size(); ++idx) {
    auto &token = (*tokens)[idx];
    if (token.raw.quoted || token.role != TokenRole::None) {
      continue;
    }
    const std::string &text = texts[idx];
    if (text.size() < 2 || text[0] != '-') {
      continue;
    }
    bool valid = false;
    if (text.starts_with("--")) {
      std::string name = text;
      const size_t eq = text.find('=');
      if (eq != std::string::npos) {
        name = text.substr(0, eq);
      }
      valid = node->long_options.contains(name);
    } else {
      valid = true;
      for (size_t i = 1; i < text.size(); ++i) {
        if (!node->short_options.contains(text[i])) {
          valid = false;
          break;
        }
      }
    }
    if (valid) {
      SetTokenClassification_(&token, TokenRole::Option);
    }
  }
}

TokenSemanticHint_ ResolveTokenSemanticHint_(
    const CommandNode *command_tree, const std::string &command_path,
    const AnalyzedToken &token, const std::string &raw_text,
    CommandContext *state) {
  TokenSemanticHint_ hint = {};
  hint.option_value_token =
      state != nullptr && state->pending_value_rule.has_value();
  hint.semantic = ConsumePendingOptionValue_(state);

  if (!hint.semantic.has_value() && command_tree && !command_path.empty() &&
      !token.raw.quoted) {
    if (StartsWithLongOption_(raw_text)) {
      hint.option_definition = true;
      const size_t eq_pos = raw_text.find('=');
      const std::string option_name =
          eq_pos == std::string::npos ? raw_text : raw_text.substr(0, eq_pos);
      const auto rule =
          command_tree->ResolveOptionValueRule(command_path, option_name, '\0', 0);
      if (rule.has_value() && state) {
        if (eq_pos == std::string::npos || eq_pos + 1 == raw_text.size()) {
          SetPendingOptionValue_(state, *rule, 0);
        } else {
          SetPendingOptionValue_(state, *rule, 1);
        }
      }
    } else if (StartsWithShortOption_(raw_text)) {
      hint.option_definition = true;
      const std::string body = raw_text.substr(1);
      for (size_t cidx = 0; cidx < body.size(); ++cidx) {
        const auto rule =
            command_tree->ResolveOptionValueRule(command_path, "", body[cidx], 0);
        if (!rule.has_value()) {
          continue;
        }
        if (state) {
          if (cidx + 1 < body.size()) {
            SetPendingOptionValue_(state, *rule, 1);
          } else {
            SetPendingOptionValue_(state, *rule, 0);
          }
        }
        break;
      }
    }
  }

  if (!hint.option_value_token && !hint.semantic.has_value() &&
      !hint.option_definition && command_tree && !command_path.empty() && state) {
    hint.positional_rule_exists =
        command_tree->HasPositionalRule(command_path, state->next_arg_index);
    hint.semantic =
        command_tree->ResolvePositionalSemantic(command_path, state->next_arg_index);
    hint.positional_consumed = true;
    return hint;
  }

  if (!hint.option_definition && !hint.option_value_token) {
    hint.positional_consumed = true;
  }
  return hint;
}

PathTarget_ ResolvePathTarget_(const std::string &raw_text,
                               const std::string &current_nickname) {
  PathTarget_ target = {};
  target.nickname_for_cfg = current_nickname;
  target.nickname_for_lookup = current_nickname;
  target.path_part_raw = raw_text;

  const size_t at_pos = FindUnescapedChar(raw_text, '@');
  if (!raw_text.empty() && raw_text.front() == '@') {
    target.explicit_target = true;
    target.explicit_local = true;
    target.nickname_for_cfg = "local";
    target.nickname_for_lookup = "local";
    target.path_part_raw = raw_text.substr(1);
    return target;
  }

  if (at_pos != std::string::npos) {
    target.explicit_target = true;
    const std::string prefix_raw = raw_text.substr(0, at_pos);
    const std::string prefix = AMStr::Strip(UnescapeBackticks(prefix_raw, true));
    target.path_part_raw = raw_text.substr(at_pos + 1);
    if (AMDomain::host::HostService::IsLocalNickname(prefix)) {
      target.explicit_local = true;
      target.nickname_for_cfg = "local";
      target.nickname_for_lookup = "local";
    } else if (!prefix.empty()) {
      target.nickname_for_cfg = prefix;
      target.nickname_for_lookup = prefix;
    }
    return target;
  }

  if (AMDomain::host::HostService::IsLocalNickname(current_nickname)) {
    target.nickname_for_cfg = "local";
    target.nickname_for_lookup = "local";
  }
  return target;
}

AMDomain::client::ClientHandle ResolvePathClient_(
    const std::shared_ptr<IInputSemanticRuntime> &runtime,
    const RuntimeContext_ &runtime_context, const PathTarget_ &target) {
  if (!runtime) {
    return nullptr;
  }

  if (target.explicit_target) {
    if (target.explicit_local) {
      return runtime->LocalClient();
    }
    return runtime->GetClient(target.nickname_for_lookup);
  }

  return runtime_context.current_client ? runtime_context.current_client
                                        : runtime->LocalClient();
}

} // namespace

std::vector<InputAnalyzer::RawToken>
InputAnalyzer::SplitTokens(const std::string &input) const {
  {
    auto cache = split_token_cache_.lock();
    auto cache_it = cache->find(input);
    if (cache_it != cache->end()) {
      return cache_it->second;
    }
  }

  std::vector<RawToken> tokens = lexer::ShellTokenLexer::Split(input);
  {
    auto cache = split_token_cache_.lock();
    auto [it, inserted] = cache->emplace(input, tokens);
    if (!inserted) {
      return it->second;
    }
  }
  return tokens;
}

InputAnalysis InputAnalyzer::Analyze(const std::string &input) const {
  InputAnalysis analysis = {};
  analysis.input = input;
  const auto split_tokens = SplitTokens(input);
  analysis.tokens.reserve(split_tokens.size());
  for (const auto &raw : split_tokens) {
    AnalyzedToken token = {};
    token.raw = raw;
    analysis.tokens.push_back(token);
  }

  InitializeTokens_(&analysis.tokens);
  ApplyShapes_(input, &analysis.tokens);
  const std::vector<std::string> texts = BuildTokenTexts_(input, analysis.tokens);

  const auto command_scan =
      ScanCommandPrefix_(command_tree_, &analysis.tokens, texts);
  MarkIllegalCommandGaps_(command_tree_, &analysis.tokens, texts);
  if (command_scan.command_tokens == 0) {
    MarkIllegalRootTail_(&analysis.tokens, texts);
  }
  MarkOptions_(&analysis.tokens, texts, command_scan.node);

  analysis.command.module = command_scan.module;
  analysis.command.command_path = command_scan.command_path;
  analysis.command.node = command_scan.node;
  analysis.command.command_tokens = command_scan.command_tokens;
  analysis.command.has_module = command_scan.has_module;
  analysis.command.has_command = command_scan.has_command;
  analysis.command.unknown_before_command = command_scan.unknown_before_command;

  const RuntimeContext_ runtime_context = BuildRuntimeContext_(runtime_);

  for (size_t idx = 0; idx < analysis.tokens.size(); ++idx) {
    auto &token = analysis.tokens[idx];
    if (idx < analysis.command.command_tokens) {
      continue;
    }

    const std::string &raw_text = texts[idx];
    if (raw_text.empty()) {
      continue;
    }

    const TokenSemanticHint_ hint = ResolveTokenSemanticHint_(
        command_tree_, analysis.command.command_path, token, raw_text,
        &analysis.command);
    token.semantic_hint = hint.semantic;
    token.option_definition = hint.option_definition;
    token.option_value_token = hint.option_value_token;
    token.positional_rule_exists = hint.positional_rule_exists;
    token.positional_consumed = hint.positional_consumed;

    if (token.role == TokenRole::Option || hint.option_definition) {
      analysis.command.options.push_back(raw_text);
    } else if (idx >= analysis.command.command_tokens) {
      analysis.command.args.push_back(raw_text);
    }

    if (token.raw.quoted) {
      ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
      continue;
    }

    if ((token.role == TokenRole::Option || hint.option_definition) &&
        !hint.semantic.has_value()) {
      continue;
    }

    const std::string unescaped_text = UnescapeBackticks(raw_text, true);

    if (token.role == TokenRole::None && hint.positional_consumed &&
        !hint.option_value_token && !hint.option_definition && command_tree_ &&
        !analysis.command.command_path.empty() && !hint.semantic.has_value() &&
        !hint.positional_rule_exists) {
      SetTokenClassification_(&token, TokenRole::IllegalCommand,
                              TokenState::Invalid);
      ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
      continue;
    }

    if (token.role == TokenRole::None && hint.semantic.has_value()) {
      switch (*hint.semantic) {
      case AMCommandArgSemantic::HostNicknameNew: {
        const bool is_sftp_or_ftp =
            (analysis.command.command_path == "sftp" ||
             analysis.command.command_path == "ftp");
        const bool is_user_at_host =
            FindUnescapedChar(raw_text, '@') != std::string::npos;
        if (!is_sftp_or_ftp || !is_user_at_host) {
          const std::string nickname = AMStr::Strip(unescaped_text);
          const ECM validate_rcm =
              AMDomain::host::HostService::ValidateFieldValue(
                  AMDomain::host::ConRequest::Attr::nickname, nickname);
          TokenState state = TokenState::NewInvalid;
          if ((validate_rcm) &&
              !AMDomain::host::HostService::IsLocalNickname(nickname) &&
              !(runtime_ && runtime_->HostExists(nickname))) {
            state = TokenState::NewValid;
          }
          SetTokenClassification_(&token, TokenRole::Nickname, state);
        }
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      }
      case AMCommandArgSemantic::HostAttr: {
        auto parsed_field =
            AMDomain::host::HostService::ParseEditableHostSetField(unescaped_text);
        SetTokenClassification_(&token, TokenRole::BuiltinArg,
                                parsed_field.has_value() ? TokenState::Valid
                                                         : TokenState::Invalid);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      }
      case AMCommandArgSemantic::TaskId:
      case AMCommandArgSemantic::PausedTaskId:
        SetTokenClassification_(&token, TokenRole::BuiltinArg, TokenState::Valid);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      case AMCommandArgSemantic::HostAttrValue:
        SetTokenClassification_(&token, TokenRole::ValidatedValue,
                                TokenState::Neutral);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      case AMCommandArgSemantic::Url:
        SetTokenClassification_(&token, TokenRole::ValidatedValue,
                                AMUrl::IsHttpUrl(unescaped_text)
                                    ? TokenState::Valid
                                    : TokenState::Invalid);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      case AMCommandArgSemantic::HostNickname:
      case AMCommandArgSemantic::ClientName:
      case AMCommandArgSemantic::PoolName:
        SetTokenClassification_(&token, TokenRole::Nickname,
                                NicknameState_(runtime_, unescaped_text));
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      case AMCommandArgSemantic::TerminalName:
        SetTokenClassification_(
            &token, TokenRole::TerminalName,
            TerminalStateToTokenState_(runtime_
                                           ? runtime_->QueryTermNameState(
                                                 runtime_context.current_nickname,
                                                 unescaped_text, false)
                                           : IInputSemanticRuntime::
                                                 TerminalNameState::Nonexistent));
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      case AMCommandArgSemantic::SshTermTarget: {
        const ParsedTermTarget_ target =
            ParseTermTarget_(raw_text, runtime_context.current_nickname);
        SetTermTargetClassification_(&token, target, true, runtime_);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      }
      case AMCommandArgSemantic::TermTargetExisting:
      case AMCommandArgSemantic::TermTargetNew: {
        const ParsedTermTarget_ target =
            ParseTermTarget_(raw_text, runtime_context.current_nickname);
        const bool allow_new =
            *hint.semantic == AMCommandArgSemantic::TermTargetNew;
        SetTermTargetClassification_(&token, target, allow_new, runtime_);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      }
      case AMCommandArgSemantic::VarZone:
        SetTokenClassification_(&token, TokenRole::VariableZone,
                                VarZoneState_(runtime_, unescaped_text));
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      case AMCommandArgSemantic::VariableName: {
        AMDomain::var::VarRef ref = {};
        const TokenState state = ParseVariablePrefix_(raw_text, &ref)
                                     ? VariableRefState_(runtime_, ref)
                                     : TokenState::Invalid;
        SetTokenClassification_(&token, TokenRole::VariableName, state);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      }
      case AMCommandArgSemantic::ShellCmd:
        SetTokenClassification_(&token, TokenRole::ShellCommand);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      case AMCommandArgSemantic::FindPattern:
        SetTokenClassification_(&token, TokenRole::FindPattern,
                                TokenState::Valid);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      case AMCommandArgSemantic::None:
      case AMCommandArgSemantic::Path:
      default:
        break;
      }
    }

    if (token.role == TokenRole::None) {
      AMDomain::var::VarRef ref = {};
      const size_t eq = raw_text.find('=');
      if (eq != std::string::npos &&
          ParseVariablePrefix_(raw_text.substr(0, eq), &ref) &&
          !ref.varname.empty()) {
        const TokenState state = VariableRefState_(runtime_, ref);
        SetTokenClassification_(&token, TokenRole::VariableReference, state);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      }
      if (ParseVariablePrefix_(raw_text, &ref)) {
        const TokenState state = VariableRefState_(runtime_, ref);
        SetTokenClassification_(&token, TokenRole::VariableReference, state);
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      }
    }

    if (token.role == TokenRole::None && hint.semantic.has_value() &&
        *hint.semantic == AMCommandArgSemantic::None &&
        IsIntegerLiteral_(raw_text)) {
      SetTokenClassification_(&token, TokenRole::ValidatedValue,
                              TokenState::Valid);
      ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
      continue;
    }

    if (token.role == TokenRole::None) {
      const size_t at_pos = FindUnescapedChar(raw_text, '@');
      const bool has_unescaped_at = at_pos != std::string::npos;
      const bool force_path =
          hint.semantic.has_value() && IsPathSemantic_(*hint.semantic);
      const bool terminal_semantic =
          hint.semantic.has_value() && IsTerminalSemantic_(*hint.semantic);
      const bool has_clear_path_sign =
          has_unescaped_at || HasClearPathSign(unescaped_text, true);

      if (force_path && !has_clear_path_sign) {
        const TokenState nick_state = NicknameState_(runtime_, unescaped_text);
        if (nick_state == TokenState::Valid ||
            nick_state == TokenState::Disconnected ||
            nick_state == TokenState::Unestablished) {
          SetTokenClassification_(&token, TokenRole::Nickname, nick_state);
          ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
          continue;
        }
      }

      const bool treat_as_path =
          !terminal_semantic &&
          (force_path || has_clear_path_sign || IsPathLikeText(unescaped_text, true));
      if (treat_as_path) {
        const PathTarget_ target =
            ResolvePathTarget_(raw_text, runtime_context.current_nickname);
        IInputSemanticRuntime::PromptPathOptions profile = {};
        if (runtime_) {
          profile = runtime_->ResolvePromptPathOptions(target.nickname_for_cfg);
        }
        if (!profile.highlight.enable) {
          SetTokenClassification_(&token, TokenRole::Path, TokenState::Valid,
                                  PathKind::None);
          ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
          continue;
        }

        const AMDomain::client::ClientHandle path_client =
            ResolvePathClient_(runtime_, runtime_context, target);
        if (!runtime_ || !path_client) {
          SetTokenClassification_(&token, TokenRole::Path,
                                  TokenState::Nonexistent, PathKind::Nonexistent);
          ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
          continue;
        }

        const std::string path_part_unescaped =
            UnescapeBackticks(target.path_part_raw, true);
        const std::string path_part_resolved =
            runtime_->SubstitutePathLike(path_part_unescaped);
        const std::string abs_path =
            runtime_->BuildPath(path_client, path_part_resolved);
        const int timeout_ms =
            ToClientTimeoutMs_(profile.highlight.timeout_ms, 1000);

        auto stat_result = runtime_->StatPath(path_client, abs_path, timeout_ms);
        if ((stat_result.rcm)) {
          SetTokenClassification_(&token, TokenRole::Path, TokenState::Valid,
                                  ToPathKind_(stat_result.data.type));
        } else if (stat_result.rcm.code == EC::FileNotExist ||
                   stat_result.rcm.code == EC::PathNotExist) {
          SetTokenClassification_(&token, TokenRole::Path,
                                  TokenState::Nonexistent, PathKind::Nonexistent);
        } else {
          SetTokenClassification_(&token, TokenRole::Path, TokenState::Invalid,
                                  PathKind::Special);
        }
        ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
        continue;
      }
    }

    ConsumePositionalArg_(&analysis.command, hint.positional_consumed);
  }

  return analysis;
}

void InputAnalyzer::ClearTokenCache() {
  auto cache = split_token_cache_.lock();
  cache->clear();
}

} // namespace AMInterface::input
