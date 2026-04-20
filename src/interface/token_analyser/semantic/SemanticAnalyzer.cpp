#include "interface/token_analyser/semantic/SemanticAnalyzer.hpp"

#include "domain/host/HostDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntime.hpp"
#include "interface/token_analyser/shared/InputTextRules.hpp"
#include "interface/token_analyser/shared/TokenAnalyzerRules.hpp"
#include <limits>
#include <optional>

namespace AMInterface::parser::semantic {
namespace {

using AMDomain::host::HostService::IsLocalNickname;
using shared::ChannelTokenTypeFromState;
using shared::ClassifyNicknameTokenType;
using shared::ClassifyVarZoneTokenType;
using shared::FindUnescapedChar;
using shared::HasClearPathSign;
using shared::IsValidOptionToken;
using shared::IsPathLikeText;
using shared::TerminalTokenTypeFromState;
using shared::UnescapeBackticks;
using shared::VarNameTypeFor;

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

bool IsTerminalChannelSemantic_(AMCommandArgSemantic semantic) {
  return semantic == AMCommandArgSemantic::TerminalName ||
         semantic == AMCommandArgSemantic::ChannelTargetExisting ||
         semantic == AMCommandArgSemantic::ChannelTargetNew ||
         semantic == AMCommandArgSemantic::SshChannelTarget;
}

struct ParsedTerminalChannelTarget_ {
  std::string terminal_name = "local";
  std::string channel_name = "";
};

struct CommandScanResult_ {
  const CommandNode *node = nullptr;
  std::string command_path = {};
  size_t command_tokens = 0;
};

struct RuntimeContext_ {
  AMDomain::client::ClientHandle current_client = nullptr;
  std::string current_nickname = "local";
};

struct ArgSemanticState_ {
  std::optional<CommandNode::OptionValueRule> pending_value_rule = std::nullopt;
  size_t pending_value_index = 0;
  std::optional<AMDomain::host::HostService::HostSetFieldRef>
      active_host_set_field = std::nullopt;
  size_t arg_index = 0;
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

struct ClassificationContext_ {
  const CommandNode *command_tree = nullptr;
  std::shared_ptr<ITokenAnalyzerRuntime> runtime = nullptr;
  CommandScanResult_ command = {};
  RuntimeContext_ runtime_context = {};
};

ParsedTerminalChannelTarget_
ParseTerminalChannelTarget_(const std::string &token,
                            const std::string &default_terminal_name) {
  ParsedTerminalChannelTarget_ out = {};
  out.terminal_name =
      AMDomain::host::HostService::NormalizeNickname(default_terminal_name);
  if (out.terminal_name.empty()) {
    out.terminal_name = "local";
  }

  const std::string text = AMStr::Strip(token);
  if (text.empty()) {
    return out;
  }

  const size_t at_pos = FindUnescapedChar(text, '@');
  if (at_pos == std::string::npos) {
    out.channel_name = AMStr::Strip(UnescapeBackticks(text, true));
    return out;
  }

  const std::string terminal_part =
      AMStr::Strip(UnescapeBackticks(text.substr(0, at_pos), true));
  if (!terminal_part.empty()) {
    out.terminal_name =
        AMDomain::host::HostService::NormalizeNickname(terminal_part);
  }
  out.channel_name = AMStr::Strip(UnescapeBackticks(text.substr(at_pos + 1), true));
  return out;
}

AMTokenType
ClassifyTerminalNameTokenType_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                               const std::string &nickname_raw,
                               const std::string &default_terminal_name) {
  if (!runtime) {
    return AMTokenType::NonexistentTerminalName;
  }
  const std::string key =
      AMStr::Strip(nickname_raw).empty() ? default_terminal_name : nickname_raw;
  return TerminalTokenTypeFromState(runtime->QueryTerminalNameState(key));
}

AMTokenType
ClassifyChannelTargetTokenType_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                                const ParsedTerminalChannelTarget_ &target,
                                bool allow_new) {
  if (!runtime) {
    return allow_new ? AMTokenType::InvalidNewChannelName
                     : AMTokenType::NonexistentChannelName;
  }
  return ChannelTokenTypeFromState(runtime->QueryChannelNameState(
      target.terminal_name, target.channel_name, allow_new));
}

AMTokenType
ClassifyPoolNameTokenType_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                           const std::string &nickname_raw) {
  const std::string nickname = AMStr::Strip(nickname_raw);
  if (nickname.empty() || !runtime) {
    return AMTokenType::NonexistentNickname;
  }
  return runtime->PoolExists(nickname) ? AMTokenType::Nickname
                                       : AMTokenType::NonexistentNickname;
}

AMTokenType ClassifyNewHostNicknameTokenType_(
    std::shared_ptr<ITokenAnalyzerRuntime> runtime,
    const std::string &nickname_raw) {
  const std::string nickname = AMStr::Strip(nickname_raw);
  ECM validate_rcm = AMDomain::host::HostService::ValidateFieldValue(
      AMDomain::host::ConRequest::Attr::nickname, nickname);
  if (!(validate_rcm)) {
    return AMTokenType::InvalidNewNickname;
  }
  if (AMDomain::host::HostService::IsLocalNickname(nickname)) {
    return AMTokenType::InvalidNewNickname;
  }
  if (runtime && runtime->HostExists(nickname)) {
    return AMTokenType::InvalidNewNickname;
  }
  return AMTokenType::ValidNewNickname;
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

AMTokenType ToPathTokenType_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return AMTokenType::File;
  case PathType::DIR:
    return AMTokenType::Dir;
  case PathType::SYMLINK:
    return AMTokenType::Symlink;
  default:
    return AMTokenType::Special;
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

std::vector<std::string>
BuildTokenTexts_(const std::string &input,
                 const std::vector<AMInterface::parser::model::RawToken>
                     &tokens) {
  std::vector<std::string> texts = {};
  texts.reserve(tokens.size());
  for (const auto &token : tokens) {
    texts.push_back(
        input.substr(token.content_start, token.content_end - token.content_start));
  }
  return texts;
}

void InitializeTokenTypes_(
    std::vector<AMInterface::parser::model::RawToken> &tokens) {
  for (auto &token : tokens) {
    token.type = token.quoted ? AMTokenType::String : AMTokenType::Common;
  }
}

CommandScanResult_ ScanCommandPrefix_(
    const CommandNode *command_tree,
    std::vector<AMInterface::parser::model::RawToken> &tokens,
    const std::vector<std::string> &texts) {
  CommandScanResult_ result = {};
  if (!command_tree) {
    return result;
  }

  bool parsing = true;
  for (size_t idx = 0; idx < tokens.size(); ++idx) {
    auto &token = tokens[idx];
    if (token.quoted) {
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
        token.type = AMTokenType::Module;
        result.command_path = text;
        result.node = command_tree->FindNode(result.command_path);
        result.command_tokens = idx + 1;
        continue;
      }
      if (command_tree->IsTopCommand(text)) {
        token.type = AMTokenType::Command;
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
          !IsVarShortcutDefineToken_(text);
      if (should_mark_illegal) {
        token.type = AMTokenType::IllegalCommand;
      }
      parsing = false;
      continue;
    }

    if (result.node && result.node->subcommands.contains(text)) {
      token.type = AMTokenType::Command;
      result.command_path += " " + text;
      result.node = command_tree->FindNode(result.command_path);
      result.command_tokens = idx + 1;
      if (!result.node || result.node->subcommands.empty()) {
        parsing = false;
      }
      continue;
    }

    if (result.node && !result.node->subcommands.empty() &&
        !StartsWithLongOption_(text) && !StartsWithShortOption_(text)) {
      token.type = AMTokenType::IllegalCommand;
    }
    parsing = false;
  }

  return result;
}

void MarkIllegalCommandGaps_(
    const CommandNode *command_tree,
    std::vector<AMInterface::parser::model::RawToken> &tokens,
    const std::vector<std::string> &texts) {
  if (!command_tree) {
    return;
  }

  std::vector<size_t> legal_indexes = {};
  legal_indexes.reserve(tokens.size());
  const CommandNode *scan_node = nullptr;
  std::string scan_path = {};

  for (size_t idx = 0; idx < tokens.size(); ++idx) {
    if (tokens[idx].quoted) {
      continue;
    }

    const std::string &text = texts[idx];
    if (text.empty()) {
      continue;
    }

    if (scan_path.empty()) {
      if (command_tree->IsModule(text)) {
        legal_indexes.push_back(idx);
        scan_path = text;
        scan_node = command_tree->FindNode(scan_path);
        continue;
      }
      if (command_tree->IsTopCommand(text)) {
        legal_indexes.push_back(idx);
        scan_path = text;
        scan_node = command_tree->FindNode(scan_path);
        continue;
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
      if (tokens[idx].quoted || tokens[idx].type != AMTokenType::Common) {
        continue;
      }
      if (IsVarShortcutDefineToken_(texts[idx])) {
        continue;
      }
      tokens[idx].type = AMTokenType::IllegalCommand;
    }
    segment_begin = legal_index + 1;
  }
}

void MarkOptions_(std::vector<AMInterface::parser::model::RawToken> &tokens,
                  const std::vector<std::string> &texts,
                  const CommandNode *node) {
  if (!node) {
    return;
  }

  for (size_t idx = 0; idx < tokens.size(); ++idx) {
    auto &token = tokens[idx];
    if (token.quoted || token.type != AMTokenType::Common) {
      continue;
    }
    if (IsValidOptionToken(texts[idx], node)) {
      token.type = AMTokenType::Option;
    }
  }
}

RuntimeContext_ BuildRuntimeContext_(
    std::shared_ptr<ITokenAnalyzerRuntime> runtime) {
  RuntimeContext_ context = {};
  context.current_client = runtime ? runtime->CurrentClient() : nullptr;
  context.current_nickname =
      runtime ? runtime->CurrentNickname() : std::string("local");
  if (context.current_nickname.empty()) {
    context.current_nickname = "local";
  }
  return context;
}

void ConsumePositionalArg_(ArgSemanticState_ &state, bool positional_consumed) {
  if (positional_consumed) {
    ++state.arg_index;
  }
}

std::optional<AMCommandArgSemantic>
ConsumePendingOptionValue_(ArgSemanticState_ &state) {
  if (!state.pending_value_rule.has_value()) {
    return std::nullopt;
  }

  const AMCommandArgSemantic semantic = state.pending_value_rule->semantic;
  ++state.pending_value_index;
  if (!state.pending_value_rule->repeat_tail &&
      state.pending_value_index >= state.pending_value_rule->value_count) {
    state.pending_value_rule.reset();
    state.pending_value_index = 0;
  }
  return semantic;
}

void SetPendingOptionValue_(ArgSemanticState_ &state,
                            const CommandNode::OptionValueRule &rule,
                            size_t consumed) {
  if (!rule.repeat_tail && consumed >= rule.value_count) {
    state.pending_value_rule.reset();
    state.pending_value_index = 0;
    return;
  }
  state.pending_value_rule = rule;
  state.pending_value_index = consumed;
}

TokenSemanticHint_ ResolveTokenSemanticHint_(
    const CommandNode *command_tree, const std::string &command_path,
    const AMInterface::parser::model::RawToken &token,
    const std::string &raw_text, ArgSemanticState_ &state) {
  TokenSemanticHint_ hint = {};
  hint.option_value_token = state.pending_value_rule.has_value();
  hint.semantic = ConsumePendingOptionValue_(state);

  if (!hint.semantic.has_value() && command_tree && !command_path.empty() &&
      !token.quoted) {
    if (StartsWithLongOption_(raw_text)) {
      hint.option_definition = true;
      const size_t eq_pos = raw_text.find('=');
      const std::string option_name =
          eq_pos == std::string::npos ? raw_text : raw_text.substr(0, eq_pos);
      const auto rule =
          command_tree->ResolveOptionValueRule(command_path, option_name, '\0', 0);
      if (rule.has_value()) {
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
        if (cidx + 1 < body.size()) {
          SetPendingOptionValue_(state, *rule, 1);
        } else {
          SetPendingOptionValue_(state, *rule, 0);
        }
        break;
      }
    }
  }

  if (!hint.option_value_token && !hint.semantic.has_value() &&
      !hint.option_definition && command_tree && !command_path.empty()) {
    hint.positional_rule_exists =
        command_tree->HasPositionalRule(command_path, state.arg_index);
    hint.semantic =
        command_tree->ResolvePositionalSemantic(command_path, state.arg_index);
    hint.positional_consumed = true;
    return hint;
  }

  if (!hint.option_definition && !hint.option_value_token) {
    hint.positional_consumed = true;
  }
  return hint;
}

bool TryClassifyIllegalPositionalToken_(
    AMInterface::parser::model::RawToken &token, const TokenSemanticHint_ &hint,
    const ClassificationContext_ &context, ArgSemanticState_ &state) {
  if (token.type != AMTokenType::Common || !hint.positional_consumed ||
      hint.option_value_token || hint.option_definition ||
      !context.command_tree || context.command.command_path.empty() ||
      hint.semantic.has_value() || hint.positional_rule_exists) {
    return false;
  }

  token.type = AMTokenType::IllegalCommand;
  ConsumePositionalArg_(state, hint.positional_consumed);
  return true;
}

bool TryClassifySemanticDrivenToken_(
    AMInterface::parser::model::RawToken &token, const std::string &raw_text,
    const std::string &unescaped_text, const TokenSemanticHint_ &hint,
    const ClassificationContext_ &context, ArgSemanticState_ &state) {
  if (token.type != AMTokenType::Common || !hint.semantic.has_value()) {
    return false;
  }

  switch (*hint.semantic) {
  case AMCommandArgSemantic::HostNicknameNew: {
    const bool is_sftp_or_ftp =
        (context.command.command_path == "sftp" ||
         context.command.command_path == "ftp");
    const bool is_user_at_host =
        FindUnescapedChar(raw_text, '@') != std::string::npos;
    if (!is_sftp_or_ftp || !is_user_at_host) {
      token.type = ClassifyNewHostNicknameTokenType_(context.runtime,
                                                     unescaped_text);
    }
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  }
  case AMCommandArgSemantic::HostAttr: {
    state.active_host_set_field = std::nullopt;
    const auto parsed_field =
        AMDomain::host::HostService::ParseEditableHostSetField(unescaped_text);
    if (parsed_field.has_value()) {
      token.type = AMTokenType::BuiltinArg;
      if (context.command.command_path == "host set") {
        state.active_host_set_field = parsed_field.value();
      }
    } else {
      token.type = AMTokenType::NonexistentBuiltinArg;
    }
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  }
  case AMCommandArgSemantic::TaskId:
    token.type = AMTokenType::BuiltinArg;
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  case AMCommandArgSemantic::HostAttrValue: {
    if (!state.active_host_set_field.has_value()) {
      token.type = AMTokenType::InvalidValue;
    } else {
      const ECM validate_rcm =
          AMDomain::host::HostService::ValidateEditableHostSetFieldValue(
              state.active_host_set_field.value(), unescaped_text);
      token.type =
          (validate_rcm) ? AMTokenType::ValidValue : AMTokenType::InvalidValue;
    }
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  }
  case AMCommandArgSemantic::HostNickname:
  case AMCommandArgSemantic::ClientName:
    token.type = ClassifyNicknameTokenType(context.runtime, unescaped_text);
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  case AMCommandArgSemantic::PoolName:
    token.type = ClassifyPoolNameTokenType_(context.runtime, unescaped_text);
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  case AMCommandArgSemantic::TerminalName:
    token.type = ClassifyTerminalNameTokenType_(
        context.runtime, unescaped_text, context.runtime_context.current_nickname);
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  case AMCommandArgSemantic::ChannelTargetExisting:
  case AMCommandArgSemantic::ChannelTargetNew:
  case AMCommandArgSemantic::SshChannelTarget: {
    const ParsedTerminalChannelTarget_ target = ParseTerminalChannelTarget_(
        raw_text, context.runtime_context.current_nickname);
    const bool allow_new =
        (*hint.semantic == AMCommandArgSemantic::ChannelTargetNew ||
         *hint.semantic == AMCommandArgSemantic::SshChannelTarget);
    token.type =
        ClassifyChannelTargetTokenType_(context.runtime, target, allow_new);
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  }
  case AMCommandArgSemantic::VarZone:
    token.type = ClassifyVarZoneTokenType(context.runtime, unescaped_text);
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  case AMCommandArgSemantic::ShellCmd:
    token.type = AMTokenType::ShellCmd;
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  default:
    return false;
  }
}

bool TryClassifyVarReferenceToken_(
    AMInterface::parser::model::RawToken &token, const std::string &raw_text,
    const TokenSemanticHint_ &hint, std::shared_ptr<ITokenAnalyzerRuntime> runtime,
    ArgSemanticState_ &state) {
  if (token.type != AMTokenType::Common) {
    return false;
  }

  AMDomain::var::VarRef ref = {};
  if (!AMDomain::var::ParseVarToken(raw_text, &ref) || !ref.valid ||
      ref.varname.empty()) {
    return false;
  }

  if (ref.explicit_domain && runtime) {
    auto scoped = runtime->GetVar(ref.domain, ref.varname);
    token.type = (scoped.rcm) ? AMTokenType::VarName : AMTokenType::VarNameMissing;
  } else {
    token.type = VarNameTypeFor(runtime, ref.varname);
  }
  ConsumePositionalArg_(state, hint.positional_consumed);
  return true;
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
    if (IsLocalNickname(prefix)) {
      target.explicit_local = true;
      target.nickname_for_cfg = "local";
      target.nickname_for_lookup = "local";
    } else if (!prefix.empty()) {
      target.nickname_for_cfg = prefix;
      target.nickname_for_lookup = prefix;
    }
    return target;
  }

  if (IsLocalNickname(current_nickname)) {
    target.nickname_for_cfg = "local";
    target.nickname_for_lookup = "local";
  }
  return target;
}

AMDomain::client::ClientHandle ResolvePathClient_(
    std::shared_ptr<ITokenAnalyzerRuntime> runtime,
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

bool TryClassifyPathLikeToken_(
    AMInterface::parser::model::RawToken &token, const std::string &raw_text,
    const std::string &unescaped_text, const TokenSemanticHint_ &hint,
    const ClassificationContext_ &context, ArgSemanticState_ &state) {
  if (token.type != AMTokenType::Common) {
    return false;
  }

  const size_t at_pos = FindUnescapedChar(raw_text, '@');
  const bool has_unescaped_at = at_pos != std::string::npos;
  const bool force_path =
      hint.semantic.has_value() && IsPathSemantic_(*hint.semantic);
  const bool terminal_channel_semantic =
      hint.semantic.has_value() && IsTerminalChannelSemantic_(*hint.semantic);
  const bool has_clear_path_sign =
      has_unescaped_at || HasClearPathSign(unescaped_text, true);

  if (force_path && !has_clear_path_sign) {
    const AMTokenType nick_type =
        ClassifyNicknameTokenType(context.runtime, unescaped_text);
    if (nick_type == AMTokenType::Nickname ||
        nick_type == AMTokenType::DisconnectedNickname ||
        nick_type == AMTokenType::UnestablishedNickname) {
      token.type = nick_type;
      ConsumePositionalArg_(state, hint.positional_consumed);
      return true;
    }
  }

  const bool treat_as_path =
      !terminal_channel_semantic &&
      (force_path || has_clear_path_sign || IsPathLikeText(unescaped_text, true));
  if (!treat_as_path) {
    return false;
  }

  const PathTarget_ target =
      ResolvePathTarget_(raw_text, context.runtime_context.current_nickname);
  ITokenAnalyzerRuntime::PromptPathOptions profile = {};
  if (context.runtime) {
    profile = context.runtime->ResolvePromptPathOptions(target.nickname_for_cfg);
  }
  if (!profile.highlight_enable) {
    token.type = AMTokenType::Path;
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  }

  const AMDomain::client::ClientHandle path_client =
      ResolvePathClient_(context.runtime, context.runtime_context, target);
  if (!context.runtime || !path_client) {
    token.type = AMTokenType::Nonexistentpath;
    ConsumePositionalArg_(state, hint.positional_consumed);
    return true;
  }

  const std::string path_part_unescaped =
      UnescapeBackticks(target.path_part_raw, true);
  const std::string path_part_resolved =
      context.runtime->SubstitutePathLike(path_part_unescaped);
  const std::string abs_path =
      context.runtime->BuildPath(path_client, path_part_resolved);
  const int timeout_ms = ToClientTimeoutMs_(profile.highlight_timeout_ms, 1000);

  auto stat_result = context.runtime->StatPath(path_client, abs_path, timeout_ms);
  if ((stat_result.rcm)) {
    token.type = ToPathTokenType_(stat_result.data.type);
  } else if (stat_result.rcm.code == EC::FileNotExist ||
             stat_result.rcm.code == EC::PathNotExist) {
    token.type = AMTokenType::Nonexistentpath;
  } else {
    token.type = AMTokenType::Special;
  }
  ConsumePositionalArg_(state, hint.positional_consumed);
  return true;
}

} // namespace

std::vector<AMInterface::parser::model::RawToken> SemanticAnalyzer::Classify(
    const std::string &input,
    const std::vector<AMInterface::parser::model::RawToken> &split_tokens)
    const {
  std::vector<AMInterface::parser::model::RawToken> tokens = split_tokens;
  const std::vector<std::string> texts = BuildTokenTexts_(input, tokens);
  InitializeTokenTypes_(tokens);

  ClassificationContext_ context = {};
  context.command_tree = command_tree_;
  context.runtime = runtime_;
  context.command = ScanCommandPrefix_(command_tree_, tokens, texts);
  MarkIllegalCommandGaps_(command_tree_, tokens, texts);
  MarkOptions_(tokens, texts, context.command.node);
  context.runtime_context = BuildRuntimeContext_(runtime_);

  ArgSemanticState_ state = {};
  for (size_t idx = 0; idx < tokens.size(); ++idx) {
    auto &token = tokens[idx];
    if (idx < context.command.command_tokens) {
      continue;
    }

    const std::string &raw_text = texts[idx];
    if (raw_text.empty()) {
      continue;
    }

    const TokenSemanticHint_ hint = ResolveTokenSemanticHint_(
        command_tree_, context.command.command_path, token, raw_text, state);

    if (token.quoted) {
      ConsumePositionalArg_(state, hint.positional_consumed);
      continue;
    }

    if ((token.type == AMTokenType::Option || hint.option_definition) &&
        !hint.semantic.has_value()) {
      continue;
    }

    const std::string unescaped_text = UnescapeBackticks(raw_text, true);
    if (TryClassifyIllegalPositionalToken_(token, hint, context, state)) {
      continue;
    }
    if (TryClassifySemanticDrivenToken_(token, raw_text, unescaped_text, hint,
                                        context, state)) {
      continue;
    }
    if (TryClassifyVarReferenceToken_(token, raw_text, hint, runtime_, state)) {
      continue;
    }
    if (TryClassifyPathLikeToken_(token, raw_text, unescaped_text, hint, context,
                                  state)) {
      continue;
    }

    ConsumePositionalArg_(state, hint.positional_consumed);
  }

  return tokens;
}

} // namespace AMInterface::parser::semantic
