#include "interface/token_analyser/semantic/SemanticAnalyzer.hpp"

#include "domain/host/HostDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntime.hpp"
#include "interface/token_analyser/shared/InputTextRules.hpp"
#include <algorithm>
#include <limits>
#include <optional>

namespace AMInterface::parser::semantic {
namespace {

bool IsLocalNickname_(const std::string &nickname) {
  return AMDomain::host::HostService::IsLocalNickname(nickname);
}

size_t FindUnescapedChar_(const std::string &text, char target) {
  return shared::FindUnescapedChar(text, target);
}

std::string UnescapeBackticks_(const std::string &text) {
  return shared::UnescapeBackticks(text, true);
}

bool IsPathLikeText_(const std::string &text) {
  return shared::IsPathLikeText(text, true);
}

bool HasClearPathSign_(const std::string &text) {
  return shared::HasClearPathSign(text, true);
}

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

AMTokenType
ClassifyNicknameTokenType_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                           const std::string &nickname_raw) {
  const std::string nickname = AMStr::Strip(nickname_raw);
  if (IsLocalNickname_(nickname)) {
    return AMTokenType::Nickname;
  }
  if (!runtime) {
    return AMTokenType::NonexistentNickname;
  }
  if (auto client = runtime->GetClient(nickname); client) {
    const auto state = client->ConfigPort().GetState();
    if (state.data.status == AMDomain::client::ClientStatus::OK) {
      return AMTokenType::Nickname;
    }
    return AMTokenType::DisconnectedNickname;
  }
  if (runtime->HostExists(nickname)) {
    return AMTokenType::UnestablishedNickname;
  }
  return AMTokenType::NonexistentNickname;
}

AMTokenType
ClassifyNewHostNicknameTokenType_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
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

AMTokenType ClassifyVarZoneTokenType_(
    std::shared_ptr<ITokenAnalyzerRuntime> runtime,
    const std::string &zone_raw) {
  const std::string zone = AMStr::Strip(zone_raw);
  if (zone.empty()) {
    return AMTokenType::NonexistentNickname;
  }
  if (zone == AMDomain::var::kPublic) {
    return AMTokenType::Nickname;
  }
  if (!runtime) {
    return AMTokenType::NonexistentNickname;
  }
  if (runtime->HasVarDomain(zone)) {
    return AMTokenType::Nickname;
  }
  if (runtime->HostExists(zone)) {
    return AMTokenType::UnestablishedNickname;
  }
  return AMTokenType::NonexistentNickname;
}

bool IsVarShortcutDefineToken_(const std::string &raw_text) {
  if (raw_text.size() >= 2 && raw_text[0] == '`' && raw_text[1] == '$') {
    return false;
  }
  const std::string text = UnescapeBackticks_(raw_text);
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

AMTokenType VarNameTypeFor_(std::shared_ptr<ITokenAnalyzerRuntime> runtime,
                            const std::string &name) {
  if (!runtime) {
    return AMTokenType::VarNameMissing;
  }
  const std::string domain = runtime->CurrentVarDomain();
  auto scoped = runtime->GetVar(domain, name);
  if ((scoped.rcm)) {
    return AMTokenType::VarName;
  }
  auto pub = runtime->GetVar(AMDomain::var::kPublic, name);
  return (pub.rcm) ? AMTokenType::VarName : AMTokenType::VarNameMissing;
}

bool IsValidOptionToken_(const std::string &token, const CommandNode *node) {
  if (!node || token.size() < 2 || token[0] != '-') {
    return false;
  }
  if (token.rfind("--", 0) == 0) {
    std::string name = token;
    const size_t eq = token.find('=');
    if (eq != std::string::npos) {
      name = token.substr(0, eq);
    }
    return node->long_options.find(name) != node->long_options.end();
  }
  if (token.size() < 2) {
    return false;
  }
  for (size_t i = 1; i < token.size(); ++i) {
    if (node->short_options.find(token[i]) == node->short_options.end()) {
      return false;
    }
  }
  return true;
}

} // namespace

std::vector<AMInterface::parser::model::RawToken>
SemanticAnalyzer::Classify(
    const std::string &input,
    const std::vector<AMInterface::parser::model::RawToken> &split_tokens) const {
  std::vector<AMInterface::parser::model::RawToken> tokens = split_tokens;
  std::vector<std::string> texts = {};
  texts.reserve(tokens.size());
  for (const auto &token : tokens) {
    texts.push_back(input.substr(token.content_start,
                                 token.content_end - token.content_start));
  }

  for (auto &token : tokens) {
    token.type = token.quoted ? AMTokenType::String : AMTokenType::Common;
  }

  const CommandNode *node = nullptr;
  std::string command_path = {};
  size_t command_tokens = 0;
  if (command_tree_) {
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

      if (command_path.empty()) {
        if (command_tree_->IsModule(text)) {
          token.type = AMTokenType::Module;
          command_path = text;
          node = command_tree_->FindNode(command_path);
          command_tokens = idx + 1;
          continue;
        }
        if (command_tree_->IsTopCommand(text)) {
          token.type = AMTokenType::Command;
          command_path = text;
          node = command_tree_->FindNode(command_path);
          command_tokens = idx + 1;
          if (!node || node->subcommands.empty()) {
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

      if (node && node->subcommands.find(text) != node->subcommands.end()) {
        token.type = AMTokenType::Command;
        command_path += " " + text;
        node = command_tree_->FindNode(command_path);
        command_tokens = idx + 1;
        if (!node || node->subcommands.empty()) {
          parsing = false;
        }
        continue;
      }

      // Current command node still expects a subcommand, but token is neither
      // a known subcommand nor an option token. Mark it as illegal command.
      if (node && !node->subcommands.empty() && !StartsWithLongOption_(text) &&
          !StartsWithShortOption_(text)) {
        token.type = AMTokenType::IllegalCommand;
      }
      parsing = false;
    }
  }

  if (command_tree_) {
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
        if (command_tree_->IsModule(text)) {
          legal_indexes.push_back(idx);
          scan_path = text;
          scan_node = command_tree_->FindNode(scan_path);
          continue;
        }
        if (command_tree_->IsTopCommand(text)) {
          legal_indexes.push_back(idx);
          scan_path = text;
          scan_node = command_tree_->FindNode(scan_path);
          continue;
        }
        continue;
      }

      if (scan_node &&
          scan_node->subcommands.find(text) != scan_node->subcommands.end()) {
        legal_indexes.push_back(idx);
        scan_path += " " + text;
        scan_node = command_tree_->FindNode(scan_path);
      }
    }

    if (!legal_indexes.empty()) {
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
  }

  if (node) {
    for (size_t idx = 0; idx < tokens.size(); ++idx) {
      auto &token = tokens[idx];
      if (token.quoted || token.type != AMTokenType::Common) {
        continue;
      }
      if (IsValidOptionToken_(texts[idx], node)) {
        token.type = AMTokenType::Option;
      }
    }
  }

  AMDomain::client::ClientHandle current_client =
      runtime_ ? runtime_->CurrentClient() : nullptr;
  std::string current_nickname = "local";
  if (current_client) {
    current_nickname = current_client->ConfigPort().GetNickname();
    if (current_nickname.empty()) {
      current_nickname = "local";
    }
  }

  std::optional<CommandNode::OptionValueRule> pending_value_rule = std::nullopt;
  size_t pending_value_index = 0;
  std::optional<AMDomain::host::HostService::HostSetFieldRef>
      active_host_set_field = std::nullopt;
  auto consume_option_value = [&]() -> std::optional<AMCommandArgSemantic> {
    if (!pending_value_rule.has_value()) {
      return std::nullopt;
    }
    const AMCommandArgSemantic semantic = pending_value_rule->semantic;
    ++pending_value_index;
    if (!pending_value_rule->repeat_tail &&
        pending_value_index >= pending_value_rule->value_count) {
      pending_value_rule.reset();
      pending_value_index = 0;
    }
    return semantic;
  };
  auto set_pending_option_value = [&](const CommandNode::OptionValueRule &rule,
                                      size_t consumed) {
    if (!rule.repeat_tail && consumed >= rule.value_count) {
      pending_value_rule.reset();
      pending_value_index = 0;
      return;
    }
    pending_value_rule = rule;
    pending_value_index = consumed;
  };

  size_t arg_index = 0;
  for (size_t idx = 0; idx < tokens.size(); ++idx) {
    auto &token = tokens[idx];
    if (idx < command_tokens) {
      continue;
    }

    const std::string &raw_text = texts[idx];
    if (raw_text.empty()) {
      continue;
    }

    bool positional_consumed = false;
    bool option_definition = false;
    const bool option_value_token = pending_value_rule.has_value();
    std::optional<AMCommandArgSemantic> semantic_hint = consume_option_value();

    if (!semantic_hint.has_value() && command_tree_ && !command_path.empty() &&
        !token.quoted) {
      if (StartsWithLongOption_(raw_text)) {
        option_definition = true;
        const size_t eq_pos = raw_text.find('=');
        const std::string option_name =
            eq_pos == std::string::npos ? raw_text : raw_text.substr(0, eq_pos);
        const auto rule =
            command_tree_->ResolveOptionValueRule(command_path, option_name, '\0', 0);
        if (rule.has_value()) {
          if (eq_pos == std::string::npos) {
            set_pending_option_value(*rule, 0);
          } else if (eq_pos + 1 < raw_text.size()) {
            set_pending_option_value(*rule, 1);
          } else {
            set_pending_option_value(*rule, 0);
          }
        }
      } else if (StartsWithShortOption_(raw_text)) {
        option_definition = true;
        const std::string body = raw_text.substr(1);
        for (size_t cidx = 0; cidx < body.size(); ++cidx) {
          const auto rule =
              command_tree_->ResolveOptionValueRule(command_path, "", body[cidx], 0);
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
    }

    if (!option_value_token && !semantic_hint.has_value() && !option_definition &&
        command_tree_ && !command_path.empty()) {
      semantic_hint = command_tree_->ResolvePositionalSemantic(command_path, arg_index);
      positional_consumed = true;
    } else if (!option_definition && !option_value_token) {
      positional_consumed = true;
    }

    if (token.quoted) {
      if (positional_consumed) {
        ++arg_index;
      }
      continue;
    }

    if ((token.type == AMTokenType::Option || option_definition) &&
        !semantic_hint.has_value()) {
      continue;
    }

    const std::string unescaped_text = UnescapeBackticks_(raw_text);
    if (token.type == AMTokenType::Common && semantic_hint.has_value()) {
      if (*semantic_hint == AMCommandArgSemantic::HostNicknameNew) {
        const bool is_sftp_or_ftp = (command_path == "sftp" || command_path == "ftp");
        const bool is_user_at_host =
            FindUnescapedChar_(raw_text, '@') != std::string::npos;
        if (is_sftp_or_ftp && is_user_at_host) {
          if (positional_consumed) {
            ++arg_index;
          }
          continue;
        }
        token.type = ClassifyNewHostNicknameTokenType_(runtime_, unescaped_text);
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      if (*semantic_hint == AMCommandArgSemantic::HostAttr ||
          *semantic_hint == AMCommandArgSemantic::TaskId) {
        if (*semantic_hint == AMCommandArgSemantic::HostAttr) {
          active_host_set_field = std::nullopt;
          const auto parsed_field =
              AMDomain::host::HostService::ParseEditableHostSetField(
                  unescaped_text);
          if (parsed_field.has_value()) {
            token.type = AMTokenType::BuiltinArg;
            if (command_path == "host set") {
              active_host_set_field = parsed_field.value();
            }
          } else {
            token.type = AMTokenType::NonexistentBuiltinArg;
          }
        } else {
          token.type = AMTokenType::BuiltinArg;
        }
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      if (*semantic_hint == AMCommandArgSemantic::HostAttrValue) {
        if (!active_host_set_field.has_value()) {
          token.type = AMTokenType::InvalidValue;
        } else {
          const ECM validate_rcm =
              AMDomain::host::HostService::ValidateEditableHostSetFieldValue(
                  active_host_set_field.value(), unescaped_text);
          token.type =
              (validate_rcm) ? AMTokenType::ValidValue : AMTokenType::InvalidValue;
        }
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      if (*semantic_hint == AMCommandArgSemantic::HostNickname ||
          *semantic_hint == AMCommandArgSemantic::ClientName) {
        token.type = ClassifyNicknameTokenType_(runtime_, unescaped_text);
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      if (*semantic_hint == AMCommandArgSemantic::VarZone) {
        token.type = ClassifyVarZoneTokenType_(runtime_, unescaped_text);
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }

      if (*semantic_hint == AMCommandArgSemantic::ShellCmd) {
        token.type = AMTokenType::ShellCmd;
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }
    }

    AMDomain::var::VarRef ref = {};
    if (token.type == AMTokenType::Common &&
        AMDomain::var::ParseVarToken(raw_text, &ref) && ref.valid &&
        !ref.varname.empty()) {
      if (ref.explicit_domain && runtime_) {
        auto scoped = runtime_->GetVar(ref.domain, ref.varname);
        token.type =
            (scoped.rcm) ? AMTokenType::VarName : AMTokenType::VarNameMissing;
      } else {
        token.type = VarNameTypeFor_(runtime_, ref.varname);
      }
      if (positional_consumed) {
        ++arg_index;
      }
      continue;
    }

    const size_t at_pos = FindUnescapedChar_(raw_text, '@');
    const bool has_unescaped_at = at_pos != std::string::npos;
    const bool force_path =
        semantic_hint.has_value() && IsPathSemantic_(*semantic_hint);
    const bool has_clear_path_sign =
        has_unescaped_at || HasClearPathSign_(unescaped_text);

    if (token.type == AMTokenType::Common && force_path && !has_clear_path_sign) {
      const AMTokenType nick_type = ClassifyNicknameTokenType_(runtime_, unescaped_text);
      if (nick_type == AMTokenType::Nickname ||
          nick_type == AMTokenType::DisconnectedNickname ||
          nick_type == AMTokenType::UnestablishedNickname) {
        token.type = nick_type;
        if (positional_consumed) {
          ++arg_index;
        }
        continue;
      }
    }

    const bool treat_as_path =
        force_path || has_clear_path_sign || IsPathLikeText_(unescaped_text);
    if (!treat_as_path) {
      if (positional_consumed) {
        ++arg_index;
      }
      continue;
    }

    std::string nickname_for_cfg = current_nickname;
    std::string nickname_for_lookup = current_nickname;
    std::string path_part_raw = raw_text;
    bool explicit_target = false;
    bool explicit_local = false;

    if (!raw_text.empty() && raw_text.front() == '@') {
      explicit_target = true;
      explicit_local = true;
      nickname_for_cfg = "local";
      nickname_for_lookup = "local";
      path_part_raw = raw_text.substr(1);
    } else if (has_unescaped_at) {
      explicit_target = true;
      const std::string prefix_raw = raw_text.substr(0, at_pos);
      const std::string prefix = AMStr::Strip(UnescapeBackticks_(prefix_raw));
      path_part_raw = raw_text.substr(at_pos + 1);
      if (IsLocalNickname_(prefix)) {
        explicit_local = true;
        nickname_for_cfg = "local";
        nickname_for_lookup = "local";
      } else if (!prefix.empty()) {
        nickname_for_cfg = prefix;
        nickname_for_lookup = prefix;
      }
    } else if (IsLocalNickname_(current_nickname)) {
      nickname_for_cfg = "local";
      nickname_for_lookup = "local";
    }

    ITokenAnalyzerRuntime::PromptPathOptions profile = {};
    if (runtime_) {
      profile = runtime_->ResolvePromptPathOptions(nickname_for_cfg);
    }
    if (!profile.highlight_enable) {
      token.type = AMTokenType::Path;
      if (positional_consumed) {
        ++arg_index;
      }
      continue;
    }

    AMDomain::client::ClientHandle path_client = nullptr;
    if (runtime_) {
      if (explicit_target) {
        if (explicit_local) {
          path_client = runtime_->LocalClient();
        } else {
          path_client = runtime_->GetClient(nickname_for_lookup);
        }
      } else {
        path_client = current_client ? current_client : runtime_->LocalClient();
      }
    }

    if (!runtime_ || !path_client) {
      token.type = AMTokenType::Nonexistentpath;
      if (positional_consumed) {
        ++arg_index;
      }
      continue;
    }

    const std::string path_part_unescaped = UnescapeBackticks_(path_part_raw);
    const std::string path_part_resolved =
        runtime_->SubstitutePathLike(path_part_unescaped);
    const std::string abs_path = runtime_->BuildPath(path_client, path_part_resolved);
    const int timeout_ms = ToClientTimeoutMs_(profile.highlight_timeout_ms, 1000);

    auto stat_result = runtime_->StatPath(path_client, abs_path, timeout_ms);
    if ((stat_result.rcm)) {
      token.type = ToPathTokenType_(stat_result.data.type);
    } else if (stat_result.rcm.code == EC::FileNotExist ||
               stat_result.rcm.code == EC::PathNotExist) {
      token.type = AMTokenType::Nonexistentpath;
    } else {
      token.type = AMTokenType::Special;
    }

    if (positional_consumed) {
      ++arg_index;
    }
  }

  return tokens;
}

} // namespace AMInterface::parser::semantic


