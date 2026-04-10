#include "interface/token_analyser/TokenTypeAnalyzer.hpp"

#include "domain/var/VarDomainService.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/token_analyser/highlight/HighlightFormatter.hpp"
#include "interface/token_analyser/lexer/ShellTokenLexer.hpp"
#include "interface/token_analyser/semantic/SemanticAnalyzer.hpp"
#include <unordered_map>

namespace AMInterface::parser {
namespace {
using TokenCacheValue = std::vector<TokenTypeAnalyzer::AMToken>;
std::unordered_map<std::string, TokenCacheValue> g_split_token_cache = {};

/** Parse a variable token at one position within one limit. */
bool ParseVarTokenAt_(const std::string &input, size_t pos, size_t limit,
                      size_t *out_end) {
  size_t parsed_end = 0;
  AMDomain::var::VarRef ref = {};
  if (!AMDomain::var::ParseVarRefAt(input, pos, limit, true, true, &parsed_end,
                                    &ref) ||
      !ref.valid) {
    return false;
  }
  if (out_end) {
    *out_end = parsed_end;
  }
  return true;
}

/** Validate full token as variable reference and optionally extract varname. */
bool ParseVarTokenText_(const std::string &token, std::string *out_name) {
  AMDomain::var::VarRef ref = {};
  if (!AMDomain::var::ParseVarToken(token, &ref) || !ref.valid ||
      ref.varname.empty()) {
    return false;
  }
  if (out_name) {
    *out_name = ref.varname;
  }
  return true;
}

/** Assign overlap resolution priority per token type. */
int PriorityForType_(AMTokenType type) {
  switch (type) {
  case AMTokenType::IllegalCommand:
    return 200;
  case AMTokenType::EscapeSign:
    return 100;
  case AMTokenType::BangSign:
    return 99;
  case AMTokenType::ShellCmd:
    return 98;
  case AMTokenType::EqualSign:
    return 95;
  case AMTokenType::VarValue:
    return 90;
  case AMTokenType::VarName:
  case AMTokenType::VarNameMissing:
  case AMTokenType::ValidValue:
  case AMTokenType::InvalidValue:
  case AMTokenType::ValidNewNickname:
  case AMTokenType::InvalidNewNickname:
  case AMTokenType::DollarSign:
  case AMTokenType::LeftBraceSign:
  case AMTokenType::RightBraceSign:
  case AMTokenType::ColonSign:
    return 80;
  case AMTokenType::AtSign:
  case AMTokenType::Nickname:
  case AMTokenType::DisconnectedNickname:
  case AMTokenType::UnestablishedNickname:
  case AMTokenType::NonexistentNickname:
  case AMTokenType::TerminalName:
  case AMTokenType::DisconnectedTerminalName:
  case AMTokenType::UnestablishedTerminalName:
  case AMTokenType::NonexistentTerminalName:
  case AMTokenType::ChannelName:
  case AMTokenType::DisconnectedChannelName:
  case AMTokenType::NonexistentChannelName:
  case AMTokenType::ValidNewChannelName:
  case AMTokenType::InvalidNewChannelName:
    return 70;
  case AMTokenType::BuiltinArg:
  case AMTokenType::NonexistentBuiltinArg:
    return 65;
  case AMTokenType::Option:
    return 60;
  case AMTokenType::Module:
  case AMTokenType::Command:
    return 50;
  case AMTokenType::Path:
  case AMTokenType::Nonexistentpath:
  case AMTokenType::File:
  case AMTokenType::Dir:
  case AMTokenType::Symlink:
  case AMTokenType::Special:
    return 40;
  case AMTokenType::String:
    return 20;
  case AMTokenType::Common:
  default:
    return 0;
  }
}

/** Resolve variable-name highlight type with current/public-domain fallback. */
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

/** Validate token against option set for one command node. */
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

void TokenTypeAnalyzer::RefreshNicknameCache() {}

void TokenTypeAnalyzer::PromptHighlighter_(ic_highlight_env_t *henv,
                                           const char *input, void *arg) {
  if (!henv || !input) {
    return;
  }
  auto *analyzer = static_cast<TokenTypeAnalyzer *>(arg);
  if (!analyzer) {
    return;
  }
  std::string formatted = {};
  analyzer->HighlightFormatted(input, &formatted);
  if (formatted.empty()) {
    return;
  }
  ic_highlight_formatted(henv, input, formatted.c_str());
}

void TokenTypeAnalyzer::ClearTokenCache() { g_split_token_cache.clear(); }

std::vector<TokenTypeAnalyzer::AMToken>
TokenTypeAnalyzer::SplitToken(const std::string &input) const {
  auto cache_it = g_split_token_cache.find(input);
  if (cache_it != g_split_token_cache.end()) {
    return cache_it->second;
  }
  std::vector<AMToken> tokens = lexer::ShellTokenLexer::Split(input);
  g_split_token_cache[input] = tokens;
  return tokens;
}

std::vector<TokenTypeAnalyzer::AMToken>
TokenTypeAnalyzer::TokenizeStyle(const std::string &input) {
  semantic::SemanticAnalyzer classifier(command_tree_, runtime_);
  return classifier.Classify(input, SplitToken(input));
}

bool TokenTypeAnalyzer::ParseVarTokenAt(const std::string &input, size_t pos,
                                        size_t limit, size_t *out_end) const {
  return ParseVarTokenAt_(input, pos, limit, out_end);
}

bool TokenTypeAnalyzer::ParseVarTokenText(const std::string &token,
                                          std::string *out_name) const {
  return ParseVarTokenText_(token, out_name);
}

AMTokenType TokenTypeAnalyzer::VarNameTypeFor(const std::string &name) const {
  return VarNameTypeFor_(runtime_, name);
}

bool TokenTypeAnalyzer::IsValidOptionToken(const std::string &token,
                                           const CommandNode *node) const {
  return IsValidOptionToken_(token, node);
}

int TokenTypeAnalyzer::PriorityForType(AMTokenType type) const {
  return PriorityForType_(type);
}

void TokenTypeAnalyzer::HighlightFormatted(const std::string &input,
                                           std::string *formatted) {
  semantic::SemanticAnalyzer classifier(command_tree_, runtime_);
  auto classified_tokens = classifier.Classify(input, SplitToken(input));
  highlight::FormatHighlightedInput(input, classified_tokens, command_tree_,
                                    runtime_, formatted);
}

} // namespace AMInterface::parser
