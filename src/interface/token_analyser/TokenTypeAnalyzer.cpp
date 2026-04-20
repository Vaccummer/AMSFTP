#include "interface/token_analyser/TokenTypeAnalyzer.hpp"

#include "interface/token_analyser/highlight/HighlightFormatter.hpp"
#include "interface/token_analyser/lexer/ShellTokenLexer.hpp"
#include "interface/token_analyser/semantic/SemanticAnalyzer.hpp"

namespace AMInterface::parser {

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

void TokenTypeAnalyzer::ClearTokenCache() {
  auto cache = split_token_cache_.lock();
  cache->clear();
}

std::vector<TokenTypeAnalyzer::AMToken>
TokenTypeAnalyzer::SplitToken(const std::string &input) const {
  {
    auto cache = split_token_cache_.lock();
    auto cache_it = cache->find(input);
    if (cache_it != cache->end()) {
      return cache_it->second;
    }
  }

  std::vector<AMToken> tokens = lexer::ShellTokenLexer::Split(input);
  {
    auto cache = split_token_cache_.lock();
    auto [it, inserted] = cache->emplace(input, tokens);
    if (!inserted) {
      return it->second;
    }
  }
  return tokens;
}

void TokenTypeAnalyzer::HighlightFormatted(const std::string &input,
                                           std::string *formatted) {
  semantic::SemanticAnalyzer classifier(command_tree_, runtime_);
  auto classified_tokens = classifier.Classify(input, SplitToken(input));
  highlight::FormatHighlightedInput(input, classified_tokens, command_tree_,
                                    runtime_, formatted);
}

} // namespace AMInterface::parser
