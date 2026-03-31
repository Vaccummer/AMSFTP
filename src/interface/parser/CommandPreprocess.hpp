#pragma once
#include "foundation/core/DataClass.hpp"
#include <string>
#include <vector>

namespace AMInterface::var {
class VarInterfaceService;
}

namespace AMInterface::parser {

class TokenTypeAnalyzer;

class AMInputPreprocess : public NonCopyableNonMovable {
public:
  AMInputPreprocess(AMInterface::var::VarInterfaceService &var_interface_service,
                    TokenTypeAnalyzer &token_type_analyzer)
      : var_interface_service_(var_interface_service),
        token_type_analyzer_(token_type_analyzer) {}
  ~AMInputPreprocess() override = default;

  /**
   * @brief Split interactive command text into CLI11 argument tokens.
   *
   * Quote wrappers are removed, and backtick escapes are restored for every
   * escaped character except `$` (`` `$`` is preserved for post-parse var
   * substitution).
   */
  std::vector<std::string> SplitCliTokens(const std::string &input) const;

  /**
   * @brief Preprocess one interactive input line before CLI11 parse.
   *
   * Pipeline priority:
   * 1) `!cmd` shell shorthand -> `{"cmd", "<cmd>"}`
   * 2) var-define shorthand (`$x=...`, `${:x}=...`, `${zone:x}=...`) ->
   *    `{"var", "def", "<lhs>", "<value>"}`
   * 3) fallback tokenization via SplitCliTokens.
   */
  ECMData<std::vector<std::string>>
  Preprocess(const std::string &input) const;

  /**
   * @brief Rewrite `$` shortcut tokens into canonical `var` commands.
   */
  bool RewriteVarShortcutTokens(std::vector<std::string> *tokens) const;

private:
  AMInterface::var::VarInterfaceService &var_interface_service_;
  TokenTypeAnalyzer &token_type_analyzer_;
};

} // namespace AMInterface::parser
