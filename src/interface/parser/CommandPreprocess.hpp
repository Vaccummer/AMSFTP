#pragma once
#include "foundation/core/DataClass.hpp"
#include <string>
#include <vector>

namespace AMInterface::var {
class VarInterfaceService;
}

namespace AMInterface::parser {

class TokenTypeAnalyzer;

struct ResolvedCharMeta {
  bool escaped = false;
  char escaped_from = '\0';
};

struct ResolvedStringMeta {
  std::string value = {};
  std::vector<ResolvedCharMeta> chars = {};
};

class AMInputPreprocess : public NonCopyableNonMovable {
public:
  AMInputPreprocess(
      AMInterface::var::VarInterfaceService &var_interface_service,
      TokenTypeAnalyzer &token_type_analyzer)
      : var_interface_service_(var_interface_service),
        token_type_analyzer_(token_type_analyzer) {}
  ~AMInputPreprocess() override = default;

  /**
   * @brief Split interactive command text into CLI11 argument tokens.
   *
   * Quote wrappers are removed, and backtick escapes are restored for every
   * escaped character except `$` (`` `$`` is preserved for post-parse var
   * substitution). Quoted literals that start with '-' are preserved as
   * positionals by inserting `--` before them during preprocess.
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
  [[nodiscard]] ECMData<std::vector<std::string>>
  Preprocess(const std::string &input) const;

  /**
   * @brief Resolve backtick escapes and emit per-character metadata.
   *
   * This helper is used by downstream token consumers that need to distinguish
   * literal symbols from escaped symbols (for example `@` in path tokens).
   * Current escape targets: `$`, `@`, '`', '"', '\''.
   */
  [[nodiscard]] static ECMData<ResolvedStringMeta>
  ResolveStringMeta(const std::string &input);

  /**
   * @brief Rewrite `$` shortcut tokens into canonical `var` commands.
   */
  bool RewriteVarShortcutTokens(std::vector<std::string> *tokens) const;

private:
  AMInterface::var::VarInterfaceService &var_interface_service_;
  TokenTypeAnalyzer &token_type_analyzer_;
};

} // namespace AMInterface::parser
