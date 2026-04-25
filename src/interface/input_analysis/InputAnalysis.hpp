#pragma once

#include "interface/input_analysis/model/RawToken.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::parser {
enum class AMCommandArgSemantic;
class CommandNode;
} // namespace AMInterface::parser

namespace AMInterface::input {

enum class TokenShape {
  Plain = 0,
  Quoted,
  EscapeLike,
  VarLike,
  PathLike,
  AtStructuredLike,
  ShellBangLike,
  OptionLike,
};

enum class TokenRole {
  None = 0,
  Module,
  Command,
  Option,
  IllegalCommand,
  StringLiteral,
  ShellCommand,
  Nickname,
  TerminalName,
  BuiltinArg,
  ValidatedValue,
  VariableReference,
  VariableName,
  VariableZone,
  VariableValue,
  Path,
  FindPattern,
  AtSign,
  DollarSign,
  EqualSign,
  LeftBrace,
  RightBrace,
  ColonSign,
  EscapeSign,
  BangSign,
};

enum class TokenState {
  Neutral = 0,
  Valid,
  Invalid,
  Missing,
  Nonexistent,
  Disconnected,
  Unestablished,
  NewValid,
  NewInvalid,
};

enum class PathKind {
  None = 0,
  File,
  Directory,
  Symlink,
  Special,
  Nonexistent,
};

struct AnalyzedToken {
  model::RawToken raw = {};
  TokenShape shape = TokenShape::Plain;
  TokenRole role = TokenRole::None;
  TokenState state = TokenState::Neutral;
  TokenState qualifier_state = TokenState::Neutral;
  PathKind path_kind = PathKind::None;
  std::optional<AMInterface::parser::AMCommandArgSemantic> semantic_hint =
      std::nullopt;
  bool option_definition = false;
  bool option_value_token = false;
  bool positional_rule_exists = false;
  bool positional_consumed = false;
};

struct InputOptionValueRule {
  std::string long_option = {};
  char short_option = '\0';
  AMInterface::parser::AMCommandArgSemantic semantic = {};
  size_t value_count = 1;
  bool repeat_tail = false;
};

struct CommandContext {
  std::string module = {};
  std::string command_path = {};
  const AMInterface::parser::CommandNode *node = nullptr;
  size_t command_tokens = 0;
  size_t next_arg_index = 0;
  bool has_module = false;
  bool has_command = false;
  bool unknown_before_command = false;
  std::vector<std::string> options = {};
  std::vector<std::string> args = {};
  std::optional<InputOptionValueRule> pending_value_rule = std::nullopt;
  size_t pending_value_index = 0;
};

struct InputAnalysis {
  std::string input = {};
  std::vector<AnalyzedToken> tokens = {};
  CommandContext command = {};
};

} // namespace AMInterface::input
