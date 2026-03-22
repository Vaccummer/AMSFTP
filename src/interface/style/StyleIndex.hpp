#pragma once

#include <cstdint>

namespace AMInterface::style {
enum class StyleIndex : uint8_t {
  None = 0,
  Protocol,
  Abort,
  Common,
  Module,
  Command,
  IllegalCommand,
  Option,
  String,
  PublicVarname,
  PrivateVarname,
  NonexistentVarname,
  VarValue,
  Nickname,
  UnestablishedNickname,
  NonexistentNickname,
  ValidNewNickname,
  InvalidNewNickname,
  BuiltinArg,
  NonexistentBuiltinArg,
  Username,
  AtSign,
  DollarSign,
  EqualSign,
  EscapedSign,
  BangSign,
  ShellCmd,
  Cwd,
  Number,
  Timestamp,
  PathLike,
  PromptUn,
  PromptAt,
  PromptHn,
  PromptEn,
  PromptNn,
  PromptCwd,
  PromptDs,
  PromptWhite,
  Error
};
} // namespace AMInterface::style
