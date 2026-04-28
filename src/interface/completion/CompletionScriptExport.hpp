#pragma once

#include "foundation/core/DataClass.hpp"
#include "interface/parser/CommandTree.hpp"

#include <cstddef>
#include <string>

namespace AMInterface::completion {

enum class CompletionScriptShell { Powershell5, Powershell7, Zsh, Bash };

CompletionScriptShell ParseCompletionScriptShell(const std::string &shell);

struct CompletionScriptExportRequest {
  const AMInterface::parser::CommandNode *command_tree = nullptr;
  CompletionScriptShell shell = CompletionScriptShell::Bash;
  std::string app_name;
  std::string out_dir;
  std::string cwd;
};

struct CompletionScriptExportResult {
  std::string output_path;
  std::string display_uri;
  size_t bytes = 0;
};

[[nodiscard]] ECMData<CompletionScriptExportResult>
ExportCompletionScript(const CompletionScriptExportRequest &request);

} // namespace AMInterface::completion
