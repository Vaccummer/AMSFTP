#include "interface/cli/ArgStruct/CompletionArgStruct.hpp"

#include "interface/cli/CLIServices.hpp"
#include "interface/completion/CompletionScriptExport.hpp"

#include <iostream>

namespace AMInterface::cli {

void CompletionArgs::reset() {
  shell_str.clear();
  out_dir.clear();
}

ECM CompletionArgs::Run(const CLIServices &managers,
                        const CliRunContext &ctx) const {
  const auto *tree = managers.runtime.command_tree;
  if (!tree) {
    std::cerr << "Error: command tree not available\n";
    return {EC::InvalidHandle, "completion", "<command-tree>",
            "command tree is null"};
  }

  const auto local_client = managers.application.client_service->GetLocalClient();
  if (!local_client) {
    return {EC::InvalidHandle, "completion", "", "local client not available"};
  }
  const ControlComponent control(ctx.task_control_token);
  auto cwd_result = managers.application.filesystem_service->GetClientCwd(
      local_client, control);
  if (!cwd_result.rcm) {
    return cwd_result.rcm;
  }

  AMInterface::completion::CompletionScriptExportRequest request = {};
  request.command_tree = tree;
  request.shell =
      AMInterface::completion::ParseCompletionScriptShell(shell_str);
  request.app_name = managers.runtime.app_name;
  request.out_dir = out_dir;
  request.cwd = cwd_result.data;
  if (managers.interfaces.style_service.IsReady()) {
    const auto style_cfg = managers.interfaces.style_service->GetInitArg().style;
    request.style_cli_module = style_cfg.common.cli_module;
    request.style_cli_command = style_cfg.common.cli_command;
    request.style_cli_option = style_cfg.common.cli_option;
    request.style_complete_help = style_cfg.complete_menu.help_style;
  }

  auto export_result = AMInterface::completion::ExportCompletionScript(request);
  if (!export_result.rcm) {
    return export_result.rcm;
  }

  std::cout << "Completion script written to file:///"
            << export_result.data.display_uri << " (" << export_result.data.bytes
            << " bytes)\n";
  return OK;
}

} // namespace AMInterface::cli
