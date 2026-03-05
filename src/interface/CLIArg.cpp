#include "interface/CLIArg.hpp"
#include "interface/ApplicationAdapters.hpp"
#include "interface/Prompt.hpp"
#include "application/client/FileCommandWorkflows.hpp"
#include "application/client/ClientSessionWorkflows.hpp"
#include "application/completion/CompletionWorkflows.hpp"
#include "application/config/ConfigWorkflows.hpp"
#include "application/config/HostProfileWorkflows.hpp"
#include "application/transfer/TaskWorkflows.hpp"
#include "application/transfer/TransferWorkflows.hpp"
#include "application/var/VarWorkflows.hpp"
#include <iostream>

CliRunContext &CliRunContext::Instance() {
  static CliRunContext instance;
  return instance;
}

namespace {
void SetEnterInteractive_(const CliRunContext &ctx, bool value) {
  ctx.enter_interactive = value;
}

void SetRequestExit_(const CliRunContext &ctx, bool value) {
  ctx.request_exit = value;
}

void SetSkipLoopExitCallbacks_(const CliRunContext &ctx, bool value) {
  ctx.skip_loop_exit_callbacks = value;
}

void PrintRunError_(const ECM &rcm) {
  if (rcm.first != EC::Success && !rcm.second.empty()) {
    std::cerr << rcm.second << std::endl;
  }
}

ECM ValidateConfigAddNickname_(
    const AMApplication::HostProfileWorkflow::IHostProfileGateway &gateway,
    const std::string &raw, std::string *normalized) {
  return AMApplication::HostProfileWorkflow::ValidateConfigAddNickname(
      gateway, raw, normalized);
}

ECM ResolveConfigAddNickname_(
    const AMApplication::HostProfileWorkflow::IHostProfileGateway &gateway,
    AMPromptManager &prompt, const std::string &arg_nickname,
    std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  const std::string seeded = AMStr::Strip(arg_nickname);
  if (!seeded.empty()) {
    return ValidateConfigAddNickname_(gateway, seeded, normalized);
  }

  auto checker = [&gateway](const std::string &text) -> bool {
    const std::string candidate = AMStr::Strip(text);
    if (candidate.empty()) {
      return true;
    }
    std::string normalized;
    ECM rcm = ValidateConfigAddNickname_(gateway, candidate, &normalized);
    return rcm.first == EC::Success;
  };
  while (true) {
    std::string input;
    if (!prompt.Prompt("Nickname: ", "", &input, checker)) {
      return Err(EC::ConfigCanceled, "add canceled");
    }
    input = AMStr::Strip(input);
    if (input.empty()) {
      continue;
    }
    ECM rcm = ValidateConfigAddNickname_(gateway, input, normalized);
    if (isok(rcm)) {
      return Ok();
    }
    prompt.ErrorFormat(rcm);
  }
}

ECM ValidateConfigProfileNickname_(
    const AMApplication::HostProfileWorkflow::IHostProfileGateway &gateway,
    const std::string &raw, std::string *normalized) {
  return AMApplication::HostProfileWorkflow::ValidateConfigProfileNickname(
      gateway, raw, normalized);
}

ECM ResolveConfigProfileNickname_(
    const AMApplication::HostProfileWorkflow::IHostProfileGateway &gateway,
    AMPromptManager &prompt, const std::vector<std::string> &candidates,
    const std::string &arg_nickname, std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  const std::string seeded = AMStr::Strip(arg_nickname);
  if (!seeded.empty()) {
    return ValidateConfigProfileNickname_(gateway, seeded, normalized);
  }

  while (true) {
    std::string input;
    if (!prompt.Prompt("Profile nickname(host): ", "", &input, {},
                       candidates)) {
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    input = AMStr::Strip(input);
    if (input.empty()) {
      continue;
    }
    ECM rcm = ValidateConfigProfileNickname_(gateway, input, normalized);
    if (isok(rcm)) {
      return Ok();
    }
    prompt.ErrorFormat(rcm);
  }
}

std::string SubstitutePathLikeArg_(
    const AMInterface::ApplicationAdapters::VarGateway &var_gateway,
    const std::string &raw) {
  return var_gateway.SubstitutePathLike(raw);
}

std::vector<std::string>
SubstitutePathLikeArgs_(
    const AMInterface::ApplicationAdapters::VarGateway &var_gateway,
    const std::vector<std::string> &raw) {
  return var_gateway.SubstitutePathLike(raw);
}

/**
 * @brief Return interactive-mode flags for client workflow execution.
 */
AMApplication::ClientWorkflow::SessionMode
BuildClientSessionMode_(const CliRunContext &ctx) {
  AMApplication::ClientWorkflow::SessionMode mode{};
  mode.enforce_interactive = ctx.enforce_interactive;
  mode.current_interactive =
      ctx.is_interactive && ctx.is_interactive->load(std::memory_order_relaxed);
  return mode;
}

/**
 * @brief Return interactive-mode flags for task workflow execution.
 */
AMApplication::TaskWorkflow::SessionMode
BuildTaskSessionMode_(const CliRunContext &ctx) {
  AMApplication::TaskWorkflow::SessionMode mode{};
  mode.enforce_interactive = ctx.enforce_interactive;
  mode.current_interactive =
      ctx.is_interactive && ctx.is_interactive->load(std::memory_order_relaxed);
  mode.command_name = ctx.command_name;
  return mode;
}

} // namespace

ECM ConfigLsArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigLs(gateway, detail);
}

void ConfigLsArgs::reset() { detail = false; }

ECM ConfigKeysArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigKeys(gateway, true);
}

void ConfigKeysArgs::reset() {}

ECM ConfigDataArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigData(gateway);
}

void ConfigDataArgs::reset() {}

ECM ConfigGetArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  AMInterface::ApplicationAdapters::CurrentClientPort client_port(
      managers.client_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigGet(gateway,
                                                              client_port,
                                                              nicknames);
}

void ConfigGetArgs::reset() { nicknames.clear(); }
ECM ConfigAddArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  std::string resolved;
  ECM rcm = ResolveConfigAddNickname_(gateway, managers.prompt_manager, nickname,
                                      &resolved);
  if (!isok(rcm)) {
    PrintRunError_(rcm);
    return rcm;
  }
  rcm = AMApplication::HostProfileWorkflow::ExecuteConfigAdd(gateway, resolved);
  PrintRunError_(rcm);
  return rcm;
}

void ConfigAddArgs::reset() { nickname.clear(); }

ECM ConfigEditArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigEdit(gateway,
                                                               nickname);
}

void ConfigEditArgs::reset() { nickname.clear(); }

ECM ConfigRenameArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigRename(gateway,
                                                                 old_name,
                                                                 new_name);
}

void ConfigRenameArgs::reset() {
  old_name.clear();
  new_name.clear();
}

ECM ConfigRemoveArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigRemove(gateway,
                                                                 names);
}

void ConfigRemoveArgs::reset() { names.clear(); }

ECM ConfigSetArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigSet(
      gateway, nickname, attrname, value);
}

void ConfigSetArgs::reset() {
  nickname.clear();
  attrname.clear();
  value.clear();
}

ECM ConfigSaveArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostConfigSaver host_saver(
      managers.host_manager);
  AMInterface::ApplicationAdapters::VarConfigSaver var_saver(
      managers.var_manager);
  AMInterface::ApplicationAdapters::PromptConfigSaver prompt_saver(
      managers.prompt_manager);
  return AMApplication::ConfigWorkflow::SaveAllFromCli(host_saver, var_saver,
                                                       prompt_saver);
}

void ConfigSaveArgs::reset() {}

ECM ConfigProfileSetArgs::Run(const CliManagers &managers,
                              const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  const std::vector<std::string> candidates = gateway.ListHostNames();
  std::string target;
  ECM rcm = ResolveConfigProfileNickname_(
      gateway, managers.prompt_manager, candidates, nickname, &target);
  if (!isok(rcm)) {
    PrintRunError_(rcm);
    return rcm;
  }
  rcm = AMApplication::HostProfileWorkflow::ExecuteConfigProfileSet(gateway,
                                                                    target);
  PrintRunError_(rcm);
  return rcm;
}

void ConfigProfileSetArgs::reset() { nickname.clear(); }

ECM ProfileEditArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  ECM rcm = AMApplication::HostProfileWorkflow::ExecuteProfileEdit(gateway,
                                                                   nickname);
  PrintRunError_(rcm);
  return rcm;
}

void ProfileEditArgs::reset() { nickname.clear(); }

ECM ProfileGetArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_manager, managers.prompt_manager);
  ECM rcm = AMApplication::HostProfileWorkflow::ExecuteProfileGet(gateway,
                                                                  nicknames);
  PrintRunError_(rcm);
  return rcm;
}

void ProfileGetArgs::reset() { nicknames.clear(); }

ECM StatArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.filesystem);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(var_gateway, paths);
  return AMApplication::ClientWorkflow::ExecuteStatPaths(
      gateway, resolved, TaskControlToken::Instance());
}

void StatArgs::reset() { paths.clear(); }

ECM LsArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::ClientPathGateway client_path(
      managers.client_manager);
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.filesystem);
  std::string query_path =
      AMStr::Strip(SubstitutePathLikeArg_(var_gateway, path));
  if (query_path.empty()) {
    query_path = client_path.CurrentWorkdir();
  }
  if (query_path.empty()) {
    query_path = "/";
  }
  ECM rcm = AMApplication::ClientWorkflow::ExecuteListPath(
      gateway, query_path, list_like, show_all, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void LsArgs::reset() {
  path.clear();
  list_like = false;
  show_all = false;
}

ECM SizeArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(var_gateway, paths);
  ECM rcm = AMApplication::FileCommandWorkflow::ExecuteGetSize(
      gateway, resolved, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void SizeArgs::reset() { paths.clear(); }

ECM FindArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const std::string resolved = SubstitutePathLikeArg_(var_gateway, path);
  ECM rcm = AMApplication::FileCommandWorkflow::ExecuteFind(
      gateway, resolved, SearchType::All, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void FindArgs::reset() { path.clear(); }

ECM MkdirArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(var_gateway, paths);
  ECM rcm = AMApplication::FileCommandWorkflow::ExecuteMkdir(
      gateway, resolved, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void MkdirArgs::reset() { paths.clear(); }

ECM RmArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(var_gateway, paths);
  ECM rcm = AMApplication::FileCommandWorkflow::ExecuteRemove(
      gateway, resolved, permanent, false, quiet, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void RmArgs::reset() {
  paths.clear();
  permanent = false;
  quiet = false;
}

ECM WalkArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const std::string resolved = SubstitutePathLikeArg_(var_gateway, path);
  ECM rcm = AMApplication::FileCommandWorkflow::ExecuteWalk(
      gateway, resolved, only_file, only_dir, show_all, !include_special, quiet,
      TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void WalkArgs::reset() {
  path.clear();
  only_file = false;
  only_dir = false;
  show_all = false;
  include_special = false;
  quiet = false;
}

ECM TreeArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const std::string resolved = SubstitutePathLikeArg_(var_gateway, path);
  ECM rcm = AMApplication::FileCommandWorkflow::ExecuteTree(
      gateway, resolved, depth, only_dir, show_all, !include_special, quiet,
      TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void TreeArgs::reset() {
  path.clear();
  depth = -1;
  only_dir = false;
  show_all = false;
  include_special = false;
  quiet = false;
}

ECM RealpathArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const std::string resolved = SubstitutePathLikeArg_(var_gateway, path);
  return AMApplication::FileCommandWorkflow::ExecuteRealpath(
      gateway, resolved, TaskControlToken::Instance());
}

void RealpathArgs::reset() { path.clear(); }

ECM RttArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  ECM rcm = AMApplication::FileCommandWorkflow::ExecuteRtt(
      gateway, times, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void RttArgs::reset() { times = 1; }

ECM ClearArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  managers.prompt_manager.ClearScreen(all);
  return {EC::Success, ""};
}

void ClearArgs::reset() { all = false; }

ECM CpArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  AMApplication::TransferWorkflow::TransferBuildArgs args{};
  args.srcs = srcs;
  args.output = output;
  args.overwrite = overwrite;
  args.no_mkdir = no_mkdir;
  args.clone = clone;
  args.include_special = include_special;
  args.resume = resume;

  AMApplication::TransferWorkflow::TransferExecutionOptions options{};
  options.run_async_from_context = ctx.async;
  options.quiet = quiet;
  options.accept_ampersand_suffix = true;

  AMInterface::ApplicationAdapters::PathSubstitutionPort substitutor(
      managers.var_manager);
  AMInterface::ApplicationAdapters::TransferExecutorPort executor(
      managers.transfer_manager);
  auto result = AMApplication::TransferWorkflow::ExecuteTransfer(
      args, options, substitutor, executor, TaskControlToken::Instance());
  PrintRunError_(result.rcm);
  return result.rcm;
}

void CpArgs::reset() {
  srcs.clear();
  output.clear();
  overwrite = false;
  no_mkdir = false;
  clone = false;
  include_special = false;
  resume = false;
  quiet = false;
}

ECM SftpArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.filesystem);
  auto result = AMApplication::ClientWorkflow::ConnectProtocolClient(
      gateway, ClientProtocol::SFTP, targets, port, password, keyfile,
      TaskControlToken::Instance());
  PrintRunError_(result.rcm);
  SetEnterInteractive_(ctx, result.enter_interactive);
  return result.rcm;
}

void SftpArgs::reset() {
  targets.clear();
  port = 22;
  password.clear();
  keyfile.clear();
}

ECM FtpArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.filesystem);
  auto result = AMApplication::ClientWorkflow::ConnectProtocolClient(
      gateway, ClientProtocol::FTP, targets, port, password, keyfile,
      TaskControlToken::Instance());
  PrintRunError_(result.rcm);
  SetEnterInteractive_(ctx, result.enter_interactive);
  return result.rcm;
}

void FtpArgs::reset() {
  targets.clear();
  port = 21;
  password.clear();
  keyfile.clear();
}

ECM ClientsArgs::Run(const CliManagers &managers,
                     const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.filesystem);
  return AMApplication::ClientWorkflow::ExecuteClientList(
      gateway, detail, TaskControlToken::Instance());
}

void ClientsArgs::reset() { detail = false; }

ECM CheckArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  return AMApplication::FileCommandWorkflow::ExecuteCheckClients(
      gateway, nicknames, detail, TaskControlToken::Instance());
}

void CheckArgs::reset() {
  nicknames.clear();
  detail = false;
}

ECM ChangeClientArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.filesystem);
  const auto result = AMApplication::ClientWorkflow::ChangeClient(
      gateway, nickname, BuildClientSessionMode_(ctx),
      TaskControlToken::Instance());
  SetEnterInteractive_(ctx, result.enter_interactive);
  return result.rcm;
}

void ChangeClientArgs::reset() { nickname.clear(); }

ECM DisconnectArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.filesystem);
  return AMApplication::ClientWorkflow::ExecuteClientDisconnect(gateway,
                                                                nicknames);
}

void DisconnectArgs::reset() { nicknames.clear(); }

ECM CdArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const std::string resolved = SubstitutePathLikeArg_(var_gateway, path);
  const auto result = AMApplication::FileCommandWorkflow::ExecuteCd(
      gateway, resolved, TaskControlToken::Instance(), false);
  SetEnterInteractive_(ctx, result.enter_interactive);
  return result.rcm;
}

void CdArgs::reset() { path.clear(); }

ECM ConnectArgs::Run(const CliManagers &managers,
                     const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.filesystem);
  const auto result = AMApplication::ClientWorkflow::ConnectNicknames(
      gateway, nicknames, force, BuildClientSessionMode_(ctx),
      TaskControlToken::Instance());
  PrintRunError_(result.rcm);
  SetEnterInteractive_(ctx, result.enter_interactive);
  return result.rcm;
}

void ConnectArgs::reset() {
  nicknames.clear();
  force = false;
}

ECM CmdArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileCommandGateway gateway(
      managers.filesystem);
  const auto result = AMApplication::FileCommandWorkflow::ExecuteShellCommand(
      gateway, timeout_ms, cmd_str, TaskControlToken::Instance());
  if (!isok(result.rcm)) {
    PrintRunError_(result.rcm);
    return result.rcm;
  }

  if (!result.output.empty()) {
    managers.prompt_manager.Print(result.output);
  }
  managers.prompt_manager.FmtPrint("Command exit with code {}",
                                   result.exit_code);
  return result.rcm;
}

void CmdArgs::reset() {
  timeout_ms = 5000;
  cmd_str.clear();
}

ECM BashArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)managers;
  SetEnterInteractive_(ctx, true);
  return {EC::Success, ""};
}

void BashArgs::reset() {}

ECM ExitArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)managers;
  SetRequestExit_(ctx, true);
  SetSkipLoopExitCallbacks_(ctx, force);
  return {EC::Success, ""};
}

void ExitArgs::reset() { force = false; }

ECM VarGetArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  return AMApplication::VarWorkflow::ExecuteVarGet(var_gateway, varname);
}

void VarGetArgs::reset() { varname.clear(); }

ECM VarDefArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  return AMApplication::VarWorkflow::ExecuteVarDef(var_gateway, global, varname,
                                                   value);
}

void VarDefArgs::reset() {
  global = false;
  varname.clear();
  value.clear();
}

ECM VarDelArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  return AMApplication::VarWorkflow::ExecuteVarDel(var_gateway, all, tokens);
}

void VarDelArgs::reset() {
  all = false;
  tokens.clear();
}

ECM VarLsArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::VarGateway var_gateway(managers.var_manager);
  return AMApplication::VarWorkflow::ExecuteVarLs(var_gateway, sections);
}

void VarLsArgs::reset() { sections.clear(); }

ECM CompleteCacheClearArgs::Run(const CliManagers &managers,
                                const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::CompletionGateway gateway;
  ECM rcm = AMApplication::CompletionWorkflow::ExecuteCompleteCacheClear(gateway);
  if (!isok(rcm)) {
    return rcm;
  }
  managers.prompt_manager.Print("Completion cache "
                                "cleared.");
  return Ok();
}

void CompleteCacheClearArgs::reset() {}

ECM TaskListArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  AMApplication::TaskWorkflow::TaskListFilter filter{};
  filter.pending = pending;
  filter.suspend = suspend;
  filter.finished = finished;
  filter.conducting = conducting;
  return AMApplication::TaskWorkflow::ExecuteTaskList(
      gateway, filter, BuildTaskSessionMode_(ctx), TaskControlToken::Instance());
}

void TaskListArgs::reset() {
  pending = false;
  suspend = false;
  finished = false;
  conducting = false;
}

ECM TaskShowArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  return AMApplication::TaskWorkflow::ExecuteTaskShow(
      gateway, ids, BuildTaskSessionMode_(ctx), TaskControlToken::Instance());
}

void TaskShowArgs::reset() { ids.clear(); }

ECM TaskInspectArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  AMApplication::TaskWorkflow::TaskInspectOptions options{};
  options.id = id;
  options.set = set;
  options.entry = entry;
  return AMApplication::TaskWorkflow::ExecuteTaskInspect(
      gateway, options, BuildTaskSessionMode_(ctx));
}

void TaskInspectArgs::reset() {
  id.clear();
  set = false;
  entry = false;
}

ECM TaskThreadArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  return AMApplication::TaskWorkflow::ExecuteTaskThread(
      gateway, num, BuildTaskSessionMode_(ctx));
}

void TaskThreadArgs::reset() { num = -1; }

ECM TaskCacheAddArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  AMInterface::ApplicationAdapters::PathSubstitutionPort substitutor(
      managers.var_manager);
  AMApplication::TransferWorkflow::TransferBuildArgs build_args{};
  build_args.srcs = srcs;
  build_args.output = output;
  build_args.overwrite = overwrite;
  build_args.no_mkdir = no_mkdir;
  build_args.clone = clone;
  build_args.include_special = include_special;
  build_args.resume = resume;

  auto result = AMApplication::TaskWorkflow::ExecuteJobCacheAdd(
      gateway, build_args, substitutor, BuildTaskSessionMode_(ctx));
  if (isok(result.rcm)) {
    managers.prompt_manager.FmtPrint("✅ job add {}", std::to_string(result.index));
  }
  return result.rcm;
}

void TaskCacheAddArgs::reset() {
  srcs.clear();
  output.clear();
  overwrite = false;
  no_mkdir = false;
  clone = false;
  include_special = false;
  resume = false;
}

ECM TaskCacheRmArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  auto result = AMApplication::TaskWorkflow::ExecuteJobCacheRemove(
      gateway, indices, BuildTaskSessionMode_(ctx));
  if (isok(result.rcm)) {
    for (size_t index : result.removed_indices) {
      managers.prompt_manager.FmtPrint("✅ job rm {}", std::to_string(index));
    }
  }
  return result.rcm;
}

void TaskCacheRmArgs::reset() { indices.clear(); }

ECM TaskCacheClearArgs::Run(const CliManagers &managers,
                            const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  ECM rcm = AMApplication::TaskWorkflow::ExecuteJobCacheClear(
      gateway, BuildTaskSessionMode_(ctx));
  if (isok(rcm)) {
    managers.prompt_manager.Print("✅ job "
                                  "cleared");
  }
  return rcm;
}

void TaskCacheClearArgs::reset() {}

ECM TaskCacheSubmitArgs::Run(const CliManagers &managers,
                             const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  AMApplication::TaskWorkflow::JobCacheSubmitOptions options{};
  options.is_async = is_async;
  options.quiet = quiet;
  options.async_suffix = async_suffix;
  return AMApplication::TaskWorkflow::ExecuteJobCacheSubmit(
      gateway, options, BuildTaskSessionMode_(ctx), TaskControlToken::Instance());
}

void TaskCacheSubmitArgs::reset() {
  is_async = false;
  quiet = false;
  async_suffix.clear();
}

ECM TaskUserSetArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  auto result = AMApplication::TaskWorkflow::ExecuteJobCacheQuery(
      gateway, indices, BuildTaskSessionMode_(ctx));
  return result.rcm;
}

void TaskUserSetArgs::reset() { indices.clear(); }

ECM TaskEntryArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  return AMApplication::TaskWorkflow::ExecuteTaskEntryQuery(
      gateway, ids, BuildTaskSessionMode_(ctx));
}

void TaskEntryArgs::reset() { ids.clear(); }

ECM TaskControlArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  AMApplication::TaskWorkflow::TaskControlAction workflow_action =
      AMApplication::TaskWorkflow::TaskControlAction::Terminate;
  switch (action) {
  case TaskControlArgs::Action::Terminate:
    workflow_action = AMApplication::TaskWorkflow::TaskControlAction::Terminate;
    break;
  case TaskControlArgs::Action::Pause:
    workflow_action = AMApplication::TaskWorkflow::TaskControlAction::Pause;
    break;
  case TaskControlArgs::Action::Resume:
    workflow_action = AMApplication::TaskWorkflow::TaskControlAction::Resume;
    break;
  default:
    return Err(EC::InvalidArg, "Unknown task control action");
  }
  return AMApplication::TaskWorkflow::ExecuteTaskControl(
      gateway, ids, workflow_action, BuildTaskSessionMode_(ctx));
}

void TaskControlArgs::reset() {
  ids.clear();
}

ECM TaskRetryArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_manager);
  AMApplication::TaskWorkflow::TaskRetryOptions options{};
  options.id = id;
  options.is_async = is_async;
  options.quiet = quiet;
  options.indices = indices;
  ECM rcm = AMApplication::TaskWorkflow::ExecuteTaskRetry(
      gateway, options, BuildTaskSessionMode_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void TaskRetryArgs::reset() {
  id.clear();
  is_async = false;
  quiet = false;
  indices.clear();
}

