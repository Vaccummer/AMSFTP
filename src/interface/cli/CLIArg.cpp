#include "interface/cli/CLIArg.hpp"
#include "interface/adapters/ApplicationAdapters.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/prompt/Prompt.hpp"
#include "infrastructure/controller/ClientControlTokenAdapter.hpp"
#include "application/client/ClientSessionWorkflows.hpp"
#include "application/completion/CompletionWorkflows.hpp"
#include "application/host/HostProfileWorkflows.hpp"
#include "application/transfer/TaskWorkflows.hpp"
#include "application/transfer/TransferWorkflows.hpp"
#include <iostream>

namespace {
using ClientPath = AMDomain::filesystem::ClientPath;

/**
 * @brief Resolve the task-control token from session context.
 */
amf ResolveTaskControlToken_(const CliRunContext &ctx) {
  if (ctx.task_control_token) {
    return ctx.task_control_token;
  }
  static const amf fallback = TaskControlToken::CreateShared();
  return fallback;
}

/**
 * @brief Resolve transfer/client interrupt token from session control context.
 */
AMDomain::client::amf ResolveTransferInterruptFlag_(const CliRunContext &ctx) {
  return AMInfra::controller::AdaptClientInterruptFlag(
      ResolveTaskControlToken_(ctx));
}

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
    AMInterface::prompt::AMPromptIOManager &prompt, const std::string &arg_nickname,
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
    AMInterface::prompt::AMPromptIOManager &prompt,
    const std::vector<std::string> &candidates,
    const std::string &arg_nickname, std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  const std::string seeded = AMStr::Strip(arg_nickname);
  if (!seeded.empty()) {
    return ValidateConfigProfileNickname_(gateway, seeded, normalized);
  }

  std::vector<std::pair<std::string, std::string>> prompt_candidates;
  prompt_candidates.reserve(candidates.size());
  for (const auto &item : candidates) {
    prompt_candidates.emplace_back(item, "");
  }

  while (true) {
    std::string input;
    if (!prompt.Prompt("Profile nickname(host): ", "", &input, {},
                       prompt_candidates)) {
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
    const CliManagers &managers,
    const std::string &raw) {
  AMInterface::var::VarInterfaceService var_interface(
      managers.var_service, managers.client_service, managers.prompt_io_manager);
  return var_interface.SubstitutePathLike(raw);
}

std::vector<std::string>
SubstitutePathLikeArgs_(
    const CliManagers &managers,
    const std::vector<std::string> &raw) {
  AMInterface::var::VarInterfaceService var_interface(
      managers.var_service, managers.client_service, managers.prompt_io_manager);
  return var_interface.SubstitutePathLike(raw);
}

/**
 * @brief Resolve one raw transfer token into explicit endpoint payload.
 */
ECM ResolveTransferEndpoint_(
    AMApplication::client::ClientAppService &client_service,
    const std::string &raw, AMDomain::client::amf interrupt_flag,
    ClientPath *out_endpoint) {
  if (!out_endpoint) {
    return Err(EC::InvalidArg, "null transfer endpoint output");
  }

  const std::string token = AMStr::Strip(raw);
  if (token.empty()) {
    return Err(EC::InvalidArg, "Transfer path is empty");
  }

  auto parsed = client_service.ParseScopedPath(token, interrupt_flag);
  ECM parse_rcm = std::get<3>(parsed);
  if (!isok(parse_rcm)) {
    return parse_rcm;
  }

  std::string nickname = std::get<0>(parsed);
  std::string path = std::get<1>(parsed);
  AMDomain::client::ClientHandle client = std::get<2>(parsed);
  if (!client) {
    if (nickname.empty()) {
      client = client_service.GetCurrentClient();
    } else {
      auto resolved_client = client_service.GetClient(nickname, true);
      client = isok(resolved_client.rcm) ? resolved_client.data : nullptr;
    }
  }
  if (!client && nickname.empty()) {
    client = client_service.GetLocalClient();
  }
  if (!client) {
    return Err(EC::ClientNotFound,
               AMStr::fmt("Resolved transfer client is null for token: {}",
                          token));
  }

  if (path.empty()) {
    path = ".";
  }
  out_endpoint->nickname = client->ConfigPort().GetNickname();
  if (out_endpoint->nickname.empty()) {
    out_endpoint->nickname = "local";
  }
  out_endpoint->path = client_service.BuildAbsolutePath(client, path);
  return Ok();
}

/**
 * @brief Build explicit transfer args from raw CLI cp/job inputs.
 */
struct TransferCliBuildResult {
  ECM rcm = Ok();
  AMApplication::TransferWorkflow::TransferBuildArgs build_args = {};
  bool suffix_async = false;
};

TransferCliBuildResult BuildTransferArgsFromCli_(
    const CliManagers &managers,
    const std::vector<std::string> &raw_srcs, const std::string &raw_output,
    bool accept_ampersand_suffix, bool overwrite, bool no_mkdir, bool clone,
    bool include_special, bool resume, AMDomain::client::amf interrupt_flag) {
  TransferCliBuildResult out = {};

  std::vector<std::string> src_tokens =
      SubstitutePathLikeArgs_(managers, raw_srcs);
  if (accept_ampersand_suffix && !src_tokens.empty() &&
      src_tokens.back() == "&") {
    out.suffix_async = true;
    src_tokens.pop_back();
  }

  if (src_tokens.empty()) {
    out.rcm = Err(EC::InvalidArg, "cp requires at least one source");
    return out;
  }

  const std::string output_token =
      AMStr::Strip(SubstitutePathLikeArg_(managers, raw_output));
  std::vector<std::string> normalized_src_tokens = {};
  std::string normalized_dst_token = {};
  if (output_token.empty()) {
    if (src_tokens.size() != 2) {
      out.rcm =
          Err(EC::InvalidArg,
              "cp requires exactly 2 paths when --output is omitted");
      return out;
    }
    normalized_src_tokens = {src_tokens.front()};
    normalized_dst_token = src_tokens.back();
  } else {
    normalized_src_tokens = src_tokens;
    normalized_dst_token = output_token;
  }

  out.build_args.srcs.clear();
  out.build_args.srcs.reserve(normalized_src_tokens.size());
  for (const auto &token : normalized_src_tokens) {
    ClientPath endpoint = {};
    ECM resolve_rcm = ResolveTransferEndpoint_(managers.client_service, token,
                                               interrupt_flag, &endpoint);
    if (!isok(resolve_rcm)) {
      out.rcm = resolve_rcm;
      return out;
    }
    out.build_args.srcs.push_back(std::move(endpoint));
  }

  ClientPath dst_endpoint = {};
  ECM dst_rcm =
      ResolveTransferEndpoint_(managers.client_service, normalized_dst_token,
                               interrupt_flag, &dst_endpoint);
  if (!isok(dst_rcm)) {
    out.rcm = dst_rcm;
    return out;
  }

  out.build_args.output = std::move(dst_endpoint);
  out.build_args.overwrite = overwrite;
  out.build_args.no_mkdir = no_mkdir;
  out.build_args.clone = clone;
  out.build_args.include_special = include_special;
  out.build_args.resume = resume;
  return out;
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

/**
 * @brief Resolve explicit transfer confirm policy from run context.
 */
AMApplication::TransferWorkflow::TransferConfirmPolicy
BuildTransferConfirmPolicy_(const CliRunContext &ctx, bool quiet) {
  if (quiet) {
    return AMApplication::TransferWorkflow::TransferConfirmPolicy::AutoApprove;
  }
  const bool is_interactive =
      ctx.enforce_interactive ||
      (ctx.is_interactive &&
       ctx.is_interactive->load(std::memory_order_relaxed));
  if (is_interactive) {
    return AMApplication::TransferWorkflow::TransferConfirmPolicy::
        RequireConfirm;
  }
  return AMApplication::TransferWorkflow::TransferConfirmPolicy::
      DenyIfConfirmNeeded;
}

} // namespace

ECM ConfigLsArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_io_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigLs(gateway, detail);
}

void ConfigLsArgs::reset() { detail = false; }

ECM ConfigKeysArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_io_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigKeys(gateway, true);
}

void ConfigKeysArgs::reset() {}

ECM ConfigDataArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_io_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigData(gateway);
}

void ConfigDataArgs::reset() {}

ECM ConfigGetArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_io_manager);
  AMInterface::ApplicationAdapters::CurrentClientPort client_port(
      managers.client_service);
  return AMApplication::HostProfileWorkflow::ExecuteConfigGet(gateway,
                                                              client_port,
                                                              nicknames);
}

void ConfigGetArgs::reset() { nicknames.clear(); }
ECM ConfigAddArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_io_manager);
  std::string resolved;
  ECM rcm = ResolveConfigAddNickname_(gateway, managers.prompt_io_manager, nickname,
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
      managers.host_config_manager, managers.prompt_io_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigEdit(gateway,
                                                               nickname);
}

void ConfigEditArgs::reset() { nickname.clear(); }

ECM ConfigRenameArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_io_manager);
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
      managers.host_config_manager, managers.prompt_io_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigRemove(gateway,
                                                                 names);
}

void ConfigRemoveArgs::reset() { names.clear(); }

ECM ConfigSetArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_io_manager);
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
  ECM rcm = managers.config_service.FlushDirtyParticipants();
  if (!isok(rcm)) {
    return rcm;
  }
  return managers.config_service.DumpAll(false);
}

void ConfigSaveArgs::reset() {}

ECM ConfigProfileSetArgs::Run(const CliManagers &managers,
                              const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_io_manager);
  const std::vector<std::string> candidates = gateway.ListHostNames();
  std::string target;
  ECM rcm = ResolveConfigProfileNickname_(
      gateway, managers.prompt_io_manager, candidates, nickname, &target);
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
      managers.host_config_manager, managers.prompt_io_manager);
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
      managers.host_config_manager, managers.prompt_io_manager);
  ECM rcm = AMApplication::HostProfileWorkflow::ExecuteProfileGet(gateway,
                                                                  nicknames);
  PrintRunError_(rcm);
  return rcm;
}

void ProfileGetArgs::reset() { nicknames.clear(); }

ECM StatArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  AMInterface::filesystem::FilesystemInterfaceSerivce filesystem(
      managers.client_service, managers.filesystem_service, managers.style_service,
      managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(managers, paths);
  AMInterface::filesystem::FilesystemStatArg arg = {};
  arg.raw_paths = resolved;
  arg.trace_link = trace_link;
  return filesystem.Stat(arg);
}

void StatArgs::reset() {
  paths.clear();
  trace_link = false;
}

ECM LsArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  AMInterface::filesystem::FilesystemInterfaceSerivce filesystem(
      managers.client_service, managers.filesystem_service, managers.style_service,
      managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  AMInterface::filesystem::FilesystemLsArg arg = {};
  arg.raw_path = SubstitutePathLikeArg_(managers, path);
  arg.list_like = list_like;
  arg.show_all = show_all;
  return filesystem.Ls(arg);
}

void LsArgs::reset() {
  path.clear();
  list_like = false;
  show_all = false;
}

ECM SizeArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(managers, paths);
  ECM rcm = filesystem.GetSize(resolved, ResolveTransferInterruptFlag_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void SizeArgs::reset() { paths.clear(); }

ECM FindArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers, path);
  ECM rcm =
      filesystem.Find(resolved, SearchType::All, ResolveTransferInterruptFlag_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void FindArgs::reset() { path.clear(); }

ECM MkdirArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  AMInterface::filesystem::FilesystemInterfaceSerivce filesystem(
      managers.client_service, managers.filesystem_service, managers.style_service,
      managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  AMInterface::filesystem::FilesystemMkdirsArg arg = {};
  arg.raw_paths = SubstitutePathLikeArgs_(managers, paths);
  return filesystem.Mkdirs(arg);
}

void MkdirArgs::reset() { paths.clear(); }

ECM RmArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(managers, paths);
  ECM rcm = filesystem.Remove(resolved, permanent, quiet,
                              ResolveTransferInterruptFlag_(ctx));
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
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers, path);
  ECM rcm = filesystem.Walk(resolved, only_file, only_dir, show_all,
                            !include_special, quiet,
                            ResolveTransferInterruptFlag_(ctx));
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
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers, path);
  ECM rcm = filesystem.Tree(resolved, depth, only_dir, show_all,
                            !include_special, quiet,
                            ResolveTransferInterruptFlag_(ctx));
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
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers, path);
  return filesystem.Realpath(resolved, ResolveTransferInterruptFlag_(ctx));
}

void RealpathArgs::reset() { path.clear(); }

ECM RttArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  ECM rcm = filesystem.TestRtt(times, ResolveTransferInterruptFlag_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void RttArgs::reset() { times = 1; }

ECM ClearArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  managers.prompt_io_manager.ClearScreen(all);
  return {EC::Success, ""};
}

void ClearArgs::reset() { all = false; }

ECM CpArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  auto build = BuildTransferArgsFromCli_(
      managers, srcs, output, true, overwrite, no_mkdir, clone, include_special,
      resume, ResolveTransferInterruptFlag_(ctx));
  if (!isok(build.rcm)) {
    PrintRunError_(build.rcm);
    return build.rcm;
  }

  AMApplication::TransferWorkflow::TransferExecutionOptions options{};
  options.run_async_from_context = ctx.async || build.suffix_async;
  options.quiet = quiet;
  options.confirm_policy = BuildTransferConfirmPolicy_(ctx, quiet);

  AMInterface::ApplicationAdapters::TransferExecutorPort executor(
      managers.transfer_service, managers.prompt_io_manager,
      options.confirm_policy,
      ResolveTransferInterruptFlag_(ctx));
  auto result = AMApplication::TransferWorkflow::ExecuteTransfer(
      build.build_args, options, executor);
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
      managers.client_service);
  auto result = AMApplication::ClientWorkflow::ConnectProtocolClient(
      gateway, AMDomain::host::ClientProtocol::SFTP, targets, port, password,
      keyfile,
      ResolveTaskControlToken_(ctx));
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
      managers.client_service);
  auto result = AMApplication::ClientWorkflow::ConnectProtocolClient(
      gateway, AMDomain::host::ClientProtocol::FTP, targets, port, password,
      keyfile,
      ResolveTaskControlToken_(ctx));
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
      managers.client_service);
  return AMApplication::ClientWorkflow::ExecuteClientList(
      gateway, detail, ResolveTaskControlToken_(ctx));
}

void ClientsArgs::reset() { detail = false; }

ECM CheckArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  ECM rcm =
      filesystem.CheckClients(nicknames, detail, ResolveTransferInterruptFlag_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void CheckArgs::reset() {
  nicknames.clear();
  detail = false;
}

ECM ChangeClientArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.client_service);
  const auto result = AMApplication::ClientWorkflow::ChangeClient(
      gateway, nickname, BuildClientSessionMode_(ctx),
      ResolveTaskControlToken_(ctx));
  SetEnterInteractive_(ctx, result.enter_interactive);
  return result.rcm;
}

void ChangeClientArgs::reset() { nickname.clear(); }

ECM DisconnectArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.client_service);
  return AMApplication::ClientWorkflow::ExecuteClientDisconnect(gateway,
                                                                nicknames);
}

void DisconnectArgs::reset() { nicknames.clear(); }

ECM CdArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  AMInterface::filesystem::FilesystemInterfaceSerivce filesystem(
      managers.client_service, managers.filesystem_service, managers.style_service,
      managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  AMInterface::filesystem::FilesystemCdArg arg = {};
  arg.raw_path = SubstitutePathLikeArg_(managers, path);
  ECM rcm = filesystem.Cd(arg);
  SetEnterInteractive_(ctx, isok(rcm));
  return rcm;
}

void CdArgs::reset() { path.clear(); }

ECM ConnectArgs::Run(const CliManagers &managers,
                     const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::ClientSessionGateway gateway(
      managers.client_service);
  const auto result = AMApplication::ClientWorkflow::ConnectNicknames(
      gateway, nicknames, force, BuildClientSessionMode_(ctx),
      ResolveTaskControlToken_(ctx));
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
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_io_manager);
  if (timeout_ms <= 0) {
    ECM rcm = Err(EC::InvalidArg, "timeout_ms must be > 0");
    PrintRunError_(rcm);
    return rcm;
  }
  const std::string command = AMStr::Strip(cmd_str);
  if (command.empty()) {
    ECM rcm = Err(EC::InvalidArg, "cmd_str cannot be empty");
    PrintRunError_(rcm);
    return rcm;
  }
  const auto shell = filesystem.ShellRun(command, timeout_ms,
                                         ResolveTransferInterruptFlag_(ctx));
  if (!isok(shell.first)) {
    PrintRunError_(shell.first);
    return shell.first;
  }

  if (!shell.second.first.empty()) {
    managers.prompt_io_manager.Print(shell.second.first);
  }
  managers.prompt_io_manager.FmtPrint("Command exit with code {}",
                                   shell.second.second);
  return shell.first;
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
  AMInterface::var::VarInterfaceService var_interface(
      managers.var_service, managers.client_service, managers.prompt_io_manager);
  auto info = var_interface.ResolveLookupToken(varname);
  if (!isok(info.rcm)) {
    return info.rcm;
  }
  managers.prompt_io_manager.FmtPrint("{}:{} = {}", info.data.domain,
                                      info.data.varname, info.data.varvalue);
  return Ok();
}

void VarGetArgs::reset() { varname.clear(); }

ECM VarDefArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::var::VarInterfaceService var_interface(
      managers.var_service, managers.client_service, managers.prompt_io_manager);
  auto target = var_interface.ResolveDefineTarget(global, varname);
  if (!isok(target.rcm)) {
    return target.rcm;
  }
  target.data.varvalue = value;
  return managers.var_service.AddVar(target.data);
}

void VarDefArgs::reset() {
  global = false;
  varname.clear();
  value.clear();
}

ECM VarDelArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  if (tokens.empty() || tokens.size() > 2) {
    return Err(EC::InvalidArg, "var del requires one var token or [zone token]");
  }

  AMInterface::var::VarInterfaceService var_interface(
      managers.var_service, managers.client_service, managers.prompt_io_manager);
  std::string zone_override = {};
  std::string token_expr = tokens.front();
  if (tokens.size() == 2) {
    zone_override = AMStr::Strip(tokens.front());
    token_expr = tokens.back();
  }

  auto parsed = var_interface.ParseVarTokenExpression(token_expr);
  if (!isok(parsed.rcm)) {
    return parsed.rcm;
  }

  if (all) {
    auto all_vars = managers.var_service.GetAllVar();
    if (!isok(all_vars.rcm)) {
      return all_vars.rcm;
    }
    ECM last = Ok();
    bool removed_any = false;
    for (const auto &[zone_name, zone_vars] : all_vars.data) {
      if (zone_vars.find(parsed.data.varname) == zone_vars.end()) {
        continue;
      }
      ECM del_rcm = managers.var_service.DelVar(zone_name, parsed.data.varname);
      if (!isok(del_rcm)) {
        last = del_rcm;
        continue;
      }
      removed_any = true;
    }
    if (!removed_any) {
      return Err(EC::InvalidArg, "variable not found");
    }
    return last;
  }

  std::string resolved_zone = {};
  if (!zone_override.empty()) {
    resolved_zone = zone_override;
  } else if (parsed.data.explicit_domain) {
    resolved_zone = parsed.data.domain;
  } else {
    resolved_zone = AMStr::Strip(managers.client_service.CurrentNickname());
    if (resolved_zone.empty()) {
      resolved_zone = "local";
    }
  }
  return managers.var_service.DelVar(resolved_zone, parsed.data.varname);
}

void VarDelArgs::reset() {
  all = false;
  tokens.clear();
}

ECM VarLsArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  auto print_zone = [&managers](const std::string &zone_name,
                                const AMApplication::var::ZoneVarInfoMap &zone_vars) {
    for (const auto &[name, info] : zone_vars) {
      (void)name;
      managers.prompt_io_manager.FmtPrint("{}:{} = {}", zone_name, info.varname,
                                          info.varvalue);
    }
  };

  if (sections.empty()) {
    auto all_vars = managers.var_service.GetAllVar();
    if (!isok(all_vars.rcm)) {
      return all_vars.rcm;
    }
    for (const auto &[zone_name, zone_vars] : all_vars.data) {
      print_zone(zone_name, zone_vars);
    }
    return Ok();
  }

  ECM last = Ok();
  for (const std::string &zone : sections) {
    auto zone_vars = managers.var_service.EnumerateZone(zone);
    if (!isok(zone_vars.rcm)) {
      last = zone_vars.rcm;
      managers.prompt_io_manager.ErrorFormat(zone_vars.rcm);
      continue;
    }
    print_zone(zone, zone_vars.data);
  }
  return last;
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
  managers.prompt_io_manager.Print("Completion cache "
                                "cleared.");
  return Ok();
}

void CompleteCacheClearArgs::reset() {}

ECM TaskListArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  AMApplication::TaskWorkflow::TaskListFilter filter{};
  filter.pending = pending;
  filter.suspend = suspend;
  filter.finished = finished;
  filter.conducting = conducting;
  return AMApplication::TaskWorkflow::ExecuteTaskList(
      gateway, filter, BuildTaskSessionMode_(ctx));
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
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  return AMApplication::TaskWorkflow::ExecuteTaskShow(
      gateway, ids, BuildTaskSessionMode_(ctx));
}

void TaskShowArgs::reset() { ids.clear(); }

ECM TaskInspectArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
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
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  return AMApplication::TaskWorkflow::ExecuteTaskThread(
      gateway, num, BuildTaskSessionMode_(ctx));
}

void TaskThreadArgs::reset() { num = -1; }

ECM TaskCacheAddArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  auto build = BuildTransferArgsFromCli_(
      managers, srcs, output, false, overwrite, no_mkdir, clone, include_special,
      resume, ResolveTransferInterruptFlag_(ctx));
  if (!isok(build.rcm)) {
    return build.rcm;
  }

  auto result = AMApplication::TaskWorkflow::ExecuteJobCacheAdd(
      gateway, build.build_args, BuildTaskSessionMode_(ctx));
  if (isok(result.rcm)) {
    managers.prompt_io_manager.FmtPrint("✅ job add {}", std::to_string(result.index));
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
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  auto result = AMApplication::TaskWorkflow::ExecuteJobCacheRemove(
      gateway, indices, BuildTaskSessionMode_(ctx));
  if (isok(result.rcm)) {
    for (size_t index : result.removed_indices) {
      managers.prompt_io_manager.FmtPrint("✅ job rm {}", std::to_string(index));
    }
  }
  return result.rcm;
}

void TaskCacheRmArgs::reset() { indices.clear(); }

ECM TaskCacheClearArgs::Run(const CliManagers &managers,
                            const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  ECM rcm = AMApplication::TaskWorkflow::ExecuteJobCacheClear(
      gateway, BuildTaskSessionMode_(ctx));
  if (isok(rcm)) {
    managers.prompt_io_manager.Print("✅ job "
                                  "cleared");
  }
  return rcm;
}

void TaskCacheClearArgs::reset() {}

ECM TaskCacheSubmitArgs::Run(const CliManagers &managers,
                             const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  AMApplication::TaskWorkflow::JobCacheSubmitOptions options{};
  options.is_async = is_async;
  options.quiet = quiet;
  options.async_suffix = async_suffix;
  return AMApplication::TaskWorkflow::ExecuteJobCacheSubmit(
      gateway, options, BuildTaskSessionMode_(ctx));
}

void TaskCacheSubmitArgs::reset() {
  is_async = false;
  quiet = false;
  async_suffix.clear();
}

ECM TaskUserSetArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  auto result = AMApplication::TaskWorkflow::ExecuteJobCacheQuery(
      gateway, indices, BuildTaskSessionMode_(ctx));
  return result.rcm;
}

void TaskUserSetArgs::reset() { indices.clear(); }

ECM TaskEntryArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
  return AMApplication::TaskWorkflow::ExecuteTaskEntryQuery(
      gateway, ids, BuildTaskSessionMode_(ctx));
}

void TaskEntryArgs::reset() { ids.clear(); }

ECM TaskControlArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
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
      managers.transfer_service, managers.prompt_io_manager,
      ResolveTransferInterruptFlag_(ctx));
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




