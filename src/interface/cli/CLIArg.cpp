#include "interface/cli/CLIArg.hpp"
#include "interface/adapters/ApplicationAdapters.hpp"
#include "interface/prompt/Prompt.hpp"
#include "infrastructure/controller/ClientControlTokenAdapter.hpp"
#include "application/client/ClientSessionWorkflows.hpp"
#include "application/completion/CompletionWorkflows.hpp"
#include "application/config/CliConfigSaveWorkflows.hpp"
#include "application/host/HostProfileWorkflows.hpp"
#include "application/transfer/TaskWorkflows.hpp"
#include "application/transfer/TransferWorkflows.hpp"
#include "application/var/VarWorkflows.hpp"
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
    const AMDomain::var::IVarSubstitutionPort &substitution_port,
    const std::string &raw) {
  return substitution_port.SubstitutePathLike(raw);
}

std::vector<std::string>
SubstitutePathLikeArgs_(
    const AMDomain::var::IVarSubstitutionPort &substitution_port,
    const std::vector<std::string> &raw) {
  return substitution_port.SubstitutePathLike(raw);
}

/**
 * @brief Resolve one raw transfer token into explicit endpoint payload.
 */
ECM ResolveTransferEndpoint_(
    AMApplication::client::ClientAppService &client_service,
    const AMDomain::var::IVarSubstitutionPort &substitution_port,
    const std::string &raw, AMDomain::client::amf interrupt_flag,
    ClientPath *out_endpoint) {
  if (!out_endpoint) {
    return Err(EC::InvalidArg, "null transfer endpoint output");
  }

  const std::string token =
      AMStr::Strip(substitution_port.SubstitutePathLike(raw));
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
    client = nickname.empty() ? client_service.GetCurrentClient()
                              : client_service.GetClient(nickname);
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
    AMApplication::client::ClientAppService &client_service,
    const AMDomain::var::IVarSubstitutionPort &substitution_port,
    const std::vector<std::string> &raw_srcs, const std::string &raw_output,
    bool accept_ampersand_suffix, bool overwrite, bool no_mkdir, bool clone,
    bool include_special, bool resume, AMDomain::client::amf interrupt_flag) {
  TransferCliBuildResult out = {};

  std::vector<std::string> src_tokens =
      SubstitutePathLikeArgs_(substitution_port, raw_srcs);
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
      AMStr::Strip(SubstitutePathLikeArg_(substitution_port, raw_output));
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
    ECM resolve_rcm = ResolveTransferEndpoint_(
        client_service, substitution_port, token, interrupt_flag, &endpoint);
    if (!isok(resolve_rcm)) {
      out.rcm = resolve_rcm;
      return out;
    }
    out.build_args.srcs.push_back(std::move(endpoint));
  }

  ClientPath dst_endpoint = {};
  ECM dst_rcm = ResolveTransferEndpoint_(client_service, substitution_port,
                                         normalized_dst_token, interrupt_flag,
                                         &dst_endpoint);
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
      managers.host_config_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigLs(gateway, detail);
}

void ConfigLsArgs::reset() { detail = false; }

ECM ConfigKeysArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigKeys(gateway, true);
}

void ConfigKeysArgs::reset() {}

ECM ConfigDataArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigData(gateway);
}

void ConfigDataArgs::reset() {}

ECM ConfigGetArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_manager);
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
      managers.host_config_manager, managers.prompt_manager);
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
      managers.host_config_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigEdit(gateway,
                                                               nickname);
}

void ConfigEditArgs::reset() { nickname.clear(); }

ECM ConfigRenameArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_manager);
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
      managers.host_config_manager, managers.prompt_manager);
  return AMApplication::HostProfileWorkflow::ExecuteConfigRemove(gateway,
                                                                 names);
}

void ConfigRemoveArgs::reset() { names.clear(); }

ECM ConfigSetArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::HostProfileGateway gateway(
      managers.host_config_manager, managers.prompt_manager);
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
      managers.host_config_manager);
  AMInterface::ApplicationAdapters::VarConfigSaver var_saver(
      managers.var_service);
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
      managers.host_config_manager, managers.prompt_manager);
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
      managers.host_config_manager, managers.prompt_manager);
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
      managers.host_config_manager, managers.prompt_manager);
  ECM rcm = AMApplication::HostProfileWorkflow::ExecuteProfileGet(gateway,
                                                                  nicknames);
  PrintRunError_(rcm);
  return rcm;
}

void ProfileGetArgs::reset() { nicknames.clear(); }

ECM StatArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_manager);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(managers.var_service, paths);
  ECM rcm = filesystem.StatPaths(resolved, ResolveTransferInterruptFlag_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void StatArgs::reset() { paths.clear(); }

ECM LsArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::ClientPathGateway client_path(
      managers.client_service);
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_manager);
  std::string query_path =
      AMStr::Strip(SubstitutePathLikeArg_(managers.var_service, path));
  if (query_path.empty()) {
    query_path = client_path.CurrentWorkdir();
  }
  if (query_path.empty()) {
    query_path = "/";
  }
  ECM rcm = filesystem.ListPath(query_path, list_like, show_all,
                                ResolveTransferInterruptFlag_(ctx));
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
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_manager);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(managers.var_service, paths);
  ECM rcm = filesystem.GetSize(resolved, ResolveTransferInterruptFlag_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void SizeArgs::reset() { paths.clear(); }

ECM FindArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers.var_service, path);
  ECM rcm =
      filesystem.Find(resolved, SearchType::All, ResolveTransferInterruptFlag_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void FindArgs::reset() { path.clear(); }

ECM MkdirArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_manager);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(managers.var_service, paths);
  ECM rcm = filesystem.Mkdir(resolved, ResolveTransferInterruptFlag_(ctx));
  PrintRunError_(rcm);
  return rcm;
}

void MkdirArgs::reset() { paths.clear(); }

ECM RmArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_manager);
  const std::vector<std::string> resolved =
      SubstitutePathLikeArgs_(managers.var_service, paths);
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
      managers.client_service, managers.prompt_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers.var_service, path);
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
      managers.client_service, managers.prompt_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers.var_service, path);
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
      managers.client_service, managers.prompt_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers.var_service, path);
  return filesystem.Realpath(resolved, ResolveTransferInterruptFlag_(ctx));
}

void RealpathArgs::reset() { path.clear(); }

ECM RttArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_manager);
  ECM rcm = filesystem.TestRtt(times, ResolveTransferInterruptFlag_(ctx));
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
  auto build = BuildTransferArgsFromCli_(
      managers.client_service, managers.var_service, srcs, output, true,
      overwrite, no_mkdir, clone, include_special, resume,
      ResolveTransferInterruptFlag_(ctx));
  if (!isok(build.rcm)) {
    PrintRunError_(build.rcm);
    return build.rcm;
  }

  AMApplication::TransferWorkflow::TransferExecutionOptions options{};
  options.run_async_from_context = ctx.async || build.suffix_async;
  options.quiet = quiet;
  options.confirm_policy = BuildTransferConfirmPolicy_(ctx, quiet);

  AMInterface::ApplicationAdapters::TransferExecutorPort executor(
      managers.transfer_service, managers.prompt_manager,
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
      managers.client_service, managers.prompt_manager);
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
  AMInterface::ApplicationAdapters::FileSystemCliAdapter filesystem(
      managers.client_service, managers.prompt_manager);
  const std::string resolved = SubstitutePathLikeArg_(managers.var_service, path);
  ECM rcm = filesystem.Cd(resolved, ResolveTransferInterruptFlag_(ctx), false);
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
      managers.client_service, managers.prompt_manager);
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
    managers.prompt_manager.Print(shell.second.first);
  }
  managers.prompt_manager.FmtPrint("Command exit with code {}",
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
  return AMInterface::ApplicationAdapters::RunVarGet(
      managers.var_service, managers.prompt_manager, varname);
}

void VarGetArgs::reset() { varname.clear(); }

ECM VarDefArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  return AMInterface::ApplicationAdapters::RunVarDef(
      managers.var_service, managers.prompt_manager, global, varname, value);
}

void VarDefArgs::reset() {
  global = false;
  varname.clear();
  value.clear();
}

ECM VarDelArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  return AMInterface::ApplicationAdapters::RunVarDel(
      managers.var_service, managers.prompt_manager, all, tokens);
}

void VarDelArgs::reset() {
  all = false;
  tokens.clear();
}

ECM VarLsArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  return AMInterface::ApplicationAdapters::RunVarLs(
      managers.var_service, managers.prompt_manager, sections);
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
      managers.transfer_service, managers.prompt_manager,
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
      managers.transfer_service, managers.prompt_manager,
      ResolveTransferInterruptFlag_(ctx));
  return AMApplication::TaskWorkflow::ExecuteTaskShow(
      gateway, ids, BuildTaskSessionMode_(ctx));
}

void TaskShowArgs::reset() { ids.clear(); }

ECM TaskInspectArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_manager,
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
      managers.transfer_service, managers.prompt_manager,
      ResolveTransferInterruptFlag_(ctx));
  return AMApplication::TaskWorkflow::ExecuteTaskThread(
      gateway, num, BuildTaskSessionMode_(ctx));
}

void TaskThreadArgs::reset() { num = -1; }

ECM TaskCacheAddArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_manager,
      ResolveTransferInterruptFlag_(ctx));
  auto build = BuildTransferArgsFromCli_(
      managers.client_service, managers.var_service, srcs, output, false,
      overwrite, no_mkdir, clone, include_special, resume,
      ResolveTransferInterruptFlag_(ctx));
  if (!isok(build.rcm)) {
    return build.rcm;
  }

  auto result = AMApplication::TaskWorkflow::ExecuteJobCacheAdd(
      gateway, build.build_args, BuildTaskSessionMode_(ctx));
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
      managers.transfer_service, managers.prompt_manager,
      ResolveTransferInterruptFlag_(ctx));
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
      managers.transfer_service, managers.prompt_manager,
      ResolveTransferInterruptFlag_(ctx));
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
      managers.transfer_service, managers.prompt_manager,
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
      managers.transfer_service, managers.prompt_manager,
      ResolveTransferInterruptFlag_(ctx));
  auto result = AMApplication::TaskWorkflow::ExecuteJobCacheQuery(
      gateway, indices, BuildTaskSessionMode_(ctx));
  return result.rcm;
}

void TaskUserSetArgs::reset() { indices.clear(); }

ECM TaskEntryArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_manager,
      ResolveTransferInterruptFlag_(ctx));
  return AMApplication::TaskWorkflow::ExecuteTaskEntryQuery(
      gateway, ids, BuildTaskSessionMode_(ctx));
}

void TaskEntryArgs::reset() { ids.clear(); }

ECM TaskControlArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  AMInterface::ApplicationAdapters::TaskGateway gateway(
      managers.transfer_service, managers.prompt_manager,
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
      managers.transfer_service, managers.prompt_manager,
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


