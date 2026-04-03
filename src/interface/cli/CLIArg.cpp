#include "interface/cli/CLIArg.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/prompt/Prompt.hpp"
#include <algorithm>

namespace AMInterface::cli {
namespace {
using PathTarget = AMDomain::filesystem::PathTarget;
using TransferConfirmPolicy = AMInterface::transfer::TransferConfirmPolicy;

void SetEnterInteractive_(const CliRunContext &ctx, bool value) {
  ctx.enter_interactive = value;
}

void SetRequestExit_(const CliRunContext &ctx, bool value) {
  ctx.request_exit = value;
}

void SetSkipLoopExitCallbacks_(const CliRunContext &ctx, bool value) {
  ctx.skip_loop_exit_callbacks = value;
}

/**
 * @brief Resolve one raw transfer token into explicit endpoint payload.
 */
ECM ResolveTransferEndpoint_(const CLIServices &managers,
                             const std::string &raw,
                             PathTarget *out_endpoint) {
  if (!out_endpoint) {
    return Err(EC::InvalidArg, "", "", "null transfer endpoint output");
  }

  const std::string token = AMStr::Strip(raw);
  if (token.empty()) {
    return Err(EC::InvalidArg, "", "", "Transfer path is empty");
  }

  auto split_result =
      managers.filesystem_interface_service->SplitRawTarget(token);
  if (!(split_result.rcm)) {
    return split_result.rcm;
  }
  *out_endpoint = std::move(split_result.data);
  return OK;
}

/**
 * @brief Build explicit transfer args from raw CLI cp/job inputs.
 */
struct TransferCliBuildResult {
  ECM rcm = OK;
  std::vector<AMDomain::transfer::UserTransferSet> transfer_sets = {};
  bool suffix_async = false;
};

TransferCliBuildResult BuildTransferArgsFromCli_(
    const CLIServices &managers, const std::vector<std::string> &raw_srcs,
    const std::string &raw_output, bool accept_ampersand_suffix, bool overwrite,
    bool no_mkdir, bool clone, bool include_special, bool resume) {
  TransferCliBuildResult out = {};

  std::vector<std::string> src_tokens = raw_srcs;
  managers.var_interface_service->VSubstitutePathLike(src_tokens);
  if (accept_ampersand_suffix && !src_tokens.empty() &&
      src_tokens.back() == "&") {
    out.suffix_async = true;
    src_tokens.pop_back();
  }

  if (src_tokens.empty()) {
    out.rcm = Err(EC::InvalidArg, "", "", "cp requires at least one source");
    return out;
  }

  std::string output_token = raw_output;
  managers.var_interface_service->VSubstitutePathLike(output_token);
  output_token = AMStr::Strip(output_token);
  std::vector<std::string> normalized_src_tokens = {};
  std::string normalized_dst_token = {};
  if (output_token.empty()) {
    if (src_tokens.size() != 2) {
      out.rcm = Err(EC::InvalidArg, "", "", "cp requires exactly 2 paths when --output is omitted");
      return out;
    }
    normalized_src_tokens = {src_tokens.front()};
    normalized_dst_token = src_tokens.back();
  } else {
    normalized_src_tokens = src_tokens;
    normalized_dst_token = output_token;
  }

  std::vector<PathTarget> src_endpoints = {};
  src_endpoints.reserve(normalized_src_tokens.size());
  for (const auto &token : normalized_src_tokens) {
    PathTarget endpoint = {};
    ECM resolve_rcm = ResolveTransferEndpoint_(managers, token, &endpoint);
    if (!(resolve_rcm)) {
      out.rcm = resolve_rcm;
      return out;
    }
    src_endpoints.push_back(std::move(endpoint));
  }

  PathTarget dst_endpoint = {};
  ECM dst_rcm =
      ResolveTransferEndpoint_(managers, normalized_dst_token, &dst_endpoint);
  if (!(dst_rcm)) {
    out.rcm = dst_rcm;
    return out;
  }

  AMDomain::transfer::UserTransferSet set = {};
  set.srcs = std::move(src_endpoints);
  set.dst = std::move(dst_endpoint);
  set.mkdir = !no_mkdir;
  set.overwrite = overwrite;
  set.clone = clone;
  set.ignore_special_file = !include_special;
  set.resume = resume;
  out.transfer_sets.push_back(std::move(set));
  return out;
}

/**
 * @brief Resolve explicit transfer confirm policy from run context.
 */
TransferConfirmPolicy BuildTransferConfirmPolicy_(const CliRunContext &ctx,
                                                  bool quiet) {
  if (quiet) {
    return TransferConfirmPolicy::AutoApprove;
  }
  const bool is_interactive =
      ctx.enforce_interactive ||
      (ctx.is_interactive &&
       ctx.is_interactive->load(std::memory_order_relaxed));
  if (is_interactive) {
    return TransferConfirmPolicy::RequireConfirm;
  }
  return TransferConfirmPolicy::DenyIfConfirmNeeded;
}

ECM UnsupportedCommand_(AMInterface::prompt::AMPromptIOManager &prompt,
                        const std::string &message) {
  (void)prompt;
  const ECM rcm = Err(EC::OperationUnsupported, "", "", message);
  return rcm;
}

} // namespace

ECM ConfigLsArgs::Run(const CLIServices &managers,
                      const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->ListHosts(detail);
}

void ConfigLsArgs::reset() { detail = false; }

ECM ConfigKeysArgs::Run(const CLIServices &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  std::string header = "";
  for (const auto key : AMDomain::host::ConRequest::FieldNames) {
    header += AMStr::ToString(key) + "\t";
  }
  for (const auto key : AMDomain::host::ClientMetaData::FieldNames) {
    header += AMStr::ToString(key) + "\t";
  }
  managers.prompt_io_manager->Print(header);
  return OK;
}

void ConfigKeysArgs::reset() {}

ECM ConfigDataArgs::Run(const CLIServices &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->ListHosts(true);
}

void ConfigDataArgs::reset() {}

ECM ConfigGetArgs::Run(const CLIServices &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->ListHosts(request.nicknames, true);
}

void ConfigGetArgs::reset() { request = {}; }

ECM ConfigAddArgs::Run(const CLIServices &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->AddHost(nickname);
}

void ConfigAddArgs::reset() { nickname.clear(); }

ECM ConfigEditArgs::Run(const CLIServices &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->ModifyHost(nickname);
}

void ConfigEditArgs::reset() { nickname.clear(); }

ECM ConfigRenameArgs::Run(const CLIServices &managers,
                          const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->RenameHost(old_name, new_name);
}

void ConfigRenameArgs::reset() {
  old_name.clear();
  new_name.clear();
}

ECM ConfigRemoveArgs::Run(const CLIServices &managers,
                          const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->RemoveHosts(names);
}

void ConfigRemoveArgs::reset() { names.clear(); }

ECM ConfigSetArgs::Run(const CLIServices &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->SetHostValue(request);
}

void ConfigSetArgs::reset() { request = {}; }

ECM ConfigSaveArgs::Run(const CLIServices &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  ECM rcm = managers.config_service->FlushDirtyParticipants();
  if (!(rcm)) {
    return rcm;
  }
  return managers.config_service->DumpAll(false);
}

void ConfigSaveArgs::reset() {}

ECM ConfigProfileSetArgs::Run(const CLIServices &managers,
                              const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::client::ChangeClientRequest request = {};
  request.nickname = AMStr::Strip(nickname).empty() ? "local" : nickname;
  request.quiet = false;
  return managers.client_interface_service->ChangeClient(request);
}

void ConfigProfileSetArgs::reset() { nickname.clear(); }

ECM ProfileEditArgs::Run(const CLIServices &managers,
                         const CliRunContext &ctx) const {
  (void)ctx;
  return managers.prompt_io_manager->Edit(nickname);
}

void ProfileEditArgs::reset() { nickname.clear(); }

ECM ProfileGetArgs::Run(const CLIServices &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  return managers.prompt_io_manager->Get(nicknames);
}

void ProfileGetArgs::reset() { nicknames.clear(); }

ECM StatArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  auto arg = request;
  managers.var_interface_service->VSubstitutePathLike(arg.raw_paths);
  return managers.filesystem_interface_service->Stat(arg);
}

void StatArgs::reset() { request = {}; }

ECM LsArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  auto arg = request;
  managers.var_interface_service->VSubstitutePathLike(arg.raw_path);
  return managers.filesystem_interface_service->Ls(arg);
}

void LsArgs::reset() { request = {}; }

ECM SizeArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  auto arg = request;
  managers.var_interface_service->VSubstitutePathLike(arg.raw_paths);
  return managers.filesystem_interface_service->GetSize(arg);
}

void SizeArgs::reset() { request = {}; }

ECM FindArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  std::string resolved = path;
  managers.var_interface_service->VSubstitutePathLike(resolved);
  AMInterface::filesystem::FilesystemFindArg arg = {};
  arg.raw_path = resolved;
  return managers.filesystem_interface_service->Find(arg);
}

void FindArgs::reset() { path.clear(); }

ECM MkdirArgs::Run(const CLIServices &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  auto arg = request;
  managers.var_interface_service->VSubstitutePathLike(arg.raw_paths);
  return managers.filesystem_interface_service->Mkdirs(arg);
}

void MkdirArgs::reset() { request = {}; }

ECM RmArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  auto resolved = paths;
  managers.var_interface_service->VSubstitutePathLike(resolved);
  if (permanent) {
    AMInterface::filesystem::FilesystemPermanentRemoveArg arg = {};
    arg.targets = resolved;
    arg.quiet = quiet;
    return managers.filesystem_interface_service->PermanentRemove(arg);
  }
  AMInterface::filesystem::FilesystemSafermArg arg = {};
  arg.targets = resolved;
  return managers.filesystem_interface_service->Saferm(arg);
}

void RmArgs::reset() {
  paths.clear();
  permanent = false;
  quiet = false;
}

ECM TreeArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  auto arg = request;
  managers.var_interface_service->VSubstitutePathLike(arg.raw_path);
  arg.ignore_special_file = !include_special;
  return managers.filesystem_interface_service->Tree(arg);
}

void TreeArgs::reset() {
  request = {};
  include_special = false;
}

ECM RealpathArgs::Run(const CLIServices &managers,
                      const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::filesystem::FilesystemRealpathArg arg = {};
  arg.raw_path = path;
  managers.var_interface_service->VSubstitutePathLike(arg.raw_path);
  return managers.filesystem_interface_service->Realpath(arg);
}

void RealpathArgs::reset() { path.clear(); }

ECM RttArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  return managers.filesystem_interface_service->TestRTT(request);
}

void RttArgs::reset() { request = {}; }

ECM ClearArgs::Run(const CLIServices &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  managers.prompt_io_manager->ClearScreen(all);
  return OK;
}

void ClearArgs::reset() { all = false; }

ECM CpArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  auto build =
      BuildTransferArgsFromCli_(managers, srcs, output, true, overwrite,
                                no_mkdir, clone, include_special, resume);
  if (!(build.rcm)) {
    return build.rcm;
  }

  AMInterface::transfer::TransferRunArg arg = {};
  arg.transfer_sets = std::move(build.transfer_sets);
  arg.quiet = quiet;
  arg.run_async = ctx.async || build.suffix_async;
  arg.timeout_ms = timeout_ms;
  arg.confirm_policy = BuildTransferConfirmPolicy_(ctx, quiet);
  const auto component = AMDomain::client::ClientControlComponent(
      ctx.task_control_token, arg.timeout_ms);
  return managers.transfer_service->Transfer(arg, component);
}

void CpArgs::reset() {
  srcs.clear();
  output.clear();
  timeout_ms = -1;
  overwrite = false;
  no_mkdir = false;
  clone = false;
  include_special = false;
  resume = false;
  quiet = false;
}

ECM CloneArgs::Run(const CLIServices &managers,
                   const CliRunContext &ctx) const {
  std::vector<std::string> raw_srcs = {src};
  const std::string suffix = AMStr::Strip(async_suffix);
  if (!suffix.empty()) {
    if (suffix != "&") {
      return Err(EC::InvalidArg, "", "", "clone async suffix must be '&'");
    }
    raw_srcs.push_back(suffix);
  }
  auto build =
      BuildTransferArgsFromCli_(managers, raw_srcs, dst, true, overwrite,
                                false, true, false, resume);
  if (!(build.rcm)) {
    return build.rcm;
  }

  AMInterface::transfer::TransferRunArg arg = {};
  arg.transfer_sets = std::move(build.transfer_sets);
  arg.quiet = quiet;
  arg.run_async = ctx.async || build.suffix_async;
  arg.timeout_ms = -1;
  arg.confirm_policy = BuildTransferConfirmPolicy_(ctx, quiet);
  const auto component = AMDomain::client::ClientControlComponent(
      ctx.task_control_token, arg.timeout_ms);
  return managers.transfer_service->Transfer(arg, component);
}

void CloneArgs::reset() {
  src.clear();
  dst.clear();
  async_suffix.clear();
  overwrite = false;
  resume = false;
  quiet = false;
}

ECM WgetArgs::Run(const CLIServices &managers,
                  const CliRunContext &ctx) const {
  std::string src_token = src;
  std::string dst_token = dst;
  managers.var_interface_service->VSubstitutePathLike(src_token);
  managers.var_interface_service->VSubstitutePathLike(dst_token);

  AMInterface::transfer::HttpGetArg arg = {};
  arg.src_url = AMStr::Strip(src_token);
  if (arg.src_url.empty()) {
    return Err(EC::InvalidArg, "", "", "wget requires one source URL");
  }

  dst_token = AMStr::Strip(dst_token);
  bool suffix_async = false;
  if (dst_token == "&") {
    suffix_async = true;
    dst_token.clear();
  }
  if (!dst_token.empty()) {
    PathTarget dst_target = {};
    ECM dst_rcm = ResolveTransferEndpoint_(managers, dst_token, &dst_target);
    if (!(dst_rcm)) {
      return dst_rcm;
    }
    arg.dst_target = std::move(dst_target);
  }

  arg.resume = resume;
  arg.overwrite = overwrite;
  arg.quiet = quiet;
  arg.bear_token = bear_token;
  arg.proxy = proxy;
  arg.https_proxy = sproxy;
  arg.redirect_times = redirect_times;
  arg.run_async = ctx.async || suffix_async;
  arg.timeout_ms = timeout_ms;
  arg.confirm_policy = BuildTransferConfirmPolicy_(ctx, quiet);

  const auto component = AMDomain::client::ClientControlComponent(
      ctx.task_control_token, arg.timeout_ms);
  return managers.transfer_service->HttpGet(arg, component);
}

void WgetArgs::reset() {
  src.clear();
  dst.clear();
  bear_token.clear();
  proxy.clear();
  sproxy.clear();
  redirect_times = -1;
  timeout_ms = -1;
  resume = false;
  overwrite = false;
  quiet = false;
}

ECM SftpArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  if (targets.empty() || targets.size() > 2) {
    return Err(EC::InvalidArg, "", "", "sftp requires user@host or nickname user@host");
  }
  auto request = this->request;
  if (targets.size() == 2) {
    request.nickname = targets[0];
    request.user_at_host = targets[1];
  } else {
    request.user_at_host = targets[0];
  }
  ECM rcm = managers.client_interface_service->ConnectSftp(request);
  SetEnterInteractive_(ctx, rcm);
  return rcm;
}

void SftpArgs::reset() {
  targets.clear();
  request = {};
  request.port = 22;
}

ECM FtpArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  if (targets.empty() || targets.size() > 2) {
    return Err(EC::InvalidArg, "", "", "ftp requires user@host or nickname user@host");
  }

  auto request = this->request;
  if (targets.size() == 2) {
    request.nickname = targets[0];
    request.user_at_host = targets[1];
  } else {
    request.user_at_host = targets[0];
  }
  ECM rcm = managers.client_interface_service->ConnectFtp(request);
  SetEnterInteractive_(ctx, (rcm));
  return rcm;
}

void FtpArgs::reset() {
  targets.clear();
  request = {};
  request.port = 21;
}

ECM ClientsArgs::Run(const CLIServices &managers,
                     const CliRunContext &ctx) const {
  (void)ctx;
  auto request = this->request;
  request.check = false;
  return managers.client_interface_service->ListClients(request);
}

void ClientsArgs::reset() { request = {}; }

ECM CheckArgs::Run(const CLIServices &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->CheckClients(request);
}

void CheckArgs::reset() { request = {}; }

ECM ChangeClientArgs::Run(const CLIServices &managers,
                          const CliRunContext &ctx) const {
  auto request = this->request;
  if (AMStr::Strip(request.nickname).empty()) {
    request.nickname = "local";
  }
  ECM rcm = managers.client_interface_service->ChangeClient(request);
  SetEnterInteractive_(ctx, (rcm));
  return rcm;
}

void ChangeClientArgs::reset() { request = {}; }

ECM DisconnectArgs::Run(const CLIServices &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  return managers.client_interface_service->RemoveClients(request);
}

void DisconnectArgs::reset() { request = {}; }

ECM CdArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  auto arg = request;
  managers.var_interface_service->VSubstitutePathLike(arg.raw_path);
  ECM rcm = managers.filesystem_interface_service->Cd(arg);
  SetEnterInteractive_(ctx, (rcm));
  return rcm;
}

void CdArgs::reset() { request = {}; }

ECM ConnectArgs::Run(const CLIServices &managers,
                     const CliRunContext &ctx) const {
  ECM rcm = managers.client_interface_service->Connect(request);
  SetEnterInteractive_(ctx, (rcm));
  return rcm;
}

void ConnectArgs::reset() { request = {}; }

ECM CmdArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)ctx;
  const std::string command = AMStr::Strip(request.cmd);
  if (command.empty()) {
    return Err(EC::InvalidArg, "", "", "cmd cannot be empty");
  }
  if (timeout_ms == 0) {
    return Err(EC::InvalidArg, "", "", "timeout_ms cannot be 0");
  }
  auto arg = request;
  arg.cmd = command;
  arg.max_time_s = timeout_ms < 0 ? -1 : std::max(1, (timeout_ms + 999) / 1000);
  return managers.filesystem_interface_service->ShellRun(arg);
}

void CmdArgs::reset() {
  timeout_ms = -1;
  request = {};
}

ECM BashArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)managers;
  SetEnterInteractive_(ctx, true);
  return OK;
}

void BashArgs::reset() {}

ECM ExitArgs::Run(const CLIServices &managers, const CliRunContext &ctx) const {
  (void)managers;
  SetRequestExit_(ctx, true);
  SetSkipLoopExitCallbacks_(ctx, force);
  return OK;
}

void ExitArgs::reset() { force = false; }

ECM VarGetArgs::Run(const CLIServices &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  return managers.var_interface_service->QueryAndPrintVar(varname);
}

void VarGetArgs::reset() { varname.clear(); }

ECM VarDefArgs::Run(const CLIServices &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  return managers.var_interface_service->DefineVar(global, varname, value);
}

void VarDefArgs::reset() {
  global = false;
  varname.clear();
  value.clear();
}

ECM VarDelArgs::Run(const CLIServices &managers,
                    const CliRunContext &ctx) const {
  (void)ctx;
  return managers.var_interface_service->DeleteVar(all, tokens);
}

void VarDelArgs::reset() {
  all = false;
  tokens.clear();
}

ECM VarLsArgs::Run(const CLIServices &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  return managers.var_interface_service->ListVars(sections);
}

void VarLsArgs::reset() { sections.clear(); }

ECM CompleteCacheClearArgs::Run(const CLIServices &managers,
                                const CliRunContext &ctx) const {
  (void)ctx;
  return UnsupportedCommand_(
      managers.prompt_io_manager,
      "Completion cache clear is deprecated in current service mode");
}

void CompleteCacheClearArgs::reset() {}

ECM TaskListArgs::Run(const CLIServices &managers,
                      const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::transfer::TransferTaskListArg arg = {};
  arg.pending = pending;
  arg.suspend = suspend;
  arg.finished = finished;
  arg.conducting = conducting;
  return managers.transfer_service->TaskList(arg);
}

void TaskListArgs::reset() {
  pending = false;
  suspend = false;
  finished = false;
  conducting = false;
}

ECM TaskShowArgs::Run(const CLIServices &managers,
                      const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::transfer::TransferTaskShowArg arg = {};
  arg.ids = ids;
  return managers.transfer_service->TaskShow(arg);
}

void TaskShowArgs::reset() { ids.clear(); }

ECM TaskInspectArgs::Run(const CLIServices &managers,
                         const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::transfer::TransferTaskInspectArg arg = {};
  arg.id = id;
  if (!set && !entry) {
    arg.show_sets = true;
    arg.show_entries = true;
  } else {
    arg.show_sets = set;
    arg.show_entries = entry;
  }
  return managers.transfer_service->TaskInspect(arg);
}

void TaskInspectArgs::reset() {
  id = 0;
  set = false;
  entry = false;
}

ECM TaskThreadArgs::Run(const CLIServices &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  (void)num;
  return UnsupportedCommand_(managers.prompt_io_manager,
                             "task thread is deprecated; configure transfer "
                             "pool via runtime settings");
}

void TaskThreadArgs::reset() { num = -1; }

ECM TaskEntryArgs::Run(const CLIServices &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::transfer::TransferTaskShowArg arg = {};
  arg.ids = ids;
  return managers.transfer_service->TaskShow(arg);
}

void TaskEntryArgs::reset() { ids.clear(); }

ECM TaskControlArgs::Run(const CLIServices &managers,
                         const CliRunContext &ctx) const {
  (void)ctx;
  AMInterface::transfer::TransferTaskControlArg arg = {};
  arg.ids = ids;
  arg.timeout_ms = 5000;
  switch (action) {
  case TaskControlArgs::Action::Terminate:
    return managers.transfer_service->TaskTerminate(arg);
  case TaskControlArgs::Action::Pause:
    return managers.transfer_service->TaskPause(arg);
  case TaskControlArgs::Action::Resume:
    return managers.transfer_service->TaskResume(arg);
  default:
    return Err(EC::InvalidArg, "", "", "Unknown task control action");
  }
}

void TaskControlArgs::reset() { ids.clear(); }

ECM TaskRetryArgs::Run(const CLIServices &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  (void)id;
  (void)is_async;
  (void)quiet;
  (void)indices;
  return UnsupportedCommand_(
      managers.prompt_io_manager,
      "task retry is deprecated in current service mode");
}

void TaskRetryArgs::reset() {
  id.clear();
  is_async = false;
  quiet = false;
  indices.clear();
}

} // namespace AMInterface::cli
