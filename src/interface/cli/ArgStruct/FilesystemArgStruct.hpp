#pragma once

#include "domain/filesystem/FileSystemModel.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include "interface/cli/ArgStruct/CommonHelpers.hpp"
#include <algorithm>
#include <string>
#include <vector>

namespace AMInterface::cli {
namespace filesystem_arg_detail {
using PathTarget = AMDomain::filesystem::PathTarget;
using TransferConfirmPolicy = AMInterface::transfer::TransferConfirmPolicy;
constexpr char kQuotedDashShellCmdSentinel = '\x1D';

inline std::string DecodeQuotedDashShellCmd(const std::string &raw) {
  if (!raw.empty() && raw.front() == kQuotedDashShellCmdSentinel) {
    return raw.substr(1);
  }
  return raw;
}

inline ECM ResolveTransferEndpoint(const CLIServices &managers,
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
      managers.interfaces.filesystem_interface_service->SplitRawTarget(token);
  if (!(split_result.rcm)) {
    return split_result.rcm;
  }
  *out_endpoint = std::move(split_result.data);
  return OK;
}

struct TransferCliBuildResult {
  ECM rcm = OK;
  std::vector<AMDomain::transfer::UserTransferSet> transfer_sets = {};
  bool suffix_async = false;
};

inline TransferCliBuildResult BuildTransferArgsFromCli(
    const CLIServices &managers, const std::vector<std::string> &raw_srcs,
    const std::string &raw_output, bool accept_ampersand_suffix, bool overwrite,
    bool no_mkdir, bool clone, bool include_special, bool resume) {
  TransferCliBuildResult out = {};

  std::vector<std::string> src_tokens = raw_srcs;
  managers.interfaces.var_interface_service->VSubstitutePathLike(src_tokens);
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
  managers.interfaces.var_interface_service->VSubstitutePathLike(output_token);
  output_token = AMStr::Strip(output_token);
  std::vector<std::string> normalized_src_tokens = {};
  std::string normalized_dst_token = {};
  if (output_token.empty()) {
    if (src_tokens.size() == 1) {
      normalized_src_tokens = {src_tokens.front()};
      normalized_dst_token = ".";
    } else if (src_tokens.size() == 2) {
      normalized_src_tokens = {src_tokens.front()};
      normalized_dst_token = src_tokens.back();
    } else {
      out.rcm =
          Err(EC::InvalidArg, "", "",
              "cp with 3+ paths requires --output to specify destination");
      return out;
    }
  } else {
    normalized_src_tokens = src_tokens;
    normalized_dst_token = output_token;
  }

  std::vector<PathTarget> src_endpoints = {};
  src_endpoints.reserve(normalized_src_tokens.size());
  for (const auto &token : normalized_src_tokens) {
    PathTarget endpoint = {};
    ECM resolve_rcm = ResolveTransferEndpoint(managers, token, &endpoint);
    if (!(resolve_rcm)) {
      out.rcm = resolve_rcm;
      return out;
    }
    src_endpoints.push_back(std::move(endpoint));
  }

  PathTarget dst_endpoint = {};
  ECM dst_rcm =
      ResolveTransferEndpoint(managers, normalized_dst_token, &dst_endpoint);
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

inline TransferConfirmPolicy
BuildTransferConfirmPolicy(const CliRunContext &ctx, bool quiet) {
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

} // namespace filesystem_arg_detail

struct StatArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemStatArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    managers.interfaces.var_interface_service->VSubstitutePathLike(
        arg.raw_paths);
    return managers.interfaces.filesystem_interface_service->Stat(arg);
  }
  void reset() override { request = {}; }
};

struct LsArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemLsArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    managers.interfaces.var_interface_service->VSubstitutePathLike(
        arg.raw_path);
    return managers.interfaces.filesystem_interface_service->Ls(arg);
  }
  void reset() override { request = {}; }
};

struct SizeArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemGetSizeArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    managers.interfaces.var_interface_service->VSubstitutePathLike(
        arg.raw_paths);
    return managers.interfaces.filesystem_interface_service->GetSize(arg);
  }
  void reset() override { request = {}; }
};

struct FindArgs : BaseArgStruct {
  std::string path = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    std::string resolved = path;
    managers.interfaces.var_interface_service->VSubstitutePathLike(resolved);
    AMInterface::filesystem::FilesystemFindArg arg = {};
    arg.raw_path = resolved;
    return managers.interfaces.filesystem_interface_service->Find(arg);
  }
  void reset() override { path.clear(); }
};

struct MkdirArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemMkdirsArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    managers.interfaces.var_interface_service->VSubstitutePathLike(
        arg.raw_paths);
    return managers.interfaces.filesystem_interface_service->Mkdirs(arg);
  }
  void reset() override { request = {}; }
};

struct RmArgs : BaseArgStruct {
  std::vector<std::string> paths = {};
  bool permanent = false;
  bool quiet = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto resolved = paths;
    managers.interfaces.var_interface_service->VSubstitutePathLike(resolved);
    if (permanent) {
      AMInterface::filesystem::FilesystemPermanentRemoveArg arg = {};
      arg.targets = resolved;
      arg.quiet = quiet;
      return managers.interfaces.filesystem_interface_service->PermanentRemove(
          arg);
    }
    AMInterface::filesystem::FilesystemSafermArg arg = {};
    arg.targets = resolved;
    return managers.interfaces.filesystem_interface_service->Saferm(arg);
  }
  void reset() override {
    paths.clear();
    permanent = false;
    quiet = false;
  }
};

struct TreeArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemTreeArg request = {};
  bool include_special = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    managers.interfaces.var_interface_service->VSubstitutePathLike(
        arg.raw_path);
    arg.ignore_special_file = !include_special;
    return managers.interfaces.filesystem_interface_service->Tree(arg);
  }
  void reset() override {
    request = {};
    include_special = false;
  }
};

struct RealpathArgs : BaseArgStruct {
  std::string path = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::filesystem::FilesystemRealpathArg arg = {};
    arg.raw_path = path;
    managers.interfaces.var_interface_service->VSubstitutePathLike(
        arg.raw_path);
    return managers.interfaces.filesystem_interface_service->Realpath(arg);
  }
  void reset() override { path.clear(); }
};

struct RttArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemTestRTTArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.filesystem_interface_service->TestRTT(request);
  }
  void reset() override { request = {}; }
};

struct ClearArgs : BaseArgStruct {
  bool all = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    managers.interfaces.prompt_io_manager->ClearScreen(all);
    return OK;
  }
  void reset() override { all = false; }
};

struct CpArgs : BaseArgStruct {
  std::vector<std::string> srcs = {};
  std::string output = {};
  int timeout_ms = -1;
  bool overwrite = false;
  bool no_mkdir = false;
  bool clone = false;
  bool include_special = false;
  bool resume = false;
  bool quiet = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    auto build = filesystem_arg_detail::BuildTransferArgsFromCli(
        managers, srcs, output, true, overwrite, no_mkdir, clone,
        include_special, resume);
    if (!(build.rcm)) {
      return build.rcm;
    }

    AMInterface::transfer::TransferRunArg arg = {};
    arg.transfer_sets = std::move(build.transfer_sets);
    arg.quiet = quiet;
    arg.run_async = ctx.async || build.suffix_async;
    arg.timeout_ms = timeout_ms;
    arg.confirm_policy =
        filesystem_arg_detail::BuildTransferConfirmPolicy(ctx, quiet);
    const auto component =
        ControlComponent(ctx.task_control_token, arg.timeout_ms);
    return managers.interfaces.transfer_service->Transfer(arg, component);
  }
  void reset() override {
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
};

struct MoveArgs : BaseArgStruct {
  std::string src = {};
  std::string dst = {};
  bool force = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    std::string src_token = src;
    std::string dst_token = dst;
    managers.interfaces.var_interface_service->VSubstitutePathLike(src_token);
    managers.interfaces.var_interface_service->VSubstitutePathLike(dst_token);

    src_token = AMStr::Strip(src_token);
    if (src_token.empty()) {
      return Err(EC::InvalidArg, "", "src", "mv requires one source path");
    }

    AMInterface::filesystem::FilesystemMoveArg arg = {};
    arg.target = src_token;
    arg.dst = AMStr::Strip(dst_token);
    arg.mkdir = true;
    arg.overwrite = force;
    return managers.interfaces.filesystem_interface_service->Move(arg);
  }
  void reset() override {
    src.clear();
    dst.clear();
    force = false;
  }
};

struct CloneArgs : BaseArgStruct {
  std::string src = {};
  std::string dst = {};
  std::string async_suffix = {};
  bool overwrite = false;
  bool resume = false;
  bool quiet = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    std::vector<std::string> raw_srcs = {src};
    const std::string suffix = AMStr::Strip(async_suffix);
    if (!suffix.empty()) {
      if (suffix != "&") {
        return Err(EC::InvalidArg, "", "", "clone async suffix must be '&'");
      }
      raw_srcs.push_back(suffix);
    }
    auto build = filesystem_arg_detail::BuildTransferArgsFromCli(
        managers, raw_srcs, dst, true, overwrite, false, true, false, resume);
    if (!(build.rcm)) {
      return build.rcm;
    }

    AMInterface::transfer::TransferRunArg arg = {};
    arg.transfer_sets = std::move(build.transfer_sets);
    arg.quiet = quiet;
    arg.run_async = ctx.async || build.suffix_async;
    arg.timeout_ms = -1;
    arg.confirm_policy =
        filesystem_arg_detail::BuildTransferConfirmPolicy(ctx, quiet);
    const auto component =
        ControlComponent(ctx.task_control_token, arg.timeout_ms);
    return managers.interfaces.transfer_service->Transfer(arg, component);
  }
  void reset() override {
    src.clear();
    dst.clear();
    async_suffix.clear();
    overwrite = false;
    resume = false;
    quiet = false;
  }
};

struct WgetArgs : BaseArgStruct {
  std::string src = {};
  std::string dst = {};
  std::string username = {};
  std::string password = {};
  std::string bear_token = {};
  std::string proxy = {};
  std::string sproxy = {};
  int redirect_times = -1;
  int timeout_ms = -1;
  bool resume = false;
  bool overwrite = false;
  bool quiet = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    std::string src_token = src;
    std::string dst_token = dst;
    managers.interfaces.var_interface_service->VSubstitutePathLike(src_token);
    managers.interfaces.var_interface_service->VSubstitutePathLike(dst_token);

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
      AMDomain::filesystem::PathTarget dst_target = {};
      ECM dst_rcm = filesystem_arg_detail::ResolveTransferEndpoint(
          managers, dst_token, &dst_target);
      if (!(dst_rcm)) {
        return dst_rcm;
      }
      arg.dst_target = std::move(dst_target);
    }

    arg.resume = resume;
    arg.overwrite = overwrite;
    arg.quiet = quiet;
    arg.username = username;
    arg.password = password;
    arg.bear_token = bear_token;
    arg.proxy = proxy;
    arg.https_proxy = sproxy;
    arg.redirect_times = redirect_times;
    arg.run_async = ctx.async || suffix_async;
    arg.timeout_ms = timeout_ms;
    arg.confirm_policy =
        filesystem_arg_detail::BuildTransferConfirmPolicy(ctx, quiet);

    const auto component =
        ControlComponent(ctx.task_control_token, arg.timeout_ms);
    return managers.interfaces.transfer_service->HttpGet(arg, component);
  }
  void reset() override {
    src.clear();
    dst.clear();
    username.clear();
    password.clear();
    bear_token.clear();
    proxy.clear();
    sproxy.clear();
    redirect_times = -1;
    timeout_ms = -1;
    resume = false;
    overwrite = false;
    quiet = false;
  }
};

struct SftpArgs : BaseArgStruct {
  std::vector<std::string> targets = {};
  AMInterface::client::ProtocolConnectRequest request = [] {
    AMInterface::client::ProtocolConnectRequest req = {};
    req.port = 22;
    return req;
  }();
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    if (targets.empty() || targets.size() > 2) {
      return Err(EC::InvalidArg, "", "",
                 "sftp requires user@host or nickname user@host");
    }
    auto req = request;
    if (targets.size() == 2) {
      req.nickname = targets[0];
      req.user_at_host = targets[1];
    } else {
      req.user_at_host = targets[0];
    }
    ECM rcm = managers.interfaces.client_interface_service->ConnectSftp(req);
    if (!(rcm)) {
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
    }
    argstruct_common::SetEnterInteractive(ctx, rcm);
    return rcm;
  }
  void reset() override {
    targets.clear();
    request = {};
    request.port = 22;
  }
};

struct FtpArgs : BaseArgStruct {
  std::vector<std::string> targets = {};
  AMInterface::client::ProtocolConnectRequest request = [] {
    AMInterface::client::ProtocolConnectRequest req = {};
    req.port = 21;
    return req;
  }();
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    if (targets.empty() || targets.size() > 2) {
      return Err(EC::InvalidArg, "", "",
                 "ftp requires user@host or nickname user@host");
    }

    auto req = request;
    if (targets.size() == 2) {
      req.nickname = targets[0];
      req.user_at_host = targets[1];
    } else {
      req.user_at_host = targets[0];
    }
    ECM rcm = managers.interfaces.client_interface_service->ConnectFtp(req);
    if (!(rcm)) {
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
    }
    argstruct_common::SetEnterInteractive(ctx, (rcm));
    return rcm;
  }
  void reset() override {
    targets.clear();
    request = {};
    request.port = 21;
  }
};

struct LocalArgs : BaseArgStruct {
  std::vector<std::string> targets = {};
  AMInterface::client::ProtocolConnectRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    if (targets.size() > 1) {
      return Err(EC::InvalidArg, "", "", "local accepts at most one nickname");
    }
    auto req = request;
    if (!targets.empty()) {
      req.nickname = targets[0];
    }
    ECM rcm = managers.interfaces.client_interface_service->ConnectLocal(req);
    if (!(rcm)) {
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
    }
    argstruct_common::SetEnterInteractive(ctx, rcm);
    return rcm;
  }
  void reset() override {
    targets.clear();
    request = {};
  }
};

struct CdArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemCdArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    managers.interfaces.var_interface_service->VSubstitutePathLike(
        arg.raw_path);
    ECM rcm = managers.interfaces.filesystem_interface_service->Cd(arg);
    argstruct_common::SetEnterInteractive(ctx, (rcm));
    return rcm;
  }
  void reset() override { request = {}; }
};

struct ConnectArgs : BaseArgStruct {
  AMInterface::client::ConnectRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    ECM rcm = managers.interfaces.client_interface_service->Connect(request);
    argstruct_common::SetEnterInteractive(ctx, (rcm));
    return rcm;
  }
  void reset() override { request = {}; }
};

struct CmdArgs : BaseArgStruct {
  int timeout_ms = -1;
  AMInterface::terminal::TerminalShellRunArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    const std::string command = AMStr::Strip(
        filesystem_arg_detail::DecodeQuotedDashShellCmd(request.cmd));
    if (command.empty()) {
      return Err(EC::InvalidArg, "", "", "cmd cannot be empty");
    }
    if (timeout_ms == 0) {
      return Err(EC::InvalidArg, "", "", "timeout_ms cannot be 0");
    }
    auto arg = request;
    arg.cmd = command;
    arg.max_time_s =
        timeout_ms < 0 ? -1 : std::max(1, (timeout_ms + 999) / 1000);
    return managers.interfaces.terminal_interface_service->ShellRun(arg);
  }
  void reset() override {
    timeout_ms = -1;
    request = {};
  }
};

struct TerminalArgs : BaseArgStruct {
  AMInterface::terminal::TerminalLaunchArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    arg.target = AMStr::Strip(arg.target);
    return managers.interfaces.terminal_interface_service->LaunchTerminal(arg);
  }
  void reset() override { request = {}; }
};

struct TermAddArgs : BaseArgStruct {
  AMInterface::terminal::TerminalAddArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    for (auto &nickname : arg.nicknames) {
      nickname = AMStr::Strip(nickname);
    }
    return managers.interfaces.terminal_interface_service->AddTerminal(arg);
  }
  void reset() override { request = {}; }
};

struct TermListArgs : BaseArgStruct {
  AMInterface::terminal::TerminalListArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.terminal_interface_service->ListTerminals(
        request);
  }
  void reset() override { request = {}; }
};

struct TermRemoveArgs : BaseArgStruct {
  AMInterface::terminal::TerminalRemoveArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    for (auto &nickname : arg.nicknames) {
      nickname = AMStr::Strip(nickname);
    }
    return managers.interfaces.terminal_interface_service->RemoveTerminal(arg);
  }
  void reset() override { request = {}; }
};

struct TermClearArgs : BaseArgStruct {
  AMInterface::terminal::TerminalClearArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.terminal_interface_service->ClearTerminals(
        request);
  }
  void reset() override { request = {}; }
};

struct ChannelAddArgs : BaseArgStruct {
  AMInterface::terminal::ChannelAddArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    arg.target = AMStr::Strip(arg.target);
    return managers.interfaces.terminal_interface_service->AddChannel(arg);
  }
  void reset() override { request = {}; }
};

struct ChannelListArgs : BaseArgStruct {
  AMInterface::terminal::ChannelListArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    return managers.interfaces.terminal_interface_service->ListChannels(arg);
  }
  void reset() override { request = {}; }
};

struct ChannelRemoveArgs : BaseArgStruct {
  AMInterface::terminal::ChannelRemoveArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    arg.target = AMStr::Strip(arg.target);
    return managers.interfaces.terminal_interface_service->RemoveChannel(arg);
  }
  void reset() override { request = {}; }
};

struct ChannelRenameArgs : BaseArgStruct {
  AMInterface::terminal::ChannelRenameArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    arg.src = AMStr::Strip(arg.src);
    arg.dst = AMStr::Strip(arg.dst);
    return managers.interfaces.terminal_interface_service->RenameChannel(arg);
  }
  void reset() override { request = {}; }
};

struct ChannelClearArgs : BaseArgStruct {
  AMInterface::terminal::ChannelClearArg request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    auto arg = request;
    arg.nickname = AMStr::Strip(arg.nickname);
    return managers.interfaces.terminal_interface_service->ClearChannels(arg);
  }
  void reset() override { request = {}; }
};

struct BashArgs : BaseArgStruct {
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)managers;
    argstruct_common::SetEnterInteractive(ctx, true);
    return OK;
  }
  void reset() override {}
};

struct ExitArgs : BaseArgStruct {
  bool force = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)managers;
    argstruct_common::SetRequestExit(ctx, true);
    argstruct_common::SetSkipLoopExitCallbacks(ctx, force);
    return OK;
  }
  void reset() override { force = false; }
};

} // namespace AMInterface::cli
