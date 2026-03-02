#include "AMCLI/CLIArg.hpp"
#include "AMCLI/Completer/Proxy.hpp"
#include <iostream>

CliManagers &CliManagers::Instance() {
  static CliManagers instance;
  return instance;
}

CliRunContext &CliRunContext::Instance() {
  static CliRunContext instance;
  return instance;
}

namespace {
void SetEnterInteractive_(const CliRunContext &ctx, bool value) {
  if (ctx.enter_interactive) {
    *ctx.enter_interactive = value;
  }
}

void SetRequestExit_(const CliRunContext &ctx, bool value) {
  if (ctx.request_exit) {
    *ctx.request_exit = value;
  }
}

void SetSkipLoopExitCallbacks_(const CliRunContext &ctx, bool value) {
  if (ctx.skip_loop_exit_callbacks) {
    *ctx.skip_loop_exit_callbacks = value;
  }
}

void PrintRunError_(const ECM &rcm) {
  if (rcm.first != EC::Success && !rcm.second.empty()) {
    std::cerr << rcm.second << std::endl;
  }
}

CR RunShellCommandViaFilesystem_(AMFileSystem &filesystem,
                                 const std::string &command, int timeout_ms) {
  return filesystem.ShellRun(command, timeout_ms, TaskControlToken::Instance());
}

ECM ValidateConfigAddNickname_(const std::string &raw,
                               std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  std::string value = AMStr::Strip(raw);
  std::string err_msg;
  EC err_code = EC::InvalidArg;
  if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Nickname, value,
                                       &value, &err_msg, true, true,
                                       &err_code)) {
    return Err(err_code, err_msg);
  }
  if (AMStr::lowercase(value) == "local") {
    return Err(EC::InvalidArg, "Nickname 'local' is reserved");
  }
  if (AMHostManager::Instance().HostExists(value)) {
    return Err(EC::InvalidArg, "Nickname already exists");
  }
  *normalized = value;
  return Ok();
}

ECM ResolveConfigAddNickname_(const std::string &arg_nickname,
                              std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  const std::string seeded = AMStr::Strip(arg_nickname);
  if (!seeded.empty()) {
    return ValidateConfigAddNickname_(seeded, normalized);
  }

  AMPromptManager &prompt = AMPromptManager::Instance();
  auto checker = [](const std::string &text) -> bool {
    const std::string candidate = AMStr::Strip(text);
    if (candidate.empty()) {
      return true;
    }
    std::string normalized;
    ECM rcm = ValidateConfigAddNickname_(candidate, &normalized);
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
    ECM rcm = ValidateConfigAddNickname_(input, normalized);
    if (isok(rcm)) {
      return Ok();
    }
    prompt.ErrorFormat(rcm);
  }
}

ECM ValidateConfigProfileNickname_(const std::string &raw,
                                   std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  std::string value = AMStr::Strip(raw);
  if (value.empty()) {
    return Err(EC::InvalidArg, "empty profile nickname");
  }
  if (!configkn::ValidateNickname(value)) {
    return Err(EC::InvalidArg, "invalid profile nickname");
  }
  if (!AMHostManager::Instance().HostExists(value)) {
    return Err(EC::HostConfigNotFound,
               AMStr::fmt("host nickname not found: {}", value));
  }
  *normalized = value;
  return Ok();
}

ECM ResolveConfigProfileNickname_(const std::string &arg_nickname,
                                  std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  const std::string seeded = AMStr::Strip(arg_nickname);
  if (!seeded.empty()) {
    return ValidateConfigProfileNickname_(seeded, normalized);
  }

  AMHostManager &host_manager = AMHostManager::Instance();
  AMPromptManager &prompt = AMPromptManager::Instance();
  std::vector<std::string> candidates = host_manager.ListNames();
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
    ECM rcm = ValidateConfigProfileNickname_(input, normalized);
    if (isok(rcm)) {
      return Ok();
    }
    prompt.ErrorFormat(rcm);
  }
}

std::string SubstitutePathLikeArg_(const std::string &raw) {
  return VarCLISet::Instance().SubstitutePathLike(raw);
}

std::vector<std::string>
SubstitutePathLikeArgs_(const std::vector<std::string> &raw) {
  std::vector<std::string> out = raw;
  VarCLISet::Instance().SubstitutePathLike(&out);
  return out;
}

ECM EnsureInteractive_(const CliRunContext &ctx) {
  const bool interactive =
      ctx.enforce_interactive ||
      (ctx.is_interactive &&
       ctx.is_interactive->load(std::memory_order_relaxed));
  if (interactive) {
    return {EC::Success, ""};
  }
  const std::string name =
      ctx.command_name.empty() ? std::string("Command") : ctx.command_name;
  return {EC::OperationUnsupported,
          AMStr::fmt("{} not supported in Non-Interactive mode", name)};
}

} // namespace

ECM CliManagers::Init() {
  ECM rcm = signal_monitor.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = config_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = prompt_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = host_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = var_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = log_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = client_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = transfer_manager.Init();
  if (!isok(rcm)) {
    return rcm;
  }
  return filesystem.Init();
}

ECM ConfigLsArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  AMHostManager &host_manager = AMHostManager::Instance();
  return host_manager.List(detail);
}

void ConfigLsArgs::reset() { detail = false; }

ECM ConfigKeysArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  AMHostManager &host_manager = AMHostManager::Instance();
  return host_manager.PrivateKeys(true).first;
}

void ConfigKeysArgs::reset() {}

ECM ConfigDataArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  AMHostManager &host_manager = AMHostManager::Instance();
  return host_manager.Src();
}

void ConfigDataArgs::reset() {}

ECM ConfigGetArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)ctx;
  auto &client_manager = managers.client_manager;
  std::vector<std::string> targets = nicknames;
  if (targets.empty()) {
    std::string current = client_manager.CurrentNickname();
    if (current.empty()) {
      current = "local";
    }
    targets.push_back(current);
  }
  AMHostManager &host_manager = AMHostManager::Instance();
  return host_manager.Query(targets);
}

void ConfigGetArgs::reset() { nicknames.clear(); }
ECM ConfigAddArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  std::string resolved;
  ECM rcm = ResolveConfigAddNickname_(nickname, &resolved);
  if (!isok(rcm)) {
    PrintRunError_(rcm);
    return rcm;
  }
  rcm = AMHostManager::Instance().Add(resolved);
  PrintRunError_(rcm);
  return rcm;
}

void ConfigAddArgs::reset() { nickname.clear(); }

ECM ConfigEditArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  return AMHostManager::Instance().Modify(nickname);
}

void ConfigEditArgs::reset() { nickname.clear(); }

ECM ConfigRenameArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  return AMHostManager::Instance().Rename(old_name, new_name);
}

void ConfigRenameArgs::reset() {
  old_name.clear();
  new_name.clear();
}

ECM ConfigRemoveArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  return AMHostManager::Instance().Delete(names);
}

void ConfigRemoveArgs::reset() { names.clear(); }

ECM ConfigSetArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  return AMHostManager::Instance().SetHostValue(nickname, attrname, value);
}

void ConfigSetArgs::reset() {
  nickname.clear();
  attrname.clear();
  value.clear();
}

ECM ConfigSaveArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  return AMHostManager::Instance().Save();
}

void ConfigSaveArgs::reset() {}

ECM ConfigProfileSetArgs::Run(const CliManagers &managers,
                              const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  std::string target;
  ECM rcm = ResolveConfigProfileNickname_(nickname, &target);
  if (!isok(rcm)) {
    PrintRunError_(rcm);
    return rcm;
  }
  rcm = AMPromptManager::Instance().Edit(target);
  PrintRunError_(rcm);
  return rcm;
}

void ConfigProfileSetArgs::reset() { nickname.clear(); }

ECM ProfileEditArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  ECM rcm = AMPromptManager::Instance().Edit(nickname);
  PrintRunError_(rcm);
  return rcm;
}

void ProfileEditArgs::reset() { nickname.clear(); }

ECM ProfileGetArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  ECM rcm = AMPromptManager::Instance().Get(nicknames);
  PrintRunError_(rcm);
  return rcm;
}

void ProfileGetArgs::reset() { nicknames.clear(); }

ECM StatArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  const std::vector<std::string> resolved = SubstitutePathLikeArgs_(paths);
  return managers.filesystem.stat(resolved, TaskControlToken::Instance());
}

void StatArgs::reset() { paths.clear(); }

ECM LsArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  auto &client_manager = managers.client_manager;
  auto &filesystem = managers.filesystem;
  std::string query_path = AMStr::Strip(SubstitutePathLikeArg_(path));
  if (query_path.empty()) {
    auto client = client_manager.CurrentClient();
    if (client) {
      query_path = client_manager.GetOrInitWorkdir(client);
    }
  }
  if (query_path.empty()) {
    query_path = "/";
  }
  ECM rcm = filesystem.ls(query_path, list_like, show_all,
                          TaskControlToken::Instance());
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
  const std::vector<std::string> resolved = SubstitutePathLikeArgs_(paths);
  ECM rcm = managers.filesystem.getsize(resolved, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void SizeArgs::reset() { paths.clear(); }

ECM FindArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  const std::string resolved = SubstitutePathLikeArg_(path);
  ECM rcm = managers.filesystem.find(resolved, SearchType::All,
                                     TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void FindArgs::reset() { path.clear(); }

ECM MkdirArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  const std::vector<std::string> resolved = SubstitutePathLikeArgs_(paths);
  ECM rcm = managers.filesystem.mkdir(resolved, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void MkdirArgs::reset() { paths.clear(); }

ECM RmArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  const std::vector<std::string> resolved = SubstitutePathLikeArgs_(paths);
  ECM rcm = managers.filesystem.rm(resolved, permanent, false, quiet,
                                   TaskControlToken::Instance());
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
  const std::string resolved = SubstitutePathLikeArg_(path);
  ECM rcm = managers.filesystem.walk(resolved, only_file, only_dir, show_all,
                                     !include_special, quiet,
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
  const std::string resolved = SubstitutePathLikeArg_(path);
  ECM rcm = managers.filesystem.tree(resolved, depth, only_dir, show_all,
                                     !include_special, quiet,
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
  const std::string resolved = SubstitutePathLikeArg_(path);
  return managers.filesystem.realpath(resolved, TaskControlToken::Instance());
}

void RealpathArgs::reset() { path.clear(); }

ECM RttArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  ECM rcm = managers.filesystem.TestRTT(times, TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
}

void RttArgs::reset() { times = 1; }

ECM ClearArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  AMPromptManager::Instance().ClearScreen(all);
  return {EC::Success, ""};
}

void ClearArgs::reset() { all = false; }

ECM CpArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)managers;
  std::vector<std::string> raw_srcs = srcs;
  bool run_async = false;
  if (!raw_srcs.empty() && raw_srcs.back() == "&") {
    run_async = true;
    raw_srcs.pop_back();
  }

  if (raw_srcs.empty()) {
    return {EC::InvalidArg, "cp requires at least one source"};
  }

  const std::vector<std::string> resolved_srcs =
      SubstitutePathLikeArgs_(raw_srcs);
  const std::string resolved_output = SubstitutePathLikeArg_(output);

  std::vector<std::string> transfer_srcs;
  std::string transfer_dst;
  if (resolved_output.empty()) {
    if (resolved_srcs.size() != 2) {
      return {EC::InvalidArg, "cp requires exactly 2 paths when "
                              "--output is omitted"};
    }
    transfer_srcs = {resolved_srcs.front()};
    transfer_dst = resolved_srcs.back();
  } else {
    transfer_srcs = resolved_srcs;
    transfer_dst = resolved_output;
  }

  UserTransferSet transfer_set;
  transfer_set.srcs = std::move(transfer_srcs);
  transfer_set.dst = std::move(transfer_dst);
  transfer_set.mkdir = !no_mkdir;
  transfer_set.overwrite = overwrite;
  transfer_set.clone = clone;
  transfer_set.ignore_special_file = !include_special;
  transfer_set.resume = resume;

  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  ECM rcm = (ctx.async || run_async)
                ? transfer_manager.transfer_async({transfer_set}, quiet,
                                                  TaskControlToken::Instance())
                : transfer_manager.transfer({transfer_set}, quiet,
                                            TaskControlToken::Instance());
  PrintRunError_(rcm);
  return rcm;
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
  auto &filesystem = managers.filesystem;
  std::string user_at_host;
  std::string nickname;
  if (targets.size() == 1) {
    user_at_host = targets[0];
  } else if (targets.size() == 2) {
    nickname = targets[0];
    user_at_host = targets[1];
  } else {
    return {EC::InvalidArg, "sftp requires user@host"};
  }
  if (user_at_host.find('@') == std::string::npos) {
    return {EC::InvalidArg, "Invalid user@host format"};
  }

  ECM rcm = filesystem.sftp(nickname, user_at_host, port, "", keyfile,
                            TaskControlToken::Instance());
  PrintRunError_(rcm);
  SetEnterInteractive_(ctx, rcm.first == EC::Success);
  return rcm;
}

void SftpArgs::reset() {
  targets.clear();
  port = 22;
  keyfile.clear();
}

ECM FtpArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  auto &filesystem = managers.filesystem;
  std::string user_at_host;
  std::string nickname;
  if (targets.size() == 1) {
    user_at_host = targets[0];
  } else if (targets.size() == 2) {
    nickname = targets[0];
    user_at_host = targets[1];
  } else {
    return {EC::InvalidArg, "ftp requires user@host"};
  }
  if (user_at_host.find('@') == std::string::npos) {
    return {EC::InvalidArg, "Invalid user@host format"};
  }

  ECM rcm = filesystem.ftp(nickname, user_at_host, port, "", keyfile,
                           TaskControlToken::Instance());
  PrintRunError_(rcm);
  SetEnterInteractive_(ctx, rcm.first == EC::Success);
  return rcm;
}

void FtpArgs::reset() {
  targets.clear();
  port = 21;
  keyfile.clear();
}

ECM ClientsArgs::Run(const CliManagers &managers,
                     const CliRunContext &ctx) const {
  (void)ctx;
  return managers.filesystem.print_clients(detail,
                                           TaskControlToken::Instance());
}

void ClientsArgs::reset() { detail = false; }

ECM CheckArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)ctx;
  return managers.filesystem.check(nicknames, detail,
                                   TaskControlToken::Instance());
}

void CheckArgs::reset() {
  nicknames.clear();
  detail = false;
}

ECM ChangeClientArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  auto &filesystem = managers.filesystem;
  const bool is_interactive =
      ctx.enforce_interactive ||
      (ctx.is_interactive &&
       ctx.is_interactive->load(std::memory_order_relaxed));
  if (is_interactive) {
    return filesystem.change_client(nickname, TaskControlToken::Instance());
  }
  ECM rcm =
      filesystem.connect(nickname, false, TaskControlToken::Instance(), true);
  SetEnterInteractive_(ctx, rcm.first == EC::Success);
  return rcm;
}

void ChangeClientArgs::reset() { nickname.clear(); }

ECM DisconnectArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  (void)ctx;
  std::string joined;
  for (size_t i = 0; i < nicknames.size(); ++i) {
    if (i > 0) {
      joined += " ";
    }
    joined += nicknames[i];
  }
  return managers.filesystem.remove_client(joined);
}

void DisconnectArgs::reset() { nicknames.clear(); }

ECM CdArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  const std::string resolved = SubstitutePathLikeArg_(path);
  ECM rcm =
      managers.filesystem.cd(resolved, TaskControlToken::Instance(), false);
  if (rcm.first == EC::Success) {
    SetEnterInteractive_(ctx, true);
  }
  return rcm;
}

void CdArgs::reset() { path.clear(); }

ECM ConnectArgs::Run(const CliManagers &managers,
                     const CliRunContext &ctx) const {
  auto &filesystem = managers.filesystem;
  const bool is_interactive =
      ctx.enforce_interactive ||
      (ctx.is_interactive &&
       ctx.is_interactive->load(std::memory_order_relaxed));
  const std::vector<std::string> targets =
      AMStr::UniqueTargetsKeepOrder(nicknames);
  if (targets.empty()) {
    ECM rcm = {EC::InvalidArg, "connect requires at "
                               "least one nickname"};
    PrintRunError_(rcm);
    return rcm;
  }

  ECM last = {EC::Success, ""};
  bool any_success = false;
  for (const auto &nickname : targets) {
    if (nickname.empty()) {
      ECM rcm = {EC::InvalidArg, "Empty nickname"};
      PrintRunError_(rcm);
      last = rcm;
      continue;
    }
    ECM rcm = filesystem.connect(nickname, force, TaskControlToken::Instance(),
                                 false);
    if (rcm.first != EC::Success) {
      PrintRunError_(rcm);
      last = rcm;
      continue;
    }
    any_success = true;
  }

  if (!is_interactive && any_success) {
    ECM rcm = filesystem.change_client("local", TaskControlToken::Instance());
    if (rcm.first != EC::Success) {
      PrintRunError_(rcm);
      if (last.first == EC::Success) {
        last = rcm;
      }
    }
    SetEnterInteractive_(ctx, rcm.first == EC::Success);
  }
  return last;
}

void ConnectArgs::reset() {
  nicknames.clear();
  force = false;
}

ECM CmdArgs::Run(const CliManagers &managers, const CliRunContext &ctx) const {
  (void)ctx;
  if (timeout_ms <= 0) {
    ECM rcm = {EC::InvalidArg, "timeout_ms must be > 0"};
    PrintRunError_(rcm);
    return rcm;
  }

  const std::string command = AMStr::Strip(cmd_str);
  if (command.empty()) {
    ECM rcm = {EC::InvalidArg, "cmd_str cannot be empty"};
    PrintRunError_(rcm);
    return rcm;
  }

  CR shell_result =
      RunShellCommandViaFilesystem_(managers.filesystem, command, timeout_ms);
  if (shell_result.first.first != EC::Success) {
    PrintRunError_(shell_result.first);
    return shell_result.first;
  }

  const std::string &msg = shell_result.second.first;
  if (!msg.empty()) {
    AMPromptManager::Instance().Print(msg);
  }
  AMPromptManager::Instance().FmtPrint("Command exit with code {}",
                                       shell_result.second.second);
  return shell_result.first;
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
  (void)managers;
  (void)ctx;
  return VarCLISet::Instance().QueryByName(varname);
}

void VarGetArgs::reset() { varname.clear(); }

ECM VarDefArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  return VarCLISet::Instance().DefineVar(global, varname, value);
}

void VarDefArgs::reset() {
  global = false;
  varname.clear();
  value.clear();
}

ECM VarDelArgs::Run(const CliManagers &managers,
                    const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  std::string section = "";
  std::string varname = "";
  if (tokens.size() == 1) {
    varname = tokens[0];
  } else if (tokens.size() == 2) {
    section = tokens[0];
    varname = tokens[1];
  } else {
    return Err(EC::InvalidArg, "var del requires: "
                               "[$section] $varname");
  }
  return VarCLISet::Instance().DeleteVarByCli(all, section, varname);
}

void VarDelArgs::reset() {
  all = false;
  tokens.clear();
}

ECM VarLsArgs::Run(const CliManagers &managers,
                   const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  return VarCLISet::Instance().ListVars(sections);
}

void VarLsArgs::reset() { sections.clear(); }

ECM CompleteCacheClearArgs::Run(const CliManagers &managers,
                                const CliRunContext &ctx) const {
  (void)managers;
  (void)ctx;
  auto *completer = AMCompleter::Active();
  if (!completer) {
    return {EC::InvalidArg, "Completer is not "
                            "active"};
  }
  completer->ClearCache();
  AMPromptManager::Instance().Print("Completion cache "
                                    "cleared.");
  return {EC::Success, ""};
}

void CompleteCacheClearArgs::reset() {}

ECM TaskListArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  return transfer_manager.List(pending, suspend, finished, conducting,
                               TaskControlToken::Instance());
}

void TaskListArgs::reset() {
  pending = false;
  suspend = false;
  finished = false;
  conducting = false;
}

ECM TaskShowArgs::Run(const CliManagers &managers,
                      const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  return AMTransferManager::Instance().Show(ids, TaskControlToken::Instance());
}

void TaskShowArgs::reset() { ids.clear(); }

ECM TaskInspectArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  if (id.empty() && !set && !entry) {
    return {EC::Success, ""};
  }
  if (id.empty()) {
    return {EC::InvalidArg, "Task id required"};
  }

  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  ECM rcm = {EC::Success, ""};
  if (set || entry) {
    if (set) {
      rcm = transfer_manager.InspectTransferSets(id);
      if (rcm.first != EC::Success) {
        return rcm;
      }
    }
    if (entry) {
      rcm = transfer_manager.InspectTaskEntries(id);
    }
  } else {
    rcm = transfer_manager.Inspect(id, false, false);
  }
  return rcm;
}

void TaskInspectArgs::reset() {
  id.clear();
  set = false;
  entry = false;
}

ECM TaskThreadArgs::Run(const CliManagers &managers,
                        const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  return AMTransferManager::Instance().Thread(num);
}

void TaskThreadArgs::reset() { num = -1; }

ECM TaskCacheAddArgs::Run(const CliManagers &managers,
                          const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  if (srcs.empty()) {
    return {EC::InvalidArg, "job add "
                            "requires at least "
                            "one source"};
  }

  const std::vector<std::string> resolved_srcs = SubstitutePathLikeArgs_(srcs);
  const std::string resolved_output = SubstitutePathLikeArg_(output);

  std::vector<std::string> transfer_srcs;
  std::string transfer_dst;
  if (resolved_output.empty()) {
    if (resolved_srcs.size() != 2) {
      return {EC::InvalidArg, "job add "
                              "requires "
                              "exactly 2 paths "
                              "when --output "
                              "is "
                              "omitted"};
    }
    transfer_srcs = {resolved_srcs.front()};
    transfer_dst = resolved_srcs.back();
  } else {
    transfer_srcs = resolved_srcs;
    transfer_dst = resolved_output;
  }

  UserTransferSet transfer_set;
  transfer_set.srcs = std::move(transfer_srcs);
  transfer_set.dst = std::move(transfer_dst);
  transfer_set.mkdir = !no_mkdir;
  transfer_set.overwrite = overwrite;
  transfer_set.clone = clone;
  transfer_set.ignore_special_file = !include_special;
  transfer_set.resume = resume;

  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  size_t index = transfer_manager.SubmitTransferSet(transfer_set);
  AMPromptManager::Instance().FmtPrint("✅ job add {}",
                                       std::to_string(index));
  return {EC::Success, ""};
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
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  std::vector<size_t> deduped = AMJson::VectorDedup(indices);
  const size_t removed = transfer_manager.DeleteTransferSets(deduped);
  if (removed < deduped.size()) {
    return {EC::InvalidArg, "Cache index "
                            "not found"};
  }
  for (size_t index : deduped) {
    AMPromptManager::Instance().FmtPrint("✅ job rm "
                                         "{}",
                                         std::to_string(index));
  }
  return {EC::Success, ""};
}

void TaskCacheRmArgs::reset() { indices.clear(); }

ECM TaskCacheClearArgs::Run(const CliManagers &managers,
                            const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  AMTransferManager::Instance().ClearCachedTransferSets();
  AMPromptManager::Instance().Print("✅ job "
                                    "cleared");
  return {EC::Success, ""};
}

void TaskCacheClearArgs::reset() {}

ECM TaskCacheSubmitArgs::Run(const CliManagers &managers,
                             const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  bool suffix_async = false;
  if (!async_suffix.empty()) {
    if (async_suffix != "&") {
      return Err(EC::InvalidArg, "job "
                                 "submit: "
                                 "trailing "
                                 "arg must be "
                                 "&");
    }
    suffix_async = true;
  }
  return AMTransferManager::Instance().SubmitCachedTransferSets(
      quiet, TaskControlToken::Instance(), is_async || suffix_async);
}

void TaskCacheSubmitArgs::reset() {
  is_async = false;
  quiet = false;
  async_suffix.clear();
}

ECM TaskUserSetArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  std::vector<size_t> deduped = AMJson::VectorDedup(indices);
  if (deduped.empty()) {
    deduped = transfer_manager.ListTransferSetIds();
  }
  ECM last = {EC::Success, ""};
  for (size_t index : deduped) {
    ECM rcm = transfer_manager.QueryCachedUserSet(index);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

void TaskUserSetArgs::reset() { indices.clear(); }

ECM TaskEntryArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  ECM last = {EC::Success, ""};
  for (const auto &entry_id : ids) {
    ECM rcm = transfer_manager.QuerySetEntry(entry_id);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

void TaskEntryArgs::reset() { ids.clear(); }

ECM TaskControlArgs::Run(const CliManagers &managers,
                         const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  switch (action) {
  case TaskControlArgs::Action::Terminate:
    return transfer_manager.Terminate(ids);
  case TaskControlArgs::Action::Pause:
    return transfer_manager.Pause(ids);
  case TaskControlArgs::Action::Resume:
    return transfer_manager.Resume(ids);
  default:
    return {EC::InvalidArg, "Unknown "
                            "task "
                            "control "
                            "action"};
  }
}

void TaskControlArgs::reset() {
  ids.clear();
}

ECM TaskRetryArgs::Run(const CliManagers &managers,
                       const CliRunContext &ctx) const {
  ECM ready = EnsureInteractive_(ctx);
  if (ready.first != EC::Success) {
    return ready;
  }
  (void)managers;
  ECM rcm = AMTransferManager::Instance().retry(id, is_async, quiet, indices);
  PrintRunError_(rcm);
  return rcm;
}

void TaskRetryArgs::reset() {
  id.clear();
  is_async = false;
  quiet = false;
  indices.clear();
}
