#pragma once
#include "AMBase/CommonTools.hpp"
#include "AMCLI/Completer/Proxy.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/FileSystem.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Prompt.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "AMManager/Transfer.hpp"
#include "AMManager/Var.hpp"
#include "CLI/CLI.hpp"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <variant>
#include <vector>

/**
 * @brief Manager references for CLI dispatch.
 */
struct CliManagers {
  std::shared_ptr<AMFileSystem> filesystem;
  std::shared_ptr<AMClientManager> client_manager;
  std::shared_ptr<AMConfigManager> config_manager;
};
/**
 * @brief Runtime context for invoking Args::Run.
 */
struct CliRunContext {
  bool async = false;
  bool enforce_interactive = false;
  std::string command_name;
  bool *enter_interactive = nullptr;
};

/**
 * @brief Set interactive-enter flag when the context carries a destination.
 */
inline void SetEnterInteractive_(const CliRunContext &ctx, bool value) {
  if (ctx.enter_interactive) {
    *ctx.enter_interactive = value;
  }
}

/**
 * @brief Print ECM error text to stderr when status is not success.
 */
inline void PrintRunError_(const ECM &rcm) {
  if (rcm.first != EC::Success && !rcm.second.empty()) {
    std::cerr << rcm.second << std::endl;
  }
}

/**
 * @brief Enforce interactive mode for task-like commands.
 */
inline ECM EnsureInteractive_(const CliRunContext &ctx) {
  if (ctx.enforce_interactive ||
      AMIsInteractive.load(std::memory_order_relaxed)) {
    return {EC::Success, ""};
  }
  const std::string name =
      ctx.command_name.empty() ? std::string("Command") : ctx.command_name;
  return {EC::OperationUnsupported,
          AMStr::amfmt("{} not supported in Non-Interactive mode", name)};
}

void ShowTaskInspectInfo();

/**
 * @brief CLI argument container for config ls.
 */
struct ConfigLsArgs {
  bool detail = false;
  /**
   * @brief Execute config ls with optional detail flag.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    AMHostManager &host_manager = AMHostManager::Instance();
    return host_manager.List(detail);
  }
  /**
   * @brief Reset config-ls arguments to defaults.
   */
  void reset() { detail = false; }
};

/**
 * @brief CLI argument container for config keys.
 */
struct ConfigKeysArgs {
  /**
   * @brief Execute config keys.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    AMHostManager &host_manager = AMHostManager::Instance();
    return host_manager.PrivateKeys(true).first;
  }
  /**
   * @brief Reset config-keys arguments to defaults.
   */
  void reset() {}
};

/**
 * @brief CLI argument container for config data.
 */
struct ConfigDataArgs {
  /**
   * @brief Execute config data.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    AMHostManager &host_manager = AMHostManager::Instance();
    return host_manager.Src();
  }
  /**
   * @brief Reset config-data arguments to defaults.
   */
  void reset() {}
};

/**
 * @brief CLI argument container for config get.
 */
struct ConfigGetArgs {
  std::vector<std::string> nicknames;
  /**
   * @brief Execute config get with optional nickname list.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    auto &client_manager = *managers.client_manager;
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
  /**
   * @brief Reset config-get arguments to defaults.
   */
  void reset() { nicknames.clear(); }
};

/**
 * @brief CLI argument container for config add.
 */
struct ConfigAddArgs {
  /**
   * @brief Execute config add.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    return AMHostManager::Instance().Add();
  }
  /**
   * @brief Reset config-add arguments to defaults.
   */
  void reset() {}
};

/**
 * @brief CLI argument container for config edit.
 */
struct ConfigEditArgs {
  std::string nickname;
  /**
   * @brief Execute config edit for a nickname.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    return AMHostManager::Instance().Modify(nickname);
  }
  /**
   * @brief Reset config-edit arguments to defaults.
   */
  void reset() { nickname.clear(); }
};

/**
 * @brief CLI argument container for config rename.
 */
struct ConfigRenameArgs {
  std::string old_name;
  std::string new_name;
  /**
   * @brief Execute config rename.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    return AMHostManager::Instance().Rename(old_name, new_name);
  }
  /**
   * @brief Reset config-rename arguments to defaults.
   */
  void reset() {
    old_name.clear();
    new_name.clear();
  }
};

/**
 * @brief CLI argument container for config remove.
 */
struct ConfigRemoveArgs {
  std::vector<std::string> names;
  /**
   * @brief Execute config remove for target names.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    return AMHostManager::Instance().Delete(names);
  }
  /**
   * @brief Reset config-remove arguments to defaults.
   */
  void reset() { names.clear(); }
};

/**
 * @brief CLI argument container for config set.
 */
struct ConfigSetArgs {
  std::string nickname;
  std::string attrname;
  std::string value;
  /**
   * @brief Execute config set for a host attribute.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    return AMHostManager::Instance().SetHostValue(nickname, attrname, value);
  }
  /**
   * @brief Reset config-set arguments to defaults.
   */
  void reset() {
    nickname.clear();
    attrname.clear();
    value.clear();
  }
};

/**
 * @brief CLI argument container for config save.
 */
struct ConfigSaveArgs {
  /**
   * @brief Execute config save.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    return AMHostManager::Instance().Save();
  }
  /**
   * @brief Reset config-save arguments to defaults.
   */
  void reset() {}
};

/**
 * @brief CLI argument container for stat.
 */
struct StatArgs {
  std::vector<std::string> paths;
  /**
   * @brief Execute stat for target paths.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    return managers.filesystem->stat(paths, amgif);
  }
  /**
   * @brief Reset stat arguments to defaults.
   */
  void reset() { paths.clear(); }
};

/**
 * @brief CLI argument container for ls.
 */
struct LsArgs {
  std::string path;
  bool list_like = false;
  bool show_all = false;
  /**
   * @brief Execute ls for a path or current workdir.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    auto &client_manager = *managers.client_manager;
    auto &filesystem = *managers.filesystem;
    std::string query_path = AMStr::Strip(path);
    if (query_path.empty()) {
      auto client = client_manager.CurrentClient();
      if (client) {
        query_path = client_manager.GetOrInitWorkdir(client);
      }
    }
    if (query_path.empty()) {
      query_path = "/";
    }
    ECM rcm = filesystem.ls(query_path, list_like, show_all, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset ls arguments to defaults.
   */
  void reset() {
    path.clear();
    list_like = false;
    show_all = false;
  }
};

/**
 * @brief CLI argument container for size.
 */
struct SizeArgs {
  std::vector<std::string> paths;
  /**
   * @brief Execute size for target paths.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    ECM rcm = managers.filesystem->getsize(paths, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset size arguments to defaults.
   */
  void reset() { paths.clear(); }
};

/**
 * @brief CLI argument container for find.
 */
struct FindArgs {
  std::string path;
  /**
   * @brief Execute find for a path.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    ECM rcm = managers.filesystem->find(path, SearchType::All, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset find arguments to defaults.
   */
  void reset() { path.clear(); }
};

/**
 * @brief CLI argument container for mkdir.
 */
struct MkdirArgs {
  std::vector<std::string> paths;
  /**
   * @brief Execute mkdir for target paths.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    ECM rcm = managers.filesystem->mkdir(paths, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset mkdir arguments to defaults.
   */
  void reset() { paths.clear(); }
};

/**
 * @brief CLI argument container for rm.
 */
struct RmArgs {
  std::vector<std::string> paths;
  bool permanent = false;
  bool quiet = false;
  /**
   * @brief Execute rm for target paths.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    ECM rcm = managers.filesystem->rm(paths, permanent, false, quiet, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset rm arguments to defaults.
   */
  void reset() {
    paths.clear();
    permanent = false;
    quiet = false;
  }
};

/**
 * @brief CLI argument container for walk.
 */
struct WalkArgs {
  std::string path;
  bool only_file = false;
  bool only_dir = false;
  bool show_all = false;
  bool include_special = false;
  bool quiet = false;
  /**
   * @brief Execute walk for a path.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    ECM rcm = managers.filesystem->walk(path, only_file, only_dir, show_all,
                                        !include_special, quiet, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset walk arguments to defaults.
   */
  void reset() {
    path.clear();
    only_file = false;
    only_dir = false;
    show_all = false;
    include_special = false;
    quiet = false;
  }
};

/**
 * @brief CLI argument container for tree.
 */
struct TreeArgs {
  std::string path;
  int depth = -1;
  bool only_dir = false;
  bool show_all = false;
  bool include_special = false;
  bool quiet = false;
  /**
   * @brief Execute tree for a path.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    ECM rcm = managers.filesystem->tree(path, depth, only_dir, show_all,
                                        !include_special, quiet, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset tree arguments to defaults.
   */
  void reset() {
    path.clear();
    depth = -1;
    only_dir = false;
    show_all = false;
    include_special = false;
    quiet = false;
  }
};

/**
 * @brief CLI argument container for realpath.
 */
struct RealpathArgs {
  std::string path;
  /**
   * @brief Execute realpath for a target path.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    return managers.filesystem->realpath(path, amgif);
  }
  /**
   * @brief Reset realpath arguments to defaults.
   */
  void reset() { path.clear(); }
};

/**
 * @brief CLI argument container for rtt.
 */
struct RttArgs {
  int times = 1;
  /**
   * @brief Execute rtt with sample count.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    ECM rcm = managers.filesystem->TestRTT(times, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset rtt arguments to defaults.
   */
  void reset() { times = 1; }
};

/**
 * @brief CLI argument container for clear.
 */
struct ClearArgs {
  bool all = false;
  /**
   * @brief Execute clear screen.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    AMPromptManager::Instance().ClearScreen(all);
    return {EC::Success, ""};
  }
  /**
   * @brief Reset clear arguments to defaults.
   */
  void reset() { all = false; }
};

/**
 * @brief CLI argument container for cp (transfer).
 */
struct CpArgs {
  std::vector<std::string> srcs;
  std::string output;
  bool overwrite = false;
  bool no_mkdir = false;
  bool clone = false;
  bool include_special = false;
  bool resume = false;
  bool quiet = false;
  /**
   * @brief Execute cp transfer.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    if (srcs.empty()) {
      return {EC::InvalidArg, "cp requires at least one source"};
    }

    std::vector<std::string> transfer_srcs;
    std::string transfer_dst;
    if (output.empty()) {
      if (srcs.size() != 2) {
        return {EC::InvalidArg,
                "cp requires exactly 2 paths when --output is omitted"};
      }
      transfer_srcs = {srcs.front()};
      transfer_dst = srcs.back();
    } else {
      transfer_srcs = srcs;
      transfer_dst = output;
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
    ECM rcm =
        ctx.async
            ? transfer_manager.transfer_async({transfer_set}, quiet, amgif)
            : transfer_manager.transfer({transfer_set}, quiet, amgif);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset cp arguments to defaults.
   */
  void reset() {
    srcs.clear();
    output.clear();
    overwrite = false;
    no_mkdir = false;
    clone = false;
    include_special = false;
    resume = false;
    quiet = false;
  }
};

/**
 * @brief CLI argument container for sftp.
 */
struct SftpArgs {
  std::vector<std::string> targets;
  int64_t port = 22;
  std::string keyfile;
  /**
   * @brief Execute sftp connection.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    auto &filesystem = *managers.filesystem;
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

    ECM rcm = filesystem.sftp(nickname, user_at_host, port, "", keyfile, amgif);
    PrintRunError_(rcm);
    *(ctx.enter_interactive) = rcm.first == EC::Success;
    return rcm;
  }
  /**
   * @brief Reset sftp arguments to defaults.
   */
  void reset() {
    targets.clear();
    port = 22;
    keyfile.clear();
  }
};

/**
 * @brief CLI argument container for ftp.
 */
struct FtpArgs {
  std::vector<std::string> targets;
  int64_t port = 21;
  std::string keyfile;
  /**
   * @brief Execute ftp connection.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    auto &filesystem = *managers.filesystem;
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

    ECM rcm = filesystem.ftp(nickname, user_at_host, port, "", keyfile, amgif);
    PrintRunError_(rcm);
    SetEnterInteractive_(ctx, rcm.first == EC::Success);
    return rcm;
  }
  /**
   * @brief Reset ftp arguments to defaults.
   */
  void reset() {
    targets.clear();
    port = 21;
    keyfile.clear();
  }
};

/**
 * @brief CLI argument container for clients.
 */
struct ClientsArgs {
  bool detail = false;
  /**
   * @brief Execute clients list.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    return managers.filesystem->print_clients(detail, amgif);
  }
  /**
   * @brief Reset clients arguments to defaults.
   */
  void reset() { detail = false; }
};

/**
 * @brief CLI argument container for check.
 */
struct CheckArgs {
  std::vector<std::string> nicknames;
  bool detail = false;
  /**
   * @brief Execute client check.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    return managers.filesystem->check(nicknames, detail, amgif);
  }
  /**
   * @brief Reset check arguments to defaults.
   */
  void reset() {
    nicknames.clear();
    detail = false;
  }
};

/**
 * @brief CLI argument container for ch.
 */
struct ChangeClientArgs {
  std::string nickname;
  /**
   * @brief Execute client change.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    auto &filesystem = *managers.filesystem;
    const bool is_interactive = ctx.enforce_interactive ||
                                AMIsInteractive.load(std::memory_order_relaxed);
    if (is_interactive) {
      return filesystem.change_client(nickname, amgif);
    }
    ECM rcm = filesystem.connect(nickname, false, amgif, true);
    SetEnterInteractive_(ctx, rcm.first == EC::Success);
    return rcm;
  }
  /**
   * @brief Reset change-client arguments to defaults.
   */
  void reset() { nickname.clear(); }
};

/**
 * @brief CLI argument container for disconnect.
 */
struct DisconnectArgs {
  std::vector<std::string> nicknames;
  /**
   * @brief Execute client disconnect.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)ctx;
    std::string joined;
    for (size_t i = 0; i < nicknames.size(); ++i) {
      if (i > 0) {
        joined += " ";
      }
      joined += nicknames[i];
    }
    return managers.filesystem->remove_client(joined);
  }
  /**
   * @brief Reset disconnect arguments to defaults.
   */
  void reset() { nicknames.clear(); }
};

/**
 * @brief CLI argument container for cd.
 */
struct CdArgs {
  std::string path;
  /**
   * @brief Execute cd.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM rcm = managers.filesystem->cd(path, amgif, false);
    if (rcm.first == EC::Success) {
      SetEnterInteractive_(ctx, true);
    }
    return rcm;
  }
  /**
   * @brief Reset cd arguments to defaults.
   */
  void reset() { path.clear(); }
};

/**
 * @brief CLI argument container for connect.
 */
struct ConnectArgs {
  std::string nickname;
  bool force = false;
  /**
   * @brief Execute connect.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    auto &filesystem = *managers.filesystem;
    const bool is_interactive = ctx.enforce_interactive ||
                                AMIsInteractive.load(std::memory_order_relaxed);
    ECM rcm = filesystem.connect(nickname, force, amgif, false);
    if (rcm.first != EC::Success) {
      PrintRunError_(rcm);
      return rcm;
    }
    if (!is_interactive) {
      rcm = filesystem.change_client("local", amgif);
      SetEnterInteractive_(ctx, rcm.first == EC::Success);
    }
    return rcm;
  }
  /**
   * @brief Reset connect arguments to defaults.
   */
  void reset() {
    nickname.clear();
    force = false;
  }
};

/**
 * @brief CLI argument container for bash.
 */
struct BashArgs {
  /**
   * @brief Enter interactive mode.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    SetEnterInteractive_(ctx, true);
    return {EC::Success, ""};
  }
  /**
   * @brief Reset bash arguments to defaults.
   */
  void reset() {}
};

/**
 * @brief CLI argument container for var.
 */
struct VarArgs {
  std::vector<std::string> tokens;
  /**
   * @brief Execute var query or assignment.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    AMVarManager &var_manager = AMVarManager::Instance();
    return var_manager.ExecuteVarTokens(tokens);
  }
  /**
   * @brief Reset var arguments to defaults.
   */
  void reset() { tokens.clear(); }
};

/**
 * @brief CLI argument container for del.
 */
struct DelArgs {
  std::vector<std::string> tokens;
  /**
   * @brief Execute delete for variable tokens.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    AMVarManager &var_manager = AMVarManager::Instance();
    return var_manager.ExecuteDelTokens(tokens);
  }
  /**
   * @brief Reset del arguments to defaults.
   */
  void reset() { tokens.clear(); }
};

/**
 * @brief CLI argument container for complete cache clear.
 */
struct CompleteCacheClearArgs {
  /**
   * @brief Execute completion cache clear.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    (void)managers;
    (void)ctx;
    auto *completer = AMCompleter::Active();
    if (!completer) {
      return {EC::InvalidArg, "Completer is not active"};
    }
    completer->ClearCache();
    AMPromptManager::Instance().Print("Completion cache cleared.");
    return {EC::Success, ""};
  }
  /**
   * @brief Reset completion cache clear arguments to defaults.
   */
  void reset() {}
};

/**
 * @brief CLI argument container for task list.
 */
struct TaskListArgs {
  bool pending = false;
  bool suspend = false;
  bool finished = false;
  bool conducting = false;
  /**
   * @brief Execute task list.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    return transfer_manager.List(pending, suspend, finished, conducting, amgif);
  }
  /**
   * @brief Reset task-list arguments to defaults.
   */
  void reset() {
    pending = false;
    suspend = false;
    finished = false;
    conducting = false;
  }
};

/**
 * @brief CLI argument container for task show.
 */
struct TaskShowArgs {
  std::vector<std::string> ids;
  /**
   * @brief Execute task show.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    return AMTransferManager::Instance().Show(ids, amgif);
  }
  /**
   * @brief Reset task-show arguments to defaults.
   */
  void reset() { ids.clear(); }
};

/**
 * @brief CLI argument container for task inspect.
 */
struct TaskInspectArgs {
  std::string id;
  bool set = false;
  bool entry = false;
  /**
   * @brief Execute task inspect.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    if (id.empty() && !set && !entry) {
      ShowTaskInspectInfo();
      return {EC::Success, ""};
    }
    if (id.empty()) {
      ShowTaskInspectInfo();
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
  /**
   * @brief Reset task-inspect arguments to defaults.
   */
  void reset() {
    id.clear();
    set = false;
    entry = false;
  }
};

/**
 * @brief CLI argument container for task thread.
 */
struct TaskThreadArgs {
  int num = -1;
  /**
   * @brief Execute task thread update/query.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    return AMTransferManager::Instance().Thread(num);
  }
  /**
   * @brief Reset task-thread arguments to defaults.
   */
  void reset() { num = -1; }
};

/**
 * @brief CLI argument container for task cache add.
 */
struct TaskCacheAddArgs {
  std::vector<std::string> srcs;
  std::string output;
  bool overwrite = false;
  bool no_mkdir = false;
  bool clone = false;
  bool include_special = false;
  bool resume = false;
  /**
   * @brief Execute task cache add.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    if (srcs.empty()) {
      return {EC::InvalidArg, "task cache add requires at least one source"};
    }

    std::vector<std::string> transfer_srcs;
    std::string transfer_dst;
    if (output.empty()) {
      if (srcs.size() != 2) {
        return {EC::InvalidArg,
                "task cache add requires exactly 2 paths when --output is "
                "omitted"};
      }
      transfer_srcs = {srcs.front()};
      transfer_dst = srcs.back();
    } else {
      transfer_srcs = srcs;
      transfer_dst = output;
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
    AMPromptManager::Instance().Print(
        AMStr::amfmt("✅ cache add {}", std::to_string(index)));
    return {EC::Success, ""};
  }
  /**
   * @brief Reset task-cache-add arguments to defaults.
   */
  void reset() {
    srcs.clear();
    output.clear();
    overwrite = false;
    no_mkdir = false;
    clone = false;
    include_special = false;
    resume = false;
  }
};

/**
 * @brief CLI argument container for task cache rm.
 */
struct TaskCacheRmArgs {
  std::vector<size_t> indices;
  /**
   * @brief Execute task cache remove.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    std::vector<size_t> deduped = VectorDedup(indices);
    const size_t removed = transfer_manager.DeleteTransferSets(deduped);
    if (removed < deduped.size()) {
      return {EC::InvalidArg, "Cache index not found"};
    }
    for (size_t index : deduped) {
      AMPromptManager::Instance().Print(
          AMStr::amfmt("✅ cache rm {}", std::to_string(index)));
    }
    return {EC::Success, ""};
  }
  /**
   * @brief Reset task-cache-rm arguments to defaults.
   */
  void reset() { indices.clear(); }
};

/**
 * @brief CLI argument container for task cache clear.
 */
struct TaskCacheClearArgs {
  /**
   * @brief Execute task cache clear.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    AMTransferManager::Instance().ClearCachedTransferSets();
    AMPromptManager::Instance().Print("✅ cache cleared");
    return {EC::Success, ""};
  }
  /**
   * @brief Reset task-cache-clear arguments to defaults.
   */
  void reset() {}
};

/**
 * @brief CLI argument container for task cache submit.
 */
struct TaskCacheSubmitArgs {
  bool is_async = false;
  bool quiet = false;
  /**
   * @brief Execute task cache submit.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    return AMTransferManager::Instance().SubmitCachedTransferSets(quiet, amgif,
                                                                  is_async);
  }
  /**
   * @brief Reset task-cache-submit arguments to defaults.
   */
  void reset() {
    is_async = false;
    quiet = false;
  }
};

/**
 * @brief CLI argument container for task userset.
 */
struct TaskUserSetArgs {
  std::vector<size_t> indices;
  /**
   * @brief Execute task userset query.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    std::vector<size_t> deduped = VectorDedup(indices);
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
  /**
   * @brief Reset task-userset arguments to defaults.
   */
  void reset() { indices.clear(); }
};

/**
 * @brief CLI argument container for task query.
 */
struct TaskEntryArgs {
  std::vector<std::string> ids;
  /**
   * @brief Execute task entry query.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
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
  /**
   * @brief Reset task-entry arguments to defaults.
   */
  void reset() { ids.clear(); }
};

/**
 * @brief CLI argument container for task control.
 */
struct TaskControlArgs {
  enum class Action { Terminate, Pause, Resume };
  std::vector<std::string> ids;
  Action action = Action::Terminate;
  /**
   * @brief Execute task control action.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
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
      return {EC::InvalidArg, "Unknown task control action"};
    }
  }
  /**
   * @brief Reset task-control arguments to defaults.
   */
  void reset() {
    ids.clear();
    action = Action::Terminate;
  }
};

/**
 * @brief CLI argument container for task retry (failed tasks).
 */
struct TaskRetryArgs {
  std::string id;
  bool is_async = false;
  bool quiet = false;
  std::vector<int> indices;
  /**
   * @brief Execute task retry.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const {
    ECM ready = EnsureInteractive_(ctx);
    if (ready.first != EC::Success) {
      return ready;
    }
    (void)managers;
    ECM rcm = AMTransferManager::Instance().retry(id, is_async, quiet, indices);
    PrintRunError_(rcm);
    return rcm;
  }
  /**
   * @brief Reset task-retry arguments to defaults.
   */
  void reset() {
    id.clear();
    is_async = false;
    quiet = false;
    indices.clear();
  }
};

/**
 * @brief Variant wrapper for selected parsed CLI argument payload.
 */
using CommonArg = std::variant<
    std::monostate, ConfigLsArgs, ConfigKeysArgs, ConfigDataArgs, ConfigGetArgs,
    ConfigAddArgs, ConfigEditArgs, ConfigRenameArgs, ConfigRemoveArgs,
    ConfigSetArgs, ConfigSaveArgs, StatArgs, LsArgs, SizeArgs, FindArgs,
    MkdirArgs, RmArgs, WalkArgs, TreeArgs, RealpathArgs, RttArgs, ClearArgs,
    CpArgs, SftpArgs, FtpArgs, ClientsArgs, CheckArgs, ChangeClientArgs,
    DisconnectArgs, CdArgs, ConnectArgs, BashArgs, VarArgs, DelArgs,
    CompleteCacheClearArgs, TaskListArgs, TaskShowArgs, TaskInspectArgs,
    TaskThreadArgs, TaskCacheAddArgs, TaskCacheRmArgs, TaskCacheClearArgs,
    TaskCacheSubmitArgs, TaskUserSetArgs, TaskEntryArgs, TaskControlArgs,
    TaskRetryArgs>;

/**
 * @brief Pool of all CLI argument structs.
 */
struct CliArgsPool {
  ConfigLsArgs config_ls;
  ConfigKeysArgs config_keys;
  ConfigDataArgs config_data;
  ConfigGetArgs config_get;
  ConfigAddArgs config_add;
  ConfigEditArgs config_edit;
  ConfigRenameArgs config_rn;
  ConfigRemoveArgs config_rm;
  ConfigSetArgs config_set;
  ConfigSaveArgs config_save;
  StatArgs stat;
  LsArgs ls;
  SizeArgs size;
  FindArgs find;
  MkdirArgs mkdir;
  RmArgs rm;
  WalkArgs walk;
  TreeArgs tree;
  RealpathArgs realpath;
  RttArgs rtt;
  ClearArgs clear;
  CpArgs cp;
  SftpArgs sftp;
  FtpArgs ftp;
  ClientsArgs clients;
  CheckArgs check;
  ChangeClientArgs ch;
  DisconnectArgs disconnect;
  CdArgs cd;
  ConnectArgs connect;
  BashArgs bash;
  VarArgs var;
  DelArgs del;
  CompleteCacheClearArgs complete_cache_clear;
  TaskListArgs task_list;
  TaskShowArgs task_show;
  TaskInspectArgs task_inspect;
  TaskThreadArgs task_thread;
  TaskCacheAddArgs task_cache_add;
  TaskCacheRmArgs task_cache_rm;
  TaskCacheClearArgs task_cache_clear;
  TaskCacheSubmitArgs task_cache_submit;
  TaskUserSetArgs task_userset;
  TaskEntryArgs task_entry;
  TaskControlArgs task_terminate;
  TaskControlArgs task_pause;
  TaskControlArgs task_resume;
  TaskRetryArgs task_retry;
  CommonArg common_arg = std::monostate{};
};

/**
 * @brief CLI subcommand handles.
 */
struct CliCommands {
  CLI::App *app = nullptr;
  CLI::App *config_cmd = nullptr;
  CLI::App *config_ls = nullptr;
  CLI::App *config_keys = nullptr;
  CLI::App *config_data = nullptr;
  CLI::App *config_get = nullptr;
  CLI::App *config_add = nullptr;
  CLI::App *config_edit = nullptr;
  CLI::App *config_rn = nullptr;
  CLI::App *config_rm = nullptr;
  CLI::App *config_set = nullptr;
  CLI::App *config_save = nullptr;
  CLI::App *stat_cmd = nullptr;
  CLI::App *ls_cmd = nullptr;
  CLI::App *size_cmd = nullptr;
  CLI::App *find_cmd = nullptr;
  CLI::App *mkdir_cmd = nullptr;
  CLI::App *rm_cmd = nullptr;
  CLI::App *walk_cmd = nullptr;
  CLI::App *tree_cmd = nullptr;
  CLI::App *realpath_cmd = nullptr;
  CLI::App *rtt_cmd = nullptr;
  CLI::App *clear_cmd = nullptr;
  CLI::App *cp_cmd = nullptr;
  CLI::App *sftp_cmd = nullptr;
  CLI::App *ftp_cmd = nullptr;
  CLI::App *client_cmd = nullptr;
  CLI::App *client_ls_cmd = nullptr;
  CLI::App *client_check_cmd = nullptr;
  CLI::App *ch_cmd = nullptr;
  CLI::App *client_rm_cmd = nullptr;
  CLI::App *cd_cmd = nullptr;
  CLI::App *connect_cmd = nullptr;
  CLI::App *var_cmd = nullptr;
  CLI::App *del_cmd = nullptr;
  CLI::App *bash_cmd = nullptr;
  CLI::App *complete_cmd = nullptr;
  CLI::App *complete_cache_cmd = nullptr;
  CLI::App *complete_cache_clear = nullptr;
  CLI::App *task_cmd = nullptr;
  CLI::App *task_cache_cmd = nullptr;
  CLI::App *task_cache_add = nullptr;
  CLI::App *task_cache_rm = nullptr;
  CLI::App *task_cache_clear = nullptr;
  CLI::App *task_cache_submit = nullptr;
  CLI::App *task_list_cmd = nullptr;
  CLI::App *task_show_cmd = nullptr;
  CLI::App *task_inspect_cmd = nullptr;
  CLI::App *task_thread_cmd = nullptr;
  CLI::App *task_userset_cmd = nullptr;
  CLI::App *task_query_cmd = nullptr;
  CLI::App *task_terminate_cmd = nullptr;
  CLI::App *task_pause_cmd = nullptr;
  CLI::App *task_resume_cmd = nullptr;
  CLI::App *task_retry_cmd = nullptr;
  CLI::App *resume_cmd = nullptr;
  const CliArgsPool *args = nullptr;
};

/**
 * @brief Exit code storage for CLI dispatch.
 */
extern int g_cli_exit_code;

/**
 * @brief Dispatch result for CLI execution.
 */
struct DispatchResult {
  ECM rcm = {EC::Success, ""};
  bool enter_interactive = false;
};

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args);

/**
 * @brief Build the shared command tree from CLI definitions.
 */
std::shared_ptr<CommandTree> BuildCommandTree(CLI::App &app,
                                              CliArgsPool &args);

/**
 * @brief Set the exit code and return.
 */
void SetCliExitCode(int code);

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
DispatchResult DispatchCliCommands(const CliCommands &cli_commands,
                                   const CliManagers &managers,
                                   bool async = false,
                                   bool enforce_interactive = false);
