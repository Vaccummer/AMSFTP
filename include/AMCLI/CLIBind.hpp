#pragma once
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/FileSystem.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "AMManager/Transfer.hpp"
#include "CLI/CLI.hpp"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief CLI argument container for config ls.
 */
struct ConfigLsArgs {
  bool detail = false;
};

/**
 * @brief CLI argument container for config get.
 */
struct ConfigGetArgs {
  std::string nickname;
};

/**
 * @brief CLI argument container for config edit.
 */
struct ConfigEditArgs {
  std::string nickname;
};

/**
 * @brief CLI argument container for config rename.
 */
struct ConfigRenameArgs {
  std::string old_name;
  std::string new_name;
};

/**
 * @brief CLI argument container for config remove.
 */
struct ConfigRemoveArgs {
  std::vector<std::string> names;
};

/**
 * @brief CLI argument container for stat.
 */
struct StatArgs {
  std::vector<std::string> paths;
};

/**
 * @brief CLI argument container for ls.
 */
struct LsArgs {
  std::string path;
  bool list_like = false;
  bool show_all = false;
};

/**
 * @brief CLI argument container for size.
 */
struct SizeArgs {
  std::vector<std::string> paths;
};

/**
 * @brief CLI argument container for find.
 */
struct FindArgs {
  std::string path;
};

/**
 * @brief CLI argument container for mkdir.
 */
struct MkdirArgs {
  std::vector<std::string> paths;
};

/**
 * @brief CLI argument container for rm.
 */
struct RmArgs {
  std::vector<std::string> paths;
  bool permanent = false;
};

/**
 * @brief CLI argument container for walk.
 */
struct WalkArgs {
  std::string path;
  bool only_file = false;
  bool only_dir = false;
  bool include_special = false;
};

/**
 * @brief CLI argument container for tree.
 */
struct TreeArgs {
  std::string path;
  int depth = -1;
  bool include_special = false;
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
  bool quiet = false;
};

/**
 * @brief CLI argument container for sftp.
 */
struct SftpArgs {
  std::string nickname;
  std::string user_at_host;
  int64_t port = 22;
  std::string password;
  std::string keyfile;
};

/**
 * @brief CLI argument container for ftp.
 */
struct FtpArgs {
  std::string nickname;
  std::string user_at_host;
  int64_t port = 21;
  std::string password;
  std::string keyfile;
};

/**
 * @brief CLI argument container for clients.
 */
struct ClientsArgs {
  bool detail = false;
};

/**
 * @brief CLI argument container for check.
 */
struct CheckArgs {
  std::vector<std::string> nicknames;
};

/**
 * @brief CLI argument container for ch.
 */
struct ChangeClientArgs {
  std::string nickname;
};

/**
 * @brief CLI argument container for disconnect.
 */
struct DisconnectArgs {
  std::vector<std::string> nicknames;
};

/**
 * @brief CLI argument container for cd.
 */
struct CdArgs {
  std::string path;
};

/**
 * @brief CLI argument container for connect.
 */
struct ConnectArgs {
  std::string nickname;
};

/**
 * @brief CLI argument container for task list.
 */
struct TaskListArgs {
  bool pending = false;
  bool finished = false;
  bool conducting = false;
};

/**
 * @brief CLI argument container for task show.
 */
struct TaskShowArgs {
  std::string id;
};

/**
 * @brief CLI argument container for task inspect.
 */
struct TaskInspectArgs {
  std::string id;
  bool set = false;
  bool entry = false;
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
};

/**
 * @brief CLI argument container for task cache rm.
 */
struct TaskCacheRmArgs {
  std::vector<size_t> indices;
};

/**
 * @brief CLI argument container for task cache submit.
 */
struct TaskCacheSubmitArgs {
  bool quiet = false;
};

/**
 * @brief CLI argument container for task userset.
 */
struct TaskUserSetArgs {
  size_t index = 0;
};

/**
 * @brief CLI argument container for task taskentry.
 */
struct TaskEntryArgs {
  std::string id;
};

/**
 * @brief CLI argument container for task control.
 */
struct TaskControlArgs {
  std::vector<std::string> ids;
};

/**
 * @brief Pool of all CLI argument structs.
 */
struct CliArgsPool {
  ConfigLsArgs config_ls;
  ConfigGetArgs config_get;
  ConfigEditArgs config_edit;
  ConfigRenameArgs config_rn;
  ConfigRemoveArgs config_rm;
  StatArgs stat;
  LsArgs ls;
  SizeArgs size;
  FindArgs find;
  MkdirArgs mkdir;
  RmArgs rm;
  WalkArgs walk;
  TreeArgs tree;
  CpArgs cp;
  SftpArgs sftp;
  FtpArgs ftp;
  ClientsArgs clients;
  CheckArgs check;
  ChangeClientArgs ch;
  DisconnectArgs disconnect;
  CdArgs cd;
  ConnectArgs connect;
  TaskListArgs task_list;
  TaskShowArgs task_show;
  TaskInspectArgs task_inspect;
  TaskCacheAddArgs task_cache_add;
  TaskCacheRmArgs task_cache_rm;
  TaskCacheSubmitArgs task_cache_submit;
  TaskUserSetArgs task_userset;
  TaskEntryArgs task_entry;
  TaskControlArgs task_terminate;
  TaskControlArgs task_pause;
  TaskControlArgs task_resume;
};

/**
 * @brief CLI subcommand handles.
 */
struct CliCommands {
  CLI::App *config_cmd = nullptr;
  CLI::App *config_ls = nullptr;
  CLI::App *config_keys = nullptr;
  CLI::App *config_data = nullptr;
  CLI::App *config_get = nullptr;
  CLI::App *config_add = nullptr;
  CLI::App *config_edit = nullptr;
  CLI::App *config_rn = nullptr;
  CLI::App *config_rm = nullptr;
  CLI::App *stat_cmd = nullptr;
  CLI::App *ls_cmd = nullptr;
  CLI::App *size_cmd = nullptr;
  CLI::App *find_cmd = nullptr;
  CLI::App *mkdir_cmd = nullptr;
  CLI::App *rm_cmd = nullptr;
  CLI::App *walk_cmd = nullptr;
  CLI::App *tree_cmd = nullptr;
  CLI::App *cp_cmd = nullptr;
  CLI::App *sftp_cmd = nullptr;
  CLI::App *ftp_cmd = nullptr;
  CLI::App *clients_cmd = nullptr;
  CLI::App *check_cmd = nullptr;
  CLI::App *ch_cmd = nullptr;
  CLI::App *disconnect_cmd = nullptr;
  CLI::App *cd_cmd = nullptr;
  CLI::App *connect_cmd = nullptr;
  CLI::App *bash_cmd = nullptr;
  CLI::App *task_cmd = nullptr;
  CLI::App *task_cache_cmd = nullptr;
  CLI::App *task_cache_add = nullptr;
  CLI::App *task_cache_rm = nullptr;
  CLI::App *task_cache_clear = nullptr;
  CLI::App *task_cache_submit = nullptr;
  CLI::App *task_list_cmd = nullptr;
  CLI::App *task_show_cmd = nullptr;
  CLI::App *task_inspect_cmd = nullptr;
  CLI::App *task_userset_cmd = nullptr;
  CLI::App *task_taskentry_cmd = nullptr;
  CLI::App *task_terminate_cmd = nullptr;
  CLI::App *task_pause_cmd = nullptr;
  CLI::App *task_resume_cmd = nullptr;
  const CliArgsPool *args = nullptr;
};

/**
 * @brief Manager references for CLI dispatch.
 */
struct CliManagers {
  std::shared_ptr<AMFileSystem> filesystem;
  std::shared_ptr<AMClientManager> client_manager;
  std::shared_ptr<AMConfigManager> config_manager;
};

/**
 * @brief Exit code storage for CLI dispatch.
 */
inline int g_cli_exit_code = 0;

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
inline CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args) {
  CliCommands commands;
  commands.args = &args;
  commands.config_cmd = app.add_subcommand("config", "Config manager");
  commands.config_ls =
      commands.config_cmd->add_subcommand("ls", "List configs");
  commands.config_ls->add_flag("-d,--detail", args.config_ls.detail,
                               "Show detailed list");
  commands.config_keys =
      commands.config_cmd->add_subcommand("keys", "List keys");
  commands.config_data =
      commands.config_cmd->add_subcommand("data", "Show config");
  commands.config_get =
      commands.config_cmd->add_subcommand("get", "Query host");
  commands.config_add = commands.config_cmd->add_subcommand("add", "Add host");
  commands.config_edit =
      commands.config_cmd->add_subcommand("edit", "Edit host");
  commands.config_rn = commands.config_cmd->add_subcommand("rn", "Rename host");
  commands.config_rm = commands.config_cmd->add_subcommand("rm", "Remove host");

  commands.config_get
      ->add_option("nickname", args.config_get.nickname, "Host nickname")
      ->required();
  commands.config_edit
      ->add_option("nickname", args.config_edit.nickname, "Host nickname")
      ->required();
  commands.config_rn->add_option("old", args.config_rn.old_name, "Old nickname")
      ->required();
  commands.config_rn->add_option("new", args.config_rn.new_name, "New nickname")
      ->required();
  commands.config_rm
      ->add_option("nicknames", args.config_rm.names,
                   "Host nicknames to remove")
      ->expected(1, -1);

  commands.stat_cmd = app.add_subcommand("stat", "Print path info");
  commands.stat_cmd->add_option("paths", args.stat.paths, "Paths to stat")
      ->expected(1, -1);

  commands.ls_cmd = app.add_subcommand("ls", "List directory");
  commands.ls_cmd->add_option("path", args.ls.path, "Path to list")
      ->expected(0, 1);
  commands.ls_cmd->add_flag("-l", args.ls.list_like, "List like");
  commands.ls_cmd->add_flag("-a", args.ls.show_all, "Show all entries");

  commands.size_cmd = app.add_subcommand("size", "Get total size");
  commands.size_cmd->add_option("paths", args.size.paths, "Paths to size")
      ->expected(1, -1);

  commands.find_cmd = app.add_subcommand("find", "Find paths");
  commands.find_cmd->add_option("path", args.find.path, "Path to find")
      ->required()
      ->expected(1, 1);

  commands.mkdir_cmd = app.add_subcommand("mkdir", "Create directories");
  commands.mkdir_cmd->add_option("paths", args.mkdir.paths, "Paths to create")
      ->expected(1, -1);

  commands.rm_cmd = app.add_subcommand("rm", "Remove paths");
  commands.rm_cmd->add_option("paths", args.rm.paths, "Paths to remove")
      ->expected(1, -1);
  commands.rm_cmd->add_flag("-p,--permanent", args.rm.permanent,
                            "Delete permanently");

  commands.walk_cmd = app.add_subcommand("walk", "Walk paths");
  commands.walk_cmd->add_option("path", args.walk.path, "Path to walk")
      ->required()
      ->expected(1, 1);
  commands.walk_cmd->add_flag("-f,--file", args.walk.only_file,
                              "Only show files");
  commands.walk_cmd->add_flag("-d,--dir", args.walk.only_dir,
                              "Only show directories");
  commands.walk_cmd->add_flag("-s,--special", args.walk.include_special,
                              "Include special files");

  commands.tree_cmd = app.add_subcommand("tree", "Print directory tree");
  commands.tree_cmd->add_option("path", args.tree.path, "Path to tree")
      ->required()
      ->expected(1, 1);
  commands.tree_cmd->add_option("--depth", args.tree.depth,
                                "Max depth (default: -1)");
  commands.tree_cmd->add_flag("-s,--special", args.tree.include_special,
                              "Include special files");

  commands.cp_cmd = app.add_subcommand("cp", "Transfer files/directories");
  commands.cp_cmd->add_option("src", args.cp.srcs, "Source paths")
      ->expected(1, -1);
  commands.cp_cmd->add_option("-o,--output", args.cp.output,
                              "Destination path (optional)");
  commands.cp_cmd->add_flag("-f,--force", args.cp.overwrite,
                            "Overwrite existing targets");
  commands.cp_cmd->add_flag("-n,--no-mkdir", args.cp.no_mkdir,
                            "Do not create missing directories");
  commands.cp_cmd->add_flag("-c,--clone", args.cp.clone,
                            "Clone instead of transfer");
  commands.cp_cmd->add_flag("-s,--special", args.cp.include_special,
                            "Include special files");
  commands.cp_cmd->add_flag("-q,--quiet", args.cp.quiet,
                            "Suppress transfer output");

  commands.sftp_cmd = app.add_subcommand("sftp", "Connect to SFTP host");
  commands.sftp_cmd
      ->add_option("user_at_host", args.sftp.user_at_host,
                   "User and host (user@host)")
      ->required()
      ->expected(1, 1);
  commands.sftp_cmd->add_option("nickname", args.sftp.nickname,
                                "Host nickname");
  commands.sftp_cmd->add_option("-p,--port", args.sftp.port, "Port");
  commands.sftp_cmd->add_option("--password", args.sftp.password, "Password");
  commands.sftp_cmd->add_option("--keyfile", args.sftp.keyfile, "Keyfile");

  commands.ftp_cmd = app.add_subcommand("ftp", "Connect to FTP host");
  commands.ftp_cmd
      ->add_option("user_at_host", args.ftp.user_at_host,
                   "User and host (user@host)")
      ->required()
      ->expected(1, 1);
  commands.ftp_cmd->add_option("nickname", args.ftp.nickname, "Host nickname");
  commands.ftp_cmd->add_option("-p,--port", args.ftp.port, "Port");
  commands.ftp_cmd->add_option("--password", args.ftp.password, "Password");
  commands.ftp_cmd->add_option("--keyfile", args.ftp.keyfile, "Keyfile");

  commands.clients_cmd = app.add_subcommand("clients", "List client names");
  commands.clients_cmd->add_flag("-d,--detail", args.clients.detail,
                                 "Show full status details");

  commands.check_cmd = app.add_subcommand("check", "Check client status");
  commands.check_cmd
      ->add_option("nicknames", args.check.nicknames, "Client nicknames")
      ->expected(0, -1);

  commands.ch_cmd = app.add_subcommand("ch", "Change current client");
  commands.ch_cmd->add_option("nickname", args.ch.nickname, "Client nickname")
      ->required()
      ->expected(1, 1);

  commands.disconnect_cmd =
      app.add_subcommand("disconnect", "Disconnect clients");
  commands.disconnect_cmd
      ->add_option("nicknames", args.disconnect.nicknames,
                   "Client nicknames to disconnect")
      ->expected(1, -1);

  commands.cd_cmd = app.add_subcommand("cd", "Change working directory");
  commands.cd_cmd->add_option("path", args.cd.path, "Target path")
      ->expected(0, 1);

  commands.connect_cmd = app.add_subcommand("connect", "Connect to a host");
  commands.connect_cmd
      ->add_option("nickname", args.connect.nickname, "Host nickname")
      ->required()
      ->expected(1, 1);

  commands.bash_cmd = app.add_subcommand("bash", "Enter interactive mode");

  commands.task_cmd = app.add_subcommand("task", "Task manager");
  commands.task_cache_cmd =
      commands.task_cmd->add_subcommand("cache", "Manage task cache");
  commands.task_cache_add =
      commands.task_cache_cmd->add_subcommand("add", "Add transfer set");
  commands.task_cache_add
      ->add_option("src", args.task_cache_add.srcs, "Source paths")
      ->expected(1, -1);
  commands.task_cache_add->add_option("-o,--output", args.task_cache_add.output,
                                      "Destination path (optional)");
  commands.task_cache_add->add_flag("-f,--force", args.task_cache_add.overwrite,
                                    "Overwrite existing targets");
  commands.task_cache_add->add_flag("-n,--no-mkdir",
                                    args.task_cache_add.no_mkdir,
                                    "Do not create missing directories");
  commands.task_cache_add->add_flag("-c,--clone", args.task_cache_add.clone,
                                    "Clone instead of transfer");
  commands.task_cache_add->add_flag("-s,--special",
                                    args.task_cache_add.include_special,
                                    "Include special files");

  commands.task_cache_rm =
      commands.task_cache_cmd->add_subcommand("rm", "Remove cached sets");
  commands.task_cache_rm
      ->add_option("indices", args.task_cache_rm.indices, "Cache indices")
      ->expected(1, -1);

  commands.task_cache_clear =
      commands.task_cache_cmd->add_subcommand("clear", "Clear cache");

  commands.task_cache_submit =
      commands.task_cache_cmd->add_subcommand("submit", "Submit cached tasks");
  commands.task_cache_submit->add_flag("-q,--quiet",
                                       args.task_cache_submit.quiet,
                                       "Suppress output and confirmation");

  commands.task_list_cmd =
      commands.task_cmd->add_subcommand("list", "List tasks");
  commands.task_list_cmd->add_flag("--pending", args.task_list.pending,
                                   "Show pending tasks");
  commands.task_list_cmd->add_flag("--finished", args.task_list.finished,
                                   "Show finished tasks");
  commands.task_list_cmd->add_flag("--conducting", args.task_list.conducting,
                                   "Show conducting tasks");

  commands.task_show_cmd =
      commands.task_cmd->add_subcommand("show", "Show task status");
  commands.task_show_cmd->add_option("id", args.task_show.id, "Task ID")
      ->required()
      ->expected(1, 1);

  commands.task_inspect_cmd =
      commands.task_cmd->add_subcommand("inspect", "Inspect a task");
  commands.task_inspect_cmd->add_option("id", args.task_inspect.id, "Task ID");
  commands.task_inspect_cmd->add_flag("--set", args.task_inspect.set,
                                      "Show transfer sets");
  commands.task_inspect_cmd->add_flag("--entry", args.task_inspect.entry,
                                      "Show task entries");

  commands.task_userset_cmd =
      commands.task_cmd->add_subcommand("userset", "Inspect cached transfer");
  commands.task_userset_cmd
      ->add_option("index", args.task_userset.index, "Cache index")
      ->required()
      ->expected(1, 1);

  commands.task_taskentry_cmd =
      commands.task_cmd->add_subcommand("taskentry", "Inspect task entry");
  commands.task_taskentry_cmd->add_option("id", args.task_entry.id, "Entry ID")
      ->required()
      ->expected(1, 1);

  commands.task_terminate_cmd =
      commands.task_cmd->add_subcommand("terminate", "Terminate task(s)");
  commands.task_terminate_cmd
      ->add_option("id", args.task_terminate.ids, "Task IDs")
      ->expected(1, -1);

  commands.task_pause_cmd =
      commands.task_cmd->add_subcommand("pause", "Pause task(s)");
  commands.task_pause_cmd->add_option("id", args.task_pause.ids, "Task IDs")
      ->expected(1, -1);

  commands.task_resume_cmd =
      commands.task_cmd->add_subcommand("resume", "Resume task(s)");
  commands.task_resume_cmd->add_option("id", args.task_resume.ids, "Task IDs")
      ->expected(1, -1);

  return commands;
}

/**
 * @brief Set the exit code and return.
 */
inline void SetCliExitCode(int code) { g_cli_exit_code = code; }

/**
 * @brief Print task inspect helper info.
 */
inline void ShowTaskInspectInfo() {
  AMPromptManager &prompt = AMPromptManager::Instance();
  prompt.Print("task inspect <id> [--set] [--entry]");
  prompt.Print("task userset <index>");
  prompt.Print("task taskentry <task_id:index>");
}

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
inline DispatchResult DispatchCliCommands(const CliCommands &cli_commands,
                                          const CliManagers &managers,
                                          bool async = false,
                                          bool enforce_interactive = false) {
  DispatchResult result;
  const CliArgsPool &args = *cli_commands.args;
  auto &config_manager = *managers.config_manager;
  auto &client_manager = *managers.client_manager;
  auto &filesystem = *managers.filesystem;
  amf flag = amgif;

  const bool any_parsed =
      cli_commands.config_cmd->parsed() || cli_commands.stat_cmd->parsed() ||
      cli_commands.ls_cmd->parsed() || cli_commands.size_cmd->parsed() ||
      cli_commands.find_cmd->parsed() || cli_commands.mkdir_cmd->parsed() ||
      cli_commands.rm_cmd->parsed() || cli_commands.walk_cmd->parsed() ||
      cli_commands.tree_cmd->parsed() || cli_commands.cp_cmd->parsed() ||
      cli_commands.clients_cmd->parsed() || cli_commands.check_cmd->parsed() ||
      cli_commands.ch_cmd->parsed() || cli_commands.disconnect_cmd->parsed() ||
      cli_commands.cd_cmd->parsed() || cli_commands.connect_cmd->parsed() ||
      cli_commands.bash_cmd->parsed() || cli_commands.task_cmd->parsed() ||
      cli_commands.task_cache_add->parsed() ||
      cli_commands.task_cache_rm->parsed() ||
      cli_commands.task_cache_clear->parsed() ||
      cli_commands.task_cache_submit->parsed() ||
      cli_commands.task_list_cmd->parsed() ||
      cli_commands.task_show_cmd->parsed() ||
      cli_commands.task_inspect_cmd->parsed() ||
      cli_commands.task_userset_cmd->parsed() ||
      cli_commands.task_taskentry_cmd->parsed() ||
      cli_commands.task_terminate_cmd->parsed() ||
      cli_commands.task_pause_cmd->parsed() ||
      cli_commands.task_resume_cmd->parsed() ||
      cli_commands.sftp_cmd->parsed() || cli_commands.ftp_cmd->parsed();

  if (!any_parsed) {
    std::string msg = "No valid command provided";
    std::cerr << msg << std::endl;
    result.rcm = {EC::InvalidArg, msg};
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  auto command_name = [&]() -> std::string {
    if (cli_commands.config_cmd->parsed()) {
      return "config";
    }
    if (cli_commands.stat_cmd->parsed()) {
      return "stat";
    }
    if (cli_commands.ls_cmd->parsed()) {
      return "ls";
    }
    if (cli_commands.size_cmd->parsed()) {
      return "size";
    }
    if (cli_commands.find_cmd->parsed()) {
      return "find";
    }
    if (cli_commands.mkdir_cmd->parsed()) {
      return "mkdir";
    }
    if (cli_commands.rm_cmd->parsed()) {
      return "rm";
    }
    if (cli_commands.walk_cmd->parsed()) {
      return "walk";
    }
    if (cli_commands.tree_cmd->parsed()) {
      return "tree";
    }
    if (cli_commands.cp_cmd->parsed()) {
      return "cp";
    }
    if (cli_commands.clients_cmd->parsed()) {
      return "clients";
    }
    if (cli_commands.check_cmd->parsed()) {
      return "check";
    }
    if (cli_commands.ch_cmd->parsed()) {
      return "ch";
    }
    if (cli_commands.disconnect_cmd->parsed()) {
      return "disconnect";
    }
    if (cli_commands.cd_cmd->parsed()) {
      return "cd";
    }
    if (cli_commands.connect_cmd->parsed()) {
      return "connect";
    }
    if (cli_commands.bash_cmd->parsed()) {
      return "bash";
    }
    if (cli_commands.task_cmd->parsed()) {
      return "task";
    }
    if (cli_commands.sftp_cmd->parsed()) {
      return "sftp";
    }
    if (cli_commands.ftp_cmd->parsed()) {
      return "ftp";
    }
    return "command";
  };

  if (enforce_interactive && !AMIsInteractive.load()) {
    std::string msg = AMStr::amfmt("{} not supported in Non-Interactive mode",
                                   command_name());
    std::cerr << msg << std::endl;
    result.rcm = {EC::OperationUnsupported, msg};
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.config_cmd->parsed()) {
    if (cli_commands.config_ls->parsed()) {
      result.rcm = args.config_ls.detail ? config_manager.List()
                                         : config_manager.ListName();
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.config_keys->parsed()) {
      auto keys_result = config_manager.PrivateKeys(true);
      result.rcm = keys_result.first;
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.config_data->parsed()) {
      result.rcm = config_manager.Src();
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.config_get->parsed()) {
      result.rcm = config_manager.Query(args.config_get.nickname);
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.config_add->parsed()) {
      result.rcm = config_manager.Add();
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.config_edit->parsed()) {
      result.rcm = config_manager.Modify(args.config_edit.nickname);
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.config_rn->parsed()) {
      result.rcm = config_manager.Rename(args.config_rn.old_name,
                                         args.config_rn.new_name);
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.config_rm->parsed()) {
      result.rcm = config_manager.Delete(args.config_rm.names);
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    std::cerr << "Invalid config command" << std::endl;
    result.rcm = {EC::InvalidArg, "Invalid config command"};
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.stat_cmd->parsed()) {
    result.rcm = filesystem.stat(args.stat.paths, flag);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.ls_cmd->parsed()) {
    std::string path = AMStr::TrimWhitespaceCopy(args.ls.path);
    if (path.empty()) {
      auto client =
          client_manager.CLIENT ? client_manager.CLIENT : client_manager.LOCAL;
      if (client) {
        path = client_manager.GetOrInitWorkdir(client);
      }
    }
    if (path.empty()) {
      path = "/";
    }
    result.rcm = filesystem.ls(path, args.ls.list_like, args.ls.show_all, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.size_cmd->parsed()) {
    result.rcm = filesystem.getsize(args.size.paths, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.find_cmd->parsed()) {
    result.rcm = filesystem.find(args.find.path, SearchType::All, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.mkdir_cmd->parsed()) {
    result.rcm = filesystem.mkdir(args.mkdir.paths, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.rm_cmd->parsed()) {
    result.rcm = filesystem.rm(args.rm.paths, args.rm.permanent, false, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.walk_cmd->parsed()) {
    result.rcm =
        filesystem.walk(args.walk.path, args.walk.only_file, args.walk.only_dir,
                        !args.walk.include_special, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.tree_cmd->parsed()) {
    result.rcm = filesystem.tree(args.tree.path, args.tree.depth,
                                 !args.tree.include_special, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.cp_cmd->parsed()) {
    if (args.cp.srcs.empty()) {
      std::cerr << "cp requires at least one source" << std::endl;
      result.rcm = {EC::InvalidArg, "cp requires at least one source"};
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    std::vector<std::string> srcs;
    std::string dst;
    if (args.cp.output.empty()) {
      if (args.cp.srcs.size() != 2) {
        std::cerr << "cp requires exactly 2 paths when --output is omitted"
                  << std::endl;
        result.rcm = {EC::InvalidArg,
                      "cp requires exactly 2 paths when --output is omitted"};
        SetCliExitCode(static_cast<int>(result.rcm.first));
        return result;
      }
      srcs = {args.cp.srcs.front()};
      dst = args.cp.srcs.back();
    } else {
      srcs = args.cp.srcs;
      dst = args.cp.output;
    }
    UserTransferSet transfer_set;
    transfer_set.srcs = std::move(srcs);
    transfer_set.dst = std::move(dst);
    transfer_set.mkdir = !args.cp.no_mkdir;
    transfer_set.overwrite = args.cp.overwrite;
    transfer_set.clone = args.cp.clone;
    transfer_set.ignore_special_file = !args.cp.include_special;

    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm =
        async ? transfer_manager.transfer_async({transfer_set}, args.cp.quiet,
                                                flag)
              : transfer_manager.transfer({transfer_set}, args.cp.quiet, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.clients_cmd->parsed()) {
    result.rcm = filesystem.print_clients(args.clients.detail, flag);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.check_cmd->parsed()) {
    result.rcm = filesystem.check(args.check.nicknames, flag);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.ch_cmd->parsed()) {
    result.rcm = filesystem.change_client(args.ch.nickname, flag);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.disconnect_cmd->parsed()) {
    std::string joined;
    for (size_t i = 0; i < args.disconnect.nicknames.size(); ++i) {
      if (i > 0) {
        joined += " ";
      }
      joined += args.disconnect.nicknames[i];
    }
    result.rcm = filesystem.remove_client(joined);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.cd_cmd->parsed()) {
    result.rcm = filesystem.cd(args.cd.path, flag);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.connect_cmd->parsed()) {
    result.rcm = filesystem.connect(args.connect.nickname, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    result.enter_interactive = result.rcm.first == EC::Success;
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.bash_cmd->parsed()) {
    result.rcm = {EC::Success, ""};
    result.enter_interactive = true;
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_cache_add->parsed()) {
    if (args.task_cache_add.srcs.empty()) {
      std::cerr << "task cache add requires at least one source" << std::endl;
      result.rcm = {EC::InvalidArg,
                    "task cache add requires at least one source"};
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    std::vector<std::string> srcs;
    std::string dst;
    if (args.task_cache_add.output.empty()) {
      if (args.task_cache_add.srcs.size() != 2) {
        std::cerr << "task cache add requires exactly 2 paths when --output "
                     "is omitted"
                  << std::endl;
        result.rcm = {
            EC::InvalidArg,
            "task cache add requires exactly 2 paths when --output is omitted"};
        SetCliExitCode(static_cast<int>(result.rcm.first));
        return result;
      }
      srcs = {args.task_cache_add.srcs.front()};
      dst = args.task_cache_add.srcs.back();
    } else {
      srcs = args.task_cache_add.srcs;
      dst = args.task_cache_add.output;
    }
    UserTransferSet transfer_set;
    transfer_set.srcs = std::move(srcs);
    transfer_set.dst = std::move(dst);
    transfer_set.mkdir = !args.task_cache_add.no_mkdir;
    transfer_set.overwrite = args.task_cache_add.overwrite;
    transfer_set.clone = args.task_cache_add.clone;
    transfer_set.ignore_special_file = !args.task_cache_add.include_special;

    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    size_t index = transfer_manager.SubmitTransferSet(transfer_set);
    AMPromptManager::Instance().Print(
        AMStr::amfmt("✅ cache add {}", std::to_string(index)));
    result.rcm = {EC::Success, ""};
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_cache_rm->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    ECM last = {EC::Success, ""};
    for (size_t index : args.task_cache_rm.indices) {
      bool removed = transfer_manager.DeleteTransferSet(index);
      if (removed) {
        AMPromptManager::Instance().Print(
            AMStr::amfmt("✅ cache rm {}", std::to_string(index)));
      } else {
        AMPromptManager::Instance().Print(
            AMStr::amfmt("❌ cache rm {} : not found", std::to_string(index)));
        last = {EC::InvalidArg, "Cache index not found"};
      }
    }
    result.rcm = last;
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_cache_clear->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    transfer_manager.ClearCachedTransferSets();
    AMPromptManager::Instance().Print("✅ cache cleared");
    result.rcm = {EC::Success, ""};
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_cache_submit->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm = transfer_manager.SubmitCachedTransferSets(
        args.task_cache_submit.quiet, flag);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_list_cmd->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm =
        transfer_manager.List(args.task_list.pending, args.task_list.finished,
                              args.task_list.conducting, flag);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_show_cmd->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm = transfer_manager.Show(args.task_show.id, flag);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_inspect_cmd->parsed()) {
    if (args.task_inspect.id.empty() && !args.task_inspect.set &&
        !args.task_inspect.entry) {
      ShowTaskInspectInfo();
      result.rcm = {EC::Success, ""};
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (args.task_inspect.id.empty()) {
      ShowTaskInspectInfo();
      result.rcm = {EC::InvalidArg, "Task id required"};
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    ECM rcm = {EC::Success, ""};
    if (args.task_inspect.set || args.task_inspect.entry) {
      if (args.task_inspect.set) {
        rcm = transfer_manager.InspectTransferSets(args.task_inspect.id);
        if (rcm.first != EC::Success) {
          result.rcm = rcm;
          SetCliExitCode(static_cast<int>(result.rcm.first));
          return result;
        }
      }
      if (args.task_inspect.entry) {
        rcm = transfer_manager.InspectTaskEntries(args.task_inspect.id);
      }
    } else {
      rcm = transfer_manager.Inspect(args.task_inspect.id, false, false);
    }
    result.rcm = rcm;
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_userset_cmd->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm = transfer_manager.InspectUserSet(args.task_userset.index);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_taskentry_cmd->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm = transfer_manager.InspectTaskEntry(args.task_entry.id);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_terminate_cmd->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm = transfer_manager.Terminate(args.task_terminate.ids);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_pause_cmd->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm = transfer_manager.Pause(args.task_pause.ids);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_resume_cmd->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    result.rcm = transfer_manager.Resume(args.task_resume.ids);
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.sftp_cmd->parsed()) {
    result.rcm = filesystem.sftp(args.sftp.nickname, args.sftp.user_at_host,
                                 args.sftp.port, args.sftp.password,
                                 args.sftp.keyfile, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    result.enter_interactive = result.rcm.first == EC::Success;
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.ftp_cmd->parsed()) {
    result.rcm =
        filesystem.ftp(args.ftp.nickname, args.ftp.user_at_host, args.ftp.port,
                       args.ftp.password, args.ftp.keyfile, flag);
    if (result.rcm.first != EC::Success) {
      std::cerr << result.rcm.second << std::endl;
    }
    result.enter_interactive = result.rcm.first == EC::Success;
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  result.rcm = {EC::InvalidArg, "No valid command provided"};
  std::cerr << result.rcm.second << std::endl;
  SetCliExitCode(static_cast<int>(result.rcm.first));
  return result;
}
