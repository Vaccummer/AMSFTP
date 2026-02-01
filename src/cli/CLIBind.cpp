
#include "AMCLI/CLIBind.hpp"
#include <algorithm>
#include <unordered_set>

int g_cli_exit_code = 0;

namespace {
/**
 * @brief Bind config-related CLI commands.
 */
void BindConfigCommands(CLI::App &app, CliArgsPool &args,
                        CliCommands &commands) {
  commands.config_cmd = app.add_subcommand("config", "Config manager");
  commands.config_ls =
      commands.config_cmd->add_subcommand("ls", "List configs");
  commands.config_ls->add_flag("-l,--list", args.config_ls.detail,
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
  commands.config_set = commands.config_cmd->add_subcommand("set", "Set host");
  commands.config_save =
      commands.config_cmd->add_subcommand("save", "Save config");

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
  commands.config_set
      ->add_option("values", args.config_set.values,
                   "nickname property value")
      ->expected(3, 3);
}

/**
 * @brief Bind client-related CLI commands.
 */
void BindClientCommands(CLI::App &app, CliArgsPool &args,
                        CliCommands &commands) {
  commands.client_cmd = app.add_subcommand("client", "Client manager");
  commands.client_ls_cmd =
      commands.client_cmd->add_subcommand("ls", "List client names");
  commands.client_ls_cmd->add_flag("-l,--list", args.clients.detail,
                                   "Show full status details");
  commands.client_check_cmd =
      commands.client_cmd->add_subcommand("check", "Check client status");
  commands.client_check_cmd
      ->add_option("nicknames", args.check.nicknames, "Client nicknames")
      ->expected(0, -1);
  commands.client_rm_cmd =
      commands.client_cmd->add_subcommand("rm", "Disconnect clients");
  commands.client_rm_cmd
      ->add_option("nicknames", args.disconnect.nicknames,
                   "Client nicknames to disconnect")
      ->expected(1, -1);
}

/**
 * @brief Bind filesystem-related CLI commands.
 */
void BindFilesystemCommands(CLI::App &app, CliArgsPool &args,
                            CliCommands &commands) {
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
  commands.tree_cmd->add_option("-d,--depth", args.tree.depth,
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

  commands.ch_cmd = app.add_subcommand("ch", "Change current client");
  commands.ch_cmd->add_option("nickname", args.ch.nickname, "Client nickname")
      ->required()
      ->expected(1, 1);

  commands.cd_cmd = app.add_subcommand("cd", "Change working directory");
  commands.cd_cmd->add_option("path", args.cd.path, "Target path")
      ->expected(0, 1);

  commands.connect_cmd = app.add_subcommand("connect", "Connect to a host");
  commands.connect_cmd
      ->add_option("nickname", args.connect.nickname, "Host nickname")
      ->required()
      ->expected(1, 1);

  commands.bash_cmd = app.add_subcommand("bash", "Enter interactive mode");
}

/**
 * @brief Bind task-related CLI commands.
 */
void BindTaskCommands(CLI::App &app, CliArgsPool &args, CliCommands &commands) {
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
  commands.task_userset_cmd =
      commands.task_cmd->add_subcommand("userset", "Inspect cached transfer");
  commands.task_userset_cmd
      ->add_option("index", args.task_userset.indices, "Cache index")
      ->expected(0, -1);

  commands.task_list_cmd =
      commands.task_cmd->add_subcommand("list", "List tasks");
  commands.task_list_cmd->add_flag("-p,--pending", args.task_list.pending,
                                   "Show pending tasks");
  commands.task_list_cmd->add_flag("-f,--finished", args.task_list.finished,
                                   "Show finished tasks");
  commands.task_list_cmd->add_flag("-c,--conducting", args.task_list.conducting,
                                   "Show conducting tasks");

  commands.task_show_cmd =
      commands.task_cmd->add_subcommand("show", "Show task status");
  commands.task_show_cmd->add_option("id", args.task_show.id, "Task ID")
      ->required()
      ->expected(1, 1);

  commands.task_inspect_cmd =
      commands.task_cmd->add_subcommand("inspect", "Inspect a task");
  commands.task_inspect_cmd->add_option("id", args.task_inspect.id, "Task ID");
  commands.task_inspect_cmd->add_flag("-s, --set", args.task_inspect.set,
                                      "Show transfer sets");
  commands.task_inspect_cmd->add_flag("-e,--entry", args.task_inspect.entry,
                                      "Show task entries");

  commands.task_query_cmd =
      commands.task_cmd->add_subcommand("query", "Inspect task entry");
  commands.task_query_cmd->add_option("id", args.task_entry.ids, "Entry ID")
      ->required()
      ->expected(1, -1);

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
}

/**
 * @brief Deduplicate indices while preserving input order.
 */
std::vector<size_t> DedupIndices(const std::vector<size_t> &indices) {
  std::vector<size_t> out;
  std::unordered_set<size_t> seen;
  out.reserve(indices.size());
  for (size_t idx : indices) {
    if (seen.insert(idx).second) {
      out.push_back(idx);
    }
  }
  return out;
}
} // namespace

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args) {
  CliCommands commands;
  commands.app = &app;
  commands.args = &args;
  BindConfigCommands(app, args, commands);
  BindClientCommands(app, args, commands);
  BindFilesystemCommands(app, args, commands);
  BindTaskCommands(app, args, commands);
  return commands;
}

/**
 * @brief Set the exit code and return.
 */
void SetCliExitCode(int code) { g_cli_exit_code = code; }

/**
 * @brief Print task inspect helper info.
 */
void ShowTaskInspectInfo() {
  AMPromptManager &prompt = AMPromptManager::Instance();
  prompt.Print("task inspect <id> [--set] [--entry]");
  prompt.Print("task userset <index> [index ...]");
  prompt.Print("task query <task_id:index> [id ...]");
}

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
DispatchResult DispatchCliCommands(const CliCommands &cli_commands,
                                   const CliManagers &managers, bool async,
                                   bool enforce_interactive) {
  DispatchResult result;
  const CliArgsPool &args = *cli_commands.args;
  auto &config_manager = *managers.config_manager;
  auto &client_manager = *managers.client_manager;
  auto &filesystem = *managers.filesystem;
  amf flag = amgif;

  bool any_parsed = false;
  if (cli_commands.app) {
    for (const auto *cmd : cli_commands.app->get_subcommands()) {
      if (cmd && cmd->parsed()) {
        any_parsed = true;
        break;
      }
    }
  }

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
    if (cli_commands.client_cmd->parsed()) {
      return "client";
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
    if (cli_commands.ch_cmd->parsed()) {
      return "ch";
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
    if (cli_commands.config_set->parsed()) {
      result.rcm = config_manager.SetHostValue(args.config_set.values);
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.config_save->parsed()) {
      result.rcm = config_manager.Dump();
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    std::cerr << "Invalid config command" << std::endl;
    result.rcm = {EC::InvalidArg, "Invalid config command"};
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.client_cmd->parsed()) {
    if (cli_commands.client_ls_cmd->parsed()) {
      result.rcm = filesystem.print_clients(args.clients.detail, flag);
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.client_check_cmd->parsed()) {
      result.rcm = filesystem.check(args.check.nicknames, flag);
      SetCliExitCode(static_cast<int>(result.rcm.first));
      return result;
    }
    if (cli_commands.client_rm_cmd->parsed()) {
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
    std::cerr << "Invalid client command" << std::endl;
    result.rcm = {EC::InvalidArg, "Invalid client command"};
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

  if (cli_commands.ch_cmd->parsed()) {
    result.rcm = filesystem.change_client(args.ch.nickname, flag);
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
    std::vector<size_t> indices = DedupIndices(args.task_userset.indices);
    if (indices.empty()) {
      indices = transfer_manager.ListTransferSetIds();
    }
    ECM last = {EC::Success, ""};
    for (size_t index : indices) {
      ECM rcm = transfer_manager.InspectUserSet(index);
      if (rcm.first != EC::Success) {
        last = rcm;
      }
    }
    result.rcm = last;
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  if (cli_commands.task_query_cmd->parsed()) {
    AMTransferManager &transfer_manager = AMTransferManager::Instance();
    ECM last = {EC::Success, ""};
    for (const auto &id : args.task_entry.ids) {
      ECM rcm = transfer_manager.InspectTaskEntry(id);
      if (rcm.first != EC::Success) {
        last = rcm;
      }
    }
    result.rcm = last;
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
