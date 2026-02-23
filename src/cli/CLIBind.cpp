
#include "AMCLI/CLIBind.hpp"
#include <type_traits>

int g_cli_exit_code = 0;

/**
 * @brief Bind config-related CLI commands.
 */
void BindConfigCommands(CommandNode *root, CliArgsPool &args,
                        CliCommands &commands) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *config_node = root->AddFunction("config", "Config manager");
  if (!config_node) {
    return;
  }
  commands.config_cmd = config_node->app;

  CommandNode *config_ls_node =
      config_node->AddFunction("ls", "List configs", args, &CliArgsPool::config_ls);
  commands.config_ls = config_ls_node ? config_ls_node->app : nullptr;
  if (config_ls_node) {
    config_ls_node->AddFlag("-l", "--list", args.config_ls.detail,
                            "Show detailed list");
  }

  CommandNode *config_keys_node = config_node->AddFunction(
      "keys", "List keys", args, &CliArgsPool::config_keys);
  commands.config_keys = config_keys_node ? config_keys_node->app : nullptr;

  CommandNode *config_data_node = config_node->AddFunction(
      "data", "Show config", args, &CliArgsPool::config_data);
  commands.config_data = config_data_node ? config_data_node->app : nullptr;

  CommandNode *config_get_node = config_node->AddFunction(
      "get", "Query host", args, &CliArgsPool::config_get);
  commands.config_get = config_get_node ? config_get_node->app : nullptr;

  CommandNode *config_add_node = config_node->AddFunction(
      "add", "Add host", args, &CliArgsPool::config_add);
  commands.config_add = config_add_node ? config_add_node->app : nullptr;

  CommandNode *config_edit_node = config_node->AddFunction(
      "edit", "Edit host", args, &CliArgsPool::config_edit);
  commands.config_edit = config_edit_node ? config_edit_node->app : nullptr;

  CommandNode *config_rn_node = config_node->AddFunction(
      "rn", "Rename host", args, &CliArgsPool::config_rn);
  commands.config_rn = config_rn_node ? config_rn_node->app : nullptr;

  CommandNode *config_rm_node = config_node->AddFunction(
      "rm", "Remove host", args, &CliArgsPool::config_rm);
  commands.config_rm = config_rm_node ? config_rm_node->app : nullptr;

  CommandNode *config_set_node = config_node->AddFunction(
      "set", "Set host", args, &CliArgsPool::config_set);
  commands.config_set = config_set_node ? config_set_node->app : nullptr;

  CommandNode *config_save_node = config_node->AddFunction(
      "save", "Save config", args, &CliArgsPool::config_save);
  commands.config_save = config_save_node ? config_save_node->app : nullptr;

  CommandNode *config_hostset_node =
      config_node->AddFunction("hostset", "Manage HostSet");
  commands.config_hostset_cmd =
      config_hostset_node ? config_hostset_node->app : nullptr;

  CommandNode *config_hostset_add_node =
      config_hostset_node ? config_hostset_node->AddFunction(
                                "add", "Create host set", args,
                                &CliArgsPool::config_hostset_add)
                          : nullptr;
  commands.config_hostset_add =
      config_hostset_add_node ? config_hostset_add_node->app : nullptr;

  CommandNode *config_hostset_edit_node =
      config_hostset_node ? config_hostset_node->AddFunction(
                                "edit", "Modify host set", args,
                                &CliArgsPool::config_hostset_edit)
                          : nullptr;
  commands.config_hostset_edit =
      config_hostset_edit_node ? config_hostset_edit_node->app : nullptr;

  CommandNode *config_hostset_rm_node =
      config_hostset_node ? config_hostset_node->AddFunction(
                                "rm", "Delete host set", args,
                                &CliArgsPool::config_hostset_rm)
                          : nullptr;
  commands.config_hostset_rm =
      config_hostset_rm_node ? config_hostset_rm_node->app : nullptr;

  CommandNode *config_hostset_save_node =
      config_hostset_node ? config_hostset_node->AddFunction(
                                "save", "Save HostSet", args,
                                &CliArgsPool::config_hostset_save)
                          : nullptr;
  commands.config_hostset_save =
      config_hostset_save_node ? config_hostset_save_node->app : nullptr;

  if (commands.config_get) {
    commands.config_get
        ->add_option("nicknames", args.config_get.nicknames, "Host nicknames")
        ->expected(0, -1);
  }
  if (commands.config_edit) {
    commands.config_edit
        ->add_option("nickname", args.config_edit.nickname, "Host nickname")
        ->required();
  }
  if (commands.config_rn) {
    commands.config_rn
        ->add_option("old", args.config_rn.old_name, "Old nickname")
        ->required();
    commands.config_rn
        ->add_option("new", args.config_rn.new_name, "New nickname")
        ->required();
  }
  if (commands.config_rm) {
    commands.config_rm
        ->add_option("nicknames", args.config_rm.names, "Host nicknames to remove")
        ->expected(1, -1);
  }
  if (commands.config_set) {
    commands.config_set
        ->add_option("nickname", args.config_set.nickname, "Host nickname")
        ->required();
    commands.config_set
        ->add_option("attrname", args.config_set.attrname, "Host property name")
        ->required();
    commands.config_set
        ->add_option("value", args.config_set.value, "Host property value")
        ->required();
  }
  if (commands.config_hostset_add) {
    commands.config_hostset_add
        ->add_option("nickname", args.config_hostset_add.nickname, "Host nickname")
        ->required();
  }
  if (commands.config_hostset_edit) {
    commands.config_hostset_edit
        ->add_option("nickname", args.config_hostset_edit.nickname, "Host nickname")
        ->required();
  }
  if (commands.config_hostset_rm) {
    commands.config_hostset_rm
        ->add_option("nicknames", args.config_hostset_rm.nicknames,
                     "Host nicknames")
        ->expected(1, -1);
  }

  if (config_get_node) {
    config_get_node->AddPositionalRule(0, Sem::HostNickname, true);
  }
  if (config_edit_node) {
    config_edit_node->AddPositionalRule(0, Sem::HostNickname, true);
  }
  if (config_rm_node) {
    config_rm_node->AddPositionalRule(0, Sem::HostNickname, true);
  }
  if (config_rn_node) {
    config_rn_node->AddPositionalRule(0, Sem::HostNickname, false);
  }
  if (config_set_node) {
    config_set_node->AddPositionalRule(0, Sem::HostNickname, false);
    config_set_node->AddPositionalRule(1, Sem::HostAttr, false);
  }
}

/**
 * @brief Bind client-related CLI commands.
 */
void BindClientCommands(CommandNode *root, CliArgsPool &args,
                        CliCommands &commands) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *client_node = root->AddFunction("client", "Client manager");
  if (!client_node) {
    return;
  }
  commands.client_cmd = client_node->app;

  CommandNode *client_ls_node = client_node->AddFunction(
      "ls", "List client names", args, &CliArgsPool::clients);
  commands.client_ls_cmd = client_ls_node ? client_ls_node->app : nullptr;
  if (client_ls_node) {
    client_ls_node->AddFlag("-d", "--detail", args.clients.detail,
                            "Show full status details");
  }

  CommandNode *client_check_node = client_node->AddFunction(
      "check", "Check client status", args, &CliArgsPool::check);
  commands.client_check_cmd =
      client_check_node ? client_check_node->app : nullptr;
  if (commands.client_check_cmd) {
    commands.client_check_cmd
        ->add_option("nicknames", args.check.nicknames, "Client nicknames")
        ->expected(0, -1);
  }
  if (client_check_node) {
    client_check_node->AddFlag("-d", "--detail", args.check.detail,
                               "Show client details");
    client_check_node->AddPositionalRule(0, Sem::ClientName, true);
  }

  CommandNode *client_rm_node = client_node->AddFunction(
      "rm", "Disconnect clients", args, &CliArgsPool::disconnect);
  commands.client_rm_cmd = client_rm_node ? client_rm_node->app : nullptr;
  if (commands.client_rm_cmd) {
    commands.client_rm_cmd
        ->add_option("nicknames", args.disconnect.nicknames,
                     "Client nicknames to disconnect")
        ->expected(1, -1);
  }
  if (client_rm_node) {
    client_rm_node->AddPositionalRule(0, Sem::ClientName, true);
  }
}

/**
 * @brief Bind variable-related CLI commands.
 */
void BindVarCommands(CommandNode *root, CliArgsPool &args,
                     CliCommands &commands) {
  if (!root) {
    return;
  }
  CommandNode *var_node = root->AddFunction("var", "Variable manager");
  if (!var_node) {
    return;
  }
  commands.var_cmd = var_node->app;

  CommandNode *var_get_node = var_node->AddFunction(
      "get", "Query variable by name", args, &CliArgsPool::var_get);
  commands.var_get_cmd = var_get_node ? var_get_node->app : nullptr;
  if (commands.var_get_cmd) {
    commands.var_get_cmd
        ->add_option("varname", args.var_get.varname, "$varname")
        ->required()
        ->expected(1, 1);
  }

  CommandNode *var_def_node = var_node->AddFunction(
      "def", "Define variable", args, &CliArgsPool::var_def);
  commands.var_def_cmd = var_def_node ? var_def_node->app : nullptr;
  if (var_def_node) {
    var_def_node->AddFlag("-g", "--global", args.var_def.global,
                          "Define in public section");
  }
  if (commands.var_def_cmd) {
    commands.var_def_cmd
        ->add_option("varname", args.var_def.varname, "$varname")
        ->required()
        ->expected(1, 1);
    commands.var_def_cmd
        ->add_option("value", args.var_def.value, "varvalue")
        ->required()
        ->expected(1, 1);
  }

  CommandNode *var_del_node = var_node->AddFunction(
      "del", "Delete variable", args, &CliArgsPool::var_del);
  commands.var_del_cmd = var_del_node ? var_del_node->app : nullptr;
  if (var_del_node) {
    var_del_node->AddFlag("-a", "--all", args.var_del.all,
                          "Delete from all sections");
  }
  if (commands.var_del_cmd) {
    commands.var_del_cmd
        ->add_option("tokens", args.var_del.tokens, "[section] $varname")
        ->required()
        ->expected(1, 2);
  }

  CommandNode *var_ls_node = var_node->AddFunction(
      "ls", "List variables by section", args, &CliArgsPool::var_ls);
  commands.var_ls_cmd = var_ls_node ? var_ls_node->app : nullptr;
  if (commands.var_ls_cmd) {
    commands.var_ls_cmd
        ->add_option("sections", args.var_ls.sections, "section names")
        ->expected(0, -1);
  }
}

/**
 * @brief Bind filesystem-related CLI commands.
 */
void BindFilesystemCommands(CommandNode *root, CliArgsPool &args,
                            CliCommands &commands) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *stat_node =
      root->AddFunction("stat", "Print path info", args, &CliArgsPool::stat);
  commands.stat_cmd = stat_node ? stat_node->app : nullptr;
  if (commands.stat_cmd) {
    commands.stat_cmd->add_option("paths", args.stat.paths, "Paths to stat")
        ->expected(1, -1);
  }
  if (stat_node) {
    stat_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *ls_node =
      root->AddFunction("ls", "List directory", args, &CliArgsPool::ls);
  commands.ls_cmd = ls_node ? ls_node->app : nullptr;
  if (commands.ls_cmd) {
    commands.ls_cmd->add_option("path", args.ls.path, "Path to list")
        ->expected(0, 1);
  }
  if (ls_node) {
    ls_node->AddFlag("-l", "", args.ls.list_like, "List like");
    ls_node->AddFlag("-a", "", args.ls.show_all, "Show all entries");
    ls_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *size_node =
      root->AddFunction("size", "Get total size", args, &CliArgsPool::size);
  commands.size_cmd = size_node ? size_node->app : nullptr;
  if (commands.size_cmd) {
    commands.size_cmd->add_option("paths", args.size.paths, "Paths to size")
        ->expected(1, -1);
  }
  if (size_node) {
    size_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *find_node =
      root->AddFunction("find", "Find paths", args, &CliArgsPool::find);
  commands.find_cmd = find_node ? find_node->app : nullptr;
  if (commands.find_cmd) {
    commands.find_cmd->add_option("path", args.find.path, "Path to find")
        ->required()
        ->expected(1, 1);
  }
  if (find_node) {
    find_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *mkdir_node = root->AddFunction("mkdir", "Create directories", args,
                                              &CliArgsPool::mkdir);
  commands.mkdir_cmd = mkdir_node ? mkdir_node->app : nullptr;
  if (commands.mkdir_cmd) {
    commands.mkdir_cmd->add_option("paths", args.mkdir.paths, "Paths to create")
        ->expected(1, -1);
  }
  if (mkdir_node) {
    mkdir_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *rm_node =
      root->AddFunction("rm", "Remove paths", args, &CliArgsPool::rm);
  commands.rm_cmd = rm_node ? rm_node->app : nullptr;
  if (commands.rm_cmd) {
    commands.rm_cmd->add_option("paths", args.rm.paths, "Paths to remove")
        ->expected(1, -1);
  }
  if (rm_node) {
    rm_node->AddFlag("-p", "--permanent", args.rm.permanent,
                     "Delete permanently");
    rm_node->AddFlag("-q", "--quiet", args.rm.quiet, "Suppress error output");
    rm_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *walk_node =
      root->AddFunction("walk", "Walk paths", args, &CliArgsPool::walk);
  commands.walk_cmd = walk_node ? walk_node->app : nullptr;
  if (commands.walk_cmd) {
    commands.walk_cmd->add_option("path", args.walk.path, "Path to walk")
        ->required()
        ->expected(1, 1);
  }
  if (walk_node) {
    walk_node->AddFlag("-f", "--file", args.walk.only_file, "Only show files");
    walk_node->AddFlag("-d", "--dir", args.walk.only_dir,
                       "Only show directories");
    walk_node->AddFlag("-a", "--all", args.walk.show_all,
                       "Show hidden entries");
    walk_node->AddFlag("-s", "--special", args.walk.include_special,
                       "Include special files");
    walk_node->AddFlag("-q", "--quiet", args.walk.quiet,
                       "Suppress error output");
    walk_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *tree_node =
      root->AddFunction("tree", "Print directory tree", args, &CliArgsPool::tree);
  commands.tree_cmd = tree_node ? tree_node->app : nullptr;
  if (commands.tree_cmd) {
    commands.tree_cmd->add_option("path", args.tree.path, "Path to tree")
        ->required()
        ->expected(1, 1);
  }
  if (tree_node) {
    tree_node->AddOption("-d", "--depth", args.tree.depth, 1, 1, Sem::None,
                         "Max depth (default: -1)");
    tree_node->AddFlag("-o", "--onlydir", args.tree.only_dir,
                       "Only show directories");
    tree_node->AddFlag("-a", "--all", args.tree.show_all,
                       "Show hidden entries");
    tree_node->AddFlag("-s", "--special", args.tree.include_special,
                       "Include special files");
    tree_node->AddFlag("-q", "--quiet", args.tree.quiet,
                       "Suppress error output");
    tree_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *realpath_node = root->AddFunction("realpath", "Print absolute path",
                                                 args, &CliArgsPool::realpath);
  commands.realpath_cmd = realpath_node ? realpath_node->app : nullptr;
  if (commands.realpath_cmd) {
    commands.realpath_cmd
        ->add_option("path", args.realpath.path, "Path to resolve")
        ->expected(0, 1);
  }
  if (realpath_node) {
    realpath_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *rtt_node = root->AddFunction("rtt", "Measure current client RTT",
                                            args, &CliArgsPool::rtt);
  commands.rtt_cmd = rtt_node ? rtt_node->app : nullptr;
  if (commands.rtt_cmd) {
    commands.rtt_cmd->add_option("times", args.rtt.times, "Samples (default: 1)")
        ->expected(0, 1);
  }

  CommandNode *clear_node =
      root->AddFunction("clear", "Clear screen", args, &CliArgsPool::clear);
  commands.clear_cmd = clear_node ? clear_node->app : nullptr;
  if (clear_node) {
    clear_node->AddFlag("-a", "--all", args.clear.all, "Clear scrollback buffer");
  }

  CommandNode *cp_node = root->AddFunction("cp", "Transfer files/directories",
                                           args, &CliArgsPool::cp);
  commands.cp_cmd = cp_node ? cp_node->app : nullptr;
  if (commands.cp_cmd) {
    commands.cp_cmd->add_option("src", args.cp.srcs, "Source paths")
        ->expected(1, -1);
  }
  if (cp_node) {
    cp_node->AddOption("-o", "--output", args.cp.output, 1, 1, Sem::Path,
                       "Destination path (optional)");
    cp_node->AddFlag("-f", "--force", args.cp.overwrite,
                     "Overwrite existing targets");
    cp_node->AddFlag("-n", "--no-mkdir", args.cp.no_mkdir,
                     "Do not create missing directories");
    cp_node->AddFlag("-c", "--clone", args.cp.clone,
                     "Clone instead of transfer");
    cp_node->AddFlag("-s", "--special", args.cp.include_special,
                     "Include special files");
    cp_node->AddFlag("-r", "--resume", args.cp.resume,
                     "Resume from existing destination file");
    cp_node->AddFlag("-q", "--quiet", args.cp.quiet,
                     "Suppress transfer output");
    cp_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *sftp_node = root->AddFunction("sftp", "Connect to SFTP host",
                                             args, &CliArgsPool::sftp);
  commands.sftp_cmd = sftp_node ? sftp_node->app : nullptr;
  if (commands.sftp_cmd) {
    commands.sftp_cmd
        ->add_option("targets", args.sftp.targets, "nickname user@host | user@host")
        ->required()
        ->expected(1, 2);
  }
  if (sftp_node) {
    sftp_node->AddOption("-p", "--port", args.sftp.port, 1, 1, Sem::None, "Port");
    sftp_node->AddOption("", "--keyfile", args.sftp.keyfile, 1, 1, Sem::None,
                         "Keyfile");
  }

  CommandNode *ftp_node =
      root->AddFunction("ftp", "Connect to FTP host", args, &CliArgsPool::ftp);
  commands.ftp_cmd = ftp_node ? ftp_node->app : nullptr;
  if (commands.ftp_cmd) {
    commands.ftp_cmd
        ->add_option("targets", args.ftp.targets, "nickname user@host | user@host")
        ->required()
        ->expected(1, 2);
  }
  if (ftp_node) {
    ftp_node->AddOption("-p", "--port", args.ftp.port, 1, 1, Sem::None, "Port");
    ftp_node->AddOption("", "--keyfile", args.ftp.keyfile, 1, 1, Sem::None,
                        "Keyfile");
  }

  CommandNode *ch_node =
      root->AddFunction("ch", "Change current client", args, &CliArgsPool::ch);
  commands.ch_cmd = ch_node ? ch_node->app : nullptr;
  if (commands.ch_cmd) {
    commands.ch_cmd
        ->add_option("nickname", args.ch.nickname, "Client nickname")
        ->required()
        ->expected(1, 1);
  }
  if (ch_node) {
    ch_node->AddPositionalRule(0, Sem::ClientName, false);
  }

  CommandNode *cd_node = root->AddFunction("cd", "Change working directory",
                                           args, &CliArgsPool::cd);
  commands.cd_cmd = cd_node ? cd_node->app : nullptr;
  if (commands.cd_cmd) {
    commands.cd_cmd->add_option("path", args.cd.path, "Target path")->expected(0, 1);
  }
  if (cd_node) {
    cd_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *connect_node =
      root->AddFunction("connect", "Connect to a host", args, &CliArgsPool::connect);
  commands.connect_cmd = connect_node ? connect_node->app : nullptr;
  if (commands.connect_cmd) {
    commands.connect_cmd
        ->add_option("nickname", args.connect.nickname, "Host nickname")
        ->required()
        ->expected(1, 1);
  }
  if (connect_node) {
    connect_node->AddFlag("-f", "--force", args.connect.force,
                          "Rebuild and replace existing client");
    connect_node->AddPositionalRule(0, Sem::HostNickname, false);
  }

  CommandNode *bash_node = root->AddFunction("bash", "Enter interactive mode", args,
                                             &CliArgsPool::bash);
  commands.bash_cmd = bash_node ? bash_node->app : nullptr;

  CommandNode *exit_node = root->AddFunction("exit", "Exit interactive mode", args,
                                             &CliArgsPool::exit);
  commands.exit_cmd = exit_node ? exit_node->app : nullptr;
  if (exit_node) {
    exit_node->AddFlag("-f", "--force", args.exit.force,
                       "Exit immediately without interactive-loop exit callbacks");
  }
}

/**
 * @brief Bind completion-related CLI commands.
 */
void BindCompleteCommands(CommandNode *root, CliArgsPool &args,
                          CliCommands &commands) {
  if (!root) {
    return;
  }
  CommandNode *complete_node =
      root->AddFunction("complete", "Completion utilities");
  commands.complete_cmd = complete_node ? complete_node->app : nullptr;

  CommandNode *cache_node =
      complete_node ? complete_node->AddFunction("cache", "Manage completion cache")
                    : nullptr;
  commands.complete_cache_cmd = cache_node ? cache_node->app : nullptr;

  CommandNode *clear_node =
      cache_node ? cache_node->AddFunction("clear", "Clear completion cache",
                                           args, &CliArgsPool::complete_cache_clear)
                 : nullptr;
  commands.complete_cache_clear = clear_node ? clear_node->app : nullptr;
}

/**
 * @brief Bind task-related CLI commands.
 */
void BindTaskCommands(CommandNode *root, CliArgsPool &args, CliCommands &commands) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }
  CommandNode *task_node = root->AddFunction("task", "Task manager");
  if (!task_node) {
    return;
  }
  commands.task_cmd = task_node->app;

  CommandNode *task_cache_node =
      task_node->AddFunction("cache", "Manage task cache");
  commands.task_cache_cmd = task_cache_node ? task_cache_node->app : nullptr;

  CommandNode *task_cache_add_node = task_cache_node
                                         ? task_cache_node->AddFunction(
                                               "add", "Add transfer set", args,
                                               &CliArgsPool::task_cache_add)
                                         : nullptr;
  commands.task_cache_add =
      task_cache_add_node ? task_cache_add_node->app : nullptr;
  if (commands.task_cache_add) {
    commands.task_cache_add
        ->add_option("src", args.task_cache_add.srcs, "Source paths")
        ->expected(1, -1);
  }
  if (task_cache_add_node) {
    task_cache_add_node->AddOption("-o", "--output", args.task_cache_add.output, 1,
                                   1, Sem::Path, "Destination path (optional)");
    task_cache_add_node->AddFlag("-f", "--force", args.task_cache_add.overwrite,
                                 "Overwrite existing targets");
    task_cache_add_node->AddFlag("-n", "--no-mkdir", args.task_cache_add.no_mkdir,
                                 "Do not create missing directories");
    task_cache_add_node->AddFlag("-c", "--clone", args.task_cache_add.clone,
                                 "Clone instead of transfer");
    task_cache_add_node->AddFlag("-s", "--special",
                                 args.task_cache_add.include_special,
                                 "Include special files");
    task_cache_add_node->AddFlag("-r", "--resume", args.task_cache_add.resume,
                                 "Resume from existing destination file");
    task_cache_add_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *task_cache_rm_node =
      task_cache_node ? task_cache_node->AddFunction(
                            "rm", "Remove cached sets", args,
                            &CliArgsPool::task_cache_rm)
                      : nullptr;
  commands.task_cache_rm = task_cache_rm_node ? task_cache_rm_node->app : nullptr;
  if (commands.task_cache_rm) {
    commands.task_cache_rm
        ->add_option("indices", args.task_cache_rm.indices, "Cache indices")
        ->expected(1, -1);
  }

  CommandNode *task_cache_clear_node =
      task_cache_node ? task_cache_node->AddFunction(
                            "clear", "Clear cache", args,
                            &CliArgsPool::task_cache_clear)
                      : nullptr;
  commands.task_cache_clear =
      task_cache_clear_node ? task_cache_clear_node->app : nullptr;

  CommandNode *task_cache_submit_node =
      task_cache_node ? task_cache_node->AddFunction(
                            "submit", "Submit cached tasks", args,
                            &CliArgsPool::task_cache_submit)
                      : nullptr;
  commands.task_cache_submit =
      task_cache_submit_node ? task_cache_submit_node->app : nullptr;
  if (task_cache_submit_node) {
    task_cache_submit_node->AddFlag("-a", "--async", args.task_cache_submit.is_async,
                                    "Submit as async task");
    task_cache_submit_node->AddFlag("-q", "--quiet", args.task_cache_submit.quiet,
                                    "Suppress output and confirmation");
  }
  if (commands.task_cache_submit) {
    commands.task_cache_submit
        ->add_option("tail", args.task_cache_submit.async_suffix,
                     "Optional '&' async suffix")
        ->expected(0, 1);
  }

  CommandNode *task_userset_node = task_node->AddFunction(
      "userset", "Inspect cached transfer", args, &CliArgsPool::task_userset);
  commands.task_userset_cmd = task_userset_node ? task_userset_node->app : nullptr;
  if (commands.task_userset_cmd) {
    commands.task_userset_cmd
        ->add_option("index", args.task_userset.indices, "Cache index")
        ->expected(0, -1);
  }

  CommandNode *task_list_node =
      task_node->AddFunction("ls", "List tasks", args, &CliArgsPool::task_list);
  commands.task_list_cmd = task_list_node ? task_list_node->app : nullptr;
  if (task_list_node) {
    task_list_node->AddFlag("-p", "--pending", args.task_list.pending,
                            "Show pending tasks");
    task_list_node->AddFlag("-s", "--suspend", args.task_list.suspend,
                            "Show paused tasks");
    task_list_node->AddFlag("-f", "--finished", args.task_list.finished,
                            "Show finished tasks");
    task_list_node->AddFlag("-c", "--conducting", args.task_list.conducting,
                            "Show conducting tasks");
  }

  CommandNode *task_show_node = task_node->AddFunction(
      "show", "Show task status", args, &CliArgsPool::task_show);
  commands.task_show_cmd = task_show_node ? task_show_node->app : nullptr;
  if (commands.task_show_cmd) {
    commands.task_show_cmd->add_option("id", args.task_show.ids, "Task ID")
        ->required()
        ->expected(1, -1);
  }
  if (task_show_node) {
    task_show_node->AddPositionalRule(0, Sem::TaskId, true);
  }

  CommandNode *task_thread_node = task_node->AddFunction(
      "thread", "Get or set thread count", args, &CliArgsPool::task_thread);
  commands.task_thread_cmd = task_thread_node ? task_thread_node->app : nullptr;
  if (commands.task_thread_cmd) {
    commands.task_thread_cmd
        ->add_option("num", args.task_thread.num, "Thread count (optional)")
        ->expected(0, 1);
  }

  CommandNode *task_inspect_node = task_node->AddFunction(
      "inspect", "Inspect a task", args, &CliArgsPool::task_inspect);
  commands.task_inspect_cmd =
      task_inspect_node ? task_inspect_node->app : nullptr;
  if (commands.task_inspect_cmd) {
    commands.task_inspect_cmd->add_option("id", args.task_inspect.id, "Task ID");
  }
  if (task_inspect_node) {
    task_inspect_node->AddFlag("-s", "--set", args.task_inspect.set,
                               "Show transfer sets");
    task_inspect_node->AddFlag("-e", "--entry", args.task_inspect.entry,
                               "Show task entries");
    task_inspect_node->AddPositionalRule(0, Sem::TaskId, true);
  }

  CommandNode *task_query_node = task_node->AddFunction(
      "query", "Inspect task entry", args, &CliArgsPool::task_entry);
  commands.task_query_cmd = task_query_node ? task_query_node->app : nullptr;
  if (commands.task_query_cmd) {
    commands.task_query_cmd->add_option("id", args.task_entry.ids, "Entry ID")
        ->required()
        ->expected(1, -1);
  }

  CommandNode *task_terminate_node = task_node->AddFunction(
      "terminate", "Terminate task(s)", args, &CliArgsPool::task_terminate);
  commands.task_terminate_cmd =
      task_terminate_node ? task_terminate_node->app : nullptr;
  if (commands.task_terminate_cmd) {
    commands.task_terminate_cmd
        ->add_option("id", args.task_terminate.ids, "Task IDs")
        ->expected(1, -1);
  }
  if (task_terminate_node) {
    task_terminate_node->AddPositionalRule(0, Sem::TaskId, true);
  }

  CommandNode *task_pause_node =
      task_node->AddFunction("pause", "Pause task(s)", args, &CliArgsPool::task_pause);
  commands.task_pause_cmd = task_pause_node ? task_pause_node->app : nullptr;
  if (commands.task_pause_cmd) {
    commands.task_pause_cmd->add_option("id", args.task_pause.ids, "Task IDs")
        ->expected(1, -1);
  }
  if (task_pause_node) {
    task_pause_node->AddPositionalRule(0, Sem::TaskId, true);
  }

  CommandNode *task_resume_node = task_node->AddFunction(
      "resume", "Resume paused task(s)", args, &CliArgsPool::task_resume);
  commands.task_resume_cmd = task_resume_node ? task_resume_node->app : nullptr;
  if (commands.task_resume_cmd) {
    commands.task_resume_cmd->add_option("id", args.task_resume.ids, "Task IDs")
        ->expected(1, -1);
  }

  CommandNode *task_retry_node = task_node->AddFunction(
      "retry", "Retry a completed task (retry failed entries)", args,
      &CliArgsPool::task_retry);
  commands.task_retry_cmd = task_retry_node ? task_retry_node->app : nullptr;
  if (task_retry_node) {
    task_retry_node->AddFlag("-a", "--async", args.task_retry.is_async,
                             "Submit task asynchronously");
    task_retry_node->AddFlag("-q", "--quiet", args.task_retry.quiet,
                             "Suppress output");
    task_retry_node->AddOption("-i", "--index", args.task_retry.indices, 0,
                               static_cast<size_t>(-1), Sem::None,
                               "1-based task indices to retry");
    task_retry_node->AddPositionalRule(0, Sem::TaskId, false);
  }
  if (commands.task_retry_cmd) {
    commands.task_retry_cmd->add_option("id", args.task_retry.id, "Task ID")
        ->required()
        ->expected(1, 1);
  }

  CommandNode *retry_node = root->AddFunction(
      "retry", "Retry a completed but failed task (retry failed entries)", args,
      &CliArgsPool::task_retry);
  commands.resume_cmd = retry_node ? retry_node->app : nullptr;
  if (retry_node) {
    retry_node->AddFlag("-a", "--async", args.task_retry.is_async,
                        "Submit task asynchronously");
    retry_node->AddFlag("-q", "--quiet", args.task_retry.quiet, "Suppress output");
    retry_node->AddOption("-i", "--index", args.task_retry.indices, 0,
                          static_cast<size_t>(-1), Sem::None,
                          "1-based task indices to retry");
    retry_node->AddPositionalRule(0, Sem::TaskId, false);
  }
  if (commands.resume_cmd) {
    commands.resume_cmd->add_option("id", args.task_retry.id, "Task ID")
        ->required()
        ->expected(1, 1);
  }

  args.task_terminate.action = TaskControlArgs::Action::Terminate;
  args.task_pause.action = TaskControlArgs::Action::Pause;
  args.task_resume.action = TaskControlArgs::Action::Resume;
}

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args) {
  auto &tree = CommandNode::Instance();
  tree.Init(app);

  CliCommands commands;
  commands.app = &app;
  commands.args = &args;
  BindConfigCommands(&tree, args, commands);
  BindClientCommands(&tree, args, commands);
  BindVarCommands(&tree, args, commands);
  BindFilesystemCommands(&tree, args, commands);
  BindCompleteCommands(&tree, args, commands);
  BindTaskCommands(&tree, args, commands);
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
  bool any_parsed = false;
  std::string command_name = "";
  if (cli_commands.app) {
    for (const auto *cmd : cli_commands.app->get_subcommands()) {
      if (cmd && cmd->parsed()) {
        any_parsed = true;
        command_name += cmd->get_name() + " ";
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
  command_name = command_name.empty()
                     ? command_name
                     : command_name.substr(0, command_name.size() - 1);
  if (std::holds_alternative<std::monostate>(args.common_arg)) {
    std::string msg = "No valid command provided";
    if (cli_commands.complete_cmd && cli_commands.complete_cmd->parsed()) {
      msg = "Invalid complete command";
    } else if (cli_commands.config_cmd && cli_commands.config_cmd->parsed()) {
      msg = "Invalid config command";
    } else if (cli_commands.client_cmd && cli_commands.client_cmd->parsed()) {
      msg = "Invalid client command";
    }
    std::cerr << msg << std::endl;
    result.rcm = {EC::InvalidArg, msg};
    SetCliExitCode(static_cast<int>(result.rcm.first));
    return result;
  }

  CliRunContext run_ctx;
  run_ctx.async = async;
  run_ctx.enforce_interactive = enforce_interactive;
  run_ctx.command_name = command_name;
  run_ctx.enter_interactive = &result.enter_interactive;
  run_ctx.request_exit = &result.request_exit;
  run_ctx.skip_loop_exit_callbacks = &result.skip_loop_exit_callbacks;

  result.rcm = std::visit(
      [&](const auto &selected) -> ECM {
        using T = std::decay_t<decltype(selected)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
          return {EC::InvalidArg, "No valid command provided"};
        } else {
          return selected.Run(managers, run_ctx);
        }
      },
      args.common_arg);

  SetCliExitCode(static_cast<int>(result.rcm.first));
  return result;
}

