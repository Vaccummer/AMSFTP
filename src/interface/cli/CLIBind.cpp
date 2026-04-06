#include "interface/cli/CLIBind.hpp"
#include "CLI/App.hpp"
#include "interface/parser/CommandTree.hpp"

namespace AMInterface::cli {

using AMInterface::parser::AMCommandArgSemantic;
using AMInterface::parser::CommandNode;

/**
 * @brief Bind host-related CLI commands.
 */
void BindConfigCommands(CommandNode *root, CliArgsPool &args,
                        CliCommands &commands) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *config_node = root->AddFunction("host", "Host manager");
  if (!config_node) {
    return;
  }
  commands.config.root = config_node->app;

  CommandNode *config_ls_node = config_node->AddFunction(
      "ls", "List hosts", args, &CliArgsPool::config, &CliConfigArgs::ls);
  commands.config.ls = config_ls_node ? config_ls_node->app : nullptr;
  if (config_ls_node) {
    config_ls_node->AddFlag("-l", "--list", args.config.ls.detail,
                            "Show detailed list");
  }

  CommandNode *config_keys_node = config_node->AddFunction(
      "keys", "List keys", args, &CliArgsPool::config, &CliConfigArgs::keys);
  commands.config.keys = config_keys_node ? config_keys_node->app : nullptr;

  CommandNode *config_data_node = config_node->AddFunction(
      "data", "Show project/config file paths", args, &CliArgsPool::config, &CliConfigArgs::data);
  commands.config.data = config_data_node ? config_data_node->app : nullptr;

  CommandNode *config_get_node = config_node->AddFunction(
      "get", "Query host", args, &CliArgsPool::config, &CliConfigArgs::get);
  commands.config.get = config_get_node ? config_get_node->app : nullptr;

  CommandNode *config_add_node = config_node->AddFunction(
      "add", "Add host", args, &CliArgsPool::config, &CliConfigArgs::add);
  commands.config.add = config_add_node ? config_add_node->app : nullptr;

  CommandNode *config_edit_node = config_node->AddFunction(
      "edit", "Edit host", args, &CliArgsPool::config, &CliConfigArgs::edit);
  commands.config.edit = config_edit_node ? config_edit_node->app : nullptr;

  CommandNode *config_rn_node = config_node->AddFunction(
      "rn", "Rename host", args, &CliArgsPool::config, &CliConfigArgs::rn);
  commands.config.rename = config_rn_node ? config_rn_node->app : nullptr;

  CommandNode *config_rm_node = config_node->AddFunction(
      "rm", "Remove host", args, &CliArgsPool::config, &CliConfigArgs::rm);
  commands.config.remove = config_rm_node ? config_rm_node->app : nullptr;

  CommandNode *config_set_node = config_node->AddFunction(
      "set", "Set host", args, &CliArgsPool::config, &CliConfigArgs::set);
  commands.config.set = config_set_node ? config_set_node->app : nullptr;

  CommandNode *config_save_node = config_node->AddFunction(
      "save", "Save all config files", args, &CliArgsPool::config, &CliConfigArgs::save);
  commands.config.save = config_save_node ? config_save_node->app : nullptr;

  CommandNode *config_backup_node = config_node->AddFunction(
      "backup", "Backup all config files", args, &CliArgsPool::config, &CliConfigArgs::backup);
  commands.config.backup =
      config_backup_node ? config_backup_node->app : nullptr;

  if (commands.config.get) {
    commands.config.get
        ->add_option("nicknames", args.config.get.request.nicknames,
                     "Host nicknames")
        ->expected(0, -1);
  }
  if (commands.config.add) {
    commands.config.add
        ->add_option("nickname", args.config.add.nickname, "Host nickname")
        ->expected(0, 1);
  }
  if (commands.config.edit) {
    commands.config.edit
        ->add_option("nickname", args.config.edit.nickname, "Host nickname")
        ->required();
  }
  if (commands.config.rename) {
    commands.config.rename
        ->add_option("old", args.config.rn.old_name, "Old nickname")
        ->required();
    commands.config.rename
        ->add_option("new", args.config.rn.new_name, "New nickname")
        ->required();
  }
  if (commands.config.remove) {
    commands.config.remove
        ->add_option("nicknames", args.config.rm.names,
                     "Host nicknames to remove")
        ->expected(1, -1);
  }
  if (commands.config.set) {
    commands.config.set
        ->add_option("nickname", args.config.set.request.nickname,
                     "Host nickname")
        ->required();
    commands.config.set
        ->add_option("attrname", args.config.set.request.attrname,
                     "Host property name")
        ->required();
    commands.config.set
        ->add_option("value", args.config.set.request.value,
                     "Host property value")
        ->required();
  }

  if (config_get_node) {
    config_get_node->AddPositionalRule(0, Sem::HostNickname, true);
  }
  if (config_add_node) {
    config_add_node->AddPositionalRule(0, Sem::HostNicknameNew, false);
  }
  if (config_edit_node) {
    config_edit_node->AddPositionalRule(0, Sem::HostNickname, true);
  }
  if (config_rm_node) {
    config_rm_node->AddPositionalRule(0, Sem::HostNickname, true);
  }
  if (config_rn_node) {
    config_rn_node->AddPositionalRule(0, Sem::HostNickname, false);
    config_rn_node->AddPositionalRule(1, Sem::HostNicknameNew, false);
  }
  if (config_set_node) {
    config_set_node->AddPositionalRule(0, Sem::HostNickname, false);
    config_set_node->AddPositionalRule(1, Sem::HostAttr, false);
  }
}

/**
 * @brief Bind profile-related CLI commands.
 */
void BindProfileCommands(CommandNode *root, CliArgsPool &args,
                         CliCommands &commands) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *profile_node = root->AddFunction("profile", "Profile manager");
  if (!profile_node) {
    return;
  }
  commands.profile.root = profile_node->app;

  CommandNode *profile_edit_node = profile_node->AddFunction(
      "edit", "Edit host profile", args, &CliArgsPool::profile, &CliProfileArgs::edit);
  commands.profile.edit =
      profile_edit_node ? profile_edit_node->app : nullptr;
  if (commands.profile.edit) {
    commands.profile.edit
        ->add_option("nickname", args.profile.edit.nickname, "Host nickname")
        ->required()
        ->expected(1, 1);
  }
  if (profile_edit_node) {
    profile_edit_node->AddPositionalRule(0, Sem::HostNickname, false);
  }

  CommandNode *profile_get_node = profile_node->AddFunction(
      "get", "Query host profile", args, &CliArgsPool::profile, &CliProfileArgs::get);
  commands.profile.get = profile_get_node ? profile_get_node->app : nullptr;
  if (commands.profile.get) {
    commands.profile.get
        ->add_option("nicknames", args.profile.get.nicknames, "Host nicknames")
        ->required()
        ->expected(1, -1);
  }
  if (profile_get_node) {
    profile_get_node->AddPositionalRule(0, Sem::HostNickname, true);
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
  commands.client.root = client_node->app;

  CommandNode *client_ls_node = client_node->AddFunction(
      "ls", "List client names", args, &CliArgsPool::client, &CliClientArgs::ls);
  commands.client.ls = client_ls_node ? client_ls_node->app : nullptr;
  if (client_ls_node) {
    client_ls_node->AddFlag("-d", "--detail", args.client.ls.request.detail,
                            "Show full status details");
  }

  CommandNode *client_check_node = client_node->AddFunction(
      "check", "Check client status", args, &CliArgsPool::client, &CliClientArgs::check);
  commands.client.check =
      client_check_node ? client_check_node->app : nullptr;
  if (commands.client.check) {
    commands.client.check
        ->add_option("nicknames", args.client.check.request.nicknames,
                     "Client nicknames")
        ->expected(0, -1);
  }
  if (client_check_node) {
    client_check_node->AddFlag("-d", "--detail", args.client.check.request.detail,
                               "Show client details");
    client_check_node->AddPositionalRule(0, Sem::ClientName, true);
  }

  CommandNode *client_rm_node = client_node->AddFunction(
      "rm", "Disconnect clients", args, &CliArgsPool::client, &CliClientArgs::disconnect);
  commands.client.remove = client_rm_node ? client_rm_node->app : nullptr;
  if (commands.client.remove) {
    commands.client.remove
        ->add_option("nicknames", args.client.disconnect.request.nicknames,
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
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }
  CommandNode *var_node = root->AddFunction("var", "Variable manager");
  if (!var_node) {
    return;
  }
  commands.var.root = var_node->app;

  CommandNode *var_get_node = var_node->AddFunction(
      "get", "Query variable by name", args, &CliArgsPool::var, &CliVarArgs::get);
  commands.var.get = var_get_node ? var_get_node->app : nullptr;
  if (commands.var.get) {
    commands.var.get
        ->add_option("varname", args.var.get.varname, "$varname")
        ->required()
        ->expected(1, 1);
  }

  CommandNode *var_def_node = var_node->AddFunction(
      "def", "Define variable", args, &CliArgsPool::var, &CliVarArgs::def);
  commands.var.def = var_def_node ? var_def_node->app : nullptr;
  if (var_def_node) {
    var_def_node->AddFlag("-g", "--global", args.var.def.global,
                          "Define in public section");
  }
  if (commands.var.def) {
    commands.var.def
        ->add_option("varname", args.var.def.varname, "$varname")
        ->required()
        ->expected(1, 1);
    commands.var.def->add_option("value", args.var.def.value, "varvalue")
        ->required()
        ->expected(1, 1);
  }

  CommandNode *var_del_node = var_node->AddFunction(
      "del", "Delete variable", args, &CliArgsPool::var, &CliVarArgs::del);
  commands.var.del = var_del_node ? var_del_node->app : nullptr;
  if (var_del_node) {
    var_del_node->AddFlag("-a", "--all", args.var.del.all,
                          "Delete from all sections");
  }
  if (commands.var.del) {
    commands.var.del
        ->add_option("tokens", args.var.del.tokens, "[section] $varname")
        ->required()
        ->expected(1, 2);
  }

  CommandNode *var_ls_node = var_node->AddFunction(
      "ls", "List variables by section", args, &CliArgsPool::var, &CliVarArgs::ls);
  commands.var.ls = var_ls_node ? var_ls_node->app : nullptr;
  if (commands.var.ls) {
    commands.var.ls
        ->add_option("sections", args.var.ls.sections, "section names")
        ->expected(0, -1);
  }
  if (var_ls_node) {
    var_ls_node->AddPositionalRule(0, Sem::VarZone, true);
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
      root->AddFunction("stat", "Print path info", args, &CliArgsPool::fs, &CliFilesystemArgs::stat);
  commands.fs.stat = stat_node ? stat_node->app : nullptr;
  if (commands.fs.stat) {
    commands.fs.stat
        ->add_option("paths", args.fs.stat.request.raw_paths, "Paths to stat")
        ->expected(1, -1);
  }
  if (stat_node) {
    stat_node->AddFlag("-L", "--trace-link", args.fs.stat.request.trace_link,
                       "Trace symlink target instead of link itself");
    stat_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *ls_node =
      root->AddFunction("ls", "List directory", args, &CliArgsPool::fs, &CliFilesystemArgs::ls);
  commands.fs.ls = ls_node ? ls_node->app : nullptr;
  if (commands.fs.ls) {
    commands.fs.ls
        ->add_option("path", args.fs.ls.request.raw_path, "Path to list")
        ->expected(0, 1);
  }
  if (ls_node) {
    ls_node->AddFlag("-l", "", args.fs.ls.request.list_like, "List like");
    ls_node->AddFlag("-a", "", args.fs.ls.request.show_all, "Show all entries");
    ls_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *size_node =
      root->AddFunction("size", "Get total size", args, &CliArgsPool::fs, &CliFilesystemArgs::size);
  commands.fs.size = size_node ? size_node->app : nullptr;
  if (commands.fs.size) {
    commands.fs.size
        ->add_option("paths", args.fs.size.request.raw_paths, "Paths to size")
        ->expected(1, -1);
  }
  if (size_node) {
    size_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *find_node =
      root->AddFunction("find", "Find paths", args, &CliArgsPool::fs, &CliFilesystemArgs::find);
  commands.fs.find = find_node ? find_node->app : nullptr;
  if (commands.fs.find) {
    commands.fs.find->add_option("path", args.fs.find.path, "Path to find")
        ->required()
        ->expected(1, 1);
  }
  if (find_node) {
    find_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *mkdir_node = root->AddFunction("mkdir", "Create directories",
                                              args, &CliArgsPool::fs, &CliFilesystemArgs::mkdir);
  commands.fs.mkdir = mkdir_node ? mkdir_node->app : nullptr;
  if (commands.fs.mkdir) {
    commands.fs.mkdir
        ->add_option("paths", args.fs.mkdir.request.raw_paths, "Paths to create")
        ->expected(1, -1);
  }
  if (mkdir_node) {
    mkdir_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *rm_node =
      root->AddFunction("rm", "Remove paths", args, &CliArgsPool::fs, &CliFilesystemArgs::rm);
  commands.fs.rm = rm_node ? rm_node->app : nullptr;
  if (commands.fs.rm) {
    commands.fs.rm->add_option("paths", args.fs.rm.paths, "Paths to remove")
        ->expected(1, -1);
  }
  if (rm_node) {
    rm_node->AddFlag("-p", "--permanent", args.fs.rm.permanent,
                     "Delete permanently");
    rm_node->AddFlag("-q", "--quiet", args.fs.rm.quiet, "Suppress error output");
    rm_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *tree_node = root->AddFunction("tree", "Print directory tree",
                                             args, &CliArgsPool::fs, &CliFilesystemArgs::tree);
  commands.fs.tree = tree_node ? tree_node->app : nullptr;
  if (commands.fs.tree) {
    commands.fs.tree
        ->add_option("path", args.fs.tree.request.raw_path, "Path to tree")
        ->required()
        ->expected(1, 1);
  }
  if (tree_node) {
    tree_node->AddOption("-d", "--depth", args.fs.tree.request.max_depth, 1, 1,
                         Sem::None, "Max depth (default: -1)");
    tree_node->AddFlag("-o", "--onlydir", args.fs.tree.request.only_dir,
                       "Only show directories");
    tree_node->AddFlag("-a", "--all", args.fs.tree.request.show_all,
                       "Show hidden entries");
    tree_node->AddFlag("-s", "--special", args.fs.tree.include_special,
                       "Include special files");
    tree_node->AddFlag("-q", "--quiet", args.fs.tree.request.quiet,
                       "Suppress error output");
    tree_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *realpath_node = root->AddFunction(
      "realpath", "Print absolute path", args, &CliArgsPool::fs, &CliFilesystemArgs::realpath);
  commands.fs.realpath = realpath_node ? realpath_node->app : nullptr;
  if (commands.fs.realpath) {
    commands.fs.realpath
        ->add_option("path", args.fs.realpath.path, "Path to resolve")
        ->expected(0, 1);
  }
  if (realpath_node) {
    realpath_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *rtt_node = root->AddFunction("rtt", "Measure current client RTT",
                                            args, &CliArgsPool::fs, &CliFilesystemArgs::rtt);
  commands.fs.rtt = rtt_node ? rtt_node->app : nullptr;
  if (commands.fs.rtt) {
    commands.fs.rtt
        ->add_option("times", args.fs.rtt.request.times, "Samples (default: 1)")
        ->expected(0, 1);
  }

  CommandNode *clear_node =
      root->AddFunction("clear", "Clear screen", args, &CliArgsPool::fs, &CliFilesystemArgs::clear);
  commands.fs.clear = clear_node ? clear_node->app : nullptr;
  if (clear_node) {
    clear_node->AddFlag("-a", "--all", args.fs.clear.all,
                        "Clear scrollback buffer");
  }

  CommandNode *cp_node = root->AddFunction("cp", "Transfer files/directories",
                                           args, &CliArgsPool::fs, &CliFilesystemArgs::cp);
  commands.fs.cp = cp_node ? cp_node->app : nullptr;
  if (commands.fs.cp) {
    commands.fs.cp->add_option("src", args.fs.cp.srcs, "Source paths")
        ->expected(1, -1);
  }
  if (cp_node) {
    cp_node->AddOption("-o", "--output", args.fs.cp.output, 1, 1, Sem::Path,
                       "Destination path (optional)");
    cp_node->AddOption(
        "-t", "--timeout", args.fs.cp.timeout_ms, 1, 1, Sem::None,
        "Transfer timeout in milliseconds (<=0 means no timeout)");
    cp_node->AddFlag("-f", "--force", args.fs.cp.overwrite,
                     "Overwrite existing targets");
    cp_node->AddFlag("-n", "--no-mkdir", args.fs.cp.no_mkdir,
                     "Do not create missing directories");
    cp_node->AddFlag("-c", "--clone", args.fs.cp.clone,
                     "Clone instead of transfer");
    cp_node->AddFlag("-s", "--special", args.fs.cp.include_special,
                     "Include special files");
    cp_node->AddFlag("-r", "--resume", args.fs.cp.resume,
                     "Resume from existing destination file");
    cp_node->AddFlag("-q", "--quiet", args.fs.cp.quiet,
                     "Suppress transfer output");
    cp_node->AddPositionalRule(0, Sem::Path, true);
  }

  CommandNode *clone_node =
      root->AddFunction("clone", "Clone one source to one destination (cp -c)",
                        args, &CliArgsPool::fs, &CliFilesystemArgs::clone);
  commands.fs.clone = clone_node ? clone_node->app : nullptr;
  if (commands.fs.clone) {
    commands.fs.clone->add_option("src", args.fs.clone.src, "Source path")
        ->required()
        ->expected(1, 1);
    commands.fs.clone->add_option("dst", args.fs.clone.dst, "Destination path")
        ->required()
        ->expected(1, 1);
    commands.fs.clone
        ->add_option("suffix", args.fs.clone.async_suffix,
                     "Optional async suffix (&)")
        ->expected(0, 1);
  }
  if (clone_node) {
    clone_node->AddFlag("-f", "--force", args.fs.clone.overwrite,
                        "Overwrite existing targets");
    clone_node->AddFlag("-r", "--resume", args.fs.clone.resume,
                        "Resume from existing destination file");
    clone_node->AddFlag("-q", "--quiet", args.fs.clone.quiet,
                        "Suppress transfer output");
    clone_node->AddPositionalRule(0, Sem::Path, false);
    clone_node->AddPositionalRule(1, Sem::Path, false);
    clone_node->AddPositionalRule(2, Sem::None, false);
  }

  CommandNode *wget_node = root->AddFunction(
      "wget", "Download one HTTP/HTTPS URL", args, &CliArgsPool::fs, &CliFilesystemArgs::wget);
  commands.fs.wget = wget_node ? wget_node->app : nullptr;
  if (commands.fs.wget) {
    commands.fs.wget
        ->add_option("src", args.fs.wget.src, "Source URL (http/https)")
        ->required()
        ->expected(1, 1);
    commands.fs.wget
        ->add_option("dst", args.fs.wget.dst, "Destination path target")
        ->expected(0, 1);
  }
  if (wget_node) {
    wget_node->AddOption("-t", "--timeout", args.fs.wget.timeout_ms, 1, 1,
                         Sem::None,
                         "Transfer timeout in milliseconds (<=0 means no "
                         "timeout)");
    wget_node->AddOption("-b", "--bear", args.fs.wget.bear_token, 1, 1, Sem::None,
                         "Bearer token");
    wget_node->AddOption("-p", "--proxy", args.fs.wget.proxy, 1, 1, Sem::None,
                         "HTTP proxy");
    wget_node->AddOption("-s", "--sproxy", args.fs.wget.sproxy, 1, 1, Sem::None,
                         "HTTPS proxy");
    wget_node->AddOption("-R", "--redirect", args.fs.wget.redirect_times, 1, 1,
                         Sem::None,
                         "Max redirect hops (default from "
                         "Options.FileSystem.wget_max_redirect)");
    wget_node->AddFlag("-r", "--resume", args.fs.wget.resume,
                       "Resume from existing destination file when possible");
    wget_node->AddFlag("-f", "--force", args.fs.wget.overwrite,
                       "Overwrite existing destination file");
    wget_node->AddFlag("-q", "--quiet", args.fs.wget.quiet,
                       "Suppress transfer output");
    wget_node->AddPositionalRule(1, Sem::Path, false);
  }

  CommandNode *sftp_node = root->AddFunction("sftp", "Connect to SFTP host",
                                             args, &CliArgsPool::fs, &CliFilesystemArgs::sftp);
  commands.fs.sftp = sftp_node ? sftp_node->app : nullptr;
  if (commands.fs.sftp) {
    commands.fs.sftp
        ->add_option("targets", args.fs.sftp.targets,
                     "nickname user@host | user@host")
        ->required()
        ->expected(1, 2);
  }
  if (sftp_node) {
    sftp_node->AddOption("-P", "--port", args.fs.sftp.request.port, 1, 1,
                         Sem::None, "Port");
    sftp_node->AddOption("-p", "--password", args.fs.sftp.request.password, 1, 1,
                         Sem::None, "Password");
    sftp_node->AddOption("-k", "--keyfile", args.fs.sftp.request.keyfile, 1, 1,
                         Sem::None, "Keyfile");
    sftp_node->AddPositionalRule(0, Sem::HostNicknameNew, false);
  }

  CommandNode *ftp_node =
      root->AddFunction("ftp", "Connect to FTP host", args, &CliArgsPool::fs, &CliFilesystemArgs::ftp);
  commands.fs.ftp = ftp_node ? ftp_node->app : nullptr;
  if (commands.fs.ftp) {
    commands.fs.ftp
        ->add_option("targets", args.fs.ftp.targets,
                     "nickname user@host | user@host")
        ->required()
        ->expected(1, 2);
  }
  if (ftp_node) {
    ftp_node->AddOption("-P", "--port", args.fs.ftp.request.port, 1, 1, Sem::None,
                        "Port");
    ftp_node->AddOption("-p", "--password", args.fs.ftp.request.password, 1, 1,
                        Sem::None, "Password");
    ftp_node->AddPositionalRule(0, Sem::HostNicknameNew, false);
  }

  CommandNode *ch_node =
      root->AddFunction("ch", "Change current client", args, &CliArgsPool::client, &CliClientArgs::change);
  commands.client.change = ch_node ? ch_node->app : nullptr;
  if (commands.client.change) {
    commands.client.change
        ->add_option("nickname", args.client.change.request.nickname, "Client nickname")
        ->expected(0, 1);
  }
  if (ch_node) {
    ch_node->AddPositionalRule(0, Sem::ClientName, false);
  }

  CommandNode *cd_node = root->AddFunction("cd", "Change working directory",
                                           args, &CliArgsPool::fs, &CliFilesystemArgs::cd);
  commands.fs.cd = cd_node ? cd_node->app : nullptr;
  if (commands.fs.cd) {
    commands.fs.cd
        ->add_option("path", args.fs.cd.request.raw_path, "Target path")
        ->expected(0, 1);
  }
  if (cd_node) {
    cd_node->AddPositionalRule(0, Sem::Path, false);
  }

  CommandNode *connect_node = root->AddFunction("connect", "Connect to a host",
                                                args, &CliArgsPool::fs, &CliFilesystemArgs::connect);
  commands.fs.connect = connect_node ? connect_node->app : nullptr;
  if (commands.fs.connect) {
    commands.fs.connect
        ->add_option("nicknames", args.fs.connect.request.nicknames,
                     "Host nicknames")
        ->required()
        ->expected(1, -1);
  }
  if (connect_node) {
    connect_node->AddFlag("-f", "--force", args.fs.connect.request.force,
                          "Rebuild and replace existing client");
    connect_node->AddPositionalRule(0, Sem::HostNickname, true);
  }

  CommandNode *cmd_node =
      root->AddFunction("cmd", "Execute one shell command on current client",
                        args, &CliArgsPool::fs, &CliFilesystemArgs::cmd);
  commands.fs.cmd = cmd_node ? cmd_node->app : nullptr;
  if (commands.fs.cmd) {
    commands.fs.cmd
        ->add_option("command", args.fs.cmd.request.cmd, "Shell command text")
        ->required()
        ->expected(1, 1);
  }
  if (cmd_node) {
    cmd_node->AddOption("-t", "--timeout", args.fs.cmd.timeout_ms, 1, 1,
                        Sem::None,
                        "Command timeout in milliseconds (<=0 means no "
                        "timeout)");
  }

  CommandNode *bash_node = root->AddFunction("bash", "Enter interactive mode",
                                             args, &CliArgsPool::fs, &CliFilesystemArgs::bash);
  commands.fs.bash = bash_node ? bash_node->app : nullptr;

  CommandNode *exit_node = root->AddFunction("exit", "Exit interactive mode",
                                             args, &CliArgsPool::fs, &CliFilesystemArgs::exit);
  commands.fs.exit = exit_node ? exit_node->app : nullptr;
  if (exit_node) {
    exit_node->AddFlag(
        "-f", "--force", args.fs.exit.force,
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
  commands.complete.root = complete_node ? complete_node->app : nullptr;

  CommandNode *cache_node =
      complete_node
          ? complete_node->AddFunction("cache", "Manage completion cache")
          : nullptr;
  commands.complete.cache_root = cache_node ? cache_node->app : nullptr;

  CommandNode *clear_node =
      cache_node
          ? cache_node->AddFunction("clear", "Clear completion cache", args,
                                    &CliArgsPool::complete, &CliCompleteArgs::cache_clear)
          : nullptr;
  commands.complete.cache_clear = clear_node ? clear_node->app : nullptr;
}

/**
 * @brief Bind task-related CLI commands.
 */
void BindTaskCommands(CommandNode *root, CliArgsPool &args,
                      CliCommands &commands) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }
  CommandNode *task_node = root->AddFunction("task", "Task manager");
  if (!task_node) {
    return;
  }
  commands.task.root = task_node->app;

  CommandNode *task_list_node =
      task_node->AddFunction("ls", "List tasks", args, &CliArgsPool::task, &CliTaskArgs::ls);
  commands.task.ls = task_list_node ? task_list_node->app : nullptr;
  if (task_list_node) {
    task_list_node->AddFlag("-p", "--pending", args.task.ls.pending,
                            "Show pending tasks");
    task_list_node->AddFlag("-s", "--suspend", args.task.ls.suspend,
                            "Show paused tasks");
    task_list_node->AddFlag("-f", "--finished", args.task.ls.finished,
                            "Show finished tasks");
    task_list_node->AddFlag("-c", "--conducting", args.task.ls.conducting,
                            "Show conducting tasks");
  }

  CommandNode *task_show_node = task_node->AddFunction(
      "show", "Show task status", args, &CliArgsPool::task, &CliTaskArgs::show);
  commands.task.show = task_show_node ? task_show_node->app : nullptr;
  if (commands.task.show) {
    commands.task.show->add_option("id", args.task.show.ids, "Task ID")
        ->required()
        ->expected(1, -1);
  }
  if (task_show_node) {
    task_show_node->AddPositionalRule(0, Sem::TaskId, true);
  }

  CommandNode *task_thread_node = task_node->AddFunction(
      "thread", "Get or set thread count", args, &CliArgsPool::task, &CliTaskArgs::thread);
  commands.task.thread = task_thread_node ? task_thread_node->app : nullptr;
  if (commands.task.thread) {
    commands.task.thread
        ->add_option("num", args.task.thread.num, "Thread count (optional)")
        ->expected(0, 1);
  }

  CommandNode *task_inspect_node = task_node->AddFunction(
      "inspect", "Inspect a task", args, &CliArgsPool::task, &CliTaskArgs::inspect);
  commands.task.inspect =
      task_inspect_node ? task_inspect_node->app : nullptr;
  if (commands.task.inspect) {
    commands.task.inspect->add_option("id", args.task.inspect.id,
                                          "Task ID");
  }
  if (task_inspect_node) {
    task_inspect_node->AddFlag("-s", "--set", args.task.inspect.set,
                               "Show transfer sets");
    task_inspect_node->AddFlag("-e", "--entry", args.task.inspect.entry,
                               "Show task entries");
    task_inspect_node->AddPositionalRule(0, Sem::TaskId, true);
  }

  CommandNode *task_query_node = task_node->AddFunction(
      "query", "Inspect task entry", args, &CliArgsPool::task, &CliTaskArgs::entry);
  commands.task.query = task_query_node ? task_query_node->app : nullptr;
  if (commands.task.query) {
    commands.task.query->add_option("id", args.task.entry.ids, "Entry ID")
        ->required()
        ->expected(1, -1);
  }

  CommandNode *task_terminate_node = task_node->AddFunction(
      "terminate", "Terminate task(s)", args, &CliArgsPool::task, &CliTaskArgs::terminate);
  commands.task.terminate =
      task_terminate_node ? task_terminate_node->app : nullptr;
  if (commands.task.terminate) {
    commands.task.terminate
        ->add_option("id", args.task.terminate.ids, "Task IDs")
        ->expected(1, -1);
  }
  if (task_terminate_node) {
    task_terminate_node->AddPositionalRule(0, Sem::TaskId, true);
  }

  CommandNode *task_pause_node = task_node->AddFunction(
      "pause", "Pause task(s)", args, &CliArgsPool::task, &CliTaskArgs::pause);
  commands.task.pause = task_pause_node ? task_pause_node->app : nullptr;
  if (commands.task.pause) {
    commands.task.pause->add_option("id", args.task.pause.ids, "Task IDs")
        ->expected(1, -1);
  }
  if (task_pause_node) {
    task_pause_node->AddPositionalRule(0, Sem::TaskId, true);
  }

  CommandNode *task_resume_node = task_node->AddFunction(
      "resume", "Resume paused task(s)", args, &CliArgsPool::task, &CliTaskArgs::resume);
  commands.task.resume = task_resume_node ? task_resume_node->app : nullptr;
  if (commands.task.resume) {
    commands.task.resume
        ->add_option("id", args.task.resume.ids, "Task IDs")
        ->expected(1, -1);
  }

  CommandNode *task_retry_node = task_node->AddFunction(
      "retry", "Retry a completed task (retry failed entries)", args,
      &CliArgsPool::task, &CliTaskArgs::retry);
  commands.task.retry = task_retry_node ? task_retry_node->app : nullptr;
  if (task_retry_node) {
    task_retry_node->AddFlag("-a", "--async", args.task.retry.is_async,
                             "Submit task asynchronously");
    task_retry_node->AddFlag("-q", "--quiet", args.task.retry.quiet,
                             "Suppress output");
    task_retry_node->AddOption("-i", "--index", args.task.retry.indices, 0,
                               static_cast<size_t>(-1), Sem::None,
                               "1-based task indices to retry");
    task_retry_node->AddPositionalRule(0, Sem::TaskId, false);
  }
  if (commands.task.retry) {
    commands.task.retry->add_option("id", args.task.retry.id, "Task ID")
        ->required()
        ->expected(1, 1);
  }

  CommandNode *retry_node = root->AddFunction(
      "retry", "Retry a completed but failed task (retry failed entries)", args,
      &CliArgsPool::task, &CliTaskArgs::retry);
  commands.task.retry_alias = retry_node ? retry_node->app : nullptr;
  if (retry_node) {
    retry_node->AddFlag("-a", "--async", args.task.retry.is_async,
                        "Submit task asynchronously");
    retry_node->AddFlag("-q", "--quiet", args.task.retry.quiet,
                        "Suppress output");
    retry_node->AddOption("-i", "--index", args.task.retry.indices, 0,
                          static_cast<size_t>(-1), Sem::None,
                          "1-based task indices to retry");
    retry_node->AddPositionalRule(0, Sem::TaskId, false);
  }
  if (commands.task.retry_alias) {
    commands.task.retry_alias->add_option("id", args.task.retry.id, "Task ID")
        ->required()
        ->expected(1, 1);
  }

  args.task.terminate.action = TaskControlArgs::Action::Terminate;
  args.task.pause.action = TaskControlArgs::Action::Pause;
  args.task.resume.action = TaskControlArgs::Action::Resume;
}

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args,
                           CommandNode &tree) {
  tree.Init(app);
  CliCommands commands;
  commands.app = &app;
  commands.args = &args;
  BindConfigCommands(&tree, args, commands);
  BindProfileCommands(&tree, args, commands);
  BindClientCommands(&tree, args, commands);
  BindVarCommands(&tree, args, commands);
  BindFilesystemCommands(&tree, args, commands);
  BindCompleteCommands(&tree, args, commands);
  BindTaskCommands(&tree, args, commands);
  return commands;
}

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
void DispatchCliCommands(const CliCommands &cli_commands,
                         const CLIServices &managers, CliRunContext &ctx) {
  ctx.rcm = OK;
  ctx.enter_interactive = false;
  ctx.request_exit = false;
  ctx.skip_loop_exit_callbacks = false;
  ctx.command_name.clear();

  auto store_exit_code = [&ctx](int code) {
    if (ctx.exit_code) {
      ctx.exit_code->store(code, std::memory_order_relaxed);
    }
  };
  if (!cli_commands.args) {
    const std::string msg = "CLI args pool is not initialized";
    std::cerr << msg << std::endl;
    ctx.rcm = {EC::UnknownError, msg};
    store_exit_code(static_cast<int>(ctx.rcm.code));
    return;
  }
  if (!ctx.task_control_token) {
    const std::string msg = "CLI session task control token is not initialized";
    std::cerr << msg << std::endl;
    ctx.rcm = {EC::InvalidArg, msg};
    store_exit_code(static_cast<int>(ctx.rcm.code));
    if (cli_commands.args) {
      cli_commands.args->ClearActive();
    }
    return;
  }
  CliArgsPool &args = *cli_commands.args;
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
    ctx.rcm = {EC::InvalidArg, msg};
    store_exit_code(static_cast<int>(ctx.rcm.code));
    args.ClearActive();
    return;
  }
  command_name = command_name.empty()
                     ? command_name
                     : command_name.substr(0, command_name.size() - 1);
  if (!args.GetActive()) {
    std::string msg = "No valid command provided";
    if (cli_commands.complete.root && cli_commands.complete.root->parsed()) {
      msg = "Invalid complete command";
    } else if (cli_commands.config.root && cli_commands.config.root->parsed()) {
      msg = "Invalid host command";
    } else if (cli_commands.client.root && cli_commands.client.root->parsed()) {
      msg = "Invalid client command";
    }
    std::cerr << msg << std::endl;
    ctx.rcm = {EC::InvalidArg, msg};
    store_exit_code(static_cast<int>(ctx.rcm.code));
    args.ClearActive();
    return;
  }

  ctx.command_name = command_name;

  BaseArgStruct *selected = args.GetActive();
  const ECM run_rcm = selected->Run(managers, ctx);
  const ECM sync_rcm = managers.application.config_service->FlushDirtyParticipants();
  ctx.rcm = run_rcm;
  if ((ctx.rcm) && !(sync_rcm)) {
    ctx.rcm = sync_rcm;
  }
  selected->reset();
  args.ClearActive();
  store_exit_code(static_cast<int>(ctx.rcm.code));
  return;
}

} // namespace AMInterface::cli




