
#include "AMCLI/CLIBind.hpp"
#include <type_traits>

int g_cli_exit_code = 0;
namespace {
/**
 * @brief Bind a CLI11 callback that stores the selected argument struct.
 */
template <typename T>
void BindArgSelection_(CLI::App *command, CliArgsPool &args,
                       T CliArgsPool::*member) {
  if (!command) {
    return;
  }
  command->callback([&args, member]() { args.common_arg = args.*member; });
}

} // namespace

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
  commands.config_hostset_cmd =
      commands.config_cmd->add_subcommand("hostset", "Manage HostSet");
  commands.config_hostset_add =
      commands.config_hostset_cmd->add_subcommand("add", "Create host set");
  commands.config_hostset_edit =
      commands.config_hostset_cmd->add_subcommand("edit", "Modify host set");
  commands.config_hostset_rm =
      commands.config_hostset_cmd->add_subcommand("rm", "Delete host set");
  commands.config_hostset_save =
      commands.config_hostset_cmd->add_subcommand("save", "Save HostSet");

  commands.config_get
      ->add_option("nicknames", args.config_get.nicknames, "Host nicknames")
      ->expected(0, -1);
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
      ->add_option("nickname", args.config_set.nickname, "Host nickname")
      ->required();
  commands.config_set
      ->add_option("attrname", args.config_set.attrname, "Host property name")
      ->required();
  commands.config_set
      ->add_option("value", args.config_set.value, "Host property value")
      ->required();
  commands.config_hostset_add
      ->add_option("nickname", args.config_hostset_add.nickname,
                   "Host nickname")
      ->required();
  commands.config_hostset_edit
      ->add_option("nickname", args.config_hostset_edit.nickname,
                   "Host nickname")
      ->required();
  commands.config_hostset_rm
      ->add_option("nicknames", args.config_hostset_rm.nicknames,
                   "Host nicknames")
      ->expected(1, -1);

  BindArgSelection_(commands.config_ls, args, &CliArgsPool::config_ls);
  BindArgSelection_(commands.config_keys, args, &CliArgsPool::config_keys);
  BindArgSelection_(commands.config_data, args, &CliArgsPool::config_data);
  BindArgSelection_(commands.config_get, args, &CliArgsPool::config_get);
  BindArgSelection_(commands.config_add, args, &CliArgsPool::config_add);
  BindArgSelection_(commands.config_edit, args, &CliArgsPool::config_edit);
  BindArgSelection_(commands.config_rn, args, &CliArgsPool::config_rn);
  BindArgSelection_(commands.config_rm, args, &CliArgsPool::config_rm);
  BindArgSelection_(commands.config_set, args, &CliArgsPool::config_set);
  BindArgSelection_(commands.config_save, args, &CliArgsPool::config_save);
  BindArgSelection_(commands.config_hostset_add, args,
                    &CliArgsPool::config_hostset_add);
  BindArgSelection_(commands.config_hostset_edit, args,
                    &CliArgsPool::config_hostset_edit);
  BindArgSelection_(commands.config_hostset_rm, args,
                    &CliArgsPool::config_hostset_rm);
  BindArgSelection_(commands.config_hostset_save, args,
                    &CliArgsPool::config_hostset_save);
}

/**
 * @brief Bind client-related CLI commands.
 */
void BindClientCommands(CLI::App &app, CliArgsPool &args,
                        CliCommands &commands) {
  commands.client_cmd = app.add_subcommand("client", "Client manager");
  commands.client_ls_cmd =
      commands.client_cmd->add_subcommand("ls", "List client names");
  commands.client_ls_cmd->add_flag("-d,--detail", args.clients.detail,
                                   "Show full status details");
  commands.client_check_cmd =
      commands.client_cmd->add_subcommand("check", "Check client status");
  commands.client_check_cmd
      ->add_option("nicknames", args.check.nicknames, "Client nicknames")
      ->expected(0, -1);
  commands.client_check_cmd->add_flag("-d,--detail", args.check.detail,
                                      "Show client details");
  commands.client_rm_cmd =
      commands.client_cmd->add_subcommand("rm", "Disconnect clients");
  commands.client_rm_cmd
      ->add_option("nicknames", args.disconnect.nicknames,
                   "Client nicknames to disconnect")
      ->expected(1, -1);

  BindArgSelection_(commands.client_ls_cmd, args, &CliArgsPool::clients);
  BindArgSelection_(commands.client_check_cmd, args, &CliArgsPool::check);
  BindArgSelection_(commands.client_rm_cmd, args, &CliArgsPool::disconnect);
}

/**
 * @brief Bind variable-related CLI commands.
 */
void BindVarCommands(CLI::App &app, CliArgsPool &args, CliCommands &commands) {
  commands.var_cmd = app.add_subcommand("var", "Variable manager");
  commands.var_get_cmd =
      commands.var_cmd->add_subcommand("get", "Query variable by name");
  commands.var_get_cmd->add_option("varname", args.var_get.varname, "$varname")
      ->required()
      ->expected(1, 1);

  commands.var_def_cmd =
      commands.var_cmd->add_subcommand("def", "Define variable");
  commands.var_def_cmd->add_flag("-g,--global", args.var_def.global,
                                 "Define in public section");
  commands.var_def_cmd->add_option("varname", args.var_def.varname, "$varname")
      ->required()
      ->expected(1, 1);
  commands.var_def_cmd->add_option("value", args.var_def.value, "varvalue")
      ->required()
      ->expected(1, 1);

  commands.var_del_cmd =
      commands.var_cmd->add_subcommand("del", "Delete variable");
  commands.var_del_cmd->add_flag("-a,--all", args.var_del.all,
                                 "Delete from all sections");
  commands.var_del_cmd
      ->add_option("tokens", args.var_del.tokens, "[section] $varname")
      ->required()
      ->expected(1, 2);

  commands.var_ls_cmd =
      commands.var_cmd->add_subcommand("ls", "List variables by section");
  commands.var_ls_cmd
      ->add_option("sections", args.var_ls.sections, "section names")
      ->expected(0, -1);

  BindArgSelection_(commands.var_get_cmd, args, &CliArgsPool::var_get);
  BindArgSelection_(commands.var_def_cmd, args, &CliArgsPool::var_def);
  BindArgSelection_(commands.var_del_cmd, args, &CliArgsPool::var_del);
  BindArgSelection_(commands.var_ls_cmd, args, &CliArgsPool::var_ls);
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
  commands.rm_cmd->add_flag("-q,--quiet", args.rm.quiet,
                            "Suppress error output");

  commands.walk_cmd = app.add_subcommand("walk", "Walk paths");
  commands.walk_cmd->add_option("path", args.walk.path, "Path to walk")
      ->required()
      ->expected(1, 1);
  commands.walk_cmd->add_flag("-f,--file", args.walk.only_file,
                              "Only show files");
  commands.walk_cmd->add_flag("-d,--dir", args.walk.only_dir,
                              "Only show directories");
  commands.walk_cmd->add_flag("-a,--all", args.walk.show_all,
                              "Show hidden entries");
  commands.walk_cmd->add_flag("-s,--special", args.walk.include_special,
                              "Include special files");
  commands.walk_cmd->add_flag("-q,--quiet", args.walk.quiet,
                              "Suppress error output");

  commands.tree_cmd = app.add_subcommand("tree", "Print directory tree");
  commands.tree_cmd->add_option("path", args.tree.path, "Path to tree")
      ->required()
      ->expected(1, 1);
  commands.tree_cmd->add_option("-d,--depth", args.tree.depth,
                                "Max depth (default: -1)");
  commands.tree_cmd->add_flag("-o,--onlydir", args.tree.only_dir,
                              "Only show directories");
  commands.tree_cmd->add_flag("-a,--all", args.tree.show_all,
                              "Show hidden entries");
  commands.tree_cmd->add_flag("-s,--special", args.tree.include_special,
                              "Include special files");
  commands.tree_cmd->add_flag("-q,--quiet", args.tree.quiet,
                              "Suppress error output");

  commands.realpath_cmd = app.add_subcommand("realpath", "Print absolute path");
  commands.realpath_cmd
      ->add_option("path", args.realpath.path, "Path to resolve")
      ->expected(0, 1);

  commands.rtt_cmd = app.add_subcommand("rtt", "Measure current client RTT");
  commands.rtt_cmd->add_option("times", args.rtt.times, "Samples (default: 1)")
      ->expected(0, 1);

  commands.clear_cmd = app.add_subcommand("clear", "Clear screen");
  commands.clear_cmd->add_flag("-a,--all", args.clear.all,
                               "Clear scrollback buffer");

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
  commands.cp_cmd->add_flag("-r,--resume", args.cp.resume,
                            "Resume from existing destination file");
  commands.cp_cmd->add_flag("-q,--quiet", args.cp.quiet,
                            "Suppress transfer output");

  commands.sftp_cmd = app.add_subcommand("sftp", "Connect to SFTP host");
  commands.sftp_cmd
      ->add_option("targets", args.sftp.targets,
                   "nickname user@host | user@host")
      ->required()
      ->expected(1, 2);
  commands.sftp_cmd->add_option("-p,--port", args.sftp.port, "Port");
  commands.sftp_cmd->add_option("--keyfile", args.sftp.keyfile, "Keyfile");

  commands.ftp_cmd = app.add_subcommand("ftp", "Connect to FTP host");
  commands.ftp_cmd
      ->add_option("targets", args.ftp.targets,
                   "nickname user@host | user@host")
      ->required()
      ->expected(1, 2);
  commands.ftp_cmd->add_option("-p,--port", args.ftp.port, "Port");
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
  commands.connect_cmd->add_flag("-f,--force", args.connect.force,
                                 "Rebuild and replace existing client");

  commands.bash_cmd = app.add_subcommand("bash", "Enter interactive mode");
  commands.exit_cmd = app.add_subcommand("exit", "Exit interactive mode");
  commands.exit_cmd->add_flag(
      "-f,--force", args.exit.force,
      "Exit immediately without interactive-loop exit callbacks");

  BindArgSelection_(commands.stat_cmd, args, &CliArgsPool::stat);
  BindArgSelection_(commands.ls_cmd, args, &CliArgsPool::ls);
  BindArgSelection_(commands.size_cmd, args, &CliArgsPool::size);
  BindArgSelection_(commands.find_cmd, args, &CliArgsPool::find);
  BindArgSelection_(commands.mkdir_cmd, args, &CliArgsPool::mkdir);
  BindArgSelection_(commands.rm_cmd, args, &CliArgsPool::rm);
  BindArgSelection_(commands.walk_cmd, args, &CliArgsPool::walk);
  BindArgSelection_(commands.tree_cmd, args, &CliArgsPool::tree);
  BindArgSelection_(commands.realpath_cmd, args, &CliArgsPool::realpath);
  BindArgSelection_(commands.rtt_cmd, args, &CliArgsPool::rtt);
  BindArgSelection_(commands.clear_cmd, args, &CliArgsPool::clear);
  BindArgSelection_(commands.cp_cmd, args, &CliArgsPool::cp);
  BindArgSelection_(commands.sftp_cmd, args, &CliArgsPool::sftp);
  BindArgSelection_(commands.ftp_cmd, args, &CliArgsPool::ftp);
  BindArgSelection_(commands.ch_cmd, args, &CliArgsPool::ch);
  BindArgSelection_(commands.cd_cmd, args, &CliArgsPool::cd);
  BindArgSelection_(commands.connect_cmd, args, &CliArgsPool::connect);
  BindArgSelection_(commands.bash_cmd, args, &CliArgsPool::bash);
  BindArgSelection_(commands.exit_cmd, args, &CliArgsPool::exit);
}

/**
 * @brief Bind completion-related CLI commands.
 */
void BindCompleteCommands(CLI::App &app, CliArgsPool &args,
                          CliCommands &commands) {
  (void)args;
  commands.complete_cmd =
      app.add_subcommand("complete", "Completion utilities");
  commands.complete_cache_cmd =
      commands.complete_cmd->add_subcommand("cache", "Manage completion cache");
  commands.complete_cache_clear = commands.complete_cache_cmd->add_subcommand(
      "clear", "Clear completion cache");
  BindArgSelection_(commands.complete_cache_clear, args,
                    &CliArgsPool::complete_cache_clear);
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
  commands.task_cache_add->add_flag("-r,--resume", args.task_cache_add.resume,
                                    "Resume from existing destination file");

  commands.task_cache_rm =
      commands.task_cache_cmd->add_subcommand("rm", "Remove cached sets");
  commands.task_cache_rm
      ->add_option("indices", args.task_cache_rm.indices, "Cache indices")
      ->expected(1, -1);

  commands.task_cache_clear =
      commands.task_cache_cmd->add_subcommand("clear", "Clear cache");

  commands.task_cache_submit =
      commands.task_cache_cmd->add_subcommand("submit", "Submit cached tasks");
  commands.task_cache_submit->add_flag(
      "-a,--async", args.task_cache_submit.is_async, "Submit as async task");
  commands.task_cache_submit->add_flag("-q,--quiet",
                                       args.task_cache_submit.quiet,
                                       "Suppress output and confirmation");
  commands.task_cache_submit
      ->add_option("tail", args.task_cache_submit.async_suffix,
                   "Optional '&' async suffix")
      ->expected(0, 1);
  commands.task_userset_cmd =
      commands.task_cmd->add_subcommand("userset", "Inspect cached transfer");
  commands.task_userset_cmd
      ->add_option("index", args.task_userset.indices, "Cache index")
      ->expected(0, -1);

  commands.task_list_cmd =
      commands.task_cmd->add_subcommand("ls", "List tasks");
  commands.task_list_cmd->add_flag("-p,--pending", args.task_list.pending,
                                   "Show pending tasks");
  commands.task_list_cmd->add_flag("-s,--suspend", args.task_list.suspend,
                                   "Show paused tasks");
  commands.task_list_cmd->add_flag("-f,--finished", args.task_list.finished,
                                   "Show finished tasks");
  commands.task_list_cmd->add_flag("-c,--conducting", args.task_list.conducting,
                                   "Show conducting tasks");

  commands.task_show_cmd =
      commands.task_cmd->add_subcommand("show", "Show task status");
  commands.task_show_cmd->add_option("id", args.task_show.ids, "Task ID")
      ->required()
      ->expected(1, -1);

  commands.task_thread_cmd =
      commands.task_cmd->add_subcommand("thread", "Get or set thread count");
  commands.task_thread_cmd
      ->add_option("num", args.task_thread.num, "Thread count (optional)")
      ->expected(0, 1);

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
      commands.task_cmd->add_subcommand("resume", "Resume paused task(s)");
  commands.task_resume_cmd->add_option("id", args.task_resume.ids, "Task IDs")
      ->expected(1, -1);

  commands.task_retry_cmd = commands.task_cmd->add_subcommand(
      "retry", "Retry a completed task (retry failed entries)");
  commands.task_retry_cmd->add_flag("-a,--async", args.task_retry.is_async,
                                    "Submit task asynchronously");
  commands.task_retry_cmd->add_flag("-q,--quiet", args.task_retry.quiet,
                                    "Suppress output");
  commands.task_retry_cmd->add_option("id", args.task_retry.id, "Task ID")
      ->required()
      ->expected(1, 1);
  commands.task_retry_cmd
      ->add_option("-i,--index", args.task_retry.indices,
                   "1-based task indices to retry")
      ->expected(0, -1);

  commands.resume_cmd = app.add_subcommand(
      "retry", "Retry a completed but failed task (retry failed entries)");
  commands.resume_cmd->add_flag("-a,--async", args.task_retry.is_async,
                                "Submit task asynchronously");
  commands.resume_cmd->add_flag("-q,--quiet", args.task_retry.quiet,
                                "Suppress output");
  commands.resume_cmd->add_option("id", args.task_retry.id, "Task ID")
      ->required()
      ->expected(1, 1);
  commands.resume_cmd
      ->add_option("-i,--index", args.task_retry.indices,
                   "1-based task indices to retry")
      ->expected(0, -1);

  args.task_terminate.action = TaskControlArgs::Action::Terminate;
  args.task_pause.action = TaskControlArgs::Action::Pause;
  args.task_resume.action = TaskControlArgs::Action::Resume;

  BindArgSelection_(commands.task_cache_add, args,
                    &CliArgsPool::task_cache_add);
  BindArgSelection_(commands.task_cache_rm, args, &CliArgsPool::task_cache_rm);
  BindArgSelection_(commands.task_cache_clear, args,
                    &CliArgsPool::task_cache_clear);
  BindArgSelection_(commands.task_cache_submit, args,
                    &CliArgsPool::task_cache_submit);
  BindArgSelection_(commands.task_list_cmd, args, &CliArgsPool::task_list);
  BindArgSelection_(commands.task_show_cmd, args, &CliArgsPool::task_show);
  BindArgSelection_(commands.task_inspect_cmd, args,
                    &CliArgsPool::task_inspect);
  BindArgSelection_(commands.task_thread_cmd, args, &CliArgsPool::task_thread);
  BindArgSelection_(commands.task_userset_cmd, args,
                    &CliArgsPool::task_userset);
  BindArgSelection_(commands.task_query_cmd, args, &CliArgsPool::task_entry);
  BindArgSelection_(commands.task_terminate_cmd, args,
                    &CliArgsPool::task_terminate);
  BindArgSelection_(commands.task_pause_cmd, args, &CliArgsPool::task_pause);
  BindArgSelection_(commands.task_resume_cmd, args, &CliArgsPool::task_resume);
  BindArgSelection_(commands.task_retry_cmd, args, &CliArgsPool::task_retry);
  BindArgSelection_(commands.resume_cmd, args, &CliArgsPool::task_retry);
}

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args) {
  CliCommands commands;
  commands.app = &app;
  commands.args = &args;
  BindConfigCommands(app, args, commands);
  BindClientCommands(app, args, commands);
  BindVarCommands(app, args, commands);
  BindFilesystemCommands(app, args, commands);
  BindCompleteCommands(app, args, commands);
  BindTaskCommands(app, args, commands);
  return commands;
}

/**
 * @brief Build tree structure from CLI metadata.
 */
void CommandTree::Build(CLI::App &app) {
  nodes_.clear();
  top_commands_.clear();
  modules_.clear();
  top_help_.clear();

  auto subs = app.get_subcommands([](CLI::App *) { return true; });
  for (auto *sub : subs) {
    if (!sub) {
      continue;
    }
    RegisterCommand_(sub->get_name(), sub->get_description());
  }
  for (auto *sub : subs) {
    if (!sub) {
      continue;
    }
    auto nested = sub->get_subcommands([](CLI::App *) { return true; });
    if (!nested.empty()) {
      modules_.insert(sub->get_name());
    }
  }

  auto build_node = [&](auto &&self, CLI::App *node_app,
                        const std::string &path, bool is_root) -> void {
    if (!node_app) {
      return;
    }

    CommandNode node;
    auto options = node_app->get_options();
    for (auto *opt : options) {
      if (!opt) {
        continue;
      }
      const std::string desc = opt->get_description();
      for (const auto &lname : opt->get_lnames()) {
        if (!lname.empty()) {
          node.long_options.emplace("--" + lname, desc);
        }
      }
      for (const auto &sname : opt->get_snames()) {
        if (!sname.empty()) {
          node.short_options.emplace(sname[0], desc);
        }
      }
    }

    auto subs_local =
        node_app->get_subcommands([](CLI::App *) { return true; });
    for (auto *sub : subs_local) {
      if (!sub) {
        continue;
      }
      node.subcommands.emplace(sub->get_name(), sub->get_description());
    }

    if (!is_root) {
      nodes_[path] = node;
    }

    for (auto *sub : subs_local) {
      if (!sub) {
        continue;
      }
      std::string next =
          path.empty() ? sub->get_name() : path + " " + sub->get_name();
      self(self, sub, next, false);
    }
  };

  build_node(build_node, &app, "", true);
}

/**
 * @brief Return true when name is a top-level command.
 */
bool CommandTree::IsTopCommand(const std::string &name) const {
  return top_commands_.find(name) != top_commands_.end();
}

/**
 * @brief Return true when name is a module (has subcommands).
 */
bool CommandTree::IsModule(const std::string &name) const {
  return modules_.find(name) != modules_.end();
}

/**
 * @brief Find a node by command path.
 */
const CommandTree::CommandNode *
CommandTree::FindNode(const std::string &path) const {
  auto it = nodes_.find(path);
  if (it == nodes_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief List top-level commands with help text.
 */
std::vector<std::pair<std::string, std::string>>
CommandTree::ListTopCommands() const {
  std::vector<std::pair<std::string, std::string>> out;
  out.reserve(top_help_.size());
  for (const auto &entry : top_help_) {
    out.emplace_back(entry.first, entry.second);
  }
  return out;
}

/**
 * @brief List subcommands for a command path.
 */
std::vector<std::pair<std::string, std::string>>
CommandTree::ListSubcommands(const std::string &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  auto it = nodes_.find(path);
  if (it == nodes_.end()) {
    return out;
  }
  out.reserve(it->second.subcommands.size());
  for (const auto &entry : it->second.subcommands) {
    out.emplace_back(entry.first, entry.second);
  }
  return out;
}

/**
 * @brief List long options for a command path.
 */
std::vector<std::pair<std::string, std::string>>
CommandTree::ListLongOptions(const std::string &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  auto it = nodes_.find(path);
  if (it == nodes_.end()) {
    return out;
  }
  out.reserve(it->second.long_options.size());
  for (const auto &entry : it->second.long_options) {
    out.emplace_back(entry.first, entry.second);
  }
  return out;
}

/**
 * @brief List short options for a command path.
 */
std::vector<std::pair<char, std::string>>
CommandTree::ListShortOptions(const std::string &path) const {
  std::vector<std::pair<char, std::string>> out;
  auto it = nodes_.find(path);
  if (it == nodes_.end()) {
    return out;
  }
  out.reserve(it->second.short_options.size());
  for (const auto &entry : it->second.short_options) {
    out.emplace_back(entry.first, entry.second);
  }
  return out;
}

/**
 * @brief Register a command path as top-level command.
 */
void CommandTree::RegisterCommand_(const std::string &path,
                                   const std::string &help) {
  if (path.empty()) {
    return;
  }
  top_commands_.insert(path);
  top_help_[path] = help;
}

/**
 * @brief Build the shared command tree from CLI definitions.
 */
std::shared_ptr<CommandTree> BuildCommandTree(CLI::App &app,
                                              CliArgsPool &args) {
  auto subs = app.get_subcommands([](CLI::App *) { return true; });
  if (subs.empty()) {
    (void)BindCliOptions(app, args);
  }

  auto tree = std::make_shared<CommandTree>();
  tree->Build(app);
  return tree;
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
