#include "AMClientManager.hpp"
#include "AMConfigManager.hpp"
#include "AMFileSystem.hpp"
#include "CLI/CLI.hpp"
#include "base/AMCliSignalMonitor.hpp"
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

/** Bind CLI subcommands/options to the provided option storage. */
struct CliOptions {
  bool config_detail = false;
  std::string config_get_name;
  std::string config_edit_name;
  std::string config_rn_old;
  std::string config_rn_new;
  std::vector<std::string> config_rm_names;

  std::vector<std::string> stat_paths;
  std::string ls_path;
  bool ls_long = false;
  bool ls_all = false;
  std::vector<std::string> size_paths;
  std::string find_path;
  std::vector<std::string> mkdir_paths;
  std::vector<std::string> rm_paths;
  bool rm_permanent = false;
  std::string walk_path;
  bool walk_only_file = false;
  bool walk_only_dir = false;
  bool walk_include_special = false;
  std::string tree_path;
  int tree_depth = -1;
  bool tree_include_special = false;
};

/** Hold CLI subcommand pointers so parsed state can be queried. */
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
};

/** Bind all CLI actions (commands/options) in one place. */
static CliCommands BindCliOptions(CLI::App &app, CliOptions &options) {
  CliCommands commands;
  commands.config_cmd = app.add_subcommand("config", "Config manager");
  commands.config_ls =
      commands.config_cmd->add_subcommand("ls", "List configs");
  commands.config_ls->add_flag("-d,--detail", options.config_detail,
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
      ->add_option("nickname", options.config_get_name, "Host nickname")
      ->required();
  commands.config_edit
      ->add_option("nickname", options.config_edit_name, "Host nickname")
      ->required();
  commands.config_rn->add_option("old", options.config_rn_old, "Old nickname")
      ->required();
  commands.config_rn->add_option("new", options.config_rn_new, "New nickname")
      ->required();
  commands.config_rm
      ->add_option("nicknames", options.config_rm_names,
                   "Host nicknames to remove")
      ->expected(1, -1);

  commands.stat_cmd = app.add_subcommand("stat", "Print path info");
  commands.stat_cmd->add_option("paths", options.stat_paths, "Paths to stat")
      ->expected(1, -1);

  commands.ls_cmd = app.add_subcommand("ls", "List directory");
  commands.ls_cmd->add_option("path", options.ls_path, "Path to list")
      ->required();
  commands.ls_cmd->add_flag("-l", options.ls_long, "List like");
  commands.ls_cmd->add_flag("-a", options.ls_all, "Show all entries");

  commands.size_cmd = app.add_subcommand("size", "Get total size");
  commands.size_cmd->add_option("paths", options.size_paths, "Paths to size")
      ->expected(1, -1);

  commands.find_cmd = app.add_subcommand("find", "Find paths");
  commands.find_cmd->add_option("path", options.find_path, "Path to find")
      ->required();

  commands.mkdir_cmd = app.add_subcommand("mkdir", "Create directories");
  commands.mkdir_cmd
      ->add_option("paths", options.mkdir_paths, "Paths to create")
      ->expected(1, -1);

  commands.rm_cmd = app.add_subcommand("rm", "Remove paths");
  commands.rm_cmd->add_option("paths", options.rm_paths, "Paths to remove")
      ->expected(1, -1);
  commands.rm_cmd->add_flag("-p,--permanent", options.rm_permanent,
                            "Delete permanently");

  commands.walk_cmd = app.add_subcommand("walk", "Walk paths");
  commands.walk_cmd->add_option("path", options.walk_path, "Path to walk")
      ->required();
  commands.walk_cmd->add_flag("-f,--file", options.walk_only_file,
                              "Only show files");
  commands.walk_cmd->add_flag("-d,--dir", options.walk_only_dir,
                              "Only show directories");
  commands.walk_cmd->add_flag("-s,--special", options.walk_include_special,
                              "Include special files");

  commands.tree_cmd = app.add_subcommand("tree", "Print directory tree");
  commands.tree_cmd->add_option("path", options.tree_path, "Path to tree")
      ->required();
  commands.tree_cmd->add_option("--depth", options.tree_depth,
                                "Max depth (default: -1)");
  commands.tree_cmd->add_flag("-s,--special", options.tree_include_special,
                              "Include special files");

  return commands;
}

/** Entry point for AMSFTP CLI (non-interactive). */
int main2(int argc, char **argv) {
  try {
    auto &signal_monitor = AMCliSignalMonitor::Instance();
    signal_monitor.InstallHandlers();
    signal_monitor.Start();

    auto &config_manager = AMConfigManager::Instance();
    auto init_status = config_manager.Init();
    if (init_status.first != EC::Success) {
      std::cerr << init_status.second << std::endl;
      return static_cast<int>(init_status.first);
    }

    auto &client_manager = AMClientManager::Instance(config_manager);
    auto &filesystem = AMFileSystem::Instance(client_manager, config_manager);
    AMClientManager::global_interrupt_flag = amgif;
    AMFileSystem::global_interrupt_flag = amgif;
    AMFileSystem::AMIsInBash = false;

    const std::string app_name =
        fs::path(argc > 0 ? argv[0] : "amsftp").filename().string();
    CLI::App app{"AMSFTP CLI", app_name};

    CliOptions cli_options;
    CliCommands cli_commands = BindCliOptions(app, cli_options);

    try {
      CLI11_PARSE(app, argc, argv);
    } catch (const CLI::ParseError &e) {
      return app.exit(e);
    }

    if (cli_commands.config_cmd->parsed()) {
      if (cli_commands.config_ls->parsed()) {
        auto status = cli_options.config_detail ? config_manager.List()
                                                : config_manager.ListName();
        return static_cast<int>(status.first);
      }
      if (cli_commands.config_keys->parsed()) {
        auto result = config_manager.PrivateKeys(true);
        return static_cast<int>(result.first.first);
      }
      if (cli_commands.config_data->parsed()) {
        auto status = config_manager.Src();
        return static_cast<int>(status.first);
      }
      if (cli_commands.config_get->parsed()) {
        auto status = config_manager.Query(cli_options.config_get_name);
        return static_cast<int>(status.first);
      }
      if (cli_commands.config_add->parsed()) {
        auto status = config_manager.Add();
        return static_cast<int>(status.first);
      }
      if (cli_commands.config_edit->parsed()) {
        auto status = config_manager.Modify(cli_options.config_edit_name);
        return static_cast<int>(status.first);
      }
      if (cli_commands.config_rn->parsed()) {
        auto status = config_manager.Rename(cli_options.config_rn_old,
                                            cli_options.config_rn_new);
        return static_cast<int>(status.first);
      }
      if (cli_commands.config_rm->parsed()) {
        auto status = config_manager.Delete(cli_options.config_rm_names);
        return static_cast<int>(status.first);
      }
      std::cerr << "Invalid config command" << std::endl;
      return static_cast<int>(EC::InvalidArg);
    }

    if (cli_commands.stat_cmd->parsed()) {
      ECM rcm = filesystem.stat(cli_options.stat_paths, amgif);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (cli_commands.ls_cmd->parsed()) {
      ECM rcm = filesystem.ls(cli_options.ls_path, cli_options.ls_long,
                              cli_options.ls_all, amgif);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (cli_commands.size_cmd->parsed()) {
      ECM rcm = filesystem.getsize(cli_options.size_paths, amgif);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (cli_commands.find_cmd->parsed()) {
      ECM rcm = filesystem.find(cli_options.find_path, SearchType::All, amgif);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (cli_commands.mkdir_cmd->parsed()) {
      ECM rcm = filesystem.mkdir(cli_options.mkdir_paths, amgif);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (cli_commands.rm_cmd->parsed()) {
      ECM rcm = filesystem.rm(cli_options.rm_paths, cli_options.rm_permanent,
                              false, amgif);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (cli_commands.walk_cmd->parsed()) {
      ECM rcm = filesystem.walk(
          cli_options.walk_path, cli_options.walk_only_file,
          cli_options.walk_only_dir, !cli_options.walk_include_special, amgif);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (cli_commands.tree_cmd->parsed()) {
      ECM rcm = filesystem.tree(cli_options.tree_path, cli_options.tree_depth,
                                !cli_options.tree_include_special, amgif);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    std::cerr << "No valid command provided" << std::endl;
    return static_cast<int>(EC::InvalidArg);
  } catch (const std::exception &e) {
    std::cerr << "Unexpected error: " << e.what() << std::endl;
    return -13;
  }
}
