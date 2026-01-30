#pragma once
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/FileSystem.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "AMManager/Transfer.hpp"
#include "CLI/CLI.hpp"
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
      ->required()
      ->expected(1);
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

  return commands;
}

/**
 * @brief Set the exit code and return.
 */
inline void SetCliExitCode(int code) { g_cli_exit_code = code; }

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
inline void DispatchCliCommands(const CliCommands &cli_commands,
                                const CliManagers &managers) {
  const CliArgsPool &args = *cli_commands.args;
  auto &config_manager = *managers.config_manager;
  auto &filesystem = *managers.filesystem;
  amf flag = amgif;

  if (cli_commands.config_cmd->parsed()) {
    if (cli_commands.config_ls->parsed()) {
      auto status = args.config_ls.detail ? config_manager.List()
                                          : config_manager.ListName();
      SetCliExitCode(static_cast<int>(status.first));
      return;
    }
    if (cli_commands.config_keys->parsed()) {
      auto result = config_manager.PrivateKeys(true);
      SetCliExitCode(static_cast<int>(result.first.first));
      return;
    }
    if (cli_commands.config_data->parsed()) {
      auto status = config_manager.Src();
      SetCliExitCode(static_cast<int>(status.first));
      return;
    }
    if (cli_commands.config_get->parsed()) {
      auto status = config_manager.Query(args.config_get.nickname);
      SetCliExitCode(static_cast<int>(status.first));
      return;
    }
    if (cli_commands.config_add->parsed()) {
      auto status = config_manager.Add();
      SetCliExitCode(static_cast<int>(status.first));
      return;
    }
    if (cli_commands.config_edit->parsed()) {
      auto status = config_manager.Modify(args.config_edit.nickname);
      SetCliExitCode(static_cast<int>(status.first));
      return;
    }
    if (cli_commands.config_rn->parsed()) {
      auto status = config_manager.Rename(args.config_rn.old_name,
                                          args.config_rn.new_name);
      SetCliExitCode(static_cast<int>(status.first));
      return;
    }
    if (cli_commands.config_rm->parsed()) {
      auto status = config_manager.Delete(args.config_rm.names);
      SetCliExitCode(static_cast<int>(status.first));
      return;
    }
    std::cerr << "Invalid config command" << std::endl;
    SetCliExitCode(static_cast<int>(EC::InvalidArg));
    return;
  }

  if (cli_commands.stat_cmd->parsed()) {
    ECM rcm = filesystem.stat(args.stat.paths, flag);
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.ls_cmd->parsed()) {
    ECM rcm =
        filesystem.ls(args.ls.path, args.ls.list_like, args.ls.show_all, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.size_cmd->parsed()) {
    ECM rcm = filesystem.getsize(args.size.paths, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.find_cmd->parsed()) {
    ECM rcm = filesystem.find(args.find.path, SearchType::All, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.mkdir_cmd->parsed()) {
    ECM rcm = filesystem.mkdir(args.mkdir.paths, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.rm_cmd->parsed()) {
    ECM rcm = filesystem.rm(args.rm.paths, args.rm.permanent, false, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.walk_cmd->parsed()) {
    ECM rcm =
        filesystem.walk(args.walk.path, args.walk.only_file, args.walk.only_dir,
                        !args.walk.include_special, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.tree_cmd->parsed()) {
    ECM rcm = filesystem.tree(args.tree.path, args.tree.depth,
                              !args.tree.include_special, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.cp_cmd->parsed()) {
    if (args.cp.srcs.empty()) {
      std::cerr << "cp requires at least one source" << std::endl;
      SetCliExitCode(static_cast<int>(EC::InvalidArg));
      return;
    }
    std::vector<std::string> srcs;
    std::string dst;
    if (args.cp.output.empty()) {
      if (args.cp.srcs.size() != 2) {
        std::cerr << "cp requires exactly 2 paths when --output is omitted"
                  << std::endl;
        SetCliExitCode(static_cast<int>(EC::InvalidArg));
        return;
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

    AMTransferManager transfer_manager(*managers.config_manager,
                                        *managers.client_manager);
    ECM rcm =
        transfer_manager.transfer({transfer_set}, args.cp.quiet, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.sftp_cmd->parsed()) {
    ECM rcm = filesystem.sftp(args.sftp.nickname, args.sftp.user_at_host,
                              args.sftp.port, args.sftp.password,
                              args.sftp.keyfile, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  if (cli_commands.ftp_cmd->parsed()) {
    ECM rcm =
        filesystem.ftp(args.ftp.nickname, args.ftp.user_at_host, args.ftp.port,
                       args.ftp.password, args.ftp.keyfile, flag);
    if (rcm.first != EC::Success) {
      std::cerr << rcm.second << std::endl;
    }
    SetCliExitCode(static_cast<int>(rcm.first));
    return;
  }

  std::cerr << "No valid command provided" << std::endl;
  SetCliExitCode(static_cast<int>(EC::InvalidArg));
}
