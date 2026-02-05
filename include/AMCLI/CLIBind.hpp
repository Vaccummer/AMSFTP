#pragma once
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/FileSystem.hpp"
#include "AMManager/Transfer.hpp"
#include "CLI/CLI.hpp"
#include <cstddef>
#include <cstdint>
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
  std::vector<std::string> nicknames;
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
 * @brief CLI argument container for config set.
 */
struct ConfigSetArgs {
  std::vector<std::string> values;
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
  bool only_dir = false;
  bool include_special = false;
};

/**
 * @brief CLI argument container for realpath.
 */
struct RealpathArgs {
  std::string path;
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
  bool force = false;
};

/**
 * @brief CLI argument container for var.
 */
struct VarArgs {
  std::vector<std::string> tokens;
};

/**
 * @brief CLI argument container for del.
 */
struct DelArgs {
  std::vector<std::string> tokens;
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
  bool resume = false;
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
  std::vector<size_t> indices;
};

/**
 * @brief CLI argument container for task query.
 */
struct TaskEntryArgs {
  std::vector<std::string> ids;
};

/**
 * @brief CLI argument container for task control.
 */
struct TaskControlArgs {
  std::vector<std::string> ids;
};

/**
 * @brief CLI argument container for task resume (failed tasks).
 */
struct TaskResumeArgs {
  std::string id;
  bool is_async = false;
  bool quiet = false;
  std::vector<int> indices;
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
  ConfigSetArgs config_set;
  StatArgs stat;
  LsArgs ls;
  SizeArgs size;
  FindArgs find;
  MkdirArgs mkdir;
  RmArgs rm;
  WalkArgs walk;
  TreeArgs tree;
  RealpathArgs realpath;
  CpArgs cp;
  SftpArgs sftp;
  FtpArgs ftp;
  ClientsArgs clients;
  CheckArgs check;
  ChangeClientArgs ch;
  DisconnectArgs disconnect;
  CdArgs cd;
  ConnectArgs connect;
  VarArgs var;
  DelArgs del;
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
  TaskResumeArgs task_resume;
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
  CLI::App *task_userset_cmd = nullptr;
  CLI::App *task_query_cmd = nullptr;
  CLI::App *task_terminate_cmd = nullptr;
  CLI::App *task_pause_cmd = nullptr;
  CLI::App *task_resume_cmd = nullptr;
  CLI::App *resume_cmd = nullptr;
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
 * @brief Set the exit code and return.
 */
void SetCliExitCode(int code);

/**
 * @brief Print task inspect helper info.
 */
void ShowTaskInspectInfo();

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
DispatchResult DispatchCliCommands(const CliCommands &cli_commands,
                                   const CliManagers &managers,
                                   bool async = false,
                                   bool enforce_interactive = false);
