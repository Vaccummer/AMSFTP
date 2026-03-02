#pragma once
#include "AMBase/DataClass.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/FileSystem.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Logger.hpp"
#include "AMManager/Prompt.hpp"
#include "AMManager/Set.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "AMManager/Transfer.hpp"
#include "AMManager/Var.hpp"
#include "CLI/CLI.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

struct CliRunContext;

/**
 * @brief Manager references for CLI dispatch.
 */
struct CliManagers : public NonCopyableNonMovable {
  /**
   * @brief Return the singleton manager bundle used by CLI entry points.
   */
  static CliManagers &Instance();

  /**
   * @brief Initialize all manager singletons in dependency-safe order.
   */
  ECM Init() override;

  AMCliSignalMonitor &signal_monitor = AMCliSignalMonitor::Instance();
  AMConfigManager &config_manager = AMConfigManager::Instance();
  AMPromptManager &prompt_manager = AMPromptManager::Instance();
  AMHostManager &host_manager = AMHostManager::Instance();
  VarCLISet &var_manager = VarCLISet::Instance();
  AMLogManager &log_manager = AMLogManager::Instance();
  AMClientManager &client_manager = AMClientManager::Instance();
  AMTransferManager &transfer_manager = AMTransferManager::Instance();
  AMSetManager &set_manager = AMSetManager::Instance();
  AMFileSystem &filesystem = AMFileSystem::Instance();

private:
  /**
   * @brief Bind all references to their corresponding singleton instances.
   */
  CliManagers() = default;
};

/**
 * @brief Runtime context for invoking Args::Run.
 */
struct CliRunContext : NonCopyableNonMovable {
  ~CliRunContext() override = default;
  static CliRunContext &Instance();
  ECM rcm = {EC::Success, ""};
  bool async = false;
  bool enforce_interactive = false;
  std::string command_name;
  bool *enter_interactive = nullptr;
  bool *request_exit = nullptr;
  bool *skip_loop_exit_callbacks = nullptr;
  std::shared_ptr<std::atomic<int>> exit_code;
  std::shared_ptr<std::atomic<bool>> is_interactive = nullptr;

private:
  CliRunContext() = default;
};

void ShowTaskInspectInfo();

/**
 * @brief CLI argument container for config ls.
 */
struct ConfigLsArgs {
  bool detail = false;
  /**
   * @brief Execute config ls with optional detail flag.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-ls arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for config keys.
 */
struct ConfigKeysArgs {
  /**
   * @brief Execute config keys.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-keys arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for config data.
 */
struct ConfigDataArgs {
  /**
   * @brief Execute config data.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-data arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for config get.
 */
struct ConfigGetArgs {
  std::vector<std::string> nicknames;
  /**
   * @brief Execute config get with optional nickname list.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-get arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for config add.
 */
struct ConfigAddArgs {
  std::string nickname;
  /**
   * @brief Execute config add.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-add arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for config edit.
 */
struct ConfigEditArgs {
  std::string nickname;
  /**
   * @brief Execute config edit for a nickname.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-edit arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-rename arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for config remove.
 */
struct ConfigRemoveArgs {
  std::vector<std::string> names;
  /**
   * @brief Execute config remove for target names.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-remove arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-set arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for config save.
 */
struct ConfigSaveArgs {
  /**
   * @brief Execute config save.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config-save arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for config profile set.
 */
struct ConfigProfileSetArgs {
  std::string nickname;
  /**
   * @brief Execute config profile set.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset config profile set arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for profile edit.
 */
struct ProfileEditArgs {
  std::string nickname;
  /**
   * @brief Execute profile edit for a host nickname.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset profile-edit arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for profile get.
 */
struct ProfileGetArgs {
  std::vector<std::string> nicknames;
  /**
   * @brief Execute profile get for one or more host nicknames.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset profile-get arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for stat.
 */
struct StatArgs {
  std::vector<std::string> paths;
  /**
   * @brief Execute stat for target paths.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset stat arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset ls arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for size.
 */
struct SizeArgs {
  std::vector<std::string> paths;
  /**
   * @brief Execute size for target paths.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset size arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for find.
 */
struct FindArgs {
  std::string path;
  /**
   * @brief Execute find for a path.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset find arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for mkdir.
 */
struct MkdirArgs {
  std::vector<std::string> paths;
  /**
   * @brief Execute mkdir for target paths.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset mkdir arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset rm arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset walk arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset tree arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for realpath.
 */
struct RealpathArgs {
  std::string path;
  /**
   * @brief Execute realpath for a target path.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset realpath arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for rtt.
 */
struct RttArgs {
  int times = 1;
  /**
   * @brief Execute rtt with sample count.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset rtt arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for clear.
 */
struct ClearArgs {
  bool all = false;
  /**
   * @brief Execute clear screen.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset clear arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset cp arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset sftp arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset ftp arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for clients.
 */
struct ClientsArgs {
  bool detail = false;
  /**
   * @brief Execute clients list.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset clients arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset check arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for ch.
 */
struct ChangeClientArgs {
  std::string nickname;
  /**
   * @brief Execute client change.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset change-client arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for disconnect.
 */
struct DisconnectArgs {
  std::vector<std::string> nicknames;
  /**
   * @brief Execute client disconnect.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset disconnect arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for cd.
 */
struct CdArgs {
  std::string path;
  /**
   * @brief Execute cd.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset cd arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for connect.
 */
struct ConnectArgs {
  std::vector<std::string> nicknames;
  bool force = false;
  /**
   * @brief Execute connect.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset connect arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for cmd.
 */
struct CmdArgs {
  int timeout_ms = 5000;
  std::string cmd_str;
  /**
   * @brief Execute one shell command on current SFTP/local client.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset cmd arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for bash.
 */
struct BashArgs {
  /**
   * @brief Enter interactive mode.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset bash arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for exit.
 */
struct ExitArgs {
  bool force = false;
  /**
   * @brief Request interactive-loop exit.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset exit arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for `var get`.
 */
struct VarGetArgs {
  std::string varname;
  /**
   * @brief Execute `var get`.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset args to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for `var def`.
 */
struct VarDefArgs {
  bool global = false;
  std::string varname;
  std::string value;
  /**
   * @brief Execute `var def`.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset args to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for `var del`.
 */
struct VarDelArgs {
  bool all = false;
  std::vector<std::string> tokens;
  /**
   * @brief Execute `var del`.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset args to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for `var ls`.
 */
struct VarLsArgs {
  std::vector<std::string> sections;
  /**
   * @brief Execute `var ls`.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset args to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for complete cache clear.
 */
struct CompleteCacheClearArgs {
  /**
   * @brief Execute completion cache clear.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset completion cache clear arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-list arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for task show.
 */
struct TaskShowArgs {
  std::vector<std::string> ids;
  /**
   * @brief Execute task show.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-show arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-inspect arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for task thread.
 */
struct TaskThreadArgs {
  int num = -1;
  /**
   * @brief Execute task thread update/query.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-thread arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-cache-add arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for task cache rm.
 */
struct TaskCacheRmArgs {
  std::vector<size_t> indices;
  /**
   * @brief Execute task cache remove.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-cache-rm arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for task cache clear.
 */
struct TaskCacheClearArgs {
  /**
   * @brief Execute task cache clear.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-cache-clear arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for task cache submit.
 */
struct TaskCacheSubmitArgs {
  bool is_async = false;
  bool quiet = false;
  std::string async_suffix;
  /**
   * @brief Execute task cache submit.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-cache-submit arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for task userset.
 */
struct TaskUserSetArgs {
  std::vector<size_t> indices;
  /**
   * @brief Execute task userset query.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-userset arguments to defaults.
   */
  void reset();
};

/**
 * @brief CLI argument container for task query.
 */
struct TaskEntryArgs {
  std::vector<std::string> ids;
  /**
   * @brief Execute task entry query.
   */
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-entry arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-control arguments to defaults.
   */
  void reset();
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
  ECM Run(const CliManagers &managers, const CliRunContext &ctx) const;
  /**
   * @brief Reset task-retry arguments to defaults.
   */
  void reset();
};

/**
 * @brief Variant wrapper for selected parsed CLI argument payload.
 */
using CommonArg = std::variant<
    std::monostate, ConfigLsArgs, ConfigKeysArgs, ConfigDataArgs, ConfigGetArgs,
    ConfigAddArgs, ConfigEditArgs, ConfigRenameArgs, ConfigRemoveArgs,
    ConfigSetArgs, ConfigSaveArgs, ConfigProfileSetArgs, ProfileEditArgs,
    ProfileGetArgs, StatArgs, LsArgs, SizeArgs, FindArgs, MkdirArgs, RmArgs,
    WalkArgs, TreeArgs, RealpathArgs, RttArgs, ClearArgs, CpArgs, SftpArgs,
    FtpArgs, ClientsArgs, CheckArgs, ChangeClientArgs, DisconnectArgs, CdArgs,
    ConnectArgs, CmdArgs, BashArgs, ExitArgs, VarGetArgs, VarDefArgs,
    VarDelArgs, VarLsArgs, CompleteCacheClearArgs, TaskListArgs, TaskShowArgs,
    TaskInspectArgs, TaskThreadArgs, TaskCacheAddArgs, TaskCacheRmArgs,
    TaskCacheClearArgs, TaskCacheSubmitArgs, TaskUserSetArgs, TaskEntryArgs,
    TaskControlArgs, TaskRetryArgs>;

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
  ConfigProfileSetArgs config_profile_set;
  ProfileEditArgs profile_edit;
  ProfileGetArgs profile_get;
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
  CmdArgs cmd;
  BashArgs bash;
  ExitArgs exit;
  VarGetArgs var_get;
  VarDefArgs var_def;
  VarDelArgs var_del;
  VarLsArgs var_ls;
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
  CLI::App *config_profile_cmd = nullptr;
  CLI::App *config_profile_set = nullptr;
  CLI::App *profile_cmd = nullptr;
  CLI::App *profile_edit_cmd = nullptr;
  CLI::App *profile_get_cmd = nullptr;
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
  CLI::App *cmd_cmd = nullptr;
  CLI::App *exit_cmd = nullptr;
  CLI::App *var_cmd = nullptr;
  CLI::App *var_get_cmd = nullptr;
  CLI::App *var_def_cmd = nullptr;
  CLI::App *var_del_cmd = nullptr;
  CLI::App *var_ls_cmd = nullptr;
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
  bool request_exit = false;
  bool skip_loop_exit_callbacks = false;
};
