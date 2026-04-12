#pragma once

#include "CLI/App.hpp"
#include "interface/cli/ArgStruct/ClientArgStruct.hpp"
#include "interface/cli/ArgStruct/ConfigArgStruct.hpp"
#include "interface/cli/ArgStruct/FilesystemArgStruct.hpp"
#include "interface/cli/ArgStruct/HostArgStruct.hpp"
#include "interface/cli/ArgStruct/ProfileArgStruct.hpp"
#include "interface/cli/ArgStruct/TaskArgStruct.hpp"
#include "interface/cli/ArgStruct/VarArgStruct.hpp"

namespace AMInterface::cli {

struct CliConfigArgs {
  ConfigLsArgs ls = {};
  ConfigSaveArgs save = {};
  ConfigBackupArgs backup = {};
  ConfigExportArgs export_config = {};
  ConfigProfileSetArgs profile_set = {};
  ConfigDecryptArgs decrypt = {};
};

struct CliHostArgs {
  HostLsArgs ls = {};
  HostGetArgs get = {};
  HostAddArgs add = {};
  HostEditArgs edit = {};
  HostRenameArgs rn = {};
  HostRemoveArgs rm = {};
  HostSetArgs set = {};
  HostKeysArgs keys = {};
};

struct CliProfileArgs {
  ProfileEditArgs edit = {};
  ProfileGetArgs get = {};
};

struct CliFilesystemArgs {
  StatArgs stat = {};
  LsArgs ls = {};
  SizeArgs size = {};
  FindArgs find = {};
  MkdirArgs mkdir = {};
  RmArgs rm = {};
  TreeArgs tree = {};
  RealpathArgs realpath = {};
  RttArgs rtt = {};
  ClearArgs clear = {};
  CpArgs cp = {};
  MoveArgs move = {};
  CloneArgs clone = {};
  WgetArgs wget = {};
  SftpArgs sftp = {};
  FtpArgs ftp = {};
  LocalArgs local = {};
  CdArgs cd = {};
  ConnectArgs connect = {};
  CmdArgs cmd = {};
  TerminalArgs ssh = {};
  BashArgs bash = {};
  ExitArgs exit = {};
};

struct CliTermArgs {
  TermAddArgs add = {};
  TermListArgs ls = {};
  TermRemoveArgs rm = {};
};

struct CliChannelArgs {
  ChannelAddArgs add = {};
  ChannelListArgs ls = {};
  ChannelRemoveArgs rm = {};
  ChannelRenameArgs rn = {};
};

struct CliClientArgs {
  ClientsArgs ls = {};
  CheckArgs check = {};
  ChangeClientArgs change = {};
  DisconnectArgs disconnect = {};
};

struct CliVarArgs {
  VarGetArgs get = {};
  VarDefArgs def = {};
  VarDelArgs del = {};
  VarLsArgs ls = {};
};

struct CliTaskArgs {
  TaskListArgs ls = {};
  TaskShowArgs show = {};
  TaskInspectArgs inspect = {};
  TaskThreadArgs thread = {};
  TaskEntryArgs entry = {};
  TaskControlArgs terminate = {};
  TaskControlArgs pause = {};
  TaskControlArgs resume = {};
  TaskRetryArgs retry = {};
};

/**
 * @brief Pool of all CLI argument structs.
 */
struct CliArgsPool {
  CliConfigArgs config = {};
  CliHostArgs host = {};
  CliProfileArgs profile = {};
  CliFilesystemArgs fs = {};
  CliTermArgs term = {};
  CliChannelArgs channel = {};
  CliClientArgs client = {};
  CliVarArgs var = {};
  CliTaskArgs task = {};

  void SetActive(BaseArgStruct *active) { active_ = active; }
  [[nodiscard]] BaseArgStruct *GetActive() const { return active_; }
  void ClearActive() { active_ = nullptr; }

private:
  BaseArgStruct *active_ = nullptr;
};

/**
 * @brief Host/config command handles.
 */
struct ConfigCommands {
  CLI::App *root = nullptr;
  CLI::App *ls = nullptr;
  CLI::App *save = nullptr;
  CLI::App *backup = nullptr;
  CLI::App *export_config = nullptr;
  CLI::App *decrypt = nullptr;
  CLI::App *profile_root = nullptr;
  CLI::App *profile_set = nullptr;
};

struct HostCommands {
  CLI::App *root = nullptr;
  CLI::App *ls = nullptr;
  CLI::App *get = nullptr;
  CLI::App *add = nullptr;
  CLI::App *edit = nullptr;
  CLI::App *rename = nullptr;
  CLI::App *remove = nullptr;
  CLI::App *set = nullptr;
  CLI::App *keys = nullptr;
};

struct ProfileCommands {
  CLI::App *root = nullptr;
  CLI::App *edit = nullptr;
  CLI::App *get = nullptr;
};

struct ClientCommands {
  CLI::App *root = nullptr;
  CLI::App *ls = nullptr;
  CLI::App *check = nullptr;
  CLI::App *change = nullptr;
  CLI::App *remove = nullptr;
};

struct FilesystemCommands {
  CLI::App *stat = nullptr;
  CLI::App *ls = nullptr;
  CLI::App *size = nullptr;
  CLI::App *find = nullptr;
  CLI::App *mkdir = nullptr;
  CLI::App *rm = nullptr;
  CLI::App *tree = nullptr;
  CLI::App *realpath = nullptr;
  CLI::App *rtt = nullptr;
  CLI::App *clear = nullptr;
  CLI::App *cp = nullptr;
  CLI::App *move = nullptr;
  CLI::App *clone = nullptr;
  CLI::App *wget = nullptr;
  CLI::App *sftp = nullptr;
  CLI::App *ftp = nullptr;
  CLI::App *local = nullptr;
  CLI::App *cd = nullptr;
  CLI::App *connect = nullptr;
  CLI::App *cmd = nullptr;
  CLI::App *ssh = nullptr;
  CLI::App *bash = nullptr;
  CLI::App *exit = nullptr;
};

struct TermCommands {
  CLI::App *root = nullptr;
  CLI::App *add = nullptr;
  CLI::App *ls = nullptr;
  CLI::App *rm = nullptr;
};

struct ChannelCommands {
  CLI::App *root = nullptr;
  CLI::App *add = nullptr;
  CLI::App *ls = nullptr;
  CLI::App *rm = nullptr;
  CLI::App *rn = nullptr;
};

struct VarCommands {
  CLI::App *root = nullptr;
  CLI::App *get = nullptr;
  CLI::App *def = nullptr;
  CLI::App *del = nullptr;
  CLI::App *ls = nullptr;
};

struct TaskCommands {
  CLI::App *root = nullptr;
  CLI::App *ls = nullptr;
  CLI::App *show = nullptr;
  CLI::App *inspect = nullptr;
  CLI::App *thread = nullptr;
  CLI::App *query = nullptr;
  CLI::App *terminate = nullptr;
  CLI::App *pause = nullptr;
  CLI::App *resume = nullptr;
  CLI::App *retry = nullptr;
  CLI::App *retry_alias = nullptr;
};

/**
 * @brief CLI subcommand handles grouped by module.
 */
struct CliCommands {
  CLI::App *app = nullptr;
  ConfigCommands config = {};
  HostCommands host = {};
  ProfileCommands profile = {};
  ClientCommands client = {};
  FilesystemCommands fs = {};
  TermCommands term = {};
  ChannelCommands channel = {};
  VarCommands var = {};
  TaskCommands task = {};
  CliArgsPool *args = nullptr;
};

} // namespace AMInterface::cli
