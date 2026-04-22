#pragma once

#include "CLI/App.hpp"
#include "interface/cli/ArgStruct/ClientArgStruct.hpp"
#include "interface/cli/ArgStruct/ConfigArgStruct.hpp"
#include "interface/cli/ArgStruct/FilesystemArgStruct.hpp"
#include "interface/cli/ArgStruct/HostArgStruct.hpp"
#include "interface/cli/ArgStruct/PoolArgStruct.hpp"
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
  MoveArgs mv = {};
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
  TermClearArgs clear = {};
};

struct CliChannelArgs {
  ChannelAddArgs add = {};
  ChannelListArgs ls = {};
  ChannelRemoveArgs rm = {};
  ChannelRenameArgs rn = {};
  ChannelClearArgs clear = {};
};

struct CliClientArgs {
  ClientsArgs ls = {};
  CheckArgs check = {};
  ClearClientsArgs clear = {};
  ChangeClientArgs change = {};
  DisconnectArgs disconnect = {};
};

struct CliPoolArgs {
  PoolLsArgs ls = {};
  PoolCheckArgs check = {};
  PoolRemoveArgs rm = {};
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
  TaskRemoveArgs rm = {};
};

struct CliArgsPool {
  CliConfigArgs config = {};
  CliHostArgs host = {};
  CliProfileArgs profile = {};
  CliFilesystemArgs fs = {};
  CliTermArgs term = {};
  CliChannelArgs channel = {};
  CliClientArgs client = {};
  CliPoolArgs pool = {};
  CliVarArgs var = {};
  CliTaskArgs task = {};

  void SetActive(BaseArgStruct *active) { active_ = active; }
  [[nodiscard]] BaseArgStruct *GetActive() const { return active_; }
  void ClearActive() { active_ = nullptr; }

private:
  BaseArgStruct *active_ = nullptr;
};

/**
 * @brief CLI runtime handles required by bind and dispatch flow.
 */
struct CliCommands {
  CLI::App *app = nullptr;
  CliArgsPool *args = nullptr;
};

} // namespace AMInterface::cli
