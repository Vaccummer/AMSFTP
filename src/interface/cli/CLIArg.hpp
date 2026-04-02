#pragma once
#include "CLI/App.hpp"
#include "application/log/LoggerAppService.hpp"
#include "application/client/ClientAppService.hpp"
#include "application/config/ConfigAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/var/VarAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/signal/SignalMonitorPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/cli/InteractiveEventRegistry.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"
#include <atomic>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace AMInterface::cli {

using amf = std::shared_ptr<AMDomain::client::IClientControlToken>;

struct CliRunContext;

template <typename T> class ServiceHolder final : public NonCopyableNonMovable {
public:
  ServiceHolder() = default;
  ~ServiceHolder() override = default;

  void SetInstance(std::unique_ptr<T> instance) const {
    instance_ = std::move(instance);
  }

  [[nodiscard]] bool IsReady() const { return instance_ != nullptr; }

  T &Get() const {
    if (!instance_) {
      throw std::runtime_error("Service is not initialized");
    }
    return *instance_;
  }

  T *operator->() const { return &Get(); }
  operator T &() const { return Get(); }

private:
  mutable std::unique_ptr<T> instance_ = nullptr;
};

/**
 * @brief Manager references for CLI dispatch.
 */
struct CLIServices : public NonCopyableNonMovable {

  /**
   * @brief Bind manager references used by CLI entry points.
   */
  CLIServices() = default;

  /**
   * @brief Initialize all bound managers in dependency-safe order.
   */
  ECM Init(amf task_control_token);

  void SetPromptProfileManager(
      std::unique_ptr<AMApplication::prompt::PromptProfileManager> manager)
      const;
  void SetPromptHistoryManager(
      std::unique_ptr<AMApplication::prompt::PromptHistoryManager> manager)
      const;
  [[nodiscard]] AMApplication::prompt::PromptProfileManager &
  PromptProfileManager() const;
  [[nodiscard]] AMApplication::prompt::PromptHistoryManager &
  PromptHistoryManager() const;

  mutable ServiceHolder<AMDomain::signal::SignalMonitor> signal_monitor = {};
  mutable ServiceHolder<AMApplication::config::ConfigAppService>
      config_service = {};
  mutable ServiceHolder<AMInterface::style::AMStyleService> style_service = {};
  mutable ServiceHolder<AMInterface::prompt::IsoclineProfileManager>
      prompt_profile_history_manager = {};
  mutable ServiceHolder<AMInterface::prompt::AMPromptIOManager>
      prompt_io_manager = {};
  mutable ServiceHolder<AMApplication::host::HostAppService> host_service =
      {};
  mutable ServiceHolder<AMApplication::host::KnownHostsAppService>
      known_hosts_service = {};
  mutable ServiceHolder<AMApplication::var::VarAppService> var_service = {};
  mutable ServiceHolder<AMApplication::log::LoggerAppService> log_manager = {};
  mutable ServiceHolder<AMApplication::client::ClientAppService>
      client_service = {};
  mutable ServiceHolder<AMApplication::filesystem::FilesystemAppService>
      filesystem_service = {};
  mutable ServiceHolder<AMInterface::client::ClientInterfaceService>
      client_interface_service = {};
  mutable ServiceHolder<AMInterface::filesystem::FilesystemInterfaceSerivce>
      filesystem_interface_service = {};
  mutable ServiceHolder<AMInterface::var::VarInterfaceService>
      var_interface_service = {};
  mutable ServiceHolder<AMDomain::transfer::ITransferPoolPort> transfer_pool =
      {};
  mutable ServiceHolder<AMInterface::transfer::TransferInterfaceService>
      transfer_service = {};
  mutable AMInteractiveEventRegistry interactive_event_registry = {};

private:
  mutable ServiceHolder<AMApplication::prompt::PromptProfileManager>
      prompt_profile_manager_ = {};
  mutable ServiceHolder<AMApplication::prompt::PromptHistoryManager>
      prompt_history_manager_ = {};
};

/**
 * @brief Runtime context for invoking Args::Run.
 */
struct CliRunContext : NonCopyableNonMovable {
  CliRunContext() = default;
  ~CliRunContext() override = default;
  ECM rcm = OK;
  bool async = false;
  bool enforce_interactive = false;
  std::string command_name;
  mutable bool enter_interactive = false;
  mutable bool request_exit = false;
  mutable bool skip_loop_exit_callbacks = false;
  amf task_control_token = nullptr;
  std::shared_ptr<std::atomic<int>> exit_code =
      std::make_shared<std::atomic<int>>(0);
  std::shared_ptr<std::atomic<bool>> is_interactive =
      std::make_shared<std::atomic<bool>>(false);
};

/**
 * @brief Base interface for all parsed CLI argument payload structs.
 */
struct BaseArgStruct {
  virtual ~BaseArgStruct() = default;
  /**
   * @brief Execute this parsed command payload.
   */
  [[nodiscard]] virtual ECM Run(const CLIServices &managers,
                                const CliRunContext &ctx) const = 0;
  /**
   * @brief Reset this payload to parser defaults.
   */
  virtual void reset() = 0;
};

/**
 * @brief CLI argument container for config ls.
 */
struct ConfigLsArgs : BaseArgStruct {
  bool detail = false;
  /**
   * @brief Execute config ls with optional detail flag.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-ls arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config keys.
 */
struct ConfigKeysArgs : BaseArgStruct {
  /**
   * @brief Execute config keys.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-keys arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config data.
 */
struct ConfigDataArgs : BaseArgStruct {
  /**
   * @brief Execute config data.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-data arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config get.
 */
struct ConfigGetArgs : BaseArgStruct {
  AMInterface::client::ListClientsRequest request = {};
  /**
   * @brief Execute config get with optional nickname list.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-get arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config add.
 */
struct ConfigAddArgs : BaseArgStruct {
  std::string nickname;
  /**
   * @brief Execute config add.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-add arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config edit.
 */
struct ConfigEditArgs : BaseArgStruct {
  std::string nickname;
  /**
   * @brief Execute config edit for a nickname.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-edit arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config rename.
 */
struct ConfigRenameArgs : BaseArgStruct {
  std::string old_name;
  std::string new_name;
  /**
   * @brief Execute config rename.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-rename arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config remove.
 */
struct ConfigRemoveArgs : BaseArgStruct {
  std::vector<std::string> names;
  /**
   * @brief Execute config remove for target names.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-remove arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config set.
 */
struct ConfigSetArgs : BaseArgStruct {
  AMInterface::client::SetHostValueRequest request = {};
  /**
   * @brief Execute config set for a host attribute.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-set arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config save.
 */
struct ConfigSaveArgs : BaseArgStruct {
  /**
   * @brief Execute config save.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config-save arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for config profile set.
 */
struct ConfigProfileSetArgs : BaseArgStruct {
  std::string nickname;
  /**
   * @brief Execute config profile set.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset config profile set arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for profile edit.
 */
struct ProfileEditArgs : BaseArgStruct {
  std::string nickname;
  /**
   * @brief Execute profile edit for a host nickname.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset profile-edit arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for profile get.
 */
struct ProfileGetArgs : BaseArgStruct {
  std::vector<std::string> nicknames;
  /**
   * @brief Execute profile get for one or more host nicknames.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset profile-get arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for stat.
 */
struct StatArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemStatArg request = {};
  /**
   * @brief Execute stat for target paths.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset stat arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for ls.
 */
struct LsArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemLsArg request = {};
  /**
   * @brief Execute ls for a path or current workdir.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset ls arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for size.
 */
struct SizeArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemGetSizeArg request = {};
  /**
   * @brief Execute size for target paths.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset size arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for find.
 */
struct FindArgs : BaseArgStruct {
  std::string path;
  /**
   * @brief Execute find for a path.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset find arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for mkdir.
 */
struct MkdirArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemMkdirsArg request = {};
  /**
   * @brief Execute mkdir for target paths.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset mkdir arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for rm.
 */
struct RmArgs : BaseArgStruct {
  std::vector<std::string> paths;
  bool permanent = false;
  bool quiet = false;
  /**
   * @brief Execute rm for target paths.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset rm arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for tree.
 */
struct TreeArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemTreeArg request = {};
  bool include_special = false;
  /**
   * @brief Execute tree for a path.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset tree arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for realpath.
 */
struct RealpathArgs : BaseArgStruct {
  std::string path;
  /**
   * @brief Execute realpath for a target path.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset realpath arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for rtt.
 */
struct RttArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemTestRTTArg request = {};
  /**
   * @brief Execute rtt with sample count.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset rtt arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for clear.
 */
struct ClearArgs : BaseArgStruct {
  bool all = false;
  /**
   * @brief Execute clear screen.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset clear arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for cp (transfer).
 */
struct CpArgs : BaseArgStruct {
  std::vector<std::string> srcs;
  std::string output;
  int timeout_ms = -1;
  bool overwrite = false;
  bool no_mkdir = false;
  bool clone = false;
  bool include_special = false;
  bool resume = false;
  bool quiet = false;
  /**
   * @brief Execute cp transfer.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset cp arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for clone (cp -c).
 */
struct CloneArgs : BaseArgStruct {
  std::string src;
  std::string dst;
  bool overwrite = false;
  bool resume = false;
  bool quiet = false;
  /**
   * @brief Execute clone transfer.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset clone arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for wget (HTTP download).
 */
struct WgetArgs : BaseArgStruct {
  std::string src;
  std::string dst;
  std::string bear_token;
  std::string proxy;
  std::string sproxy;
  int timeout_ms = -1;
  bool resume = false;
  bool overwrite = false;
  bool quiet = false;
  /**
   * @brief Execute wget transfer.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset wget arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for sftp.
 */
struct SftpArgs : BaseArgStruct {
  std::vector<std::string> targets;
  AMInterface::client::ProtocolConnectRequest request = [] {
    AMInterface::client::ProtocolConnectRequest req = {};
    req.port = 22;
    return req;
  }();
  /**
   * @brief Execute sftp connection.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset sftp arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for ftp.
 */
struct FtpArgs : BaseArgStruct {
  std::vector<std::string> targets;
  AMInterface::client::ProtocolConnectRequest request = [] {
    AMInterface::client::ProtocolConnectRequest req = {};
    req.port = 21;
    return req;
  }();
  /**
   * @brief Execute ftp connection.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset ftp arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for clients.
 */
struct ClientsArgs : BaseArgStruct {
  AMInterface::client::ListClientsRequest request = {};
  /**
   * @brief Execute clients list.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset clients arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for check.
 */
struct CheckArgs : BaseArgStruct {
  AMInterface::client::CheckClientsRequest request = {};
  /**
   * @brief Execute client check.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset check arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for ch.
 */
struct ChangeClientArgs : BaseArgStruct {
  AMInterface::client::ChangeClientRequest request = {};
  /**
   * @brief Execute client change.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset change-client arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for disconnect.
 */
struct DisconnectArgs : BaseArgStruct {
  AMInterface::client::RemoveClientsRequest request = {};
  /**
   * @brief Execute client disconnect.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset disconnect arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for cd.
 */
struct CdArgs : BaseArgStruct {
  AMInterface::filesystem::FilesystemCdArg request = {};
  /**
   * @brief Execute cd.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset cd arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for connect.
 */
struct ConnectArgs : BaseArgStruct {
  AMInterface::client::ConnectRequest request = {};
  /**
   * @brief Execute connect.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset connect arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for cmd.
 */
struct CmdArgs : BaseArgStruct {
  int timeout_ms = -1;
  AMInterface::filesystem::FilesystemShellRunArg request = {};
  /**
   * @brief Execute one shell command on current SFTP/local client.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset cmd arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for bash.
 */
struct BashArgs : BaseArgStruct {
  /**
   * @brief Enter interactive mode.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset bash arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for exit.
 */
struct ExitArgs : BaseArgStruct {
  bool force = false;
  /**
   * @brief Request interactive-loop exit.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset exit arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for `var get`.
 */
struct VarGetArgs : BaseArgStruct {
  std::string varname;
  /**
   * @brief Execute `var get`.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset args to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for `var def`.
 */
struct VarDefArgs : BaseArgStruct {
  bool global = false;
  std::string varname;
  std::string value;
  /**
   * @brief Execute `var def`.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset args to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for `var del`.
 */
struct VarDelArgs : BaseArgStruct {
  bool all = false;
  std::vector<std::string> tokens;
  /**
   * @brief Execute `var del`.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset args to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for `var ls`.
 */
struct VarLsArgs : BaseArgStruct {
  std::vector<std::string> sections;
  /**
   * @brief Execute `var ls`.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset args to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for complete cache clear.
 */
struct CompleteCacheClearArgs : BaseArgStruct {
  /**
   * @brief Execute completion cache clear.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset completion cache clear arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for task list.
 */
struct TaskListArgs : BaseArgStruct {
  bool pending = false;
  bool suspend = false;
  bool finished = false;
  bool conducting = false;
  /**
   * @brief Execute task list.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset task-list arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for task show.
 */
struct TaskShowArgs : BaseArgStruct {
  std::vector<std::string> ids;
  /**
   * @brief Execute task show.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset task-show arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for task inspect.
 */
struct TaskInspectArgs : BaseArgStruct {
  std::string id;
  bool set = false;
  bool entry = false;
  /**
   * @brief Execute task inspect.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset task-inspect arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for task thread.
 */
struct TaskThreadArgs : BaseArgStruct {
  int num = -1;
  /**
   * @brief Execute task thread update/query.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset task-thread arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for task query.
 */
struct TaskEntryArgs : BaseArgStruct {
  std::vector<std::string> ids;
  /**
   * @brief Execute task entry query.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset task-entry arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for task control.
 */
struct TaskControlArgs : BaseArgStruct {
  enum class Action { Terminate, Pause, Resume };
  std::vector<std::string> ids;
  Action action = Action::Terminate;
  /**
   * @brief Execute task control action.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset task-control arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief CLI argument container for task retry (failed tasks).
 */
struct TaskRetryArgs : BaseArgStruct {
  std::string id;
  bool is_async = false;
  bool quiet = false;
  std::vector<int> indices;
  /**
   * @brief Execute task retry.
   */
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  /**
   * @brief Reset task-retry arguments to defaults.
   */
  void reset() override;
};

/**
 * @brief Pool of all CLI argument structs.
 */
struct CliArgsPool {
  std::shared_ptr<ConfigLsArgs> config_ls = std::make_shared<ConfigLsArgs>();
  std::shared_ptr<ConfigKeysArgs> config_keys =
      std::make_shared<ConfigKeysArgs>();
  std::shared_ptr<ConfigDataArgs> config_data =
      std::make_shared<ConfigDataArgs>();
  std::shared_ptr<ConfigGetArgs> config_get = std::make_shared<ConfigGetArgs>();
  std::shared_ptr<ConfigAddArgs> config_add = std::make_shared<ConfigAddArgs>();
  std::shared_ptr<ConfigEditArgs> config_edit =
      std::make_shared<ConfigEditArgs>();
  std::shared_ptr<ConfigRenameArgs> config_rn =
      std::make_shared<ConfigRenameArgs>();
  std::shared_ptr<ConfigRemoveArgs> config_rm =
      std::make_shared<ConfigRemoveArgs>();
  std::shared_ptr<ConfigSetArgs> config_set = std::make_shared<ConfigSetArgs>();
  std::shared_ptr<ConfigSaveArgs> config_save =
      std::make_shared<ConfigSaveArgs>();
  std::shared_ptr<ConfigProfileSetArgs> config_profile_set =
      std::make_shared<ConfigProfileSetArgs>();
  std::shared_ptr<ProfileEditArgs> profile_edit =
      std::make_shared<ProfileEditArgs>();
  std::shared_ptr<ProfileGetArgs> profile_get =
      std::make_shared<ProfileGetArgs>();
  std::shared_ptr<StatArgs> stat = std::make_shared<StatArgs>();
  std::shared_ptr<LsArgs> ls = std::make_shared<LsArgs>();
  std::shared_ptr<SizeArgs> size = std::make_shared<SizeArgs>();
  std::shared_ptr<FindArgs> find = std::make_shared<FindArgs>();
  std::shared_ptr<MkdirArgs> mkdir = std::make_shared<MkdirArgs>();
  std::shared_ptr<RmArgs> rm = std::make_shared<RmArgs>();
  std::shared_ptr<TreeArgs> tree = std::make_shared<TreeArgs>();
  std::shared_ptr<RealpathArgs> realpath = std::make_shared<RealpathArgs>();
  std::shared_ptr<RttArgs> rtt = std::make_shared<RttArgs>();
  std::shared_ptr<ClearArgs> clear = std::make_shared<ClearArgs>();
  std::shared_ptr<CpArgs> cp = std::make_shared<CpArgs>();
  std::shared_ptr<CloneArgs> clone = std::make_shared<CloneArgs>();
  std::shared_ptr<WgetArgs> wget = std::make_shared<WgetArgs>();
  std::shared_ptr<SftpArgs> sftp = std::make_shared<SftpArgs>();
  std::shared_ptr<FtpArgs> ftp = std::make_shared<FtpArgs>();
  std::shared_ptr<ClientsArgs> clients = std::make_shared<ClientsArgs>();
  std::shared_ptr<CheckArgs> check = std::make_shared<CheckArgs>();
  std::shared_ptr<ChangeClientArgs> ch = std::make_shared<ChangeClientArgs>();
  std::shared_ptr<DisconnectArgs> disconnect =
      std::make_shared<DisconnectArgs>();
  std::shared_ptr<CdArgs> cd = std::make_shared<CdArgs>();
  std::shared_ptr<ConnectArgs> connect = std::make_shared<ConnectArgs>();
  std::shared_ptr<CmdArgs> cmd = std::make_shared<CmdArgs>();
  std::shared_ptr<BashArgs> bash = std::make_shared<BashArgs>();
  std::shared_ptr<ExitArgs> exit = std::make_shared<ExitArgs>();
  std::shared_ptr<VarGetArgs> var_get = std::make_shared<VarGetArgs>();
  std::shared_ptr<VarDefArgs> var_def = std::make_shared<VarDefArgs>();
  std::shared_ptr<VarDelArgs> var_del = std::make_shared<VarDelArgs>();
  std::shared_ptr<VarLsArgs> var_ls = std::make_shared<VarLsArgs>();
  std::shared_ptr<CompleteCacheClearArgs> complete_cache_clear =
      std::make_shared<CompleteCacheClearArgs>();
  std::shared_ptr<TaskListArgs> task_list = std::make_shared<TaskListArgs>();
  std::shared_ptr<TaskShowArgs> task_show = std::make_shared<TaskShowArgs>();
  std::shared_ptr<TaskInspectArgs> task_inspect =
      std::make_shared<TaskInspectArgs>();
  std::shared_ptr<TaskThreadArgs> task_thread =
      std::make_shared<TaskThreadArgs>();
  std::shared_ptr<TaskEntryArgs> task_entry = std::make_shared<TaskEntryArgs>();
  std::shared_ptr<TaskControlArgs> task_terminate =
      std::make_shared<TaskControlArgs>();
  std::shared_ptr<TaskControlArgs> task_pause =
      std::make_shared<TaskControlArgs>();
  std::shared_ptr<TaskControlArgs> task_resume =
      std::make_shared<TaskControlArgs>();
  std::shared_ptr<TaskRetryArgs> task_retry = std::make_shared<TaskRetryArgs>();
  BaseArgStruct *active = nullptr;
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
  CLI::App *tree_cmd = nullptr;
  CLI::App *realpath_cmd = nullptr;
  CLI::App *rtt_cmd = nullptr;
  CLI::App *clear_cmd = nullptr;
  CLI::App *cp_cmd = nullptr;
  CLI::App *clone_cmd = nullptr;
  CLI::App *wget_cmd = nullptr;
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
  CLI::App *task_list_cmd = nullptr;
  CLI::App *task_show_cmd = nullptr;
  CLI::App *task_inspect_cmd = nullptr;
  CLI::App *task_thread_cmd = nullptr;
  CLI::App *task_query_cmd = nullptr;
  CLI::App *task_terminate_cmd = nullptr;
  CLI::App *task_pause_cmd = nullptr;
  CLI::App *task_resume_cmd = nullptr;
  CLI::App *task_retry_cmd = nullptr;
  CLI::App *resume_cmd = nullptr;
  CliArgsPool *args = nullptr;
};

} // namespace AMInterface::cli
