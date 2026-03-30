#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/client/ClientSessionWorkflows.hpp"
#include "application/client/FileCommandWorkflows.hpp"
#include "application/completion/CompletionWorkflows.hpp"
#include "application/config/ConfigAppService.hpp"
#include "application/config/CliConfigSaveWorkflows.hpp"
#include "application/host/HostProfileWorkflows.hpp"
#include "application/transfer/TaskWorkflows.hpp"
#include "application/transfer/TransferWorkflows.hpp"
#include "application/var/VarWorkflows.hpp"
#include "interface/adapters/filesystem/FileSystemAdapter.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/config/ConfigModel.hpp"
#include "domain/signal/SignalMonitorPort.hpp"
#include "domain/transfer/TransferPorts.hpp"
#include "domain/var/VarModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/bar.hpp"
#include "interface/style/StyleIndex.hpp"
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace AMInterface::prompt {
class IsoclineProfileManager;
class AMPromptIOManager;
}
namespace AMApplication::client {
class ClientAppService;
}
namespace AMInterface::style {
class AMStyleService;
}
namespace AMDomain::host {
class AMHostConfigManager;
class AMKnownHostsManager;
}
namespace AMDomain::var {
class IVarQueryPort;
class IVarSubstitutionPort;
class IVarRepository;
class ICurrentDomainProvider;
}
namespace AMApplication::VarWorkflow {
class VarAppService;
}
namespace AMApplication::TransferWorkflow {
class TransferAppService;
struct TaskSummaryView;
struct TaskEntryView;
struct TransferSetView;
struct TaskView;
}

namespace AMInterface::ApplicationAdapters {
/**
 * @brief Host/profile workflow gateway backed by host config + prompt services.
 */
class HostProfileGateway final
    : public AMApplication::HostProfileWorkflow::IHostProfileGateway {
public:
  /**
   * @brief Construct gateway from host and prompt managers.
   */
  HostProfileGateway(AMDomain::host::AMHostConfigManager &host_config_manager,
                     AMInterface::prompt::AMPromptIOManager &prompt_io_manager);
  ~HostProfileGateway() override = default;

  [[nodiscard]] bool HostExists(const std::string &nickname) const override;
  ECM ListHosts(bool detail) override;
  ECM ListPrivateKeys(bool detail) override;
  ECM ShowConfigSource() override;
  ECM QueryHosts(const std::vector<std::string> &nicknames) override;
  ECM AddHost(const std::string &nickname) override;
  ECM EditHost(const std::string &nickname) override;
  ECM RenameHost(const std::string &old_name,
                 const std::string &new_name) override;
  ECM RemoveHosts(const std::vector<std::string> &nicknames) override;
  ECM SetHostValue(const std::string &nickname, const std::string &attrname,
                   const std::string &value) override;
  ECM SaveHosts() override;
  ECM EditProfile(const std::string &nickname) override;
  ECM GetProfiles(const std::vector<std::string> &nicknames) override;

  /**
   * @brief List all configured host nicknames.
   */
  [[nodiscard]] std::vector<std::string> ListHostNames() const;

private:
  AMDomain::host::AMHostConfigManager &host_config_manager_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
};

/**
 * @brief Current-client workflow port backed by client app service.
 */
class CurrentClientPort final
    : public AMApplication::HostProfileWorkflow::ICurrentClientPort {
public:
  /**
   * @brief Construct reader from client app service.
   */
  explicit CurrentClientPort(AMApplication::client::ClientAppService &client_service);
  ~CurrentClientPort() override = default;

  [[nodiscard]] std::string CurrentNickname() const override;

private:
  AMApplication::client::ClientAppService &client_service_;
};

class ConfigBackedVarRepository final : public AMDomain::var::IVarRepository {
public:
  /**
   * @brief Construct repository from config app service.
   */
  explicit ConfigBackedVarRepository(
      AMApplication::config::AMConfigAppService &config_service);
  ~ConfigBackedVarRepository() override = default;

  ECM Load(AMDomain::var::VarDomainService::DomainDict *out_vars) override;
  ECM Save(const AMDomain::var::VarDomainService::DomainDict &vars,
           bool async = true) override;

private:
  AMApplication::config::AMConfigAppService &config_service_;
};

/**
 * @brief Current-domain provider backed by client app service.
 */
class CurrentVarDomainProvider final
    : public AMDomain::var::ICurrentDomainProvider {
public:
  /**
   * @brief Construct provider from client app service.
   */
  explicit CurrentVarDomainProvider(
      AMApplication::client::ClientAppService &client_service);
  ~CurrentVarDomainProvider() override = default;

  [[nodiscard]] std::string CurrentDomain() const override;

private:
  AMApplication::client::ClientAppService &client_service_;
};

/**
 * @brief Helper adapter for current-client path context queries.
 */
class ClientPathGateway final {
public:
  /**
   * @brief Construct path helper from client app service.
   */
  explicit ClientPathGateway(AMApplication::client::ClientAppService &client_service);

  /**
   * @brief Return current workdir or empty string when unavailable.
   */
  [[nodiscard]] std::string CurrentWorkdir() const;

private:
  AMApplication::client::ClientAppService &client_service_;
};

/**
 * @brief Host-config saver workflow port backed by host manager.
 */
class HostConfigSaver final
    : public AMApplication::ConfigWorkflow::IHostConfigSaver {
public:
  /**
   * @brief Construct saver from host manager.
   */
  explicit HostConfigSaver(AMDomain::host::AMHostConfigManager &host_config_manager);
  ~HostConfigSaver() override = default;

  ECM SaveHostConfig() override;

private:
  AMDomain::host::AMHostConfigManager &host_config_manager_;
};

/**
 * @brief Var-config saver workflow port backed by var app service.
 */
class VarConfigSaver final
    : public AMApplication::ConfigWorkflow::IVarConfigSaver {
public:
  /**
   * @brief Construct saver from var app service.
   */
  explicit VarConfigSaver(AMApplication::VarWorkflow::VarAppService &var_service);
  ~VarConfigSaver() override = default;

  ECM SaveVarConfig(bool dump_now) override;

private:
  AMApplication::VarWorkflow::VarAppService &var_service_;
};

/**
 * @brief Prompt-config saver workflow port backed by prompt manager.
 */
class PromptConfigSaver final
    : public AMApplication::ConfigWorkflow::IPromptConfigSaver {
public:
  /**
   * @brief Construct saver from prompt manager.
   */
  explicit PromptConfigSaver(
      AMInterface::prompt::IsoclineProfileManager &prompt_profile_history_manager);
  ~PromptConfigSaver() override = default;

  ECM SavePromptConfig(bool dump_now) override;

private:
  AMInterface::prompt::IsoclineProfileManager &prompt_profile_history_manager_;
};

/**
 * @brief Client-session workflow gateway backed by client app service.
 */
class ClientSessionGateway final
    : public AMApplication::ClientWorkflow::IClientSessionGateway {
public:
  /**
   * @brief Construct gateway from client app service.
   */
  explicit ClientSessionGateway(
      AMApplication::client::ClientAppService &client_service);
  ~ClientSessionGateway() override = default;

  ECM ConnectNickname(const std::string &nickname, bool force,
                      bool switch_client,
                      amf interrupt_flag = nullptr) override;
  ECM ChangeCurrentClient(const std::string &nickname,
                          amf interrupt_flag = nullptr) override;
  ECM ConnectSftp(const std::string &nickname, const std::string &user_at_host,
                  int64_t port, const std::string &password,
                  const std::string &keyfile,
                  amf interrupt_flag = nullptr) override;
  ECM ConnectFtp(const std::string &nickname, const std::string &user_at_host,
                 int64_t port, const std::string &password,
                 const std::string &keyfile,
                 amf interrupt_flag = nullptr) override;
  ECM ListClients(bool detail, amf interrupt_flag = nullptr) override;
  ECM DisconnectClients(const std::vector<std::string> &nicknames) override;
  ECM StatPaths(const std::vector<std::string> &paths,
                amf interrupt_flag = nullptr) override;
  ECM ListPath(const std::string &path, bool list_like, bool show_all,
               amf interrupt_flag = nullptr) override;

private:
  AMApplication::client::ClientAppService &client_service_;
};

/**
 * @brief Execute CLI `var get` against the var app service.
 */
ECM RunVarGet(AMApplication::VarWorkflow::VarAppService &var_service,
              AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
              const std::string &token_name);

/**
 * @brief Execute CLI `var def` against the var app service.
 */
ECM RunVarDef(AMApplication::VarWorkflow::VarAppService &var_service,
              AMInterface::prompt::AMPromptIOManager &prompt_io_manager, bool global,
              const std::string &token_name, const std::string &value);

/**
 * @brief Execute CLI `var del` against the var app service.
 */
ECM RunVarDel(AMApplication::VarWorkflow::VarAppService &var_service,
              AMInterface::prompt::AMPromptIOManager &prompt_io_manager, bool all,
              const std::vector<std::string> &tokens);

/**
 * @brief Execute CLI `var ls` against the var app service.
 */
ECM RunVarLs(AMApplication::VarWorkflow::VarAppService &var_service,
             AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
             const std::vector<std::string> &domains);

/**
 * @brief Completion workflow gateway backed by active completer runtime.
 */
class CompletionGateway final
    : public AMApplication::CompletionWorkflow::ICompletionGateway {
public:
  /**
   * @brief Construct completion gateway.
   */
  CompletionGateway() = default;
  ~CompletionGateway() override = default;

  [[nodiscard]] bool HasActiveCompleter() const override;
  void ClearActiveCompleterCache() const override;
};

/**
 * @brief Transfer-executor workflow port backed by transfer app service.
 */
class TransferExecutorPort final
    : public AMDomain::transfer::ITransferExecutorPort {
public:
  /**
   * @brief Construct executor from transfer app service.
   */
  TransferExecutorPort(
      AMApplication::TransferWorkflow::TransferAppService &transfer_service,
      AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
      AMApplication::TransferWorkflow::TransferConfirmPolicy confirm_policy =
          AMApplication::TransferWorkflow::TransferConfirmPolicy::RequireConfirm,
      AMDomain::client::amf task_control_token = nullptr);
  ~TransferExecutorPort() override = default;

  ECM Transfer(const std::vector<UserTransferSet> &transfer_sets,
               bool quiet) override;
  ECM TransferAsync(const std::vector<UserTransferSet> &transfer_sets,
                    bool quiet) override;

private:
  AMApplication::TransferWorkflow::TransferAppService &transfer_service_;
  AMInterface::prompt::AMPromptIOManager *prompt_io_manager_ = nullptr;
  AMApplication::TransferWorkflow::TransferConfirmPolicy confirm_policy_ =
      AMApplication::TransferWorkflow::TransferConfirmPolicy::RequireConfirm;
  AMDomain::client::amf task_control_token_ = nullptr;
};

/**
 * @brief Task workflow gateway backed by transfer app service.
 */
class TaskGateway final : public AMApplication::TaskWorkflow::ITaskGateway {
public:
  /**
   * @brief Construct gateway from transfer app service.
   */
  TaskGateway(AMApplication::TransferWorkflow::TransferAppService &transfer_service,
              AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
              AMDomain::client::amf task_control_token = nullptr);
  ~TaskGateway() override = default;

  ECM ListTasks(bool pending, bool suspend, bool finished,
                bool conducting) override;
  ECM ShowTasks(const std::vector<std::string> &ids) override;
  ECM InspectTask(const std::string &id, bool show_sets,
                  bool show_entries) override;
  ECM InspectTaskSets(const std::string &id) override;
  ECM InspectTaskEntries(const std::string &id) override;
  ECM QueryTaskEntry(const std::string &entry_id) override;
  ECM Thread(int num = -1) override;
  ECM TerminateTasks(const std::vector<std::string> &ids) override;
  ECM PauseTasks(const std::vector<std::string> &ids) override;
  ECM ResumeTasks(const std::vector<std::string> &ids) override;
  ECM RetryTask(const std::string &id, bool is_async, bool quiet,
                const std::vector<int> &indices) override;
  size_t AddCachedTransferSet(const UserTransferSet &transfer_set) override;
  size_t RemoveCachedTransferSets(const std::vector<size_t> &indices) override;
  void ClearCachedTransferSets() override;
  ECM SubmitCachedTransferSets(bool quiet, bool is_async = false) override;
  ECM QueryCachedTransferSet(size_t index) override;
  [[nodiscard]] std::vector<size_t> ListCachedTransferSetIds() const override;

private:
  void PrintTaskSummary_(
      const AMApplication::TransferWorkflow::TaskSummaryView &task_summary,
      bool verbose) const;
  void PrintTaskEntries_(
      const AMApplication::TransferWorkflow::TaskView &task_view) const;
  void PrintTaskSets_(
      const AMApplication::TransferWorkflow::TaskView &task_view) const;

  AMApplication::TransferWorkflow::TransferAppService &transfer_service_;
  AMInterface::prompt::AMPromptIOManager *prompt_io_manager_ = nullptr;
  AMDomain::client::amf task_control_token_ = nullptr;
};

/**
 * @brief Prompt path-related options used by highlighter/completion logic.
 */
struct PromptPathOptions {
  bool inline_hint_enable = true;
  size_t inline_hint_timeout_ms = 0;
  bool complete_use_async = false;
  size_t complete_timeout_ms = 0;
  bool highlight_enable = true;
  size_t highlight_timeout_ms = 0;
};

namespace Runtime {
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
/**
 * @brief Explicit runtime dependency bindings for completion/highlight
 * helpers.
 */
struct RuntimeBindings {
  AMDomain::host::AMHostConfigManager *host_config_manager = nullptr;
  AMDomain::host::AMKnownHostsManager *known_hosts_manager = nullptr;
  AMApplication::client::ClientAppService *client_service = nullptr;
  AMApplication::TransferWorkflow::TransferAppService *transfer_service = nullptr;
  const AMDomain::var::IVarQueryPort *var_query = nullptr;
  const AMDomain::var::IVarSubstitutionPort *var_substitution = nullptr;
  AMSignalMonitorPort *signal_monitor = nullptr;
  AMInterface::prompt::IsoclineProfileManager *prompt_profile_history_manager = nullptr;
  AMInterface::prompt::AMPromptIOManager *prompt_io_manager = nullptr;
  AMApplication::config::AMConfigAppService *config_service = nullptr;
  AMInterface::style::AMStyleService *style_service = nullptr;
};

/**
 * @brief Bind runtime dependencies explicitly.
 */
void Bind(const RuntimeBindings &bindings);

/**
 * @brief Clear runtime dependency bindings.
 */
void Reset();

/**
 * @brief Return whether all runtime dependencies are bound.
 */
[[nodiscard]] bool IsBound();

/**
 * @brief Return bound application config service reference.
 *
 * @throws std::runtime_error when runtime bindings are incomplete.
 */
AMApplication::config::AMConfigAppService &ConfigServiceOrThrow();

/**
 * @brief Return bound style service reference.
 *
 * @throws std::runtime_error when runtime bindings are incomplete.
 */
AMInterface::style::AMStyleService &StyleServiceOrThrow();

/**
 * @brief Return bound host-config manager reference.
 *
 * @throws std::runtime_error when runtime bindings are incomplete.
 */
AMDomain::host::AMHostConfigManager &HostConfigManagerOrThrow();

/**
 * @brief Return bound known-host manager reference.
 *
 * @throws std::runtime_error when runtime bindings are incomplete.
 */
AMDomain::host::AMKnownHostsManager &KnownHostsManagerOrThrow();

/**
 * @brief Return bound client application service reference.
 *
 * @throws std::runtime_error when runtime bindings are incomplete.
 */
AMApplication::client::ClientAppService &ClientServiceOrThrow();

/**
 * @brief Return bound client runtime port reference.
 */
AMDomain::client::IClientRuntimePort &ClientRuntimePortOrThrow();

/**
 * @brief Return bound client lifecycle port reference.
 */
AMDomain::client::IClientLifecyclePort &ClientLifecyclePortOrThrow();

/**
 * @brief Return bound client path port reference.
 */
AMDomain::client::IClientPathPort &ClientPathPortOrThrow();

/**
 * @brief Return true when a configured host nickname exists.
 */
[[nodiscard]] bool HostExists(const std::string &nickname);

/**
 * @brief Return configured host nicknames.
 */
[[nodiscard]] std::vector<std::string> ListHostNames();

/**
 * @brief Return created/connected client nicknames.
 */
[[nodiscard]] std::vector<std::string> ListClientNames();

/**
 * @brief Return tracked transfer task IDs.
 */
[[nodiscard]] std::vector<std::string> ListTaskIds();

/**
 * @brief Resolve one client by nickname.
 */
[[nodiscard]] ClientHandle GetClient(const std::string &nickname);

/**
 * @brief Resolve one host client from client-maintainer by nickname.
 */
[[nodiscard]] ClientHandle GetHostClient(const std::string &nickname);

/**
 * @brief Return local client instance.
 */
[[nodiscard]] ClientHandle LocalClient();

/**
 * @brief Return current active client.
 */
[[nodiscard]] ClientHandle CurrentClient();

/**
 * @brief Return current active nickname.
 */
[[nodiscard]] std::string CurrentNickname();

/**
 * @brief Parse one raw path token through bound client path service.
 */
[[nodiscard]] AMDomain::client::ParsedClientPath
ParsePath(const std::string &input, amf interrupt_flag = nullptr);

/**
 * @brief Return client workdir, initializing when absent.
 */
[[nodiscard]] std::string GetOrInitWorkdir(const ClientHandle &client);

/**
 * @brief Update one client workdir in application session state.
 */
ECM SetClientWorkdir(const ClientHandle &client, const std::string &path);

/**
 * @brief Set current active client instance.
 */
void SetCurrentClient(const ClientHandle &client);

/**
 * @brief Connect one configured nickname through bound lifecycle port.
 */
std::pair<ECM, ClientHandle>
ConnectNickname(const std::string &nickname, bool force = false,
                bool register_to_manager = true,
                amf interrupt_flag = nullptr);

/**
 * @brief Connect one explicit request through bound lifecycle port.
 */
std::pair<ECM, ClientHandle>
ConnectRequest(const AMDomain::client::ClientConnectContext &context,
               amf interrupt_flag = nullptr);

/**
 * @brief Remove one client through bound lifecycle port.
 */
ECM RemoveClient(const std::string &nickname);

/**
 * @brief Build absolute path from client + raw path.
 */
[[nodiscard]] std::string BuildPath(const ClientHandle &client,
                                    const std::string &path);

/**
 * @brief Substitute path-like variable segments in one raw token.
 */
[[nodiscard]] std::string SubstitutePathLike(const std::string &raw);

/**
 * @brief Return true when one variable domain exists.
 */
[[nodiscard]] bool HasVarDomain(const std::string &domain);

/**
 * @brief Return all available variable domains.
 */
[[nodiscard]] std::vector<std::string> ListVarDomains();

/**
 * @brief Return variables in one domain.
 */
[[nodiscard]] std::vector<AMDomain::var::VarInfo>
ListVarsByDomain(const std::string &domain);

/**
 * @brief Return current variable domain.
 */
[[nodiscard]] std::string CurrentVarDomain();

/**
 * @brief Query one variable value by domain/name.
 */
[[nodiscard]] AMDomain::var::VarInfo GetVar(const std::string &domain,
                                             const std::string &name);

/**
 * @brief Resolve prompt-path options for one nickname profile.
 */
[[nodiscard]] PromptPathOptions
ResolvePromptPathOptions(const std::string &nickname);

/**
 * @brief Resolve one settings string with fallback.
 */
[[nodiscard]] std::string
ResolveSettingString(const std::vector<std::string> &path,
                     const std::string &fallback = "");

/**
 * @brief Resolve one settings integer with fallback.
 */
[[nodiscard]] int ResolveSettingInt(const std::vector<std::string> &path,
                                    int fallback);

/**
 * @brief Execute config backup when pending writes exceed threshold.
 */
ECM BackupConfigIfNeeded();

/**
 * @brief Resolve one config document storage path.
 */
[[nodiscard]] bool GetConfigDataPath(AMDomain::config::DocumentKind kind,
                                     std::filesystem::path *out_path);

/**
 * @brief Return whether one config document has unsaved mutations.
 */
[[nodiscard]] bool IsConfigDirty(AMDomain::config::DocumentKind kind);

/**
 * @brief Load one config document from storage.
 */
ECM LoadConfig(AMDomain::config::DocumentKind kind, bool strict);

/**
 * @brief Format text through interface style service.
 */
[[nodiscard]] std::string Format(const std::string &text,
                                 AMInterface::style::StyleIndex style_index,
                                 const PathInfo *path_info = nullptr);

/**
 * @brief Create one progress bar using style configuration.
 */
[[nodiscard]] AMProgressBar CreateProgressBar(int64_t total_size,
                                              const std::string &prefix);

/**
 * @brief Format one UTF-8 table using configured style defaults.
 */
[[nodiscard]] std::string
FormatUtf8Table(const std::vector<std::string> &keys,
                const std::vector<std::vector<std::string>> &rows);

/**
 * @brief Style one filesystem path display item.
 */
[[nodiscard]] std::string StylePath(const PathInfo &info,
                                    const std::string &name);

/**
 * @brief Register one named signal hook.
 */
bool RegisterSignalHook(const std::string &name,
                        const AMDomain::signal::SignalHook &hook);

/**
 * @brief Unregister one named signal hook.
 */
bool UnregisterSignalHook(const std::string &name);

/**
 * @brief Set signal-hook priority.
 */
bool SetSignalHookPriority(const std::string &name, int priority);

/**
 * @brief Silence one registered CLI signal hook.
 */
void SilenceSignalHook(const std::string &name);

/**
 * @brief Resume one registered CLI signal hook.
 */
void ResumeSignalHook(const std::string &name);
} // namespace Runtime
} // namespace AMInterface::ApplicationAdapters











