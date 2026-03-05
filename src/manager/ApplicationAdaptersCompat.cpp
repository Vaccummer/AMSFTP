#include "interface/ApplicationAdapters.hpp"
#include "interface/Completer/Proxy.hpp"
#include "interface/Prompt.hpp"
#include "domain/client/ClientManager.hpp"
#include "domain/filesystem/FileSystemManager.hpp"
#include "domain/host/HostManager.hpp"
#include "domain/transfer/TransferManager.hpp"
#include "domain/var/VarManager.hpp"
#include "infrastructure/Config.hpp"
#include "infrastructure/SignalMonitor.hpp"
#include <atomic>
#include <stdexcept>

namespace AMInterface::ApplicationAdapters {
/**
 * @brief Construct host/profile gateway from legacy managers.
 */
HostProfileGateway::HostProfileGateway(AMDomain::host::AMHostManager &host_manager,
                                       AMPromptManager &prompt_manager)
    : host_manager_(host_manager), prompt_manager_(prompt_manager) {}

/**
 * @brief Return whether one host nickname exists.
 */
bool HostProfileGateway::HostExists(const std::string &nickname) const {
  return host_manager_.HostExists(nickname);
}

/**
 * @brief List hosts using host manager CLI surface.
 */
ECM HostProfileGateway::ListHosts(bool detail) {
  return host_manager_.List(detail);
}

/**
 * @brief List private keys through host manager.
 */
ECM HostProfileGateway::ListPrivateKeys(bool detail) {
  return host_manager_.PrivateKeys(detail).first;
}

/**
 * @brief Show host configuration source payload.
 */
ECM HostProfileGateway::ShowConfigSource() { return host_manager_.Src(); }

/**
 * @brief Query one or more host entries.
 */
ECM HostProfileGateway::QueryHosts(const std::vector<std::string> &nicknames) {
  return host_manager_.Query(nicknames);
}

/**
 * @brief Add one host entry.
 */
ECM HostProfileGateway::AddHost(const std::string &nickname) {
  return host_manager_.Add(nickname);
}

/**
 * @brief Edit one host entry.
 */
ECM HostProfileGateway::EditHost(const std::string &nickname) {
  return host_manager_.Modify(nickname);
}

/**
 * @brief Rename one host entry.
 */
ECM HostProfileGateway::RenameHost(const std::string &old_name,
                                   const std::string &new_name) {
  return host_manager_.Rename(old_name, new_name);
}

/**
 * @brief Remove one or more host entries.
 */
ECM HostProfileGateway::RemoveHosts(const std::vector<std::string> &nicknames) {
  return host_manager_.Delete(nicknames);
}

/**
 * @brief Set one host attribute value.
 */
ECM HostProfileGateway::SetHostValue(const std::string &nickname,
                                     const std::string &attrname,
                                     const std::string &value) {
  return host_manager_.SetHostValue(nickname, attrname, value);
}

/**
 * @brief Persist host configuration.
 */
ECM HostProfileGateway::SaveHosts() { return host_manager_.Save(); }

/**
 * @brief Edit prompt profile for one nickname.
 */
ECM HostProfileGateway::EditProfile(const std::string &nickname) {
  return prompt_manager_.Edit(nickname);
}

/**
 * @brief Query prompt profiles for nicknames.
 */
ECM HostProfileGateway::GetProfiles(const std::vector<std::string> &nicknames) {
  return prompt_manager_.Get(nicknames);
}

/**
 * @brief List all configured host nicknames.
 */
std::vector<std::string> HostProfileGateway::ListHostNames() const {
  return host_manager_.ListNames();
}

/**
 * @brief Construct current-client reader from client manager.
 */
CurrentClientPort::CurrentClientPort(AMDomain::client::AMClientManager &client_manager)
    : client_manager_(client_manager) {}

/**
 * @brief Return the active client nickname.
 */
std::string CurrentClientPort::CurrentNickname() const {
  return client_manager_.CurrentNickname();
}

/**
 * @brief Construct path helper from client manager.
 */
ClientPathGateway::ClientPathGateway(AMDomain::client::AMClientManager &client_manager)
    : client_manager_(client_manager) {}

/**
 * @brief Return current workdir or empty string when unavailable.
 */
std::string ClientPathGateway::CurrentWorkdir() const {
  auto client = client_manager_.CurrentClient();
  if (!client) {
    return "";
  }
  return client_manager_.GetOrInitWorkdir(client);
}

/**
 * @brief Construct host config saver from host manager.
 */
HostConfigSaver::HostConfigSaver(AMDomain::host::AMHostManager &host_manager)
    : host_manager_(host_manager) {}

/**
 * @brief Persist host configuration state.
 */
ECM HostConfigSaver::SaveHostConfig() { return host_manager_.Save(); }

/**
 * @brief Construct var config saver from var manager.
 */
VarConfigSaver::VarConfigSaver(AMDomain::var::VarCLISet &var_manager)
    : var_manager_(var_manager) {}

/**
 * @brief Persist variable state.
 *
 * `dump_now=true` maps to synchronous save.
 */
ECM VarConfigSaver::SaveVarConfig(bool dump_now) {
  return var_manager_.Save(!dump_now);
}

/**
 * @brief Construct prompt config saver from prompt manager.
 */
PromptConfigSaver::PromptConfigSaver(AMPromptManager &prompt_manager)
    : prompt_manager_(prompt_manager) {}

/**
 * @brief Persist prompt state.
 *
 * Prompt manager persists history through FlushHistory.
 */
ECM PromptConfigSaver::SavePromptConfig(bool dump_now) {
  (void)dump_now;
  prompt_manager_.FlushHistory();
  return Ok();
}

/**
 * @brief Construct client-session gateway from filesystem manager.
 */
ClientSessionGateway::ClientSessionGateway(AMDomain::filesystem::AMFileSystem &filesystem)
    : filesystem_(filesystem) {}

/**
 * @brief Connect one configured nickname.
 */
ECM ClientSessionGateway::ConnectNickname(const std::string &nickname,
                                          bool force, bool switch_client,
                                          amf interrupt_flag) {
  return filesystem_.connect(nickname, force, interrupt_flag, switch_client);
}

/**
 * @brief Change current active client nickname.
 */
ECM ClientSessionGateway::ChangeCurrentClient(const std::string &nickname,
                                              amf interrupt_flag) {
  return filesystem_.change_client(nickname, interrupt_flag);
}

/**
 * @brief Connect one SFTP target.
 */
ECM ClientSessionGateway::ConnectSftp(const std::string &nickname,
                                      const std::string &user_at_host,
                                      int64_t port,
                                      const std::string &password,
                                      const std::string &keyfile,
                                      amf interrupt_flag) {
  return filesystem_.sftp(nickname, user_at_host, port, password, keyfile,
                          interrupt_flag);
}

/**
 * @brief Connect one FTP target.
 */
ECM ClientSessionGateway::ConnectFtp(const std::string &nickname,
                                     const std::string &user_at_host,
                                     int64_t port, const std::string &password,
                                     const std::string &keyfile,
                                     amf interrupt_flag) {
  return filesystem_.ftp(nickname, user_at_host, port, password, keyfile,
                         interrupt_flag);
}

/**
 * @brief Print current client table.
 */
ECM ClientSessionGateway::ListClients(bool detail, amf interrupt_flag) {
  return filesystem_.print_clients(detail, interrupt_flag);
}

/**
 * @brief Remove one or more clients by nickname list.
 */
ECM ClientSessionGateway::DisconnectClients(
    const std::vector<std::string> &nicknames) {
  std::string joined;
  for (size_t i = 0; i < nicknames.size(); ++i) {
    if (i > 0) {
      joined += " ";
    }
    joined += nicknames[i];
  }
  return filesystem_.remove_client(joined);
}

/**
 * @brief Print stat info for one or more resolved paths.
 */
ECM ClientSessionGateway::StatPaths(const std::vector<std::string> &paths,
                                    amf interrupt_flag) {
  return filesystem_.stat(paths, interrupt_flag);
}

/**
 * @brief List directory entries for one resolved path.
 */
ECM ClientSessionGateway::ListPath(const std::string &path, bool list_like,
                                   bool show_all, amf interrupt_flag) {
  return filesystem_.ls(path, list_like, show_all, interrupt_flag);
}

/**
 * @brief Construct filesystem command gateway from filesystem manager.
 */
FileCommandGateway::FileCommandGateway(AMDomain::filesystem::AMFileSystem &filesystem)
    : filesystem_(filesystem) {}

/**
 * @brief Check clients by nickname list.
 */
ECM FileCommandGateway::CheckClients(const std::vector<std::string> &nicknames,
                                     bool detail, amf interrupt_flag) {
  return filesystem_.check(nicknames, detail, interrupt_flag);
}

/**
 * @brief Print current clients.
 */
ECM FileCommandGateway::ListClients(bool detail, amf interrupt_flag) {
  return filesystem_.print_clients(detail, interrupt_flag);
}

/**
 * @brief Disconnect clients by nickname list.
 */
ECM FileCommandGateway::DisconnectClients(
    const std::vector<std::string> &nicknames) {
  return filesystem_.remove_client(JoinNicknames_(nicknames));
}

/**
 * @brief Print stat for one or more paths.
 */
ECM FileCommandGateway::StatPaths(const std::vector<std::string> &paths,
                                  amf interrupt_flag, int timeout_ms) {
  return filesystem_.stat(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief List one path.
 */
ECM FileCommandGateway::ListPath(const std::string &path, bool list_like,
                                 bool show_all, amf interrupt_flag,
                                 int timeout_ms) {
  return filesystem_.ls(path, list_like, show_all, interrupt_flag, timeout_ms);
}

/**
 * @brief Print size for one or more paths.
 */
ECM FileCommandGateway::GetSize(const std::vector<std::string> &paths,
                                amf interrupt_flag, int timeout_ms) {
  return filesystem_.getsize(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief Run find on one path.
 */
ECM FileCommandGateway::Find(const std::string &path, SearchType type,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_.find(path, type, interrupt_flag, timeout_ms);
}

/**
 * @brief Create directories for one or more paths.
 */
ECM FileCommandGateway::Mkdir(const std::vector<std::string> &paths,
                              amf interrupt_flag, int timeout_ms) {
  return filesystem_.mkdir(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief Remove one or more paths.
 */
ECM FileCommandGateway::Remove(const std::vector<std::string> &paths,
                               bool permanent, bool force, bool quiet,
                               amf interrupt_flag, int timeout_ms) {
  return filesystem_.rm(paths, permanent, force, quiet, interrupt_flag,
                        timeout_ms);
}

/**
 * @brief Walk one path.
 */
ECM FileCommandGateway::Walk(const std::string &path, bool only_file,
                             bool only_dir, bool show_all,
                             bool ignore_special_file, bool quiet,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_.walk(path, only_file, only_dir, show_all,
                          ignore_special_file, quiet, interrupt_flag,
                          timeout_ms);
}

/**
 * @brief Print one path tree.
 */
ECM FileCommandGateway::Tree(const std::string &path, int max_depth,
                             bool only_dir, bool show_all,
                             bool ignore_special_file, bool quiet,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_.tree(path, max_depth, only_dir, show_all,
                          ignore_special_file, quiet, interrupt_flag,
                          timeout_ms);
}

/**
 * @brief Resolve one real path.
 */
ECM FileCommandGateway::Realpath(const std::string &path, amf interrupt_flag,
                                 int timeout_ms) {
  return filesystem_.realpath(path, interrupt_flag, timeout_ms);
}

/**
 * @brief Measure RTT for current client.
 */
ECM FileCommandGateway::TestRtt(int times, amf interrupt_flag) {
  return filesystem_.TestRTT(times, interrupt_flag);
}

/**
 * @brief Change current workdir.
 */
ECM FileCommandGateway::Cd(const std::string &path, amf interrupt_flag,
                           bool from_history) {
  return filesystem_.cd(path, interrupt_flag, from_history);
}

/**
 * @brief Run one shell command.
 */
std::pair<ECM, std::pair<std::string, int>>
FileCommandGateway::ShellRun(const std::string &cmd, int max_time_ms,
                             amf interrupt_flag) {
  return filesystem_.ShellRun(cmd, max_time_ms, interrupt_flag);
}

/**
 * @brief Join nicknames for legacy remove-client API.
 */
std::string
FileCommandGateway::JoinNicknames_(const std::vector<std::string> &nicknames) const {
  std::string joined;
  for (size_t i = 0; i < nicknames.size(); ++i) {
    if (i > 0) {
      joined += " ";
    }
    joined += nicknames[i];
  }
  return joined;
}

/**
 * @brief Construct path-substitution port from var manager.
 */
PathSubstitutionPort::PathSubstitutionPort(AMDomain::var::VarCLISet &var_manager)
    : var_manager_(var_manager) {}

/**
 * @brief Substitute one path-like token.
 */
std::string PathSubstitutionPort::SubstitutePathLike(
    const std::string &raw) const {
  return var_manager_.SubstitutePathLike(raw);
}

/**
 * @brief Substitute path-like tokens in one vector.
 */
std::vector<std::string>
PathSubstitutionPort::SubstitutePathLike(
    const std::vector<std::string> &raw) const {
  std::vector<std::string> out = raw;
  var_manager_.SubstitutePathLike(&out);
  return out;
}

/**
 * @brief Construct variable gateway from var manager.
 */
VarGateway::VarGateway(AMDomain::var::VarCLISet &var_manager) : var_manager_(var_manager) {}

/**
 * @brief Substitute one path-like token.
 */
std::string VarGateway::SubstitutePathLike(const std::string &raw) const {
  return var_manager_.SubstitutePathLike(raw);
}

/**
 * @brief Substitute path-like tokens in one vector.
 */
std::vector<std::string>
VarGateway::SubstitutePathLike(const std::vector<std::string> &raw) const {
  std::vector<std::string> out = raw;
  var_manager_.SubstitutePathLike(&out);
  return out;
}

/**
 * @brief Query one variable by token name.
 */
ECM VarGateway::QueryByName(const std::string &token_name) const {
  return var_manager_.QueryByName(token_name);
}

/**
 * @brief Define one variable.
 */
ECM VarGateway::DefineVar(bool global, const std::string &name,
                          const std::string &value) const {
  return var_manager_.DefineVar(global, name, value);
}

/**
 * @brief Delete one variable by CLI args.
 */
ECM VarGateway::DeleteVarByCli(bool all, const std::string &section,
                               const std::string &varname) const {
  return var_manager_.DeleteVarByCli(all, section, varname);
}

/**
 * @brief List variables by domain filters.
 */
ECM VarGateway::ListVars(const std::vector<std::string> &domains) const {
  return var_manager_.ListVars(domains);
}

/**
 * @brief Return true when an active completer instance exists.
 */
bool CompletionGateway::HasActiveCompleter() const {
  return AMCompleter::Active() != nullptr;
}

/**
 * @brief Clear active completer cache.
 */
void CompletionGateway::ClearActiveCompleterCache() const {
  AMCompleter *completer = AMCompleter::Active();
  if (completer) {
    completer->ClearCache();
  }
}

/**
 * @brief Construct transfer executor from transfer manager.
 */
TransferExecutorPort::TransferExecutorPort(AMDomain::transfer::AMTransferManager &transfer_manager)
    : transfer_manager_(transfer_manager) {}

/**
 * @brief Execute transfer sets synchronously.
 */
ECM TransferExecutorPort::Transfer(const std::vector<UserTransferSet> &transfer_sets,
                                   bool quiet, amf interrupt_flag) {
  return transfer_manager_.transfer(transfer_sets, quiet, interrupt_flag);
}

/**
 * @brief Execute transfer sets asynchronously.
 */
ECM TransferExecutorPort::TransferAsync(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    amf interrupt_flag) {
  return transfer_manager_.transfer_async(transfer_sets, quiet, interrupt_flag);
}

/**
 * @brief Construct task gateway from transfer manager.
 */
TaskGateway::TaskGateway(AMDomain::transfer::AMTransferManager &transfer_manager)
    : transfer_manager_(transfer_manager) {}

/**
 * @brief List task states.
 */
ECM TaskGateway::ListTasks(bool pending, bool suspend, bool finished,
                           bool conducting, amf interrupt_flag) {
  return transfer_manager_.List(pending, suspend, finished, conducting,
                                interrupt_flag);
}

/**
 * @brief Show one or more tasks.
 */
ECM TaskGateway::ShowTasks(const std::vector<std::string> &ids,
                           amf interrupt_flag) {
  return transfer_manager_.Show(ids, interrupt_flag);
}

/**
 * @brief Inspect one task.
 */
ECM TaskGateway::InspectTask(const std::string &id, bool show_sets,
                             bool show_entries) {
  return transfer_manager_.Inspect(id, show_sets, show_entries);
}

/**
 * @brief Inspect transfer sets of one task.
 */
ECM TaskGateway::InspectTaskSets(const std::string &id) {
  return transfer_manager_.InspectTransferSets(id);
}

/**
 * @brief Inspect entries of one task.
 */
ECM TaskGateway::InspectTaskEntries(const std::string &id) {
  return transfer_manager_.InspectTaskEntries(id);
}

/**
 * @brief Query one task entry by id.
 */
ECM TaskGateway::QueryTaskEntry(const std::string &entry_id) {
  return transfer_manager_.QuerySetEntry(entry_id);
}

/**
 * @brief Query or set worker thread count.
 */
ECM TaskGateway::Thread(int num) { return transfer_manager_.Thread(num); }

/**
 * @brief Terminate tasks by ids.
 */
ECM TaskGateway::TerminateTasks(const std::vector<std::string> &ids) {
  return transfer_manager_.Terminate(ids);
}

/**
 * @brief Pause tasks by ids.
 */
ECM TaskGateway::PauseTasks(const std::vector<std::string> &ids) {
  return transfer_manager_.Pause(ids);
}

/**
 * @brief Resume tasks by ids.
 */
ECM TaskGateway::ResumeTasks(const std::vector<std::string> &ids) {
  return transfer_manager_.Resume(ids);
}

/**
 * @brief Retry a finished task.
 */
ECM TaskGateway::RetryTask(const std::string &id, bool is_async, bool quiet,
                           const std::vector<int> &indices) {
  return transfer_manager_.retry(id, is_async, quiet, indices);
}

/**
 * @brief Add one transfer set to cache.
 */
size_t TaskGateway::AddCachedTransferSet(const UserTransferSet &transfer_set) {
  return transfer_manager_.SubmitTransferSet(transfer_set);
}

/**
 * @brief Remove cached transfer sets.
 */
size_t
TaskGateway::RemoveCachedTransferSets(const std::vector<size_t> &indices) {
  return transfer_manager_.DeleteTransferSets(indices);
}

/**
 * @brief Clear all cached transfer sets.
 */
void TaskGateway::ClearCachedTransferSets() {
  transfer_manager_.ClearCachedTransferSets();
}

/**
 * @brief Submit cached transfer sets.
 */
ECM TaskGateway::SubmitCachedTransferSets(bool quiet, amf interrupt_flag,
                                          bool is_async) {
  return transfer_manager_.SubmitCachedTransferSets(quiet, interrupt_flag,
                                                    is_async);
}

/**
 * @brief Query one cached transfer set.
 */
ECM TaskGateway::QueryCachedTransferSet(size_t index) {
  return transfer_manager_.QueryCachedUserSet(index);
}

/**
 * @brief List cached transfer set ids.
 */
std::vector<size_t> TaskGateway::ListCachedTransferSetIds() const {
  return transfer_manager_.ListTransferSetIds();
}

namespace {
/**
 * @brief Runtime dependency slots bound once from startup wiring.
 */
struct RuntimeBindingState {
  std::atomic<AMDomain::host::AMHostManager *> host_manager{nullptr};
  std::atomic<AMDomain::client::AMClientManager *> client_manager{nullptr};
  std::atomic<AMDomain::transfer::AMTransferManager *> transfer_manager{nullptr};
  std::atomic<AMDomain::var::VarCLISet *> var_manager{nullptr};
  std::atomic<AMInfraCliSignalMonitor *> signal_monitor{nullptr};
  std::atomic<AMPromptManager *> prompt_manager{nullptr};
  std::atomic<AMInfraConfigManager *> config_manager{nullptr};
  std::atomic<AMDomain::filesystem::AMFileSystem *> filesystem{nullptr};
};

/**
 * @brief Return process-wide runtime binding storage.
 */
RuntimeBindingState &RuntimeBindingState_() {
  static RuntimeBindingState state;
  return state;
}
} // namespace

/**
 * @brief Bind runtime dependencies explicitly.
 */
void Runtime::Bind(const RuntimeBindings &bindings) {
  auto &state = RuntimeBindingState_();
  state.host_manager.store(bindings.host_manager, std::memory_order_release);
  state.client_manager.store(bindings.client_manager, std::memory_order_release);
  state.transfer_manager.store(bindings.transfer_manager,
                               std::memory_order_release);
  state.var_manager.store(bindings.var_manager, std::memory_order_release);
  state.signal_monitor.store(bindings.signal_monitor, std::memory_order_release);
  state.prompt_manager.store(bindings.prompt_manager, std::memory_order_release);
  state.config_manager.store(bindings.config_manager, std::memory_order_release);
  state.filesystem.store(bindings.filesystem, std::memory_order_release);
}

/**
 * @brief Clear runtime dependency bindings.
 */
void Runtime::Reset() {
  auto &state = RuntimeBindingState_();
  state.host_manager.store(nullptr, std::memory_order_release);
  state.client_manager.store(nullptr, std::memory_order_release);
  state.transfer_manager.store(nullptr, std::memory_order_release);
  state.var_manager.store(nullptr, std::memory_order_release);
  state.signal_monitor.store(nullptr, std::memory_order_release);
  state.prompt_manager.store(nullptr, std::memory_order_release);
  state.config_manager.store(nullptr, std::memory_order_release);
  state.filesystem.store(nullptr, std::memory_order_release);
}

/**
 * @brief Return whether all runtime dependencies are bound.
 */
bool Runtime::IsBound() {
  auto &state = RuntimeBindingState_();
  return state.host_manager.load(std::memory_order_acquire) &&
         state.client_manager.load(std::memory_order_acquire) &&
         state.transfer_manager.load(std::memory_order_acquire) &&
         state.var_manager.load(std::memory_order_acquire) &&
         state.signal_monitor.load(std::memory_order_acquire) &&
         state.prompt_manager.load(std::memory_order_acquire) &&
         state.config_manager.load(std::memory_order_acquire) &&
         state.filesystem.load(std::memory_order_acquire);
}

/**
 * @brief Return bound config manager reference or throw when unbound.
 */
AMInfraConfigManager &Runtime::ConfigManagerOrThrow() {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  if (!config_manager) {
    throw std::runtime_error("Runtime config manager is not bound");
  }
  return *config_manager;
}

/**
 * @brief Return true when a configured host nickname exists.
 */
bool Runtime::HostExists(const std::string &nickname) {
  AMDomain::host::AMHostManager *host_manager =
      RuntimeBindingState_().host_manager.load(std::memory_order_acquire);
  return host_manager ? host_manager->HostExists(nickname) : false;
}

/**
 * @brief Return configured host nicknames.
 */
std::vector<std::string> Runtime::ListHostNames() {
  AMDomain::host::AMHostManager *host_manager =
      RuntimeBindingState_().host_manager.load(std::memory_order_acquire);
  return host_manager ? host_manager->ListNames() : std::vector<std::string>{};
}

/**
 * @brief Return created/connected client nicknames.
 */
std::vector<std::string> Runtime::ListClientNames() {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->GetClientNames()
                        : std::vector<std::string>{};
}

/**
 * @brief Return tracked transfer task IDs.
 */
std::vector<std::string> Runtime::ListTaskIds() {
  AMDomain::transfer::AMTransferManager *transfer_manager =
      RuntimeBindingState_().transfer_manager.load(std::memory_order_acquire);
  return transfer_manager ? transfer_manager->ListTaskIds()
                          : std::vector<std::string>{};
}

/**
 * @brief Resolve one client by nickname.
 */
Runtime::ClientHandle Runtime::GetClient(const std::string &nickname) {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->GetClient(nickname) : nullptr;
}

/**
 * @brief Resolve one host client from client-maintainer by nickname.
 */
Runtime::ClientHandle Runtime::GetHostClient(const std::string &nickname) {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->Clients().GetHost(nickname) : nullptr;
}

/**
 * @brief Return local client instance.
 */
Runtime::ClientHandle Runtime::LocalClient() {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->LocalClient() : nullptr;
}

/**
 * @brief Return current active client.
 */
Runtime::ClientHandle Runtime::CurrentClient() {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->CurrentClient() : nullptr;
}

/**
 * @brief Build absolute path from client + raw path.
 */
std::string Runtime::BuildPath(const Runtime::ClientHandle &client,
                               const std::string &path) {
  AMDomain::client::AMClientManager *client_manager =
      RuntimeBindingState_().client_manager.load(std::memory_order_acquire);
  return client_manager ? client_manager->BuildPath(client, path) : path;
}

/**
 * @brief Substitute path-like variable segments in one raw token.
 */
std::string Runtime::SubstitutePathLike(const std::string &raw) {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->SubstitutePathLike(raw) : raw;
}

/**
 * @brief Return true when one variable domain exists.
 */
bool Runtime::HasVarDomain(const std::string &domain) {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->HasDomain(domain) : false;
}

/**
 * @brief Return all available variable domains.
 */
std::vector<std::string> Runtime::ListVarDomains() {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->ListDomains() : std::vector<std::string>{};
}

/**
 * @brief Return variables in one domain.
 */
std::vector<VarInfo> Runtime::ListVarsByDomain(const std::string &domain) {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->ListByDomain(domain) : std::vector<VarInfo>{};
}

/**
 * @brief Return current variable domain.
 */
std::string Runtime::CurrentVarDomain() {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->CurrentDomain() : "";
}

/**
 * @brief Query one variable value by domain/name.
 */
VarInfo Runtime::GetVar(const std::string &domain, const std::string &name) {
  AMDomain::var::VarCLISet *var_manager =
      RuntimeBindingState_().var_manager.load(std::memory_order_acquire);
  return var_manager ? var_manager->GetVar(domain, name) : VarInfo{};
}

/**
 * @brief Resolve prompt-path options for one nickname profile.
 */
PromptPathOptions
Runtime::ResolvePromptPathOptions(const std::string &nickname) {
  AMPromptManager *prompt_manager =
      RuntimeBindingState_().prompt_manager.load(std::memory_order_acquire);
  if (!prompt_manager) {
    return {};
  }
  const AMPromptProfileArgs &profile =
      prompt_manager->ResolvePromptProfileArgs(nickname);
  PromptPathOptions out{};
  out.inline_hint_enable = profile.inline_hint.path.enable;
  out.inline_hint_timeout_ms = profile.inline_hint.path.timeout_ms;
  out.complete_use_async = profile.complete.path.use_async;
  out.complete_timeout_ms = profile.complete.path.timeout_ms;
  out.highlight_enable = profile.highlight.path.enable;
  out.highlight_timeout_ms = profile.highlight.path.timeout_ms;
  return out;
}

/**
 * @brief Resolve one settings string with fallback.
 */
std::string Runtime::ResolveSettingString(const std::vector<std::string> &path,
                                          const std::string &fallback) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->ResolveArg<std::string>(
                              DocumentKind::Settings, path, fallback, {})
                        : fallback;
}

/**
 * @brief Resolve one settings integer with fallback.
 */
int Runtime::ResolveSettingInt(const std::vector<std::string> &path,
                               int fallback) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->ResolveArg<int>(
                              DocumentKind::Settings, path, fallback, {})
                        : fallback;
}

/**
 * @brief Format text through ConfigManager style formatter.
 */
std::string Runtime::Format(const std::string &text,
                            const std::string &style_key,
                            const PathInfo *path_info) {
  AMInfraConfigManager *config_manager =
      RuntimeBindingState_().config_manager.load(std::memory_order_acquire);
  return config_manager ? config_manager->Format(text, style_key, path_info)
                        : text;
}

/**
 * @brief Silence one registered CLI signal hook.
 */
void Runtime::SilenceSignalHook(const std::string &name) {
  AMInfraCliSignalMonitor *signal_monitor =
      RuntimeBindingState_().signal_monitor.load(std::memory_order_acquire);
  if (signal_monitor) {
    signal_monitor->SilenceHook(name);
  }
}

/**
 * @brief Resume one registered CLI signal hook.
 */
void Runtime::ResumeSignalHook(const std::string &name) {
  AMInfraCliSignalMonitor *signal_monitor =
      RuntimeBindingState_().signal_monitor.load(std::memory_order_acquire);
  if (signal_monitor) {
    signal_monitor->ResumeHook(name);
  }
}

/**
 * @brief Style one filesystem path display item.
 */
std::string Runtime::StylePath(const PathInfo &info, const std::string &name) {
  AMDomain::filesystem::AMFileSystem *filesystem =
      RuntimeBindingState_().filesystem.load(std::memory_order_acquire);
  return filesystem ? filesystem->StylePath(info, name) : name;
}
} // namespace AMInterface::ApplicationAdapters



