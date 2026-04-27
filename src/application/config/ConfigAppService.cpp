#include "application/config/ConfigAppService.hpp"
#include "application/log/ProgramTrace.hpp"
#include "domain/config/ConfigDomainService.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"

#include <array>
#include <utility>
#include <vector>

namespace {
using AMDomain::config::ConfigBackupSet;
using AMDomain::config::DocumentKind;

constexpr std::array<DocumentKind, 3> kDocumentKindOrder = {
    DocumentKind::Config,
    DocumentKind::Settings,
    DocumentKind::KnownHosts,
};
} // namespace

namespace AMApplication::config {

/**
 * @brief Construct one app service with store init payload.
 */
ConfigAppService::ConfigAppService(ConfigStoreInitArg init_arg)
    : init_arg_(std::move(init_arg)) {}

void ConfigAppService::SetLogger(AMApplication::log::LoggerAppService *logger) {
  logger_ = logger;
}

void ConfigAppService::SetWriteLock(
    std::unique_ptr<AMDomain::config::IConfigWriteLockPort> lock) {
  write_lock_ = std::move(lock);
}

/**
 * @brief Build one owned config store from init arg.
 */
ECM ConfigAppService::Init() {
  const ConfigStoreInitArg init_arg = init_arg_.lock().load();
  auto store_data = AMDomain::config::CreateConfigStorePort(init_arg);
  if (!store_data.rcm || !store_data.data) {
    return (store_data.rcm) ? Err{EC::ConfigNotInitialized, "config.init", "",
                                  "failed to create config store"}
                            : store_data.rcm;
  }
  store_ = std::move(store_data.data);
  {
    auto backup_set = backup_set_.lock();
    backup_set.store(ConfigBackupSet{});
  }
  if (dump_error_cb_) {
    store_->SetDumpErrorCallback(
        [this](const ECM &err) { dump_error_cb_(err); });
  } else {
    store_->SetDumpErrorCallback({});
  }
  if (write_lock_) {
    const ECM lock_rcm = write_lock_->TryAcquire();
    TraceConfig_(lock_rcm, write_lock_->LockPath().string(), "config.lock",
                 lock_rcm ? "write lock acquired" : "readonly session");
  }
  return OK;
}

void ConfigAppService::SetInitArg(ConfigStoreInitArg init_arg) {
  auto guard = init_arg_.lock();
  guard.store(std::move(init_arg));
}

ConfigStoreInitArg ConfigAppService::GetInitArg() const {
  return init_arg_.lock().load();
}

/**
 * @brief Load one document or all documents from store.
 */
ECM ConfigAppService::Load(std::optional<AMDomain::config::DocumentKind> kind,
                           bool force) {
  if (!store_) {
    const ECM rcm = {EC::ConfigNotInitialized, "config.load", "",
                     "config store is not bound"};
    TraceConfig_(rcm, kind.has_value() ? AMStr::ToString(*kind) : "<all>",
                 "config.load");
    return rcm;
  }
  const ECM rcm = store_->Load(kind, force);
  TraceConfig_(rcm, kind.has_value() ? AMStr::ToString(*kind) : "<all>",
               "config.load", AMStr::fmt("force={}", force ? "true" : "false"));
  return rcm;
}

/**
 * @brief Dump one document; optional async scheduling.
 */
ECM ConfigAppService::Dump(AMDomain::config::DocumentKind kind,
                           const std::string &dst_path, bool async) {
  if (!store_) {
    const ECM rcm = {EC::ConfigNotInitialized, "config.dump", "",
                     "config store is not bound"};
    TraceConfig_(rcm, AMStr::ToString(kind), "config.dump");
    return rcm;
  }
  if (dst_path.empty()) {
    const ECM lock_rcm = EnsureConfigWriteLock();
    if (!(lock_rcm)) {
      TraceConfig_(lock_rcm, AMStr::ToString(kind), "config.dump",
                   "original config dump requires write lock");
      return lock_rcm;
    }
  }
  const ECM rcm = store_->Dump(kind, std::filesystem::path(dst_path), async);
  TraceConfig_(rcm, AMStr::ToString(kind), "config.dump",
               AMStr::fmt("async={} dst={}", async ? "true" : "false",
                          dst_path.empty() ? std::string("<default>")
                                           : dst_path));
  return rcm;
}

ECM ConfigAppService::EnsureConfigWriteLock() {
  if (!write_lock_) {
    return OK;
  }
  if (write_lock_->IsHeld()) {
    return OK;
  }
  const ECM rcm = write_lock_->TryAcquire();
  TraceConfig_(rcm, write_lock_->LockPath().string(), "config.lock",
               rcm ? "write lock acquired" : "failed to acquire write lock");
  return rcm;
}

bool ConfigAppService::HasConfigWriteLock() const {
  return !write_lock_ || write_lock_->IsHeld();
}

std::filesystem::path ConfigAppService::GetConfigWriteLockPath() const {
  return write_lock_ ? write_lock_->LockPath() : std::filesystem::path();
}

std::string ConfigAppService::GetConfigWriteLockOwnerInfo() const {
  return write_lock_ ? write_lock_->OwnerInfo() : std::string();
}

/**
 * @brief Close store resources and reset app state.
 */
void ConfigAppService::CloseHandles() {
  if (store_) {
    store_->Close();
  }
  store_.reset();
  if (write_lock_) {
    write_lock_->Release();
  }
  auto backup_set = backup_set_.lock();
  backup_set.store(ConfigBackupSet{});
  {
    auto sync_participants = sync_participants_.lock();
    sync_participants.get().clear();
  }
  next_sync_participant_id_.store(1, std::memory_order_release);
  sync_flush_running_.store(false, std::memory_order_release);
}

/**
 * @brief Bind callback invoked on write/dump failures.
 */
void ConfigAppService::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
  if (!store_) {
    return;
  }
  if (dump_error_cb_) {
    store_->SetDumpErrorCallback(
        [this](const ECM &err) { dump_error_cb_(err); });
  } else {
    store_->SetDumpErrorCallback({});
  }
}

/**
 * @brief Return whether one document is dirty in store.
 */
bool ConfigAppService::IsDirty(AMDomain::config::DocumentKind kind) const {
  return store_ && store_->IsDirty(kind);
}

/**
 * @brief Execute one backup cycle when policy conditions are met.
 */
ECM ConfigAppService::BackupIfNeeded() {
  if (!store_) {
    const ECM rcm = {EC::ConfigNotInitialized, "config.backup", "",
                     "config store is not bound"};
    TraceConfig_(rcm, "<policy>", "config.backup");
    return rcm;
  }
  if (!HasConfigWriteLock()) {
    TraceConfig_(OK, "<policy>", "config.backup",
                 "skip auto backup in readonly session");
    return OK;
  }

  const BackupContext context = BuildBackupContext_();
  if (context.normalized_changed && !Write(context.backup_set)) {
    return {EC::ConfigDumpFailed, "config.backup", "",
            "failed to update backup policy settings"};
  }
  if (!IsBackupDue_(context)) {
    if (context.normalized_changed) {
      const ECM dump_rcm = Dump(DocumentKind::Settings, "", true);
      TraceConfig_(dump_rcm, "<policy>", "config.backup",
                   "normalized backup policy only");
      return dump_rcm;
    }
    TraceConfig_(OK, "<policy>", "config.backup", "backup not due");
    return OK;
  }
  const std::vector<ECM> rcms =
      BackupWithContext_(ListOwnedDocumentKinds_(), context);
  for (const ECM &rcm : rcms) {
    if (!(rcm)) {
      TraceConfig_(rcm, "<policy>", "config.backup", "backup failed");
      return rcm;
    }
  }
  TraceConfig_(OK, "<policy>", "config.backup", "backup completed");
  return OK;
}

bool ConfigAppService::IsBackupNeeded() const {
  if (!store_) {
    return false;
  }
  if (!HasConfigWriteLock()) {
    return false;
  }
  return IsBackupDue_(BuildBackupContext_());
}

std::vector<ECM> ConfigAppService::Backup(
    const std::vector<AMDomain::config::DocumentKind> &kinds) {
  if (!store_) {
    return {Err{EC::ConfigNotInitialized, "config.backup", "",
                "config store is not bound"}};
  }
  return BackupWithContext_(kinds, BuildBackupContext_());
}

ECMData<SyncParticipantId>
ConfigAppService::RegisterSyncPort(IConfigSyncPort *port) {
  if (port == nullptr) {
    return {0, Err{EC::InvalidArg, "config.register_sync", "",
                    "sync port is null"}};
  }
  auto sync_participants = sync_participants_.lock();
  for (const auto &participant : sync_participants.get()) {
    if (participant.port == port) {
      return {participant.id, OK};
    }
  }
  const SyncParticipantId id =
      next_sync_participant_id_.fetch_add(1, std::memory_order_acq_rel);
  sync_participants.get().emplace_back(id, port);
  return {id, OK};
}

ECM ConfigAppService::UnregisterSyncPort(SyncParticipantId participant_id) {
  auto sync_participants = sync_participants_.lock();
  const auto erased =
      std::erase_if(sync_participants.get(),
                    [participant_id](const SyncParticipant &participant) {
                      return participant.id == participant_id;
                    });
  if (erased == 0) {
    return Err{EC::InvalidArg, "config.unregister_sync", "",
               "sync port not found"};
  }
  return OK;
}

ECM ConfigAppService::FlushDirtyParticipants() {
  if (!store_) {
    const ECM rcm = Err{EC::ConfigNotInitialized, "config.flush_dirty", "",
                        "config store is not bound"};
    TraceConfig_(rcm, "<participants>", "config.flush_dirty");
    return rcm;
  }

  std::vector<SyncParticipant> participants = {};
  {
    if (sync_flush_running_.exchange(true, std::memory_order_acq_rel)) {
      const ECM rcm = Err{EC::BadOperationOrder, "config.flush_dirty", "",
                          "sync flush already running"};
      TraceConfig_(rcm, "<participants>", "config.flush_dirty");
      return rcm;
    }
    auto sync_participants = sync_participants_.lock();
    participants = sync_participants.load();
  }

  auto reset_running = [this]() {
    sync_flush_running_.store(false, std::memory_order_release);
  };
  struct SyncFlushGuard {
    std::function<void()> fn = {};
    ~SyncFlushGuard() {
      if (fn) {
        fn();
      }
    }
  } guard{reset_running};

  ECM first_error = OK;
  for (const SyncParticipant &participant : participants) {
    if (participant.port == nullptr) {
      if ((first_error)) {
        first_error =
            Err{EC::InvalidArg, "config.flush_dirty", "",
                "invalid sync participant"};
      }
      continue;
    }
    if (!participant.port->IsConfigDirty()) {
      continue;
    }
    const ECM flush_rcm = participant.port->FlushTo(store_.get());
    if (!(flush_rcm)) {
      if ((first_error)) {
        first_error = flush_rcm;
      }
      continue;
    }
    participant.port->ClearConfigDirty();
  }

  TraceConfig_(first_error, "<participants>", "config.flush_dirty",
               AMStr::fmt("participants={}", participants.size()));
  return first_error;
}

ECM ConfigAppService::FlushAndDumpDirtyDocuments() {
  ECM rcm = FlushDirtyParticipants();
  if (!(rcm)) {
    return rcm;
  }

  ECM first_error = OK;
  for (const ConfigDocumentState &doc : ListDocuments()) {
    if (doc.status != ConfigDocumentStatus::Dirty) {
      continue;
    }
    const ECM dump_rcm = Dump(doc.kind, "", false);
    if (!(dump_rcm) && (first_error)) {
      first_error = dump_rcm;
    }
  }
  return first_error;
}

std::vector<ConfigDocumentState> ConfigAppService::ListDocuments() const {
  std::vector<ConfigDocumentState> out = {};
  const std::vector<DocumentKind> kinds = ListOwnedDocumentKinds_();
  out.reserve(kinds.size());
  for (DocumentKind kind : kinds) {
    std::filesystem::path data_path = {};
    (void)GetDataPath(kind, &data_path);
    out.emplace_back(kind,
                     IsDirty(kind) ? ConfigDocumentStatus::Dirty
                                   : ConfigDocumentStatus::Clean,
                     std::move(data_path));
  }
  return out;
}

/**
 * @brief Return data file path for one document.
 */
bool ConfigAppService::GetDataPath(AMDomain::config::DocumentKind kind,
                                   std::filesystem::path *value) const {
  return store_ && value && store_->GetDataPath(kind, value);
}

/**
 * @brief Return project root path.
 */
std::filesystem::path ConfigAppService::ProjectRoot() const {
  return store_ ? store_->ProjectRoot() : std::filesystem::path();
}

ConfigAppService::BackupContext ConfigAppService::BuildBackupContext_() const {
  BackupContext context = {};
  context.now_s = static_cast<int64_t>(AMTime::seconds());
  context.backup_set = LoadBackupSet_();
  const ConfigBackupSet before_normalize = context.backup_set;
  AMDomain::config::service::NormalizeBackupSet(&context.backup_set,
                                                context.now_s);
  context.normalized_changed = context.backup_set != before_normalize;
  return context;
}

bool ConfigAppService::IsBackupDue_(const BackupContext &context) const {
  if (!context.backup_set.enabled) {
    return false;
  }
  if (context.backup_set.interval_s > 0 &&
      (context.now_s - context.backup_set.last_backup_time_s) <
          context.backup_set.interval_s) {
    return false;
  }
  return true;
}

void ConfigAppService::TraceConfig_(const ECM &rcm, const std::string &target,
                                    const std::string &action,
                                    const std::string &message) const {
  std::string detail = message;
  if (!(rcm)) {
    if (!detail.empty()) {
      detail += "; ";
    }
    detail += AMStr::fmt("result={} error={}", AMStr::ToString(rcm.code),
                         rcm.msg());
  }
  AMApplication::log::ProgramTrace(
      logger_, rcm, target.empty() ? std::string("<config>") : target, action,
      detail);
}

std::vector<DocumentKind> ConfigAppService::ListOwnedDocumentKinds_() const {
  std::vector<DocumentKind> out = {};
  const ConfigStoreInitArg init_arg = init_arg_.lock().load();
  out.reserve(init_arg.layout.size());
  for (DocumentKind kind : kDocumentKindOrder) {
    if (init_arg.layout.contains(kind)) {
      out.push_back(kind);
    }
  }
  return out;
}

std::vector<ECM>
ConfigAppService::BackupWithContext_(const std::vector<DocumentKind> &kinds,
                                     const BackupContext &context) {
  std::vector<ECM> out = {};
  if (kinds.empty()) {
    return out;
  }
  ConfigBackupSet backup_set = context.backup_set;
  const BackupTargets targets = BuildBackupTargets_(context.now_s);
  if (targets.backup_dir.empty()) {
    out.emplace_back(EC::ConfigDumpFailed, "config.backup", "",
                     "project root is empty, cannot backup");
    return out;
  }

  const ECM mk_bak_rcm = AMPath::mkdirs(targets.backup_dir);
  if (!(mk_bak_rcm)) {
    out.push_back(mk_bak_rcm);
    return out;
  }
  const ECM mk_stamp_rcm = AMPath::mkdirs(targets.stamp_dir);
  if (!(mk_stamp_rcm)) {
    out.push_back(mk_stamp_rcm);
    return out;
  }

  out.reserve(kinds.size());
  bool has_dump_error = false;
  for (DocumentKind kind : kinds) {
    const std::filesystem::path dst_path = ResolveBackupPath_(targets, kind);
    if (dst_path.empty()) {
      has_dump_error = true;
      out.emplace_back(EC::InvalidArg, "config.backup", "",
                       "unsupported backup document kind");
      continue;
    }
    const ECM rcm = Dump(kind, dst_path.string(), false);
    if (!(rcm)) {
      has_dump_error = true;
    }
    out.push_back(rcm);
  }
  if (!has_dump_error) {
    backup_set.last_backup_time_s = context.now_s;
    if (!Write(backup_set)) {
      out.emplace_back(EC::ConfigDumpFailed, "config.backup", "",
                       "failed to update backup timestamp");
      return out;
    }

    store_->PruneBackupFiles(targets.backup_dir, backup_set.max_backup_count);

    const ECM dump_settings_rcm = Dump(DocumentKind::Settings, "", true);
    if (!(dump_settings_rcm)) {
      out.push_back(dump_settings_rcm);
    }
  }
  return out;
}

ConfigBackupSet ConfigAppService::LoadBackupSet_() const {
  ConfigBackupSet loaded = backup_set_.lock().load();
  if (!store_) {
    return loaded;
  }
  if (store_->Read(std::type_index(typeid(ConfigBackupSet)),
                   static_cast<void *>(&loaded))) {
    auto backup_set = backup_set_.lock();
    backup_set.store(loaded);
  }
  return loaded;
}

ConfigAppService::BackupTargets
ConfigAppService::BuildBackupTargets_(int64_t backup_time_s) const {
  BackupTargets out = {};
  const std::filesystem::path root_dir = ProjectRoot();
  if (root_dir.empty()) {
    return out;
  }

  const std::string stamp =
      FormatTime(static_cast<size_t>(backup_time_s), "%Y-%m-%d_%H-%M-%S");
  out.backup_dir = root_dir / "config" / "bak";
  out.stamp_dir = out.backup_dir / stamp;
  out.config_file = out.stamp_dir / "config.toml";
  out.settings_file = out.stamp_dir / "settings.toml";
  out.known_hosts_file = out.stamp_dir / "known_hosts.toml";
  return out;
}

std::filesystem::path
ConfigAppService::ResolveBackupPath_(const BackupTargets &targets,
                                     DocumentKind kind) const {
  if (kind == DocumentKind::Config) {
    return targets.config_file;
  }
  if (kind == DocumentKind::Settings) {
    return targets.settings_file;
  }
  if (kind == DocumentKind::KnownHosts) {
    return targets.known_hosts_file;
  }
  return {};
}
} // namespace AMApplication::config
