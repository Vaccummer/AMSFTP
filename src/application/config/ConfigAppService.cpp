#include "application/config/ConfigAppService.hpp"

#include "domain/config/ConfigDomainService.hpp"
#include "foundation/tools/time.hpp"
#include <algorithm>
#include <utility>
#include <vector>

namespace {
using DocumentKind = AMDomain::config::DocumentKind;
using ConfigBackupSet = AMDomain::config::ConfigBackupSet;

bool EndsWith_(const std::string &text, const std::string &suffix) {
  return text.ends_with(suffix);
}

bool StartsWith_(const std::string &text, const std::string &prefix) {
  return text.starts_with(prefix);
}

bool IsLegacyBackupFileName_(const std::string &name) {
  if (!EndsWith_(name, ".toml.bak")) {
    return false;
  }
  return StartsWith_(name, "config-") || StartsWith_(name, "settings-") ||
         StartsWith_(name, "known_hosts-");
}
} // namespace

namespace AMApplication::config {

/**
 * @brief Construct one app service with store init payload.
 */
ConfigAppService::ConfigAppService(ConfigStoreInitArg init_arg)
    : init_arg_(std::move(init_arg)) {}

/**
 * @brief Build one owned config store from init arg.
 */
ECM ConfigAppService::Init() {
  const ConfigStoreInitArg init_arg = init_arg_.lock().load();
  auto store_data = AMDomain::config::CreateConfigStorePort(init_arg);
  if (!store_data.rcm || !store_data.data) {
    return (store_data.rcm) ? Err(EC::ConfigNotInitialized, "", "",
                                  "failed to create config store")
                            : store_data.rcm;
  }
  owned_store_ = std::move(store_data.data);
  store_ = owned_store_.get();
  {
    auto backup_set = backup_set_.lock();
    backup_set.store(ConfigBackupSet{});
  }
  if (store_ && dump_error_cb_) {
    store_->SetDumpErrorCallback([this](const ECM &err) {
      if (dump_error_cb_) {
        dump_error_cb_(err);
      }
    });
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
 * @brief Bind store dependency.
 */
void ConfigAppService::Bind(IConfigStorePort *store) {
  owned_store_.reset();
  store_ = store;
  {
    auto backup_set = backup_set_.lock();
    backup_set.store(ConfigBackupSet{});
  }
  if (store_ && dump_error_cb_) {
    store_->SetDumpErrorCallback([this](const ECM &err) {
      if (dump_error_cb_) {
        dump_error_cb_(err);
      }
    });
  }
}

/**
 * @brief Load one document or all documents from store.
 */
ECM ConfigAppService::Load(std::optional<AMDomain::config::DocumentKind> kind,
                           bool force) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "", "", "config store is not bound");
  }
  return store_->Load(kind, force);
}

/**
 * @brief Dump one document; optional async scheduling.
 */
ECM ConfigAppService::Dump(AMDomain::config::DocumentKind kind,
                           const std::string &dst_path, bool async) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "", "", "config store is not bound");
  }
  return store_->Dump(kind, std::filesystem::path(dst_path), async);
}

/**
 * @brief Dump all documents; optional async scheduling.
 */
ECM ConfigAppService::DumpAll(bool async) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "", "", "config store is not bound");
  }
  return store_->DumpAll(async);
}

/**
 * @brief Close store resources and reset app state.
 */
void ConfigAppService::CloseHandles() {
  if (store_) {
    store_->Close();
  }
  if (owned_store_) {
    owned_store_.reset();
    store_ = nullptr;
  }
  auto backup_set = backup_set_.lock();
  backup_set.store(ConfigBackupSet{});
  {
    std::lock_guard<std::mutex> lock(sync_participants_mtx_);
    sync_participants_.clear();
    next_sync_participant_id_ = 1;
    sync_flush_running_ = false;
  }
}

/**
 * @brief Bind callback invoked on write/dump failures.
 */
void ConfigAppService::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
  if (store_) {
    store_->SetDumpErrorCallback([this](const ECM &err) {
      if (dump_error_cb_) {
        dump_error_cb_(err);
      }
    });
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
    return {EC::ConfigNotInitialized, "", "", "config store is not bound"};
  }

  const auto now_s = static_cast<int64_t>(AMTime::seconds());
  ConfigBackupSet backup_set = LoadBackupSet_();
  const ConfigBackupSet before_normalize = backup_set;
  AMDomain::config::service::NormalizeBackupSet(&backup_set, now_s);
  const bool normalized_changed =
      !IsBackupSetEqual_(backup_set, before_normalize);
  if (normalized_changed && !Write(backup_set)) {
    return {EC::ConfigDumpFailed, "", "",
            "failed to update backup policy settings"};
  }
  if (!IsBackupNeeded()) {
    if (normalized_changed) {
      return Dump(DocumentKind::Settings, "", true);
    }
    return OK;
  }
  const std::vector<ECM> rcms = Backup({});
  for (const ECM &rcm : rcms) {
    if (!(rcm)) {
      return rcm;
    }
  }
  return OK;
}

bool ConfigAppService::IsBackupNeeded() const {
  if (!store_) {
    return false;
  }
  const auto now_s = static_cast<int64_t>(AMTime::seconds());
  ConfigBackupSet backup_set = LoadBackupSet_();
  AMDomain::config::service::NormalizeBackupSet(&backup_set, now_s);
  if (!backup_set.enabled) {
    return false;
  }
  if (backup_set.interval_s > 0 &&
      (now_s - backup_set.last_backup_time_s) < backup_set.interval_s) {
    return false;
  }
  return true;
}

std::vector<ECM> ConfigAppService::Backup(
    const std::vector<AMDomain::config::DocumentKind> &kinds) {
  std::vector<ECM> out = {};
  if (!store_) {
    out.emplace_back(EC::ConfigNotInitialized, "", "",
                     "config store is not bound");
    return out;
  }

  const auto now_s = static_cast<int64_t>(AMTime::seconds());
  ConfigBackupSet backup_set = LoadBackupSet_();
  AMDomain::config::service::NormalizeBackupSet(&backup_set, now_s);

  const BackupTargets targets = BuildBackupTargets_(now_s);
  if (targets.backup_dir.empty()) {
    out.emplace_back(EC::ConfigDumpFailed, "", "",
                     "project root is empty, cannot backup");
    return out;
  }

  const ECM mk_bak_rcm = EnsureDirectory(targets.backup_dir);
  if (!(mk_bak_rcm)) {
    out.push_back(mk_bak_rcm);
    return out;
  }
  const ECM mk_stamp_rcm = EnsureDirectory(targets.stamp_dir);
  if (!(mk_stamp_rcm)) {
    out.push_back(mk_stamp_rcm);
    return out;
  }

  const std::vector<DocumentKind> selected_kinds = ResolveBackupKinds_(kinds);
  out.reserve(selected_kinds.size());
  bool has_dump_error = false;
  for (DocumentKind kind : selected_kinds) {
    const std::filesystem::path dst_path = ResolveBackupPath_(targets, kind);
    if (dst_path.empty()) {
      has_dump_error = true;
      out.emplace_back(EC::InvalidArg, "", "",
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
    backup_set.last_backup_time_s = now_s;
    if (!Write(backup_set)) {
      out.emplace_back(EC::ConfigDumpFailed, "", "",
                       "failed to update backup timestamp");
      return out;
    }

    CleanupLegacyBackupFiles_(targets.backup_dir);
    PruneBackupFolders_(targets.backup_dir, backup_set.max_backup_count);

    const ECM dump_settings_rcm = Dump(DocumentKind::Settings, "", true);
    if (!(dump_settings_rcm)) {
      out.push_back(dump_settings_rcm);
    }
  }
  return out;
}

/**
 * @brief Submit one asynchronous write task.
 */
void ConfigAppService::SubmitWriteTask(std::function<ECM()> task) {
  if (!store_) {
    if (task) {
      (void)task();
    }
    return;
  }
  store_->SubmitWriteTask(std::move(task));
}

ECMData<ConfigAppService::SyncParticipantId>
ConfigAppService::RegisterSyncPort(IConfigSyncPort *port) {
  if (port == nullptr) {
    return {0, Err(EC::InvalidArg, "", "", "sync port is null")};
  }
  std::lock_guard<std::mutex> lock(sync_participants_mtx_);
  for (const auto &participant : sync_participants_) {
    if (participant.port == port) {
      return {participant.id, OK};
    }
  }
  const SyncParticipantId id = next_sync_participant_id_++;
  sync_participants_.push_back({id, port});
  return {id, OK};
}

ECM ConfigAppService::UnregisterSyncPort(SyncParticipantId participant_id) {
  std::lock_guard<std::mutex> lock(sync_participants_mtx_);
  const auto erased = std::erase_if(
      sync_participants_, [participant_id](const SyncParticipant &participant) {
        return participant.id == participant_id;
      });
  if (erased == 0) {
    return Err(EC::InvalidArg, "", "", "sync port not found");
  }
  return OK;
}

ECM ConfigAppService::FlushDirtyParticipants() {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "", "", "config store is not bound");
  }

  std::vector<SyncParticipant> participants = {};
  {
    std::lock_guard<std::mutex> lock(sync_participants_mtx_);
    if (sync_flush_running_) {
      return Err(EC::BadOperationOrder, "", "", "sync flush already running");
    }
    sync_flush_running_ = true;
    participants = sync_participants_;
  }

  auto reset_running = [this]() {
    std::lock_guard<std::mutex> lock(sync_participants_mtx_);
    sync_flush_running_ = false;
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
        first_error = Err(EC::InvalidArg, "", "", "invalid sync participant");
      }
      continue;
    }
    if (!participant.port->IsConfigDirty()) {
      continue;
    }
    const ECM flush_rcm = participant.port->FlushTo(this);
    if (!(flush_rcm)) {
      if ((first_error)) {
        first_error = flush_rcm;
      }
      continue;
    }
    participant.port->ClearConfigDirty();
  }

  return first_error;
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

/**
 * @brief Ensure one directory exists.
 */
ECM ConfigAppService::EnsureDirectory(const std::filesystem::path &dir) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "", "", "config store is not bound");
  }
  return store_->EnsureDirectory(dir);
}

/**
 * @brief Prune old backup timestamp folders under one backup directory.
 */
void ConfigAppService::PruneBackupFiles(const std::filesystem::path &bak_dir,
                                        int64_t max_count) {
  if (!store_) {
    return;
  }
  store_->PruneBackupFiles(bak_dir, max_count);
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
  out.history_file = out.stamp_dir / "history.toml";
  return out;
}

void ConfigAppService::PruneBackupFolders_(const std::filesystem::path &bak_dir,
                                           int64_t max_count) {
  if (!store_) {
    return;
  }
  store_->PruneBackupFiles(bak_dir, max_count);
}

void ConfigAppService::CleanupLegacyBackupFiles_(
    const std::filesystem::path &bak_dir) {
  std::error_code ec;
  if (!std::filesystem::exists(bak_dir, ec) || ec) {
    return;
  }
  for (const auto &entry : std::filesystem::directory_iterator(bak_dir, ec)) {
    if (ec) {
      break;
    }
    if (!entry.is_regular_file(ec) || ec) {
      continue;
    }
    const std::string name = entry.path().filename().string();
    if (!IsLegacyBackupFileName_(name)) {
      continue;
    }
    std::filesystem::remove(entry.path(), ec);
  }
}

bool ConfigAppService::IsBackupSetEqual_(const ConfigBackupSet &lhs,
                                         const ConfigBackupSet &rhs) {
  return lhs.enabled == rhs.enabled && lhs.interval_s == rhs.interval_s &&
         lhs.max_backup_count == rhs.max_backup_count &&
         lhs.last_backup_time_s == rhs.last_backup_time_s;
}

std::vector<DocumentKind>
ConfigAppService::ResolveBackupKinds_(const std::vector<DocumentKind> &kinds) {
  if (kinds.empty()) {
    return {DocumentKind::Config, DocumentKind::Settings,
            DocumentKind::KnownHosts};
  }

  std::vector<DocumentKind> resolved = {};
  resolved.reserve(kinds.size());
  for (DocumentKind kind : kinds) {
    if (std::find(resolved.begin(), resolved.end(), kind) == resolved.end()) {
      resolved.push_back(kind);
    }
  }
  return resolved;
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
  if (kind == DocumentKind::History) {
    return targets.history_file;
  }
  return {};
}
} // namespace AMApplication::config

