#include "application/config/ConfigAppService.hpp"

#include "domain/config/ConfigRules.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/time.hpp"
#include <algorithm>
#include <utility>
#include <vector>

namespace {
using DocumentKind = AMDomain::config::DocumentKind;
using ConfigBackupSet = AMDomain::config::ConfigBackupSet;

bool EndsWith_(const std::string &text, const std::string &suffix) {
  if (text.size() < suffix.size()) {
    return false;
  }
  return text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool StartsWith_(const std::string &text, const std::string &prefix) {
  if (text.size() < prefix.size()) {
    return false;
  }
  return text.compare(0, prefix.size(), prefix) == 0;
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
AMConfigAppService::AMConfigAppService(ConfigStoreInitArg init_arg)
    : init_arg_(std::move(init_arg)) {}

/**
 * @brief Build one owned config store from init arg.
 */
ECM AMConfigAppService::Init() {
  const ConfigStoreInitArg init_arg = init_arg_.lock().load();
  auto store_data = AMDomain::config::CreateConfigStorePort(init_arg);
  if (!isok(store_data.rcm) || !store_data.data) {
    return isok(store_data.rcm)
               ? Err(EC::ConfigNotInitialized, "failed to create config store")
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
  return Ok();
}

void AMConfigAppService::SetInitArg(ConfigStoreInitArg init_arg) {
  auto guard = init_arg_.lock();
  guard.store(std::move(init_arg));
}

ConfigStoreInitArg AMConfigAppService::GetInitArg() const {
  return init_arg_.lock().load();
}

/**
 * @brief Bind store dependency.
 */
void AMConfigAppService::Bind(IConfigStorePort *store) {
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
ECM AMConfigAppService::Load(std::optional<AMDomain::config::DocumentKind> kind,
                             bool force) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }
  return store_->Load(kind, force);
}

/**
 * @brief Dump one document; optional async scheduling.
 */
ECM AMConfigAppService::Dump(AMDomain::config::DocumentKind kind,
                             const std::string &dst_path, bool async) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }
  return store_->Dump(kind, std::filesystem::path(dst_path), async);
}

/**
 * @brief Dump all documents; optional async scheduling.
 */
ECM AMConfigAppService::DumpAll(bool async) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }
  return store_->DumpAll(async);
}

/**
 * @brief Close store resources and reset app state.
 */
void AMConfigAppService::CloseHandles() {
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
void AMConfigAppService::SetDumpErrorCallback(DumpErrorCallback cb) {
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
bool AMConfigAppService::IsDirty(AMDomain::config::DocumentKind kind) const {
  return store_ && store_->IsDirty(kind);
}

/**
 * @brief Execute one backup cycle when policy conditions are met.
 */
ECM AMConfigAppService::BackupIfNeeded() {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }

  const auto now_s = static_cast<int64_t>(AMTime::seconds());
  ConfigBackupSet backup_set = LoadBackupSet_();
  const ConfigBackupSet before_normalize = backup_set;
  AMDomain::config::AMConfigRules::NormalizeBackupSet(&backup_set, now_s);
  const bool normalized_changed =
      !IsBackupSetEqual_(backup_set, before_normalize);
  if (normalized_changed && !Write(backup_set)) {
    return Err(EC::ConfigDumpFailed, "failed to update backup policy settings");
  }
  if (!IsBackupNeeded()) {
    if (normalized_changed) {
      return Dump(DocumentKind::Settings, "", true);
    }
    return Ok();
  }
  const std::vector<ECM> rcms = Backup({});
  for (const ECM &rcm : rcms) {
    if (!isok(rcm)) {
      return rcm;
    }
  }
  return Ok();
}

bool AMConfigAppService::IsBackupNeeded() const {
  if (!store_) {
    return false;
  }
  const auto now_s = static_cast<int64_t>(AMTime::seconds());
  ConfigBackupSet backup_set = LoadBackupSet_();
  AMDomain::config::AMConfigRules::NormalizeBackupSet(&backup_set, now_s);
  if (!backup_set.enabled) {
    return false;
  }
  if (backup_set.interval_s > 0 &&
      (now_s - backup_set.last_backup_time_s) < backup_set.interval_s) {
    return false;
  }
  return true;
}

std::vector<ECM> AMConfigAppService::Backup(
    const std::vector<AMDomain::config::DocumentKind> &kinds) {
  std::vector<ECM> out = {};
  if (!store_) {
    out.push_back(Err(EC::ConfigNotInitialized, "config store is not bound"));
    return out;
  }

  const auto now_s = static_cast<int64_t>(AMTime::seconds());
  ConfigBackupSet backup_set = LoadBackupSet_();
  AMDomain::config::AMConfigRules::NormalizeBackupSet(&backup_set, now_s);

  const BackupTargets targets = BuildBackupTargets_(now_s);
  if (targets.backup_dir.empty()) {
    out.push_back(
        Err(EC::ConfigDumpFailed, "project root is empty, cannot backup"));
    return out;
  }

  const ECM mk_bak_rcm = EnsureDirectory(targets.backup_dir);
  if (!isok(mk_bak_rcm)) {
    out.push_back(mk_bak_rcm);
    return out;
  }
  const ECM mk_stamp_rcm = EnsureDirectory(targets.stamp_dir);
  if (!isok(mk_stamp_rcm)) {
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
      out.push_back(Err(EC::InvalidArg, "unsupported backup document kind"));
      continue;
    }
    const ECM rcm = Dump(kind, dst_path.string(), false);
    if (!isok(rcm)) {
      has_dump_error = true;
    }
    out.push_back(rcm);
  }
  if (!has_dump_error) {
    backup_set.last_backup_time_s = now_s;
    if (!Write(backup_set)) {
      out.push_back(
          Err(EC::ConfigDumpFailed, "failed to update backup timestamp"));
      return out;
    }

    CleanupLegacyBackupFiles_(targets.backup_dir);
    PruneBackupFolders_(targets.backup_dir, backup_set.max_backup_count);

    const ECM dump_settings_rcm = Dump(DocumentKind::Settings, "", true);
    if (!isok(dump_settings_rcm)) {
      out.push_back(dump_settings_rcm);
    }
  }
  return out;
}

/**
 * @brief Submit one asynchronous write task.
 */
void AMConfigAppService::SubmitWriteTask(std::function<ECM()> task) {
  if (!store_) {
    if (task) {
      (void)task();
    }
    return;
  }
  store_->SubmitWriteTask(std::move(task));
}

ECMData<AMConfigAppService::SyncParticipantId>
AMConfigAppService::RegisterSyncParticipantImpl_(
    AMDomain::config::ConfigPayloadTag tag, std::function<bool()> is_dirty,
    std::function<ECM()> flush_once, std::function<void()> clear_dirty) {
  if (!is_dirty || !flush_once || !clear_dirty) {
    return {0, Err(EC::InvalidArg, "invalid sync participant callbacks")};
  }

  std::lock_guard<std::mutex> lock(sync_participants_mtx_);
  const SyncParticipantId id = next_sync_participant_id_++;
  SyncParticipant participant = {};
  participant.id = id;
  participant.tag = tag;
  participant.is_dirty = std::move(is_dirty);
  participant.flush_once = std::move(flush_once);
  participant.clear_dirty = std::move(clear_dirty);
  sync_participants_.push_back(std::move(participant));
  return {id, Ok()};
}

ECM AMConfigAppService::UnregisterSyncParticipant(
    SyncParticipantId participant_id) {
  std::lock_guard<std::mutex> lock(sync_participants_mtx_);
  const auto it = std::remove_if(
      sync_participants_.begin(), sync_participants_.end(),
      [participant_id](const SyncParticipant &participant) {
        return participant.id == participant_id;
      });
  if (it == sync_participants_.end()) {
    return Err(EC::InvalidArg, "sync participant not found");
  }
  sync_participants_.erase(it, sync_participants_.end());
  return Ok();
}

ECM AMConfigAppService::FlushDirtyParticipants() {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }

  std::vector<SyncParticipant> participants = {};
  {
    std::lock_guard<std::mutex> lock(sync_participants_mtx_);
    if (sync_flush_running_) {
      return Err(EC::BadOperationOrder, "sync flush already running");
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

  ECM first_error = Ok();
  for (const SyncParticipant &participant : participants) {
    if (!participant.is_dirty || !participant.flush_once ||
        !participant.clear_dirty) {
      if (isok(first_error)) {
        first_error =
            Err(EC::InvalidArg, "invalid sync participant callbacks");
      }
      continue;
    }
    if (!participant.is_dirty()) {
      continue;
    }
    const ECM flush_rcm = participant.flush_once();
    if (!isok(flush_rcm)) {
      if (isok(first_error)) {
        first_error = flush_rcm;
      }
      continue;
    }
    participant.clear_dirty();
  }

  return first_error;
}

/**
 * @brief Return data file path for one document.
 */
bool AMConfigAppService::GetDataPath(AMDomain::config::DocumentKind kind,
                                     std::filesystem::path *value) const {
  return store_ && value && store_->GetDataPath(kind, value);
}

/**
 * @brief Return project root path.
 */
std::filesystem::path AMConfigAppService::ProjectRoot() const {
  return store_ ? store_->ProjectRoot() : std::filesystem::path();
}

/**
 * @brief Ensure one directory exists.
 */
ECM AMConfigAppService::EnsureDirectory(const std::filesystem::path &dir) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }
  return store_->EnsureDirectory(dir);
}

/**
 * @brief Prune old backup timestamp folders under one backup directory.
 */
void AMConfigAppService::PruneBackupFiles(const std::filesystem::path &bak_dir,
                                          int64_t max_count) {
  if (!store_) {
    return;
  }
  store_->PruneBackupFiles(bak_dir, max_count);
}

ConfigBackupSet AMConfigAppService::LoadBackupSet_() const {
  ConfigBackupSet loaded = backup_set_.lock().load();
  if (!store_) {
    return loaded;
  }
  if (store_->Read(AMDomain::config::ConfigPayloadTag::ConfigBackupSet,
                   static_cast<void *>(&loaded))) {
    auto backup_set = backup_set_.lock();
    backup_set.store(loaded);
  }
  return loaded;
}

AMConfigAppService::BackupTargets
AMConfigAppService::BuildBackupTargets_(int64_t backup_time_s) const {
  BackupTargets out = {};
  const std::filesystem::path root_dir = ProjectRoot();
  if (root_dir.empty()) {
    return out;
  }

  const std::string stamp =
      FormatTime(static_cast<size_t>(backup_time_s), "%Y-%m-%d-%H-%M");
  out.backup_dir = root_dir / "config" / "bak";
  out.stamp_dir = out.backup_dir / stamp;
  out.config_file = out.stamp_dir / "config.toml";
  out.settings_file = out.stamp_dir / "settings.toml";
  out.known_hosts_file = out.stamp_dir / "known_hosts.toml";
  out.history_file = out.stamp_dir / "history.toml";
  return out;
}

void AMConfigAppService::PruneBackupFolders_(
    const std::filesystem::path &bak_dir, int64_t max_count) {
  if (!store_) {
    return;
  }
  store_->PruneBackupFiles(bak_dir, max_count);
}

void AMConfigAppService::CleanupLegacyBackupFiles_(
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

bool AMConfigAppService::IsBackupSetEqual_(const ConfigBackupSet &lhs,
                                           const ConfigBackupSet &rhs) {
  return lhs.enabled == rhs.enabled && lhs.interval_s == rhs.interval_s &&
         lhs.max_backup_count == rhs.max_backup_count &&
         lhs.last_backup_time_s == rhs.last_backup_time_s;
}

std::vector<DocumentKind> AMConfigAppService::ResolveBackupKinds_(
    const std::vector<DocumentKind> &kinds) {
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
AMConfigAppService::ResolveBackupPath_(const BackupTargets &targets,
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
