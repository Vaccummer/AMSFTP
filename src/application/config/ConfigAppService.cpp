#include "application/config/ConfigAppService.hpp"

#include "foundation/tools/enum_related.hpp"

namespace AMApplication::config {
/**
 * @brief Construct one app service with optional bound dependencies.
 */
AMConfigAppService::AMConfigAppService(IConfigStorePort *store,
                                       AMConfigBackupUseCase *backup_use_case)
    : store_(store), backup_use_case_(backup_use_case) {}

/**
 * @brief Bind store and use-case dependencies.
 */
void AMConfigAppService::Bind(IConfigStorePort *store,
                              AMConfigBackupUseCase *backup_use_case) {
  store_ = store;
  backup_use_case_ = backup_use_case;
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
 * @brief Execute auto-backup use-case.
 */
ECM AMConfigAppService::BackupIfNeeded() {
  if (!backup_use_case_) {
    return Err(EC::OperationUnsupported, "backup use-case is not bound");
  }
  return backup_use_case_->Execute(this);
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
 * @brief Prune old backups matching naming convention.
 */
void AMConfigAppService::PruneBackupFiles(const std::filesystem::path &dir,
                                          const std::string &prefix,
                                          const std::string &suffix,
                                          int64_t max_count) {
  if (!store_) {
    return;
  }
  store_->PruneBackupFiles(dir, prefix, suffix, max_count);
}
} // namespace AMApplication::config
