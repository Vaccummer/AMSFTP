#include "application/config/ConfigAppService.hpp"

#include "foundation/tools/enum_related.hpp"

namespace AMApplication::config {
AMConfigAppService::AMConfigAppService(IConfigStorePort *store,
                                       AMConfigBackupUseCase *backup_use_case)
    : store_(store), backup_use_case_(backup_use_case) {}

void AMConfigAppService::Bind(IConfigStorePort *store,
                              AMConfigBackupUseCase *backup_use_case) {
  store_ = store;
  backup_use_case_ = backup_use_case;
}

ECM AMConfigAppService::Load(std::optional<AMDomain::config::DocumentKind> kind,
                             bool force) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }
  return store_->Load(kind, force);
}

ECM AMConfigAppService::Dump(AMDomain::config::DocumentKind kind,
                             const std::string &dst_path, bool async) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }
  return store_->Dump(kind, std::filesystem::path(dst_path), async);
}

ECM AMConfigAppService::DumpAll(bool async) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }
  return store_->DumpAll(async);
}

void AMConfigAppService::CloseHandles() {
  if (store_) {
    store_->Close();
  }
}

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

bool AMConfigAppService::IsDirty(AMDomain::config::DocumentKind kind) const {
  return store_ && store_->IsDirty(kind);
}

ECM AMConfigAppService::BackupIfNeeded() {
  if (!backup_use_case_) {
    return Err(EC::OperationUnsupported, "backup use-case is not bound");
  }
  return backup_use_case_->Execute(this);
}

void AMConfigAppService::SubmitWriteTask(std::function<ECM()> task) {
  if (!store_) {
    if (task) {
      (void)task();
    }
    return;
  }
  store_->SubmitWriteTask(std::move(task));
}

bool AMConfigAppService::GetJson(AMDomain::config::DocumentKind kind,
                                 Json *value) const {
  return ReadDocumentJson_(kind, value);
}

bool AMConfigAppService::GetJsonStr(AMDomain::config::DocumentKind kind,
                                    std::string *value, int indent) const {
  if (!value) {
    return false;
  }
  Json json = Json::object();
  if (!GetJson(kind, &json)) {
    return false;
  }
  *value = json.dump(indent);
  return true;
}

bool AMConfigAppService::GetDataPath(AMDomain::config::DocumentKind kind,
                                     std::filesystem::path *value) const {
  return store_ && value && store_->GetDataPath(kind, value);
}

std::filesystem::path AMConfigAppService::ProjectRoot() const {
  return store_ ? store_->ProjectRoot() : std::filesystem::path();
}

ECM AMConfigAppService::EnsureDirectory(const std::filesystem::path &dir) {
  if (!store_) {
    return Err(EC::ConfigNotInitialized, "config store is not bound");
  }
  return store_->EnsureDirectory(dir);
}

void AMConfigAppService::PruneBackupFiles(const std::filesystem::path &dir,
                                          const std::string &prefix,
                                          const std::string &suffix,
                                          int64_t max_count) {
  if (!store_) {
    return;
  }
  store_->PruneBackupFiles(dir, prefix, suffix, max_count);
}

bool AMConfigAppService::DelArg(AMDomain::config::DocumentKind kind,
                                const Path &path) {
  Json root = Json::object();
  if (!ReadDocumentJson_(kind, &root)) {
    return false;
  }
  if (!AMJson::DelKey(root, path)) {
    return false;
  }
  return WriteDocumentJson_(kind, root);
}

bool AMConfigAppService::ReadDocumentJson_(
    AMDomain::config::DocumentKind kind, Json *out) const {
  if (!out || !store_) {
    return false;
  }
  AMDomain::arg::TypeTag type = AMDomain::arg::TypeTag::Config;
  if (!AMDomain::config::AMConfigRules::TypeTagForDocumentKind(kind, &type)) {
    return false;
  }

  switch (type) {
  case AMDomain::arg::TypeTag::Config: {
    AMDomain::arg::ConfigArg arg{};
    if (!store_->Read(type, &arg)) {
      return false;
    }
    *out = arg.value;
    return true;
  }
  case AMDomain::arg::TypeTag::Settings: {
    AMDomain::arg::SettingsArg arg{};
    if (!store_->Read(type, &arg)) {
      return false;
    }
    *out = arg.value;
    return true;
  }
  case AMDomain::arg::TypeTag::KnownHosts: {
    AMDomain::arg::KnownHostsArg arg{};
    if (!store_->Read(type, &arg)) {
      return false;
    }
    *out = arg.value;
    return true;
  }
  case AMDomain::arg::TypeTag::History: {
    AMDomain::arg::HistoryArg arg{};
    if (!store_->Read(type, &arg)) {
      return false;
    }
    *out = arg.value;
    return true;
  }
  default:
    return false;
  }
}

bool AMConfigAppService::WriteDocumentJson_(
    AMDomain::config::DocumentKind kind, const Json &json) {
  if (!store_) {
    return false;
  }
  AMDomain::arg::TypeTag type = AMDomain::arg::TypeTag::Config;
  if (!AMDomain::config::AMConfigRules::TypeTagForDocumentKind(kind, &type)) {
    return false;
  }

  switch (type) {
  case AMDomain::arg::TypeTag::Config: {
    AMDomain::arg::ConfigArg arg{};
    arg.value = json;
    return store_->Write(type, &arg);
  }
  case AMDomain::arg::TypeTag::Settings: {
    AMDomain::arg::SettingsArg arg{};
    arg.value = json;
    return store_->Write(type, &arg);
  }
  case AMDomain::arg::TypeTag::KnownHosts: {
    AMDomain::arg::KnownHostsArg arg{};
    arg.value = json;
    return store_->Write(type, &arg);
  }
  case AMDomain::arg::TypeTag::History: {
    AMDomain::arg::HistoryArg arg{};
    arg.value = json;
    return store_->Write(type, &arg);
  }
  default:
    return false;
  }
}
} // namespace AMApplication::config
