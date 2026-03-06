#include "infrastructure/Config.hpp"

namespace {
/** @brief JSON schema used to validate config/internal/history.toml. */
inline constexpr char kHistorySchemaJson[250] = R"json(
{
  "type": "object",
  "additionalProperties": {
    "type": "object",
    "properties": {
      "commands": {
        "type": "array",
        "items": {
          "type": "string"
        }
      }
    },
    "additionalProperties": false
  }
}
)json";
} // namespace

ECM AMInfraConfigStorage::AMInit(const std::filesystem::path &root_dir) {
  std::unordered_map<DocumentKind, std::filesystem::path> paths;
  std::unordered_map<DocumentKind, std::filesystem::path> schemas;

  paths[DocumentKind::Config] = root_dir / "config" / "config.toml";
  paths[DocumentKind::Settings] = root_dir / "config" / "settings.toml";
  paths[DocumentKind::KnownHosts] =
      root_dir / "config" / "internal" / "known_hosts.toml";
  paths[DocumentKind::History] =
      root_dir / "config" / "internal" / "history.toml";

  schemas[DocumentKind::Config] =
      root_dir / "config" / "schema" / "config.schema.json";
  schemas[DocumentKind::Settings] =
      root_dir / "config" / "schema" / "settings.schema.json";
  schemas[DocumentKind::KnownHosts] =
      root_dir / "config" / "schema" / "known_hosts.schema.json";

  return AMInit(root_dir, paths, schemas);
}

ECM AMInfraConfigStorage::AMInit(
    const std::filesystem::path &root_dir,
    const std::unordered_map<DocumentKind, std::filesystem::path> &paths,
    const std::unordered_map<DocumentKind, std::filesystem::path> &schemas) {
  CloseHandles();
  root_dir_ = root_dir;

  std::unordered_map<DocumentKind, AMDomain::config::AMConfigManager::DocumentInitSpec>
      specs;
  auto fill_spec = [&](DocumentKind kind, const std::filesystem::path &fallback,
                       const std::filesystem::path &schema_fallback) {
    AMDomain::config::AMConfigManager::DocumentInitSpec spec{};
    auto path_it = paths.find(kind);
    spec.json_path = (path_it == paths.end()) ? fallback : path_it->second;
    auto schema_it = schemas.find(kind);
    spec.schema_path =
        (schema_it == schemas.end()) ? schema_fallback : schema_it->second;
    if (kind == DocumentKind::History) {
      spec.schema_data = kHistorySchemaJson;
    } else {
      spec.schema_data = AMJson::ReadSchemaData(spec.schema_path, nullptr);
      if (spec.schema_data.empty()) {
        spec.schema_data = "{}";
      }
    }
    specs[kind] = std::move(spec);
  };

  fill_spec(DocumentKind::Config, root_dir / "config" / "config.toml",
            root_dir / "config" / "schema" / "config.schema.json");
  fill_spec(DocumentKind::Settings, root_dir / "config" / "settings.toml",
            root_dir / "config" / "schema" / "settings.schema.json");
  fill_spec(DocumentKind::KnownHosts,
            root_dir / "config" / "internal" / "known_hosts.toml",
            root_dir / "config" / "schema" / "known_hosts.schema.json");
  fill_spec(DocumentKind::History,
            root_dir / "config" / "internal" / "history.toml", {});

  config_manager_.SetDumpErrorCallback([this](const ECM &err) {
    NotifyDumpError_(err);
  });
  ECM rcm = config_manager_.Init(specs, &write_dispatcher_);
  initialized_ = isok(rcm);
  return rcm;
}

ECM AMInfraConfigStorage::Load(std::optional<DocumentKind> kind, bool force) {
  return config_manager_.Load(kind, force);
}

void AMInfraConfigStorage::CloseHandles() {
  config_manager_.CloseHandles();
  initialized_ = false;
}

bool AMInfraConfigStorage::IsDirty(DocumentKind kind) const {
  return config_manager_.IsDirty(kind);
}

ECM AMInfraConfigStorage::DumpAll(bool async) {
  return config_manager_.DumpAll(async);
}

ECM AMInfraConfigStorage::Dump(DocumentKind kind, const std::string &path,
                               bool async) {
  return config_manager_.Dump(kind, path, async);
}

ECM AMInfraConfigStorage::BackupIfNeeded() {
  return config_manager_.BackupIfNeeded(root_dir_);
}

void AMInfraConfigStorage::StartWriteThread() {
  std::lock_guard<std::mutex> lock(write_mtx_);
  config_manager_.StartWriteThread();
}

void AMInfraConfigStorage::StopWriteThread() {
  std::lock_guard<std::mutex> lock(write_mtx_);
  config_manager_.StopWriteThread();
}

void AMInfraConfigStorage::SubmitWriteTask(std::function<ECM()> task) {
  config_manager_.SubmitWriteTask(std::move(task));
}

void AMInfraConfigStorage::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
}

bool AMInfraConfigStorage::GetJson(DocumentKind kind, Json *value) const {
  return config_manager_.GetJson(kind, value);
}

bool AMInfraConfigStorage::GetJsonStr(DocumentKind kind, std::string *value,
                                      int indent) const {
  if (!value) {
    return false;
  }
  Json json = Json::object();
  if (!config_manager_.GetJson(kind, &json)) {
    return false;
  }
  *value = json.dump(indent);
  return true;
}

bool AMInfraConfigStorage::GetDataPath(DocumentKind kind,
                                       std::filesystem::path *value) const {
  return config_manager_.GetDataPath(kind, value);
}

/**
 * @brief Create or return one sync port for one `(kind, path)` key.
 */
AMInfraConfigStorage::SyncPort
AMInfraConfigStorage::CreateOrGetSyncPort(DocumentKind kind, const Path &path,
                                          const Json &fallback) {
  return config_manager_.CreateOrGetSyncPort(kind, path, fallback);
}

/**
 * @brief Return one sync port by `(kind, path)` key when registered.
 */
AMInfraConfigStorage::SyncPort
AMInfraConfigStorage::GetSyncPort(DocumentKind kind, const Path &path) const {
  return config_manager_.GetSyncPort(kind, path);
}

std::filesystem::path AMInfraConfigStorage::ProjectRoot() const {
  return root_dir_;
}

ECM AMInfraConfigStorage::ConfigBackupIfNeeded() { return BackupIfNeeded(); }

void AMInfraConfigStorage::NotifyDumpError_(const ECM &err) const {
  if (dump_error_cb_) {
    dump_error_cb_(err);
  }
}
