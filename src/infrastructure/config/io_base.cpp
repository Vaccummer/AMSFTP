#include "foundation/tools/time.hpp"
#include "infrastructure/Config.hpp"
#include "infrastructure/config/SuperTomlHandle.hpp"

#include <algorithm>
#include <limits>
#include <optional>

namespace {
using Json = nlohmann::ordered_json;

/**
 * @brief Read a field as int64 when available.
 */
std::optional<int64_t> GetIntField(const Json &obj, const std::string &key) {
  if (!obj.is_object()) {
    return std::nullopt;
  }
  auto it = obj.find(key);
  if (it == obj.end()) {
    return std::nullopt;
  }
  if (it->is_number_integer()) {
    return it->get<int64_t>();
  }
  if (it->is_number_unsigned()) {
    const auto value = it->get<uint64_t>();
    if (value <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
      return static_cast<int64_t>(value);
    }
    return std::nullopt;
  }
  if (it->is_string()) {
    try {
      return std::stoll(it->get<std::string>());
    } catch (...) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

/**
 * @brief Read a boolean field from JSON when available.
 */
std::optional<bool> GetBoolField(const Json &obj, const std::string &key) {
  if (!obj.is_object()) {
    return std::nullopt;
  }
  auto it = obj.find(key);
  if (it == obj.end()) {
    return std::nullopt;
  }
  if (it->is_boolean()) {
    return it->get<bool>();
  }
  if (it->is_number_integer()) {
    return it->get<int64_t>() != 0;
  }
  if (it->is_number_unsigned()) {
    return it->get<uint64_t>() != 0;
  }
  if (it->is_string()) {
    const std::string token = AMStr::lowercase(it->get<std::string>());
    if (token == "true") {
      return true;
    }
    if (token == "false") {
      return false;
    }
  }
  return std::nullopt;
}

/**
 * @brief Return true if filename starts with prefix and ends with suffix.
 */
bool MatchBackupName_(const std::string &name, const std::string &prefix,
                      const std::string &suffix) {
  if (name.size() < prefix.size() + suffix.size()) {
    return false;
  }
  if (name.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }
  return name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/**
 * @brief Remove oldest backups to keep at most max_count files.
 */
void PruneBackupFiles_(const std::filesystem::path &dir,
                       const std::string &prefix, const std::string &suffix,
                       int64_t max_count) {
  if (max_count <= 0) {
    return;
  }
  std::error_code ec;
  if (!std::filesystem::exists(dir, ec) || ec) {
    return;
  }

  std::vector<std::filesystem::path> items;
  for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
    if (ec) {
      break;
    }
    if (!entry.is_regular_file(ec) || ec) {
      continue;
    }
    const std::string name = entry.path().filename().string();
    if (MatchBackupName_(name, prefix, suffix)) {
      items.push_back(entry.path());
    }
  }

  if (items.size() <= static_cast<size_t>(max_count)) {
    return;
  }

  std::sort(items.begin(), items.end(),
            [](const std::filesystem::path &a, const std::filesystem::path &b) {
              return a.filename().string() < b.filename().string();
            });

  const size_t remove_count = items.size() - static_cast<size_t>(max_count);
  for (size_t i = 0; i < remove_count; ++i) {
    std::filesystem::remove(items[i], ec);
  }
}
} // namespace

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

/**
 * @brief Initialize storage paths from a project root directory.
 */
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

/**
 * @brief Initialize storage with explicit document paths and schemas.
 */
ECM AMInfraConfigStorage::AMInit(
    const std::filesystem::path &root_dir,
    const std::unordered_map<DocumentKind, std::filesystem::path> &paths,
    const std::unordered_map<DocumentKind, std::filesystem::path> &schemas) {
  CloseHandles();
  root_dir_ = root_dir;
  docs_.clear();

  auto init_doc = [&](DocumentKind kind, const std::filesystem::path &fallback,
                      const std::filesystem::path &schema_fallback) {
    DocumentState &doc = docs_[kind];
    auto path_it = paths.find(kind);
    doc.path = (path_it == paths.end()) ? fallback : path_it->second;
    auto schema_it = schemas.find(kind);
    doc.schema_path =
        (schema_it == schemas.end()) ? schema_fallback : schema_it->second;
    doc.handle.reset();
  };

  init_doc(DocumentKind::Config, root_dir / "config" / "config.toml",
           root_dir / "config" / "schema" / "config.schema.json");
  init_doc(DocumentKind::Settings, root_dir / "config" / "settings.toml",
           root_dir / "config" / "schema" / "settings.schema.json");
  init_doc(DocumentKind::KnownHosts,
           root_dir / "config" / "internal" / "known_hosts.toml",
           root_dir / "config" / "schema" / "known_hosts.schema.json");
  init_doc(DocumentKind::History,
           root_dir / "config" / "internal" / "history.toml", {});

  backup_prune_checked_ = false;
  StartWriteThread();
  initialized_ = true;
  return Load();
}

/**
 * @brief Load a document from disk, or all documents when kind is nullopt.
 */
ECM AMInfraConfigStorage::Load(std::optional<DocumentKind> kind, bool force) {
  auto load_single = [&](DocumentKind target_kind) -> ECM {
    DocumentState *doc = GetDoc_(target_kind);
    if (!doc) {
      return Err(EC::ConfigNotInitialized, "document not initialized");
    }
    if (!force && doc->handle) {
      return Ok();
    }
    return LoadDocument_(target_kind, doc);
  };

  if (kind.has_value()) {
    return load_single(kind.value());
  }
  for (DocumentKind current : magic_enum::enum_values<DocumentKind>()) {
    ECM rcm = load_single(current);
    if (rcm.first != EC::Success) {
      return rcm;
    }
  }
  return Ok();
}

/**
 * @brief Load a document into memory using SuperTomlHandle.
 */
ECM AMInfraConfigStorage::LoadDocument_(DocumentKind kind, DocumentState *doc) {
  if (!doc) {
    return Err(EC::ConfigNotInitialized, "document not initialized");
  }
  if (!doc->handle) {
    doc->handle = std::make_shared<AMInfraSuperTomlHandle>();
  }

  std::string schema_json = "{}";
  if (kind == DocumentKind::History) {
    schema_json = kHistorySchemaJson;
  } else {
    schema_json = AMJson::ReadSchemaData(doc->schema_path, nullptr);
    if (schema_json.empty()) {
      schema_json = "{}";
    }
  }
  return doc->handle->Init(doc->path, schema_json);
}

/**
 * @brief Release cfgffi handles and reset pointers without dumping.
 */
void AMInfraConfigStorage::CloseHandles() {
  StopWriteThread();
  for (auto &entry : docs_) {
    DocumentState &doc = entry.second;
    if (doc.handle) {
      doc.handle->Close();
      doc.handle.reset();
    }
  }
  initialized_ = false;
}

/**
 * @brief Report whether a document has pending changes.
 */
bool AMInfraConfigStorage::IsDirty(DocumentKind kind) const {
  const DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    return false;
  }
  return doc->handle->IsDirty();
}

/**
 * @brief Persist all document snapshots to disk.
 */
ECM AMInfraConfigStorage::DumpAll(bool async) {
  if (async) {
    SubmitWriteTask([this]() -> ECM { return DumpAll(false); });
    return Ok();
  }

  ECM rcm = Dump(DocumentKind::Config);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  rcm = Dump(DocumentKind::Settings);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  rcm = Dump(DocumentKind::KnownHosts);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  DocumentState *history_doc = GetDoc_(DocumentKind::History);
  if (history_doc && history_doc->handle) {
    rcm = Dump(DocumentKind::History);
  }
  return rcm;
}

/**
 * @brief Persist a single document snapshot to disk.
 */
ECM AMInfraConfigStorage::Dump(DocumentKind kind, const std::string &path,
                               bool async) {
  if (async) {
    const std::string path_copy = path;
    SubmitWriteTask([this, kind, path_copy]() -> ECM {
      return Dump(kind, path_copy, false);
    });
    return Ok();
  }

  DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    ECM rcm = Err(EC::ConfigNotInitialized, "document not initialized");
    NotifyDumpError_(rcm);
    return rcm;
  }
  if (path.empty() && !doc->handle->IsDirty()) {
    return Ok();
  }

  ECM rcm = Ok();
  if (path.empty()) {
    rcm = doc->handle->DumpInplace();
  } else {
    rcm = doc->handle->DumpTo(path);
  }
  if (rcm.first != EC::Success) {
    NotifyDumpError_(rcm);
  }
  return rcm;
}

/**
 * @brief Trigger backup logic when needed.
 */
ECM AMInfraConfigStorage::BackupIfNeeded() {
  constexpr bool kDefaultEnabled = true;
  constexpr int64_t kDefaultLastBackupS = 0;
  constexpr int64_t kDefaultMaxBackupCount = 3;
  constexpr int64_t kMinIntervalS = 15;
  constexpr int64_t kNegativeIntervalFallbackS = 60;

  DocumentState *settings_doc = GetDoc_(DocumentKind::Settings);
  DocumentState *config_doc = GetDoc_(DocumentKind::Config);
  DocumentState *known_doc = GetDoc_(DocumentKind::KnownHosts);
  if (!settings_doc || !settings_doc->handle || !config_doc ||
      !config_doc->handle || !known_doc || !known_doc->handle) {
    return Err(EC::ConfigNotInitialized, "config documents not initialized");
  }

  Json settings_json = Json::object();
  if (!settings_doc->handle->GetJson(&settings_json)) {
    return Err(EC::ConfigLoadFailed, "failed to read settings document");
  }
  if (!settings_json.is_object()) {
    settings_json = Json::object();
  }

  bool changed = false;
  Json &options_cfg = settings_json["Options"];
  if (!options_cfg.is_object()) {
    options_cfg = Json::object();
    changed = true;
  }
  Json &backup_cfg = options_cfg["AutoConfigBackup"];
  if (!backup_cfg.is_object()) {
    backup_cfg = Json::object();
    changed = true;
  }

  bool enabled = kDefaultEnabled;
  if (auto v = GetBoolField(backup_cfg, "enabled")) {
    enabled = *v;
  } else {
    backup_cfg["enabled"] = kDefaultEnabled;
    changed = true;
  }

  int64_t interval_s = kNegativeIntervalFallbackS;
  if (auto v = GetIntField(backup_cfg, "interval_s")) {
    interval_s = *v;
  } else {
    changed = true;
  }
  if (interval_s <= 0) {
    interval_s = kNegativeIntervalFallbackS;
    changed = true;
  } else if (interval_s < kMinIntervalS) {
    interval_s = kMinIntervalS;
    changed = true;
  }
  backup_cfg["interval_s"] = interval_s;

  int64_t max_backup_count = kDefaultMaxBackupCount;
  if (auto v = GetIntField(backup_cfg, "max_backup_count")) {
    max_backup_count = *v;
  } else {
    changed = true;
  }
  if (max_backup_count < 1) {
    max_backup_count = 1;
    changed = true;
  }
  backup_cfg["max_backup_count"] = max_backup_count;

  const auto now_s = static_cast<int64_t>(AMTime::seconds());
  int64_t last_backup_time_s = kDefaultLastBackupS;
  if (auto v = GetIntField(backup_cfg, "last_backup_time_s")) {
    last_backup_time_s = *v;
  } else {
    changed = true;
  }
  if (last_backup_time_s < 0) {
    last_backup_time_s = 0;
    changed = true;
  }
  if (last_backup_time_s > now_s) {
    last_backup_time_s = now_s;
    changed = true;
  }
  backup_cfg["last_backup_time_s"] = last_backup_time_s;

  if (changed) {
    settings_doc->handle->Set(std::vector<std::string>{}, settings_json);
  }

  if (!backup_prune_checked_) {
    const std::filesystem::path backup_dir = root_dir_ / "config" / "bak";
    PruneBackupFiles_(backup_dir, "config-", ".toml.bak", max_backup_count);
    PruneBackupFiles_(backup_dir, "settings-", ".toml.bak", max_backup_count);
    PruneBackupFiles_(backup_dir, "known_hosts-", ".toml.bak",
                      max_backup_count);
    backup_prune_checked_ = true;
  }

  auto settings_handle_inplace = settings_doc->handle;
  auto dump_settings_inplace = [settings_handle_inplace]() -> ECM {
    if (!settings_handle_inplace) {
      return Err(EC::ConfigNotInitialized, "settings handle not initialized");
    }
    return settings_handle_inplace->DumpInplace();
  };

  if (!enabled) {
    if (changed) {
      SubmitWriteTask(dump_settings_inplace);
    }
    return Ok();
  }

  if (interval_s > 0 && (now_s - last_backup_time_s) < interval_s) {
    if (changed) {
      SubmitWriteTask(dump_settings_inplace);
    }
    return Ok();
  }

  backup_cfg["last_backup_time_s"] = now_s;
  settings_doc->handle->Set(std::vector<std::string>{}, settings_json);

  const std::filesystem::path backup_dir = root_dir_ / "config" / "bak";
  std::error_code ec;
  std::filesystem::create_directories(backup_dir, ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed,
               "failed to create backup dir: " + ec.message());
  }

  const std::string stamp =
      FormatTime(static_cast<size_t>(now_s), "%Y-%m-%d-%H-%M");
  const std::filesystem::path config_backup =
      backup_dir / ("config-" + stamp + ".toml.bak");
  const std::filesystem::path settings_backup =
      backup_dir / ("settings-" + stamp + ".toml.bak");
  const std::filesystem::path known_hosts_backup =
      backup_dir / ("known_hosts-" + stamp + ".toml.bak");

  auto config_handle = config_doc->handle;
  auto backup_settings_handle = settings_doc->handle;
  auto known_handle = known_doc->handle;
  SubmitWriteTask([config_handle, backup_settings_handle, known_handle,
                   config_backup,
                   settings_backup, known_hosts_backup]() -> ECM {
    if (!config_handle || !backup_settings_handle || !known_handle) {
      return Err(EC::ConfigNotInitialized, "config handles not initialized");
    }
    ECM rcm = config_handle->DumpTo(config_backup);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    rcm = backup_settings_handle->DumpTo(settings_backup);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    return known_handle->DumpTo(known_hosts_backup);
  });

  SubmitWriteTask(dump_settings_inplace);
  return Ok();
}

/**
 * @brief Start the background writer thread if not running.
 */
void AMInfraConfigStorage::StartWriteThread() {
  std::lock_guard<std::mutex> lock(write_mtx_);
  write_dispatcher_.Start();
}

/**
 * @brief Stop the background writer thread and drain pending tasks.
 */
void AMInfraConfigStorage::StopWriteThread() {
  std::lock_guard<std::mutex> lock(write_mtx_);
  write_dispatcher_.Stop();
}

/**
 * @brief Submit a write task to the background queue.
 */
void AMInfraConfigStorage::SubmitWriteTask(std::function<ECM()> task) {
  if (!task) {
    return;
  }
  if (!write_dispatcher_.IsRunning()) {
    ECM rcm = task();
    if (rcm.first != EC::Success) {
      NotifyDumpError_(rcm);
    }
    return;
  }
  write_dispatcher_.Submit([this, task = std::move(task)]() mutable {
    ECM rcm = task();
    if (rcm.first != EC::Success) {
      NotifyDumpError_(rcm);
    }
  });
}

/**
 * @brief Register a callback invoked on dump errors.
 */
void AMInfraConfigStorage::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
}

/**
 * @brief Return a thread-safe copy of a document JSON.
 */
bool AMInfraConfigStorage::GetJson(DocumentKind kind,
                                   nlohmann::ordered_json *value) const {
  if (!value) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    return false;
  }
  return doc->handle->GetJson(value);
}

/**
 * @brief Return a thread-safe serialized JSON string of a document.
 */
bool AMInfraConfigStorage::GetJsonStr(DocumentKind kind, std::string *value,
                                      int indent) const {
  if (!value) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    return false;
  }
  nlohmann::ordered_json json = nlohmann::ordered_json::object();
  if (!doc->handle->GetJson(&json)) {
    return false;
  }
  *value = json.dump(indent);
  return true;
}

/**
 * @brief Return the config data path tracked for a document.
 */
bool AMInfraConfigStorage::GetDataPath(DocumentKind kind,
                                       std::filesystem::path *value) const {
  if (!value) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return false;
  }
  *value = doc->path;
  return true;
}

/**
 * @brief Locate a document state by kind.
 */
DocumentState *AMInfraConfigStorage::GetDoc_(DocumentKind kind) {
  auto it = docs_.find(kind);
  if (it == docs_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Notify any registered dump-error callback.
 */
void AMInfraConfigStorage::NotifyDumpError_(const ECM &err) const {
  if (dump_error_cb_) {
    dump_error_cb_(err);
  }
}

/**
 * @brief Locate a document state by kind (const).
 */
const DocumentState *AMInfraConfigStorage::GetDoc_(DocumentKind kind) const {
  auto it = docs_.find(kind);
  if (it == docs_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Return the project root directory path.
 */
std::filesystem::path AMInfraConfigStorage::ProjectRoot() const {
  return root_dir_;
}

/**
 * @brief Backup config/settings/known_hosts when the interval elapses.
 */
ECM AMInfraConfigStorage::ConfigBackupIfNeeded() { return BackupIfNeeded(); }
