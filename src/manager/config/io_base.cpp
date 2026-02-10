#include "AMBase/CommonTools.hpp"
#include "internal_func.hpp"

using namespace AMConfigInternal;
/** @brief JSON schema used to validate .AMSFTP_History.toml. */
inline constexpr const char kHistorySchemaJson[] = R"json(
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
 * @brief Construct a storage layer with empty state.
 */
AMConfigStorage::AMConfigStorage() = default;

/**
 * @brief Stop the background writer thread on destruction.
 */
AMConfigStorage::~AMConfigStorage() { CloseHandles(); }

/**
 * @brief Initialize storage paths from a project root directory.
 */
ECM AMConfigStorage::Init(const std::filesystem::path &root_dir) {
  std::unordered_map<DocumentKind, std::filesystem::path> paths;
  std::unordered_map<DocumentKind, std::filesystem::path> schemas;

  paths[DocumentKind::Config] = root_dir / "config" / "config.toml";
  paths[DocumentKind::Settings] = root_dir / "config" / "settings.toml";
  paths[DocumentKind::KnownHosts] = root_dir / "config" / "known_hosts.toml";
  paths[DocumentKind::History] = root_dir / ".AMSFTP_History.toml";

  schemas[DocumentKind::Config] = root_dir / "config" / "config.schema.json";
  schemas[DocumentKind::Settings] =
      root_dir / "config" / "settings.schema.json";
  schemas[DocumentKind::KnownHosts] =
      root_dir / "config" / "known_hosts.schema.json";

  return Init(root_dir, paths, schemas);
}

/**
 * @brief Initialize storage with explicit document paths and schemas.
 */
ECM AMConfigStorage::Init(
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
    doc.handle = nullptr;
    doc.json = nlohmann::ordered_json::object();
    doc.dirty = false;
    doc.last_modified = std::chrono::system_clock::time_point{};
  };

  init_doc(DocumentKind::Config, root_dir / "config" / "config.toml",
           root_dir / "config" / "config.schema.json");
  init_doc(DocumentKind::Settings, root_dir / "config" / "settings.toml",
           root_dir / "config" / "settings.schema.json");
  init_doc(DocumentKind::KnownHosts, root_dir / "config" / "known_hosts.toml",
           root_dir / "config" / "known_hosts.schema.json");
  init_doc(DocumentKind::History, root_dir / ".AMSFTP_History.toml", {});

  backup_prune_checked_ = false;
  shutdown_requested_.store(false, std::memory_order_relaxed);
  StartWriteThread();
  return Ok();
}

/**
 * @brief Bind cfgffi handles used for persisting config documents.
 */
ECM AMConfigStorage::BindHandles(ConfigHandle *config_handle,
                                 ConfigHandle *settings_handle,
                                 ConfigHandle *known_hosts_handle,
                                 ConfigHandle *history_handle) {
  DocumentState *config_doc = GetDoc_(DocumentKind::Config);
  DocumentState *settings_doc = GetDoc_(DocumentKind::Settings);
  DocumentState *known_doc = GetDoc_(DocumentKind::KnownHosts);
  DocumentState *history_doc = GetDoc_(DocumentKind::History);
  if (!config_doc || !settings_doc || !known_doc || !history_doc) {
    return Err(EC::ConfigNotInitialized, "config documents not initialized");
  }
  config_doc->handle = config_handle;
  settings_doc->handle = settings_handle;
  known_doc->handle = known_hosts_handle;
  history_doc->handle = history_handle;
  return Ok();
}

/**
 * @brief Load config, settings, and known_hosts documents from disk.
 */
ECM AMConfigStorage::LoadAll() {
  ECM rcm = Load(DocumentKind::Config);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  rcm = Load(DocumentKind::Settings);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  rcm = Load(DocumentKind::KnownHosts);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return Ok();
}

/**
 * @brief Load a document from disk by kind.
 */
ECM AMConfigStorage::Load(DocumentKind kind) {
  DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return Err(EC::ConfigNotInitialized, "document not initialized");
  }
  if (kind == DocumentKind::History && doc->handle) {
    return Ok();
  }
  return LoadDocument_(kind, doc);
}

/**
 * @brief Close storage with a final dump and shutdown.
 */
ECM AMConfigStorage::Close() {
  ECM rcm = DumpAll();
  CloseHandles();
  return rcm;
}

/**
 * @brief Release cfgffi handles and reset pointers without dumping.
 */
void AMConfigStorage::CloseHandles() {
  StopWriteThread();
  std::lock_guard<std::mutex> lock(handle_mtx_);
  for (auto &entry : docs_) {
    DocumentState &doc = entry.second;
    if (doc.handle) {
      cfgffi_free_handle(doc.handle);
      doc.handle = nullptr;
    }
  }
}

/**
 * @brief Snapshot a document in a thread-safe manner.
 */
nlohmann::ordered_json AMConfigStorage::Snapshot(DocumentKind kind) const {
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return nlohmann::ordered_json::object();
  }
  std::lock_guard<std::mutex> lock(doc->mtx);
  return doc->json;
}

/**
 * @brief Report whether a document has pending changes.
 */
bool AMConfigStorage::IsDirty(DocumentKind kind) const {
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return false;
  }
  std::lock_guard<std::mutex> lock(doc->mtx);
  return doc->dirty;
}

/**
 * @brief Mutate a document and optionally persist immediately.
 */
ECM AMConfigStorage::Mutate(
    DocumentKind kind, std::function<void(nlohmann::ordered_json &)> mutator,
    bool dump_now) {
  DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return Err(EC::ConfigNotInitialized, "document not initialized");
  }
  if (!mutator) {
    return Err(EC::InvalidArg, "null mutator");
  }
  {
    std::lock_guard<std::mutex> lock(doc->mtx);
    mutator(doc->json);
    doc->dirty = true;
  }
  if (dump_now) {
    return Dump(kind);
  }
  return Ok();
}

/**
 * @brief Persist all document snapshots to disk.
 */
ECM AMConfigStorage::DumpAll() {
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
ECM AMConfigStorage::Dump(DocumentKind kind, const std::string &path) {
  DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return Err(EC::ConfigNotInitialized, "document not initialized");
  }
  if (path.empty()) {
    std::lock_guard<std::mutex> lock(doc->mtx);
    if (!doc->dirty) {
      return Ok();
    }
  }
  std::filesystem::path out_path = path.empty() ? doc->path : path;
  std::error_code ec;
  if (!out_path.empty()) {
    std::filesystem::create_directories(out_path.parent_path(), ec);
    if (ec) {
      return Err(
          EC::ConfigDumpFailed,
          AMStr::amfmt("failed to create config directory: {}", ec.message()));
    }
  }
  if (path.empty()) {
    return WriteHandleJson_(doc, kind);
  }

  std::string json_payload;
  {
    std::lock_guard<std::mutex> lock(doc->mtx);
    json_payload = doc->json.dump(2);
  }
  WriteSnapshotToPath_(doc->handle, json_payload, out_path);
  return Ok();
}

/**
 * @brief Trigger backup logic when needed.
 */
ECM AMConfigStorage::BackupIfNeeded() {
  constexpr bool kDefaultEnabled = true;
  constexpr int64_t kDefaultLastBackupS = 0;
  constexpr int64_t kDefaultMaxBackupCount = 3;
  constexpr int64_t kMinIntervalS = 15;
  constexpr int64_t kNegativeIntervalFallbackS = 60;

  DocumentState *settings_doc = GetDoc_(DocumentKind::Settings);
  DocumentState *config_doc = GetDoc_(DocumentKind::Config);
  DocumentState *known_doc = GetDoc_(DocumentKind::KnownHosts);
  if (!settings_doc || !config_doc || !known_doc) {
    return Err(EC::ConfigNotInitialized, "config documents not initialized");
  }

  bool changed = false;
  {
    std::lock_guard<std::mutex> lock(settings_doc->mtx);
    if (!settings_doc->json.is_object()) {
      settings_doc->json = Json::object();
      changed = true;
    }

    Json &backup_cfg = settings_doc->json["AutoConfigBackup"];
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
    if (interval_s == 0) {
      interval_s = kNegativeIntervalFallbackS;
      changed = true;
    } else if (interval_s < 0) {
      interval_s = kNegativeIntervalFallbackS;
      changed = true;
    } else if (interval_s > 0 && interval_s < kMinIntervalS) {
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

    const int64_t now_s = static_cast<int64_t>(timenow());
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

    settings_doc->dirty = settings_doc->dirty || changed;
  }

  if (!backup_prune_checked_) {
    std::filesystem::path backup_dir = root_dir_ / "config" / "bak";
    int64_t max_backup_count = kDefaultMaxBackupCount;
    {
      std::lock_guard<std::mutex> lock(settings_doc->mtx);
      const Json &backup_cfg = settings_doc->json["AutoConfigBackup"];
      if (auto v = GetIntField(backup_cfg, "max_backup_count")) {
        max_backup_count = *v;
      }
    }
    PruneBackupFiles_(backup_dir, "config-", ".toml.bak", max_backup_count);
    PruneBackupFiles_(backup_dir, "settings-", ".toml.bak", max_backup_count);
    PruneBackupFiles_(backup_dir, "known_hosts-", ".toml.bak",
                      max_backup_count);
    backup_prune_checked_ = true;
  }

  bool enabled = kDefaultEnabled;
  int64_t interval_s = kNegativeIntervalFallbackS;
  int64_t last_backup_time_s = kDefaultLastBackupS;
  auto now_s = static_cast<int64_t>(timenow());
  {
    std::lock_guard<std::mutex> lock(settings_doc->mtx);
    const Json &backup_cfg = settings_doc->json["AutoConfigBackup"];
    if (auto v = GetBoolField(backup_cfg, "enabled")) {
      enabled = *v;
    }
    if (auto v = GetIntField(backup_cfg, "interval_s")) {
      interval_s = *v;
    }
    if (auto v = GetIntField(backup_cfg, "last_backup_time_s")) {
      last_backup_time_s = *v;
    }
  }

  if (!enabled) {
    if (changed) {
      std::string settings_json;
      {
        std::lock_guard<std::mutex> lock(settings_doc->mtx);
        settings_json = settings_doc->json.dump(2);
      }
      SubmitWriteTask([this, settings_json]() -> ECM {
        std::lock_guard<std::mutex> lock(handle_mtx_);
        DocumentState *doc = GetDoc_(DocumentKind::Settings);
        if (!doc || !doc->handle) {
          return Err(EC::ConfigNotInitialized,
                     "settings handle not initialized");
        }
        WriteSnapshotToPath_(doc->handle, settings_json, doc->path);
        return Ok();
      });
    }
    return Ok();
  }

  if (interval_s > 0 && (now_s - last_backup_time_s) < interval_s) {
    if (changed) {
      std::string settings_json;
      {
        std::lock_guard<std::mutex> lock(settings_doc->mtx);
        settings_json = settings_doc->json.dump(2);
      }
      SubmitWriteTask([this, settings_json]() -> ECM {
        std::lock_guard<std::mutex> lock(handle_mtx_);
        DocumentState *doc = GetDoc_(DocumentKind::Settings);
        if (!doc || !doc->handle) {
          return Err(EC::ConfigNotInitialized,
                     "settings handle not initialized");
        }
        WriteSnapshotToPath_(doc->handle, settings_json, doc->path);
        return Ok();
      });
    }
    return Ok();
  }

  if (!config_doc->handle || !settings_doc->handle || !known_doc->handle) {
    return Err(EC::ConfigNotInitialized, "config handles not initialized");
  }

  {
    std::lock_guard<std::mutex> lock(settings_doc->mtx);
    settings_doc->json["AutoConfigBackup"]["last_backup_time_s"] = now_s;
    settings_doc->dirty = true;
  }

  std::filesystem::path backup_dir = root_dir_ / "config" / "bak";
  std::error_code ec;
  std::filesystem::create_directories(backup_dir, ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed,
               "failed to create backup dir: " + ec.message());
  }

  const std::string stamp =
      FormatTime(static_cast<size_t>(now_s), "%Y-%m-%d-%H-%M");
  std::filesystem::path config_backup =
      backup_dir / ("config-" + stamp + ".toml.bak");
  std::filesystem::path settings_backup =
      backup_dir / ("settings-" + stamp + ".toml.bak");
  std::filesystem::path known_hosts_backup =
      backup_dir / ("known_hosts-" + stamp + ".toml.bak");

  std::string config_json;
  std::string settings_json;
  std::string known_hosts_json;
  {
    std::lock_guard<std::mutex> lock(config_doc->mtx);
    config_json = config_doc->json.dump(2);
  }
  {
    std::lock_guard<std::mutex> lock(settings_doc->mtx);
    settings_json = settings_doc->json.dump(2);
  }
  {
    std::lock_guard<std::mutex> lock(known_doc->mtx);
    known_hosts_json = known_doc->json.dump(2);
  }

  SubmitWriteTask([this, config_backup, settings_backup, known_hosts_backup,
                   config_json, settings_json, known_hosts_json]() -> ECM {
    std::lock_guard<std::mutex> lock(handle_mtx_);
    DocumentState *config_doc = GetDoc_(DocumentKind::Config);
    DocumentState *settings_doc = GetDoc_(DocumentKind::Settings);
    DocumentState *known_doc = GetDoc_(DocumentKind::KnownHosts);
    if (!config_doc || !settings_doc || !known_doc) {
      return Err(EC::ConfigNotInitialized, "config documents not initialized");
    }
    WriteSnapshotToPath_(config_doc->handle, config_json, config_backup);
    WriteSnapshotToPath_(settings_doc->handle, settings_json, settings_backup);
    WriteSnapshotToPath_(known_doc->handle, known_hosts_json,
                         known_hosts_backup);
    return Ok();
  });

  if (changed) {
    SubmitWriteTask([this, settings_json]() -> ECM {
      std::lock_guard<std::mutex> lock(handle_mtx_);
      DocumentState *doc = GetDoc_(DocumentKind::Settings);
      if (!doc || !doc->handle) {
        return Err(EC::ConfigNotInitialized, "settings handle not initialized");
      }
      WriteSnapshotToPath_(doc->handle, settings_json, doc->path);
      return Ok();
    });
  }

  return Ok();
}

/**
 * @brief Start the background writer thread if not running.
 */
void AMConfigStorage::StartWriteThread() {
  std::lock_guard<std::mutex> lock(write_mtx_);
  if (write_running_.load(std::memory_order_relaxed)) {
    return;
  }
  shutdown_requested_.store(false, std::memory_order_relaxed);
  write_running_.store(true, std::memory_order_relaxed);
  write_thread_ = std::thread([this]() { WriteThreadLoop_(); });
}

/**
 * @brief Stop the background writer thread and drain pending tasks.
 */
void AMConfigStorage::StopWriteThread() {
  shutdown_requested_.store(true, std::memory_order_relaxed);
  write_running_.store(false, std::memory_order_relaxed);
  write_cv_.notify_all();
  if (write_thread_.joinable()) {
    write_thread_.join();
  }
}

/**
 * @brief Submit a write task to the background queue.
 */
void AMConfigStorage::SubmitWriteTask(std::function<ECM()> task) {
  if (!task) {
    return;
  }
  if (!write_running_.load(std::memory_order_relaxed)) {
    (void)task();
    return;
  }
  {
    std::lock_guard<std::mutex> lock(write_mtx_);
    write_queue_.push(std::move(task));
  }
  write_cv_.notify_one();
}

/**
 * @brief Submit a no-arg write task to the background queue.
 */
void AMConfigStorage::SubmitWriteTaskVoid(std::function<void()> task) {
  SubmitWriteTask([task]() -> ECM {
    task();
    return Ok();
  });
}

/**
 * @brief Provide mutable access to a document JSON.
 */
std::optional<std::reference_wrapper<nlohmann::ordered_json>>
AMConfigStorage::GetJson(DocumentKind kind) {
  DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return std::nullopt;
  }
  return std::ref(doc->json);
}

/**
 * @brief Provide read-only access to a document JSON.
 */
std::optional<std::reference_wrapper<const nlohmann::ordered_json>>
AMConfigStorage::GetJson(DocumentKind kind) const {
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return std::nullopt;
  }
  return std::cref(doc->json);
}

/**
 * @brief Return the root directory used by the storage layer.
 */
const std::filesystem::path &AMConfigStorage::RootDir() const {
  return root_dir_;
}

/**
 * @brief Return the config and schema paths tracked by the storage layer.
 */
std::pair<std::optional<std::filesystem::path>,
          std::optional<std::filesystem::path>>
AMConfigStorage::GetDataPath(DocumentKind kind) const {
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return {std::nullopt, std::nullopt};
  }
  return {doc->path, doc->schema_path};
}

/**
 * @brief Query a JSON value by path from a root object.
 */
bool AMConfigStorage::QueryKey(const nlohmann::ordered_json &root,
                               const Path &path, Value *value) const {
  if (!value) {
    return false;
  }
  const nlohmann::ordered_json *node = &root;
  for (const auto &seg : path) {
    if (!node->is_object()) {
      return false;
    }
    auto it = node->find(seg);
    if (it == node->end()) {
      return false;
    }
    node = &(*it);
  }
  if (node->is_boolean()) {
    *value = node->get<bool>();
    return true;
  }
  if (node->is_number_integer()) {
    *value = node->get<int64_t>();
    return true;
  }
  if (node->is_number_unsigned()) {
    *value = static_cast<int64_t>(node->get<size_t>());
    return true;
  }
  if (node->is_string()) {
    *value = node->get<std::string>();
    return true;
  }
  if (node->is_array()) {
    std::vector<std::string> values;
    values.reserve(node->size());
    for (const auto &child : *node) {
      if (child.is_string()) {
        values.push_back(child.get<std::string>());
        continue;
      }
      if (child.is_boolean()) {
        values.push_back(child.get<bool>() ? "true" : "false");
        continue;
      }
      if (child.is_number_integer()) {
        values.push_back(std::to_string(child.get<int64_t>()));
        continue;
      }
      if (child.is_number_unsigned()) {
        values.push_back(std::to_string(child.get<size_t>()));
        continue;
      }
      if (child.is_number_float()) {
        values.push_back(std::to_string(child.get<double>()));
        continue;
      }
      if (child.is_null()) {
        values.emplace_back("null");
        continue;
      }
      return false;
    }
    *value = std::move(values);
    return true;
  }
  return false;
}

/**
 * @brief Locate a document state by kind.
 */
DocumentState *AMConfigStorage::GetDoc_(DocumentKind kind) {
  auto it = docs_.find(kind);
  if (it == docs_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Locate a document state by kind (const).
 */
const DocumentState *AMConfigStorage::GetDoc_(DocumentKind kind) const {
  auto it = docs_.find(kind);
  if (it == docs_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Load a document into memory using cfgffi.
 */
ECM AMConfigStorage::LoadDocument_(DocumentKind kind, DocumentState *doc) {
  if (!doc) {
    return Err(EC::ConfigNotInitialized, "document not initialized");
  }
  std::string error;
  if (!EnsureFileExists(doc->path, &error)) {
    return Err(EC::ConfigLoadFailed,
               "failed to create " + AM_ENUM_NAME(kind) + " file: " + error);
  }
  std::string schema_json;
  if (kind == DocumentKind::History) {
    schema_json = kHistorySchemaJson;
  } else {
    schema_json = LoadSchemaJson(doc->schema_path, &error);
  }
  char *err = nullptr;
  {
    std::lock_guard<std::mutex> lock(handle_mtx_);
    if (doc->handle) {
      cfgffi_free_handle(doc->handle);
      doc->handle = nullptr;
    }
    doc->handle =
        cfgffi_read(doc->path.string().c_str(), schema_json.c_str(), &err);
  }
  if (!doc->handle) {
    std::string msg = err ? err : "cfgffi_read failed";
    if (err) {
      cfgffi_free_string(err);
    }
    return Err(EC::ConfigLoadFailed,
               "failed to parse " + AM_ENUM_NAME(kind) + ": " + msg);
  }
  if (err) {
    cfgffi_free_string(err);
  }
  char *json_c = cfgffi_get_json(doc->handle);
  if (!json_c) {
    return Err(EC::ConfigLoadFailed,
               "failed to read " + AM_ENUM_NAME(kind) + " json");
  }
  std::string json_str(json_c);
  cfgffi_free_string(json_c);
  Json parsed;
  if (!ParseJsonString(json_str, &parsed, &error)) {
    return Err(EC::ConfigLoadFailed,
               "failed to parse " + AM_ENUM_NAME(kind) + " json: " + error);
  }
  {
    std::lock_guard<std::mutex> lock(doc->mtx);
    doc->json = std::move(parsed);
    doc->dirty = false;
    doc->last_modified = std::chrono::system_clock::now();
  }
  return Ok();
}

/**
 * @brief Write JSON content into a cfgffi handle and refresh the cache.
 */
ECM AMConfigStorage::WriteHandleJson_(DocumentState *doc, DocumentKind kind) {
  const std::string label = std::string(AM_ENUM_NAME(kind));
  if (!doc || !doc->handle) {
    return Err(EC::ConfigNotInitialized,
               AMStr::amfmt("{} handle not initialized", label));
  }
  nlohmann::ordered_json snapshot;
  {
    std::lock_guard<std::mutex> lock(doc->mtx);
    snapshot = doc->json;
  }
  std::string payload = snapshot.dump(2);
  char *err = nullptr;
  {
    std::lock_guard<std::mutex> lock(handle_mtx_);
    int rc = cfgffi_write_inplace(doc->handle, payload.c_str(), &err);
    if (rc != 0) {
      std::string msg = err ? err : "cfgffi_write error";
      if (err) {
        cfgffi_free_string(err);
      }
      return Err(EC::ConfigDumpFailed, AMStr::amfmt("Failed to dump to {}: {}",
                                                    doc->path.string(), msg));
    }
    if (err) {
      cfgffi_free_string(err);
    }
    char *json_c = cfgffi_get_json(doc->handle);
    if (json_c) {
      std::string json_str(json_c);
      cfgffi_free_string(json_c);
      Json parsed;
      if (ParseJsonString(json_str, &parsed, nullptr)) {
        std::lock_guard<std::mutex> doc_lock(doc->mtx);
        doc->json = std::move(parsed);
      }
    }
  }
  {
    std::lock_guard<std::mutex> lock(doc->mtx);
    doc->dirty = false;
    doc->last_modified = std::chrono::system_clock::now();
  }
  return Ok();
}

/**
 * @brief Write a TOML snapshot to a target path using the given handle.
 */
void AMConfigStorage::WriteSnapshotToPath_(
    ConfigHandle *handle, const std::string &json,
    const std::filesystem::path &out_path) const {
  if (!handle) {
    return;
  }
  char *err = nullptr;
  int rc = cfgffi_write(handle, out_path.string().c_str(), json.c_str(), &err);
  if (err) {
    cfgffi_free_string(err);
  }
  (void)rc;
}

/**
 * @brief Worker loop that processes queued write tasks.
 */
void AMConfigStorage::WriteThreadLoop_() {
  for (;;) {
    std::function<ECM()> task;
    {
      std::unique_lock<std::mutex> lock(write_mtx_);
      write_cv_.wait(lock, [&]() {
        return shutdown_requested_.load(std::memory_order_relaxed) ||
               !write_queue_.empty();
      });
      if (shutdown_requested_.load(std::memory_order_relaxed) &&
          write_queue_.empty()) {
        break;
      }
      task = std::move(write_queue_.front());
      write_queue_.pop();
    }
    if (task) {
      try {
        (void)task();
      } catch (...) {
      }
    }
  }
}
