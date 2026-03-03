#include "AMBase/Path.hpp"
#include "AMBase/tools/json.hpp"
#include "AMBase/tools/time.hpp"
#include "AMManager/Config.hpp"
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>

namespace {
using Json = nlohmann::ordered_json;

/**
 * @brief Read a text file into a string buffer.
 */
bool ReadTextFile(const std::filesystem::path &path, std::string *out,
                  std::string *error) {
  if (!out) {
    if (error)
      *error = "null output buffer";
    return false;
  }
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in.is_open()) {
    if (error)
      *error = "failed to open file";
    return false;
  }
  std::ostringstream oss;
  oss << in.rdbuf();
  if (!in.good() && !in.eof()) {
    if (error)
      *error = "failed to read file";
    return false;
  }
  *out = oss.str();
  return true;
}

/**
 * @brief Load a JSON schema file or return an empty schema string.
 */
std::string LoadSchemaJson(const std::filesystem::path &schema_path,
                           std::string *error) {
  if (schema_path.empty())
    return "{}";
  std::string json;
  std::string read_error;
  if (!ReadTextFile(schema_path, &json, &read_error)) {
    if (error)
      *error = "failed to read schema: " + read_error;
    return "{}";
  }
  if (json.empty())
    return "{}";
  return json;
}

/**
 * @brief Ensure a file exists by creating its parent directory and file.
 */
bool EnsureFileExists(const std::filesystem::path &path, std::string *error) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error)
      *error = ec.message();
    return false;
  }
  if (!std::filesystem::exists(path, ec)) {
    std::ofstream out(path);
    if (!out.is_open()) {
      if (error)
        *error = "failed to create file";
      return false;
    }
  }
  return true;
}

/**
 * @brief Parse a JSON string into an ordered_json structure.
 */
bool ParseJsonString(const std::string &text, Json *out, std::string *error) {
  if (!out) {
    if (error)
      *error = "null json output";
    return false;
  }
  try {
    *out = Json::parse(text);
    return true;
  } catch (const std::exception &e) {
    if (error)
      *error = e.what();
    return false;
  }
}

/**
 * @brief Read a field as a string when available.
 */
std::optional<std::string> GetStringField(const Json &obj,
                                          const std::string &key) {
  if (!obj.is_object())
    return std::nullopt;
  auto it = obj.find(key);
  if (it == obj.end())
    return std::nullopt;
  if (it->is_string())
    return it->get<std::string>();
  if (it->is_number_integer())
    return std::to_string(it->get<int64_t>());
  if (it->is_number_unsigned())
    return std::to_string(it->get<size_t>());
  if (it->is_boolean())
    return it->get<bool>() ? "true" : "false";
  return std::nullopt;
}

/**
 * @brief Read a field as int64 when available.
 */
std::optional<int64_t> GetIntField(const Json &obj, const std::string &key) {
  if (!obj.is_object())
    return std::nullopt;
  auto it = obj.find(key);
  if (it == obj.end())
    return std::nullopt;
  if (it->is_number_integer())
    return it->get<int64_t>();
  if (it->is_number_unsigned()) {
    auto value = it->get<size_t>();
    if (value <= static_cast<size_t>(std::numeric_limits<int64_t>::max()))
      return static_cast<int64_t>(value);
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
 * @brief Read a boolean field from a JSON object when available.
 */
std::optional<bool> GetBoolField(const Json &obj, const std::string &key) {
  if (!obj.is_object())
    return std::nullopt;
  auto it = obj.find(key);
  if (it == obj.end())
    return std::nullopt;
  if (it->is_boolean())
    return it->get<bool>();
  if (it->is_number_integer())
    return it->get<int64_t>() != 0;
  if (it->is_number_unsigned())
    return it->get<size_t>() != 0;
  if (it->is_string()) {
    std::string value = AMStr::lowercase(it->get<std::string>());
    if (value == "true")
      return true;
    if (value == "false")
      return false;
  }
  return std::nullopt;
}

/**
 * @brief Return the HOSTS array if present and valid.
 */
const Json *GetHostsArray(const Json &root) {
  if (!root.is_object())
    return nullptr;
  auto it = root.find("HOSTS");
  if (it == root.end() || !it->is_array())
    return nullptr;
  return &(*it);
}

/**
 * @brief Check whether a host table contains required fields.
 */
bool IsHostValid(const Json &tbl) {
  auto nickname = GetStringField(tbl, "nickname");
  if (!nickname || nickname->empty())
    return false;
  auto hostname = GetStringField(tbl, "hostname");
  if (!hostname || hostname->empty())
    return false;
  return true;
}

/**
 * @brief Ensure the HOSTS array exists and return it for mutation.
 */
Json *EnsureHostsArray(Json &root) {
  if (!root.is_object())
    root = Json::object();
  auto it = root.find("HOSTS");
  if (it == root.end() || !it->is_array()) {
    root["HOSTS"] = Json::array();
  }
  return &root["HOSTS"];
}

/**
 * @brief Locate a host entry by nickname.
 */
const Json *FindHostJson(const Json &root, const std::string &nickname,
                         std::size_t *out_index = nullptr) {
  const Json *arr = GetHostsArray(root);
  if (!arr)
    return nullptr;
  for (std::size_t i = 0; i < arr->size(); ++i) {
    const Json &item = (*arr)[i];
    if (!item.is_object())
      continue;
    if (!IsHostValid(item))
      continue;
    auto name = GetStringField(item, "nickname");
    if (name && *name == nickname) {
      if (out_index)
        *out_index = i;
      return &item;
    }
  }
  return nullptr;
}

/**
 * @brief Locate a mutable host entry by nickname.
 */
Json *FindHostJsonMutable(Json &root, const std::string &nickname,
                          std::size_t *out_index = nullptr) {
  Json *arr = EnsureHostsArray(root);
  if (!arr)
    return nullptr;
  for (std::size_t i = 0; i < arr->size(); ++i) {
    Json &item = (*arr)[i];
    if (!item.is_object())
      continue;
    auto name = GetStringField(item, "nickname");
    if (name && *name == nickname) {
      if (out_index)
        *out_index = i;
      return &item;
    }
  }
  return nullptr;
}

/**
 * @brief Return true if the name starts with prefix and ends with suffix.
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
 * @brief Remove oldest backups matching prefix/suffix to keep max_count files.
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
    std::string name = entry.path().filename().string();
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

  size_t remove_count = items.size() - static_cast<size_t>(max_count);
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
ECM AMConfigStorage::AMInit(const std::filesystem::path &root_dir) {
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
ECM AMConfigStorage::AMInit(
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
           root_dir / "config" / "schema" / "config.schema.json");
  init_doc(DocumentKind::Settings, root_dir / "config" / "settings.toml",
           root_dir / "config" / "schema" / "settings.schema.json");
  init_doc(DocumentKind::KnownHosts,
           root_dir / "config" / "internal" / "known_hosts.toml",
           root_dir / "config" / "schema" / "known_hosts.schema.json");
  init_doc(DocumentKind::History,
           root_dir / "config" / "internal" / "history.toml", {});

  backup_prune_checked_ = false;
  shutdown_requested_.store(false, std::memory_order_relaxed);
  StartWriteThread();
  initialized_ = true;
  return Load();
}

/**
 * @brief Load a document from disk, or all documents when kind is nullopt.
 */
ECM AMConfigStorage::Load(std::optional<DocumentKind> kind, bool force) {
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
 * @brief Load a document into memory using cfgffi.
 */
ECM AMConfigStorage::LoadDocument_(DocumentKind kind, DocumentState *doc) {
  if (!doc) {
    return Err(EC::ConfigNotInitialized, "document not initialized");
  }
  std::string error;
  if (!EnsureFileExists(doc->path, &error)) {
    return Err(EC::ConfigLoadFailed,
               "failed to create " + AMStr::ToString(kind) + " file: " + error);
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
               "failed to parse " + AMStr::ToString(kind) + ": " + msg);
  }
  if (err) {
    cfgffi_free_string(err);
  }
  char *json_c = cfgffi_get_json(doc->handle);
  if (!json_c) {
    return Err(EC::ConfigLoadFailed,
               "failed to read " + AMStr::ToString(kind) + " json");
  }
  std::string json_str(json_c);
  cfgffi_free_string(json_c);
  Json parsed;
  if (!ParseJsonString(json_str, &parsed, &error)) {
    return Err(EC::ConfigLoadFailed,
               "failed to parse " + AMStr::ToString(kind) + " json: " + error);
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
  initialized_ = false;
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
 * @brief Persist all document snapshots to disk.
 */
ECM AMConfigStorage::DumpAll(bool async) {
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
ECM AMConfigStorage::Dump(DocumentKind kind, const std::string &path,
                          bool async) {
  if (async) {
    std::string path_copy = path;
    SubmitWriteTask([this, kind, path_copy]() -> ECM {
      return Dump(kind, path_copy, false);
    });
    return Ok();
  }

  DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    ECM rcm = Err(EC::ConfigNotInitialized, "document not initialized");
    NotifyDumpError_(rcm);
    return rcm;
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
      ECM rcm = Err(
          EC::ConfigDumpFailed,
          AMStr::fmt("failed to create config directory: {}", ec.message()));
      NotifyDumpError_(rcm);
      return rcm;
    }
  }
  if (path.empty()) {
    ECM rcm = WriteHandleJson_(doc, kind);
    return rcm;
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

    Json &options_cfg = settings_doc->json["Options"];
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

    auto now_s = static_cast<int64_t>(AMTime::seconds());
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
      const Json *backup_cfg = nullptr;
      auto opt_it = settings_doc->json.find("Options");
      if (opt_it != settings_doc->json.end() && opt_it->is_object()) {
        auto bc_it = opt_it->find("AutoConfigBackup");
        if (bc_it != opt_it->end() && bc_it->is_object()) {
          backup_cfg = &(*bc_it);
        }
      }
      if (backup_cfg) {
        if (auto v = GetIntField(*backup_cfg, "max_backup_count")) {
          max_backup_count = *v;
        }
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
  auto now_s = static_cast<int64_t>(AMTime::seconds());
  {
    std::lock_guard<std::mutex> lock(settings_doc->mtx);
    const Json *backup_cfg = nullptr;
    auto opt_it = settings_doc->json.find("Options");
    if (opt_it != settings_doc->json.end() && opt_it->is_object()) {
      auto bc_it = opt_it->find("AutoConfigBackup");
      if (bc_it != opt_it->end() && bc_it->is_object()) {
        backup_cfg = &(*bc_it);
      }
    }
    if (backup_cfg) {
      if (auto v = GetBoolField(*backup_cfg, "enabled")) {
        enabled = *v;
      }
      if (auto v = GetIntField(*backup_cfg, "interval_s")) {
        interval_s = *v;
      }
      if (auto v = GetIntField(*backup_cfg, "last_backup_time_s")) {
        last_backup_time_s = *v;
      }
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
    settings_doc->json["Options"]["AutoConfigBackup"]["last_backup_time_s"] =
        now_s;
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
    std::lock_guard<std::mutex> lock(write_queue_mtx_);
    write_queue_.push(std::move(task));
  }
  write_cv_.notify_one();
}

/**
 * @brief Register a callback invoked on dump errors.
 */
void AMConfigStorage::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
}

/**
 * @brief Return a thread-safe copy of a document JSON.
 */
bool AMConfigStorage::GetJson(DocumentKind kind,
                              nlohmann::ordered_json *value) const {
  if (!value) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return false;
  }
  *value = doc->GetJson();
  return true;
}

/**
 * @brief Return a thread-safe serialized JSON string of a document.
 */
bool AMConfigStorage::GetJsonStr(DocumentKind kind, std::string *value,
                                 int indent) const {
  if (!value) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return false;
  }
  *value = doc->GetJsonStr(indent);
  return true;
}

/**
 * @brief Return the config data path tracked for a document.
 */
bool AMConfigStorage::GetDataPath(DocumentKind kind,
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
DocumentState *AMConfigStorage::GetDoc_(DocumentKind kind) {
  auto it = docs_.find(kind);
  if (it == docs_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief Notify any registered dump-error callback.
 */
void AMConfigStorage::NotifyDumpError_(const ECM &err) const {
  if (dump_error_cb_) {
    dump_error_cb_(err);
  }
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
 * @brief Write JSON content into a cfgffi handle and refresh the cache.
 */
ECM AMConfigStorage::WriteHandleJson_(DocumentState *doc, DocumentKind kind) {
  const std::string label = std::string(AMStr::ToString(kind));
  if (!doc || !doc->handle) {
    ECM rcm =
        Err(EC::ConfigNotInitialized,
            AMStr::fmt("{} handle not initialized", label));
    NotifyDumpError_(rcm);
    return rcm;
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
      ECM rcm = Err(EC::ConfigDumpFailed,
                    AMStr::fmt("Failed to dump to {}: {}", doc->path.string(),
                               msg));
      NotifyDumpError_(rcm);
      return rcm;
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
    ConfigHandle *handle, std::string_view json,
    const std::filesystem::path &out_path) const {
  if (!handle) {
    NotifyDumpError_(
        Err(EC::ConfigNotInitialized, "config handle not initialized"));
    return;
  }
  char *err = nullptr;
  const int rc = cfgffi_write(handle, out_path.string().c_str(), json.data(),
                              &err);
  const std::string err_msg = err ? err : "";
  if (err) {
    cfgffi_free_string(err);
  }
  if (rc != 0 || !err_msg.empty()) {
    const std::string msg =
        err_msg.empty() ? AMStr::fmt("cfgffi_write failed with code {}", rc)
                        : err_msg;
    NotifyDumpError_(Err(EC::ConfigDumpFailed,
                         AMStr::fmt("Failed to write snapshot to {}: {}",
                                    out_path.string(), msg)));
  }
}

/**
 * @brief Worker loop that processes queued write tasks.
 */
void AMConfigStorage::WriteThreadLoop_() {
  while (true) {
    std::function<ECM()> task;
    {
      std::unique_lock<std::mutex> lock(write_queue_mtx_);
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
      task();
    }
  }
}

/**
 * @brief Return the project root directory path.
 */
std::filesystem::path AMConfigStorage::ProjectRoot() const { return root_dir_; }

/**
 * @brief Backup config/settings/known_hosts when the interval elapses.
 */
ECM AMConfigStorage::ConfigBackupIfNeeded() { return BackupIfNeeded(); }
