#include "domain/config/ConfigManager.hpp"

#include "foundation/tools/time.hpp"
#include "infrastructure/config/SuperTomlHandle.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <optional>

namespace {
using AMDomain::config::DocumentKind;
using Json = nlohmann::ordered_json;

constexpr std::array<DocumentKind, 4> kRequiredKinds = {
    DocumentKind::Config, DocumentKind::Settings, DocumentKind::KnownHosts,
    DocumentKind::History};

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

namespace AMDomain::config {
ECM AMConfigManager::Init(
    const std::unordered_map<DocumentKind, DocumentInitSpec> &specs,
    AMDomain::writer::AMAsyncWriteSchedulerPort *writer) {
  CloseHandles();
  docs_.clear();
  writer_ = writer;
  backup_prune_checked_ = false;

  for (const auto kind : kRequiredKinds) {
    auto it = specs.find(kind);
    if (it == specs.end()) {
      return Err(EC::ConfigNotInitialized, "missing document init spec");
    }
    DocumentState state{};
    state.json_path = it->second.json_path;
    state.schema_path = it->second.schema_path;
    state.schema_data = it->second.schema_data;
    if (kind == DocumentKind::History && state.schema_data.empty()) {
      state.schema_data = kHistorySchemaJson;
    }
    if (state.schema_data.empty()) {
      state.schema_data = AMJson::ReadSchemaData(state.schema_path, nullptr);
      if (state.schema_data.empty()) {
        state.schema_data = "{}";
      }
    }
    docs_[kind] = std::move(state);
  }

  StartWriteThread();
  initialized_ = true;
  return Load();
}

ECM AMConfigManager::Load(std::optional<DocumentKind> kind, bool force) {
  auto load_single = [&](DocumentKind target_kind) -> ECM {
    DocumentState *doc = GetDoc_(target_kind);
    if (!doc) {
      return Err(EC::ConfigNotInitialized, "document not initialized");
    }
    if (!force && doc->handle) {
      return Ok();
    }
    ECM rcm = LoadDocument_(target_kind, doc);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    SyncPortsFromDocument_(target_kind);
    return Ok();
  };

  if (kind.has_value()) {
    return load_single(kind.value());
  }
  for (const auto current : kRequiredKinds) {
    ECM rcm = load_single(current);
    if (rcm.first != EC::Success) {
      return rcm;
    }
  }
  return Ok();
}

ECM AMConfigManager::LoadDocument_(DocumentKind kind, DocumentState *doc) {
  if (!doc) {
    return Err(EC::ConfigNotInitialized, "document not initialized");
  }
  if (!doc->handle) {
    doc->handle = std::make_shared<AMInfraSuperTomlHandle>();
  }

  if (doc->schema_data.empty()) {
    if (kind == DocumentKind::History) {
      doc->schema_data = kHistorySchemaJson;
    } else {
      doc->schema_data = AMJson::ReadSchemaData(doc->schema_path, nullptr);
      if (doc->schema_data.empty()) {
        doc->schema_data = "{}";
      }
    }
  }
  return doc->handle->Init(doc->json_path, doc->schema_data);
}

ECM AMConfigManager::Dump(DocumentKind kind, const std::string &dst_path,
                          bool async) {
  if (async) {
    const std::string path_copy = dst_path;
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
  ECM sync_rcm = SyncPortsToDocument_(kind);
  if (sync_rcm.first != EC::Success) {
    NotifyDumpError_(sync_rcm);
    return sync_rcm;
  }
  if (dst_path.empty() && !doc->handle->IsDirty()) {
    return Ok();
  }

  ECM rcm = Ok();
  if (dst_path.empty()) {
    rcm = doc->handle->DumpInplace();
  } else {
    rcm = doc->handle->DumpTo(dst_path);
  }
  if (rcm.first != EC::Success) {
    NotifyDumpError_(rcm);
  }
  return rcm;
}

ECM AMConfigManager::DumpAll(bool async) {
  if (async) {
    SubmitWriteTask([this]() -> ECM { return DumpAll(false); });
    return Ok();
  }

  for (const auto kind : kRequiredKinds) {
    ECM rcm = Dump(kind);
    if (rcm.first != EC::Success) {
      return rcm;
    }
  }
  return Ok();
}

void AMConfigManager::CloseHandles() {
  StopWriteThread();
  for (auto &[_, doc] : docs_) {
    if (doc.handle) {
      doc.handle->Close();
      doc.handle.reset();
    }
  }
  initialized_ = false;
  backup_prune_checked_ = false;
}

void AMConfigManager::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
}

void AMConfigManager::StartWriteThread() {
  if (writer_) {
    writer_->Start();
  }
}

void AMConfigManager::StopWriteThread() {
  if (writer_) {
    writer_->Stop();
  }
}

void AMConfigManager::SubmitWriteTask(std::function<ECM()> task) {
  if (!task) {
    return;
  }
  if (!writer_ || !writer_->IsRunning()) {
    ECM rcm = task();
    if (rcm.first != EC::Success) {
      NotifyDumpError_(rcm);
    }
    return;
  }
  writer_->Submit([this, task = std::move(task)]() mutable {
    ECM rcm = task();
    if (rcm.first != EC::Success) {
      NotifyDumpError_(rcm);
    }
  });
}

bool AMConfigManager::GetJson(DocumentKind kind, Json *out) const {
  if (!out) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    return false;
  }
  return doc->handle->GetJson(out);
}

bool AMConfigManager::ReadValue(DocumentKind kind, const Path &path,
                                JsonValue *out) const {
  if (!out) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    return false;
  }
  return doc->handle->ReadValue(path, out);
}

bool AMConfigManager::WriteValue(DocumentKind kind, const Path &path,
                                 const JsonValue &value) {
  DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    return false;
  }
  return doc->handle->WriteValue(path, value);
}

bool AMConfigManager::DeleteValue(DocumentKind kind, const Path &path) {
  DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    return false;
  }
  return doc->handle->DeleteValue(path);
}

bool AMConfigManager::GetSchemaData(DocumentKind kind, std::string *out) const {
  if (!out) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return false;
  }
  *out = doc->schema_data;
  return true;
}

bool AMConfigManager::GetSchemaJson(DocumentKind kind, std::string *out) const {
  return GetSchemaData(kind, out);
}

bool AMConfigManager::GetSchemaJson(DocumentKind kind, Json *out) const {
  if (!out) {
    return false;
  }
  std::string schema_data;
  if (!GetSchemaData(kind, &schema_data)) {
    return false;
  }
  try {
    *out = Json::parse(schema_data);
    return true;
  } catch (...) {
    return false;
  }
}

bool AMConfigManager::GetDataPath(DocumentKind kind,
                                  std::filesystem::path *out) const {
  if (!out) {
    return false;
  }
  const DocumentState *doc = GetDoc_(kind);
  if (!doc) {
    return false;
  }
  *out = doc->json_path;
  return true;
}

bool AMConfigManager::IsDirty(DocumentKind kind) const {
  const DocumentState *doc = GetDoc_(kind);
  if (!doc || !doc->handle) {
    return false;
  }
  return doc->handle->IsDirty();
}

/**
 * @brief Create or return one sync port for one `(kind, path)` key.
 */
AMConfigManager::SyncPort
AMConfigManager::CreateOrGetSyncPort(DocumentKind kind, const Path &path,
                                     const Json &fallback) {
  {
    std::lock_guard<std::mutex> lock(sync_ports_mtx_);
    auto kind_it = sync_ports_.find(kind);
    if (kind_it != sync_ports_.end()) {
      auto path_it = kind_it->second.find(path);
      if (path_it != kind_it->second.end()) {
        return path_it->second;
      }
    }
  }

  Json init_json = fallback;
  JsonValue loaded_value;
  if (ReadValue(kind, path, &loaded_value)) {
    init_json = AMJson::ToJson(loaded_value);
  }
  SyncPort created =
      std::make_shared<AMConfigSyncPort>(kind, Path(path), std::move(init_json));

  std::lock_guard<std::mutex> lock(sync_ports_mtx_);
  auto [it, inserted] = sync_ports_[kind].emplace(path, created);
  if (!inserted) {
    return it->second;
  }
  return created;
}

/**
 * @brief Return one sync port by `(kind, path)` key when registered.
 */
AMConfigManager::SyncPort AMConfigManager::GetSyncPort(
    DocumentKind kind, const Path &path) const {
  std::lock_guard<std::mutex> lock(sync_ports_mtx_);
  auto kind_it = sync_ports_.find(kind);
  if (kind_it == sync_ports_.end()) {
    return nullptr;
  }
  auto path_it = kind_it->second.find(path);
  if (path_it == kind_it->second.end()) {
    return nullptr;
  }
  return path_it->second;
}

/**
 * @brief Pull latest payload from ports and merge back into manager JSON.
 */
ECM AMConfigManager::SyncPortsToDocument_(DocumentKind kind) {
  std::vector<SyncPort> ports;
  {
    std::lock_guard<std::mutex> lock(sync_ports_mtx_);
    auto kind_it = sync_ports_.find(kind);
    if (kind_it == sync_ports_.end()) {
      return Ok();
    }
    ports.reserve(kind_it->second.size());
    for (const auto &[_, port] : kind_it->second) {
      ports.push_back(port);
    }
  }

  for (const auto &port : ports) {
    if (!port) {
      continue;
    }
    if (!port->TriggerDumpCallback()) {
      return Err(EC::ConfigDumpFailed, "sync port dump callback failed");
    }
    Json payload = Json::object();
    if (!port->GetJson(&payload)) {
      return Err(EC::ConfigDumpFailed, "failed to read sync port json");
    }
    if (!WriteValue(kind, port->GetPath(), payload)) {
      return Err(EC::ConfigDumpFailed, "failed to merge sync port json");
    }
  }
  return Ok();
}

/**
 * @brief Load-sync currently loaded manager JSON value into registered ports.
 */
void AMConfigManager::SyncPortsFromDocument_(DocumentKind kind) {
  std::vector<SyncPort> ports;
  {
    std::lock_guard<std::mutex> lock(sync_ports_mtx_);
    auto kind_it = sync_ports_.find(kind);
    if (kind_it == sync_ports_.end()) {
      return;
    }
    ports.reserve(kind_it->second.size());
    for (const auto &[_, port] : kind_it->second) {
      ports.push_back(port);
    }
  }

  for (const auto &port : ports) {
    if (!port) {
      continue;
    }
    JsonValue value;
    if (!ReadValue(kind, port->GetPath(), &value)) {
      continue;
    }
    port->SetJson(AMJson::ToJson(value));
  }
}

ECM AMConfigManager::BackupIfNeeded(const std::filesystem::path &root_dir) {
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
    const std::filesystem::path backup_dir = root_dir / "config" / "bak";
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

  const std::filesystem::path backup_dir = root_dir / "config" / "bak";
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
                   config_backup, settings_backup,
                   known_hosts_backup]() -> ECM {
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

void AMConfigManager::NotifyDumpError_(const ECM &err) const {
  if (dump_error_cb_) {
    dump_error_cb_(err);
  }
}

AMConfigManager::DocumentState *AMConfigManager::GetDoc_(DocumentKind kind) {
  auto it = docs_.find(kind);
  if (it == docs_.end()) {
    return nullptr;
  }
  return &it->second;
}

const AMConfigManager::DocumentState *
AMConfigManager::GetDoc_(DocumentKind kind) const {
  auto it = docs_.find(kind);
  if (it == docs_.end()) {
    return nullptr;
  }
  return &it->second;
}
} // namespace AMDomain::config
