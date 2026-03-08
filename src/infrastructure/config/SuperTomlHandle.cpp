#include "infrastructure/config/SuperTomlHandle.hpp"

#include "foundation/tools/string.hpp"
#include "infrastructure/config/DecorderRegistry.hpp"

#include <fstream>

namespace {
using DocumentKind = AMDomain::config::DocumentKind;

/**
 * @brief Ensure target file exists and its parent directory is present.
 */
bool EnsureFileExists_(const std::filesystem::path &path, std::string *error) {
  std::error_code ec;
  const auto parent = path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      if (error) {
        *error = ec.message();
      }
      return false;
    }
  }
  if (!std::filesystem::exists(path, ec)) {
    std::ofstream out(path, std::ios::out | std::ios::binary);
    if (!out.is_open()) {
      if (error) {
        *error = "failed to create file";
      }
      return false;
    }
  }
  return true;
}

/**
 * @brief Parse JSON text into ordered json value.
 */
bool ParseJson_(const std::string &text, Json *out, std::string *error) {
  if (!out) {
    if (error) {
      *error = "null output json";
    }
    return false;
  }
  try {
    *out = Json::parse(text);
    return true;
  } catch (const std::exception &e) {
    if (error) {
      *error = e.what();
    }
    return false;
  }
}

/**
 * @brief Infer document kind from file name.
 */
DocumentKind InferKindFromPath_(const std::filesystem::path &path) {
  const std::string file = AMStr::lowercase(path.filename().string());
  if (file == "config.toml") {
    return DocumentKind::Config;
  }
  if (file == "settings.toml") {
    return DocumentKind::Settings;
  }
  if (file == "known_hosts.toml") {
    return DocumentKind::KnownHosts;
  }
  if (file == "history.toml") {
    return DocumentKind::History;
  }
  return DocumentKind::Config;
}

/**
 * @brief Return whether runtime arg type belongs to current document kind.
 */
bool IsTypeMatchedByHandle_(AMDomain::arg::TypeTag type,
                            DocumentKind handle_kind) {
  DocumentKind expected = DocumentKind::Config;
  if (!AMDomain::arg::FindDocumentKind(type, &expected)) {
    return false;
  }
  return expected == handle_kind;
}
} // namespace

/**
 * @brief Backward-compatible initializer from path and schema text.
 */
ECM AMInfraSuperTomlHandle::Init(const std::filesystem::path &path,
                                 const std::string &schema_json) {
  AMDomain::config::HandleInitSpec spec = {};
  spec.kind = InferKindFromPath_(path);
  spec.path = path;
  spec.schema_json = schema_json;
  return Init(spec);
}

/**
 * @brief Initialize handle with document kind, path and schema.
 */
ECM AMInfraSuperTomlHandle::Init(const AMDomain::config::HandleInitSpec &spec) {
  std::lock_guard<std::mutex> lock(mtx_);

  if (cfgffi_handle_) {
    cfgffi_free_handle(cfgffi_handle_);
    cfgffi_handle_ = nullptr;
  }

  init_spec_ = spec;
  if (init_spec_.path.empty()) {
    return Err(EC::ConfigLoadFailed, "config path is empty");
  }

  schema_json_ = AMStr::Strip(init_spec_.schema_json);
  if (schema_json_.empty() && !init_spec_.schema_path.empty()) {
    schema_json_ = AMJson::ReadSchemaData(init_spec_.schema_path, nullptr);
  }
  if (schema_json_.empty()) {
    schema_json_ = "{}";
  }

  json_ = Json::object();
  is_dirty_ = false;
  last_modified_ = std::chrono::system_clock::time_point{};

  std::string error;
  if (!EnsureFileExists_(init_spec_.path, &error)) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to prepare config file {}: {}",
                          init_spec_.path.string(), error));
  }

  char *err = nullptr;
  cfgffi_handle_ =
      cfgffi_read(init_spec_.path.string().c_str(), schema_json_.c_str(), &err);
  if (!cfgffi_handle_) {
    std::string msg = err ? err : "cfgffi_read failed";
    if (err) {
      cfgffi_free_string(err);
    }
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to read config file {}: {}",
                          init_spec_.path.string(), msg));
  }
  if (err) {
    cfgffi_free_string(err);
  }

  char *json_c = cfgffi_get_json(cfgffi_handle_);
  if (!json_c) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to read config json from {}",
                          init_spec_.path.string()));
  }

  std::string json_text(json_c);
  cfgffi_free_string(json_c);

  Json parsed = Json::object();
  if (!ParseJson_(json_text, &parsed, &error)) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to parse config json from {}: {}",
                          init_spec_.path.string(), error));
  }

  json_ = std::move(parsed);
  init_spec_.schema_json = schema_json_;
  return Ok();
}

/**
 * @brief Return currently bound initialization specification.
 */
bool AMInfraSuperTomlHandle::GetInitSpec(
    AMDomain::config::HandleInitSpec *out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  *out = init_spec_;
  return true;
}

/**
 * @brief Return a copy of in-memory json document.
 */
bool AMInfraSuperTomlHandle::GetJson(Json *out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  *out = json_;
  return true;
}

/**
 * @brief Read one typed config arg from this handle.
 */
bool AMInfraSuperTomlHandle::ReadValue(AMDomain::arg::TypeTag type,
                                       void *out) const {
  if (!out) {
    return false;
  }

  std::lock_guard<std::mutex> lock(mtx_);
  if (!cfgffi_handle_) {
    return false;
  }
  if (!IsTypeMatchedByHandle_(type, init_spec_.kind)) {
    return false;
  }

  return AMInfra::config::DecodeArg(type, json_, out, nullptr);
}

/**
 * @brief Write one typed config arg into this handle.
 */
bool AMInfraSuperTomlHandle::WriteValue(AMDomain::arg::TypeTag type,
                                        const void *in) {
  if (!in) {
    return false;
  }

  std::lock_guard<std::mutex> lock(mtx_);
  if (!cfgffi_handle_) {
    return false;
  }
  if (!IsTypeMatchedByHandle_(type, init_spec_.kind)) {
    return false;
  }

  Json next = Json::object();
  if (!AMInfra::config::EncodeArg(type, in, &next, nullptr)) {
    return false;
  }

  json_ = std::move(next);
  is_dirty_ = true;
  last_modified_ = std::chrono::system_clock::now();
  return true;
}

/**
 * @brief Dump current in-memory JSON to original file path.
 */
ECM AMInfraSuperTomlHandle::DumpInplace() { return DumpTo(init_spec_.path); }

/**
 * @brief Dump current in-memory JSON to destination path.
 */
ECM AMInfraSuperTomlHandle::DumpTo(const std::filesystem::path &dst_path) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!cfgffi_handle_) {
    return Err(EC::ConfigNotInitialized, "config handle not initialized");
  }
  if (dst_path.empty()) {
    return Err(EC::ConfigDumpFailed, "destination path is empty");
  }

  std::error_code ec;
  const auto parent = dst_path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      return Err(EC::ConfigDumpFailed,
                 AMStr::fmt("failed to create directory for {}: {}",
                            dst_path.string(), ec.message()));
    }
  }

  const std::string payload = json_.dump(2);
  char *err = nullptr;
  int rc = 0;
  if (dst_path == init_spec_.path) {
    rc = cfgffi_write_inplace(cfgffi_handle_, payload.c_str(), &err);
  } else {
    rc = cfgffi_write(cfgffi_handle_, dst_path.string().c_str(),
                      payload.c_str(), &err);
  }

  if (rc != 0) {
    std::string msg = err ? err : "cfgffi write failed";
    if (err) {
      cfgffi_free_string(err);
    }
    return Err(EC::ConfigDumpFailed,
               AMStr::fmt("failed to dump config to {}: {}", dst_path.string(),
                          msg));
  }
  if (err) {
    cfgffi_free_string(err);
  }

  is_dirty_ = false;
  return Ok();
}

/**
 * @brief Return stored schema json string.
 */
bool AMInfraSuperTomlHandle::GetSchemaJson(std::string *out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  *out = schema_json_;
  return true;
}

/**
 * @brief Return stored schema json as Json.
 */
bool AMInfraSuperTomlHandle::GetSchemaJson(Json *out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  try {
    *out = Json::parse(schema_json_);
    return true;
  } catch (...) {
    return false;
  }
}

/**
 * @brief Close underlying cfgffi handle and reset state.
 */
void AMInfraSuperTomlHandle::Close() {
  std::lock_guard<std::mutex> lock(mtx_);
  if (cfgffi_handle_) {
    cfgffi_free_handle(cfgffi_handle_);
    cfgffi_handle_ = nullptr;
  }
  init_spec_ = {};
  schema_json_ = "{}";
  json_ = Json::object();
  is_dirty_ = false;
  last_modified_ = std::chrono::system_clock::time_point{};
}

/**
 * @brief Return whether in-memory data is dirty.
 */
bool AMInfraSuperTomlHandle::IsDirty() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return is_dirty_;
}

/**
 * @brief Return last modification timestamp.
 */
std::chrono::system_clock::time_point
AMInfraSuperTomlHandle::LastModified() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return last_modified_;
}

/**
 * @brief Return original TOML path for this handle.
 */
std::filesystem::path AMInfraSuperTomlHandle::Path() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return init_spec_.path;
}

