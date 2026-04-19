#include "infrastructure/config/TomlConfigHandle.hpp"
#include "foundation/tools/string.hpp"

#include <fstream>

namespace {
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
} // namespace

/**
 * @brief Initialize handle with document kind, path and schema.
 */
namespace AMInfra::config {
ECM TomlConfigHandle::Init(const ConfigDocumentSpec &spec) {
  std::lock_guard<std::mutex> lock(mtx_);

  if (rust_toml_handle_) {
    RustTomlFreeHandle(rust_toml_handle_);
    rust_toml_handle_ = nullptr;
  }

  spec_ = spec;
  if (spec_.data_path.empty()) {
    return Err(EC::ConfigLoadFailed, "", "", "config path is empty");
  }

  const char *schema_json = spec_.schema_json;
  if (schema_json == nullptr) {
    schema_json = "{}";
  }
  std::string normalized_schema_json = AMStr::Strip(schema_json);
  if (normalized_schema_json.empty()) {
    normalized_schema_json = "{}";
  }

  json_ = Json::object();
  is_dirty_ = false;
  last_modified_ = std::chrono::system_clock::time_point{};

  std::string error;
  if (!EnsureFileExists_(spec_.data_path, &error)) {
    return Err(EC::ConfigLoadFailed, "", "",
               AMStr::fmt("failed to prepare config file {}: {}",
                          spec_.data_path.string(), error));
  }

  char *err = nullptr;
  rust_toml_handle_ = RustTomlRead(spec_.data_path.string().c_str(),
                                   normalized_schema_json.c_str(), &err);
  if (!rust_toml_handle_) {
    std::string msg = err ? err : "RustTomlRead failed";
    if (err) {
      RustTomlFreeString(err);
    }
    return Err(EC::ConfigLoadFailed, "", "",
               AMStr::fmt("failed to read config file {}: {}",
                          spec_.data_path.string(), msg));
  }
  if (err) {
    RustTomlFreeString(err);
  }

  char *json_c = RustTomlGetJson(rust_toml_handle_);
  if (!json_c) {
    return Err(EC::ConfigLoadFailed, "", "",
               AMStr::fmt("failed to read config json from {}",
                          spec_.data_path.string()));
  }

  std::string json_text(json_c);
  RustTomlFreeString(json_c);

  Json parsed = Json::object();
  if (!ParseJson_(json_text, &parsed, &error)) {
    return Err(EC::ConfigLoadFailed, "", "",
               AMStr::fmt("failed to parse config json from {}: {}",
                          spec_.data_path.string(), error));
  }

  json_ = std::move(parsed);
  return OK;
}

/**
 * @brief Return a copy of in-memory json document.
 */
bool TomlConfigHandle::GetJson(Json *out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  *out = json_;
  return true;
}

/**
 * @brief Replace the in-memory json document and mark handle dirty.
 */
bool TomlConfigHandle::SetJson(const Json &json) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!rust_toml_handle_) {
    return false;
  }
  json_ = json;
  is_dirty_ = true;
  last_modified_ = std::chrono::system_clock::now();
  return true;
}

/**
 * @brief Dump current in-memory JSON to original file path.
 */
ECM TomlConfigHandle::DumpInplace() {
  return DumpTo(spec_.data_path);
}

/**
 * @brief Dump current in-memory JSON to destination path.
 */
ECM TomlConfigHandle::DumpTo(const std::filesystem::path &dst_path) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!rust_toml_handle_) {
    return Err(EC::ConfigNotInitialized, "", "",
               "config handle not initialized");
  }
  if (dst_path.empty()) {
    return Err(EC::ConfigDumpFailed, "", "", "destination path is empty");
  }

  std::error_code ec;
  const auto parent = dst_path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      return Err(EC::ConfigDumpFailed, "", "",
                 AMStr::fmt("failed to create directory for {}: {}",
                            dst_path.string(), ec.message()));
    }
  }

  const std::string payload = json_.dump(2);
  char *err = nullptr;
  int rc = 0;
  if (dst_path == spec_.data_path) {
    rc = RustTomlWriteInplace(rust_toml_handle_, payload.c_str(), &err);
  } else {
    rc = RustTomlWrite(rust_toml_handle_, dst_path.string().c_str(),
                       payload.c_str(), &err);
  }

  if (rc != 0) {
    std::string msg = err ? err : "cfgffi write failed";
    if (err) {
      RustTomlFreeString(err);
    }
    return Err(
        EC::ConfigDumpFailed, "", "",
        AMStr::fmt("failed to dump config to {}: {}", dst_path.string(), msg));
  }
  if (err) {
    RustTomlFreeString(err);
  }

  is_dirty_ = false;
  return OK;
}

/**
 * @brief Close underlying RustToml handle and reset state.
 */
void TomlConfigHandle::Close() {
  std::lock_guard<std::mutex> lock(mtx_);
  if (rust_toml_handle_) {
    RustTomlFreeHandle(rust_toml_handle_);
    rust_toml_handle_ = nullptr;
  }
  spec_ = {};
  json_ = Json::object();
  is_dirty_ = false;
  last_modified_ = std::chrono::system_clock::time_point{};
}

/**
 * @brief Return whether in-memory data is dirty.
 */
bool TomlConfigHandle::IsDirty() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return is_dirty_;
}

/**
 * @brief Return last modification timestamp.
 */
std::chrono::system_clock::time_point
TomlConfigHandle::LastModified() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return last_modified_;
}
} // namespace AMInfra::config


