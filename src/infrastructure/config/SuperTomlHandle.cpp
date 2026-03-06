#include "infrastructure/config/SuperTomlHandle.hpp"

#include "foundation/tools/string.hpp"
#include <fstream>

namespace {
using Json = nlohmann::ordered_json;

/**
 * @brief Ensure target file exists and its parent directory is present.
 */
bool EnsureFileExists(const std::filesystem::path &path, std::string *error) {
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
 * @brief Parse JSON text into ordered JSON.
 */
bool ParseJson(const std::string &text, Json *out, std::string *error) {
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
 * @brief Initialize handle with file path and schema json text.
 */
ECM AMInfraSuperTomlHandle::Init(const std::filesystem::path &path,
                                 const std::string &schema_json) {
  std::lock_guard<std::mutex> lock(mtx_);

  if (cfgffi_handle_) {
    cfgffi_free_handle(cfgffi_handle_);
    cfgffi_handle_ = nullptr;
  }
  ori_path_ = path;
  schema_json_ = schema_json.empty() ? "{}" : schema_json;
  json_ = Json::object();
  is_dirty_ = false;
  last_modified_ = std::chrono::system_clock::time_point{};

  std::string error;
  if (!EnsureFileExists(ori_path_, &error)) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to prepare config file {}: {}",
                          ori_path_.string(), error));
  }

  char *err = nullptr;
  cfgffi_handle_ =
      cfgffi_read(ori_path_.string().c_str(), schema_json_.c_str(), &err);
  if (!cfgffi_handle_) {
    std::string msg = err ? err : "cfgffi_read failed";
    if (err) {
      cfgffi_free_string(err);
    }
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to read config file {}: {}",
                          ori_path_.string(), msg));
  }
  if (err) {
    cfgffi_free_string(err);
  }

  char *json_c = cfgffi_get_json(cfgffi_handle_);
  if (!json_c) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to read config json from {}",
                          ori_path_.string()));
  }
  std::string json_text(json_c);
  cfgffi_free_string(json_c);
  Json parsed = Json::object();
  if (!ParseJson(json_text, &parsed, &error)) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to parse config json from {}: {}",
                          ori_path_.string(), error));
  }
  json_ = std::move(parsed);
  return Ok();
}

/**
 * @brief Get full in-memory JSON snapshot.
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
 * @brief Read value by path as JsonValue.
 */
bool AMInfraSuperTomlHandle::ReadValue(const Path &path, JsonValue *out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  Json node = Json::object();
  if (!AMJson::QueryKey(json_, path, &node)) {
    return false;
  }
  return AMJson::ToJsonValue(node, out);
}

/**
 * @brief Write value by path.
 */
bool AMInfraSuperTomlHandle::WriteValue(const Path &path,
                                        const JsonValue &value) {
  std::lock_guard<std::mutex> lock(mtx_);
  Json node = AMJson::ToJson(value);
  bool ok = false;
  if (path.empty()) {
    json_ = std::move(node);
    ok = true;
  } else {
    if (!json_.is_object()) {
      json_ = Json::object();
    }
    ok = AMJson::SetKey(json_, path, node);
  }
  if (!ok) {
    return false;
  }
  is_dirty_ = true;
  last_modified_ = std::chrono::system_clock::now();
  return true;
}

/**
 * @brief Delete value by path.
 */
bool AMInfraSuperTomlHandle::DeleteValue(const Path &path) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!json_.is_object()) {
    return false;
  }
  if (!AMJson::DelKey(json_, path)) {
    return false;
  }
  is_dirty_ = true;
  last_modified_ = std::chrono::system_clock::now();
  return true;
}

/**
 * @brief Dump current in-memory JSON to original file path.
 */
ECM AMInfraSuperTomlHandle::DumpInplace() { return DumpTo(ori_path_); }

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
  if (dst_path == ori_path_) {
    rc = cfgffi_write_inplace(cfgffi_handle_, payload.c_str(), &err);
  } else {
    rc = cfgffi_write(cfgffi_handle_, dst_path.string().c_str(), payload.c_str(),
                      &err);
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
  return ori_path_;
}
