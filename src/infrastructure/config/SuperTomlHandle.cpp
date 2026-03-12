#include "infrastructure/config/SuperTomlHandle.hpp"

#include "foundation/tools/enum_related.hpp"
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
ECM AMInfraSuperTomlHandle::Init(const AMInfra::config::ConfigDocumentSpec &spec) {
  std::lock_guard<std::mutex> lock(mtx_);

  if (cfgffi_handle_) {
    cfgffi_free_handle(cfgffi_handle_);
    cfgffi_handle_ = nullptr;
  }

  spec_ = spec;
  if (spec_.data_path.empty()) {
    return Err(EC::ConfigLoadFailed, "config path is empty");
  }

  spec_.schema_json = AMStr::Strip(spec_.schema_json);
  if (spec_.schema_json.empty()) {
    spec_.schema_json = "{}";
  }

  json_ = Json::object();
  is_dirty_ = false;
  last_modified_ = std::chrono::system_clock::time_point{};

  std::string error;
  if (!EnsureFileExists_(spec_.data_path, &error)) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to prepare config file {}: {}",
                          spec_.data_path.string(), error));
  }

  char *err = nullptr;
  cfgffi_handle_ =
      cfgffi_read(spec_.data_path.string().c_str(), spec_.schema_json.c_str(), &err);
  if (!cfgffi_handle_) {
    std::string msg = err ? err : "cfgffi_read failed";
    if (err) {
      cfgffi_free_string(err);
    }
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to read config file {}: {}",
                          spec_.data_path.string(), msg));
  }
  if (err) {
    cfgffi_free_string(err);
  }

  char *json_c = cfgffi_get_json(cfgffi_handle_);
  if (!json_c) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to read config json from {}",
                          spec_.data_path.string()));
  }

  std::string json_text(json_c);
  cfgffi_free_string(json_c);

  Json parsed = Json::object();
  if (!ParseJson_(json_text, &parsed, &error)) {
    return Err(EC::ConfigLoadFailed,
               AMStr::fmt("failed to parse config json from {}: {}",
                          spec_.data_path.string(), error));
  }

  json_ = std::move(parsed);
  return Ok();
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
 * @brief Replace the in-memory json document and mark handle dirty.
 */
bool AMInfraSuperTomlHandle::SetJson(const Json &json) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!cfgffi_handle_) {
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
ECM AMInfraSuperTomlHandle::DumpInplace() { return DumpTo(spec_.data_path); }

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
  if (dst_path == spec_.data_path) {
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
 * @brief Close underlying cfgffi handle and reset state.
 */
void AMInfraSuperTomlHandle::Close() {
  std::lock_guard<std::mutex> lock(mtx_);
  if (cfgffi_handle_) {
    cfgffi_free_handle(cfgffi_handle_);
    cfgffi_handle_ = nullptr;
  }
  spec_ = {};
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
