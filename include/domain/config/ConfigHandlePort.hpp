#pragma once
#include "foundation/DataClass.hpp"
#include "foundation/tools/json.hpp"
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace AMDomain::config {
/**
 * @brief Abstract config handle contract for one TOML-backed JSON document.
 */
class AMInfraConfigHandlePort : NonCopyableNonMovable {
public:
  using Path = std::vector<std::string>;

  virtual ~AMInfraConfigHandlePort() = default;

  /**
   * @brief Initialize handle with file path and schema json text.
   */
  virtual ECM Init(const std::filesystem::path &path,
                   const std::string &schema_json) = 0;

  /**
   * @brief Get full in-memory JSON snapshot.
   */
  virtual bool GetJson(Json *out) const = 0;

  /**
   * @brief Read value by path as JsonValue.
   */
  virtual bool ReadValue(const Path &path, JsonValue *out) const = 0;

  /**
   * @brief Write value by path.
   */
  virtual bool WriteValue(const Path &path, const JsonValue &value) = 0;

  /**
   * @brief Delete value by path.
   */
  virtual bool DeleteValue(const Path &path) = 0;

  /**
   * @brief Dump current in-memory JSON to original file path.
   */
  virtual ECM DumpInplace() = 0;

  /**
   * @brief Dump current in-memory JSON to destination path.
   */
  virtual ECM DumpTo(const std::filesystem::path &dst_path) = 0;

  /**
   * @brief Return stored schema json string.
   */
  virtual bool GetSchemaJson(std::string *out) const = 0;

  /**
   * @brief Return stored schema json as Json.
   */
  virtual bool GetSchemaJson(Json *out) const = 0;

  /**
   * @brief Close underlying cfgffi handle and reset state.
   */
  virtual void Close() = 0;

  /**
   * @brief Return whether in-memory data is dirty.
   */
  [[nodiscard]] virtual bool IsDirty() const = 0;

  /**
   * @brief Return last modification timestamp.
   */
  [[nodiscard]] virtual std::chrono::system_clock::time_point
  LastModified() const = 0;

  /**
   * @brief Typed read helper based on ReadValue.
   */
  template <typename T> bool Resolve(const Path &path, T *out) const {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    if (!out) {
      return false;
    }
    JsonValue value;
    if (!ReadValue(path, &value)) {
      return false;
    }
    return AMJson::JsonValueTo(value, out);
  }

  /**
   * @brief Typed write helper based on WriteValue.
   */
  template <typename T> bool Set(const Path &path, const T &value) {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    JsonValue boxed;
    if (!AMJson::ToJsonValue(value, &boxed)) {
      return false;
    }
    return WriteValue(path, boxed);
  }

protected:
  mutable std::mutex mtx_;
};
} // namespace AMDomain::config

/**
 * @brief Backward-compatible global alias for gradual migration.
 */
using AMInfraConfigHandlePort = AMDomain::config::AMInfraConfigHandlePort;
