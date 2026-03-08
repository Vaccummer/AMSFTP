#pragma once
#include "domain/arg/ArgTypes.hpp"
#include "foundation/DataClass.hpp"
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <type_traits>

namespace AMDomain::config {
/**
 * @brief Configuration document kinds handled by config manager.
 */
enum class DocumentKind {
  Config = 1,
  Settings = 2,
  KnownHosts = 3,
  History = 4
};

struct HandleInitSpec {
  DocumentKind kind = DocumentKind::Config;
  std::filesystem::path path;
  std::string schema_json;
  std::filesystem::path schema_path;
};
} // namespace AMDomain::config

namespace AMDomain::arg {
inline bool FindDocumentKind(TypeTag type,
                             AMDomain::config::DocumentKind *out) {
  if (!out) {
    return false;
  }

  using AMDomain::config::DocumentKind;
  switch (type) {
  case TypeTag::Config:
    *out = DocumentKind::Config;
    return true;
  case TypeTag::Settings:
    *out = DocumentKind::Settings;
    return true;
  case TypeTag::KnownHosts:
    *out = DocumentKind::KnownHosts;
    return true;
  case TypeTag::History:
    *out = DocumentKind::History;
    return true;
  case TypeTag::HostConfig:
    *out = DocumentKind::Config;
    return true;
  case TypeTag::KnownHostEntry:
    *out = DocumentKind::KnownHosts;
    return true;
  default:
    return false;
  }
}
} // namespace AMDomain::arg

namespace AMDomain::config {
/**
 * @brief Abstract config handle contract for one TOML-backed JSON document.
 */
class AMInfraConfigHandlePort : NonCopyableNonMovable {
public:
  ~AMInfraConfigHandlePort() override = default;

  /**
   * @brief Initialize handle with input specification.
   */
  virtual ECM Init(const HandleInitSpec &spec) = 0;

  /**
   * @brief Return initialization specification currently bound to this handle.
   */
  virtual bool GetInitSpec(HandleInitSpec *out) const = 0;

  /**
   * @brief Dump current in-memory JSON to original file path.
   */
  virtual ECM DumpInplace() = 0;

  /**
   * @brief Dump current in-memory JSON to destination path.
   */
  virtual ECM DumpTo(const std::filesystem::path &dst_path) = 0;

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

  template <typename T> bool Read(T *out) const {
    using ValueT = std::decay_t<T>;
    static_assert(AMDomain::arg::kSupportedArgType<ValueT>,
                  "T is not a supported config arg type");
    if (!out) {
      return false;
    }
    return ReadValue(AMDomain::arg::TypeTagOf<ValueT>::value,
                     static_cast<void *>(out));
  }

  template <typename T> bool Write(const T &in) {
    using ValueT = std::decay_t<T>;
    static_assert(AMDomain::arg::kSupportedArgType<ValueT>,
                  "T is not a supported config arg type");
    return WriteValue(AMDomain::arg::TypeTagOf<ValueT>::value,
                      static_cast<const void *>(&in));
  }

protected:
  virtual bool ReadValue(AMDomain::arg::TypeTag type, void *out) const = 0;
  virtual bool WriteValue(AMDomain::arg::TypeTag type, const void *in) = 0;
  mutable std::mutex mtx_;
};
} // namespace AMDomain::config

/**
 * @brief Backward-compatible global alias for gradual migration.
 */
using AMInfraConfigHandlePort = AMDomain::config::AMInfraConfigHandlePort;
using DocumentKind = AMDomain::config::DocumentKind;
