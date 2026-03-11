#pragma once

#include "domain/arg/ArgTypes.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/DataClass.hpp"
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <type_traits>
#include <unordered_map>

namespace AMInfra::config {
/**
 * @brief Infrastructure bootstrap data for one persisted config document.
 */
struct ConfigDocumentSpec {
  AMDomain::config::DocumentKind kind = AMDomain::config::DocumentKind::Config;
  std::filesystem::path data_path;
  std::string schema_json = "{}";
};

using ConfigStoreLayout =
    std::unordered_map<AMDomain::config::DocumentKind, ConfigDocumentSpec>;

/**
 * @brief Infrastructure contract for one persisted config document handle.
 */
class IConfigDocumentHandle : NonCopyableNonMovable {
public:
  ~IConfigDocumentHandle() = default;

  /**
   * @brief Initialize handle from resolved infrastructure document spec.
   */
  virtual ECM Init(const ConfigDocumentSpec &spec) = 0;

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
} // namespace AMInfra::config
