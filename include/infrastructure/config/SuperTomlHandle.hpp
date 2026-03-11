#pragma once
#include "foundation/RustTomlRead.h"
#include "foundation/tools/json.hpp"
#include "infrastructure/config/ConfigDocumentHandle.hpp"

/**
 * @brief Concrete cfgffi-backed TOML handle with in-memory Json cache.
 */
class AMInfraSuperTomlHandle final
    : public AMInfra::config::IConfigDocumentHandle {
public:
  /**
   * @brief Construct an empty TOML handle.
   */
  AMInfraSuperTomlHandle() = default;

  /**
   * @brief Release cfgffi resources.
   */
  ~AMInfraSuperTomlHandle() { Close(); }

  /**
   * @brief Initialize handle with document kind, path and schema.
   */
  ECM Init(const AMInfra::config::ConfigDocumentSpec &spec) override;

  /**
   * @brief Dump in-memory data to original config path.
   */
  ECM DumpInplace() override;

  /**
   * @brief Dump in-memory data to target path.
   */
  ECM DumpTo(const std::filesystem::path &dst_path) override;

  /**
   * @brief Close handle and clear in-memory cache.
   */
  void Close() override;

  /**
   * @brief Return whether in-memory cache changed since last dump.
   */
  [[nodiscard]] bool IsDirty() const override;

  /**
   * @brief Return last in-memory modification timestamp.
   */
  [[nodiscard]] std::chrono::system_clock::time_point
  LastModified() const override;

  /**
   * @brief Return a copy of in-memory json document.
   */
  [[nodiscard]] bool GetJson(Json *out) const;

protected:
  /**
   * @brief Read one typed config arg from this handle.
   */
  bool ReadValue(AMDomain::arg::TypeTag type, void *out) const override;

  /**
   * @brief Write one typed config arg into this handle.
   */
  bool WriteValue(AMDomain::arg::TypeTag type, const void *in) override;

private:
  AMInfra::config::ConfigDocumentSpec spec_{};
  ConfigHandle *cfgffi_handle_ = nullptr;
  Json json_ = Json::object();
  bool is_dirty_ = false;
  std::chrono::system_clock::time_point last_modified_{};
};
