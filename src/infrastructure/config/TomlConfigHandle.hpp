#pragma once
#include "foreign/amsrust/include/RustTomlRead.h"
#include "foundation/tools/json.hpp"
#include "infrastructure/config/IConfigFileHandle.hpp"

/**
 * @brief Concrete RustToml-backed TOML handle with in-memory Json cache.
 */
namespace AMInfra::config {
class TomlConfigHandle final : public IConfigFileHandle {
public:
  /**
   * @brief Construct an empty TOML handle.
   */
  TomlConfigHandle() = default;

  /**
   * @brief Release RustToml resources.
   */
  ~TomlConfigHandle() override { Close(); }

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
  [[nodiscard]] bool GetJson(Json *out) const override;

  /**
   * @brief Replace the in-memory json document and mark handle dirty.
   */
  bool SetJson(const Json &json) override;

private:
  mutable std::mutex mtx_;
  AMInfra::config::ConfigDocumentSpec spec_{};
  ConfigHandle *rust_toml_handle_ = nullptr;
  Json json_ = Json::object();
  bool is_dirty_ = false;
  std::chrono::system_clock::time_point last_modified_{};
};
} // namespace AMInfra::config
