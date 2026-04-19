#pragma once

#include "domain/config/ConfigModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/json.hpp"
#include <chrono>
#include <filesystem>

namespace AMInfra::config {
using ConfigDocumentSpec = AMDomain::config::ConfigDocumentSpec;
using ConfigStoreLayout = AMDomain::config::ConfigStoreLayout;

/**
 * @brief Infrastructure contract for one persisted config document handle.
 */
class IConfigFileHandle : NonCopyableNonMovable {
public:
  ~IConfigFileHandle() override = default;

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

  /**
   * @brief Return a copy of in-memory JSON document.
   */
  [[nodiscard]] virtual bool GetJson(AMJson::Json *out) const = 0;

  /**
   * @brief Replace the in-memory JSON document.
   */
  virtual bool SetJson(const AMJson::Json &json) = 0;
};
} // namespace AMInfra::config
