#pragma once

#include "domain/config/ConfigModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <typeindex>

namespace AMDomain::config {

/**
 * @brief Application-layer port for config persistence operations.
 */
class IConfigStorePort {
public:
  using DumpErrorCallback = std::function<void(ECM)>;
  virtual ~IConfigStorePort() = default;

  /**
   * @brief Load one document or all documents.
   */
  virtual ECM Load(std::optional<AMDomain::config::DocumentKind> kind,
                   bool force) = 0;

  /**
   * @brief Dump one document; optional async scheduling.
   */
  virtual ECM Dump(AMDomain::config::DocumentKind kind,
                   const std::filesystem::path &dst_path, bool async) = 0;

  /**
   * @brief Close store resources and stop background workers.
   */
  virtual void Close() = 0;

  /**
   * @brief Return whether one document has in-memory changes.
   */
  [[nodiscard]] virtual bool
  IsDirty(AMDomain::config::DocumentKind kind) const = 0;

  /**
   * @brief Return storage data path currently tracked for one document.
   */
  [[nodiscard]] virtual bool GetDataPath(AMDomain::config::DocumentKind kind,
                                         std::filesystem::path *out) const = 0;

  /**
   * @brief Bind callback used for async dump/write errors.
   */
  virtual void SetDumpErrorCallback(DumpErrorCallback cb) = 0;

  /**
   * @brief Return project root currently bound to store.
   */
  [[nodiscard]] virtual std::filesystem::path ProjectRoot() const = 0;

  /**
   * @brief Remove old backup timestamp folders and keep max_count directories.
   */
  virtual void PruneBackupFiles(const std::filesystem::path &bak_dir,
                                int64_t max_count) = 0;

  /**
   * @brief Read one typed payload from store.
   */
  [[nodiscard]] virtual bool Read(const std::type_index &type_key,
                                  void *out) const = 0;

  /**
   * @brief Write one typed payload into store.
   */
  [[nodiscard]] virtual bool Write(const std::type_index &type_key,
                                   const void *in) = 0;

  /**
   * @brief Erase one typed payload subtree from store.
   */
  [[nodiscard]] virtual bool Erase(const std::type_index &type_key,
                                   const void *in) = 0;
};

/**
 * @brief Create/configure one config store from init arg.
 */
[[nodiscard]] ECMData<std::unique_ptr<IConfigStorePort>>
CreateConfigStorePort(const ConfigStoreInitArg &arg);

/**
 * @brief Build default config-store init payload for one project root.
 */
[[nodiscard]] ConfigStoreInitArg
BuildDefaultConfigStoreInitArg(const std::filesystem::path &root_dir);
} // namespace AMDomain::config
