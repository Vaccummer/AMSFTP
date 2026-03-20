#pragma once

#include "domain/config/ConfigModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <typeindex>

namespace AMApplication::config {
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
   * @brief Dump all documents; optional async scheduling.
   */
  virtual ECM DumpAll(bool async) = 0;

  /**
   * @brief Close store resources and stop background workers.
   */
  virtual void Close() = 0;

  /**
   * @brief Return whether one document has in-memory changes.
   */
  [[nodiscard]] virtual bool IsDirty(AMDomain::config::DocumentKind kind) const = 0;

  /**
   * @brief Return storage data path currently tracked for one document.
   */
  [[nodiscard]] virtual bool
  GetDataPath(AMDomain::config::DocumentKind kind,
              std::filesystem::path *out) const = 0;

  /**
   * @brief Read one typed payload from store.
   */
  [[nodiscard]] virtual bool Read(const std::type_index &type,
                                  void *out) const = 0;

  /**
   * @brief Write one typed payload into store.
   */
  [[nodiscard]] virtual bool Write(const std::type_index &type,
                                   const void *in) = 0;

  /**
   * @brief Erase one typed payload subtree from store.
   */
  [[nodiscard]] virtual bool Erase(const std::type_index &type,
                                   const void *in) = 0;

  /**
   * @brief Bind callback used for async dump/write errors.
   */
  virtual void SetDumpErrorCallback(DumpErrorCallback cb) = 0;

  /**
   * @brief Submit one write task to store scheduler.
   */
  virtual void SubmitWriteTask(std::function<ECM()> task) = 0;

  /**
   * @brief Return project root currently bound to store.
   */
  [[nodiscard]] virtual std::filesystem::path ProjectRoot() const = 0;

  /**
   * @brief Ensure one directory exists.
   */
  virtual ECM EnsureDirectory(const std::filesystem::path &dir) = 0;

  /**
   * @brief Remove old backups matching prefix/suffix and keep max_count files.
   */
  virtual void PruneBackupFiles(const std::filesystem::path &dir,
                                const std::string &prefix,
                                const std::string &suffix,
                                int64_t max_count) = 0;
};
} // namespace AMApplication::config
