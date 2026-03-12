#pragma once

#include "application/config/ConfigBackupUseCase.hpp"
#include "application/config/ConfigStorePort.hpp"
#include "foundation/DataClass.hpp"
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <type_traits>
#include <typeindex>

namespace AMApplication::config {
/**
 * @brief Application service orchestrating config store operations.
 */
class AMConfigAppService : NonCopyable {
public:
  using DumpErrorCallback = std::function<void(ECM)>;

  /**
   * @brief Construct one app service with optional bound dependencies.
   */
  explicit AMConfigAppService(IConfigStorePort *store = nullptr,
                              AMConfigBackupUseCase *backup_use_case = nullptr);

  /**
   * @brief Bind store and use-case dependencies.
   */
  void Bind(IConfigStorePort *store, AMConfigBackupUseCase *backup_use_case);

  /**
   * @brief Load one document or all documents from store.
   */
  ECM Load(std::optional<AMDomain::config::DocumentKind> kind = std::nullopt,
           bool force = false);

  /**
   * @brief Dump one document; optional async scheduling.
   */
  ECM Dump(AMDomain::config::DocumentKind kind,
           const std::string &dst_path = "", bool async = false);

  /**
   * @brief Dump all documents; optional async scheduling.
   */
  ECM DumpAll(bool async = false);

  /**
   * @brief Close store resources and reset app state.
   */
  void CloseHandles();

  /**
   * @brief Bind callback invoked on write/dump failures.
   */
  void SetDumpErrorCallback(DumpErrorCallback cb);

  /**
   * @brief Return whether one document is dirty in store.
   */
  [[nodiscard]] bool IsDirty(AMDomain::config::DocumentKind kind) const;

  /**
   * @brief Execute auto-backup use-case.
   */
  ECM BackupIfNeeded();

  /**
   * @brief Submit one asynchronous write task.
   */
  void SubmitWriteTask(std::function<ECM()> task);

  /**
   * @brief Return data file path for one document.
   */
  [[nodiscard]] bool GetDataPath(AMDomain::config::DocumentKind kind,
                                 std::filesystem::path *value) const;

  /**
   * @brief Return project root path.
   */
  [[nodiscard]] std::filesystem::path ProjectRoot() const;

  /**
   * @brief Ensure one directory exists.
   */
  ECM EnsureDirectory(const std::filesystem::path &dir);

  /**
   * @brief Prune old backups matching naming convention.
   */
  void PruneBackupFiles(const std::filesystem::path &dir,
                        const std::string &prefix, const std::string &suffix,
                        int64_t max_count);

  /**
   * @brief Read one typed payload from store.
   */
  template <typename T> [[nodiscard]] bool Read(T *out) const {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    if (!out || !store_) {
      return false;
    }
    return store_->Read(std::type_index(typeid(ValueT)),
                        static_cast<void *>(out));
  }

  /**
   * @brief Write one typed payload into store.
   */
  template <typename T> [[nodiscard]] bool Write(const T &value) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    if (!store_) {
      return false;
    }
    return store_->Write(std::type_index(typeid(ValueT)),
                         static_cast<const void *>(&value));
  }

  /**
   * @brief Erase one typed payload subtree from store.
   */
  template <typename T> [[nodiscard]] bool Erase(const T &value) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    if (!store_) {
      return false;
    }
    return store_->Erase(std::type_index(typeid(ValueT)),
                         static_cast<const void *>(&value));
  }

private:
  IConfigStorePort *store_ = nullptr;
  AMConfigBackupUseCase *backup_use_case_ = nullptr;
  DumpErrorCallback dump_error_cb_;
};
} // namespace AMApplication::config
