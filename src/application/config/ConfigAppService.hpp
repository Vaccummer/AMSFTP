#pragma once

#include "domain/config/ConfigModel.hpp"
#include "domain/config/ConfigStorePort.hpp"
#include "foundation/core/DataClass.hpp"
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <typeindex>
#include <vector>

namespace AMApplication::config {
using IConfigStorePort = AMDomain::config::IConfigStorePort;
using ConfigBackupSet = AMDomain::config::ConfigBackupSet;
using ConfigStoreInitArg = AMDomain::config::ConfigStoreInitArg;
/**
 * @brief Application service orchestrating config store operations.
 */
class AMConfigAppService : NonCopyable {
public:
  using DumpErrorCallback = std::function<void(ECM)>;

  /**
   * @brief Construct one app service with store init payload.
   */
  explicit AMConfigAppService(ConfigStoreInitArg init_arg = {});

  /**
   * @brief Build one owned config store from init arg.
   */
  ECM Init();

  /**
   * @brief Update store init payload used by Init().
   */
  void SetInitArg(ConfigStoreInitArg init_arg);

  /**
   * @brief Return current store init payload.
   */
  [[nodiscard]] ConfigStoreInitArg GetInitArg() const;

  /**
   * @brief Bind store dependency.
   */
  void Bind(IConfigStorePort *store);

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
   * @brief Execute one backup cycle when policy conditions are met.
   */
  ECM BackupIfNeeded();

  std::vector<ECM>
  Backup(const std::vector<AMDomain::config::DocumentKind> &kinds = {});

  /**
   * @brief Return true when current backup policy requires a backup now.
   */
  [[nodiscard]] bool IsBackupNeeded() const;

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
   * @brief Prune old backup timestamp folders under one backup directory.
   */
  void PruneBackupFiles(const std::filesystem::path &bak_dir,
                        int64_t max_count);

  /**
   * @brief Read one typed payload from store.
   */
  template <typename T> [[nodiscard]] bool Read(T *out) const {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    if (!out || !store_) {
      return false;
    }
    const bool ok =
        store_->Read(std::type_index(typeid(ValueT)), static_cast<void *>(out));
    if constexpr (std::is_same_v<ValueT, ConfigBackupSet>) {
      if (ok) {
        auto backup_set = backup_set_.lock();
        backup_set.store(*out);
      }
    }
    return ok;
  }

  /**
   * @brief Write one typed payload into store.
   */
  template <typename T> [[nodiscard]] bool Write(const T &value) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    if (!store_) {
      return false;
    }
    const bool ok = store_->Write(std::type_index(typeid(ValueT)),
                                  static_cast<const void *>(&value));
    if constexpr (std::is_same_v<ValueT, ConfigBackupSet>) {
      if (ok) {
        auto backup_set = backup_set_.lock();
        backup_set.store(value);
      }
    }
    return ok;
  }

  /**
   * @brief Erase one typed payload subtree from store.
   */
  template <typename T> [[nodiscard]] bool Erase(const T &value) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    if (!store_) {
      return false;
    }
    const bool ok = store_->Erase(std::type_index(typeid(ValueT)),
                                  static_cast<const void *>(&value));
    if constexpr (std::is_same_v<ValueT, ConfigBackupSet>) {
      if (ok) {
        auto backup_set = backup_set_.lock();
        backup_set.store(ConfigBackupSet{});
      }
    }
    return ok;
  }

private:
  struct BackupTargets {
    std::filesystem::path backup_dir = {};
    std::filesystem::path stamp_dir = {};
    std::filesystem::path config_file = {};
    std::filesystem::path settings_file = {};
    std::filesystem::path known_hosts_file = {};
    std::filesystem::path history_file = {};
  };

  [[nodiscard]] ConfigBackupSet LoadBackupSet_() const;
  [[nodiscard]] BackupTargets BuildBackupTargets_(int64_t backup_time_s) const;
  void PruneBackupFolders_(const std::filesystem::path &bak_dir,
                           int64_t max_count);
  static void CleanupLegacyBackupFiles_(const std::filesystem::path &bak_dir);
  static bool IsBackupSetEqual_(const ConfigBackupSet &lhs,
                                const ConfigBackupSet &rhs);
  static std::vector<AMDomain::config::DocumentKind>
  ResolveBackupKinds_(const std::vector<AMDomain::config::DocumentKind> &kinds);
  [[nodiscard]] std::filesystem::path
  ResolveBackupPath_(const BackupTargets &targets,
                     AMDomain::config::DocumentKind kind) const;

  mutable AMAtomic<ConfigStoreInitArg> init_arg_ = {};
  mutable AMAtomic<ConfigBackupSet> backup_set_ = {};
  std::unique_ptr<IConfigStorePort> owned_store_ = nullptr;
  IConfigStorePort *store_ = nullptr;
  DumpErrorCallback dump_error_cb_;
};
} // namespace AMApplication::config
