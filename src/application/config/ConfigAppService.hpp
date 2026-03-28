#pragma once

#include "domain/arg/ArgStructTag.hpp"
#include "domain/config/ConfigModel.hpp"
#include "domain/config/ConfigStorePort.hpp"
#include "foundation/core/DataClass.hpp"
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace AMDomain::host {
struct HostConfigArg;
struct KnownHostEntryArg;
}
namespace AMDomain::client {
struct ClientServiceArg;
}
namespace AMDomain::filesystem {
struct FilesystemArg;
}
namespace AMDomain::var {
struct VarSetArg;
}
namespace AMDomain::prompt {
struct PromptProfileArg;
struct PromptHistoryArg;
}
namespace AMDomain::style {
struct StyleConfigArg;
}

namespace AMApplication::config {
struct SettingsOptionsSnapshot;
struct UserVarsSnapshot;
struct PromptProfileDocument;
struct PromptHistoryDocument;
struct AMStyleSnapshot;

using IConfigStorePort = AMDomain::config::IConfigStorePort;
using ConfigBackupSet = AMDomain::config::ConfigBackupSet;
using ConfigStoreInitArg = AMDomain::config::ConfigStoreInitArg;

namespace detail {
template <typename T> struct ConfigPayloadTagTraits {
  static constexpr bool kMapped = false;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::ConfigStoreInitArg;
};

template <typename T>
[[nodiscard]] constexpr std::optional<AMDomain::config::ConfigPayloadTag>
ResolveConfigPayloadTag() {
  using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
  if constexpr (ConfigPayloadTagTraits<ValueT>::kMapped) {
    return ConfigPayloadTagTraits<ValueT>::kTag;
  }
  return std::nullopt;
}

template <> struct ConfigPayloadTagTraits<AMDomain::host::HostConfigArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::HostConfigArg;
};
template <> struct ConfigPayloadTagTraits<AMDomain::host::KnownHostEntryArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::KnownHostEntryArg;
};
template <> struct ConfigPayloadTagTraits<ConfigBackupSet> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::ConfigBackupSet;
};
template <> struct ConfigPayloadTagTraits<SettingsOptionsSnapshot> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::SettingsOptionsSnapshot;
};
template <> struct ConfigPayloadTagTraits<UserVarsSnapshot> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::UserVarsSnapshot;
};
template <> struct ConfigPayloadTagTraits<PromptProfileDocument> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::PromptProfileDocument;
};
template <> struct ConfigPayloadTagTraits<PromptHistoryDocument> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::PromptHistoryDocument;
};
template <> struct ConfigPayloadTagTraits<AMStyleSnapshot> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::StyleSnapshot;
};
template <> struct ConfigPayloadTagTraits<AMDomain::client::ClientServiceArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::ClientServiceArg;
};
template <> struct ConfigPayloadTagTraits<AMDomain::filesystem::FilesystemArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::FilesystemArg;
};
template <> struct ConfigPayloadTagTraits<AMDomain::var::VarSetArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::VarSetArg;
};
template <> struct ConfigPayloadTagTraits<AMDomain::prompt::PromptProfileArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::PromptProfileArg;
};
template <> struct ConfigPayloadTagTraits<AMDomain::prompt::PromptHistoryArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::PromptHistoryArg;
};
template <> struct ConfigPayloadTagTraits<AMDomain::style::StyleConfigArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::StyleConfigArg;
};
template <> struct ConfigPayloadTagTraits<ConfigStoreInitArg> {
  static constexpr bool kMapped = true;
  static constexpr AMDomain::config::ConfigPayloadTag kTag =
      AMDomain::config::ConfigPayloadTag::ConfigStoreInitArg;
};
} // namespace detail

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
    const auto tag = detail::ResolveConfigPayloadTag<ValueT>();
    if (!tag.has_value()) {
      return false;
    }
    const bool ok = store_->Read(tag.value(), static_cast<void *>(out));
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
    const auto tag = detail::ResolveConfigPayloadTag<ValueT>();
    if (!tag.has_value()) {
      return false;
    }
    const bool ok = store_->Write(tag.value(), static_cast<const void *>(&value));
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
    const auto tag = detail::ResolveConfigPayloadTag<ValueT>();
    if (!tag.has_value()) {
      return false;
    }
    const bool ok = store_->Erase(tag.value(), static_cast<const void *>(&value));
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
