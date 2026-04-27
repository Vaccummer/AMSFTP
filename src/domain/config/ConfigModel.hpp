#pragma once

#include <cstdint>
#include <filesystem>
#include <unordered_map>

namespace AMDomain::config {
/**
 * @brief Configuration document kinds handled by the config subsystem.
 */
enum class DocumentKind {
  Config = 1,
  Settings = 2,
  KnownHosts = 3
};

/**
 * @brief Backup policy values persisted under `Options.AutoConfigBackup`.
 */
struct ConfigBackupSet {
  bool enabled = true;
  int64_t interval_s = 60;
  int64_t max_backup_count = 3;
  int64_t last_backup_time_s = 0;
};

inline bool operator==(const ConfigBackupSet &lhs, const ConfigBackupSet &rhs) {
  return lhs.enabled == rhs.enabled && lhs.interval_s == rhs.interval_s &&
         lhs.max_backup_count == rhs.max_backup_count &&
         lhs.last_backup_time_s == rhs.last_backup_time_s;
}

inline bool operator!=(const ConfigBackupSet &lhs, const ConfigBackupSet &rhs) {
  return !(lhs == rhs);
}

/**
 * @brief Store bootstrap data for one persisted config document.
 */
struct ConfigDocumentSpec {
  DocumentKind kind = DocumentKind::Config;
  std::filesystem::path data_path = {};
};

using ConfigStoreLayout = std::unordered_map<DocumentKind, ConfigDocumentSpec>;

/**
 * @brief Init payload used to create/configure one config store instance.
 */
struct ConfigStoreInitArg {
  std::filesystem::path root_dir = {};
  ConfigStoreLayout layout = {};
};
} // namespace AMDomain::config
