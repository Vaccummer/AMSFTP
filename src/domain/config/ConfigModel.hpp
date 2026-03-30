#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>

namespace AMDomain::config {
/**
 * @brief Configuration document kinds handled by the config subsystem.
 */
enum class DocumentKind {
  Config = 1,
  Settings = 2,
  KnownHosts = 3,
  History = 4
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

/**
 * @brief Settings payload for `Options.TransferManager`.
 */
struct TransferManagerArg {
  int init_thread_num = 1;
  int max_thread_num = 16;
};

/**
 * @brief Settings payload for `Options.LogManager`.
 */
struct LogManagerArg {
  int client_trace_level = 4;
  int program_trace_level = 4;
};

/**
 * @brief Store bootstrap data for one persisted config document.
 */
struct ConfigDocumentSpec {
  DocumentKind kind = DocumentKind::Config;
  std::filesystem::path data_path = {};
  std::string schema_json = "{}";
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
