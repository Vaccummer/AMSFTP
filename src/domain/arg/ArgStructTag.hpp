#pragma once

namespace AMDomain::arg {
/**
 * @brief Typed payload tag used by config store codec routing.
 */
enum class ConfigPayloadTag {
  HostConfigArg = 1,
  KnownHostEntryArg = 2,
  ConfigBackupSet = 3,
  SettingsOptionsSnapshot = 4,
  UserVarsSnapshot = 5,
  PromptProfileDocument = 6,
  PromptHistoryDocument = 7,
  StyleSnapshot = 8,
  ClientServiceArg = 9,
  FilesystemArg = 10,
  VarSetArg = 11,
  PromptProfileArg = 12,
  PromptHistoryArg = 13,
  StyleConfigArg = 14,
  ConfigStoreInitArg = 15,
};
} // namespace AMDomain::arg

namespace AMDomain::config {
using ConfigPayloadTag = AMDomain::arg::ConfigPayloadTag;
} // namespace AMDomain::config
