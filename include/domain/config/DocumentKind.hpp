#pragma once

namespace AMDomain::config {
/**
 * @brief Configuration document kinds handled by config manager.
 */
enum class DocumentKind {
  Config = 1,
  Settings = 2,
  KnownHosts = 3,
  History = 4
};
} // namespace AMDomain::config

/**
 * @brief Backward-compatible global alias for gradual migration.
 */
using DocumentKind = AMDomain::config::DocumentKind;

