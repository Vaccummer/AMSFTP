#pragma once
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
} // namespace AMDomain::config
