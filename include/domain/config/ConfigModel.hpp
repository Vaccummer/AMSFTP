#pragma once
#include "domain/arg/ArgTypes.hpp"
#include <filesystem>
#include <string>

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

/**
 * @brief Initialization payload for one config handle.
 */
struct HandleInitSpec {
  DocumentKind kind = DocumentKind::Config;
  std::filesystem::path path;
  std::string schema_json;
  std::filesystem::path schema_path;
};

inline bool FindDocumentKind(AMDomain::arg::TypeTag type,
                             AMDomain::config::DocumentKind *out) {
  if (!out) {
    return false;
  }

  using AMDomain::config::DocumentKind;
  switch (type) {
  case AMDomain::arg::TypeTag::Config:
    *out = DocumentKind::Config;
    return true;
  case AMDomain::arg::TypeTag::Settings:
    *out = DocumentKind::Settings;
    return true;
  case AMDomain::arg::TypeTag::KnownHosts:
    *out = DocumentKind::KnownHosts;
    return true;
  case AMDomain::arg::TypeTag::History:
    *out = DocumentKind::History;
    return true;
  case AMDomain::arg::TypeTag::HostConfig:
    *out = DocumentKind::Config;
    return true;
  case AMDomain::arg::TypeTag::KnownHostEntry:
    *out = DocumentKind::KnownHosts;
    return true;
  default:
    return false;
  }
}
} // namespace AMDomain::config
