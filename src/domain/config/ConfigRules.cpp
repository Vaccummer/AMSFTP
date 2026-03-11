#include "domain/config/ConfigRules.hpp"

#include <algorithm>

namespace AMDomain::config {
bool AMConfigRules::TypeTagForDocumentKind(DocumentKind kind,
                                           AMDomain::arg::TypeTag *out) {
  if (!out) {
    return false;
  }
  switch (kind) {
  case DocumentKind::Config:
    *out = AMDomain::arg::TypeTag::Config;
    return true;
  case DocumentKind::Settings:
    *out = AMDomain::arg::TypeTag::Settings;
    return true;
  case DocumentKind::KnownHosts:
    *out = AMDomain::arg::TypeTag::KnownHosts;
    return true;
  case DocumentKind::History:
    *out = AMDomain::arg::TypeTag::History;
    return true;
  default:
    return false;
  }
}

bool AMConfigRules::ReadRootJsonFromArg(AMDomain::arg::TypeTag type,
                                        const void *arg, Json *out) {
  if (!arg || !out) {
    return false;
  }
  switch (type) {
  case AMDomain::arg::TypeTag::Config:
    *out = static_cast<const AMDomain::arg::ConfigArg *>(arg)->value;
    return true;
  case AMDomain::arg::TypeTag::Settings:
    *out = static_cast<const AMDomain::arg::SettingsArg *>(arg)->value;
    return true;
  case AMDomain::arg::TypeTag::KnownHosts:
    *out = static_cast<const AMDomain::arg::KnownHostsArg *>(arg)->value;
    return true;
  case AMDomain::arg::TypeTag::History:
    *out = static_cast<const AMDomain::arg::HistoryArg *>(arg)->value;
    return true;
  default:
    return false;
  }
}

bool AMConfigRules::WriteRootJsonToArg(AMDomain::arg::TypeTag type,
                                       const Json &json, void *arg) {
  if (!arg) {
    return false;
  }
  switch (type) {
  case AMDomain::arg::TypeTag::Config:
    static_cast<AMDomain::arg::ConfigArg *>(arg)->value = json;
    return true;
  case AMDomain::arg::TypeTag::Settings:
    static_cast<AMDomain::arg::SettingsArg *>(arg)->value = json;
    return true;
  case AMDomain::arg::TypeTag::KnownHosts:
    static_cast<AMDomain::arg::KnownHostsArg *>(arg)->value = json;
    return true;
  case AMDomain::arg::TypeTag::History:
    static_cast<AMDomain::arg::HistoryArg *>(arg)->value = json;
    return true;
  default:
    return false;
  }
}

int64_t AMConfigRules::ClampBackupIntervalSeconds(int64_t interval_s) {
  constexpr int64_t kMinIntervalS = 15;
  constexpr int64_t kFallbackS = 60;
  if (interval_s <= 0) {
    return kFallbackS;
  }
  return std::max(kMinIntervalS, interval_s);
}

int64_t AMConfigRules::ClampBackupCount(int64_t max_backup_count) {
  return std::max<int64_t>(1, max_backup_count);
}

int64_t AMConfigRules::ClampLastBackupTimestamp(int64_t last_backup_s,
                                                int64_t now_s) {
  if (last_backup_s < 0) {
    return 0;
  }
  if (last_backup_s > now_s) {
    return now_s;
  }
  return last_backup_s;
}
} // namespace AMDomain::config
