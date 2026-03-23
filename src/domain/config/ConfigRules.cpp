#include "domain/config/ConfigRules.hpp"

#include <algorithm>

namespace AMDomain::config {
/**
 * @brief Clamp backup interval seconds to a safe positive value.
 */
int64_t AMConfigRules::ClampBackupIntervalSeconds(int64_t interval_s) {
  constexpr int64_t kMinIntervalS = 15;
  constexpr int64_t kFallbackS = 60;
  if (interval_s <= 0) {
    return kFallbackS;
  }
  return std::max(kMinIntervalS, interval_s);
}

/**
 * @brief Clamp backup retention count to at least one file.
 */
int64_t AMConfigRules::ClampBackupCount(int64_t max_backup_count) {
  return std::max<int64_t>(1, max_backup_count);
}

/**
 * @brief Normalize persisted backup timestamp into [0, now_s].
 */
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

void AMConfigRules::NormalizeBackupSet(ConfigBackupSet *set, int64_t now_s) {
  if (!set) {
    return;
  }
  set->interval_s = ClampBackupIntervalSeconds(set->interval_s);
  set->max_backup_count = ClampBackupCount(set->max_backup_count);
  set->last_backup_time_s =
      ClampLastBackupTimestamp(set->last_backup_time_s, now_s);
}
} // namespace AMDomain::config
