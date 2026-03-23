#pragma once

#include "domain/config/ConfigModel.hpp"
#include <cstdint>

namespace AMDomain::config {
/**
 * @brief Pure domain rules for backup value normalization.
 */
class AMConfigRules {
public:
  /**
   * @brief Clamp backup interval seconds to a safe positive value.
   */
  [[nodiscard]] static int64_t ClampBackupIntervalSeconds(int64_t interval_s);

  /**
   * @brief Clamp backup retention count to at least one file.
   */
  [[nodiscard]] static int64_t ClampBackupCount(int64_t max_backup_count);

  /**
   * @brief Normalize persisted backup timestamp into [0, now_s].
   */
  [[nodiscard]] static int64_t ClampLastBackupTimestamp(int64_t last_backup_s,
                                                        int64_t now_s);

  /**
   * @brief Normalize one backup policy set in-place.
   */
  static void NormalizeBackupSet(ConfigBackupSet *set, int64_t now_s);
};
} // namespace AMDomain::config
