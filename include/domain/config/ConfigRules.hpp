#pragma once

#include "domain/arg/ArgTypes.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/tools/json.hpp"

namespace AMDomain::config {
/**
 * @brief Pure domain rules for config type/document and value normalization.
 */
class AMConfigRules {
public:
  /**
   * @brief Map one document kind to arg runtime type tag.
   */
  [[nodiscard]] static bool TypeTagForDocumentKind(
      DocumentKind kind, AMDomain::arg::TypeTag *out);

  /**
   * @brief Read root JSON from one typed arg payload.
   */
  [[nodiscard]] static bool ReadRootJsonFromArg(AMDomain::arg::TypeTag type,
                                                const void *arg, Json *out);

  /**
   * @brief Write root JSON into one typed arg payload.
   */
  [[nodiscard]] static bool WriteRootJsonToArg(AMDomain::arg::TypeTag type,
                                               const Json &json, void *arg);

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
};
} // namespace AMDomain::config

