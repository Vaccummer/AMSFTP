#pragma once

#include "foundation/core/DataClass.hpp"

namespace AMApplication::config {
class AMConfigAppService;

/**
 * @brief Application use-case for config auto-backup policy and scheduling.
 */
class AMConfigBackupUseCase {
public:
  /**
   * @brief Execute one backup cycle when policy conditions are met.
   */
  ECM Execute(AMConfigAppService *service);
};
} // namespace AMApplication::config

