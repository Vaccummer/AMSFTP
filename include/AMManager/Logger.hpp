#pragma once
#include "AMManager/Config.hpp"
#include "infrastructure/Logger.hpp"

/**
 * @brief Legacy compatibility wrapper for singleton log manager access.
 */
class AMLogManager : public AMInfraLogManager {
public:
  AMLogManager() { BindConfigManager(&AMConfigManager::Instance()); }

  /**
   * @brief Return process-global compatibility log manager instance.
   * @return Legacy singleton wrapper instance.
   */
  static AMLogManager &Instance() {
    static AMLogManager instance;
    instance.BindConfigManager(&AMConfigManager::Instance());
    return instance;
  }
};
