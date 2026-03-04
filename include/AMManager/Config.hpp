#pragma once
#include "infrastructure/Config.hpp"

using AMConfigStorage = AMInfraConfigStorage;

/**
 * @brief Legacy compatibility wrapper for singleton config access.
 */
class AMConfigManager : public AMInfraConfigManager {
public:
  AMConfigManager() = default;

  /**
   * @brief Return process-global compatibility config manager instance.
   * @return Legacy singleton wrapper instance.
   */
  static AMConfigManager &Instance() {
    static AMConfigManager instance;
    return instance;
  }
};
