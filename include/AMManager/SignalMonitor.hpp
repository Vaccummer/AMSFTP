#pragma once
#include "infrastructure/SignalMonitor.hpp"

/**
 * @brief Legacy compatibility wrapper for singleton signal-monitor access.
 */
class AMCliSignalMonitor : public AMInfraCliSignalMonitor {
public:
  AMCliSignalMonitor() = default;

  /**
   * @brief Bind compatibility token for legacy singleton monitor access.
   * @param token Token shared by legacy call paths.
   */
  static void SetCompatibilityTaskControlToken(
      const std::shared_ptr<TaskControlToken> &token) {
    CompatibilityTaskControlToken_() = token;
    Instance().BindTaskControlToken(token);
  }

  /**
   * @brief Clear compatibility token binding for legacy singleton monitor.
   */
  static void ClearCompatibilityTaskControlToken() {
    CompatibilityTaskControlToken_().reset();
    Instance().ClearTaskControlToken();
  }

  /**
   * @brief Return process-global compatibility signal monitor instance.
   * @return Legacy singleton wrapper instance.
   */
  static AMCliSignalMonitor &Instance() {
    static AMCliSignalMonitor instance;
    const auto token = CompatibilityTaskControlToken_();
    if (token) {
      instance.BindTaskControlToken(token);
    }
    return instance;
  }

private:
  /**
   * @brief Shared compatibility token binding for legacy singleton access.
   * @return Mutable shared pointer storage for compatibility token.
   */
  static std::shared_ptr<TaskControlToken> &CompatibilityTaskControlToken_() {
    static std::shared_ptr<TaskControlToken> token = nullptr;
    return token;
  }
};
