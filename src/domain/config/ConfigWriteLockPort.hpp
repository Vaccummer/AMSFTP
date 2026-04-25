#pragma once

#include "foundation/core/DataClass.hpp"

#include <filesystem>
#include <string>

namespace AMDomain::config {

/**
 * @brief Process-level write lease for persisted config files.
 */
class IConfigWriteLockPort : public NonCopyableNonMovable {
public:
  ~IConfigWriteLockPort() override = default;

  /**
   * @brief Try to acquire the write lease for this process.
   */
  [[nodiscard]] virtual ECM TryAcquire() = 0;

  /**
   * @brief Release the write lease if this process owns it.
   */
  virtual void Release() = 0;

  /**
   * @brief Return whether this process currently owns the lease.
   */
  [[nodiscard]] virtual bool IsHeld() const = 0;

  /**
   * @brief Return the lock file path used by this lease.
   */
  [[nodiscard]] virtual std::filesystem::path LockPath() const = 0;

  /**
   * @brief Return a short owner/debug string for diagnostics.
   */
  [[nodiscard]] virtual std::string OwnerInfo() const = 0;
};

} // namespace AMDomain::config
