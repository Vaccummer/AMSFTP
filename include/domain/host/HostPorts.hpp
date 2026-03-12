#pragma once
#include "domain/host/HostModel.hpp"
#include <utility>

namespace AMDomain::host {
/**
 * @brief Port for loading and saving the full host config snapshot.
 */
class IHostConfigSnapshotStore {
public:
  virtual ~IHostConfigSnapshotStore() = default;

  /**
   * @brief Load the full host configuration snapshot.
   */
  [[nodiscard]] virtual std::pair<ECM, HostConfigArg> LoadSnapshot() const = 0;

  /**
   * @brief Save the full host configuration snapshot and dump it to disk.
   */
  virtual ECM SaveSnapshot(const HostConfigArg &snapshot,
                           bool dump_async = true) = 0;
};

/**
 * @brief Port for loading and saving the full known-host snapshot.
 */
class IKnownHostSnapshotStore {
public:
  virtual ~IKnownHostSnapshotStore() = default;

  /**
   * @brief Load the full known-host snapshot.
   */
  [[nodiscard]] virtual std::pair<ECM, KnownHostEntryArg>
  LoadSnapshot() const = 0;

  /**
   * @brief Save the full known-host snapshot and dump it to disk.
   */
  virtual ECM SaveSnapshot(const KnownHostEntryArg &snapshot,
                           bool dump_async = true) = 0;
};
} // namespace AMDomain::host
