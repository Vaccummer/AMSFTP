#pragma once
#include "domain/host/HostModel.hpp"
#include <string>
#include <utility>
#include <vector>

namespace AMDomain::host {
/**
 * @brief Port for reading and writing host config entries.
 */
class IHostConfigRepository {
public:
  virtual ~IHostConfigRepository() = default;

  /**
   * @brief Get one host configuration by nickname.
   */
  virtual std::pair<ECM, HostConfig>
  GetClientConfig(const std::string &nickname) = 0;

  /**
   * @brief Get synthesized local host configuration.
   */
  virtual std::pair<ECM, HostConfig> GetLocalConfig() = 0;

  /**
   * @brief Add one host configuration entry; optionally allow overwrite.
   */
  virtual ECM AddHost(const HostConfig &entry, bool overwrite = true) = 0;

  /**
   * @brief Delete one host configuration entry by nickname.
   */
  virtual ECM DelHost(const std::string &nickname) = 0;

  /**
   * @brief Return whether the nickname exists.
   */
  [[nodiscard]] virtual bool HostExists(const std::string &nickname) const = 0;

  /**
   * @brief List all configured host nicknames.
   */
  [[nodiscard]] virtual std::vector<std::string> ListNames() const = 0;
};

/**
 * @brief Port for known-host fingerprint persistence.
 */
class IKnownHostRepository {
public:
  virtual ~IKnownHostRepository() = default;

  /**
   * @brief Lookup one known-host fingerprint.
   */
  [[nodiscard]] virtual ECM FindKnownHost(KnownHostQuery &query) const = 0;

  /**
   * @brief Insert or update one known-host fingerprint.
   */
  virtual ECM UpsertKnownHost(const KnownHostQuery &query,
                              bool overwrite = true) = 0;
};
} // namespace AMDomain::host



