#pragma once
#include "domain/host/HostModel.hpp"
#include "domain/host/KnownHostQuery.hpp"
#include <string>
#include <unordered_map>
#include <vector>

namespace AMDomain::host {
/**
 * @brief Pure domain service for host model validation and in-memory rules.
 *
 * This service contains no direct dependency on infrastructure storage or CLI.
 */
class HostDomainService {
public:
  using HostConfigMap = std::unordered_map<std::string, HostConfig>;

  /**
   * @brief Build normalized host config map from raw host json.
   *
   * @param hosts_json Raw host object json.
   * @param local_fallback Prebuilt local fallback config.
   * @param local_user Runtime local username.
   */
  [[nodiscard]] HostConfigMap CollectHosts(const Json &hosts_json,
                                           const HostConfig &local_fallback,
                                           const std::string &local_user) const;

  /**
   * @brief Lookup one host config from map by nickname.
   */
  [[nodiscard]] std::pair<ECM, HostConfig>
  GetClientConfig(const HostConfigMap &host_configs,
                  const std::string &nickname) const;

  /**
   * @brief Build one local host config from optional local json and defaults.
   */
  [[nodiscard]] std::pair<ECM, HostConfig>
  BuildLocalConfig(const Json *local_json, const std::string &local_user,
                   const std::string &fallback_home,
                   const std::string &fallback_trash) const;

  /**
   * @brief Validate host upsert request.
   */
  [[nodiscard]] ECM ValidateHostUpsert(const HostConfig &entry) const;

  /**
   * @brief Return whether nickname exists in host config map.
   */
  [[nodiscard]] bool HostExists(const HostConfigMap &host_configs,
                                const std::string &nickname) const;

  /**
   * @brief List sorted host nicknames from host config map.
   */
  [[nodiscard]] std::vector<std::string>
  ListNames(const HostConfigMap &host_configs) const;

  /**
   * @brief Upsert one host config into an in-memory host map.
   */
  [[nodiscard]] ECM UpsertHostInMemory(HostConfigMap *host_configs,
                                       const std::string &nickname,
                                       const HostConfig &entry) const;

  /**
   * @brief Remove one host config from an in-memory host map.
   */
  [[nodiscard]] ECM RemoveHostInMemory(HostConfigMap *host_configs,
                                       const std::string &nickname) const;

  /**
   * @brief Validate and fill known-host query from resolved fingerprint text.
   */
  [[nodiscard]] ECM ResolveKnownHostQuery(KnownHostQuery *query,
                                          const std::string &fingerprint) const;

  /**
   * @brief Validate known-host upsert and return stripped fingerprint.
   */
  [[nodiscard]] ECM ValidateKnownHostUpsert(const KnownHostQuery &query,
                                            std::string *fingerprint) const;
};
} // namespace AMDomain::host

