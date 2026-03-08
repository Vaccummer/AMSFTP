#pragma once
#include "domain/host/HostModel.hpp"
#include <map>
#include <string>
#include <utility>

namespace AMDomain::host {
/**
 * @brief Domain service for host-manager validation and lookup rules.
 */
class HostManagerService {
public:
  using HostConfigMap = std::map<std::string, HostConfig>;

  /**
   * @brief Check whether nickname maps to local profile.
   *
   * Any case variant of "local" is treated as local nickname.
   */
  [[nodiscard]] static bool IsLocalNickname(const std::string &nickname);

  /**
   * @brief Check whether nickname already exists in map/local profile.
   */
  [[nodiscard]] static bool
  NicknameExists(const HostConfigMap &host_configs, const std::string &nickname,
                 const HostConfig *local_config = nullptr);

  /**
   * @brief Validate host config using request checks + nickname rules.
   */
  [[nodiscard]] static bool IsValidConfig(const HostConfig &config,
                                          std::string *error_info = nullptr);

  /**
   * @brief Validate request using existing request checks + nickname rules.
   */
  [[nodiscard]] static bool IsValidConfig(const ConRequest &request,
                                          std::string *error_info = nullptr);

  /**
   * @brief Get config by nickname from map/local profile.
   */
  [[nodiscard]] static std::pair<ECM, HostConfig>
  GetConfigByNickname(const HostConfigMap &host_configs,
                      const std::string &nickname,
                      const HostConfig *local_config = nullptr);
};

/**
 * @brief Domain service for known-host query validation/resolve rules.
 */
class KnownHostService {
public:
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

  /**
   * @brief Check whether one known-host query key already exists in map.
   */
  [[nodiscard]] bool QueryExists(const KnownHostMap &known_hosts,
                                 const KnownHostQuery &query) const;
};

/**
 * @brief Backward-compatible alias kept during service rename migration.
 */
using HostDomainService = HostManagerService;
} // namespace AMDomain::host



