#pragma once
#include "domain/host/HostModel.hpp"
#include "domain/host/HostPorts.hpp"
#include "foundation/DataClass.hpp"
#include <map>
#include <string>
#include <vector>

namespace AMDomain::host {
/**
 * @brief Host configuration manager for host map and local profile state.
 */
class AMHostConfigManager : public IHostConfigRepository,
                            public NonCopyableNonMovable {
public:
  using HostConfigMap = std::map<std::string, HostConfig>;

  explicit AMHostConfigManager() = default;

  /**
   * @brief Initialize manager from explicit host config payload.
   */
  ECM Init(const HostConfigArg &host_config_arg);

  /**
   * @brief Return one host config by nickname.
   */
  [[nodiscard]] std::pair<ECM, HostConfig>
  GetClientConfig(const std::string &nickname) override;

  /**
   * @brief Return local host config currently cached in manager.
   */
  [[nodiscard]] std::pair<ECM, HostConfig> GetLocalConfig() override;

  /**
   * @brief Return all non-local host configs keyed by nickname.
   */
  [[nodiscard]] const HostConfigMap &HostConfigs() const;

  /**
   * @brief Return host config payload including map and local config.
   */
  [[nodiscard]] HostConfigArg GetInitArg() const;

  [[nodiscard]] std::vector<std::string> ListNames() const override;

  [[nodiscard]] bool HostExists(const std::string &nickname) const override;

  /**
   * @brief Add one host config into map/storage; optionally allow overwrite.
   */
  ECM AddHost(const HostConfig &entry, bool overwrite = true) override;

  /**
   * @brief Delete one host config by nickname.
   */
  ECM DelHost(const std::string &nickname) override;

  [[nodiscard]] std::vector<std::string> PrivateKeys() const;

  // legacy APIs for CLI commands; to be refactored into application or
  // interface layer
  ECM List(bool detailed = true) const;
  ECM Add(const std::string &nickname = "");
  ECM Modify(const std::string &nickname);
  ECM Delete(const std::string &nickname);
  ECM Delete(const std::vector<std::string> &targets);
  ECM Query(const std::string &targets) const;
  ECM Query(const std::vector<std::string> &targets) const;
  ECM Rename(const std::string &old_nickname, const std::string &new_nickname);
  ECM Src() const;
  [[nodiscard]] ECM Save();
  ECM SetHostValue(const std::string &nickname, const std::string &attrname,
                   const std::string &value_str);
  // legacy APIs for CLI commands; to be refactored into application or
  // interface layer

private:
  mutable HostConfigMap host_configs_ = {};
  mutable HostConfig local_config_ = {};
  mutable std::vector<std::string> private_keys_ = {};
};

/**
 * @brief Known-host manager for fingerprint query/upsert operations.
 */
class AMKnownHostsManager : public IKnownHostRepository,
                            public NonCopyableNonMovable {
public:
  explicit AMKnownHostsManager() = default;

  /**
   * @brief Initialize manager from explicit known-host snapshot.
   */
  ECM Init(const KnownHostMap &known_hosts);

  /**
   * @brief Return in-memory known-host mapping.
   */
  [[nodiscard]] const KnownHostMap &KnownHosts() const;

  [[nodiscard]] ECM FindKnownHost(KnownHostQuery &query) const override;
  ECM UpsertKnownHost(const KnownHostQuery &query,
                      bool overwrite = true) override;

private:
  mutable KnownHostMap known_hosts_ = {};
};
} // namespace AMDomain::host


