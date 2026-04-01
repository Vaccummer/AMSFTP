#pragma once
#include "domain/host/HostModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <map>
#include <string>
#include <vector>

namespace AMApplication::host {
/**
 * @brief Host configuration manager for host map and local profile state.
 */
class HostAppService : public NonCopyableNonMovable {
public:
  using HostConfigMap = std::map<std::string, AMDomain::host::HostConfig>;
  using HostConfigArg = AMDomain::host::HostConfigArg;
  using HostConfig = AMDomain::host::HostConfig;

  explicit HostAppService() = default;
  ~HostAppService() override = default;

  /**
   * @brief Initialize manager from explicit host config payload.
   */
  ECM Init(const HostConfigArg &host_config_arg);

  /**
   * @brief Return host config payload including map and local config.
   */
  [[nodiscard]] HostConfigArg GetInitArg() const;

  /**
   * @brief Return one host config by nickname.
   */
  [[nodiscard]] ECMData<HostConfig>
  GetClientConfig(const std::string &nickname, bool case_sensitive);

  /**
   * @brief Return local host config currently cached in manager.
   */
  [[nodiscard]] ECMData<HostConfig> GetLocalConfig();

  /**
   * @brief Return all non-local host configs keyed by nickname.
   */
  [[nodiscard]] const HostConfigMap &HostConfigs() const;

  [[nodiscard]] std::vector<std::string> ListNames() const;

  [[nodiscard]] bool HostExists(const std::string &nickname) const;

  /**
   * @brief Add one host config into map/storage; optionally allow overwrite.
   */
  ECM AddHost(const HostConfig &entry, bool overwrite = true);

  /**
   * @brief Delete one host config by nickname.
   */
  ECM DelHost(const std::string &nickname);

  [[nodiscard]] std::vector<std::string> PrivateKeys() const;

  mutable HostConfigMap host_configs_ = {};
  mutable HostConfig local_config_ = {};
  mutable std::vector<std::string> private_keys_ = {};
};

/**
 * @brief Known-host manager for fingerprint query/upsert operations.
 */
class AMKnownHostsAppService : public NonCopyableNonMovable {
public:
  using KnownHostQuery = AMDomain::host::KnownHostQuery;
  using KnownHostMap = AMDomain::host::KnownHostMap;
  using KnownHostEntryArg = AMDomain::host::KnownHostEntryArg;
  explicit AMKnownHostsAppService() = default;
  virtual ~AMKnownHostsAppService() override = default;

  /**
   * @brief Initialize manager by loading known-host snapshot from store.
   */
  ECM Init();

  /**
   * @brief Initialize manager from explicit known-host snapshot.
   */
  ECM Init(const KnownHostMap &known_hosts);

  /**
   * @brief Return in-memory known-host mapping.
   */
  [[nodiscard]] const KnownHostMap &KnownHosts() const;

  [[nodiscard]] ECM FindKnownHost(KnownHostQuery &query) const;
  ECM UpsertKnownHost(const KnownHostQuery &query, bool overwrite = true);

private:
  ECM EnsureSnapshotLoaded_() const;
  ECM LoadSnapshot_() const;
  [[nodiscard]] KnownHostEntryArg SnapshotFromCache_() const;
  ECM PersistSnapshot_(const KnownHostEntryArg &snapshot,
                       bool dump_async = true);
  void ResetSnapshotCache_();

  mutable KnownHostMap known_hosts_ = {};
  mutable bool snapshot_loaded_ = false;
};
} // namespace AMApplication::host
