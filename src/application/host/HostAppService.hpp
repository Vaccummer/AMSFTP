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
class AMHostAppService : public NonCopyableNonMovable {
public:
  using HostConfigMap = std::map<std::string, AMDomain::host::HostConfig>;
  using HostConfigArg = AMDomain::host::HostConfigArg;
  using HostConfig = AMDomain::host::HostConfig;

  explicit AMHostAppService() = default;
  virtual ~AMHostAppService() override = default;

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
  [[nodiscard]] std::pair<ECM, HostConfig>
  GetClientConfig(const std::string &nickname);

  /**
   * @brief Return local host config currently cached in manager.
   */
  [[nodiscard]] std::pair<ECM, HostConfig> GetLocalConfig();

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
  ECM EnsureSnapshotLoaded_() const;
  ECM LoadSnapshot_() const;
  [[nodiscard]] HostConfigArg SnapshotFromCache_() const;
  ECM PersistSnapshot_(const HostConfigArg &snapshot, bool dump_async = true);
  void ResetSnapshotCache_();

  mutable HostConfigMap host_configs_ = {};
  mutable HostConfig local_config_ = {};
  mutable std::vector<std::string> private_keys_ = {};
  mutable bool snapshot_loaded_ = false;
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
