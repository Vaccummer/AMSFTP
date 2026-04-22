#pragma once
#include "domain/config/ConfigSyncPort.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <map>
#include <string>
#include <vector>

namespace AMApplication::log {
class LoggerAppService;
}

namespace AMApplication::host {
using AMDomain::host::HostConfig;
using AMDomain::host::HostConfigArg;
using AMDomain::host::KnownHostEntryArg;
using AMDomain::host::KnownHostMap;
using AMDomain::host::KnownHostQuery;
using HostConfigMap = std::map<std::string, HostConfig>;
/**
 * @brief Host configuration manager for host map and local profile state.
 */
class HostAppService : public AMDomain::config::IConfigSyncPort {
public:
  explicit HostAppService(AMApplication::log::LoggerAppService *logger =
                              nullptr)
      : IConfigSyncPort(typeid(HostConfigArg)), logger_(logger) {}
  ~HostAppService() override = default;

  /**
   * @brief Initialize manager from explicit host config payload.
   */
  ECM Init(const HostConfigArg &host_config_arg);

  /**
   * @brief Return host config payload including map and local config.
   */
  [[nodiscard]] HostConfigArg GetInitArg() const;

  ECM FlushTo(AMDomain::config::IConfigStorePort *store) override;

  /**
   * @brief Return one host config by nickname.
   */
  [[nodiscard]] ECMData<HostConfig> GetClientConfig(const std::string &nickname,
                                                    bool case_sensitive);

  /**
   * @brief Return local host config currently cached in manager.
   */
  [[nodiscard]] ECMData<HostConfig> GetLocalConfig();

  [[nodiscard]] std::vector<std::string> ListNames() const;

  [[nodiscard]] bool HostExists(const std::string &nickname) const;

  [[nodiscard]] ECMData<std::string>
  CheckNicknameAvailable(const std::string &nickname) const;

  /**
   * @brief Add one host config into map/storage; optionally allow overwrite.
   */
  ECM AddHost(const HostConfig &entry, bool overwrite = true);

  /**
   * @brief Delete one host config by nickname.
   */
  ECM DelHost(const std::string &nickname);

  [[nodiscard]] std::vector<std::string> PrivateKeys() const;

  mutable AMAtomic<HostConfigMap> host_configs_ = {};
  mutable AMAtomic<HostConfig> local_config_ = {};
  mutable AMAtomic<std::vector<std::string>> private_keys_ = {};

private:
  void TraceHost_(const ECM &rcm, const std::string &nickname,
                  const std::string &action,
                  const std::string &message = {}) const;
  AMApplication::log::LoggerAppService *logger_ = nullptr;
};

/**
 * @brief Known-host manager for fingerprint query/upsert operations.
 */
class KnownHostsAppService : public AMDomain::config::IConfigSyncPort {
public:
  explicit KnownHostsAppService(AMApplication::log::LoggerAppService *logger =
                                    nullptr)
      : IConfigSyncPort(typeid(KnownHostEntryArg)), logger_(logger) {}
  ~KnownHostsAppService() override = default;

  /**
   * @brief Initialize manager from explicit known-host snapshot.
   */
  ECM Init(const KnownHostMap &known_hosts);

  [[nodiscard]] KnownHostMap GetInitArg() const;

  ECM FlushTo(AMDomain::config::IConfigStorePort *store) override;

  [[nodiscard]] ECM FindKnownHost(KnownHostQuery &query) const;

  ECM UpsertKnownHost(const KnownHostQuery &query, bool overwrite = true);

private:
  void TraceKnownHost_(const ECM &rcm, const KnownHostQuery &query,
                       const std::string &action,
                       const std::string &message = {}) const;
  AMApplication::log::LoggerAppService *logger_ = nullptr;
  mutable AMAtomic<KnownHostMap> known_hosts_ = {};
};

} // namespace AMApplication::host
