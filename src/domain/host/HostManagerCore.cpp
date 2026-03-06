#include "domain/host/HostDomainService.hpp"
#include "interface/ApplicationAdapters.hpp"
#include "foundation/Path.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/json.hpp"
#include "domain/host/HostManager.hpp"
#include <string>

namespace {
/**
 * @brief Resolve the local username from environment variables.
 */
std::string GetLocalUsername_() {
  std::string local_user = "";
#ifdef _WIN32
  AMStr::GetEnv("USERNAME", &local_user);
#else
  AMStr::GetEnv("USER", &local_user);
#endif
  if (local_user.empty()) {
    local_user = "local";
  }
  return local_user;
}

/**
 * @brief Return shared host domain service instance.
 */
AMDomain::host::HostDomainService &HostDomainService_() {
  static AMDomain::host::HostDomainService service;
  return service;
}

/**
 * @brief Return whether one hostname already exists in configured host entries.
 */
bool HostnameExistsInConfig_(const std::string &hostname) {
  Json hosts_json;
  AMInfraConfigManager &config =
      AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow();
  if (!config.ResolveArg(DocumentKind::Config, {configkn::hosts}, &hosts_json) ||
      !hosts_json.is_object()) {
    return false;
  }

  const std::string target = AMStr::lowercase(AMStr::Strip(hostname));
  for (auto it = hosts_json.begin(); it != hosts_json.end(); ++it) {
    if (!it.value().is_object()) {
      continue;
    }
    std::string existing_hostname;
    AMJson::QueryKey(it.value(), {configkn::hostname}, &existing_hostname);
    if (AMStr::lowercase(AMStr::Strip(existing_hostname)) == target) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Bind manager-side hostname existence checker into domain validator.
 */
const bool kBindHostnameExistsChecker_ = []() {
  configkn::SetHostnameExistsChecker(HostnameExistsInConfig_);
  return true;
}();
} // namespace

ECM AMDomain::host::AMHostManager::Save() {
  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
      DocumentKind::Config, "", true);
}

void AMDomain::host::AMHostManager::CollectHosts_() const {
  Json hosts_json;
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
           .ResolveArg(DocumentKind::Config, {configkn::hosts}, &hosts_json)) {
    host_configs.clear();
    return;
  }

  HostConfig local_fallback;
  auto [local_rcm, local_cfg] =
      const_cast<AMDomain::host::AMHostManager *>(this)->GetLocalConfig();
  if (local_rcm.first == EC::Success && local_cfg.IsValid()) {
    local_fallback = local_cfg;
  }

  host_configs = HostDomainService_().CollectHosts(hosts_json, local_fallback,
                                                   GetLocalUsername_());
}

std::pair<ECM, HostConfig>
AMDomain::host::AMHostManager::GetClientConfig(const std::string &nickname) {
  return HostDomainService_().GetClientConfig(host_configs, nickname);
}

/**
 * @brief Get local client config from config storage or use defaults.
 */
std::pair<ECM, HostConfig> AMDomain::host::AMHostManager::GetLocalConfig() {
  const std::string local_user = GetLocalUsername_();
  const std::string fallback_home = AMFS::HomePath();

  std::string root_dir = "";
  if (!AMStr::GetEnv("AMSFTP_ROOT", &root_dir) || root_dir.empty()) {
    root_dir =
        AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
            .ProjectRoot()
            .string();
  }
  const std::string fallback_trash = AMPathStr::join(root_dir, "trash");

  Json host_json;
  Json *local_ptr = nullptr;
  if (AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
          .ResolveArg(DocumentKind::Config, {configkn::hosts, "local"},
                      &host_json) &&
      host_json.is_object()) {
    local_ptr = &host_json;
  }

  return HostDomainService_().BuildLocalConfig(local_ptr, local_user,
                                               fallback_home, fallback_trash);
}

ECM AMDomain::host::AMHostManager::UpsertHost(const HostConfig &entry,
                                              bool dump_now) {
  ECM validate_rcm = HostDomainService_().ValidateHostUpsert(entry);
  if (validate_rcm.first != EC::Success) {
    return validate_rcm;
  }
  ECM rcm = AddHost_(entry.request.nickname, entry);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (!dump_now) {
    return Ok();
  }
  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
      DocumentKind::Config, "", true);
}

ECM AMDomain::host::AMHostManager::FindKnownHost(KnownHostQuery &query) const {
  std::string fingerprint = "";
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
           .ResolveArg(DocumentKind::KnownHosts, query.GetPath(),
                       &fingerprint)) {
    return ECM{EC::HostConfigNotFound,
               "fingerprint not found for given host query"};
  }
  return HostDomainService_().ResolveKnownHostQuery(&query, fingerprint);
}

ECM AMDomain::host::AMHostManager::UpsertKnownHost(const KnownHostQuery &query,
                                                   bool dump_now) {
  std::string fingerprint;
  ECM validate_rcm =
      HostDomainService_().ValidateKnownHostUpsert(query, &fingerprint);
  if (validate_rcm.first != EC::Success) {
    return validate_rcm;
  }
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().SetArg(
          DocumentKind::KnownHosts, query.GetPath(), fingerprint)) {
    return Err(EC::CommonFailure, "failed to write known_hosts data");
  }
  if (!dump_now) {
    return Ok();
  }
  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
      DocumentKind::KnownHosts, "", true);
}

bool AMDomain::host::AMHostManager::HostExists(const std::string &nickname) const {
  return HostDomainService_().HostExists(host_configs, nickname);
}

std::vector<std::string> AMDomain::host::AMHostManager::ListNames() const {
  return HostDomainService_().ListNames(host_configs);
}

ECM AMDomain::host::AMHostManager::Add(const std::string &nickname) {
  (void)nickname;
  return Err(EC::OperationUnsupported,
             "Interactive add is owned by interface layer");
}

ECM AMDomain::host::AMHostManager::Modify(const std::string &nickname) {
  (void)nickname;
  return Err(EC::OperationUnsupported,
             "Interactive modify is owned by interface layer");
}

ECM AMDomain::host::AMHostManager::AddHost_(const std::string &nickname,
                                            const HostConfig &entry) {
  ECM memory_rcm =
      HostDomainService_().UpsertHostInMemory(&host_configs, nickname, entry);
  if (memory_rcm.first != EC::Success) {
    return memory_rcm;
  }
  auto json_entry = entry.GetJson();
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().SetArg(
          DocumentKind::Config, {configkn::hosts, nickname}, json_entry)) {
    return Err(EC::CommonFailure, "failed to set config in memory data");
  }
  return Ok();
}

ECM AMDomain::host::AMHostManager::RemoveHost_(const std::string &nickname) {
  CollectHosts_();
  ECM memory_rcm =
      HostDomainService_().RemoveHostInMemory(&host_configs, nickname);
  if (memory_rcm.first != EC::Success) {
    return memory_rcm;
  }
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().DelArg(
          DocumentKind::Config, {configkn::hosts, nickname})) {
    return Err(EC::CommonFailure, "failed to remove config in memory data");
  }
  return Ok();
}
