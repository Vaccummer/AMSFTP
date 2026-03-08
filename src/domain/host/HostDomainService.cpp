#include "domain/host/HostDomainService.hpp"

namespace AMDomain::host {
bool HostManagerService::IsLocalNickname(const std::string &nickname) {
  return AMStr::lowercase(AMStr::Strip(nickname)) == "local";
}

bool HostManagerService::NicknameExists(const HostConfigMap &host_configs,
                                        const std::string &nickname,
                                        const HostConfig *local_config) {
  if (nickname.empty()) {
    return false;
  }
  if (host_configs.find(nickname) != host_configs.end()) {
    return true;
  }
  if (!IsLocalNickname(nickname)) {
    return false;
  }
  return local_config && !local_config->request.nickname.empty();
}

bool HostManagerService::IsValidConfig(const ConRequest &request,
                                       std::string *error_info) {
  if (error_info) {
    error_info->clear();
  }
  if (!request.IsValid(error_info)) {
    return false;
  }
  if (!ValidateNickname(request.nickname)) {
    if (error_info) {
      *error_info = "nickname contains invalid characters";
    }
    return false;
  }
  return true;
}

bool HostManagerService::IsValidConfig(const HostConfig &config,
                                       std::string *error_info) {
  return IsValidConfig(config.request, error_info);
}

std::pair<ECM, HostConfig>
HostManagerService::GetConfigByNickname(const HostConfigMap &host_configs,
                                        const std::string &nickname,
                                        const HostConfig *local_config) {
  if (nickname.empty()) {
    return {Err(EC::HostConfigNotFound, "host config not found: empty nickname"),
            {}};
  }

  if (IsLocalNickname(nickname)) {
    if (!local_config || local_config->request.nickname.empty()) {
      return {Err(EC::HostConfigNotFound, "local host config not found"), {}};
    }
    return {Ok(), *local_config};
  }

  auto it = host_configs.find(nickname);
  if (it == host_configs.end()) {
    return {Err(EC::HostConfigNotFound,
                AMStr::fmt("host config not found: {}", nickname)),
            {}};
  }
  return {Ok(), it->second};
}

ECM KnownHostService::ResolveKnownHostQuery(KnownHostQuery *query,
                                            const std::string &fingerprint) const {
  if (!query) {
    return {EC::InvalidArg, "null known-host query"};
  }
  if (!query->IsValid()) {
    return {EC::InvalidArg, "invalid query args"};
  }
  if (fingerprint.empty()) {
    return {EC::InvalidArg, "fingerprint is found but empty"};
  }
  query->SetFingerprint(fingerprint);
  return Ok();
}

ECM KnownHostService::ValidateKnownHostUpsert(const KnownHostQuery &query,
                                              std::string *fingerprint) const {
  if (!query.IsValid()) {
    return Err(EC::InvalidArg, "invalid known-host query");
  }
  const std::string stripped = AMStr::Strip(query.GetFingerprint());
  if (stripped.empty()) {
    return Err(EC::InvalidArg, "empty fingerprint");
  }
  if (fingerprint) {
    *fingerprint = stripped;
  }
  return Ok();
}

bool KnownHostService::QueryExists(const KnownHostMap &known_hosts,
                                   const KnownHostQuery &query) const {
  return known_hosts.find(BuildKnownHostKey(query)) != known_hosts.end();
}
} // namespace AMDomain::host



