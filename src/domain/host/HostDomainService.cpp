#include "domain/host/HostDomainService.hpp"
#include <algorithm>

namespace AMDomain::host {
HostDomainService::HostConfigMap
HostDomainService::CollectHosts(const Json &hosts_json,
                                const HostConfig &local_fallback,
                                const std::string &local_user) const {
  HostConfigMap out;
  if (!hosts_json.is_object()) {
    return out;
  }

  out.reserve(hosts_json.size() + 1);
  for (auto it = hosts_json.begin(); it != hosts_json.end(); ++it) {
    const std::string nickname = it.key();
    const std::string lowered = AMStr::lowercase(AMStr::Strip(nickname));
    const bool is_local = (lowered == "local");
    const std::string key = is_local ? "local" : nickname;
    auto cfg = HostConfig(nickname, it.value());

    if (is_local) {
      if (cfg.IsValid()) {
        cfg.request.username = local_user;
        out[key] = cfg;
      } else if (local_fallback.IsValid()) {
        out[key] = local_fallback;
      }
      continue;
    }

    if (cfg.IsValid()) {
      out[key] = cfg;
    }
  }
  return out;
}

std::pair<ECM, HostConfig>
HostDomainService::GetClientConfig(const HostConfigMap &host_configs,
                                   const std::string &nickname) const {
  if (nickname.empty()) {
    return {Err(EC::HostConfigNotFound, "host config not found: empty nickname"),
            {}};
  }
  auto it = host_configs.find(nickname);
  if (it == host_configs.end()) {
    return {Err(EC::HostConfigNotFound,
                AMStr::fmt("host config not found: {}", nickname)),
            {}};
  }
  return {Ok(), it->second};
}

std::pair<ECM, HostConfig> HostDomainService::BuildLocalConfig(
    const Json *local_json, const std::string &local_user,
    const std::string &fallback_home, const std::string &fallback_trash) const {
  HostConfig result;
  if (local_json && local_json->is_object()) {
    HostConfig stored("local", *local_json);
    if (stored.IsValid()) {
      result = stored;
    }
  }

  if (result.request.nickname.empty()) {
    result.request.nickname = "local";
  }
  if (result.request.hostname.empty()) {
    result.request.hostname = "localhost";
  }
  if (result.request.username.empty()) {
    result.request.username = local_user;
  }
  if (result.request.port <= 0 || result.request.port > 65535) {
    result.request.port = configkn::DefaultSFTPPort;
  }

  result.request.protocol = ClientProtocol::LOCAL;
  if (result.request.buffer_size <= 0) {
    result.request.buffer_size = 64 * AMMB;
  } else {
    result.request.buffer_size =
        std::min(std::max(result.request.buffer_size,
                          static_cast<int64_t>(AMMinBufferSize)),
                 static_cast<int64_t>(AMMaxBufferSize));
  }

  if (result.metadata.login_dir.empty()) {
    result.metadata.login_dir = fallback_home;
  }
  if (result.request.trash_dir.empty()) {
    result.request.trash_dir = fallback_trash;
  }

  return {Ok(), result};
}

ECM HostDomainService::ValidateHostUpsert(const HostConfig &entry) const {
  if (!entry.IsValid()) {
    return Err(EC::InvalidArg, "invalid host config");
  }
  if (!configkn::ValidateNickname(entry.request.nickname)) {
    return Err(EC::InvalidArg, "invalid nickname");
  }
  return Ok();
}

bool HostDomainService::HostExists(const HostConfigMap &host_configs,
                                   const std::string &nickname) const {
  if (nickname.empty()) {
    return false;
  }
  return host_configs.find(nickname) != host_configs.end();
}

std::vector<std::string>
HostDomainService::ListNames(const HostConfigMap &host_configs) const {
  std::vector<std::string> names;
  names.reserve(host_configs.size());
  for (const auto &pair : host_configs) {
    names.push_back(pair.first);
  }
  std::sort(names.begin(), names.end());
  return names;
}

ECM HostDomainService::UpsertHostInMemory(HostConfigMap *host_configs,
                                          const std::string &nickname,
                                          const HostConfig &entry) const {
  if (!host_configs) {
    return Err(EC::InvalidArg, "null host config map");
  }
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host name");
  }

  ECM valid_rcm = ValidateHostUpsert(entry);
  if (valid_rcm.first != EC::Success) {
    return valid_rcm;
  }

  (*host_configs)[nickname] = entry;
  return Ok();
}

ECM HostDomainService::RemoveHostInMemory(HostConfigMap *host_configs,
                                          const std::string &nickname) const {
  if (!host_configs) {
    return Err(EC::InvalidArg, "null host config map");
  }
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host name");
  }

  if (host_configs->erase(nickname) == 0) {
    return Err(EC::HostConfigNotFound, "host config not found");
  }
  return Ok();
}

ECM HostDomainService::ResolveKnownHostQuery(KnownHostQuery *query,
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

ECM HostDomainService::ValidateKnownHostUpsert(
    const KnownHostQuery &query, std::string *fingerprint) const {
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
} // namespace AMDomain::host
