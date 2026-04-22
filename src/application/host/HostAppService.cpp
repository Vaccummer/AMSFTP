#include "application/host/HostAppService.hpp"
#include "application/log/ProgramTrace.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>

namespace AMApplication::host {
namespace {
using AMDomain::host::ClientProtocol;
using AMDomain::host::HostConfig;
using AMDomain::host::HostConfigArg;
using AMDomain::host::KnownHostEntryArg;
using AMDomain::host::KnownHostMap;
using AMDomain::host::KnownHostQuery;
using AMDomain::host::HostService::IsLocalNickname;
using AMDomain::host::HostService::NormalizeNickname;
using AMDomain::host::HostService::ValidateConfig;
using AMDomain::host::HostService::ValidateNickname;

} // namespace

void HostAppService::TraceHost_(const ECM &rcm, const std::string &nickname,
                                const std::string &action,
                                const std::string &message) const {
  std::string detail = message;
  if (!(rcm)) {
    if (!detail.empty()) {
      detail += "; ";
    }
    detail += AMStr::fmt("result={} error={}", AMStr::ToString(rcm.code),
                         rcm.msg());
  }
  AMApplication::log::ProgramTrace(
      logger_, rcm, nickname.empty() ? std::string("<host>") : nickname, action,
      detail);
}

ECM HostAppService::Init(const HostConfigArg &host_config_arg) {
  HostConfigMap host_configs = {};
  HostConfig local_candidate = host_config_arg.local_config;
  for (const auto &[raw_name, cfg] : host_config_arg.host_configs) {
    std::string key = NormalizeNickname(raw_name);
    HostConfig value = cfg;
    value.request.nickname = key;
    if (IsLocalNickname(key)) {
      local_candidate = value;
      continue;
    }
    host_configs[key] = value;
  }

  local_candidate.request.nickname = "local";
  local_candidate.request.protocol = ClientProtocol::LOCAL;
  HostConfig local_config = {};
  const ECM local_validate = ValidateConfig(local_candidate);
  if (!(local_validate)) {
    local_config = AMDomain::host::HostService::LocalConfigFallback();
  } else {
    local_config = std::move(local_candidate);
  }
  if (!host_configs.contains(AMDomain::host::klocalname)) {
    host_configs[AMDomain::host::klocalname] = local_config;
  }

  {
    auto guard = host_configs_.lock();
    guard.store(std::move(host_configs));
  }
  {
    auto guard = local_config_.lock();
    guard.store(std::move(local_config));
  }
  {
    auto guard = private_keys_.lock();
    guard.store(host_config_arg.private_keys);
  }
  TraceHost_(OK, "<all>", "host.init",
             AMStr::fmt("hosts={} private_keys={}", host_configs.size(),
                        host_config_arg.private_keys.size()));
  return OK;
}

HostConfigArg HostAppService::GetInitArg() const {
  HostConfigArg out = {};
  out.host_configs = host_configs_.lock().load();
  out.local_config = local_config_.lock().load();
  out.private_keys = private_keys_.lock().load();
  return out;
}

ECM HostAppService::FlushTo(AMDomain::config::IConfigStorePort *store) {
  if (store == nullptr) {
    return Err(EC::InvalidArg, "host.flush", "", "config store is null");
  }
  const HostConfigArg snapshot = GetInitArg();
  if (!store->Write(std::type_index(typeid(HostConfigArg)),
                    static_cast<const void *>(&snapshot))) {
    return Err(EC::ConfigDumpFailed, "host.flush", "",
               "failed to flush host config");
  }
  return OK;
}

ECMData<HostConfig> HostAppService::GetClientConfig(const std::string &nickname,
                                                    bool case_sensitive) {
  const std::string key = AMStr::Strip(nickname);
  if (key.empty()) {
    return {HostConfig{},
            Err(EC::HostConfigNotFound, "host.get", "", "Host not found")};
  }

  const std::string normalized_key = NormalizeNickname(key);
  if (IsLocalNickname(normalized_key)) {
    return {local_config_.lock().load(), OK};
  }

  const auto host_configs = host_configs_.lock();
  auto it = host_configs->find(normalized_key);
  if (it != host_configs->end()) {
    return {it->second, OK};
  }

  if (!case_sensitive) {
    const std::string lowered = AMStr::lowercase(key);
    std::vector<std::string> matched = {};
    for (const auto &[name, _] : *host_configs) {
      if (AMStr::lowercase(name) == lowered) {
        matched.push_back(name);
      }
    }
    if (matched.size() == 1) {
      auto matched_it = host_configs->find(matched.front());
      if (matched_it != host_configs->end()) {
        return {matched_it->second, OK};
      }
    }
    if (matched.size() > 1) {
      return {HostConfig{},
              Err(EC::HostConfigNotFound, "host.get", key,
                  AMStr::fmt("Ambiguous host nickname, candidates: {}",
                             AMStr::join(matched, ", ")))};
    }
  }

  return {HostConfig{}, Err(EC::HostConfigNotFound, "host.get", normalized_key,
                            "Host not found")};
}

ECMData<HostConfig> HostAppService::GetLocalConfig() {
  auto local_config = local_config_.lock();
  if (local_config->request.nickname.empty()) {
    local_config.store(AMDomain::host::HostService::LocalConfigFallback());
  }
  return {local_config.load(), OK};
}

std::vector<std::string> HostAppService::ListNames() const {
  const auto host_configs = host_configs_.lock();
  std::vector<std::string> names = {};
  names.reserve(host_configs->size());
  for (const auto &[name, _] : *host_configs) {
    (void)_;
    names.push_back(name);
  }
  std::sort(names.begin(), names.end());
  return names;
}

bool HostAppService::HostExists(const std::string &nickname) const {
  const std::string key = NormalizeNickname(nickname);
  if (IsLocalNickname(key)) {
    return true;
  }
  return host_configs_.lock()->contains(key);
}

ECMData<std::string>
HostAppService::CheckNicknameAvailable(const std::string &nickname) const {
  const std::string normalized = NormalizeNickname(AMStr::Strip(nickname));
  if (normalized.empty() || !ValidateNickname(normalized)) {
    return {"", Err(EC::InvalidArg, "host.check_nickname", "",
                    "invalid host nickname")};
  }
  if (IsLocalNickname(normalized)) {
    return {"", Err(EC::InvalidArg, "host.check_nickname", "",
                    "Nickname 'local' is reserved")};
  }
  if (host_configs_.lock()->contains(normalized)) {
    return {"", Err(EC::KeyAlreadyExists, "host.check_nickname", "",
                    AMStr::fmt("host already exists: {}", normalized))};
  }
  return {normalized, OK};
}

ECM HostAppService::AddHost(const HostConfig &entry, bool overwrite) {
  HostConfig normalized = entry;
  normalized.request.nickname = NormalizeNickname(normalized.request.nickname);
  if (!ValidateNickname(normalized.request.nickname)) {
    return Err(EC::InvalidArg, "host.add", "", "invalid host nickname");
  }

  ECM validate_rcm = ValidateConfig(normalized);
  if (!(validate_rcm)) {
    TraceHost_(validate_rcm, normalized.request.nickname, "host.add",
               "validation failed");
    return validate_rcm;
  }

  if (IsLocalNickname(normalized.request.nickname)) {
    auto local_config = local_config_.lock();
    local_config.store(normalized);
    local_config->request.nickname = "local";
    local_config->request.protocol = ClientProtocol::LOCAL;
    MarkConfigDirty();
    TraceHost_(OK, "local", "host.add", "updated local config");
    return OK;
  }

  auto host_configs = host_configs_.lock();
  auto it = host_configs->find(normalized.request.nickname);
  if (it != host_configs->end() && !overwrite) {
    const ECM rcm = Err(
        EC::KeyAlreadyExists, "host.add", "",
        AMStr::fmt("host already exists: {}", normalized.request.nickname));
    TraceHost_(rcm, normalized.request.nickname, "host.add");
    return rcm;
  }
  (*host_configs)[normalized.request.nickname] = std::move(normalized);
  MarkConfigDirty();
  TraceHost_(OK, normalized.request.nickname, "host.add",
             AMStr::fmt("overwrite={}", overwrite ? "true" : "false"));
  return OK;
}

ECM HostAppService::DelHost(const std::string &nickname) {
  const std::string key = NormalizeNickname(nickname);
  if (IsLocalNickname(key)) {
    const ECM rcm =
        Err(EC::InvalidArg, "host.del", "", "local host cannot be removed");
    TraceHost_(rcm, key, "host.del");
    return rcm;
  }
  auto host_configs = host_configs_.lock();
  auto it = host_configs->find(key);
  if (it == host_configs->end()) {
    const ECM rcm = Err(EC::HostConfigNotFound, "host.del", "",
                        AMStr::fmt("host not found: {}", key));
    TraceHost_(rcm, key, "host.del");
    return rcm;
  }
  host_configs->erase(it);
  MarkConfigDirty();
  TraceHost_(OK, key, "host.del", "removed host config");
  return OK;
}

std::vector<std::string> HostAppService::PrivateKeys() const {
  return private_keys_.lock().load();
}

ECM KnownHostsAppService::Init(const KnownHostMap &known_hosts) {
  auto guard = known_hosts_.lock();
  guard.store(known_hosts);
  AMApplication::log::ProgramTrace(
      logger_, AMDomain::client::TraceLevel::Info, EC::Success, "<all>",
      "known_hosts.init", AMStr::fmt("entries={}", known_hosts.size()));
  return OK;
}

KnownHostMap KnownHostsAppService::GetInitArg() const {
  return known_hosts_.lock().load();
}

ECM KnownHostsAppService::FlushTo(AMDomain::config::IConfigStorePort *store) {
  if (store == nullptr) {
    return Err(EC::InvalidArg, "known_hosts.flush", "", "config store is null");
  }
  const KnownHostEntryArg snapshot = {GetInitArg()};
  if (!store->Write(std::type_index(typeid(KnownHostEntryArg)),
                    static_cast<const void *>(&snapshot))) {
    return Err(EC::ConfigDumpFailed, "known_hosts.flush", "",
               "failed to flush known-hosts config");
  }
  return OK;
}

ECM KnownHostsAppService::FindKnownHost(KnownHostQuery &query) const {
  ECM validate_rcm = AMDomain::host::KnownHostRules::ValidateConfig(query);
  if (!(validate_rcm)) {
    TraceKnownHost_(validate_rcm, query, "known_hosts.find",
                    "validation failed");
    return validate_rcm;
  }
  const auto key = AMDomain::host::KnownHostRules::BuildKnownHostKey(query);
  const auto known_hosts = known_hosts_.lock();
  auto it = known_hosts->find(key);
  if (it == known_hosts->end()) {
    const ECM rcm = Err(EC::HostConfigNotFound, "known_hosts.find", "",
                        "known host entry not found");
    TraceKnownHost_(rcm, query, "known_hosts.find");
    return rcm;
  }
  query = it->second;
  TraceKnownHost_(OK, query, "known_hosts.find", "matched known host");
  return OK;
}

ECM KnownHostsAppService::UpsertKnownHost(const KnownHostQuery &query,
                                          bool overwrite) {
  ECM validate_rcm = AMDomain::host::KnownHostRules::ValidateConfig(query);
  if (!(validate_rcm)) {
    TraceKnownHost_(validate_rcm, query, "known_hosts.upsert",
                    "validation failed");
    return validate_rcm;
  }
  const auto key = AMDomain::host::KnownHostRules::BuildKnownHostKey(query);
  auto known_hosts = known_hosts_.lock();
  if (!overwrite && known_hosts->contains(key)) {
    const ECM rcm = Err(EC::KeyAlreadyExists, "known_hosts.upsert", "",
                        "known host entry already exists");
    TraceKnownHost_(rcm, query, "known_hosts.upsert");
    return rcm;
  }
  (*known_hosts)[key] = query;
  MarkConfigDirty();
  TraceKnownHost_(OK, query, "known_hosts.upsert",
                  AMStr::fmt("overwrite={}", overwrite ? "true" : "false"));
  return OK;
}

void KnownHostsAppService::TraceKnownHost_(
    const ECM &rcm, const KnownHostQuery &query, const std::string &action,
    const std::string &message) const {
  std::string target = query.nickname;
  if (!query.hostname.empty()) {
    target = AMStr::fmt("{}@{}:{}", query.username, query.hostname, query.port);
  }
  std::string detail = message;
  if (!(rcm)) {
    if (!detail.empty()) {
      detail += "; ";
    }
    detail += AMStr::fmt("result={} error={}", AMStr::ToString(rcm.code),
                         rcm.msg());
  }
  AMApplication::log::ProgramTrace(
      logger_, rcm, target.empty() ? std::string("<known-host>") : target,
      action, detail);
}

} // namespace AMApplication::host
