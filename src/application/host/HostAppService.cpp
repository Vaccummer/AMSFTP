#include "application/host/HostAppService.hpp"

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

ECM HostAppService::Init(const HostConfigArg &host_config_arg) {
  host_configs_.clear();
  private_keys_.clear();

  HostConfig local_candidate = host_config_arg.local_config;
  for (const auto &[raw_name, cfg] : host_config_arg.host_configs) {
    std::string key = NormalizeNickname(raw_name);
    HostConfig value = cfg;
    value.request.nickname = key;
    if (IsLocalNickname(key)) {
      local_candidate = value;
      continue;
    }
    host_configs_[key] = value;
  }

  local_candidate.request.nickname = "local";
  local_candidate.request.protocol = ClientProtocol::LOCAL;
  const ECM local_validate = ValidateConfig(local_candidate);
  if (!(local_validate)) {
    local_config_ = AMDomain::host::HostService::LocalConfigFallback();
  } else {
    local_config_ = std::move(local_candidate);
  }
  if (!host_configs_.contains(AMDomain::host::klocalname)) {
    host_configs_[AMDomain::host::klocalname] = local_config_;
  }

  private_keys_ = host_config_arg.private_keys;
  return OK;
}

HostConfigArg HostAppService::GetInitArg() const {
  HostConfigArg out = {};
  out.host_configs = host_configs_;
  out.local_config = local_config_;
  out.private_keys = private_keys_;
  return out;
}

ECM HostAppService::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (config_service == nullptr) {
    return Err(EC::InvalidArg, __func__, "", "config service is null");
  }
  if (!config_service->Write<HostConfigArg>(GetInitArg())) {
    return Err(EC::ConfigDumpFailed, __func__, "", "failed to flush host config");
  }
  return OK;
}

ECMData<HostConfig> HostAppService::GetClientConfig(const std::string &nickname,
                                                    bool case_sensitive) {
  const std::string key = AMStr::Strip(nickname);
  if (key.empty()) {
    return {HostConfig{}, Err(EC::HostConfigNotFound, __func__, "",
                              "Host not found")};
  }

  const std::string normalized_key = NormalizeNickname(key);
  if (IsLocalNickname(normalized_key)) {
    return {local_config_, OK};
  }

  auto it = host_configs_.find(normalized_key);
  if (it != host_configs_.end()) {
    return {it->second, OK};
  }

  if (!case_sensitive) {
    const std::string lowered = AMStr::lowercase(key);
    std::vector<std::string> matched = {};
    for (const auto &[name, _] : host_configs_) {
      if (AMStr::lowercase(name) == lowered) {
        matched.push_back(name);
      }
    }
    if (matched.size() == 1) {
      auto matched_it = host_configs_.find(matched.front());
      if (matched_it != host_configs_.end()) {
        return {matched_it->second, OK};
      }
    }
    if (matched.size() > 1) {
      return {HostConfig{},
              Err(EC::HostConfigNotFound, __func__, key,
                  AMStr::fmt("Ambiguous host nickname, candidates: {}",
                             AMStr::join(matched, ", ")))};
    }
  }

  return {HostConfig{}, Err(EC::HostConfigNotFound, __func__, normalized_key,
                            "Host not found")};
}

ECMData<HostConfig> HostAppService::GetLocalConfig() {
  if (local_config_.request.nickname.empty()) {
    local_config_ = AMDomain::host::HostService::LocalConfigFallback();
  }
  return {local_config_, OK};
}

const HostAppService::HostConfigMap &HostAppService::HostConfigs() const {
  return host_configs_;
}

std::vector<std::string> HostAppService::ListNames() const {
  std::vector<std::string> names = {};
  names.reserve(host_configs_.size());
  for (const auto &[name, _] : host_configs_) {
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
  return host_configs_.contains(key);
}

ECMData<std::string>
HostAppService::CheckNicknameAvailable(const std::string &nickname) const {
  const std::string normalized = NormalizeNickname(AMStr::Strip(nickname));
  if (normalized.empty() || !ValidateNickname(normalized)) {
    return {"", Err(EC::InvalidArg, __func__, "", "invalid host nickname")};
  }
  if (IsLocalNickname(normalized)) {
    return {"", Err(EC::InvalidArg, __func__, "", "Nickname 'local' is reserved")};
  }
  if (host_configs_.contains(normalized)) {
    return {"", Err(EC::KeyAlreadyExists, __func__, "", AMStr::fmt("host already exists: {}", normalized))};
  }
  return {normalized, OK};
}

ECM HostAppService::AddHost(const HostConfig &entry, bool overwrite) {
  HostConfig normalized = entry;
  normalized.request.nickname = NormalizeNickname(normalized.request.nickname);
  if (!ValidateNickname(normalized.request.nickname)) {
    return Err(EC::InvalidArg, __func__, "", "invalid host nickname");
  }

  ECM validate_rcm = ValidateConfig(normalized);
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  if (IsLocalNickname(normalized.request.nickname)) {
    local_config_ = normalized;
    local_config_.request.nickname = "local";
    local_config_.request.protocol = ClientProtocol::LOCAL;
    MarkConfigDirty();
    return OK;
  }

  auto it = host_configs_.find(normalized.request.nickname);
  if (it != host_configs_.end() && !overwrite) {
    return Err(EC::KeyAlreadyExists, __func__, "", AMStr::fmt("host already exists: {}",
                                                normalized.request.nickname));
  }
  host_configs_[normalized.request.nickname] = std::move(normalized);
  MarkConfigDirty();
  return OK;
}

ECM HostAppService::DelHost(const std::string &nickname) {
  const std::string key = NormalizeNickname(nickname);
  if (IsLocalNickname(key)) {
    return Err(EC::InvalidArg, __func__, "", "local host cannot be removed");
  }
  auto it = host_configs_.find(key);
  if (it == host_configs_.end()) {
    return Err(EC::HostConfigNotFound, __func__, "", AMStr::fmt("host not found: {}", key));
  }
  host_configs_.erase(it);
  MarkConfigDirty();
  return OK;
}

std::vector<std::string> HostAppService::PrivateKeys() const {
  return private_keys_;
}

ECM KnownHostsAppService::Init() {
  known_hosts_.clear();
  snapshot_loaded_ = true;
  return OK;
}

ECM KnownHostsAppService::Init(const KnownHostMap &known_hosts) {
  known_hosts_ = known_hosts;
  snapshot_loaded_ = true;
  return OK;
}

const KnownHostsAppService::KnownHostMap &
KnownHostsAppService::KnownHosts() const {
  (void)EnsureSnapshotLoaded_();
  return known_hosts_;
}

ECM KnownHostsAppService::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (config_service == nullptr) {
    return Err(EC::InvalidArg, __func__, "", "config service is null");
  }
  const KnownHostEntryArg snapshot = SnapshotFromCache_();
  if (!config_service->Write<KnownHostEntryArg>(snapshot)) {
    return Err(EC::ConfigDumpFailed, __func__, "", "failed to flush known-hosts config");
  }
  return OK;
}

ECM KnownHostsAppService::FindKnownHost(KnownHostQuery &query) const {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!(load_rcm)) {
    return load_rcm;
  }
  ECM validate_rcm = AMDomain::host::KnownHostRules::ValidateConfig(query);
  if (!(validate_rcm)) {
    return validate_rcm;
  }
  const auto key = AMDomain::host::KnownHostRules::BuildKnownHostKey(query);
  auto it = known_hosts_.find(key);
  if (it == known_hosts_.end()) {
    return Err(EC::HostConfigNotFound, __func__, "", "known host entry not found");
  }
  query = it->second;
  return OK;
}

ECM KnownHostsAppService::UpsertKnownHost(const KnownHostQuery &query,
                                          bool overwrite) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!(load_rcm)) {
    return load_rcm;
  }
  ECM validate_rcm = AMDomain::host::KnownHostRules::ValidateConfig(query);
  if (!(validate_rcm)) {
    return validate_rcm;
  }
  const auto key = AMDomain::host::KnownHostRules::BuildKnownHostKey(query);
  if (!overwrite && known_hosts_.contains(key)) {
    return Err(EC::KeyAlreadyExists, __func__, "", "known host entry already exists");
  }
  known_hosts_[key] = query;
  MarkConfigDirty();
  return OK;
}

ECM KnownHostsAppService::EnsureSnapshotLoaded_() const {
  return snapshot_loaded_ ? OK : LoadSnapshot_();
}

ECM KnownHostsAppService::LoadSnapshot_() const {
  if (snapshot_loaded_) {
    return OK;
  }
  known_hosts_.clear();
  snapshot_loaded_ = true;
  return OK;
}

KnownHostEntryArg KnownHostsAppService::SnapshotFromCache_() const {
  KnownHostEntryArg out = {};
  out.entries = known_hosts_;
  return out;
}

ECM KnownHostsAppService::PersistSnapshot_(const KnownHostEntryArg &snapshot,
                                           bool dump_async) {
  (void)dump_async;
  return Init(snapshot.entries);
}

void KnownHostsAppService::ResetSnapshotCache_() {
  known_hosts_.clear();
  snapshot_loaded_ = false;
}
} // namespace AMApplication::host
