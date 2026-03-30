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

HostConfig BuildDefaultLocalConfig_() {
  HostConfig cfg = {};
  cfg.request.nickname = "local";
  cfg.request.protocol = ClientProtocol::LOCAL;
  cfg.request.hostname = "localhost";
  cfg.request.username = "local";
  cfg.request.port = 0;
  return cfg;
}

std::string NormalizeHostKey_(const std::string &nickname) {
  const std::string normalized = NormalizeNickname(nickname);
  return normalized.empty() ? std::string("local") : normalized;
}
} // namespace

ECM AMHostAppService::Init(const HostConfigArg &host_config_arg) {
  host_configs_.clear();
  local_config_ = BuildDefaultLocalConfig_();
  private_keys_.clear();

  for (const auto &[raw_name, cfg] : host_config_arg.host_configs) {
    std::string key = NormalizeHostKey_(raw_name);
    HostConfig value = cfg;
    value.request.nickname = key;
    if (IsLocalNickname(key)) {
      local_config_ = value;
      local_config_.request.nickname = "local";
      local_config_.request.protocol = ClientProtocol::LOCAL;
      continue;
    }
    host_configs_[key] = value;
  }

  if (!host_config_arg.local_config.request.nickname.empty()) {
    local_config_ = host_config_arg.local_config;
    local_config_.request.nickname = "local";
    local_config_.request.protocol = ClientProtocol::LOCAL;
  }

  private_keys_ = host_config_arg.private_keys;
  snapshot_loaded_ = true;
  return Ok();
}

HostConfigArg AMHostAppService::GetInitArg() const { return SnapshotFromCache_(); }

std::pair<ECM, HostConfig>
AMHostAppService::GetClientConfig(const std::string &nickname) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return {load_rcm, {}};
  }
  const std::string key = NormalizeHostKey_(nickname);
  if (IsLocalNickname(key)) {
    return {Err(EC::InvalidArg, "use GetLocalConfig for local nickname"), {}};
  }
  auto it = host_configs_.find(key);
  if (it == host_configs_.end()) {
    return {Err(EC::HostConfigNotFound, AMStr::fmt("host not found: {}", key)),
            {}};
  }
  return {Ok(), it->second};
}

std::pair<ECM, HostConfig> AMHostAppService::GetLocalConfig() {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return {load_rcm, {}};
  }
  return {Ok(), local_config_};
}

const AMHostAppService::HostConfigMap &AMHostAppService::HostConfigs() const {
  (void)EnsureSnapshotLoaded_();
  return host_configs_;
}

std::vector<std::string> AMHostAppService::ListNames() const {
  (void)EnsureSnapshotLoaded_();
  std::vector<std::string> names = {};
  names.reserve(host_configs_.size());
  for (const auto &[name, _] : host_configs_) {
    (void)_;
    names.push_back(name);
  }
  std::sort(names.begin(), names.end());
  return names;
}

bool AMHostAppService::HostExists(const std::string &nickname) const {
  (void)EnsureSnapshotLoaded_();
  const std::string key = NormalizeHostKey_(nickname);
  if (IsLocalNickname(key)) {
    return true;
  }
  return host_configs_.find(key) != host_configs_.end();
}

ECM AMHostAppService::AddHost(const HostConfig &entry, bool overwrite) {
  (void)entry;
  (void)overwrite;
  return Err(EC::InvalidArg, "AddHost not implemented yet");
}

ECM AMHostAppService::DelHost(const std::string &nickname) {
  (void)nickname;
  return Err(EC::InvalidArg, "DelHost not implemented yet");
}

std::vector<std::string> AMHostAppService::PrivateKeys() const {
  (void)EnsureSnapshotLoaded_();
  return private_keys_;
}

ECM AMHostAppService::List(bool detailed) const {
  (void)detailed;
  (void)EnsureSnapshotLoaded_();
  return Ok();
}

ECM AMHostAppService::Add(const std::string &nickname) {
  (void)nickname;
  return Err(EC::InvalidArg, "Add not implemented yet");
}

ECM AMHostAppService::Modify(const std::string &nickname) {
  (void)nickname;
  return Err(EC::InvalidArg, "Modify not implemented yet");
}

ECM AMHostAppService::Delete(const std::string &nickname) {
  (void)nickname;
  return Err(EC::InvalidArg, "Delete not implemented yet");
}

ECM AMHostAppService::Delete(const std::vector<std::string> &targets) {
  (void)targets;
  return Err(EC::InvalidArg, "Delete(list) not implemented yet");
}

ECM AMHostAppService::Query(const std::string &targets) const {
  return HostExists(targets)
             ? Ok()
             : Err(EC::HostConfigNotFound,
                   AMStr::fmt("host not found: {}", AMStr::Strip(targets)));
}

ECM AMHostAppService::Query(const std::vector<std::string> &targets) const {
  ECM status = Ok();
  for (const auto &name : targets) {
    ECM rcm = Query(name);
    if (!isok(rcm)) {
      status = rcm;
    }
  }
  return status;
}

ECM AMHostAppService::Rename(const std::string &old_nickname,
                             const std::string &new_nickname) {
  (void)old_nickname;
  (void)new_nickname;
  return Err(EC::InvalidArg, "Rename not implemented yet");
}

ECM AMHostAppService::Src() const {
  (void)EnsureSnapshotLoaded_();
  return Ok();
}

ECM AMHostAppService::Save() { return Ok(); }

ECM AMHostAppService::SetHostValue(const std::string &nickname,
                                   const std::string &attrname,
                                   const std::string &value_str) {
  (void)nickname;
  (void)attrname;
  (void)value_str;
  return Err(EC::InvalidArg, "SetHostValue not implemented yet");
}

ECM AMHostAppService::EnsureSnapshotLoaded_() const {
  return snapshot_loaded_ ? Ok() : LoadSnapshot_();
}

ECM AMHostAppService::LoadSnapshot_() const {
  if (snapshot_loaded_) {
    return Ok();
  }
  host_configs_.clear();
  local_config_ = BuildDefaultLocalConfig_();
  private_keys_.clear();
  snapshot_loaded_ = true;
  return Ok();
}

HostConfigArg AMHostAppService::SnapshotFromCache_() const {
  HostConfigArg out = {};
  out.host_configs = host_configs_;
  out.local_config = local_config_;
  out.private_keys = private_keys_;
  return out;
}

ECM AMHostAppService::PersistSnapshot_(const HostConfigArg &snapshot,
                                       bool dump_async) {
  (void)dump_async;
  return Init(snapshot);
}

void AMHostAppService::ResetSnapshotCache_() {
  host_configs_.clear();
  local_config_ = BuildDefaultLocalConfig_();
  private_keys_.clear();
  snapshot_loaded_ = false;
}

ECM AMKnownHostsAppService::Init() {
  known_hosts_.clear();
  snapshot_loaded_ = true;
  return Ok();
}

ECM AMKnownHostsAppService::Init(const KnownHostMap &known_hosts) {
  known_hosts_ = known_hosts;
  snapshot_loaded_ = true;
  return Ok();
}

const AMKnownHostsAppService::KnownHostMap &
AMKnownHostsAppService::KnownHosts() const {
  (void)EnsureSnapshotLoaded_();
  return known_hosts_;
}

ECM AMKnownHostsAppService::FindKnownHost(KnownHostQuery &query) const {
  (void)query;
  return Err(EC::HostConfigNotFound, "known host entry not found");
}

ECM AMKnownHostsAppService::UpsertKnownHost(const KnownHostQuery &query,
                                            bool overwrite) {
  (void)overwrite;
  const std::string key = query.username + "@" + query.hostname + ":" +
                          std::to_string(query.port);
  known_hosts_[key] = query;
  return Ok();
}

ECM AMKnownHostsAppService::EnsureSnapshotLoaded_() const {
  return snapshot_loaded_ ? Ok() : LoadSnapshot_();
}

ECM AMKnownHostsAppService::LoadSnapshot_() const {
  if (snapshot_loaded_) {
    return Ok();
  }
  known_hosts_.clear();
  snapshot_loaded_ = true;
  return Ok();
}

KnownHostEntryArg AMKnownHostsAppService::SnapshotFromCache_() const {
  KnownHostEntryArg out = {};
  out.entries = known_hosts_;
  return out;
}

ECM AMKnownHostsAppService::PersistSnapshot_(const KnownHostEntryArg &snapshot,
                                             bool dump_async) {
  (void)dump_async;
  return Init(snapshot.entries);
}

void AMKnownHostsAppService::ResetSnapshotCache_() {
  known_hosts_.clear();
  snapshot_loaded_ = false;
}
} // namespace AMApplication::host
