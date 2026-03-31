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

HostConfigArg AMHostAppService::GetInitArg() const {
  return SnapshotFromCache_();
}

std::pair<ECM, HostConfig>
AMHostAppService::GetClientConfig(const std::string &nickname) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return {load_rcm, {}};
  }
  const std::string key = NormalizeHostKey_(nickname);
  if (IsLocalNickname(key)) {
    return {Ok(), local_config_};
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
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }

  HostConfig normalized = entry;
  normalized.request.nickname = NormalizeHostKey_(normalized.request.nickname);
  if (!ValidateNickname(normalized.request.nickname)) {
    return Err(EC::InvalidArg, "invalid host nickname");
  }

  ECM validate_rcm = ValidateConfig(normalized);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  if (IsLocalNickname(normalized.request.nickname)) {
    local_config_ = normalized;
    local_config_.request.nickname = "local";
    local_config_.request.protocol = ClientProtocol::LOCAL;
    return Ok();
  }

  auto it = host_configs_.find(normalized.request.nickname);
  if (it != host_configs_.end() && !overwrite) {
    return Err(EC::KeyAlreadyExists, AMStr::fmt("host already exists: {}",
                                                normalized.request.nickname));
  }
  host_configs_[normalized.request.nickname] = std::move(normalized);
  return Ok();
}

ECM AMHostAppService::DelHost(const std::string &nickname) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  const std::string key = NormalizeHostKey_(nickname);
  if (IsLocalNickname(key)) {
    return Err(EC::InvalidArg, "local host cannot be removed");
  }
  auto it = host_configs_.find(key);
  if (it == host_configs_.end()) {
    return Err(EC::HostConfigNotFound, AMStr::fmt("host not found: {}", key));
  }
  host_configs_.erase(it);
  return Ok();
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
  HostConfig cfg = {};
  cfg.request.nickname = AMStr::Strip(nickname);
  if (cfg.request.nickname.empty()) {
    return Err(EC::InvalidArg, "nickname cannot be empty");
  }
  cfg.request.protocol = ClientProtocol::SFTP;
  return AddHost(cfg, false);
}

ECM AMHostAppService::Modify(const std::string &nickname) {
  if (!HostExists(nickname)) {
    return Err(EC::HostConfigNotFound, "host not found");
  }
  return Ok();
}

ECM AMHostAppService::Delete(const std::string &nickname) {
  return DelHost(nickname);
}

ECM AMHostAppService::Delete(const std::vector<std::string> &targets) {
  ECM status = Ok();
  for (const auto &name : targets) {
    ECM rcm = DelHost(name);
    if (!isok(rcm)) {
      status = rcm;
    }
  }
  return status;
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
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  const std::string old_key = NormalizeHostKey_(old_nickname);
  const std::string new_key = NormalizeHostKey_(new_nickname);
  if (IsLocalNickname(old_key) || IsLocalNickname(new_key)) {
    return Err(EC::InvalidArg, "local host cannot be renamed");
  }
  if (!ValidateNickname(new_key)) {
    return Err(EC::InvalidArg, "invalid new nickname");
  }
  auto old_it = host_configs_.find(old_key);
  if (old_it == host_configs_.end()) {
    return Err(EC::HostConfigNotFound,
               AMStr::fmt("host not found: {}", old_key));
  }
  if (host_configs_.find(new_key) != host_configs_.end()) {
    return Err(EC::KeyAlreadyExists,
               AMStr::fmt("host already exists: {}", new_key));
  }
  HostConfig moved = old_it->second;
  moved.request.nickname = new_key;
  host_configs_.erase(old_it);
  host_configs_[new_key] = std::move(moved);
  return Ok();
}

ECM AMHostAppService::Src() const {
  (void)EnsureSnapshotLoaded_();
  return Ok();
}

ECM AMHostAppService::Save() { return Ok(); }

ECM AMHostAppService::SetHostValue(const std::string &nickname,
                                   const std::string &attrname,
                                   const std::string &value_str) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  const std::string key = NormalizeHostKey_(nickname);
  HostConfig cfg = {};
  if (IsLocalNickname(key)) {
    cfg = local_config_;
  } else {
    auto it = host_configs_.find(key);
    if (it == host_configs_.end()) {
      return Err(EC::HostConfigNotFound, AMStr::fmt("host not found: {}", key));
    }
    cfg = it->second;
  }

  const std::string field = AMStr::lowercase(AMStr::Strip(attrname));
  if (field == "hostname") {
    cfg.request.hostname = value_str;
  } else if (field == "username") {
    cfg.request.username = value_str;
  } else if (field == "port") {
    int64_t port = 0;
    if (!AMStr::GetNumber(value_str, &port)) {
      return Err(EC::InvalidArg, "invalid port");
    }
    cfg.request.port = port;
  } else if (field == "protocol") {
    cfg.request.protocol =
        AMDomain::host::HostService::StrToProtocol(AMStr::Strip(value_str));
  } else if (field == "password") {
    cfg.request.password = value_str;
  } else if (field == "keyfile") {
    cfg.request.keyfile = value_str;
  } else if (field == "buffer_size") {
    int64_t buffer_size = 0;
    if (!AMStr::GetNumber(value_str, &buffer_size)) {
      return Err(EC::InvalidArg, "invalid buffer_size");
    }
    cfg.request.buffer_size = buffer_size;
  } else if (field == "compression") {
    bool compression = false;
    if (!AMStr::GetBool(value_str, &compression)) {
      return Err(EC::InvalidArg, "invalid compression value");
    }
    cfg.request.compression = compression;
  } else if (field == "trash_dir") {
    cfg.metadata.trash_dir = value_str;
  } else if (field == "login_dir") {
    cfg.metadata.login_dir = value_str;
  } else if (field == "cmd_prefix") {
    cfg.metadata.cmd_prefix = value_str;
  } else if (field == "wrap_cmd") {
    bool wrap_cmd = false;
    if (!AMStr::GetBool(value_str, &wrap_cmd)) {
      return Err(EC::InvalidArg, "invalid wrap_cmd value");
    }
    cfg.metadata.wrap_cmd = wrap_cmd;
  } else {
    return Err(EC::InvalidArg, AMStr::fmt("unsupported field: {}", field));
  }

  ECM validate_rcm = ValidateConfig(cfg);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  if (IsLocalNickname(key)) {
    local_config_ = std::move(cfg);
    local_config_.request.nickname = "local";
    local_config_.request.protocol = ClientProtocol::LOCAL;
  } else {
    cfg.request.nickname = key;
    host_configs_[key] = std::move(cfg);
  }
  return Ok();
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
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  ECM validate_rcm = AMDomain::host::KnownHostRules::ValidateConfig(query);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }
  const auto key = AMDomain::host::KnownHostRules::BuildKnownHostKey(query);
  auto it = known_hosts_.find(key);
  if (it == known_hosts_.end()) {
    return Err(EC::HostConfigNotFound, "known host entry not found");
  }
  query = it->second;
  return Ok();
}

ECM AMKnownHostsAppService::UpsertKnownHost(const KnownHostQuery &query,
                                            bool overwrite) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  ECM validate_rcm = AMDomain::host::KnownHostRules::ValidateConfig(query);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }
  const auto key = AMDomain::host::KnownHostRules::BuildKnownHostKey(query);
  if (!overwrite && known_hosts_.find(key) != known_hosts_.end()) {
    return Err(EC::KeyAlreadyExists, "known host entry already exists");
  }
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
