#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostManager.hpp"
#include "foundation/tools/enum_related.hpp"
#include <algorithm>
#include <string>

namespace {
AMDomain::host::HostDomainService &HostDomainService_() {
  static AMDomain::host::HostDomainService service;
  return service;
}

AMDomain::host::KnownHostService &KnownHostService_() {
  static AMDomain::host::KnownHostService service;
  return service;
}

bool IsLocalNickname_(const std::string &nickname) {
  return HostDomainService_().IsLocalNickname(nickname);
}
} // namespace

void AMDomain::host::AMHostConfigManager::BindSnapshotStore(
    IHostConfigSnapshotStore *snapshot_store) {
  snapshot_store_ = snapshot_store;
}

ECM AMDomain::host::AMHostConfigManager::Init(
    const HostConfigArg &host_config_arg) {
  std::string validate_error;
  for (const auto &[nickname, cfg] : host_config_arg.host_configs) {
    if (HostDomainService_().IsLocalNickname(nickname)) {
      return Err(EC::InvalidArg,
                 AMStr::fmt("non-local map contains local nickname: {}", nickname));
    }
    if (!HostDomainService_().IsValidConfig(cfg, &validate_error)) {
      return Err(EC::InvalidArg,
                 AMStr::fmt("invalid host config '{}': {}", nickname,
                            validate_error.empty() ? "invalid config"
                                                   : validate_error));
    }
  }

  if (!host_config_arg.local_config.request.nickname.empty()) {
    const HostConfig &local_cfg = host_config_arg.local_config;
    if (!HostDomainService_().IsLocalNickname(local_cfg.request.nickname)) {
      return Err(EC::InvalidArg,
                 "local config nickname must be 'local' (case-insensitive)");
    }
    if (local_cfg.request.protocol != ClientProtocol::LOCAL) {
      return Err(EC::InvalidArg, "local config protocol must be LOCAL");
    }
    if (!HostDomainService_().IsValidConfig(local_cfg, &validate_error)) {
      return Err(EC::InvalidArg,
                 validate_error.empty() ? "invalid local config"
                                        : validate_error);
    }
  }

  host_configs_ = host_config_arg.host_configs;
  local_config_ = host_config_arg.local_config;
  private_keys_ = host_config_arg.private_keys;
  snapshot_loaded_ = true;
  return Ok();
}

ECM AMDomain::host::AMHostConfigManager::EnsureSnapshotLoaded_() const {
  if (snapshot_loaded_) {
    return Ok();
  }
  return LoadSnapshot_();
}

ECM AMDomain::host::AMHostConfigManager::LoadSnapshot_() const {
  if (!snapshot_store_) {
    return Err(EC::ConfigNotInitialized, "host snapshot store is not bound");
  }
  const auto [load_rcm, snapshot] = snapshot_store_->LoadSnapshot();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  return const_cast<AMHostConfigManager *>(this)->Init(snapshot);
}

HostConfigArg AMDomain::host::AMHostConfigManager::SnapshotFromCache_() const {
  HostConfigArg out{};
  out.host_configs = host_configs_;
  out.local_config = local_config_;
  out.private_keys = private_keys_;
  return out;
}

ECM AMDomain::host::AMHostConfigManager::PersistSnapshot_(
    const HostConfigArg &snapshot, bool dump_async) {
  if (!snapshot_store_) {
    return Err(EC::ConfigNotInitialized, "host snapshot store is not bound");
  }

  const HostConfigArg previous = SnapshotFromCache_();
  const bool had_snapshot = snapshot_loaded_;
  ECM init_rcm = Init(snapshot);
  if (!isok(init_rcm)) {
    return init_rcm;
  }
  ECM save_rcm = snapshot_store_->SaveSnapshot(snapshot, dump_async);
  if (!isok(save_rcm)) {
    if (had_snapshot) {
      (void)Init(previous);
    } else {
      ResetSnapshotCache_();
    }
    return save_rcm;
  }
  return Ok();
}

void AMDomain::host::AMHostConfigManager::ResetSnapshotCache_() {
  host_configs_.clear();
  local_config_ = {};
  private_keys_.clear();
  snapshot_loaded_ = false;
}

ECM AMDomain::host::AMHostConfigManager::Save() {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  return PersistSnapshot_(SnapshotFromCache_(), true);
}

std::pair<ECM, HostConfig> AMDomain::host::AMHostConfigManager::GetClientConfig(
    const std::string &nickname) {
  if (IsLocalNickname_(nickname)) {
    return GetLocalConfig();
  }

  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return {load_rcm, {}};
  }
  return HostDomainService_().GetConfigByNickname(host_configs_, nickname,
                                                  &local_config_);
}

std::pair<ECM, HostConfig> AMDomain::host::AMHostConfigManager::GetLocalConfig() {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return {load_rcm, {}};
  }
  if (local_config_.request.nickname.empty()) {
    return {Err(EC::HostConfigNotFound, "local host config not found"), {}};
  }
  return {Ok(), local_config_};
}

const AMDomain::host::AMHostConfigManager::HostConfigMap &
AMDomain::host::AMHostConfigManager::HostConfigs() const {
  (void)EnsureSnapshotLoaded_();
  return host_configs_;
}

HostConfigArg AMDomain::host::AMHostConfigManager::GetInitArg() const {
  (void)EnsureSnapshotLoaded_();
  return SnapshotFromCache_();
}

ECM AMDomain::host::AMHostConfigManager::AddHost(const HostConfig &entry,
                                                 bool overwrite) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }

  std::string validate_error;
  if (!HostDomainService_().IsValidConfig(entry, &validate_error)) {
    return Err(EC::InvalidArg,
               validate_error.empty() ? "invalid host config" : validate_error);
  }

  const std::string nickname = AMStr::Strip(entry.request.nickname);
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host name");
  }
  if (!overwrite && HostExists(nickname)) {
    return Err(EC::KeyAlreadyExists,
               AMStr::fmt("host nickname already exists: {}", nickname));
  }

  HostConfigArg next = SnapshotFromCache_();
  if (IsLocalNickname_(nickname)) {
    next.local_config = entry;
  } else {
    next.host_configs[nickname] = entry;
  }
  return PersistSnapshot_(next, true);
}

ECM AMDomain::host::AMHostConfigManager::DelHost(const std::string &nickname) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }

  const std::string key = AMStr::Strip(nickname);
  if (key.empty()) {
    return Err(EC::InvalidArg, "empty host name");
  }
  if (IsLocalNickname_(key)) {
    return Err(EC::OperationUnsupported, "local host cannot be removed");
  }
  if (host_configs_.find(key) == host_configs_.end()) {
    return Err(EC::HostConfigNotFound, "host config not found");
  }

  HostConfigArg next = SnapshotFromCache_();
  next.host_configs.erase(key);
  return PersistSnapshot_(next, true);
}

bool AMDomain::host::AMHostConfigManager::HostExists(
    const std::string &nickname) const {
  if (!isok(EnsureSnapshotLoaded_())) {
    return false;
  }
  return HostDomainService_().NicknameExists(host_configs_, nickname,
                                             &local_config_);
}

std::vector<std::string> AMDomain::host::AMHostConfigManager::ListNames() const {
  if (!isok(EnsureSnapshotLoaded_())) {
    return {};
  }

  std::vector<std::string> names;
  names.reserve(host_configs_.size() + 1);
  if (!local_config_.request.nickname.empty()) {
    names.push_back("local");
  }
  for (const auto &[nickname, _] : host_configs_) {
    if (!IsLocalNickname_(nickname)) {
      names.push_back(nickname);
    }
  }
  std::sort(names.begin(), names.end());
  return names;
}

ECM AMDomain::host::AMHostConfigManager::Add(const std::string &nickname) {
  (void)nickname;
  return Err(EC::OperationUnsupported,
             "Interactive add is owned by interface layer");
}

ECM AMDomain::host::AMHostConfigManager::Modify(const std::string &nickname) {
  (void)nickname;
  return Err(EC::OperationUnsupported,
             "Interactive modify is owned by interface layer");
}

void AMDomain::host::AMKnownHostsManager::BindSnapshotStore(
    IKnownHostSnapshotStore *snapshot_store) {
  snapshot_store_ = snapshot_store;
}

ECM AMDomain::host::AMKnownHostsManager::Init() { return LoadSnapshot_(); }

ECM AMDomain::host::AMKnownHostsManager::Init(
    const KnownHostMap &known_hosts) {
  known_hosts_ = known_hosts;
  snapshot_loaded_ = true;
  return Ok();
}

ECM AMDomain::host::AMKnownHostsManager::EnsureSnapshotLoaded_() const {
  if (snapshot_loaded_) {
    return Ok();
  }
  return LoadSnapshot_();
}

ECM AMDomain::host::AMKnownHostsManager::LoadSnapshot_() const {
  if (!snapshot_store_) {
    return Err(EC::ConfigNotInitialized,
               "known-host snapshot store is not bound");
  }
  const auto [load_rcm, snapshot] = snapshot_store_->LoadSnapshot();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  return const_cast<AMKnownHostsManager *>(this)->Init(snapshot.entries);
}

KnownHostEntryArg AMDomain::host::AMKnownHostsManager::SnapshotFromCache_() const {
  KnownHostEntryArg out{};
  out.entries = known_hosts_;
  return out;
}

ECM AMDomain::host::AMKnownHostsManager::PersistSnapshot_(
    const KnownHostEntryArg &snapshot, bool dump_async) {
  if (!snapshot_store_) {
    return Err(EC::ConfigNotInitialized,
               "known-host snapshot store is not bound");
  }

  const KnownHostEntryArg previous = SnapshotFromCache_();
  const bool had_snapshot = snapshot_loaded_;
  ECM init_rcm = Init(snapshot.entries);
  if (!isok(init_rcm)) {
    return init_rcm;
  }
  ECM save_rcm = snapshot_store_->SaveSnapshot(snapshot, dump_async);
  if (!isok(save_rcm)) {
    if (had_snapshot) {
      (void)Init(previous.entries);
    } else {
      ResetSnapshotCache_();
    }
    return save_rcm;
  }
  return Ok();
}

void AMDomain::host::AMKnownHostsManager::ResetSnapshotCache_() {
  known_hosts_.clear();
  snapshot_loaded_ = false;
}

const AMDomain::host::KnownHostMap &
AMDomain::host::AMKnownHostsManager::KnownHosts() const {
  (void)EnsureSnapshotLoaded_();
  return known_hosts_;
}

ECM AMDomain::host::AMKnownHostsManager::FindKnownHost(
    KnownHostQuery &query) const {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }

  auto resolve_from_cache = [this, &query]() -> ECM {
    auto it = known_hosts_.find(BuildKnownHostKey(query));
    if (it == known_hosts_.end()) {
      return ECM{EC::HostConfigNotFound,
                 "fingerprint not found for given host query"};
    }
    return KnownHostService_().ResolveKnownHostQuery(
        &query, it->second.GetFingerprint());
  };

  ECM resolve_rcm = resolve_from_cache();
  if (isok(resolve_rcm)) {
    return resolve_rcm;
  }
  load_rcm = LoadSnapshot_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  return resolve_from_cache();
}

ECM AMDomain::host::AMKnownHostsManager::UpsertKnownHost(
    const KnownHostQuery &query, bool overwrite) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }

  std::string fingerprint;
  ECM validate_rcm =
      KnownHostService_().ValidateKnownHostUpsert(query, &fingerprint);
  if (validate_rcm.first != EC::Success) {
    return validate_rcm;
  }

  if (!overwrite && KnownHostService_().QueryExists(known_hosts_, query)) {
    return Err(EC::KeyAlreadyExists, "known-host entry already exists");
  }

  KnownHostQuery stored = query;
  (void)stored.SetFingerprint(fingerprint);

  KnownHostEntryArg snapshot = SnapshotFromCache_();
  snapshot.entries[BuildKnownHostKey(stored)] = stored;
  return PersistSnapshot_(snapshot, true);
}
