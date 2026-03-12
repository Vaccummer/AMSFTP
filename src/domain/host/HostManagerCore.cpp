#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostManager.hpp"
#include "interface/ApplicationAdapters.hpp"
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

AMDomain::host::HostConfigArg LoadHostConfigArg_() {
  AMDomain::host::HostConfigArg out{};
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Read(&out);
  return out;
}

AMDomain::host::KnownHostMap LoadKnownHosts_() {
  AMDomain::host::KnownHostEntryArg out{};
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Read(&out);
  return out.entries;
}
} // namespace

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
  return Ok();
}

ECM AMDomain::host::AMHostConfigManager::Save() {
  return AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Dump(
      DocumentKind::Config, "", true);
}

std::pair<ECM, HostConfig> AMDomain::host::AMHostConfigManager::GetClientConfig(
    const std::string &nickname) {
  if (IsLocalNickname_(nickname)) {
    return GetLocalConfig();
  }
  return HostDomainService_().GetConfigByNickname(host_configs_, nickname,
                                                  &local_config_);
}

std::pair<ECM, HostConfig> AMDomain::host::AMHostConfigManager::GetLocalConfig() {
  if (!local_config_.request.nickname.empty()) {
    return {Ok(), local_config_};
  }

  const HostConfigArg host_config_arg = LoadHostConfigArg_();
  ECM init_rcm = Init(host_config_arg);
  if (init_rcm.first != EC::Success) {
    return {init_rcm, {}};
  }
  if (local_config_.request.nickname.empty()) {
    return {Err(EC::HostConfigNotFound, "local host config not found"), {}};
  }
  return {Ok(), local_config_};
}

const AMDomain::host::AMHostConfigManager::HostConfigMap &
AMDomain::host::AMHostConfigManager::HostConfigs() const {
  return host_configs_;
}

HostConfigArg AMDomain::host::AMHostConfigManager::GetInitArg() const {
  HostConfigArg out{};
  out.host_configs = host_configs_;
  out.local_config = local_config_;
  out.private_keys = private_keys_;
  return out;
}

ECM AMDomain::host::AMHostConfigManager::AddHost(const HostConfig &entry,
                                                 bool overwrite) {
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

  HostConfigArg next = GetInitArg();
  if (IsLocalNickname_(nickname)) {
    next.local_config = entry;
  } else {
    next.host_configs[nickname] = entry;
  }

  if (!AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Write(next)) {
    return Err(EC::CommonFailure, "failed to persist host config snapshot");
  }

  host_configs_ = next.host_configs;
  local_config_ = next.local_config;
  private_keys_ = next.private_keys;
  return AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Dump(
      DocumentKind::Config, "", true);
}

ECM AMDomain::host::AMHostConfigManager::DelHost(const std::string &nickname) {
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

  HostConfigArg next = GetInitArg();
  next.host_configs.erase(key);
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Write(next)) {
    return Err(EC::CommonFailure, "failed to persist host config snapshot");
  }

  host_configs_ = next.host_configs;
  local_config_ = next.local_config;
  private_keys_ = next.private_keys;
  return AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Dump(
      DocumentKind::Config, "", true);
}

bool AMDomain::host::AMHostConfigManager::HostExists(
    const std::string &nickname) const {
  return HostDomainService_().NicknameExists(host_configs_, nickname,
                                             &local_config_);
}

std::vector<std::string> AMDomain::host::AMHostConfigManager::ListNames() const {
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

ECM AMDomain::host::AMKnownHostsManager::Init() {
  known_hosts_ = LoadKnownHosts_();
  return Ok();
}

ECM AMDomain::host::AMKnownHostsManager::Init(
    const KnownHostMap &known_hosts) {
  known_hosts_ = known_hosts;
  return Ok();
}

const AMDomain::host::KnownHostMap &
AMDomain::host::AMKnownHostsManager::KnownHosts() const {
  return known_hosts_;
}

ECM AMDomain::host::AMKnownHostsManager::FindKnownHost(
    KnownHostQuery &query) const {
  auto it = known_hosts_.find(BuildKnownHostKey(query));
  if (it != known_hosts_.end()) {
    return KnownHostService_().ResolveKnownHostQuery(&query,
                                                     it->second.GetFingerprint());
  }

  KnownHostEntryArg snapshot = {};
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Read(&snapshot)) {
    return ECM{EC::HostConfigNotFound,
               "fingerprint not found for given host query"};
  }
  auto loaded_it = snapshot.entries.find(BuildKnownHostKey(query));
  if (loaded_it == snapshot.entries.end()) {
    return ECM{EC::HostConfigNotFound,
               "fingerprint not found for given host query"};
  }
  return KnownHostService_().ResolveKnownHostQuery(
      &query, loaded_it->second.GetFingerprint());
}

ECM AMDomain::host::AMKnownHostsManager::UpsertKnownHost(
    const KnownHostQuery &query, bool overwrite) {
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

  KnownHostEntryArg snapshot{};
  snapshot.entries = known_hosts_;
  snapshot.entries[BuildKnownHostKey(stored)] = stored;
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Write(snapshot)) {
    return Err(EC::CommonFailure, "failed to write known-host snapshot");
  }

  known_hosts_ = std::move(snapshot.entries);
  return AMInterface::ApplicationAdapters::Runtime::ConfigServiceOrThrow().Dump(
      DocumentKind::KnownHosts, "", true);
}
