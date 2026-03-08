#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostManager.hpp"
#include "foundation/tools/json.hpp"
#include "interface/ApplicationAdapters.hpp"
#include <algorithm>
#include <string>

namespace {
/**
 * @brief Return shared host-manager service instance.
 */
AMDomain::host::HostDomainService &HostDomainService_() {
  static AMDomain::host::HostDomainService service;
  return service;
}

/**
 * @brief Return shared known-host service instance.
 */
AMDomain::host::KnownHostService &KnownHostService_() {
  static AMDomain::host::KnownHostService service;
  return service;
}

/**
 * @brief Return true when nickname targets local config entry.
 */
bool IsLocalNickname_(const std::string &nickname) {
  return HostDomainService_().IsLocalNickname(nickname);
}

/**
 * @brief Build host-manager init payload from current config storage.
 */
AMDomain::host::HostConfigArg LoadHostConfigArg_() {
  Json hosts_json = Json::object();
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
      .ResolveArg(DocumentKind::Config, {AttrName::hosts}, &hosts_json);
  if (!hosts_json.is_object()) {
    hosts_json = Json::object();
  }

  AMDomain::host::HostConfigArg out{};
  for (auto it = hosts_json.begin(); it != hosts_json.end(); ++it) {
    if (!it.value().is_object()) {
      continue;
    }

    const std::string nickname = it.key();
    HostConfig cfg(nickname, it.value());
    if (IsLocalNickname_(nickname)) {
      out.local_config = cfg;
      continue;
    }

    std::string err;
    if (!HostDomainService_().IsValidConfig(cfg, &err)) {
      continue;
    }
    out.host_configs[nickname] = cfg;
  }

  std::vector<std::string> private_keys;
  (void)AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
      .ResolveArg(DocumentKind::Config, {AttrName::keys}, &private_keys);
  out.private_keys = std::move(private_keys);
  return out;
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
  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
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

/**
 * @brief Get local client config from cache or build from config storage.
 */
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

  auto json_entry = entry.GetJson();
  if (IsLocalNickname_(nickname)) {
    local_config_ = entry;
    if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
             .SetArg(DocumentKind::Config, {AttrName::hosts, "local"},
                     json_entry)) {
      return Err(EC::CommonFailure, "failed to set local config in memory data");
    }
  } else {
    host_configs_[nickname] = entry;
    if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().SetArg(
            DocumentKind::Config, {AttrName::hosts, nickname}, json_entry)) {
      return Err(EC::CommonFailure, "failed to set config in memory data");
    }
  }

  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
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
  if (host_configs_.erase(key) == 0) {
    return Err(EC::HostConfigNotFound, "host config not found");
  }
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().DelArg(
          DocumentKind::Config, {AttrName::hosts, key})) {
    return Err(EC::CommonFailure, "failed to remove config in memory data");
  }
  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
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
  if (!local_config_.request.nickname.empty() ) {
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

namespace {
/**
 * @brief Load known-host map snapshot from config storage.
 */
AMDomain::host::KnownHostMap LoadKnownHosts_() {
  Json known_hosts_json;
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
           .ResolveArg(DocumentKind::KnownHosts, {}, &known_hosts_json) ||
      !known_hosts_json.is_object()) {
    return {};
  }

  AMDomain::host::KnownHostMap collected;
  for (auto host_it = known_hosts_json.begin(); host_it != known_hosts_json.end();
       ++host_it) {
    if (!host_it.value().is_object()) {
      continue;
    }
    const std::string hostname = AMStr::Strip(host_it.key());
    if (hostname.empty()) {
      continue;
    }

    for (auto port_it = host_it.value().begin(); port_it != host_it.value().end();
         ++port_it) {
      if (!port_it.value().is_object()) {
        continue;
      }
      int64_t port_num = 0;
      if (!AMJson::StrValueParse(AMStr::Strip(port_it.key()), &port_num) ||
          port_num <= 0 || port_num > 65535) {
        continue;
      }

      for (auto user_it = port_it.value().begin();
           user_it != port_it.value().end(); ++user_it) {
        if (!user_it.value().is_object()) {
          continue;
        }
        const std::string username = AMStr::Strip(user_it.key());

        for (auto proto_it = user_it.value().begin();
             proto_it != user_it.value().end(); ++proto_it) {
          if (!proto_it.value().is_string()) {
            continue;
          }
          const std::string protocol =
              AMStr::lowercase(AMStr::Strip(proto_it.key()));
          const std::string fingerprint =
              AMStr::Strip(proto_it.value().get<std::string>());
          if (protocol.empty() || fingerprint.empty()) {
            continue;
          }

          KnownHostQuery query{"", hostname, static_cast<int>(port_num),
                               protocol, username, fingerprint};
          if (!query.IsValid()) {
            continue;
          }
          collected[BuildKnownHostKey(query)] = query;
        }
      }
    }
  }

  return collected;
}
} // namespace

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
  if (KnownHostService_().QueryExists(known_hosts_, query)) {
    auto it = known_hosts_.find(BuildKnownHostKey(query));
    return KnownHostService_().ResolveKnownHostQuery(&query,
                                                     it->second.GetFingerprint());
  }

  std::string fingerprint = "";
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
           .ResolveArg(DocumentKind::KnownHosts, query.GetPath(),
                       &fingerprint)) {
    return ECM{EC::HostConfigNotFound,
               "fingerprint not found for given host query"};
  }
  return KnownHostService_().ResolveKnownHostQuery(&query, fingerprint);
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
  known_hosts_[BuildKnownHostKey(stored)] = stored;

  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().SetArg(
          DocumentKind::KnownHosts, query.GetPath(), fingerprint)) {
    return Err(EC::CommonFailure, "failed to write known_hosts data");
  }
  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
      DocumentKind::KnownHosts, "", true);
}

