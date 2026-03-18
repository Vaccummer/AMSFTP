#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/enum_related.hpp"
#include <cctype>

namespace AMDomain::host {
namespace HostService {
bool IsNicknameValid(const std::string &nickname) {
  const std::string stripped = AMStr::Strip(nickname);
  if (stripped.empty()) {
    return false;
  }
  for (const char ch : stripped) {
    if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' ||
        ch == '-') {
      continue;
    }
    return false;
  }
  return true;
}

bool IsLocalNickname(const std::string &nickname) {
  return AMStr::lowercase(AMStr::Strip(nickname)) == "local";
}

bool NicknameExists(const HostConfigMap &host_configs,
                    const std::string &nickname,
                    const HostConfig *local_config) {
  const std::string key = AMStr::Strip(nickname);
  if (key.empty()) {
    return false;
  }
  if (host_configs.find(key) != host_configs.end()) {
    return true;
  }
  if (!IsLocalNickname(key)) {
    return false;
  }
  return local_config && !local_config->request.nickname.empty();
}

ECM ValidateConfig(const ConRequest &request) {
  ECM validate_rcm =
      ValidateFieldValue(ConRequest::Attr::nickname, request.nickname);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm =
      ValidateFieldValue(ConRequest::Attr::protocol, request.protocol);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  if (request.protocol != ClientProtocol::LOCAL) {
    validate_rcm =
        ValidateFieldValue(ConRequest::Attr::hostname, request.hostname);
    if (!isok(validate_rcm)) {
      return validate_rcm;
    }

    validate_rcm =
        ValidateFieldValue(ConRequest::Attr::username, request.username);
    if (!isok(validate_rcm)) {
      return validate_rcm;
    }

    validate_rcm = ValidateFieldValue(ConRequest::Attr::port, request.port);
    if (!isok(validate_rcm)) {
      return validate_rcm;
    }
  }

  validate_rcm =
      ValidateFieldValue(ConRequest::Attr::password, request.password);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm = ValidateFieldValue(ConRequest::Attr::keyfile, request.keyfile);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm =
      ValidateFieldValue(ConRequest::Attr::trash_dir, request.trash_dir);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm =
      ValidateFieldValue(ConRequest::Attr::buffer_size, request.buffer_size);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  return ValidateFieldValue(ConRequest::Attr::compression, request.compression);
}

ECM ValidateConRequest(const ConRequest &request, std::string *error_info) {
  ECM validate_rcm = ValidateConfig(request);
  if (error_info) {
    error_info->clear();
    if (!isok(validate_rcm)) {
      *error_info = validate_rcm.second;
    }
  }
  return validate_rcm;
}

ECM ValidateConfig(const ClientMetaData &metadata) {
  ECM validate_rcm =
      ValidateFieldValue(ClientMetaData::Attr::login_dir, metadata.login_dir);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm = ValidateFieldValue(ClientMetaData::Attr::cwd, metadata.cwd);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm =
      ValidateFieldValue(ClientMetaData::Attr::cmd_prefix, metadata.cmd_prefix);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  return ValidateFieldValue(ClientMetaData::Attr::wrap_cmd, metadata.wrap_cmd);
}

ECM ValidateConfig(const HostConfig &config) {
  ECM validate_rcm = ValidateConfig(config.request);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }
  return ValidateConfig(config.metadata);
}

bool IsValidConfig(const ConRequest &request, std::string *error_info) {
  return isok(ValidateConRequest(request, error_info));
}

bool IsValidConfig(const HostConfig &config, std::string *error_info) {
  ECM validate_rcm = ValidateConfig(config);
  if (error_info) {
    error_info->clear();
    if (!isok(validate_rcm)) {
      *error_info = validate_rcm.second;
    }
  }
  return isok(validate_rcm);
}

std::pair<ECM, HostConfig>
GetConfigByNickname(const HostConfigMap &host_configs,
                    const std::string &nickname,
                    const HostConfig *local_config) {
  const std::string key = AMStr::Strip(nickname);
  if (key.empty()) {
    return {
        Err(EC::HostConfigNotFound, "host config not found: empty nickname"),
        {}};
  }

  if (IsLocalNickname(key)) {
    if (!local_config || local_config->request.nickname.empty()) {
      return {Err(EC::HostConfigNotFound, "local host config not found"), {}};
    }
    return {Ok(), *local_config};
  }

  auto it = host_configs.find(key);
  if (it == host_configs.end()) {
    return {Err(EC::HostConfigNotFound,
                AMStr::fmt("host config not found: {}", key)),
            {}};
  }
  return {Ok(), it->second};
}
} // namespace HostService

namespace KnownHostRules {
ECM ValidateConfig(const KnownHostQuery &request) {
  ECM validate_rcm =
      ValidateFieldValue(KnownHostQuery::Attr::hostname, request.hostname);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }
  return ValidateFieldValue(KnownHostQuery::Attr::port, request.port);
}
} // namespace KnownHostRules
} // namespace AMDomain::host
