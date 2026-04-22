#include "domain/host/HostDomainService.hpp"
#include <cctype>

namespace AMDomain::host {
namespace HostService {
namespace {
std::string NormalizeFieldName_(const std::string &field_name) {
  return AMStr::lowercase(AMStr::Strip(field_name));
}

template <typename Attr> std::string AttrName_(Attr attr) {
  return NormalizeFieldName_(std::string(magic_enum::enum_name(attr)));
}
} // namespace

const std::vector<HostSetFieldRef> &EditableHostSetFields() {
  static const std::vector<HostSetFieldRef> kFields = [] {
    std::vector<HostSetFieldRef> out = {};

    auto add_request = [&out](ConRequest::Attr attr) {
      HostSetFieldRef item = {};
      item.name = AttrName_(attr);
      item.scope = HostSetFieldRef::Scope::Request;
      item.request_attr = attr;
      out.push_back(std::move(item));
    };

    auto add_metadata = [&out](ClientMetaData::Attr attr) {
      HostSetFieldRef item = {};
      item.name = AttrName_(attr);
      item.scope = HostSetFieldRef::Scope::Metadata;
      item.metadata_attr = attr;
      out.push_back(std::move(item));
    };

    add_request(ConRequest::Attr::hostname);
    add_request(ConRequest::Attr::username);
    add_request(ConRequest::Attr::port);
    add_request(ConRequest::Attr::protocol);
    add_request(ConRequest::Attr::password);
    add_request(ConRequest::Attr::keyfile);
    add_request(ConRequest::Attr::compression);

    add_metadata(ClientMetaData::Attr::trash_dir);
    add_metadata(ClientMetaData::Attr::login_dir);
    add_metadata(ClientMetaData::Attr::cmd_template);
    return out;
  }();
  return kFields;
}

const std::vector<std::string> &EditableHostSetFieldNames() {
  static const std::vector<std::string> kNames = [] {
    std::vector<std::string> names = {};
    const auto &fields = EditableHostSetFields();
    names.reserve(fields.size());
    for (const auto &field : fields) {
      names.push_back(field.name);
    }
    return names;
  }();
  return kNames;
}

std::optional<HostSetFieldRef>
ParseEditableHostSetField(const std::string &field_name) {
  const std::string normalized = NormalizeFieldName_(field_name);
  if (normalized.empty()) {
    return std::nullopt;
  }
  const auto &fields = EditableHostSetFields();
  for (const auto &field : fields) {
    if (field.name == normalized) {
      return field;
    }
  }
  return std::nullopt;
}

ECM ValidateEditableHostSetFieldValue(const HostSetFieldRef &field,
                                      const std::string &value) {
  if (field.scope == HostSetFieldRef::Scope::Request) {
    return ValidateFieldValue(field.request_attr, value);
  }
  return ValidateFieldValue(field.metadata_attr, value);
}

const HostConfig &LocalConfigFallback() {
  static const HostConfig kFallback = []() {
    HostConfig cfg = {};
    cfg.request.nickname = "local";
    cfg.request.protocol = ClientProtocol::LOCAL;
    cfg.request.hostname = "localhost";
    cfg.request.username = "local";
    cfg.request.port = 0;
    return cfg;
  }();
  return kFallback;
}

void vNormalizeNickname(std::string &nickname) {
  AMStr::VStrip(nickname);
  if (IsLocalNickname(nickname)) {
    nickname = "local";
  }
}

std::string NormalizeNickname(const std::string &nickname) {
  std::string normalized = nickname;
  vNormalizeNickname(normalized);
  return normalized;
}

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
  if (host_configs.contains(key)) {
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
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm =
      ValidateFieldValue(ConRequest::Attr::protocol, request.protocol);
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  if (request.protocol != ClientProtocol::LOCAL) {
    validate_rcm =
        ValidateFieldValue(ConRequest::Attr::hostname, request.hostname);
    if (!(validate_rcm)) {
      return validate_rcm;
    }

    validate_rcm =
        ValidateFieldValue(ConRequest::Attr::username, request.username);
    if (!(validate_rcm)) {
      return validate_rcm;
    }

    validate_rcm = ValidateFieldValue(ConRequest::Attr::port, request.port);
    if (!(validate_rcm)) {
      return validate_rcm;
    }
  }

  validate_rcm =
      ValidateFieldValue(ConRequest::Attr::password, request.password);
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm = ValidateFieldValue(ConRequest::Attr::keyfile, request.keyfile);
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  return ValidateFieldValue(ConRequest::Attr::compression, request.compression);
}

ECM ValidateConRequest(const ConRequest &request, std::string *error_info) {
  ECM validate_rcm = ValidateConfig(request);
  if (error_info) {
    error_info->clear();
    if (!(validate_rcm)) {
      *error_info = validate_rcm.error;
    }
  }
  return validate_rcm;
}

ECM ValidateConfig(const ClientMetaData &metadata) {
  ECM validate_rcm =
      ValidateFieldValue(ClientMetaData::Attr::trash_dir, metadata.trash_dir);
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm =
      ValidateFieldValue(ClientMetaData::Attr::login_dir, metadata.login_dir);
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm = ValidateFieldValue(ClientMetaData::Attr::cwd, metadata.cwd);
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  validate_rcm = ValidateFieldValue(ClientMetaData::Attr::cmd_template,
                                    metadata.cmd_template);
  if (!(validate_rcm)) {
    return validate_rcm;
  }
  return OK;
}

ECM ValidateConfig(const HostConfig &config) {
  ECM validate_rcm = ValidateConfig(config.request);
  if (!(validate_rcm)) {
    return validate_rcm;
  }
  return ValidateConfig(config.metadata);
}

bool IsValidConfig(const ConRequest &request, std::string *error_info) {
  return (ValidateConRequest(request, error_info));
}

bool IsValidConfig(const HostConfig &config, std::string *error_info) {
  ECM validate_rcm = ValidateConfig(config);
  if (error_info) {
    error_info->clear();
    if (!(validate_rcm)) {
      *error_info = validate_rcm.error;
    }
  }
  return (validate_rcm);
}

std::pair<ECM, HostConfig>
GetConfigByNickname(const HostConfigMap &host_configs,
                    const std::string &nickname,
                    const HostConfig *local_config) {
  const std::string key = AMStr::Strip(nickname);
  if (key.empty()) {
    return {Err(EC::HostConfigNotFound, "", "",
                "host config not found: empty nickname"),
            {}};
  }

  if (IsLocalNickname(key)) {
    if (!local_config || local_config->request.nickname.empty()) {
      return {Err(EC::HostConfigNotFound, "", "",
                  "local host config not found"),
              {}};
    }
    return {OK, *local_config};
  }

  auto it = host_configs.find(key);
  if (it == host_configs.end()) {
    return {Err(EC::HostConfigNotFound, "", "",
                AMStr::fmt("host config not found: {}", key)),
            {}};
  }
  return {OK, it->second};
}
} // namespace HostService

namespace KnownHostRules {
ECM ValidateConfig(const KnownHostQuery &request) {
  ECM validate_rcm =
      ValidateFieldValue(KnownHostQuery::Attr::hostname, request.hostname);
  if (!(validate_rcm)) {
    return validate_rcm;
  }
  return ValidateFieldValue(KnownHostQuery::Attr::port, request.port);
}
} // namespace KnownHostRules
} // namespace AMDomain::host

