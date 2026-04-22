#pragma once
#include "domain/host/HostModel.hpp"
#include "foundation/tools/string.hpp"
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace AMDomain::host {

namespace HostService {
using HostConfigMap = std::map<std::string, HostConfig>;

struct HostSetFieldRef {
  enum class Scope {
    Request = 1,
    Metadata = 2,
  };
  std::string name = {};
  Scope scope = Scope::Request;
  ConRequest::Attr request_attr = ConRequest::Attr::nickname;
  ClientMetaData::Attr metadata_attr = ClientMetaData::Attr::trash_dir;
};

[[nodiscard]] const std::vector<HostSetFieldRef> &EditableHostSetFields();
[[nodiscard]] const std::vector<std::string> &EditableHostSetFieldNames();
[[nodiscard]] std::optional<HostSetFieldRef>
ParseEditableHostSetField(const std::string &field_name);
[[nodiscard]] ECM
ValidateEditableHostSetFieldValue(const HostSetFieldRef &field,
                                  const std::string &value);

[[nodiscard]] const HostConfig &LocalConfigFallback();

inline ClientProtocol StrToProtocol(const std::string &protocol_str) {
  auto key = AMStr::uppercase(AMStr::Strip(protocol_str));
  auto it = magic_enum::enum_cast<ClientProtocol>(key);
  if (it.has_value() && it.value() != ClientProtocol::UnInitilized) {
    return it.value();
  }
  return ClientProtocol::SFTP; // Default to SFTP if unrecognized
}

[[nodiscard]] bool IsNicknameValid(const std::string &nickname);
[[nodiscard]] inline bool ValidateNickname(const std::string &nickname) {
  return IsNicknameValid(nickname);
}

void vNormalizeNickname(std::string &nickname);
[[nodiscard]] std::string NormalizeNickname(const std::string &nickname);
[[nodiscard]] bool IsLocalNickname(const std::string &nickname);

[[nodiscard]] bool NicknameExists(const HostConfigMap &host_configs,
                                  const std::string &nickname,
                                  const HostConfig *local_config = nullptr);
[[nodiscard]] std::pair<ECM, HostConfig>
GetConfigByNickname(const HostConfigMap &host_configs,
                    const std::string &nickname,
                    const HostConfig *local_config = nullptr);
[[nodiscard]] bool IsValidConfig(const ConRequest &request,
                                 std::string *error_info = nullptr);
[[nodiscard]] bool IsValidConfig(const HostConfig &config,
                                 std::string *error_info = nullptr);

template <typename T>
[[nodiscard]] inline ECM ValidateFieldValue(ConRequest::Attr attr, T value) {
  auto invalid_type = [attr]() -> ECM {
    if (attr == ConRequest::Attr::nickname) {
      return Err(EC::InvalidArg, "", "",
                 "Invalid type for nickname, expected string-like type");
    }
    if (attr == ConRequest::Attr::hostname) {
      return Err(EC::InvalidArg, "", "",
                 "Invalid type for hostname, expected string-like type");
    }
    if (attr == ConRequest::Attr::username) {
      return Err(EC::InvalidArg, "", "",
                 "Invalid type for username, expected string-like type");
    }
    if (attr == ConRequest::Attr::protocol) {
      return Err(EC::InvalidArg, "", "",
                 "Invalid type for protocol, expected ClientProtocol or "
                 "string-like type");
    }
    if (attr == ConRequest::Attr::port) {
      return Err(EC::InvalidArg, "", "",
                 "Invalid type for port, expected integer or string-like type");
    }
    if (attr == ConRequest::Attr::password ||
        attr == ConRequest::Attr::keyfile) {
      return Err(EC::InvalidArg, "", "",
                 "Invalid type for path/text field, expected string-like type");
    }
    if (attr == ConRequest::Attr::compression) {
      return Err(EC::InvalidArg, "", "",
                 "Invalid type for compression, expected bool or "
                 "string-like type");
    }
    return Err(EC::InvalidArg, "", "",
               AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  };

  using DT = std::decay_t<T>;
  constexpr bool kStringLike = std::is_constructible_v<std::string, T>;

  if constexpr (std::is_same_v<DT, ClientProtocol>) {
    if (attr != ConRequest::Attr::protocol) {
      return invalid_type();
    }
    if (value == ClientProtocol::UnInitilized) {
      return Err(EC::InvalidArg, "", "", "Unsupported protocol");
    }
    return OK;
  }

  if constexpr (std::is_same_v<DT, bool>) {
    if (attr == ConRequest::Attr::compression) {
      return OK;
    }
    return invalid_type();
  }

  if constexpr (std::is_integral_v<DT> && !std::is_same_v<DT, bool>) {
    if (attr == ConRequest::Attr::port) {
      const int64_t port_value = static_cast<int64_t>(value);
      if (port_value <= 0 || port_value > 65535) {
        return Err(EC::InvalidArg, "", "",
                   "Port must be an integer between 1 and 65535");
      }
      return OK;
    }
    return invalid_type();
  }

  if constexpr (kStringLike) {
    const std::string text_value = std::string(value);

    if (attr == ConRequest::Attr::nickname) {
      const std::string text = AMStr::Strip(text_value);
      if (!ValidateNickname(text)) {
        return Err(EC::InvalidArg, "", "",
                   "Invalid nickname: only alphanumeric, underscore, and "
                   "hyphen characters are allowed");
      }
      return OK;
    }

    if (attr == ConRequest::Attr::hostname) {
      if (AMStr::Strip(text_value).empty()) {
        return Err(EC::InvalidArg, "", "", "Hostname cannot be empty");
      }
      return OK;
    }

    if (attr == ConRequest::Attr::username) {
      if (AMStr::Strip(text_value).empty()) {
        return Err(EC::InvalidArg, "", "", "Username cannot be empty");
      }
      return OK;
    }

    if (attr == ConRequest::Attr::protocol) {
      const std::string text = AMStr::lowercase(AMStr::Strip(text_value));
      if (text == "sftp" || text == "ftp" || text == "local" ||
          text == "http") {
        return OK;
      }
      return Err(EC::InvalidArg, "", "",
                 "Protocol must be sftp, ftp, local, or http");
    }

    if (attr == ConRequest::Attr::port) {
      int64_t parsed_port = 0;
      if (!AMStr::GetNumber(text_value, &parsed_port) || parsed_port <= 0 ||
          parsed_port > 65535) {
        return Err(EC::InvalidArg, "", "",
                   "Port must be an integer between 1 and 65535");
      }
      return OK;
    }

    if (attr == ConRequest::Attr::password ||
        attr == ConRequest::Attr::keyfile) {
      return OK;
    }

    if (attr == ConRequest::Attr::compression) {
      bool parsed = false;
      if (!AMStr::GetBool(text_value, &parsed)) {
        return Err(EC::InvalidArg, "", "", "Compression must be true or false");
      }
      return OK;
    }

    return Err(EC::InvalidArg, "", "",
               AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }

  return invalid_type();
}
template <typename T>
[[nodiscard]] inline ECM ValidateFieldValue(ClientMetaData::Attr attr,
                                            T) {
  auto invalid_type = [attr]() -> ECM {
    if (attr == ClientMetaData::Attr::trash_dir ||
        attr == ClientMetaData::Attr::login_dir ||
        attr == ClientMetaData::Attr::cwd ||
        attr == ClientMetaData::Attr::cmd_template) {
      return Err(EC::InvalidArg, "", "",
                 "invalid type: expected string-like value");
    }
    return Err(EC::InvalidArg, "", "",
               AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  };

  constexpr bool kStringLike = std::is_constructible_v<std::string, T>;

  if constexpr (kStringLike) {
    if (attr == ClientMetaData::Attr::trash_dir ||
        attr == ClientMetaData::Attr::login_dir ||
        attr == ClientMetaData::Attr::cwd ||
        attr == ClientMetaData::Attr::cmd_template) {
      return OK;
    }
    return Err(EC::InvalidArg, "", "",
               AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }

  return invalid_type();
}

ECM ValidateConfig(const HostConfig &config);
ECM ValidateConfig(const ClientMetaData &metadata);
ECM ValidateConfig(const ConRequest &request);

} // namespace HostService

namespace KnownHostRules {
template <typename T>
[[nodiscard]] inline ECM ValidateFieldValue(KnownHostQuery::Attr attr,
                                            T value) {
  auto invalid_type = [attr]() -> ECM {
    if (attr == KnownHostQuery::Attr::port) {
      return Err(EC::InvalidArg, "", "",
                 "invalid type for port, expected integer or string-like type");
    }
    if (attr == KnownHostQuery::Attr::nickname) {
      return Err(EC::InvalidArg, "", "",
                 "invalid type for nickname, expected string-like type");
    }
    if (attr == KnownHostQuery::Attr::hostname) {
      return Err(EC::InvalidArg, "", "",
                 "invalid type for hostname, expected string-like type");
    }
    if (attr == KnownHostQuery::Attr::protocol) {
      return Err(EC::InvalidArg, "", "",
                 "invalid type for protocol, expected string-like type");
    }
    if (attr == KnownHostQuery::Attr::username) {
      return Err(EC::InvalidArg, "", "",
                 "invalid type for username, expected string-like type");
    }
    if (attr == KnownHostQuery::Attr::fingerprint) {
      return Err(EC::InvalidArg, "", "",
                 "invalid type for fingerprint, expected string-like type");
    }
    return Err(EC::InvalidArg, "", "",
               AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  };

  using DT = std::decay_t<T>;
  constexpr bool kStringLike = std::is_constructible_v<std::string, T>;

  if constexpr (std::is_integral_v<DT> && !std::is_same_v<DT, bool>) {
    if (attr != KnownHostQuery::Attr::port) {
      return invalid_type();
    }
    const int64_t numeric_value = static_cast<int64_t>(value);
    if (numeric_value <= 0 || numeric_value > 65535) {
      return Err(EC::InvalidArg, "", "",
                 "port must be an integer between 1 and 65535");
    }
    return OK;
  }

  if constexpr (kStringLike) {
    const std::string text_value = std::string(value);
    if (attr == KnownHostQuery::Attr::nickname) {
      const std::string text = AMStr::Strip(text_value);
      if (text.empty()) {
        return OK;
      }
      if (!HostService::ValidateNickname(text)) {
        return Err(EC::InvalidArg, "", "",
                   "Invalid nickname: only alphanumeric, underscore, and "
                   "hyphen characters are allowed");
      }
      return OK;
    }
    if (attr == KnownHostQuery::Attr::hostname) {
      if (AMStr::Strip(text_value).empty()) {
        return Err(EC::InvalidArg, "", "", "hostname cannot be empty");
      }
      return OK;
    }
    if (attr == KnownHostQuery::Attr::port) {
      int64_t parsed_port = 0;
      if (!AMStr::GetNumber(text_value, &parsed_port) || parsed_port <= 0 ||
          parsed_port > 65535) {
        return Err(EC::InvalidArg, "", "",
                   "port must be an integer between 1 and 65535");
      }
      return OK;
    }
    if (attr == KnownHostQuery::Attr::protocol) {
      if (AMStr::Strip(text_value).empty()) {
        return Err(EC::InvalidArg, "", "", "protocol cannot be empty");
      }
      return OK;
    }
    if (attr == KnownHostQuery::Attr::username) {
      return OK;
    }
    if (attr == KnownHostQuery::Attr::fingerprint) {
      if (AMStr::Strip(text_value).empty()) {
        return Err(EC::InvalidArg, "", "", "fingerprint cannot be empty");
      }
      return OK;
    }
    return Err(EC::InvalidArg, "", "",
               AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }

  return invalid_type();
}

ECM ValidateConfig(const KnownHostQuery &request);

inline KnownHostKey BuildKnownHostKey(const KnownHostQuery &query) {
  return {AMStr::Strip(query.hostname), query.port,
          AMStr::Strip(query.username),
          AMStr::lowercase(AMStr::Strip(query.protocol))};
}

} // namespace KnownHostRules
} // namespace AMDomain::host
