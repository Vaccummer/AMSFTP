#pragma once
#include "foundation/Enum.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace AMDomain::host {
using EC = ErrorCode;
using ECM = std::pair<ErrorCode, std::string>;

enum class ClientProtocol { UnInitilized = -1, SFTP = 1, FTP = 2, LOCAL = 3 };

/**
 * @brief Validate host nickname text.
 */
inline bool ValidateNickname(const std::string &nickname) {
  if (nickname.empty()) {
    return false;
  }
  for (const auto &ch : nickname) {
    if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' ||
        ch == '-') {
      continue;
    }
    return false;
  }
  return true;
}

/**
 * @brief Convert protocol text to protocol enum.
 */
inline ClientProtocol StrToProtocol(const std::string &protocol_str) {
  auto key = AMStr::lowercase(AMStr::Strip(protocol_str));
  if (key == "sftp") {
    return ClientProtocol::SFTP;
  }
  if (key == "ftp") {
    return ClientProtocol::FTP;
  }
  if (key == "local") {
    return ClientProtocol::LOCAL;
  }
  return ClientProtocol::SFTP;
}

namespace detail {
/**
 * @brief Parse one boolean from stripped text without JSON helpers.
 */
inline bool ParseBoolText(const std::string &text, bool *out) {
  if (!out) {
    return false;
  }
  const std::string normalized = AMStr::lowercase(AMStr::Strip(text));
  if (normalized == "true" || normalized == "1" || normalized == "yes" ||
      normalized == "y" || normalized == "on") {
    *out = true;
    return true;
  }
  if (normalized == "false" || normalized == "0" || normalized == "no" ||
      normalized == "n" || normalized == "off") {
    *out = false;
    return true;
  }
  return false;
}

/**
 * @brief Parse one signed integral value from stripped text without JSON helpers.
 */
template <typename T>
inline bool ParseIntegralText(const std::string &text, T *out) {
  static_assert(std::is_integral_v<T> && !std::is_same_v<T, bool>);
  if (!out) {
    return false;
  }
  const std::string trimmed = AMStr::Strip(text);
  if (trimmed.empty()) {
    return false;
  }
  std::istringstream iss(trimmed);
  long long parsed = 0;
  char extra = '\0';
  if (!(iss >> parsed)) {
    return false;
  }
  if (iss >> extra) {
    return false;
  }
  if (parsed < static_cast<long long>(std::numeric_limits<T>::min()) ||
      parsed > static_cast<long long>(std::numeric_limits<T>::max())) {
    return false;
  }
  *out = static_cast<T>(parsed);
  return true;
}
} // namespace detail

/**
 * @brief Client runtime metadata bound to one host profile.
 */
struct ClientMetaData {
  enum class Attr {
    login_dir = 1,
    cwd = 2,
    cmd_prefix = 3,
    wrap_cmd = 4,
  };

  std::string login_dir = "";
  std::string cwd = "";
  std::string cmd_prefix = "";
  bool wrap_cmd = false;

  /**
   * @brief Return ordered metadata fields as key-value pairs.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  GetStrDict() const {
    return {
        {"login_dir", login_dir},
        {"cwd", cwd},
        {"cmd_prefix", cmd_prefix},
        {"wrap_cmd", wrap_cmd ? "true" : "false"},
    };
  }

  [[nodiscard]] static std::vector<Attr> GetFieldNames() {
    static const std::vector<Attr> attrs = []() {
      auto values = magic_enum::enum_values<Attr>();
      return std::vector<Attr>(values.begin(), values.end());
    }();
    return attrs;
  }

  template <typename T>
  bool GetFieldValue(Attr attr, T *out_value, ECM *rcm = nullptr) const {
    if (!out_value) {
      if (rcm) {
        *rcm = {EC::InvalidArg, "null output pointer"};
      }
      return false;
    }

    if (rcm) {
      *rcm = {EC::Success, ""};
    }

    auto fail = [rcm](const std::string &msg) -> bool {
      if (rcm) {
        *rcm = {EC::InvalidArg, msg};
      }
      return false;
    };

    if (attr == Attr::login_dir || attr == Attr::cwd ||
        attr == Attr::cmd_prefix) {
      if constexpr (std::is_assignable_v<T &, std::string>) {
        if (attr == Attr::login_dir) {
          *out_value = login_dir;
        } else if (attr == Attr::cwd) {
          *out_value = cwd;
        } else {
          *out_value = cmd_prefix;
        }
        return true;
      }
      return fail("type mismatch: expected std::string output type");
    }

    if (attr == Attr::wrap_cmd) {
      if constexpr (std::is_same_v<T, bool>) {
        *out_value = wrap_cmd;
        return true;
      }
      return fail("type mismatch: expected bool output type for wrap_cmd");
    }

    return fail(AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }

  template <typename T>
  bool ValidateFieldValue(Attr attr, const T &value, ECM *rcm) {
    if (rcm) {
      *rcm = {EC::Success, ""};
    }

    auto fail = [rcm](EC code, const std::string &msg) -> bool {
      if (rcm) {
        *rcm = {code, msg};
      }
      return false;
    };

    constexpr bool kStringLike = std::is_constructible_v<std::string, T>;

    if (attr == Attr::login_dir || attr == Attr::cwd ||
        attr == Attr::cmd_prefix) {
      if constexpr (kStringLike) {
        return true;
      }
      return fail(EC::InvalidArg, "invalid type: expected string-like value");
    }

    if (attr == Attr::wrap_cmd) {
      if constexpr (std::is_same_v<std::decay_t<T>, bool>) {
        return true;
      }
      if constexpr (kStringLike) {
        bool parsed = false;
        if (!detail::ParseBoolText(std::string(value), &parsed)) {
          return fail(EC::InvalidArg, "wrap_cmd must be true or false");
        }
        return true;
      }
      return fail(EC::InvalidArg, "invalid type: expected bool or string-like");
    }

    return fail(EC::InvalidArg,
                AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }
};
/**
 * @brief Connection request payload for host/client initialization.
 */
struct ConRequest {
  enum class Attr {
    nickname = 3,
    protocol = 1,
    hostname = 5,
    username = 7,
    port = 9,
    password = 11,
    buffer_size = 13,
    trash_dir = 15,
    keyfile = 17,
    compression = 19,
  };

  std::string nickname = "";
  ClientProtocol protocol = ClientProtocol::SFTP;
  std::string hostname = "";
  std::string username = "";
  int64_t port = 22;
  std::string password = "";
  std::string keyfile = "";
  int64_t buffer_size = 0;
  bool compression = false;
  std::string trash_dir = "";
  ConRequest() = default;
  static constexpr auto FieldNames = magic_enum::enum_values<Attr>();
  using MemberPtr =
      std::variant<std::string ConRequest::*, ClientProtocol ConRequest::*,
                   int64_t ConRequest::*, bool ConRequest::*>;
  static constexpr std::array<MemberPtr, magic_enum::enum_count<Attr>()>
      members{&ConRequest::nickname,    &ConRequest::hostname,
              &ConRequest::username,    &ConRequest::password,
              &ConRequest::trash_dir,   &ConRequest::keyfile,
              &ConRequest::protocol,    &ConRequest::port,
              &ConRequest::buffer_size, &ConRequest::compression};

  ConRequest(ClientProtocol protocol, std::string nickname,
             std::string hostname, std::string username, int port = 22,
             std::string password = "", std::string keyfile = "",
             bool compression = false, std::string trash_dir = "",
             int64_t buffer_size = 0)
      : nickname(std::move(nickname)), hostname(std::move(hostname)),
        trash_dir(std::move(trash_dir)), buffer_size(buffer_size),
        protocol(protocol), port(port), username(std::move(username)),
        password(std::move(password)), keyfile(std::move(keyfile)),
        compression(std::move(compression)) {}

  /**
   * @brief Return ordered request fields as key-value pairs.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  GetStrDict() const {
    return {
        {"nickname", nickname},
        {"protocol", AMStr::lowercase(AMStr::ToString(protocol))},
        {"hostname", hostname},
        {"username", username},
        {"port", std::to_string(port)},
        {"password", password},
        {"keyfile", keyfile},
        {"buffer_size", std::to_string(buffer_size)},
        {"compression", compression ? "true" : "false"},
        {"trash_dir", trash_dir},
    };
  }

  template <typename T>
  bool GetFieldValue2(Attr attr, T *out_value, ECM *rcm = nullptr) const {
    if (!out_value) {
      if (rcm) {
        *rcm = {EC::InvalidArg, "null output pointer"};
      }
      return false;
    }

    if (rcm) {
      *rcm = {EC::Success, ""};
    }

    auto fail = [rcm](const std::string &msg) -> bool {
      if (rcm) {
        *rcm = {EC::InvalidArg, msg};
      }
      return false;
    };

    if (attr == Attr::nickname || attr == Attr::hostname ||
        attr == Attr::username || attr == Attr::password ||
        attr == Attr::trash_dir || attr == Attr::keyfile) {
      if constexpr (std::is_assignable_v<T &, std::string>) {
        if (attr == Attr::nickname) {
          *out_value = nickname;
        } else if (attr == Attr::hostname) {
          *out_value = hostname;
        } else if (attr == Attr::username) {
          *out_value = username;
        } else if (attr == Attr::password) {
          *out_value = password;
        } else if (attr == Attr::trash_dir) {
          *out_value = trash_dir;
        } else {
          *out_value = keyfile;
        }
        return true;
      }
      return fail("type mismatch: expected std::string output type");
    }

    if (attr == Attr::protocol) {
      if constexpr (std::is_assignable_v<T &, ClientProtocol>) {
        *out_value = protocol;
        return true;
      }
      return fail("type mismatch: expected ClientProtocol output type");
    }

    if (attr == Attr::port) {
      if constexpr (std::is_integral_v<T> && !std::is_same_v<T, bool>) {
        *out_value = static_cast<T>(port);
        return true;
      }
      return fail("type mismatch: expected integral output type for port");
    }

    if (attr == Attr::buffer_size) {
      if constexpr (std::is_integral_v<T> && !std::is_same_v<T, bool>) {
        *out_value = static_cast<T>(buffer_size);
        return true;
      }
      return fail(
          "type mismatch: expected integral output type for buffer_size");
    }

    if (attr == Attr::compression) {
      if constexpr (std::is_same_v<T, bool>) {
        *out_value = compression;
        return true;
      }
      return fail("type mismatch: expected bool output type for compression");
    }

    return fail(AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }

  template <typename T>
  bool GetFieldValue(Attr attr, T *out_value, ECM *rcm = nullptr) const {
    if (!out_value) {
      if (rcm)
        *rcm = {EC::InvalidArg, "null output pointer"};
      return false;
    }

    auto idx = magic_enum::enum_index(attr);
    if (!idx) {
      if (rcm)
        *rcm = {EC::InvalidArg, "invalid attr"};
      return false;
    }

    const auto &mp = members[*idx];

    bool ok = std::visit(
        [&](auto member) -> bool {
          using Field = std::decay_t<decltype(this->*member)>;

          if constexpr (std::is_assignable_v<T &, Field>) {
            *out_value = this->*member;
            return true;
          }

          if constexpr (std::is_integral_v<T> && std::is_integral_v<Field> &&
                        !std::is_same_v<T, bool>) {
            *out_value = static_cast<T>(this->*member);
            return true;
          }

          return false;
        },
        mp);

    if (!ok && rcm) {
      *rcm = {EC::InvalidArg, "type mismatch"};
    }

    return ok;
  }

  template <typename T>
  bool ValidateFieldValue(Attr attr, const T &value, ECM *rcm) {
    if (rcm) {
      *rcm = {EC::Success, ""};
    }

    auto fail = [rcm](EC code, const std::string &msg) -> bool {
      if (rcm) {
        *rcm = {code, msg};
      }
      return false;
    };

    using DT = std::decay_t<T>;
    constexpr bool kStringLike = std::is_constructible_v<std::string, T>;

    if (attr == Attr::nickname) {
      if constexpr (kStringLike) {
        const std::string text = AMStr::Strip(std::string(value));
        if (!ValidateNickname(text)) {
          return fail(EC::InvalidArg,
                      "Invalid nickname: only alphanumeric, underscore, and "
                      "hyphen characters are allowed");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "Invalid type for nickname, expected string-like type");
    }

    if (attr == Attr::hostname) {
      if constexpr (kStringLike) {
        if (AMStr::Strip(std::string(value)).empty()) {
          return fail(EC::InvalidArg, "Hostname cannot be empty");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "Invalid type for hostname, expected string-like type");
    }

    if (attr == Attr::username) {
      if constexpr (kStringLike) {
        if (AMStr::Strip(std::string(value)).empty()) {
          return fail(EC::InvalidArg, "Username cannot be empty");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "Invalid type for username, expected string-like type");
    }

    if (attr == Attr::protocol) {
      if constexpr (std::is_same_v<DT, ClientProtocol>) {
        if (value == ClientProtocol::UnInitilized) {
          return fail(EC::InvalidArg, "Unsupported protocol");
        }
        return true;
      }
      if constexpr (kStringLike) {
        const std::string text =
            AMStr::lowercase(AMStr::Strip(std::string(value)));
        if (text == "sftp" || text == "ftp" || text == "local") {
          return true;
        }
        return fail(EC::InvalidArg, "Protocol must be sftp, ftp, or local");
      }
      return fail(EC::InvalidArg,
                  "Invalid type for protocol, expected ClientProtocol or "
                  "string-like type");
    }

    if (attr == Attr::port) {
      if constexpr (std::is_integral_v<DT> && !std::is_same_v<DT, bool>) {
        const auto port_value = static_cast<int64_t>(value);
        if (port_value <= 0 || port_value > 65535) {
          return fail(EC::InvalidArg,
                      "Port must be an integer between 1 and 65535");
        }
        return true;
      }
      if constexpr (kStringLike) {
        int64_t port_value = 0;
        if (!detail::ParseIntegralText(std::string(value), &port_value) ||
            port_value <= 0 || port_value > 65535) {
          return fail(EC::InvalidArg,
                      "Port must be an integer between 1 and 65535");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "Invalid type for port, expected integer or string-like "
                  "type");
    }

    if (attr == Attr::password || attr == Attr::keyfile ||
        attr == Attr::trash_dir) {
      if constexpr (kStringLike) {
        return true;
      }
      return fail(EC::InvalidArg,
                  "Invalid type for path/text field, expected string-like "
                  "type");
    }

    if (attr == Attr::buffer_size) {
      if constexpr (std::is_integral_v<DT> && !std::is_same_v<DT, bool>) {
        const auto size_value = static_cast<int64_t>(value);
        if (size_value <= 0 ||
            size_value > static_cast<int64_t>(AMMaxBufferSize)) {
          return fail(EC::InvalidArg,
                      "Buffer size must be a positive integer and not exceed "
                      "AMMaxBufferSize");
        }
        return true;
      }
      if constexpr (kStringLike) {
        int64_t size_value = 0;
        if (!detail::ParseIntegralText(std::string(value), &size_value) ||
            size_value <= 0 ||
            size_value > static_cast<int64_t>(AMMaxBufferSize)) {
          return fail(EC::InvalidArg,
                      "Buffer size must be a positive integer and not exceed "
                      "AMMaxBufferSize");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "Invalid type for buffer_size, expected integer or "
                  "string-like type");
    }

    if (attr == Attr::compression) {
      if constexpr (std::is_same_v<DT, bool>) {
        return true;
      }
      if constexpr (kStringLike) {
        bool bool_value = false;
        if (!detail::ParseBoolText(std::string(value), &bool_value)) {
          return fail(EC::InvalidArg, "Compression must be true or false");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "Invalid type for compression, expected bool or "
                  "string-like type");
    }

    return fail(EC::InvalidArg,
                AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }

  /**
   * @brief Validate connection request fields.
   */
  [[nodiscard]] bool IsValid(std::string *error_info = nullptr) const {
    if (protocol == ClientProtocol::UnInitilized) {
      if (error_info) {
        error_info->clear();
        *error_info =
            AMStr::fmt("Unsupported protocol: {}", AMStr::ToString(protocol));
      }
      return false;
    }
    if (nickname.empty()) {
      if (error_info) {
        error_info->clear();
        *error_info = "Invalid empty nickname";
      }
      return false;
    }
    if (protocol == ClientProtocol::LOCAL) {
      return true;
    }
    if (hostname.empty()) {
      if (error_info) {
        error_info->clear();
        *error_info = "Invalid empty hostname, and  protocol is not LOCAL";
      }
      return false;
    }
    if (username.empty()) {
      if (error_info) {
        error_info->clear();
        *error_info = "Invalid empty username, and  protocol is not LOCAL";
      }
      return false;
    }
    if (port <= 0 || port > 65535) {
      if (error_info) {
        error_info->clear();
        *error_info = "Invalid port: out of range 1-65535";
      }
      return false;
    }
    return true;
  }
};

/**
 * @brief Domain model for one host configuration entry.
 */
struct HostConfig {
  ConRequest request = {};
  ClientMetaData metadata = {};

  /**
   * @brief Return ordered fields as key-value pairs.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  GetStrDict() const {
    auto pairs = request.GetStrDict();
    auto metadata_pairs = metadata.GetStrDict();
    pairs.insert(pairs.end(), metadata_pairs.begin(), metadata_pairs.end());
    return pairs;
  }
  HostConfig() = default;
};

/**
 * @brief Value object used to identify and validate one known-host entry.
 *
 * This model is shared by domain services and infrastructure adapters.
 */
class KnownHostQuery {
public:
  enum class Attr {
    nickname = 1,
    hostname = 2,
    port = 3,
    protocol = 4,
    username = 5,
    fingerprint = 6,
  };

  std::string nickname = "";
  std::string hostname = "";
  int port = 0;
  std::string protocol = "";
  std::string username = "";

  /**
   * @brief Construct one query from explicit host identity fields.
   */
  KnownHostQuery(std::string_view nickname, std::string_view hostname, int port,
                 std::string_view protocol, std::string_view username,
                 std::string_view fingerprint = "")
      : nickname(nickname), hostname(hostname), port(port), protocol(protocol),
        username(username), fingerprint_(fingerprint) {}

  /**
   * @brief Construct one empty query.
   */
  KnownHostQuery() = default;

  /**
   * @brief Return whether the query has minimum valid host identity fields.
   */
  [[nodiscard]] bool IsValid() const {
    return !hostname.empty() && port > 0 && port <= 65535;
  }

  /**
   * @brief Build hierarchical config path keys for known-host storage lookup.
   */
  [[nodiscard]] std::vector<std::string> GetPath() const {
    return {hostname, std::to_string(port), username, protocol};
  }

  /**
   * @brief Set fingerprint value.
   *
   * @return True when non-empty fingerprint is accepted.
   */
  bool SetFingerprint(const std::string &fingerprint) {
    if (fingerprint.empty()) {
      return false;
    }
    fingerprint_ = fingerprint;
    return true;
  }

  /**
   * @brief Get currently stored fingerprint text.
   */
  [[nodiscard]] std::string GetFingerprint() const { return fingerprint_; }

  [[nodiscard]] static std::vector<Attr> GetFieldNames() {
    static const std::vector<Attr> attrs = []() {
      auto values = magic_enum::enum_values<Attr>();
      std::sort(values.begin(), values.end(), [](Attr a, Attr b) {
        return static_cast<int>(a) < static_cast<int>(b);
      });
      return std::vector<Attr>(values.begin(), values.end());
    }();
    return attrs;
  }

  template <typename T>
  bool GetFieldValue(Attr attr, T *out_value, ECM *rcm = nullptr) const {
    if (!out_value) {
      if (rcm) {
        *rcm = {EC::InvalidArg, "null output pointer"};
      }
      return false;
    }

    if (rcm) {
      *rcm = {EC::Success, ""};
    }

    auto fail = [rcm](const std::string &msg) -> bool {
      if (rcm) {
        *rcm = {EC::InvalidArg, msg};
      }
      return false;
    };

    if (attr == Attr::nickname || attr == Attr::hostname ||
        attr == Attr::protocol || attr == Attr::username ||
        attr == Attr::fingerprint) {
      if constexpr (std::is_assignable_v<T &, std::string>) {
        if (attr == Attr::nickname) {
          *out_value = nickname;
        } else if (attr == Attr::hostname) {
          *out_value = hostname;
        } else if (attr == Attr::protocol) {
          *out_value = protocol;
        } else if (attr == Attr::username) {
          *out_value = username;
        } else {
          *out_value = fingerprint_;
        }
        return true;
      }
      return fail("type mismatch: expected std::string output type");
    }

    if (attr == Attr::port) {
      if constexpr (std::is_integral_v<T> && !std::is_same_v<T, bool>) {
        *out_value = static_cast<T>(port);
        return true;
      }
      return fail("type mismatch: expected integral output type for port");
    }

    return fail(AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }

  template <typename T>
  bool ValidateFieldValue(Attr attr, const T &value, ECM *rcm) {
    if (rcm) {
      *rcm = {EC::Success, ""};
    }

    auto fail = [rcm](EC code, const std::string &msg) -> bool {
      if (rcm) {
        *rcm = {code, msg};
      }
      return false;
    };

    using DT = std::decay_t<T>;
    constexpr bool kStringLike = std::is_constructible_v<std::string, T>;

    if (attr == Attr::nickname) {
      if constexpr (kStringLike) {
        const std::string text = AMStr::Strip(std::string(value));
        if (text.empty()) {
          return true;
        }
        if (!ValidateNickname(text)) {
          return fail(EC::InvalidArg,
                      "Invalid nickname: only alphanumeric, underscore, and "
                      "hyphen characters are allowed");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "invalid type for nickname, expected string-like type");
    }

    if (attr == Attr::hostname) {
      if constexpr (kStringLike) {
        if (AMStr::Strip(std::string(value)).empty()) {
          return fail(EC::InvalidArg, "hostname cannot be empty");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "invalid type for hostname, expected string-like type");
    }

    if (attr == Attr::port) {
      if constexpr (std::is_integral_v<DT> && !std::is_same_v<DT, bool>) {
        const int64_t v = static_cast<int64_t>(value);
        if (v <= 0 || v > 65535) {
          return fail(EC::InvalidArg,
                      "port must be an integer between 1 and 65535");
        }
        return true;
      }
      if constexpr (kStringLike) {
        int64_t v = 0;
        if (!detail::ParseIntegralText(std::string(value), &v) ||
            v <= 0 || v > 65535) {
          return fail(EC::InvalidArg,
                      "port must be an integer between 1 and 65535");
        }
        return true;
      }
      return fail(
          EC::InvalidArg,
          "invalid type for port, expected integer or string-like type");
    }

    if (attr == Attr::protocol) {
      if constexpr (kStringLike) {
        if (AMStr::Strip(std::string(value)).empty()) {
          return fail(EC::InvalidArg, "protocol cannot be empty");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "invalid type for protocol, expected string-like type");
    }

    if (attr == Attr::username) {
      if constexpr (kStringLike) {
        return true;
      }
      return fail(EC::InvalidArg,
                  "invalid type for username, expected string-like type");
    }

    if (attr == Attr::fingerprint) {
      if constexpr (kStringLike) {
        if (AMStr::Strip(std::string(value)).empty()) {
          return fail(EC::InvalidArg, "fingerprint cannot be empty");
        }
        return true;
      }
      return fail(EC::InvalidArg,
                  "invalid type for fingerprint, expected string-like type");
    }

    return fail(EC::InvalidArg,
                AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }

private:
  std::string fingerprint_ = "";
};

/**
 * @brief Aggregated host config payload used by host domain managers.
 */
struct HostConfigArg {
  std::map<std::string, HostConfig> host_configs = {};
  HostConfig local_config = {};
  std::vector<std::string> private_keys = {};
};

/**
 * @brief Aggregated known-host payload used by host domain managers.
 */
using KnownHostKey =
    std::tuple<std::string, int, std::string,
               std::string>; // hostname, port, username, protocol
using KnownHostMap = std::map<KnownHostKey, KnownHostQuery>;

/**
 * @brief Build normalized known-host map key from one query.
 */
inline KnownHostKey BuildKnownHostKey(const KnownHostQuery &query) {
  return {AMStr::Strip(query.hostname), query.port,
          AMStr::Strip(query.username),
          AMStr::lowercase(AMStr::Strip(query.protocol))};
}

struct KnownHostEntryArg {
  KnownHostMap entries = {};
};

/**
 * @brief Parse a host attribute name into HostAttr.

inline bool ParseHostAttr(const std::string &attr_name, HostAttr *out_attr) {
  if (!out_attr) {
    return false;
  }
  const std::string key = AMStr::lowercase(AMStr::Strip(attr_name));
  if (key == "nickname") {
    *out_attr = HostAttr::Nickname;
    return true;
  }
  if (key == "hostname") {
    *out_attr = HostAttr::Hostname;
    return true;
  }
  if (key == "username") {
    *out_attr = HostAttr::Username;
    return true;
  }
  if (key == "port") {
    *out_attr = HostAttr::Port;
    return true;
  }
  if (key == "password") {
    *out_attr = HostAttr::Password;
    return true;
  }
  if (key == "protocol") {
    *out_attr = HostAttr::Protocol;
    return true;
  }
  if (key == "buffer_size") {
    *out_attr = HostAttr::BufferSize;
    return true;
  }
  if (key == "trash_dir") {
    *out_attr = HostAttr::TrashDir;
    return true;
  }
  if (key == "login_dir") {
    *out_attr = HostAttr::LoginDir;
    return true;
  }
  if (key == "keyfile") {
    *out_attr = HostAttr::Keyfile;
    return true;
  }
  if (key == "compression") {
    *out_attr = HostAttr::Compression;
    return true;
  }
  if (key == "cmd_prefix") {
    *out_attr = HostAttr::CmdPrefix;
    return true;
  }
  if (key == "wrap_cmd") {
    *out_attr = HostAttr::WrapCmd;
    return true;
  }
  return false;
}*/

/**
 * @brief Validate one host attribute value.

bool ValidateHostAttrValue(HostAttr attr, const std::string &value,
                           std::string *normalized = nullptr,
                           std::string *error_msg = nullptr,
                           bool allow_exists_hostname = true,
                           bool allow_local_hostname = true,
                           EC *code = nullptr);
 */

/** @brief Backward-compatible alias. Prefer HostConfig. */
using ClientConfig = HostConfig;
} // namespace AMDomain::host
