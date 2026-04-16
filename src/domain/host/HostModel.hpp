#pragma once
#include "foundation/core/Enum.hpp"
#include "foundation/tools/string.hpp"
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace AMDomain::host {
using EC = ErrorCode;

enum class ClientProtocol {
  UnInitilized = -1,
  SFTP = 1,
  FTP = 2,
  LOCAL = 3,
  HTTP = 4
};

/**
 * @brief Client runtime metadata bound to one host profile.
 */
struct ClientMetaData {
  enum class Attr {
    trash_dir = 1,
    login_dir = 2,
    cwd = 3,
    cmd_template = 4,
  };
  std::string trash_dir = "";
  std::string login_dir = "";
  std::string cwd = "";
  std::string cmd_template = "";
  static constexpr auto FieldNames = magic_enum::enum_values<Attr>();
  using MemberPtr = std::variant<std::string ClientMetaData::*>;
  using Value = std::variant<std::string>;
  static_assert(magic_enum::enum_count<Attr>() == 4,
                "ClientMetaData::members must stay aligned with Attr values");
  static constexpr std::array<MemberPtr, magic_enum::enum_count<Attr>()>
      members{&ClientMetaData::trash_dir, &ClientMetaData::login_dir,
              &ClientMetaData::cwd, &ClientMetaData::cmd_template};

  [[nodiscard]] std::vector<std::pair<Attr, Value>> GetDict() const {
    std::vector<std::pair<Attr, Value>> out;
    static_assert(members.size() == FieldNames.size(),
                  "ClientMetaData::members and FieldNames size mismatch");
    out.reserve(FieldNames.size());
    for (size_t i = 0; i < FieldNames.size(); ++i) {
      const Attr attr = FieldNames[i];
      const MemberPtr &mp = members[i];
      std::visit(
          [&](auto member) { out.emplace_back(attr, Value{this->*member}); },
          mp);
    }
    return out;
  }

  /**
   * @brief Return ordered metadata fields as key-value pairs.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  GetStrDict() const {
    const auto dict = GetDict();
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(dict.size());
    for (const auto &entry : dict) {
      const std::string key = std::string(magic_enum::enum_name(entry.first));
      const std::string value = std::visit(
          [](const auto &item) -> std::string {
            using VT = std::decay_t<decltype(item)>;
            static_assert(std::is_same_v<VT, std::string>,
                          "Unsupported type in ClientMetaData::Value");
            if constexpr (std::is_same_v<VT, std::string>) {
              return item;
            }
          },
          entry.second);
      out.emplace_back(key, value);
    }
    return out;
  }

  template <typename T>
  bool GetFieldValue(Attr attr, T *out_value, ECM *rcm = nullptr) const {
    if (!out_value) {
      if (rcm) {
        *rcm = {EC::InvalidArg, "", "", "null output pointer"};
      }
      return false;
    }

    if (rcm) {
      *rcm = OK;
    }

    auto fail = [rcm](const std::string &msg) -> bool {
      if (rcm) {
        *rcm = {EC::InvalidArg, "", "", msg};
      }
      return false;
    };

    if (attr == Attr::trash_dir || attr == Attr::login_dir ||
        attr == Attr::cwd ||
        attr == Attr::cmd_template) {
      if constexpr (std::is_assignable_v<T &, std::string>) {
        if (attr == Attr::trash_dir) {
          *out_value = trash_dir;
        } else if (attr == Attr::login_dir) {
          *out_value = login_dir;
        } else if (attr == Attr::cwd) {
          *out_value = cwd;
        } else {
          *out_value = cmd_template;
        }
        return true;
      }
      return fail("type mismatch: expected std::string output type");
    }

    return fail(AMStr::fmt("Unknown field attr: {}", static_cast<int>(attr)));
  }
};
/**
 * @brief Connection request payload for host/client initialization.
 */
struct ConRequest {
  enum class Attr {
    protocol = 1,
    nickname = 3,
    hostname = 5,
    username = 7,
    port = 9,
    password = 11,
    buffer_size = 13,
    keyfile = 17,
    compression = 19,
  };
  using ClientNickname = std::string;

  ClientNickname nickname = "";
  ClientProtocol protocol = ClientProtocol::SFTP;
  std::string hostname = "";
  std::string username = "";
  int64_t port = 22;
  std::string password = "";
  std::string keyfile = "";
  int64_t buffer_size = 0;
  bool compression = false;
  ConRequest() = default;
  static constexpr auto FieldNames = magic_enum::enum_values<Attr>();
  using MemberPtr =
      std::variant<std::string ConRequest::*, ClientProtocol ConRequest::*,
                   int64_t ConRequest::*, bool ConRequest::*>;
  using Value = std::variant<std::string, ClientProtocol, int64_t, bool>;
  static_assert(magic_enum::enum_count<Attr>() == 9,
                "ConRequest::members must stay aligned with Attr values");
  static constexpr std::array<MemberPtr, magic_enum::enum_count<Attr>()>
      members{&ConRequest::protocol,    &ConRequest::nickname,
              &ConRequest::hostname,    &ConRequest::username,
              &ConRequest::port,        &ConRequest::password,
              &ConRequest::buffer_size, &ConRequest::keyfile,
              &ConRequest::compression};

  ConRequest(ClientProtocol protocol, std::string nickname,
             std::string hostname, std::string username, int port = 22,
             std::string password = "", std::string keyfile = "",
             bool compression = false, int64_t buffer_size = 0)
      : nickname(std::move(nickname)), hostname(std::move(hostname)),
        buffer_size(buffer_size), protocol(protocol), port(port),
        username(std::move(username)), password(std::move(password)),
        keyfile(std::move(keyfile)), compression(std::move(compression)) {}

  [[nodiscard]] std::vector<std::pair<Attr, Value>> GetDict() const {
    std::vector<std::pair<Attr, Value>> out;
    static_assert(members.size() == FieldNames.size(),
                  "ConRequest::members and FieldNames size mismatch");
    out.reserve(FieldNames.size());
    for (size_t i = 0; i < FieldNames.size(); ++i) {
      const Attr attr = FieldNames[i];
      const MemberPtr &mp = members[i];
      std::visit(
          [&](auto member) { out.emplace_back(attr, Value{this->*member}); },
          mp);
    }
    return out;
  }

  /**
   * @brief Return ordered request fields as key-value pairs.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  GetStrDict() const {
    const auto dict = GetDict();
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(dict.size());

    for (const auto &entry : dict) {
      if (entry.first == Attr::buffer_size) {
        continue;
      }
      const std::string key = std::string(magic_enum::enum_name(entry.first));
      const std::string value = std::visit(
          [&](const auto &item) -> std::string {
            using VT = std::decay_t<decltype(item)>;
            static_assert(std::is_same_v<VT, std::string> ||
                              std::is_same_v<VT, bool> ||
                              std::is_same_v<VT, int64_t> ||
                              std::is_same_v<VT, ClientProtocol>,
                          "Unsupported type in ConRequest::Value");
            if constexpr (std::is_same_v<VT, ClientProtocol>) {
              return AMStr::lowercase(AMStr::ToString(item));
            }
            if constexpr (std::is_same_v<VT, bool>) {
              return item ? "true" : "false";
            }
            if constexpr (std::is_same_v<VT, int64_t>) {
              return std::to_string(item);
            }
            if constexpr (std::is_same_v<VT, std::string>) {
              return item;
            }
          },
          entry.second);
      out.emplace_back(key, value);
    }

    return out;
  }

  template <typename T>
  bool GetFieldValue(Attr attr, T *out_value, ECM *rcm = nullptr) const {
    if (!out_value) {
      if (rcm)
        *rcm = {EC::InvalidArg, "", "", "null output pointer"};
      return false;
    }

    auto idx = magic_enum::enum_index(attr);
    if (!idx) {
      if (rcm)
        *rcm = {EC::InvalidArg, "", "", "invalid attr"};
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
      *rcm = {EC::InvalidArg, "", "", "type mismatch"};
    }

    return ok;
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
private:
  std::string fingerprint_ = "";

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
  static constexpr auto FieldNames = magic_enum::enum_values<Attr>();
  using MemberPtr =
      std::variant<std::string KnownHostQuery::*, int KnownHostQuery::*>;
  using Value = std::variant<std::string, int>;
  static_assert(magic_enum::enum_count<Attr>() == 6,
                "KnownHostQuery::members must stay aligned with Attr values");
  static constexpr std::array<MemberPtr, magic_enum::enum_count<Attr>()>
      members{&KnownHostQuery::nickname, &KnownHostQuery::hostname,
              &KnownHostQuery::port,     &KnownHostQuery::protocol,
              &KnownHostQuery::username, &KnownHostQuery::fingerprint_};

  /**
   * @brief Construct one query from explicit host identity fields.
   */
  KnownHostQuery(std::string_view nickname, std::string_view hostname, int port,
                 std::string_view protocol, std::string_view username,
                 std::string_view fingerprint = "")
      : fingerprint_(fingerprint), nickname(nickname), hostname(hostname),
        port(port), protocol(protocol), username(username) {}

  /**
   * @brief Construct one empty query.
   */
  KnownHostQuery() = default;

  [[nodiscard]] std::vector<std::pair<Attr, Value>> GetDict() const {
    std::vector<std::pair<Attr, Value>> out;
    static_assert(members.size() == FieldNames.size(),
                  "KnownHostQuery::members and FieldNames size mismatch");
    out.reserve(FieldNames.size());
    for (size_t i = 0; i < FieldNames.size(); ++i) {
      const Attr attr = FieldNames[i];
      const MemberPtr &mp = members[i];
      std::visit(
          [&](auto member) { out.emplace_back(attr, Value{this->*member}); },
          mp);
    }
    return out;
  }

  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  GetStrDict() const {
    const auto dict = GetDict();
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(dict.size());
    for (const auto &entry : dict) {
      const std::string key = std::string(magic_enum::enum_name(entry.first));
      const std::string value = std::visit(
          [](const auto &item) -> std::string {
            static_assert(
                std::is_same_v<std::decay_t<decltype(item)>, std::string> ||
                    std::is_same_v<std::decay_t<decltype(item)>, int>,
                "Unsupported type in KnownHostQuery::Value");
            using VT = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<VT, int>) {
              return std::to_string(item);
            } else if constexpr (std::is_same_v<VT, std::string>) {
              return item;
            }
          },
          entry.second);
      out.emplace_back(key, value);
    }
    return out;
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

  template <typename T>
  bool GetFieldValue(Attr attr, T *out_value, ECM *rcm = nullptr) const {
    if (!out_value) {
      if (rcm) {
        *rcm = {EC::InvalidArg, "", "", "null output pointer"};
      }
      return false;
    }

    if (rcm) {
      *rcm = OK;
    }

    auto fail = [rcm](const std::string &msg) -> bool {
      if (rcm) {
        *rcm = {EC::InvalidArg, "", "", msg};
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

struct KnownHostEntryArg {
  KnownHostMap entries = {};
};
} // namespace AMDomain::host

