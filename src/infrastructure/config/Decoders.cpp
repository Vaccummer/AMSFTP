#include "domain/config/ConfigModel.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/string.hpp"
#include "internal/ArgCodecRegistry.hpp"
#include <algorithm>
#include <cstdint>
#include <tuple>

namespace {
using TypeTag = AMDomain::arg::TypeTag;
using DocumentKind = AMDomain::config::DocumentKind;

namespace codec_common {
/**
 * @brief Set optional error text and return false.
 */
bool Fail_(std::string *error, const std::string &msg) {
  if (error) {
    *error = msg;
  }
  return false;
}
} // namespace codec_common

namespace config_arg_codec {
/**
 * @brief Codec for generic config-document json payload.
 */
class ConfigArgCodec final : public AMInfra::config::IArgCodec {
public:
  /**
   * @brief Return codec type tag.
   */
  [[nodiscard]] TypeTag Tag() const override { return TypeTag::Config; }

  /**
   * @brief Return codec document kind.
   */
  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Config;
  }

  /**
   * @brief Decode root json into ConfigArg.
   */
  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output ConfigArg");
    }
    auto *typed = static_cast<AMDomain::arg::ConfigArg *>(out);
    typed->value = root;
    return true;
  }

  /**
   * @brief Encode ConfigArg into root json.
   */
  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error, "null input ConfigArg or root json");
    }
    const auto *typed = static_cast<const AMDomain::arg::ConfigArg *>(in);
    *root = typed->value;
    return true;
  }
};
} // namespace config_arg_codec

namespace settings_arg_codec {
/**
 * @brief Codec for generic settings-document json payload.
 */
class SettingsArgCodec final : public AMInfra::config::IArgCodec {
public:
  /**
   * @brief Return codec type tag.
   */
  [[nodiscard]] TypeTag Tag() const override { return TypeTag::Settings; }

  /**
   * @brief Return codec document kind.
   */
  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  /**
   * @brief Decode root json into SettingsArg.
   */
  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output SettingsArg");
    }
    auto *typed = static_cast<AMDomain::arg::SettingsArg *>(out);
    typed->value = root;
    return true;
  }

  /**
   * @brief Encode SettingsArg into root json.
   */
  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error, "null input SettingsArg or root json");
    }
    const auto *typed = static_cast<const AMDomain::arg::SettingsArg *>(in);
    *root = typed->value;
    return true;
  }
};
} // namespace settings_arg_codec

namespace known_hosts_arg_codec {
/**
 * @brief Codec for generic known-hosts json payload.
 */
class KnownHostsArgCodec final : public AMInfra::config::IArgCodec {
public:
  /**
   * @brief Return codec type tag.
   */
  [[nodiscard]] TypeTag Tag() const override { return TypeTag::KnownHosts; }

  /**
   * @brief Return codec document kind.
   */
  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::KnownHosts;
  }

  /**
   * @brief Decode root json into KnownHostsArg.
   */
  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output KnownHostsArg");
    }
    auto *typed = static_cast<AMDomain::arg::KnownHostsArg *>(out);
    typed->value = root;
    return true;
  }

  /**
   * @brief Encode KnownHostsArg into root json.
   */
  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input KnownHostsArg or root json");
    }
    const auto *typed = static_cast<const AMDomain::arg::KnownHostsArg *>(in);
    *root = typed->value;
    return true;
  }
};
} // namespace known_hosts_arg_codec

namespace history_arg_codec {
/**
 * @brief Codec for generic history-document json payload.
 */
class HistoryArgCodec final : public AMInfra::config::IArgCodec {
public:
  /**
   * @brief Return codec type tag.
   */
  [[nodiscard]] TypeTag Tag() const override { return TypeTag::History; }

  /**
   * @brief Return codec document kind.
   */
  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::History;
  }

  /**
   * @brief Decode root json into HistoryArg.
   */
  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output HistoryArg");
    }
    auto *typed = static_cast<AMDomain::arg::HistoryArg *>(out);
    typed->value = root;
    return true;
  }

  /**
   * @brief Encode HistoryArg into root json.
   */
  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error, "null input HistoryArg or root json");
    }
    const auto *typed = static_cast<const AMDomain::arg::HistoryArg *>(in);
    *root = typed->value;
    return true;
  }
};
} // namespace history_arg_codec

namespace host_config_arg_codec {
inline constexpr const char *kHostsKey = "HOSTS";
inline constexpr const char *kPrivateKeysKey = "private_keys";
inline constexpr const char *kHostnameKey = "hostname";
inline constexpr const char *kUsernameKey = "username";
inline constexpr const char *kPortKey = "port";
inline constexpr const char *kPasswordKey = "password";
inline constexpr const char *kProtocolKey = "protocol";
inline constexpr const char *kBufferSizeKey = "buffer_size";
inline constexpr const char *kTrashDirKey = "trash_dir";
inline constexpr const char *kLoginDirKey = "login_dir";
inline constexpr const char *kCwdKey = "cwd";
inline constexpr const char *kKeyFileKey = "keyfile";
inline constexpr const char *kCompressionKey = "compression";
inline constexpr const char *kCmdPrefixKey = "cmd_prefix";
inline constexpr const char *kWrapCmdKey = "wrap_cmd";
inline constexpr int kDefaultSFTPPort = 22;
inline constexpr int kDefaultFTPPort = 21;

/**
 * @brief Decode one host entry JSON object into domain host config.
 */
bool DecodeHostConfig_(const std::string &nickname, const Json &json,
                       AMDomain::host::HostConfig *out, std::string *error) {
  if (!out) {
    return codec_common::Fail_(error, "null output host config");
  }
  if (!json.is_object()) {
    return codec_common::Fail_(error, "host entry is not object");
  }

  AMDomain::host::HostConfig cfg = {};
  cfg.request.nickname = nickname;

  (void)AMJson::QueryKey(json, {kHostnameKey}, &cfg.request.hostname);
  (void)AMJson::QueryKey(json, {kUsernameKey}, &cfg.request.username);
  (void)AMJson::QueryKey(json, {kPasswordKey}, &cfg.request.password);
  (void)AMJson::QueryKey(json, {kKeyFileKey}, &cfg.request.keyfile);
  (void)AMJson::QueryKey(json, {kTrashDirKey}, &cfg.request.trash_dir);
  (void)AMJson::QueryKey(json, {kCompressionKey}, &cfg.request.compression);
  (void)AMJson::QueryKey(json, {kLoginDirKey}, &cfg.metadata.login_dir);
  (void)AMJson::QueryKey(json, {kCwdKey}, &cfg.metadata.cwd);
  (void)AMJson::QueryKey(json, {kCmdPrefixKey}, &cfg.metadata.cmd_prefix);
  (void)AMJson::QueryKey(json, {kWrapCmdKey}, &cfg.metadata.wrap_cmd);

  std::string protocol_str = "sftp";
  (void)AMJson::QueryKey(json, {kProtocolKey}, &protocol_str);
  cfg.request.protocol = AMDomain::host::StrToProtocol(protocol_str);

  int parsed_port = 0;
  if (AMJson::QueryKey(json, {kPortKey}, &parsed_port) && parsed_port > 0 &&
      parsed_port <= 65535) {
    cfg.request.port = parsed_port;
  } else {
    cfg.request.port =
        (cfg.request.protocol == AMDomain::host::ClientProtocol::FTP)
            ? kDefaultFTPPort
            : kDefaultSFTPPort;
  }

  int64_t parsed_buffer_size = 0;
  if (AMJson::QueryKey(json, {kBufferSizeKey}, &parsed_buffer_size) &&
      parsed_buffer_size > 0) {
    cfg.request.buffer_size =
        std::min<int64_t>(std::max<int64_t>(parsed_buffer_size, 1),
                          static_cast<int64_t>(AMMaxBufferSize));
  } else {
    cfg.request.buffer_size = AMDefaultRemoteBufferSize;
  }

  *out = std::move(cfg);
  return true;
}

/**
 * @brief Encode one domain host config into one JSON object.
 */
Json EncodeHostConfig_(const AMDomain::host::HostConfig &cfg) {
  Json out = Json::object();
  out[kHostnameKey] = cfg.request.hostname;
  out[kUsernameKey] = cfg.request.username;
  out[kPortKey] = cfg.request.port;
  out[kPasswordKey] = cfg.request.password;
  out[kProtocolKey] = AMStr::lowercase(AMStr::ToString(cfg.request.protocol));
  out[kBufferSizeKey] = cfg.request.buffer_size;
  out[kTrashDirKey] = cfg.request.trash_dir;
  out[kLoginDirKey] = cfg.metadata.login_dir;
  out[kCwdKey] = cfg.metadata.cwd;
  out[kKeyFileKey] = cfg.request.keyfile;
  out[kCompressionKey] = cfg.request.compression;
  out[kCmdPrefixKey] = cfg.metadata.cmd_prefix;
  out[kWrapCmdKey] = cfg.metadata.wrap_cmd;
  return out;
}
/**
 * @brief Codec for typed host configuration aggregate payload.
 */
class HostConfigArgCodec final : public AMInfra::config::IArgCodec {
public:
  /**
   * @brief Return codec type tag.
   */
  [[nodiscard]] TypeTag Tag() const override { return TypeTag::HostConfig; }

  /**
   * @brief Return codec document kind.
   */
  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Config;
  }

  /**
   * @brief Decode config root json into HostConfigArg.
   */
  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output HostConfigArg");
    }

    auto *typed = static_cast<AMDomain::host::HostConfigArg *>(out);
    typed->host_configs.clear();
    typed->local_config = {};
    typed->private_keys.clear();

    if (!root.is_object()) {
      return true;
    }

    Json hosts_json = Json::object();
    if (AMJson::QueryKey(root, {kHostsKey}, &hosts_json) &&
        hosts_json.is_object()) {
      for (auto it = hosts_json.begin(); it != hosts_json.end(); ++it) {
        if (!it.value().is_object()) {
          continue;
        }

        AMDomain::host::HostConfig cfg = {};
        std::string decode_error;
        if (!DecodeHostConfig_(it.key(), it.value(), &cfg, &decode_error)) {
          continue;
        }

        if (AMDomain::host::HostManagerService::IsLocalNickname(it.key())) {
          typed->local_config = std::move(cfg);
          continue;
        }

        std::string validate_error;
        if (!AMDomain::host::HostManagerService::IsValidConfig(
                cfg, &validate_error)) {
          continue;
        }
        typed->host_configs[it.key()] = std::move(cfg);
      }
    }

    std::vector<std::string> keys = {};
    if (AMJson::QueryKey(root, {kPrivateKeysKey}, &keys)) {
      typed->private_keys = AMJson::VectorDedup(keys);
    }

    return true;
  }

  /**
   * @brief Encode HostConfigArg into config root json.
   */
  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input HostConfigArg or root json");
    }

    const auto *typed = static_cast<const AMDomain::host::HostConfigArg *>(in);

    Json out = Json::object();
    Json hosts = Json::object();

    if (!typed->local_config.request.nickname.empty()) {
      hosts["local"] = EncodeHostConfig_(typed->local_config);
    }

    for (const auto &[nickname, cfg] : typed->host_configs) {
      if (AMDomain::host::HostManagerService::IsLocalNickname(nickname)) {
        hosts["local"] = EncodeHostConfig_(cfg);
        continue;
      }
      hosts[nickname] = EncodeHostConfig_(cfg);
    }

    out[kHostsKey] = std::move(hosts);
    out[kPrivateKeysKey] = AMJson::VectorDedup(typed->private_keys);

    *root = std::move(out);
    return true;
  }
};
} // namespace host_config_arg_codec

namespace known_host_entry_arg_codec {
/**
 * @brief Codec for typed known-host entry aggregate payload.
 */
class KnownHostEntryArgCodec final : public AMInfra::config::IArgCodec {
public:
  /**
   * @brief Return codec type tag.
   */
  [[nodiscard]] TypeTag Tag() const override { return TypeTag::KnownHostEntry; }

  /**
   * @brief Return codec document kind.
   */
  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::KnownHosts;
  }

  /**
   * @brief Decode known-host root json into KnownHostEntryArg.
   */
  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output KnownHostEntryArg");
    }

    auto *typed = static_cast<AMDomain::host::KnownHostEntryArg *>(out);
    typed->entries.clear();
    if (!root.is_object()) {
      return true;
    }

    for (auto host_it = root.begin(); host_it != root.end(); ++host_it) {
      if (!host_it.value().is_object()) {
        continue;
      }
      const std::string hostname = AMStr::Strip(host_it.key());
      if (hostname.empty()) {
        continue;
      }

      for (auto port_it = host_it.value().begin();
           port_it != host_it.value().end(); ++port_it) {
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

            AMDomain::host::KnownHostQuery query{
                "",       hostname, static_cast<int>(port_num),
                protocol, username, fingerprint};
            if (!query.IsValid()) {
              continue;
            }

            AMDomain::host::KnownHostKey key = {
                hostname, static_cast<int>(port_num), username, protocol};
            typed->entries[key] = std::move(query);
          }
        }
      }
    }

    return true;
  }

  /**
   * @brief Encode KnownHostEntryArg into known-host root json.
   */
  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input KnownHostEntryArg or root json");
    }

    const auto *typed =
        static_cast<const AMDomain::host::KnownHostEntryArg *>(in);
    Json out = Json::object();

    for (const auto &[key, query] : typed->entries) {
      std::string hostname = AMStr::Strip(query.hostname);
      int port = query.port;
      std::string username = AMStr::Strip(query.username);
      std::string protocol = AMStr::lowercase(AMStr::Strip(query.protocol));

      if (hostname.empty()) {
        hostname = AMStr::Strip(std::get<0>(key));
      }
      if (port <= 0 || port > 65535) {
        port = std::get<1>(key);
      }
      if (username.empty()) {
        username = AMStr::Strip(std::get<2>(key));
      }
      if (protocol.empty()) {
        protocol = AMStr::lowercase(AMStr::Strip(std::get<3>(key)));
      }

      const std::string fingerprint = AMStr::Strip(query.GetFingerprint());
      if (hostname.empty() || port <= 0 || port > 65535 || protocol.empty() ||
          fingerprint.empty()) {
        continue;
      }

      out[hostname][std::to_string(port)][username][protocol] = fingerprint;
    }

    *root = std::move(out);
    return true;
  }
};
} // namespace known_host_entry_arg_codec
} // namespace

namespace AMInfra::config {
/**
 * @brief Construct registry with built-in codec strategies.
 */
ArgCodecRegistry::ArgCodecRegistry() {
  codecs_.push_back(std::make_unique<config_arg_codec::ConfigArgCodec>());
  codecs_.push_back(std::make_unique<settings_arg_codec::SettingsArgCodec>());
  codecs_.push_back(
      std::make_unique<known_hosts_arg_codec::KnownHostsArgCodec>());
  codecs_.push_back(std::make_unique<history_arg_codec::HistoryArgCodec>());
  codecs_.push_back(
      std::make_unique<host_config_arg_codec::HostConfigArgCodec>());
  codecs_.push_back(
      std::make_unique<known_host_entry_arg_codec::KnownHostEntryArgCodec>());

  for (const auto &codec : codecs_) {
    if (!codec) {
      continue;
    }
    map_[codec->Tag()] = codec.get();
  }
}

/**
 * @brief Return shared singleton registry instance.
 */
const ArgCodecRegistry &ArgCodecRegistry::Instance() {
  static const ArgCodecRegistry registry = {};
  return registry;
}

/**
 * @brief Lookup codec by arg runtime type tag.
 */
const IArgCodec *ArgCodecRegistry::Find(AMDomain::arg::TypeTag type) const {
  auto it = map_.find(type);
  if (it == map_.end()) {
    return nullptr;
  }
  return it->second;
}

/**
 * @brief Decode JSON root into typed arg payload by runtime type tag.
 */
bool DecodeArg(AMDomain::arg::TypeTag type, const Json &root, void *out,
               std::string *error) {
  const IArgCodec *codec = ArgCodecRegistry::Instance().Find(type);
  if (!codec) {
    return codec_common::Fail_(error, "codec not found for arg type");
  }
  return codec->Decode(root, out, error);
}

/**
 * @brief Encode typed arg payload into JSON root by runtime type tag.
 */
bool EncodeArg(AMDomain::arg::TypeTag type, const void *in, Json *root,
               std::string *error) {
  const IArgCodec *codec = ArgCodecRegistry::Instance().Find(type);
  if (!codec) {
    return codec_common::Fail_(error, "codec not found for arg type");
  }
  return codec->Encode(in, root, error);
}
} // namespace AMInfra::config
