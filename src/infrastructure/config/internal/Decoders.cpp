#include "domain/client/ClientDomainService.hpp"
#include "domain/client/ClientModel.hpp"
#include "domain/config/ConfigModel.hpp"
#include "domain/filesystem/FileSystemModel.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "domain/log/LoggerModel.hpp"
#include "domain/prompt/PromptDomainModel.hpp"
#include "domain/style/StyleDomainModel.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "domain/style/StyleDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/json.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/config/internal/ArgCodecRegistry.hpp"
#include <algorithm>
#include <cstdint>
#include <tuple>

namespace {
using DocumentKind = AMDomain::config::DocumentKind;
using AMDomain::client::ClientService::AMDefaultLocalBufferSize;
using AMDomain::client::ClientService::AMDefaultRemoteBufferSize;
using AMDomain::client::ClientService::AMMaxBufferSize;
using AMDomain::client::ClientService::AMMinBufferSize;
using namespace AMDomain::host::HostService;
using namespace AMDomain::host::KnownHostRules;
namespace codec_common {
bool Fail_(std::string *error, const std::string &msg) {
  if (error) {
    *error = msg;
  }
  return false;
}

Json QueryObjectAt_(const Json &root, const std::vector<std::string> &path) {
  Json out = Json::object();
  if (AMJson::QueryKey(root, path, &out) && out.is_object()) {
    return out;
  }
  return Json::object();
}

std::string ScalarToString_(const Json &value) {
  if (value.is_string()) {
    return value.get<std::string>();
  }
  if (value.is_boolean()) {
    return value.get<bool>() ? "true" : "false";
  }
  if (value.is_number_integer()) {
    return std::to_string(value.get<int64_t>());
  }
  if (value.is_number_unsigned()) {
    return std::to_string(value.get<uint64_t>());
  }
  if (value.is_number_float()) {
    return AMStr::fmt("{}", value.get<double>());
  }
  return "";
}

std::map<std::string, std::string> ReadStringMap_(const Json &json,
                                                  bool lowercase_keys = false) {
  std::map<std::string, std::string> out;
  if (!json.is_object()) {
    return out;
  }
  for (auto it = json.begin(); it != json.end(); ++it) {
    if (!it.value().is_string()) {
      continue;
    }
    std::string key = it.key();
    if (lowercase_keys) {
      key = AMStr::lowercase(key);
    }
    out[key] = it.value().get<std::string>();
  }
  return out;
}

Json WriteStringMap_(const std::map<std::string, std::string> &mapd) {
  Json out = Json::object();
  for (const auto &[key, value] : mapd) {
    out[key] = value;
  }
  return out;
}
} // namespace codec_common

namespace host_codec {
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
inline constexpr const char *kCmdTemplateKey = "cmd_template";
inline constexpr const char *kCmdPrefixKey = "cmd_prefix";
inline constexpr int kDefaultSFTPPort = 22;
inline constexpr int kDefaultFTPPort = 21;

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
  (void)AMJson::QueryKey(json, {kTrashDirKey}, &cfg.metadata.trash_dir);
  (void)AMJson::QueryKey(json, {kCompressionKey}, &cfg.request.compression);
  (void)AMJson::QueryKey(json, {kLoginDirKey}, &cfg.metadata.login_dir);
  (void)AMJson::QueryKey(json, {kCwdKey}, &cfg.metadata.cwd);
  bool has_cmd_template = false;
  std::string cmd_template = {};
  has_cmd_template =
      AMJson::QueryKey(json, {kCmdTemplateKey}, &cmd_template);
  if (has_cmd_template) {
    cfg.metadata.cmd_template = cmd_template;
  } else {
    (void)AMJson::QueryKey(json, {kCmdPrefixKey}, &cfg.metadata.cmd_template);
  }

  std::string protocol_str = "sftp";
  (void)AMJson::QueryKey(json, {kProtocolKey}, &protocol_str);
  cfg.request.protocol =
      AMDomain::host::HostService::StrToProtocol(protocol_str);

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

Json EncodeHostConfig_(const AMDomain::host::HostConfig &cfg) {
  Json out = Json::object();
  out[kHostnameKey] = cfg.request.hostname;
  out[kUsernameKey] = cfg.request.username;
  out[kPortKey] = cfg.request.port;
  out[kPasswordKey] = cfg.request.password;
  out[kProtocolKey] = AMStr::lowercase(AMStr::ToString(cfg.request.protocol));
  out[kBufferSizeKey] = cfg.request.buffer_size;
  out[kTrashDirKey] = cfg.metadata.trash_dir;
  out[kLoginDirKey] = cfg.metadata.login_dir;
  out[kCwdKey] = cfg.metadata.cwd;
  out[kKeyFileKey] = cfg.request.keyfile;
  out[kCompressionKey] = cfg.request.compression;
  out[kCmdTemplateKey] = cfg.metadata.cmd_template;
  return out;
}

class HostConfigArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(AMDomain::host::HostConfigArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Config;
  }

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

    Json hosts_json = codec_common::QueryObjectAt_(root, {kHostsKey});
    if (hosts_json.is_object()) {
      for (auto it = hosts_json.begin(); it != hosts_json.end(); ++it) {
        if (!it.value().is_object()) {
          continue;
        }

        AMDomain::host::HostConfig cfg = {};
        std::string decode_error;
        if (!DecodeHostConfig_(it.key(), it.value(), &cfg, &decode_error)) {
          continue;
        }

        if (AMDomain::host::HostService::IsLocalNickname(it.key())) {
          typed->local_config = std::move(cfg);
          continue;
        }

        std::string validate_error;
        if (!IsValidConfig(cfg, &validate_error)) {
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

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input HostConfigArg or root json");
    }

    const auto *typed = static_cast<const AMDomain::host::HostConfigArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }

    Json hosts = Json::object();
    if (!typed->local_config.request.nickname.empty()) {
      hosts["local"] = EncodeHostConfig_(typed->local_config);
    }
    for (const auto &[nickname, cfg] : typed->host_configs) {
      if (IsLocalNickname(nickname)) {
        hosts["local"] = EncodeHostConfig_(cfg);
        continue;
      }
      hosts[nickname] = EncodeHostConfig_(cfg);
    }

    (*root)[kHostsKey] = std::move(hosts);
    (*root)[kPrivateKeysKey] = AMJson::VectorDedup(typed->private_keys);
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {kHostsKey});
    (void)AMJson::DelKey(*root, {kPrivateKeysKey});
    return true;
  }
};

class KnownHostEntryArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(AMDomain::host::KnownHostEntryArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::KnownHosts;
  }

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
            if (!ValidateConfig(query)) {
              continue;
            }

            typed->entries[BuildKnownHostKey(query)] = std::move(query);
          }
        }
      }
    }

    return true;
  }

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

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    *root = Json::object();
    return true;
  }
};
} // namespace host_codec

namespace settings_codec {
using AMDomain::client::ClientServiceArg;
using AMDomain::config::ConfigBackupSet;
using AMDomain::log::LogManagerArg;
using AMDomain::transfer::TransferManagerArg;
using AMDomain::filesystem::FilesystemArg;
using AMDomain::var::VarSetArg;

Json OptionsRoot_(const Json &root) {
  return codec_common::QueryObjectAt_(root, {"Options"});
}

void DecodeConfigBackupSet_(const Json &json, ConfigBackupSet *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"enabled"}, &out->enabled);
  (void)AMJson::QueryKey(json, {"interval_s"}, &out->interval_s);
  (void)AMJson::QueryKey(json, {"max_backup_count"}, &out->max_backup_count);
  (void)AMJson::QueryKey(json, {"last_backup_time_s"},
                         &out->last_backup_time_s);
}

Json EncodeConfigBackupSet_(const ConfigBackupSet &in) {
  Json out = Json::object();
  out["enabled"] = in.enabled;
  out["interval_s"] = in.interval_s;
  out["max_backup_count"] = in.max_backup_count;
  out["last_backup_time_s"] = in.last_backup_time_s;
  return out;
}

class ConfigBackupSetCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(ConfigBackupSet));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output ConfigBackupSet");
    }
    auto *typed = static_cast<ConfigBackupSet *>(out);
    *typed = {};
    DecodeConfigBackupSet_(
        codec_common::QueryObjectAt_(root, {"Options", "AutoConfigBackup"}),
        typed);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input ConfigBackupSet or root json");
    }
    const auto *typed = static_cast<const ConfigBackupSet *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    (*root)["Options"]["AutoConfigBackup"] = EncodeConfigBackupSet_(*typed);
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "AutoConfigBackup"});
    return true;
  }
};

class TransferManagerArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(TransferManagerArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output TransferManagerArg");
    }
    auto *typed = static_cast<TransferManagerArg *>(out);
    *typed = {};

    const Json options = OptionsRoot_(root);
    (void)AMJson::QueryKey(options, {"TransferManager", "init_thread_num"},
                           &typed->init_thread_num);
    (void)AMJson::QueryKey(options, {"TransferManager", "max_thread_num"},
                           &typed->max_thread_num);
    (void)AMJson::QueryKey(options, {"TransferManager", "buffer_size"},
                           &typed->buffer_size);
    (void)AMJson::QueryKey(options, {"TransferManager", "min_buffer"},
                           &typed->min_buffer);
    (void)AMJson::QueryKey(options, {"TransferManager", "max_buffer"},
                           &typed->max_buffer);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input TransferManagerArg or root json");
    }
    const auto *typed = static_cast<const TransferManagerArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }

    (*root)["Options"]["TransferManager"]["init_thread_num"] =
        typed->init_thread_num;
    (*root)["Options"]["TransferManager"]["max_thread_num"] =
        typed->max_thread_num;
    (*root)["Options"]["TransferManager"]["buffer_size"] = typed->buffer_size;
    (*root)["Options"]["TransferManager"]["min_buffer"] = typed->min_buffer;
    (*root)["Options"]["TransferManager"]["max_buffer"] = typed->max_buffer;
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "TransferManager"});
    return true;
  }
};

class LogManagerArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(LogManagerArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output LogManagerArg");
    }
    auto *typed = static_cast<LogManagerArg *>(out);
    *typed = {};

    const Json options = OptionsRoot_(root);
    (void)AMJson::QueryKey(options, {"LogManager", "client_trace_level"},
                           &typed->client_trace_level);
    (void)AMJson::QueryKey(options, {"LogManager", "program_trace_level"},
                           &typed->program_trace_level);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input LogManagerArg or root json");
    }
    const auto *typed = static_cast<const LogManagerArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }

    (*root)["Options"]["LogManager"]["client_trace_level"] =
        typed->client_trace_level;
    (*root)["Options"]["LogManager"]["program_trace_level"] =
        typed->program_trace_level;
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "LogManager"});
    return true;
  }
};

class ClientServiceArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(ClientServiceArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output ClientServiceArg");
    }
    auto *typed = static_cast<ClientServiceArg *>(out);
    *typed = {};
    const Json options = OptionsRoot_(root);
    (void)AMJson::QueryKey(options, {"ClientManager", "heartbeat_interval_s"},
                           &typed->heartbeat_interval_s);
    (void)AMJson::QueryKey(options, {"ClientManager", "heartbeat_timeout_ms"},
                           &typed->heartbeat_timeout_ms);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input ClientServiceArg or root json");
    }
    const auto *typed = static_cast<const ClientServiceArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    (*root)["Options"]["ClientManager"]["heartbeat_interval_s"] =
        typed->heartbeat_interval_s;
    (*root)["Options"]["ClientManager"]["heartbeat_timeout_ms"] =
        typed->heartbeat_timeout_ms;
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "ClientManager"});
    return true;
  }
};

class FilesystemArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(FilesystemArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output FilesystemArg");
    }
    auto *typed = static_cast<FilesystemArg *>(out);
    *typed = {};
    const Json options = OptionsRoot_(root);
    (void)AMJson::QueryKey(options, {"FileSystem", "max_cd_history"},
                           &typed->max_cd_history);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input FilesystemArg or root json");
    }
    const auto *typed = static_cast<const FilesystemArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    (*root)["Options"]["FileSystem"]["max_cd_history"] = typed->max_cd_history;
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "FileSystem"});
    return true;
  }
};

class VarSetArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(VarSetArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output VarSetArg");
    }
    auto *typed = static_cast<VarSetArg *>(out);
    typed->set.clear();

    const Json user_vars = codec_common::QueryObjectAt_(root, {"UserVars"});
    for (auto it = user_vars.begin(); it != user_vars.end(); ++it) {
      if (it.value().is_object()) {
        if (it.key() != AMDomain::var::kPublic &&
            !AMDomain::var::IsValidZoneName(it.key())) {
          continue;
        }
        auto &vars = typed->set[it.key()];
        for (auto vit = it.value().begin(); vit != it.value().end(); ++vit) {
          if (!AMDomain::var::IsValidVarname(vit.key())) {
            continue;
          }
          vars[vit.key()] = codec_common::ScalarToString_(vit.value());
        }
        continue;
      }
      if (!AMDomain::var::IsValidVarname(it.key())) {
        continue;
      }
      typed->set[AMDomain::var::kPublic][it.key()] =
          codec_common::ScalarToString_(it.value());
    }
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error, "null input VarSetArg or root json");
    }
    const auto *typed = static_cast<const VarSetArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    Json out = Json::object();
    for (const auto &[domain, vars] : typed->set) {
      Json section = Json::object();
      for (const auto &[name, value] : vars) {
        section[name] = value;
      }
      out[domain] = std::move(section);
    }
    (*root)["UserVars"] = std::move(out);
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"UserVars"});
    return true;
  }
};
} // namespace settings_codec

namespace prompt_codec {
using AMDomain::prompt::PromptHistoryArg;
using AMDomain::prompt::PromptProfileArg;
using AMDomain::prompt::PromptProfileSettings;

void DecodePromptProfileSettings_(const Json &json,
                                  PromptProfileSettings *out) {
  if (!out || !json.is_object()) {
    return;
  }
  *out = {};
  (void)AMJson::QueryKey(json, {"Prompt", "marker"}, &out->prompt.marker);
  (void)AMJson::QueryKey(json, {"Prompt", "continuation_marker"},
                         &out->prompt.continuation_marker);
  if (!AMJson::QueryKey(json, {"Prompt", "enable_multiline"},
                        &out->prompt.enable_multiline)) {
    (void)AMJson::QueryKey(json, {"Prompt", "enable_muiltiline"},
                           &out->prompt.enable_multiline);
  }

  (void)AMJson::QueryKey(json, {"History", "enable"}, &out->history.enable);
  (void)AMJson::QueryKey(json, {"History", "enable_duplicates"},
                         &out->history.enable_duplicates);
  (void)AMJson::QueryKey(json, {"History", "max_count"},
                         &out->history.max_count);

  (void)AMJson::QueryKey(json, {"InlineHint", "enable"},
                         &out->inline_hint.enable);
  if (!AMJson::QueryKey(json, {"InlineHint", "render_delay_ms"},
                        &out->inline_hint.render_delay_ms)) {
    (void)AMJson::QueryKey(json, {"InlineHint", "delay_ms"},
                           &out->inline_hint.render_delay_ms);
  }
  (void)AMJson::QueryKey(json, {"InlineHint", "search_delay_ms"},
                         &out->inline_hint.search_delay_ms);
  (void)AMJson::QueryKey(json, {"InlineHint", "Path", "enable"},
                         &out->inline_hint.path.enable);
  (void)AMJson::QueryKey(json, {"InlineHint", "Path", "use_async"},
                         &out->inline_hint.path.use_async);
  (void)AMJson::QueryKey(json, {"InlineHint", "Path", "timeout_ms"},
                         &out->inline_hint.path.timeout_ms);

  (void)AMJson::QueryKey(json, {"Complete", "Searcher", "Path", "use_async"},
                         &out->complete.path.use_async);
  (void)AMJson::QueryKey(json, {"Complete", "Searcher", "Path", "timeout_ms"},
                         &out->complete.path.timeout_ms);

  (void)AMJson::QueryKey(json, {"Highlight", "delay_ms"},
                         &out->highlight.delay_ms);
  (void)AMJson::QueryKey(json, {"Highlight", "Path", "enable"},
                         &out->highlight.path.enable);
  (void)AMJson::QueryKey(json, {"Highlight", "Path", "timeout_ms"},
                         &out->highlight.path.timeout_ms);

  out->history.max_count = std::min(std::max(1, out->history.max_count), 200);
  out->inline_hint.render_delay_ms =
      std::max(0, out->inline_hint.render_delay_ms);
  out->inline_hint.search_delay_ms =
      std::max(0, out->inline_hint.search_delay_ms);
  out->highlight.delay_ms = std::max(0, out->highlight.delay_ms);
  if (out->inline_hint.path.timeout_ms < 1) {
    out->inline_hint.path.timeout_ms = 600;
  }
  if (out->complete.path.timeout_ms < 1) {
    out->complete.path.timeout_ms = 3000;
  }
  if (out->highlight.path.timeout_ms < 1) {
    out->highlight.path.timeout_ms = 1000;
  }
}

Json EncodePromptProfileSettings_(const PromptProfileSettings &in) {
  Json out = Json::object();
  out["Prompt"]["marker"] = in.prompt.marker;
  out["Prompt"]["continuation_marker"] = in.prompt.continuation_marker;
  out["Prompt"]["enable_muiltiline"] = in.prompt.enable_multiline;

  out["History"]["enable"] = in.history.enable;
  out["History"]["enable_duplicates"] = in.history.enable_duplicates;
  out["History"]["max_count"] = in.history.max_count;

  out["InlineHint"]["enable"] = in.inline_hint.enable;
  out["InlineHint"]["render_delay_ms"] = in.inline_hint.render_delay_ms;
  out["InlineHint"]["search_delay_ms"] = in.inline_hint.search_delay_ms;
  out["InlineHint"]["Path"]["enable"] = in.inline_hint.path.enable;
  out["InlineHint"]["Path"]["use_async"] = in.inline_hint.path.use_async;
  out["InlineHint"]["Path"]["timeout_ms"] = in.inline_hint.path.timeout_ms;

  out["Complete"]["Searcher"]["Path"]["use_async"] = in.complete.path.use_async;
  out["Complete"]["Searcher"]["Path"]["timeout_ms"] =
      in.complete.path.timeout_ms;

  out["Highlight"]["delay_ms"] = in.highlight.delay_ms;
  out["Highlight"]["Path"]["enable"] = in.highlight.path.enable;
  out["Highlight"]["Path"]["timeout_ms"] = in.highlight.path.timeout_ms;
  return out;
}

class PromptProfileArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(PromptProfileArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output PromptProfileArg");
    }
    auto *typed = static_cast<PromptProfileArg *>(out);
    typed->set.clear();
    const Json profile_root =
        codec_common::QueryObjectAt_(root, {"PromptProfile"});
    for (auto it = profile_root.begin(); it != profile_root.end(); ++it) {
      if (!it.value().is_object()) {
        continue;
      }
      PromptProfileSettings item{};
      DecodePromptProfileSettings_(it.value(), &item);
      typed->set[it.key()] = std::move(item);
    }
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input PromptProfileArg or root json");
    }
    const auto *typed = static_cast<const PromptProfileArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    Json out = Json::object();
    for (const auto &[name, settings] : typed->set) {
      out[name] = EncodePromptProfileSettings_(settings);
    }
    (*root)["PromptProfile"] = std::move(out);
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"PromptProfile"});
    return true;
  }
};

class PromptHistoryArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(PromptHistoryArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::History;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output PromptHistoryArg");
    }
    auto *typed = static_cast<PromptHistoryArg *>(out);
    typed->set.clear();
    if (!root.is_object()) {
      return true;
    }
    for (auto it = root.begin(); it != root.end(); ++it) {
      Json commands = Json::array();
      if (!AMJson::QueryKey(it.value(), {"commands"}, &commands) ||
          !commands.is_array()) {
        continue;
      }
      std::vector<std::string> out_commands = {};
      for (const auto &item : commands) {
        if (item.is_string()) {
          out_commands.push_back(item.get<std::string>());
        }
      }
      typed->set[it.key()] = std::move(out_commands);
    }
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input PromptHistoryArg or root json");
    }
    const auto *typed = static_cast<const PromptHistoryArg *>(in);
    Json out = Json::object();
    for (const auto &[name, commands] : typed->set) {
      out[name]["commands"] = commands;
    }
    *root = std::move(out);
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    *root = Json::object();
    return true;
  }
};
} // namespace prompt_codec

namespace style_codec {
using AMDomain::style::CLIPromptStyle;
using AMDomain::style::CompleteMenuStyle;
using AMDomain::style::InputHighlightStyle;
using AMDomain::style::InternalStyle;
using AMDomain::style::PathHighlightStyle;
using AMDomain::style::ProgressBarStyle;
using AMDomain::style::StyleConfigArg;
using AMDomain::style::SystemInfoStyle;
using AMDomain::style::TableStyle;
using AMDomain::style::ValueQueryHighlightStyle;

void DecodeCompleteMenu_(const Json &json, CompleteMenuStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"maxnum"}, &out->maxnum);
  (void)AMJson::QueryKey(json, {"maxrows_perpage"}, &out->maxrows_perpage);
  (void)AMJson::QueryKey(json, {"item_select_sign"}, &out->item_select_sign);
  (void)AMJson::QueryKey(json, {"number_pick"}, &out->number_pick);
  (void)AMJson::QueryKey(json, {"auto_fillin"}, &out->auto_fillin);
  (void)AMJson::QueryKey(json, {"order_num_style"}, &out->order_num_style);
  (void)AMJson::QueryKey(json, {"help_style"}, &out->help_style);
  (void)AMJson::QueryKey(json, {"complete_delay_ms"}, &out->complete_delay_ms);
  (void)AMJson::QueryKey(json, {"async_workers"}, &out->async_workers);
}

Json EncodeCompleteMenu_(const CompleteMenuStyle &in) {
  Json out = Json::object();
  out["maxnum"] = in.maxnum;
  out["maxrows_perpage"] = in.maxrows_perpage;
  out["item_select_sign"] = in.item_select_sign;
  out["number_pick"] = in.number_pick;
  out["auto_fillin"] = in.auto_fillin;
  out["order_num_style"] = in.order_num_style;
  out["help_style"] = in.help_style;
  out["complete_delay_ms"] = in.complete_delay_ms;
  out["async_workers"] = in.async_workers;
  return out;
}

void DecodeTable_(const Json &json, TableStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"color"}, &out->color);
  (void)AMJson::QueryKey(json, {"left_padding"}, &out->left_padding);
  (void)AMJson::QueryKey(json, {"right_padding"}, &out->right_padding);
  (void)AMJson::QueryKey(json, {"top_padding"}, &out->top_padding);
  (void)AMJson::QueryKey(json, {"bottom_padding"}, &out->bottom_padding);
  (void)AMJson::QueryKey(json, {"refresh_interval_ms"}, &out->refresh_interval_ms);
  (void)AMJson::QueryKey(json, {"speed_window_size"}, &out->speed_window_size);
}

Json EncodeTable_(const TableStyle &in) {
  Json out = Json::object();
  out["color"] = in.color;
  out["left_padding"] = in.left_padding;
  out["right_padding"] = in.right_padding;
  out["top_padding"] = in.top_padding;
  out["bottom_padding"] = in.bottom_padding;
  out["refresh_interval_ms"] = in.refresh_interval_ms;
  out["speed_window_size"] = in.speed_window_size;
  return out;
}

void DecodeProgressBar_(const Json &json, ProgressBarStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"start"}, &out->start);
  (void)AMJson::QueryKey(json, {"end"}, &out->end);
  (void)AMJson::QueryKey(json, {"fill"}, &out->fill);
  (void)AMJson::QueryKey(json, {"lead"}, &out->lead);
  (void)AMJson::QueryKey(json, {"remaining"}, &out->remaining);
  (void)AMJson::QueryKey(json, {"color"}, &out->color);
  (void)AMJson::QueryKey(json, {"refresh_interval_ms"}, &out->refresh_interval_ms);
  (void)AMJson::QueryKey(json, {"speed_window_size"}, &out->speed_window_size);
  (void)AMJson::QueryKey(json, {"bar_width"}, &out->bar_width);
  (void)AMJson::QueryKey(json, {"width_offset"}, &out->width_offset);
  (void)AMJson::QueryKey(json, {"show_percentage"}, &out->show_percentage);
  (void)AMJson::QueryKey(json, {"show_elapsed_time"}, &out->show_elapsed_time);
  (void)AMJson::QueryKey(json, {"show_remaining_time"}, &out->show_remaining_time);
}

Json EncodeProgressBar_(const ProgressBarStyle &in) {
  Json out = Json::object();
  out["start"] = in.start;
  out["end"] = in.end;
  out["fill"] = in.fill;
  out["lead"] = in.lead;
  out["remaining"] = in.remaining;
  out["color"] = in.color;
  out["refresh_interval_ms"] = in.refresh_interval_ms;
  out["speed_window_size"] = in.speed_window_size;
  out["bar_width"] = in.bar_width;
  out["width_offset"] = in.width_offset;
  out["show_percentage"] = in.show_percentage;
  out["show_elapsed_time"] = in.show_elapsed_time;
  out["show_remaining_time"] = in.show_remaining_time;
  return out;
}

void DecodeCliPrompt_(const Json &json, CLIPromptStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }

  Json shortcut = codec_common::QueryObjectAt_(json, {"shortcut"});
  if (!shortcut.is_object()) {
    shortcut = codec_common::QueryObjectAt_(json, {"Shortcut"});
  }
  if (shortcut.is_object()) {
    out->shortcut = codec_common::ReadStringMap_(shortcut, true);
  }

  Json icons = codec_common::QueryObjectAt_(json, {"icons"});
  if (!icons.is_object()) {
    icons = codec_common::QueryObjectAt_(json, {"Icons"});
  }
  (void)AMJson::QueryKey(icons, {"windows"}, &out->icons.windows);
  (void)AMJson::QueryKey(icons, {"linux"}, &out->icons.linux);
  (void)AMJson::QueryKey(icons, {"macos"}, &out->icons.macos);

  Json named = codec_common::QueryObjectAt_(json, {"named_styles"});
  if (!named.is_object()) {
    named = codec_common::QueryObjectAt_(json, {"NamedStyles"});
  }
  if (!named.is_object()) {
    named = codec_common::QueryObjectAt_(json, {"namedstyles"});
  }
  (void)AMJson::QueryKey(named, {"un"}, &out->named_styles.un);
  (void)AMJson::QueryKey(named, {"at"}, &out->named_styles.at);
  (void)AMJson::QueryKey(named, {"hn"}, &out->named_styles.hn);
  (void)AMJson::QueryKey(named, {"en"}, &out->named_styles.en);
  (void)AMJson::QueryKey(named, {"nn"}, &out->named_styles.nn);
  (void)AMJson::QueryKey(named, {"cwd"}, &out->named_styles.cwd);
  (void)AMJson::QueryKey(named, {"ds"}, &out->named_styles.ds);
  (void)AMJson::QueryKey(named, {"white"}, &out->named_styles.white);

  Json template_json = codec_common::QueryObjectAt_(json, {"template"});
  if (!template_json.is_object()) {
    template_json = codec_common::QueryObjectAt_(json, {"Template"});
  }
  (void)AMJson::QueryKey(template_json, {"core_prompt"},
                         &out->prompt_template.core_prompt);
  (void)AMJson::QueryKey(template_json, {"history_search_prompt"},
                         &out->prompt_template.history_search_prompt);

  // Backward compatibility: accept misspelled "templete" section.
  if (out->prompt_template.core_prompt.empty() ||
      out->prompt_template.history_search_prompt.empty()) {
    Json templete_json = codec_common::QueryObjectAt_(json, {"templete"});
    if (!templete_json.is_object()) {
      templete_json = codec_common::QueryObjectAt_(json, {"Templete"});
    }
    if (out->prompt_template.core_prompt.empty()) {
      (void)AMJson::QueryKey(templete_json, {"core_prompt"},
                             &out->prompt_template.core_prompt);
    }
    if (out->prompt_template.history_search_prompt.empty()) {
      (void)AMJson::QueryKey(templete_json, {"history_search_prompt"},
                             &out->prompt_template.history_search_prompt);
    }
  }

  // Backward compatibility: accept legacy flat "format" key.
  if (out->prompt_template.core_prompt.empty()) {
    (void)AMJson::QueryKey(json, {"format"}, &out->prompt_template.core_prompt);
  }
}

Json EncodeCliPrompt_(const CLIPromptStyle &in) {
  Json out = Json::object();
  out["shortcut"] = codec_common::WriteStringMap_(in.shortcut);

  out["icons"]["windows"] = in.icons.windows;
  out["icons"]["linux"] = in.icons.linux;
  out["icons"]["macos"] = in.icons.macos;

  out["named_styles"]["un"] = in.named_styles.un;
  out["named_styles"]["at"] = in.named_styles.at;
  out["named_styles"]["hn"] = in.named_styles.hn;
  out["named_styles"]["en"] = in.named_styles.en;
  out["named_styles"]["nn"] = in.named_styles.nn;
  out["named_styles"]["cwd"] = in.named_styles.cwd;
  out["named_styles"]["ds"] = in.named_styles.ds;
  out["named_styles"]["white"] = in.named_styles.white;

  out["template"]["core_prompt"] = in.prompt_template.core_prompt;
  out["template"]["history_search_prompt"] =
      in.prompt_template.history_search_prompt;
  return out;
}

void DecodeInputHighlight_(const Json &json, InputHighlightStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"protocol"}, &out->protocol);
  (void)AMJson::QueryKey(json, {"abort"}, &out->abort);
  (void)AMJson::QueryKey(json, {"common"}, &out->common);
  (void)AMJson::QueryKey(json, {"module"}, &out->module);
  (void)AMJson::QueryKey(json, {"command"}, &out->command);
  (void)AMJson::QueryKey(json, {"illegal_command"}, &out->illegal_command);
  (void)AMJson::QueryKey(json, {"option"}, &out->option);
  (void)AMJson::QueryKey(json, {"string"}, &out->string);
  (void)AMJson::QueryKey(json, {"public_varname"}, &out->public_varname);
  (void)AMJson::QueryKey(json, {"private_varname"}, &out->private_varname);
  (void)AMJson::QueryKey(json, {"nonexistent_varname"}, &out->nonexistent_varname);
  (void)AMJson::QueryKey(json, {"varvalue"}, &out->varvalue);
  (void)AMJson::QueryKey(json, {"nickname"}, &out->nickname);
  (void)AMJson::QueryKey(json, {"unestablished_nickname"}, &out->unestablished_nickname);
  (void)AMJson::QueryKey(json, {"nonexistent_nickname"}, &out->nonexistent_nickname);
  (void)AMJson::QueryKey(json, {"valid_new_nickname"}, &out->valid_new_nickname);
  (void)AMJson::QueryKey(json, {"invalid_new_nickname"}, &out->invalid_new_nickname);
  (void)AMJson::QueryKey(json, {"builtin_arg"}, &out->builtin_arg);
  (void)AMJson::QueryKey(json, {"nonexistent_builtin_arg"}, &out->nonexistent_builtin_arg);
  (void)AMJson::QueryKey(json, {"username"}, &out->username);
  (void)AMJson::QueryKey(json, {"atsign"}, &out->atsign);
  (void)AMJson::QueryKey(json, {"dollarsign"}, &out->dollarsign);
  (void)AMJson::QueryKey(json, {"equalsign"}, &out->equalsign);
  (void)AMJson::QueryKey(json, {"escapedsign"}, &out->escapedsign);
  (void)AMJson::QueryKey(json, {"bangsign"}, &out->bangsign);
  (void)AMJson::QueryKey(json, {"shell_cmd"}, &out->shell_cmd);
  (void)AMJson::QueryKey(json, {"cwd"}, &out->cwd);
  (void)AMJson::QueryKey(json, {"number"}, &out->number);
  (void)AMJson::QueryKey(json, {"timestamp"}, &out->timestamp);
  (void)AMJson::QueryKey(json, {"path_like"}, &out->path_like);
}

Json EncodeInputHighlight_(const InputHighlightStyle &in) {
  Json out = Json::object();
  out["protocol"] = in.protocol;
  out["abort"] = in.abort;
  out["common"] = in.common;
  out["module"] = in.module;
  out["command"] = in.command;
  out["illegal_command"] = in.illegal_command;
  out["option"] = in.option;
  out["string"] = in.string;
  out["public_varname"] = in.public_varname;
  out["private_varname"] = in.private_varname;
  out["nonexistent_varname"] = in.nonexistent_varname;
  out["varvalue"] = in.varvalue;
  out["nickname"] = in.nickname;
  out["unestablished_nickname"] = in.unestablished_nickname;
  out["nonexistent_nickname"] = in.nonexistent_nickname;
  out["valid_new_nickname"] = in.valid_new_nickname;
  out["invalid_new_nickname"] = in.invalid_new_nickname;
  out["builtin_arg"] = in.builtin_arg;
  out["nonexistent_builtin_arg"] = in.nonexistent_builtin_arg;
  out["username"] = in.username;
  out["atsign"] = in.atsign;
  out["dollarsign"] = in.dollarsign;
  out["equalsign"] = in.equalsign;
  out["escapedsign"] = in.escapedsign;
  out["bangsign"] = in.bangsign;
  out["shell_cmd"] = in.shell_cmd;
  out["cwd"] = in.cwd;
  out["number"] = in.number;
  out["timestamp"] = in.timestamp;
  out["path_like"] = in.path_like;
  return out;
}

void DecodeValueQueryHighlight_(const Json &json, ValueQueryHighlightStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"valid_value"}, &out->valid_value);
  (void)AMJson::QueryKey(json, {"invalid_value"}, &out->invalid_value);
  (void)AMJson::QueryKey(json, {"prompt_style"}, &out->prompt_style);
}

Json EncodeValueQueryHighlight_(const ValueQueryHighlightStyle &in) {
  Json out = Json::object();
  out["valid_value"] = in.valid_value;
  out["invalid_value"] = in.invalid_value;
  out["prompt_style"] = in.prompt_style;
  return out;
}

void DecodeInternalStyle_(const Json &json, InternalStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"inline_hint"}, &out->inline_hint);
  if (!AMJson::QueryKey(json, {"default_prompt_style"}, &out->default_prompt)) {
    (void)AMJson::QueryKey(json, {"default_prompt"}, &out->default_prompt);
  }
}

Json EncodeInternalStyle_(const InternalStyle &in) {
  Json out = Json::object();
  out["inline_hint"] = in.inline_hint;
  out["default_prompt_style"] = in.default_prompt;
  return out;
}

void DecodePathHighlight_(const Json &json, PathHighlightStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"path_str"}, &out->path_str);
  (void)AMJson::QueryKey(json, {"root"}, &out->root);
  (void)AMJson::QueryKey(json, {"node_dir_name"}, &out->node_dir_name);
  (void)AMJson::QueryKey(json, {"filename"}, &out->filename);
  (void)AMJson::QueryKey(json, {"dir"}, &out->dir);
  (void)AMJson::QueryKey(json, {"regular"}, &out->regular);
  (void)AMJson::QueryKey(json, {"symlink"}, &out->symlink);
  (void)AMJson::QueryKey(json, {"otherspecial"}, &out->otherspecial);
  (void)AMJson::QueryKey(json, {"nonexistent"}, &out->nonexistent);
}

Json EncodePathHighlight_(const PathHighlightStyle &in) {
  Json out = Json::object();
  out["path_str"] = in.path_str;
  out["root"] = in.root;
  out["node_dir_name"] = in.node_dir_name;
  out["filename"] = in.filename;
  out["dir"] = in.dir;
  out["regular"] = in.regular;
  out["symlink"] = in.symlink;
  out["otherspecial"] = in.otherspecial;
  out["nonexistent"] = in.nonexistent;
  return out;
}

void DecodeSystemInfo_(const Json &json, SystemInfoStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"info"}, &out->info);
  (void)AMJson::QueryKey(json, {"success"}, &out->success);
  (void)AMJson::QueryKey(json, {"error"}, &out->error);
  (void)AMJson::QueryKey(json, {"warning"}, &out->warning);
}

Json EncodeSystemInfo_(const SystemInfoStyle &in) {
  Json out = Json::object();
  out["info"] = in.info;
  out["success"] = in.success;
  out["error"] = in.error;
  out["warning"] = in.warning;
  return out;
}

class StyleSnapshotCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(StyleConfigArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output StyleConfigArg");
    }
    auto *typed = static_cast<StyleConfigArg *>(out);
    *typed = {};

    const Json style = codec_common::QueryObjectAt_(root, {"Style"});
    Json global_shortcut = codec_common::QueryObjectAt_(style, {"shortcut"});
    if (!global_shortcut.is_object()) {
      global_shortcut = codec_common::QueryObjectAt_(style, {"Shortcut"});
    }

    DecodeCompleteMenu_(codec_common::QueryObjectAt_(style, {"CompleteMenu"}),
                        &typed->style.complete_menu);
    DecodeTable_(codec_common::QueryObjectAt_(style, {"Table"}),
                 &typed->style.table);
    DecodeProgressBar_(codec_common::QueryObjectAt_(style, {"ProgressBar"}),
                       &typed->style.progress_bar);
    DecodeCliPrompt_(codec_common::QueryObjectAt_(style, {"CLIPrompt"}),
                     &typed->style.cli_prompt);
    if (global_shortcut.is_object()) {
      auto shortcut_map = codec_common::ReadStringMap_(global_shortcut, true);
      for (auto &[key, value] : shortcut_map) {
        if (typed->style.cli_prompt.shortcut.find(key) ==
            typed->style.cli_prompt.shortcut.end()) {
          typed->style.cli_prompt.shortcut[key] = std::move(value);
        }
      }
    }
    DecodeInputHighlight_(
        codec_common::QueryObjectAt_(style, {"InputHighlight"}),
        &typed->style.input_highlight);
    DecodeValueQueryHighlight_(
        codec_common::QueryObjectAt_(style, {"ValueQueryHighlight"}),
        &typed->style.value_query_highlight);
    DecodeInternalStyle_(codec_common::QueryObjectAt_(style, {"InternalStyle"}),
                         &typed->style.internal_style);
    DecodePathHighlight_(codec_common::QueryObjectAt_(style, {"Path"}),
                         &typed->style.path);
    DecodeSystemInfo_(codec_common::QueryObjectAt_(style, {"SystemInfo"}),
                      &typed->style.system_info);

    AMDomain::style::services::NormalizeStyleConfigArg(typed);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input StyleConfigArg or root json");
    }
    const auto *typed = static_cast<const StyleConfigArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }

    Json style = Json::object();
    style["CompleteMenu"] = EncodeCompleteMenu_(typed->style.complete_menu);
    style["Table"] = EncodeTable_(typed->style.table);
    style["ProgressBar"] = EncodeProgressBar_(typed->style.progress_bar);
    style["shortcut"] = codec_common::WriteStringMap_(typed->style.cli_prompt.shortcut);
    style["CLIPrompt"] = EncodeCliPrompt_(typed->style.cli_prompt);
    style["InputHighlight"] =
        EncodeInputHighlight_(typed->style.input_highlight);
    style["ValueQueryHighlight"] =
        EncodeValueQueryHighlight_(typed->style.value_query_highlight);
    style["InternalStyle"] = EncodeInternalStyle_(typed->style.internal_style);
    style["Path"] = EncodePathHighlight_(typed->style.path);
    style["SystemInfo"] = EncodeSystemInfo_(typed->style.system_info);
    (*root)["Style"] = std::move(style);
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Style"});
    return true;
  }
};

class StyleConfigArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(StyleConfigArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    StyleSnapshotCodec snapshot_codec = {};
    return snapshot_codec.Decode(root, out, error);
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    StyleSnapshotCodec snapshot_codec = {};
    return snapshot_codec.Encode(in, root, error);
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    StyleSnapshotCodec snapshot_codec = {};
    return snapshot_codec.Erase(in, root, error);
  }
};
} // namespace style_codec

} // namespace

namespace AMInfra::config {
std::unordered_map<std::type_index, const IArgCodec *>
BuildCodecMap() {
  static const host_codec::HostConfigArgCodec host_config_codec = {};
  static const host_codec::KnownHostEntryArgCodec known_host_codec = {};
  static const settings_codec::ConfigBackupSetCodec backup_set_codec = {};
  static const settings_codec::TransferManagerArgCodec transfer_manager_codec =
      {};
  static const settings_codec::LogManagerArgCodec log_manager_codec = {};
  static const settings_codec::ClientServiceArgCodec client_service_codec = {};
  static const settings_codec::FilesystemArgCodec filesystem_codec = {};
  static const settings_codec::VarSetArgCodec var_set_codec = {};
  static const prompt_codec::PromptProfileArgCodec prompt_profile_arg_codec =
      {};
  static const prompt_codec::PromptHistoryArgCodec prompt_history_arg_codec =
      {};
  static const style_codec::StyleConfigArgCodec style_config_arg_codec = {};

  std::unordered_map<std::type_index, const IArgCodec *> map = {};
  map[host_config_codec.TypeKey()] = &host_config_codec;
  map[known_host_codec.TypeKey()] = &known_host_codec;
  map[backup_set_codec.TypeKey()] = &backup_set_codec;
  map[transfer_manager_codec.TypeKey()] = &transfer_manager_codec;
  map[log_manager_codec.TypeKey()] = &log_manager_codec;
  map[client_service_codec.TypeKey()] = &client_service_codec;
  map[filesystem_codec.TypeKey()] = &filesystem_codec;
  map[var_set_codec.TypeKey()] = &var_set_codec;
  map[prompt_profile_arg_codec.TypeKey()] = &prompt_profile_arg_codec;
  map[prompt_history_arg_codec.TypeKey()] = &prompt_history_arg_codec;
  map[style_config_arg_codec.TypeKey()] = &style_config_arg_codec;
  return map;
}
} // namespace AMInfra::config
