#include "domain/client/ClientDomainService.hpp"
#include "domain/client/ClientModel.hpp"
#include "domain/completion/CompletionModel.hpp"
#include "domain/config/ConfigModel.hpp"
#include "domain/filesystem/FileSystemModel.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "domain/log/LoggerModel.hpp"
#include "domain/prompt/PromptDomainModel.hpp"
#include "domain/style/StyleDomainModel.hpp"
#include "domain/style/StyleDomainService.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/json.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/config/internal/ArgCodecRegistry.hpp"
#include <algorithm>
#include <cstdint>
#include <tuple>

namespace {
using DocumentKind = AMDomain::config::DocumentKind;
using AMDomain::client::ClientService::AMDefaultBufferSize;
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
inline constexpr int kDefaultHTTPPort = 80;

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
  has_cmd_template = AMJson::QueryKey(json, {kCmdTemplateKey}, &cmd_template);
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
    if (cfg.request.protocol == AMDomain::host::ClientProtocol::FTP) {
      cfg.request.port = kDefaultFTPPort;
    } else if (cfg.request.protocol == AMDomain::host::ClientProtocol::HTTP) {
      cfg.request.port = kDefaultHTTPPort;
    } else {
      cfg.request.port = kDefaultSFTPPort;
    }
  }

  int64_t parsed_buffer_size = 0;
  if (AMJson::QueryKey(json, {kBufferSizeKey}, &parsed_buffer_size) &&
      parsed_buffer_size > 0) {
    cfg.request.buffer_size =
        std::min<int64_t>(std::max<int64_t>(parsed_buffer_size, 1),
                          static_cast<int64_t>(AMMaxBufferSize));
  } else {
    cfg.request.buffer_size = AMDefaultBufferSize;
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
using AMDomain::completion::CompleterArg;
using AMDomain::config::ConfigBackupSet;
using AMDomain::filesystem::FilesystemArg;
using AMDomain::log::LogManagerArg;
using AMDomain::transfer::TransferManagerArg;
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
    (void)AMJson::QueryKey(options, {"TransferManager", "max_threads"},
                           &typed->max_threads);
    if (typed->max_threads <= 0) {
      (void)AMJson::QueryKey(options, {"TransferManager", "max_thread_num"},
                             &typed->max_threads);
    }
    (void)AMJson::QueryKey(options,
                           {"TransferManager", "bar_refresh_interval_ms"},
                           &typed->bar_refresh_interval_ms);
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

    (*root)["Options"]["TransferManager"]["max_threads"] = typed->max_threads;
    (*root)["Options"]["TransferManager"]["bar_refresh_interval_ms"] =
        typed->bar_refresh_interval_ms;
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
    (void)AMJson::QueryKey(options, {"LogManager", "ClientLogPath"},
                           &typed->client_log_path);
    (void)AMJson::QueryKey(options, {"LogManager", "ProgramLogPath"},
                           &typed->program_log_path);
    (void)AMJson::QueryKey(options, {"LogManager", "client_log_path"},
                           &typed->client_log_path);
    (void)AMJson::QueryKey(options, {"LogManager", "program_log_path"},
                           &typed->program_log_path);
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
    (*root)["Options"]["LogManager"]["client_log_path"] =
        typed->client_log_path;
    (*root)["Options"]["LogManager"]["program_log_path"] =
        typed->program_log_path;
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

class CompleterArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(CompleterArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output CompleterArg");
    }
    auto *typed = static_cast<CompleterArg *>(out);
    *typed = {};

    const Json options = OptionsRoot_(root);
    (void)AMJson::QueryKey(options, {"Completer", "maxnum"}, &typed->maxnum);
    (void)AMJson::QueryKey(options, {"Completer", "maxrows_perpage"},
                           &typed->maxrows_perpage);
    (void)AMJson::QueryKey(options, {"Completer", "number_pick"},
                           &typed->number_pick);
    (void)AMJson::QueryKey(options, {"Completer", "auto_fillin"},
                           &typed->auto_fillin);
    (void)AMJson::QueryKey(options, {"Completer", "complete_delay_ms"},
                           &typed->complete_delay_ms);
    (void)AMJson::QueryKey(options, {"Completer", "async_workers"},
                           &typed->async_workers);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error, "null input CompleterArg or root json");
    }
    const auto *typed = static_cast<const CompleterArg *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }

    (*root)["Options"]["Completer"]["maxnum"] = typed->maxnum;
    (*root)["Options"]["Completer"]["maxrows_perpage"] = typed->maxrows_perpage;
    (*root)["Options"]["Completer"]["number_pick"] = typed->number_pick;
    (*root)["Options"]["Completer"]["auto_fillin"] = typed->auto_fillin;
    (*root)["Options"]["Completer"]["complete_delay_ms"] =
        typed->complete_delay_ms;
    (*root)["Options"]["Completer"]["async_workers"] = typed->async_workers;
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "Completer"});
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
    (void)AMJson::QueryKey(options, {"ClientManager", "check_timeout_ms"},
                           &typed->check_timeout_ms);
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
    (*root)["Options"]["ClientManager"]["check_timeout_ms"] =
        typed->check_timeout_ms;
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
    (void)AMJson::QueryKey(options, {"FileSystem", "wget_max_redirect"},
                           &typed->wget_max_redirect);
    (void)AMJson::QueryKey(options, {"Terminal", "read_timeout_ms"},
                           &typed->terminal_read_timeout_ms);
    (void)AMJson::QueryKey(options, {"Terminal", "send_timeout_ms"},
                           &typed->terminal_send_timeout_ms);
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
    (*root)["Options"]["FileSystem"]["wget_max_redirect"] =
        typed->wget_max_redirect;
    (*root)["Options"]["Terminal"]["read_timeout_ms"] =
        typed->terminal_read_timeout_ms;
    (*root)["Options"]["Terminal"]["send_timeout_ms"] =
        typed->terminal_send_timeout_ms;
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "FileSystem"});
    (void)AMJson::DelKey(*root, {"Options", "Terminal"});
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
  (void)AMJson::QueryKey(json, {"item_select_sign"}, &out->item_select_sign);
  (void)AMJson::QueryKey(json, {"order_num_style"}, &out->order_num_style);
  (void)AMJson::QueryKey(json, {"help_style"}, &out->help_style);
}

Json EncodeCompleteMenu_(const CompleteMenuStyle &in) {
  Json out = Json::object();
  out["item_select_sign"] = in.item_select_sign;
  out["order_num_style"] = in.order_num_style;
  out["help_style"] = in.help_style;
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
  (void)AMJson::QueryKey(json, {"refresh_interval_ms"},
                         &out->refresh_interval_ms);
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
  (void)AMJson::QueryKey(json, {"prefix_template"}, &out->prefix_template);
  (void)AMJson::QueryKey(json, {"bar_template"}, &out->bar_template);
  (void)AMJson::QueryKey(json, {"refresh_interval_ms"},
                         &out->refresh_interval_ms);
  if (!AMJson::QueryKey(json, {"prefix_fixed_width"},
                        &out->prefix_fixed_width)) {
    // backward compatibility
    (void)AMJson::QueryKey(json, {"width_offset"}, &out->prefix_fixed_width);
  }

  const Json bar = codec_common::QueryObjectAt_(json, {"Bar"});
  (void)AMJson::QueryKey(bar, {"fill"}, &out->bar.fill);
  (void)AMJson::QueryKey(bar, {"lead"}, &out->bar.lead);
  (void)AMJson::QueryKey(bar, {"remaining"}, &out->bar.remaining);
  (void)AMJson::QueryKey(bar, {"bar_width"}, &out->bar.bar_width);

  const Json speed = codec_common::QueryObjectAt_(json, {"Speed"});
  (void)AMJson::QueryKey(speed, {"speed_num_fixed_width"},
                         &out->speed.speed_num_fixed_width);
  (void)AMJson::QueryKey(speed, {"speed_num_max_float_digits"},
                         &out->speed.speed_num_max_float_digits);
  (void)AMJson::QueryKey(speed, {"speed_window_ms"},
                         &out->speed.speed_window_ms);

  const Json size = codec_common::QueryObjectAt_(json, {"Size"});
  (void)AMJson::QueryKey(size, {"totol_size_fixed_width"},
                         &out->size.totol_size_fixed_width);
  // compatibility key
  (void)AMJson::QueryKey(size, {"total_size_fixed_width"},
                         &out->size.totol_size_fixed_width);
  (void)AMJson::QueryKey(size, {"totol_size_max_float_digits"},
                         &out->size.totol_size_max_float_digits);
  // compatibility key
  (void)AMJson::QueryKey(size, {"total_size_max_float_digits"},
                         &out->size.totol_size_max_float_digits);
  (void)AMJson::QueryKey(size, {"transferred_size_fixed_width"},
                         &out->size.transferred_size_fixed_width);
  (void)AMJson::QueryKey(size, {"transferred_size_max_float_digits"},
                         &out->size.transferred_size_max_float_digits);
}

Json EncodeProgressBar_(const ProgressBarStyle &in) {
  Json out = Json::object();
  out["prefix_template"] = in.prefix_template;
  out["bar_template"] = in.bar_template;
  out["refresh_interval_ms"] = in.refresh_interval_ms;
  out["prefix_fixed_width"] = in.prefix_fixed_width;
  out["Bar"]["fill"] = in.bar.fill;
  out["Bar"]["lead"] = in.bar.lead;
  out["Bar"]["remaining"] = in.bar.remaining;
  out["Bar"]["bar_width"] = in.bar.bar_width;
  out["Speed"]["speed_num_fixed_width"] = in.speed.speed_num_fixed_width;
  out["Speed"]["speed_num_max_float_digits"] =
      in.speed.speed_num_max_float_digits;
  out["Speed"]["speed_window_ms"] = in.speed.speed_window_ms;
  out["Size"]["totol_size_fixed_width"] = in.size.totol_size_fixed_width;
  out["Size"]["totol_size_max_float_digits"] =
      in.size.totol_size_max_float_digits;
  out["Size"]["transferred_size_fixed_width"] =
      in.size.transferred_size_fixed_width;
  out["Size"]["transferred_size_max_float_digits"] =
      in.size.transferred_size_max_float_digits;
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
  if (named.is_object()) {
    for (auto it = named.begin(); it != named.end(); ++it) {
      if (!it.value().is_string()) {
        continue;
      }
      const std::string key = AMStr::lowercase(AMStr::Strip(it.key()));
      if (key.empty() || out->shortcut.contains(key)) {
        continue;
      }
      out->shortcut[key] = it.value().get<std::string>();
    }
  }

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

  out["template"]["core_prompt"] = in.prompt_template.core_prompt;
  out["template"]["history_search_prompt"] =
      in.prompt_template.history_search_prompt;
  return out;
}

void DecodeInputHighlight_(const Json &json, InputHighlightStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"default_style"}, &out->default_style);
  (void)AMJson::QueryKey(json, {"type_string"}, &out->type_string);
  (void)AMJson::QueryKey(json, {"type_number"}, &out->type_number);
  (void)AMJson::QueryKey(json, {"type_protocol"}, &out->type_protocol);
  (void)AMJson::QueryKey(json, {"type_username"}, &out->type_username);
  (void)AMJson::QueryKey(json, {"type_abort"}, &out->type_abort);
  (void)AMJson::QueryKey(json, {"type_hostname"}, &out->type_hostname);
  (void)AMJson::QueryKey(json, {"type_shell_cmd"}, &out->type_shell_cmd);
  (void)AMJson::QueryKey(json, {"sign_escaped"}, &out->sign_escaped);
  (void)AMJson::QueryKey(json, {"sign_bang"}, &out->sign_bang);
  (void)AMJson::QueryKey(json, {"cli_command"}, &out->cli_command);
  (void)AMJson::QueryKey(json, {"cli_unexpected"}, &out->cli_unexpected);
  (void)AMJson::QueryKey(json, {"cli_module"}, &out->cli_module);
  (void)AMJson::QueryKey(json, {"cli_option"}, &out->cli_option);
  (void)AMJson::QueryKey(json, {"varname_public"}, &out->varname_public);
  (void)AMJson::QueryKey(json, {"varname_private"}, &out->varname_private);
  (void)AMJson::QueryKey(json, {"varname_nonexistent"},
                         &out->varname_nonexistent);
  (void)AMJson::QueryKey(json, {"varname_dollar"}, &out->varname_dollar);
  (void)AMJson::QueryKey(json, {"varname_left_brace"},
                         &out->varname_left_brace);
  (void)AMJson::QueryKey(json, {"varname_right_brace"},
                         &out->varname_right_brace);
  (void)AMJson::QueryKey(json, {"varname_colon"}, &out->varname_colon);
  (void)AMJson::QueryKey(json, {"varname_equal"}, &out->varname_equal);
  (void)AMJson::QueryKey(json, {"varvalue"}, &out->varvalue);
  (void)AMJson::QueryKey(json, {"nickname_ok"}, &out->nickname_ok);
  (void)AMJson::QueryKey(json, {"nickname_at"}, &out->nickname_at);
  (void)AMJson::QueryKey(json, {"nickname_disconnected"},
                         &out->nickname_disconnected);
  (void)AMJson::QueryKey(json, {"nickname_unestablished"},
                         &out->nickname_unestablished);
  (void)AMJson::QueryKey(json, {"nickname_nonexistent"},
                         &out->nickname_nonexistent);
  (void)AMJson::QueryKey(json, {"nickname_new_valid"},
                         &out->nickname_new_valid);
  (void)AMJson::QueryKey(json, {"nickname_new_invalid"},
                         &out->nickname_new_invalid);
  (void)AMJson::QueryKey(json, {"termname_ok"}, &out->termname_ok);
  (void)AMJson::QueryKey(json, {"termname_at"}, &out->termname_at);
  (void)AMJson::QueryKey(json, {"termname_disconnected"},
                         &out->termname_disconnected);
  (void)AMJson::QueryKey(json, {"termname_unestablished"},
                         &out->termname_unestablished);
  (void)AMJson::QueryKey(json, {"termname_nonexistent"},
                         &out->termname_nonexistent);
  (void)AMJson::QueryKey(json, {"channelname_ok"}, &out->channelname_ok);
  (void)AMJson::QueryKey(json, {"channelname_disconnected"},
                         &out->channelname_disconnected);
  (void)AMJson::QueryKey(json, {"channelname_nonexistent"},
                         &out->channelname_nonexistent);
  (void)AMJson::QueryKey(json, {"channelname_new_valid"},
                         &out->channelname_new_valid);
  (void)AMJson::QueryKey(json, {"channelname_new_invalid"},
                         &out->channelname_new_invalid);
  (void)AMJson::QueryKey(json, {"attr_valid"}, &out->attr_valid);
  (void)AMJson::QueryKey(json, {"attr_invalid"}, &out->attr_invalid);

  std::string legacy = {};
  if (AMJson::QueryKey(json, {"protocol"}, &legacy) &&
      out->type_protocol.empty()) {
    out->type_protocol = legacy;
  }
  if (AMJson::QueryKey(json, {"abort"}, &legacy) && out->type_abort.empty()) {
    out->type_abort = legacy;
  }
  if (AMJson::QueryKey(json, {"common"}, &legacy) &&
      out->default_style.empty()) {
    out->default_style = legacy;
  }
  if (AMJson::QueryKey(json, {"module"}, &legacy) && out->cli_module.empty()) {
    out->cli_module = legacy;
  }
  if (AMJson::QueryKey(json, {"command"}, &legacy) &&
      out->cli_command.empty()) {
    out->cli_command = legacy;
  }
  if (AMJson::QueryKey(json, {"unexpected"}, &legacy) &&
      out->cli_unexpected.empty()) {
    out->cli_unexpected = legacy;
  }
  if (AMJson::QueryKey(json, {"illegal_command"}, &legacy) &&
      out->cli_unexpected.empty()) {
    out->cli_unexpected = legacy;
  }
  if (AMJson::QueryKey(json, {"option"}, &legacy) && out->cli_option.empty()) {
    out->cli_option = legacy;
  }
  if (AMJson::QueryKey(json, {"string"}, &legacy) && out->type_string.empty()) {
    out->type_string = legacy;
  }
  if (AMJson::QueryKey(json, {"public_varname"}, &legacy) &&
      out->varname_public.empty()) {
    out->varname_public = legacy;
  }
  if (AMJson::QueryKey(json, {"private_varname"}, &legacy) &&
      out->varname_private.empty()) {
    out->varname_private = legacy;
  }
  if (AMJson::QueryKey(json, {"nonexistent_varname"}, &legacy) &&
      out->varname_nonexistent.empty()) {
    out->varname_nonexistent = legacy;
  }
  if (AMJson::QueryKey(json, {"varname_dollar"}, &legacy) &&
      out->varname_dollar.empty()) {
    out->varname_dollar = legacy;
  }
  if (AMJson::QueryKey(json, {"varname_left_brace"}, &legacy) &&
      out->varname_left_brace.empty()) {
    out->varname_left_brace = legacy;
  }
  if (AMJson::QueryKey(json, {"varname_right_brace"}, &legacy) &&
      out->varname_right_brace.empty()) {
    out->varname_right_brace = legacy;
  }
  if (AMJson::QueryKey(json, {"varname_colon"}, &legacy) &&
      out->varname_colon.empty()) {
    out->varname_colon = legacy;
  }
  if (AMJson::QueryKey(json, {"varname_equal"}, &legacy) &&
      out->varname_equal.empty()) {
    out->varname_equal = legacy;
  }
  if (AMJson::QueryKey(json, {"nickname"}, &legacy) &&
      out->nickname_ok.empty()) {
    out->nickname_ok = legacy;
  }
  if (AMJson::QueryKey(json, {"nickname_at"}, &legacy) &&
      out->nickname_at.empty()) {
    out->nickname_at = legacy;
  }
  if (AMJson::QueryKey(json, {"disconnected_nickname"}, &legacy) &&
      out->nickname_disconnected.empty()) {
    out->nickname_disconnected = legacy;
  }
  if (AMJson::QueryKey(json, {"unestablished_nickname"}, &legacy) &&
      out->nickname_unestablished.empty()) {
    out->nickname_unestablished = legacy;
  }
  if (AMJson::QueryKey(json, {"nonexistent_nickname"}, &legacy) &&
      out->nickname_nonexistent.empty()) {
    out->nickname_nonexistent = legacy;
  }
  if (AMJson::QueryKey(json, {"valid_new_nickname"}, &legacy) &&
      out->nickname_new_valid.empty()) {
    out->nickname_new_valid = legacy;
  }
  if (AMJson::QueryKey(json, {"invalid_new_nickname"}, &legacy) &&
      out->nickname_new_invalid.empty()) {
    out->nickname_new_invalid = legacy;
  }
  if (AMJson::QueryKey(json, {"builtin_arg"}, &legacy) &&
      out->attr_valid.empty()) {
    out->attr_valid = legacy;
  }
  if (AMJson::QueryKey(json, {"nonexistent_builtin_arg"}, &legacy) &&
      out->attr_invalid.empty()) {
    out->attr_invalid = legacy;
  }
  if (AMJson::QueryKey(json, {"username"}, &legacy) &&
      out->type_username.empty()) {
    out->type_username = legacy;
  }
  if (AMJson::QueryKey(json, {"atsign"}, &legacy) &&
      out->nickname_at.empty()) {
    out->nickname_at = legacy;
  }
  if (AMJson::QueryKey(json, {"dollarsign"}, &legacy) &&
      out->varname_dollar.empty()) {
    out->varname_dollar = legacy;
  }
  if (AMJson::QueryKey(json, {"equalsign"}, &legacy) &&
      out->varname_equal.empty()) {
    out->varname_equal = legacy;
  }
  if (AMJson::QueryKey(json, {"escapedsign"}, &legacy) &&
      out->sign_escaped.empty()) {
    out->sign_escaped = legacy;
  }
  if (AMJson::QueryKey(json, {"bangsign"}, &legacy) &&
      out->sign_bang.empty()) {
    out->sign_bang = legacy;
  }
  if (AMJson::QueryKey(json, {"shell_cmd"}, &legacy) &&
      out->type_shell_cmd.empty()) {
    out->type_shell_cmd = legacy;
  }
  if (AMJson::QueryKey(json, {"number"}, &legacy) && out->type_number.empty()) {
    out->type_number = legacy;
  }
  if (AMJson::QueryKey(json, {"timestamp"}, &legacy) &&
      out->default_style.empty()) {
    out->default_style = legacy;
  }
  if (AMJson::QueryKey(json, {"path_like"}, &legacy) &&
      out->default_style.empty()) {
    out->default_style = legacy;
  }
  if (AMJson::QueryKey(json, {"termname"}, &legacy) &&
      out->termname_ok.empty()) {
    out->termname_ok = legacy;
  }
  if (AMJson::QueryKey(json, {"termname_at"}, &legacy) &&
      out->termname_at.empty()) {
    out->termname_at = legacy;
  }
  if (AMJson::QueryKey(json, {"disconnected_termname"}, &legacy) &&
      out->termname_disconnected.empty()) {
    out->termname_disconnected = legacy;
  }
  if (AMJson::QueryKey(json, {"unestablished_termname"}, &legacy) &&
      out->termname_unestablished.empty()) {
    out->termname_unestablished = legacy;
  }
  if (AMJson::QueryKey(json, {"nonexistent_termname"}, &legacy) &&
      out->termname_nonexistent.empty()) {
    out->termname_nonexistent = legacy;
  }
  if (AMJson::QueryKey(json, {"channelname"}, &legacy) &&
      out->channelname_ok.empty()) {
    out->channelname_ok = legacy;
  }
  if (AMJson::QueryKey(json, {"disconnected_channelname"}, &legacy) &&
      out->channelname_disconnected.empty()) {
    out->channelname_disconnected = legacy;
  }
  if (AMJson::QueryKey(json, {"nonexistent_channelname"}, &legacy) &&
      out->channelname_nonexistent.empty()) {
    out->channelname_nonexistent = legacy;
  }
  if (AMJson::QueryKey(json, {"valid_new_channelname"}, &legacy) &&
      out->channelname_new_valid.empty()) {
    out->channelname_new_valid = legacy;
  }
  if (AMJson::QueryKey(json, {"invalid_new_channelname"}, &legacy) &&
      out->channelname_new_invalid.empty()) {
    out->channelname_new_invalid = legacy;
  }
}

[[maybe_unused]] Json EncodeInputHighlight_(const InputHighlightStyle &in) {
  Json out = Json::object();
  out["default_style"] = in.default_style;
  out["type_string"] = in.type_string;
  out["type_number"] = in.type_number;
  out["type_protocol"] = in.type_protocol;
  out["type_username"] = in.type_username;
  out["type_abort"] = in.type_abort;
  out["type_hostname"] = in.type_hostname;
  out["type_shell_cmd"] = in.type_shell_cmd;
  out["sign_escaped"] = in.sign_escaped;
  out["sign_bang"] = in.sign_bang;
  out["cli_command"] = in.cli_command;
  out["cli_unexpected"] = in.cli_unexpected;
  out["cli_module"] = in.cli_module;
  out["cli_option"] = in.cli_option;
  out["varname_public"] = in.varname_public;
  out["varname_private"] = in.varname_private;
  out["varname_nonexistent"] = in.varname_nonexistent;
  out["varname_dollar"] = in.varname_dollar;
  out["varname_left_brace"] = in.varname_left_brace;
  out["varname_right_brace"] = in.varname_right_brace;
  out["varname_colon"] = in.varname_colon;
  out["varname_equal"] = in.varname_equal;
  out["varvalue"] = in.varvalue;
  out["nickname_ok"] = in.nickname_ok;
  out["nickname_at"] = in.nickname_at;
  out["nickname_disconnected"] = in.nickname_disconnected;
  out["nickname_unestablished"] = in.nickname_unestablished;
  out["nickname_nonexistent"] = in.nickname_nonexistent;
  out["nickname_new_valid"] = in.nickname_new_valid;
  out["nickname_new_invalid"] = in.nickname_new_invalid;
  out["termname_ok"] = in.termname_ok;
  out["termname_at"] = in.termname_at;
  out["termname_disconnected"] = in.termname_disconnected;
  out["termname_unestablished"] = in.termname_unestablished;
  out["termname_nonexistent"] = in.termname_nonexistent;
  out["channelname_ok"] = in.channelname_ok;
  out["channelname_disconnected"] = in.channelname_disconnected;
  out["channelname_nonexistent"] = in.channelname_nonexistent;
  out["channelname_new_valid"] = in.channelname_new_valid;
  out["channelname_new_invalid"] = in.channelname_new_invalid;
  out["attr_valid"] = in.attr_valid;
  out["attr_invalid"] = in.attr_invalid;
  return out;
}

void DecodeCommon_(const Json &json, InputHighlightStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }

  DecodeInputHighlight_(json, out);

  (void)AMJson::QueryKey(json, {"default"}, &out->default_style);
  (void)AMJson::QueryKey(json, {"type", "string"}, &out->type_string);
  (void)AMJson::QueryKey(json, {"type", "number"}, &out->type_number);
  (void)AMJson::QueryKey(json, {"type", "protocol"}, &out->type_protocol);
  (void)AMJson::QueryKey(json, {"type", "username"}, &out->type_username);
  (void)AMJson::QueryKey(json, {"type", "abort"}, &out->type_abort);
  (void)AMJson::QueryKey(json, {"type", "hostname"}, &out->type_hostname);
  (void)AMJson::QueryKey(json, {"type", "shell_cmd"}, &out->type_shell_cmd);

  (void)AMJson::QueryKey(json, {"sign", "escaped"}, &out->sign_escaped);
  (void)AMJson::QueryKey(json, {"sign", "bang"}, &out->sign_bang);

  (void)AMJson::QueryKey(json, {"cli", "command"}, &out->cli_command);
  (void)AMJson::QueryKey(json, {"cli", "unexpected"}, &out->cli_unexpected);
  if (out->cli_unexpected.empty()) {
    (void)AMJson::QueryKey(json, {"cli", "illegal_command"},
                           &out->cli_unexpected);
  }
  (void)AMJson::QueryKey(json, {"cli", "module"}, &out->cli_module);
  (void)AMJson::QueryKey(json, {"cli", "option"}, &out->cli_option);

  (void)AMJson::QueryKey(json, {"varname", "public"}, &out->varname_public);
  (void)AMJson::QueryKey(json, {"varname", "private"}, &out->varname_private);
  (void)AMJson::QueryKey(json, {"varname", "nonexistent"},
                         &out->varname_nonexistent);
  (void)AMJson::QueryKey(json, {"varname", "dollar"},
                         &out->varname_dollar);
  (void)AMJson::QueryKey(json, {"varname", "left_brace"},
                         &out->varname_left_brace);
  (void)AMJson::QueryKey(json, {"varname", "right_brace"},
                         &out->varname_right_brace);
  (void)AMJson::QueryKey(json, {"varname", "colon"},
                         &out->varname_colon);
  (void)AMJson::QueryKey(json, {"varname", "equal"},
                         &out->varname_equal);
  (void)AMJson::QueryKey(json, {"varvalue"}, &out->varvalue);

  (void)AMJson::QueryKey(json, {"nickname", "ok"}, &out->nickname_ok);
  (void)AMJson::QueryKey(json, {"nickname", "at"}, &out->nickname_at);
  (void)AMJson::QueryKey(json, {"nickname", "disconnected"},
                         &out->nickname_disconnected);
  (void)AMJson::QueryKey(json, {"nickname", "unestablished"},
                         &out->nickname_unestablished);
  (void)AMJson::QueryKey(json, {"nickname", "nonexistent"},
                         &out->nickname_nonexistent);
  (void)AMJson::QueryKey(json, {"nickname", "new", "valid"},
                         &out->nickname_new_valid);
  (void)AMJson::QueryKey(json, {"nickname", "new", "invalid"},
                         &out->nickname_new_invalid);

  (void)AMJson::QueryKey(json, {"termname", "ok"}, &out->termname_ok);
  (void)AMJson::QueryKey(json, {"termname", "at"}, &out->termname_at);
  (void)AMJson::QueryKey(json, {"termname", "disconnected"},
                         &out->termname_disconnected);
  (void)AMJson::QueryKey(json, {"termname", "unestablished"},
                         &out->termname_unestablished);
  (void)AMJson::QueryKey(json, {"termname", "nonexistent"},
                         &out->termname_nonexistent);

  (void)AMJson::QueryKey(json, {"channelname", "ok"}, &out->channelname_ok);
  (void)AMJson::QueryKey(json, {"channelname", "disconnected"},
                         &out->channelname_disconnected);
  (void)AMJson::QueryKey(json, {"channelname", "nonexistent"},
                         &out->channelname_nonexistent);
  (void)AMJson::QueryKey(json, {"channelname", "new", "valid"},
                         &out->channelname_new_valid);
  (void)AMJson::QueryKey(json, {"channelname", "new", "invalid"},
                         &out->channelname_new_invalid);

  (void)AMJson::QueryKey(json, {"attr", "valid"}, &out->attr_valid);
  (void)AMJson::QueryKey(json, {"attr", "invalid"},
                         &out->attr_invalid);

  if (out->type_shell_cmd.empty()) {
    out->type_shell_cmd = out->cli_command;
  }
}

Json EncodeCommon_(const InputHighlightStyle &in) {
  Json out = Json::object();
  out["default"] = in.default_style;
  out["type"]["string"] = in.type_string;
  out["type"]["number"] = in.type_number;
  out["type"]["protocol"] = in.type_protocol;
  out["type"]["username"] = in.type_username;
  out["type"]["abort"] = in.type_abort;
  out["type"]["hostname"] = in.type_hostname;
  out["type"]["shell_cmd"] = in.type_shell_cmd;

  out["sign"]["escaped"] = in.sign_escaped;
  out["sign"]["bang"] = in.sign_bang;

  out["cli"]["command"] = in.cli_command;
  out["cli"]["unexpected"] = in.cli_unexpected;
  out["cli"]["module"] = in.cli_module;
  out["cli"]["option"] = in.cli_option;

  out["varname"]["public"] = in.varname_public;
  out["varname"]["private"] = in.varname_private;
  out["varname"]["nonexistent"] = in.varname_nonexistent;
  out["varname"]["dollar"] = in.varname_dollar;
  out["varname"]["left_brace"] = in.varname_left_brace;
  out["varname"]["right_brace"] = in.varname_right_brace;
  out["varname"]["colon"] = in.varname_colon;
  out["varname"]["equal"] = in.varname_equal;
  out["varvalue"] = in.varvalue;

  out["nickname"]["ok"] = in.nickname_ok;
  out["nickname"]["at"] = in.nickname_at;
  out["nickname"]["disconnected"] = in.nickname_disconnected;
  out["nickname"]["unestablished"] = in.nickname_unestablished;
  out["nickname"]["nonexistent"] = in.nickname_nonexistent;
  out["nickname"]["new"]["valid"] = in.nickname_new_valid;
  out["nickname"]["new"]["invalid"] = in.nickname_new_invalid;

  out["termname"]["ok"] = in.termname_ok;
  out["termname"]["at"] = in.termname_at;
  out["termname"]["disconnected"] = in.termname_disconnected;
  out["termname"]["unestablished"] = in.termname_unestablished;
  out["termname"]["nonexistent"] = in.termname_nonexistent;

  out["channelname"]["ok"] = in.channelname_ok;
  out["channelname"]["disconnected"] = in.channelname_disconnected;
  out["channelname"]["nonexistent"] = in.channelname_nonexistent;
  out["channelname"]["new"]["valid"] = in.channelname_new_valid;
  out["channelname"]["new"]["invalid"] = in.channelname_new_invalid;

  out["attr"]["valid"] = in.attr_valid;
  out["attr"]["invalid"] = in.attr_invalid;
  return out;
}

void DecodeValueQueryHighlight_(const Json &json,
                                ValueQueryHighlightStyle *out) {
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
  (void)AMJson::QueryKey(json, {"default"}, &out->default_style);
  (void)AMJson::QueryKey(json, {"tree", "root"}, &out->tree_root);
  (void)AMJson::QueryKey(json, {"tree", "node"}, &out->tree_node);
  (void)AMJson::QueryKey(json, {"tree", "leaf"}, &out->tree_leaf);
  (void)AMJson::QueryKey(json, {"type", "dir"}, &out->type_dir);
  (void)AMJson::QueryKey(json, {"type", "regular"}, &out->type_regular);
  (void)AMJson::QueryKey(json, {"type", "symlink"}, &out->type_symlink);
  (void)AMJson::QueryKey(json, {"type", "otherspecial"},
                         &out->type_otherspecial);
  (void)AMJson::QueryKey(json, {"type", "nonexistent"},
                         &out->type_nonexistent);

  std::string legacy = {};
  if (AMJson::QueryKey(json, {"cwd"}, &legacy) && out->type_dir.empty()) {
    out->type_dir = legacy;
  }
  if (AMJson::QueryKey(json, {"path_str"}, &legacy) &&
      out->default_style.empty()) {
    out->default_style = legacy;
  }
  if (AMJson::QueryKey(json, {"root"}, &legacy) && out->tree_root.empty()) {
    out->tree_root = legacy;
  }
  if (AMJson::QueryKey(json, {"node_dir_name"}, &legacy) &&
      out->tree_node.empty()) {
    out->tree_node = legacy;
  }
  if (AMJson::QueryKey(json, {"filename"}, &legacy) &&
      out->tree_leaf.empty()) {
    out->tree_leaf = legacy;
  }
  if (AMJson::QueryKey(json, {"dir"}, &legacy) && out->type_dir.empty()) {
    out->type_dir = legacy;
  }
  if (AMJson::QueryKey(json, {"regular"}, &legacy) &&
      out->type_regular.empty()) {
    out->type_regular = legacy;
  }
  if (AMJson::QueryKey(json, {"symlink"}, &legacy) &&
      out->type_symlink.empty()) {
    out->type_symlink = legacy;
  }
  if (AMJson::QueryKey(json, {"otherspecial"}, &legacy) &&
      out->type_otherspecial.empty()) {
    out->type_otherspecial = legacy;
  }
  if (AMJson::QueryKey(json, {"nonexistent"}, &legacy) &&
      out->type_nonexistent.empty()) {
    out->type_nonexistent = legacy;
  }
  if (out->default_style.empty()) {
    out->default_style = out->type_regular;
  }
  if (out->tree_node.empty()) {
    out->tree_node = out->type_dir;
  }
  if (out->tree_leaf.empty()) {
    out->tree_leaf = out->type_regular;
  }
}

Json EncodePathHighlight_(const PathHighlightStyle &in) {
  Json out = Json::object();
  out["default"] = in.default_style;
  out["tree"]["root"] = in.tree_root;
  out["tree"]["node"] = in.tree_node;
  out["tree"]["leaf"] = in.tree_leaf;
  out["type"]["dir"] = in.type_dir;
  out["type"]["regular"] = in.type_regular;
  out["type"]["symlink"] = in.type_symlink;
  out["type"]["otherspecial"] = in.type_otherspecial;
  out["type"]["nonexistent"] = in.type_nonexistent;
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
        if (!typed->style.cli_prompt.shortcut.contains(key)) {
          typed->style.cli_prompt.shortcut[key] = std::move(value);
        }
      }
    }
    DecodeInputHighlight_(
        codec_common::QueryObjectAt_(style, {"InputHighlight"}),
        &typed->style.common);
    DecodeCommon_(codec_common::QueryObjectAt_(style, {"Common"}),
                  &typed->style.common);
    DecodeValueQueryHighlight_(
        codec_common::QueryObjectAt_(style, {"ValueQueryHighlight"}),
        &typed->style.value_query_highlight);
    DecodeInternalStyle_(codec_common::QueryObjectAt_(style, {"InternalStyle"}),
                         &typed->style.internal_style);
    DecodePathHighlight_(codec_common::QueryObjectAt_(style, {"Path"}),
                         &typed->style.path);
    DecodeSystemInfo_(codec_common::QueryObjectAt_(style, {"SystemInfo"}),
                      &typed->style.system_info);

    AMDomain::style::service::NormalizeStyleConfigArg(typed);
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
    style["shortcut"] =
        codec_common::WriteStringMap_(typed->style.cli_prompt.shortcut);
    style["CLIPrompt"] = EncodeCliPrompt_(typed->style.cli_prompt);
    style["Common"] = EncodeCommon_(typed->style.common);
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
std::unordered_map<std::type_index, const IArgCodec *> BuildCodecMap() {
  static const host_codec::HostConfigArgCodec host_config_codec = {};
  static const host_codec::KnownHostEntryArgCodec known_host_codec = {};
  static const settings_codec::ConfigBackupSetCodec backup_set_codec = {};
  static const settings_codec::TransferManagerArgCodec transfer_manager_codec =
      {};
  static const settings_codec::LogManagerArgCodec log_manager_codec = {};
  static const settings_codec::CompleterArgCodec completer_codec = {};
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
  map[completer_codec.TypeKey()] = &completer_codec;
  map[client_service_codec.TypeKey()] = &client_service_codec;
  map[filesystem_codec.TypeKey()] = &filesystem_codec;
  map[var_set_codec.TypeKey()] = &var_set_codec;
  map[prompt_profile_arg_codec.TypeKey()] = &prompt_profile_arg_codec;
  map[prompt_history_arg_codec.TypeKey()] = &prompt_history_arg_codec;
  map[style_config_arg_codec.TypeKey()] = &style_config_arg_codec;
  return map;
}
} // namespace AMInfra::config
