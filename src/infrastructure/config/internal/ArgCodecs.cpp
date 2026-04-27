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
#include "domain/terminal/TerminalModel.hpp"
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
inline constexpr const char *kTrashDirKey = "trash_dir";
inline constexpr const char *kLoginDirKey = "login_dir";
inline constexpr const char *kCwdKey = "cwd";
inline constexpr const char *kKeyFileKey = "keyfile";
inline constexpr const char *kCompressionKey = "compression";
inline constexpr const char *kCmdTemplateKey = "cmd_template";
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
  (void)AMJson::QueryKey(json, {kCmdTemplateKey}, &cfg.metadata.cmd_template);

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
using AMDomain::terminal::TerminalManagerArg;
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
    (void)AMJson::QueryKey(options, {"TransferManager", "refresh_interval_ms"},
                           &typed->refresh_interval_ms);
    (void)AMJson::QueryKey(options,
                           {"TransferManager", "speed_windows_size_s"},
                           &typed->speed_windows_size_s);
    (void)AMJson::QueryKey(options, {"TransferManager", "ring_buffersize"},
                           &typed->ring_buffersize);
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
    (*root)["Options"]["TransferManager"]["refresh_interval_ms"] =
        typed->refresh_interval_ms;
    (*root)["Options"]["TransferManager"]["speed_windows_size_s"] =
        typed->speed_windows_size_s;
    (*root)["Options"]["TransferManager"]["ring_buffersize"] =
        typed->ring_buffersize;
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

class TerminalManagerArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index TypeKey() const override {
    return std::type_index(typeid(TerminalManagerArg));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output TerminalManagerArg");
    }
    auto *typed = static_cast<TerminalManagerArg *>(out);
    *typed = {};

    const Json options = OptionsRoot_(root);
    (void)AMJson::QueryKey(options, {"TerminalManager", "read_timeout_ms"},
                           &typed->read_timeout_ms);
    (void)AMJson::QueryKey(options, {"TerminalManager", "send_timeout_ms"},
                           &typed->send_timeout_ms);
    (void)AMJson::QueryKey(
        options, {"TerminalManager", "channel_cache_threshold_bytes", "warning"},
        &typed->channel_cache_threshold_bytes.warning);
    (void)AMJson::QueryKey(
        options, {"TerminalManager", "channel_cache_threshold_bytes",
                  "terminate"},
        &typed->channel_cache_threshold_bytes.terminate);
    AMDomain::terminal::NormalizeTerminalManagerArg(typed);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input TerminalManagerArg or root json");
    }
    auto typed = *static_cast<const TerminalManagerArg *>(in);
    AMDomain::terminal::NormalizeTerminalManagerArg(&typed);
    if (!root->is_object()) {
      *root = Json::object();
    }

    (void)AMJson::DelKey(*root,
                         {"Options", "TerminalManager",
                          "channel_cache_threshold_Bytes"});
    (*root)["Options"]["TerminalManager"]["read_timeout_ms"] =
        typed.read_timeout_ms;
    (*root)["Options"]["TerminalManager"]["send_timeout_ms"] =
        typed.send_timeout_ms;
    (*root)["Options"]["TerminalManager"]["channel_cache_threshold_bytes"]
           ["warning"] = typed.channel_cache_threshold_bytes.warning;
    (*root)["Options"]["TerminalManager"]["channel_cache_threshold_bytes"]
           ["terminate"] = typed.channel_cache_threshold_bytes.terminate;
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "TerminalManager"});
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
  (void)AMJson::QueryKey(json, {"Prompt", "enable_multiline"},
                         &out->prompt.enable_multiline);

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
  out["Prompt"]["enable_multiline"] = in.prompt.enable_multiline;

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
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output PromptHistoryArg");
    }
    auto *typed = static_cast<PromptHistoryArg *>(out);
    *typed = PromptHistoryArg{};
    if (!root.is_object()) {
      return true;
    }
    const Json options = settings_codec::OptionsRoot_(root);
    (void)AMJson::QueryKey(options, {"PromptHistoryManager", "history_dir"},
                           &typed->history_dir);
    (void)AMJson::QueryKey(
        options, {"PromptHistoryManager", "allow_continuous_duplicates"},
        &typed->allow_continuous_duplicates);
    (void)AMJson::QueryKey(options, {"PromptHistoryManager", "max_count"},
                           &typed->max_count);
    typed->max_count = std::clamp(typed->max_count, 1, 200);
    if (AMStr::Strip(typed->history_dir).empty()) {
      typed->history_dir = "./history";
    }
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input PromptHistoryArg or root json");
    }
    auto typed = *static_cast<const PromptHistoryArg *>(in);
    typed.max_count = std::clamp(typed.max_count, 1, 200);
    if (AMStr::Strip(typed.history_dir).empty()) {
      typed.history_dir = "./history";
    }
    if (!root->is_object()) {
      *root = Json::object();
    }
    (*root)["Options"]["PromptHistoryManager"]["history_dir"] =
        typed.history_dir;
    (*root)["Options"]["PromptHistoryManager"]
           ["allow_continuous_duplicates"] =
        typed.allow_continuous_duplicates;
    (*root)["Options"]["PromptHistoryManager"]["max_count"] = typed.max_count;
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options", "PromptHistoryManager"});
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
using AMDomain::style::TerminalStyle;
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

void DecodeProgressBar_(const Json &json, ProgressBarStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"prefix_template"}, &out->prefix_template);
  (void)AMJson::QueryKey(json, {"bar_template"}, &out->bar_template);
  (void)AMJson::QueryKey(json, {"refresh_interval_ms"},
                         &out->refresh_interval_ms);
  (void)AMJson::QueryKey(json, {"prefix_fixed_width"},
                         &out->prefix_fixed_width);

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
  (void)AMJson::QueryKey(size, {"totol_size_max_float_digits"},
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

  Json icons = codec_common::QueryObjectAt_(json, {"icons"});
  if (!icons.is_object()) {
    icons = codec_common::QueryObjectAt_(json, {"Icons"});
  }
  (void)AMJson::QueryKey(icons, {"default"}, &out->icons.default_icon);
  (void)AMJson::QueryKey(icons, {"windows"}, &out->icons.windows);
  (void)AMJson::QueryKey(icons, {"linux"}, &out->icons.linux);
  (void)AMJson::QueryKey(icons, {"macos"}, &out->icons.macos);
  (void)AMJson::QueryKey(icons, {"freebsd"}, &out->icons.freebsd);
  (void)AMJson::QueryKey(icons, {"unix"}, &out->icons.unix);

  Json template_json = codec_common::QueryObjectAt_(json, {"template"});
  (void)AMJson::QueryKey(template_json, {"core_prompt"},
                         &out->prompt_template.core_prompt);
  (void)AMJson::QueryKey(template_json, {"history_search_prompt"},
                         &out->prompt_template.history_search_prompt);
}

Json EncodeCliPrompt_(const CLIPromptStyle &in) {
  Json out = Json::object();

  out["icons"]["default"] = in.icons.default_icon;
  out["icons"]["windows"] = in.icons.windows;
  out["icons"]["linux"] = in.icons.linux;
  out["icons"]["macos"] = in.icons.macos;
  out["icons"]["freebsd"] = in.icons.freebsd;
  out["icons"]["unix"] = in.icons.unix;

  out["template"]["core_prompt"] = in.prompt_template.core_prompt;
  out["template"]["history_search_prompt"] =
      in.prompt_template.history_search_prompt;
  return out;
}

void DecodeCommon_(const Json &json, InputHighlightStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }

  (void)AMJson::QueryKey(json, {"default"}, &out->default_style);
  (void)AMJson::QueryKey(json, {"type", "string"}, &out->type_string);
  (void)AMJson::QueryKey(json, {"type", "error"}, &out->type_error);
  (void)AMJson::QueryKey(json, {"type", "number"}, &out->type_number);
  (void)AMJson::QueryKey(json, {"type", "protocol"}, &out->type_protocol);
  (void)AMJson::QueryKey(json, {"type", "username"}, &out->type_username);
  (void)AMJson::QueryKey(json, {"type", "abort"}, &out->type_abort);
  (void)AMJson::QueryKey(json, {"type", "hostname"}, &out->type_hostname);
  (void)AMJson::QueryKey(json, {"type", "shell_cmd"}, &out->type_shell_cmd);
  (void)AMJson::QueryKey(json, {"type", "table_skeleton"},
                         &out->type_table_skeleton);

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
  (void)AMJson::QueryKey(json, {"varname", "zone"}, &out->varname_zone);
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
  (void)AMJson::QueryKey(json, {"termname", "nonexistent"},
                         &out->termname_nonexistent);
  (void)AMJson::QueryKey(json, {"termname", "new", "valid"},
                         &out->termname_new_valid);
  (void)AMJson::QueryKey(json, {"termname", "new", "invalid"},
                         &out->termname_new_invalid);

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
  out["type"]["error"] = in.type_error;
  out["type"]["number"] = in.type_number;
  out["type"]["protocol"] = in.type_protocol;
  out["type"]["username"] = in.type_username;
  out["type"]["abort"] = in.type_abort;
  out["type"]["hostname"] = in.type_hostname;
  out["type"]["shell_cmd"] = in.type_shell_cmd;
  out["type"]["table_skeleton"] = in.type_table_skeleton;

  out["sign"]["escaped"] = in.sign_escaped;
  out["sign"]["bang"] = in.sign_bang;

  out["cli"]["command"] = in.cli_command;
  out["cli"]["unexpected"] = in.cli_unexpected;
  out["cli"]["module"] = in.cli_module;
  out["cli"]["option"] = in.cli_option;

  out["varname"]["public"] = in.varname_public;
  out["varname"]["private"] = in.varname_private;
  out["varname"]["zone"] = in.varname_zone;
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
  out["termname"]["nonexistent"] = in.termname_nonexistent;
  out["termname"]["new"]["valid"] = in.termname_new_valid;
  out["termname"]["new"]["invalid"] = in.termname_new_invalid;

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
}

Json EncodeValueQueryHighlight_(const ValueQueryHighlightStyle &in) {
  Json out = Json::object();
  out["valid_value"] = in.valid_value;
  out["invalid_value"] = in.invalid_value;
  return out;
}

void DecodeInternalStyle_(const Json &json, InternalStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"inline_hint"}, &out->inline_hint);
  (void)AMJson::QueryKey(json, {"default_prompt_style"}, &out->default_prompt);
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
  (void)AMJson::QueryKey(json, {"find", "pattern"}, &out->find_pattern);
  if (out->default_style.empty()) {
    out->default_style = out->type_regular;
  }
  if (out->tree_node.empty()) {
    out->tree_node = out->type_dir;
  }
  if (out->tree_leaf.empty()) {
    out->tree_leaf = out->type_regular;
  }
  if (out->find_pattern.empty()) {
    out->find_pattern = out->type_regular;
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
  out["find"]["pattern"] = in.find_pattern;
  return out;
}

void DecodeTerminalStyle_(const Json &json, TerminalStyle *out) {
  if (!out || !json.is_object()) {
    return;
  }
  const bool has_banner_template =
      AMJson::QueryKey(json, {"banner", "template"},
                       &out->banner.template_text);
  (void)AMJson::QueryKey(json, {"banner", "background"},
                         &out->banner.background);
  (void)AMJson::QueryKey(json, {"banner", "align"}, &out->banner.align);
  const bool has_legacy_banner_template =
      AMJson::QueryKey(json, {"banner_template"}, &out->banner_template);
  if (!has_banner_template && has_legacy_banner_template &&
      !out->banner_template.empty()) {
    out->banner.template_text = out->banner_template;
  }
  out->banner_template = out->banner.template_text;
}

Json EncodeTerminalStyle_(const TerminalStyle &in) {
  Json out = Json::object();
  out["banner"]["template"] = in.banner.template_text;
  out["banner"]["background"] = in.banner.background;
  out["banner"]["align"] = in.banner.align;
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
    Json global_shortcut = codec_common::QueryObjectAt_(style, {"Shortcut"});

    DecodeCompleteMenu_(codec_common::QueryObjectAt_(style, {"CompleteMenu"}),
                        &typed->style.complete_menu);
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
    DecodeCommon_(codec_common::QueryObjectAt_(style, {"Common"}),
                  &typed->style.common);
    DecodeValueQueryHighlight_(
        codec_common::QueryObjectAt_(style, {"ValueQueryHighlight"}),
        &typed->style.value_query_highlight);
    DecodeInternalStyle_(codec_common::QueryObjectAt_(style, {"InternalStyle"}),
                         &typed->style.internal_style);
    DecodePathHighlight_(codec_common::QueryObjectAt_(style, {"Path"}),
                         &typed->style.path);
    DecodeTerminalStyle_(codec_common::QueryObjectAt_(style, {"Terminal"}),
                         &typed->style.terminal);

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
    style["ProgressBar"] = EncodeProgressBar_(typed->style.progress_bar);
    style["Shortcut"] =
        codec_common::WriteStringMap_(typed->style.cli_prompt.shortcut);
    style["CLIPrompt"] = EncodeCliPrompt_(typed->style.cli_prompt);
    style["Common"] = EncodeCommon_(typed->style.common);
    style["ValueQueryHighlight"] =
        EncodeValueQueryHighlight_(typed->style.value_query_highlight);
    style["InternalStyle"] = EncodeInternalStyle_(typed->style.internal_style);
    style["Path"] = EncodePathHighlight_(typed->style.path);
    style["Terminal"] = EncodeTerminalStyle_(typed->style.terminal);
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
  static const settings_codec::TerminalManagerArgCodec terminal_manager_codec =
      {};
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
  map[terminal_manager_codec.TypeKey()] = &terminal_manager_codec;
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
