#include "application/config/ConfigPayloads.hpp"
#include "domain/config/ConfigModel.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "domain/var/VarModel.hpp"
#include "foundation/tools/string.hpp"
#include "internal/ArgCodecRegistry.hpp"
#include <algorithm>
#include <cstdint>
#include <tuple>

namespace {
using DocumentKind = AMDomain::config::DocumentKind;

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
inline constexpr const char *kCmdPrefixKey = "cmd_prefix";
inline constexpr const char *kWrapCmdKey = "wrap_cmd";
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

class HostConfigArgCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index Type() const override {
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
      if (AMDomain::host::HostManagerService::IsLocalNickname(nickname)) {
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
  [[nodiscard]] std::type_index Type() const override {
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

            AMDomain::host::KnownHostQuery query{
                "",       hostname, static_cast<int>(port_num),
                protocol, username, fingerprint};
            if (!query.IsValid()) {
              continue;
            }

            typed->entries[AMDomain::host::BuildKnownHostKey(query)] =
                std::move(query);
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
using AMApplication::config::AutoBackupSettings;
using AMApplication::config::SettingsOptionsSnapshot;
using AMApplication::config::UserVarsSnapshot;

Json OptionsRoot_(const Json &root) {
  return codec_common::QueryObjectAt_(root, {"Options"});
}

void DecodeAutoBackupSettings_(const Json &json,
                               AutoBackupSettings *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"enabled"}, &out->enabled);
  (void)AMJson::QueryKey(json, {"interval_s"}, &out->interval_s);
  (void)AMJson::QueryKey(json, {"max_backup_count"}, &out->max_backup_count);
  (void)AMJson::QueryKey(json, {"last_backup_time_s"}, &out->last_backup_time_s);
}

Json EncodeAutoBackupSettings_(const AutoBackupSettings &in) {
  Json out = Json::object();
  out["enabled"] = in.enabled;
  out["interval_s"] = in.interval_s;
  out["max_backup_count"] = in.max_backup_count;
  out["last_backup_time_s"] = in.last_backup_time_s;
  return out;
}

class AutoBackupSettingsCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index Type() const override {
    return std::type_index(typeid(AutoBackupSettings));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output AutoBackupSettings");
    }
    auto *typed = static_cast<AutoBackupSettings *>(out);
    *typed = {};
    DecodeAutoBackupSettings_(codec_common::QueryObjectAt_(root, {"Options", "AutoConfigBackup"}),
                              typed);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input AutoBackupSettings or root json");
    }
    const auto *typed = static_cast<const AutoBackupSettings *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    (*root)["Options"]["AutoConfigBackup"] = EncodeAutoBackupSettings_(*typed);
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

class SettingsOptionsSnapshotCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index Type() const override {
    return std::type_index(typeid(SettingsOptionsSnapshot));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output SettingsOptionsSnapshot");
    }
    auto *typed = static_cast<SettingsOptionsSnapshot *>(out);
    *typed = {};

    const Json options = OptionsRoot_(root);
    (void)AMJson::QueryKey(options, {"ClientManager", "heartbeat_timeout_ms"},
                           &typed->client_manager.heartbeat_timeout_ms);
    (void)AMJson::QueryKey(options, {"TransferManager", "init_thread_num"},
                           &typed->transfer_manager.init_thread_num);
    (void)AMJson::QueryKey(options, {"TransferManager", "max_thread_num"},
                           &typed->transfer_manager.max_thread_num);
    (void)AMJson::QueryKey(options, {"FileSystem", "max_cd_history"},
                           &typed->filesystem.max_cd_history);
    (void)AMJson::QueryKey(options, {"LogManager", "client_trace_level"},
                           &typed->log_manager.client_trace_level);
    (void)AMJson::QueryKey(options, {"LogManager", "program_trace_level"},
                           &typed->log_manager.program_trace_level);
    DecodeAutoBackupSettings_(codec_common::QueryObjectAt_(options, {"AutoConfigBackup"}),
                              &typed->auto_config_backup);
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input SettingsOptionsSnapshot or root json");
    }
    const auto *typed = static_cast<const SettingsOptionsSnapshot *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }

    (*root)["Options"]["ClientManager"]["heartbeat_timeout_ms"] =
        typed->client_manager.heartbeat_timeout_ms;
    (*root)["Options"]["TransferManager"]["init_thread_num"] =
        typed->transfer_manager.init_thread_num;
    (*root)["Options"]["TransferManager"]["max_thread_num"] =
        typed->transfer_manager.max_thread_num;
    (*root)["Options"]["FileSystem"]["max_cd_history"] =
        typed->filesystem.max_cd_history;
    (*root)["Options"]["LogManager"]["client_trace_level"] =
        typed->log_manager.client_trace_level;
    (*root)["Options"]["LogManager"]["program_trace_level"] =
        typed->log_manager.program_trace_level;
    (*root)["Options"]["AutoConfigBackup"] =
        EncodeAutoBackupSettings_(typed->auto_config_backup);
    return true;
  }

  [[nodiscard]] bool Erase(const void *in, Json *root,
                           std::string *error) const override {
    (void)in;
    if (!root) {
      return codec_common::Fail_(error, "null root json");
    }
    (void)AMJson::DelKey(*root, {"Options"});
    return true;
  }
};

class UserVarsSnapshotCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index Type() const override {
    return std::type_index(typeid(UserVarsSnapshot));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output UserVarsSnapshot");
    }
    auto *typed = static_cast<UserVarsSnapshot *>(out);
    typed->domains.clear();

    const Json user_vars = codec_common::QueryObjectAt_(root, {"UserVars"});
    for (auto it = user_vars.begin(); it != user_vars.end(); ++it) {
      if (it.value().is_object()) {
        if (it.key() != varsetkn::kPublic && !varsetkn::IsValidZoneName(it.key())) {
          continue;
        }
        auto &vars = typed->domains[it.key()];
        for (auto vit = it.value().begin(); vit != it.value().end(); ++vit) {
          if (!varsetkn::IsValidVarname(vit.key())) {
            continue;
          }
          vars[vit.key()] = codec_common::ScalarToString_(vit.value());
        }
        continue;
      }

      if (!varsetkn::IsValidVarname(it.key())) {
        continue;
      }
      typed->domains[varsetkn::kPublic][it.key()] =
          codec_common::ScalarToString_(it.value());
    }
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input UserVarsSnapshot or root json");
    }
    const auto *typed = static_cast<const UserVarsSnapshot *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    Json out = Json::object();
    for (const auto &[domain, vars] : typed->domains) {
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
using AMApplication::config::PromptHistoryDocument;
using AMApplication::config::PromptProfileDocument;
using AMApplication::config::PromptProfileSettings;

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
  out->inline_hint.render_delay_ms = std::max(0, out->inline_hint.render_delay_ms);
  out->inline_hint.search_delay_ms = std::max(0, out->inline_hint.search_delay_ms);
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
  out["Complete"]["Searcher"]["Path"]["timeout_ms"] = in.complete.path.timeout_ms;

  out["Highlight"]["delay_ms"] = in.highlight.delay_ms;
  out["Highlight"]["Path"]["enable"] = in.highlight.path.enable;
  out["Highlight"]["Path"]["timeout_ms"] = in.highlight.path.timeout_ms;
  return out;
}

class PromptProfileDocumentCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index Type() const override {
    return std::type_index(typeid(PromptProfileDocument));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output PromptProfileDocument");
    }
    auto *typed = static_cast<PromptProfileDocument *>(out);
    typed->profiles.clear();

    const Json profile_root = codec_common::QueryObjectAt_(root, {"PromptProfile"});
    for (auto it = profile_root.begin(); it != profile_root.end(); ++it) {
      if (!it.value().is_object()) {
        continue;
      }
      PromptProfileSettings item{};
      DecodePromptProfileSettings_(it.value(), &item);
      typed->profiles[it.key()] = std::move(item);
    }
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input PromptProfileDocument or root json");
    }
    const auto *typed = static_cast<const PromptProfileDocument *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    Json out = Json::object();
    for (const auto &[name, settings] : typed->profiles) {
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

class PromptHistoryDocumentCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index Type() const override {
    return std::type_index(typeid(PromptHistoryDocument));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::History;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output PromptHistoryDocument");
    }
    auto *typed = static_cast<PromptHistoryDocument *>(out);
    typed->commands_by_profile.clear();
    if (!root.is_object()) {
      return true;
    }
    for (auto it = root.begin(); it != root.end(); ++it) {
      Json commands = Json::array();
      if (!AMJson::QueryKey(it.value(), {"commands"}, &commands) ||
          !commands.is_array()) {
        continue;
      }
      std::vector<std::string> out_commands;
      for (const auto &item : commands) {
        if (item.is_string()) {
          out_commands.push_back(item.get<std::string>());
        }
      }
      typed->commands_by_profile[it.key()] = std::move(out_commands);
    }
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input PromptHistoryDocument or root json");
    }
    const auto *typed = static_cast<const PromptHistoryDocument *>(in);
    Json out = Json::object();
    for (const auto &[name, commands] : typed->commands_by_profile) {
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
using AMApplication::config::AMStyleSnapshot;
using AMApplication::config::AMStyleCLIPromptArgs;
using AMApplication::config::AMStyleCompleteMenuArgs;
using AMApplication::config::AMStyleProgressBarArgs;
using AMApplication::config::AMStyleTableArgs;

void DecodeCompleteMenu_(const Json &json, AMStyleCompleteMenuArgs *out) {
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

Json EncodeCompleteMenu_(const AMStyleCompleteMenuArgs &in) {
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

void DecodeTable_(const Json &json, AMStyleTableArgs *out) {
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

Json EncodeTable_(const AMStyleTableArgs &in) {
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

void DecodeProgressBar_(const Json &json, AMStyleProgressBarArgs *out) {
  if (!out || !json.is_object()) {
    return;
  }
  (void)AMJson::QueryKey(json, {"lborder"}, &out->lborder);
  (void)AMJson::QueryKey(json, {"rborder"}, &out->rborder);
  (void)AMJson::QueryKey(json, {"fill"}, &out->fill);
  (void)AMJson::QueryKey(json, {"head"}, &out->head);
  (void)AMJson::QueryKey(json, {"remain"}, &out->remain);
  (void)AMJson::QueryKey(json, {"color"}, &out->color);
  (void)AMJson::QueryKey(json, {"refresh_interval_ms"}, &out->refresh_interval_ms);
  (void)AMJson::QueryKey(json, {"speed_window_size"}, &out->speed_window_size);
  (void)AMJson::QueryKey(json, {"bar_width"}, &out->bar_width);
  (void)AMJson::QueryKey(json, {"width_offset"}, &out->width_offset);
  (void)AMJson::QueryKey(json, {"show_percentage"}, &out->show_percentage);
  (void)AMJson::QueryKey(json, {"show_elapsed_time"}, &out->show_elapsed_time);
  (void)AMJson::QueryKey(json, {"show_remaining_time"}, &out->show_remaining_time);
}

Json EncodeProgressBar_(const AMStyleProgressBarArgs &in) {
  Json out = Json::object();
  out["lborder"] = in.lborder;
  out["rborder"] = in.rborder;
  out["fill"] = in.fill;
  out["head"] = in.head;
  out["remain"] = in.remain;
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

void DecodeCliPrompt_(const Json &json, AMStyleCLIPromptArgs *out) {
  if (!out || !json.is_object()) {
    return;
  }
  out->shortcut = codec_common::ReadStringMap_(codec_common::QueryObjectAt_(json, {"shortcut"}));
  out->icons = codec_common::ReadStringMap_(codec_common::QueryObjectAt_(json, {"icons"}), true);

  Json template_json = codec_common::QueryObjectAt_(json, {"template"});
  if (template_json.empty()) {
    template_json = codec_common::QueryObjectAt_(json, {"templete"});
  }
  (void)AMJson::QueryKey(template_json, {"core_prompt"}, &out->prompt_template.core_prompt);
  (void)AMJson::QueryKey(template_json, {"history_search_prompt"},
                         &out->prompt_template.history_search_prompt);
  if (out->prompt_template.core_prompt.empty()) {
    (void)AMJson::QueryKey(json, {"format"}, &out->prompt_template.core_prompt);
  }

  out->named_styles.clear();
  for (auto it = json.begin(); it != json.end(); ++it) {
    const std::string key = it.key();
    if (key == "shortcut" || key == "icons" || key == "template" ||
        key == "templete") {
      continue;
    }
    if (!it.value().is_string()) {
      continue;
    }
    out->named_styles[key] = it.value().get<std::string>();
  }
}

Json EncodeCliPrompt_(const AMStyleCLIPromptArgs &in) {
  Json out = Json::object();
  for (const auto &[key, value] : in.named_styles) {
    out[key] = value;
  }
  out["shortcut"] = codec_common::WriteStringMap_(in.shortcut);
  out["icons"] = codec_common::WriteStringMap_(in.icons);
  out["template"]["core_prompt"] = in.prompt_template.core_prompt;
  out["template"]["history_search_prompt"] =
      in.prompt_template.history_search_prompt;
  return out;
}

class StyleSnapshotCodec final : public AMInfra::config::IArgCodec {
public:
  [[nodiscard]] std::type_index Type() const override {
    return std::type_index(typeid(AMStyleSnapshot));
  }

  [[nodiscard]] DocumentKind Kind() const override {
    return DocumentKind::Settings;
  }

  [[nodiscard]] bool Decode(const Json &root, void *out,
                            std::string *error) const override {
    if (!out) {
      return codec_common::Fail_(error, "null output AMStyleSnapshot");
    }
    auto *typed = static_cast<AMStyleSnapshot *>(out);
    *typed = {};

    const Json style = codec_common::QueryObjectAt_(root, {"Style"});
    DecodeCompleteMenu_(codec_common::QueryObjectAt_(style, {"CompleteMenu"}),
                        &typed->complete_menu);
    DecodeTable_(codec_common::QueryObjectAt_(style, {"Table"}),
                 &typed->table);
    DecodeProgressBar_(codec_common::QueryObjectAt_(style, {"ProgressBar"}),
                       &typed->progress_bar);
    DecodeCliPrompt_(codec_common::QueryObjectAt_(style, {"CLIPrompt"}),
                     &typed->cli_prompt);
    typed->input_highlight =
        codec_common::ReadStringMap_(codec_common::QueryObjectAt_(style, {"InputHighlight"}));
    typed->value_query_highlight =
        codec_common::ReadStringMap_(codec_common::QueryObjectAt_(style, {"ValueQueryHighlight"}));
    typed->path = codec_common::ReadStringMap_(codec_common::QueryObjectAt_(style, {"Path"}));
    typed->system_info =
        codec_common::ReadStringMap_(codec_common::QueryObjectAt_(style, {"SystemInfo"}));
    typed->Normalize();
    return true;
  }

  [[nodiscard]] bool Encode(const void *in, Json *root,
                            std::string *error) const override {
    if (!in || !root) {
      return codec_common::Fail_(error,
                                 "null input AMStyleSnapshot or root json");
    }
    const auto *typed = static_cast<const AMStyleSnapshot *>(in);
    if (!root->is_object()) {
      *root = Json::object();
    }
    Json style = Json::object();
    style["CompleteMenu"] = EncodeCompleteMenu_(typed->complete_menu);
    style["Table"] = EncodeTable_(typed->table);
    style["ProgressBar"] = EncodeProgressBar_(typed->progress_bar);
    style["CLIPrompt"] = EncodeCliPrompt_(typed->cli_prompt);
    style["InputHighlight"] = codec_common::WriteStringMap_(typed->input_highlight);
    style["ValueQueryHighlight"] = codec_common::WriteStringMap_(typed->value_query_highlight);
    style["Path"] = codec_common::WriteStringMap_(typed->path);
    style["SystemInfo"] = codec_common::WriteStringMap_(typed->system_info);
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
} // namespace style_codec

} // namespace

namespace AMInfra::config {
ArgCodecRegistry::ArgCodecRegistry() {
  codecs_.push_back(std::make_unique<host_codec::HostConfigArgCodec>());
  codecs_.push_back(std::make_unique<host_codec::KnownHostEntryArgCodec>());
  codecs_.push_back(std::make_unique<settings_codec::AutoBackupSettingsCodec>());
  codecs_.push_back(std::make_unique<settings_codec::SettingsOptionsSnapshotCodec>());
  codecs_.push_back(std::make_unique<settings_codec::UserVarsSnapshotCodec>());
  codecs_.push_back(std::make_unique<prompt_codec::PromptProfileDocumentCodec>());
  codecs_.push_back(std::make_unique<prompt_codec::PromptHistoryDocumentCodec>());
  codecs_.push_back(std::make_unique<style_codec::StyleSnapshotCodec>());

  for (const auto &codec : codecs_) {
    if (!codec) {
      continue;
    }
    map_[codec->Type()] = codec.get();
  }
}

const ArgCodecRegistry &ArgCodecRegistry::Instance() {
  static const ArgCodecRegistry registry = {};
  return registry;
}

const IArgCodec *ArgCodecRegistry::Find(const std::type_index &type) const {
  auto it = map_.find(type);
  if (it == map_.end()) {
    return nullptr;
  }
  return it->second;
}

bool DecodeArg(const std::type_index &type, const Json &root, void *out,
               std::string *error) {
  const IArgCodec *codec = ArgCodecRegistry::Instance().Find(type);
  if (!codec) {
    return codec_common::Fail_(error, "codec not found for payload type");
  }
  return codec->Decode(root, out, error);
}

bool EncodeArg(const std::type_index &type, const void *in, Json *root,
               std::string *error) {
  const IArgCodec *codec = ArgCodecRegistry::Instance().Find(type);
  if (!codec) {
    return codec_common::Fail_(error, "codec not found for payload type");
  }
  return codec->Encode(in, root, error);
}

bool EraseArg(const std::type_index &type, const void *in, Json *root,
              std::string *error) {
  const IArgCodec *codec = ArgCodecRegistry::Instance().Find(type);
  if (!codec) {
    return codec_common::Fail_(error, "codec not found for payload type");
  }
  return codec->Erase(in, root, error);
}
} // namespace AMInfra::config
