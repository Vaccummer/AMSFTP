#pragma once
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"
#include "AMClient/SFTP.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <cstdint>
#include <unordered_map>

namespace configkn {
/**
 * @brief Host config attribute selector for unified value validation.
 */
enum class HostAttr {
  Nickname,
  Hostname,
  Username,
  Port,
  Password,
  Protocol,
  BufferSize,
  TrashDir,
  LoginDir,
  Keyfile,
  Compression,
  CmdPrefix,
  WrapCmd,
};

/**
 * @brief Parse a host attribute name into HostAttr.
 */
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
}

inline bool ValidateNickname(const std::string &nickname) {
  if (nickname.empty())
    return false;
  for (const auto &ch : nickname) {
    if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' ||
        ch == '-') {
      continue;
    }
    return false;
  }
  return true;
};

inline ClientProtocol StrToProtocol(const std::string &protocol_str) {
  const static std::unordered_map<std::string, ClientProtocol> protocol_map = {
      {"sftp", ClientProtocol::SFTP},
      {"ftp", ClientProtocol::FTP},
      {"local", ClientProtocol::LOCAL},
  };
  auto it = protocol_map.find(AMStr::lowercase(protocol_str));
  if (it != protocol_map.end()) {
    return it->second;
  } else {
    return ClientProtocol::SFTP;
  }
}

/**
 * @brief Validate one host attribute value.
 *
 * @param attr Attribute selector.
 * @param value Input raw value.
 * @param normalized Optional normalized output value.
 * @param error_msg Optional validation error message.
 * @param allow_exists_hostname Whether existing hostnames in config are
 * allowed.
 * @param allow_local_hostname Whether local hostnames are allowed.
 * @param code Optional output error code.
 * @return true if input value is valid for the given attribute.
 */
bool ValidateHostAttrValue(HostAttr attr, const std::string &value,
                           std::string *normalized = nullptr,
                           std::string *error_msg = nullptr,
                           bool allow_exists_hostname = true,
                           bool allow_local_hostname = true,
                           EC *code = nullptr);
inline constexpr int DefaultSFTPPort = 22;
inline constexpr int DefaultFTPPort = 21;
inline const static std::string fingerprint = "fingerprint";
inline const static std::string hosts = "HOSTS";
inline const static std::string keys = "private_keys";
inline const static std::string hostname = "hostname";
inline const static std::string username = "username";
inline const static std::string port = "port";
inline const static std::string password = "password";
inline const static std::string protocol = "protocol";
inline const static std::string buffer_size = "buffer_size";
inline const static std::string trash_dir = "trash_dir";
inline const static std::string login_dir = "login_dir";
inline const static std::string keyfile = "keyfile";
inline const static std::string compression = "compression";
inline const static std::string cmd_prefix = "cmd_prefix";
inline const static std::string wrap_cmd = "wrap_cmd";

inline static const std::array<std::string, 12> fileds = {
    configkn::hostname,    configkn::username,   configkn::protocol,
    configkn::port,        configkn::password,   configkn::buffer_size,
    configkn::trash_dir,   configkn::login_dir,  configkn::keyfile,
    configkn::compression, configkn::cmd_prefix, configkn::wrap_cmd,
};
} // namespace configkn

struct ClientMetaData {
  std::string cmd_prefix = "";
  bool wrap_cmd = false;
  std::string login_dir = "";
};

struct HostConfig {
  ConRequest request = {};
  ClientMetaData metadata = {};

  [[nodiscard]] std::unordered_map<std::string, std::string>
  GetStrDict() const {
    return {
        {"hostname", request.hostname},
        {"username", request.username},
        {"port", std::to_string(request.port)},
        {"password", request.password},
        {"protocol", AM_ENUM_NAME(request.protocol)},
        {"buffer_size", std::to_string(request.buffer_size)},
        {"trash_dir", request.trash_dir},
        {"login_dir", metadata.login_dir},
        {"keyfile", request.keyfile},
        {"compression", request.compression ? "true" : "false"},
        {"cmd_prefix", metadata.cmd_prefix},
        {"wrap_cmd", metadata.wrap_cmd ? "true" : "false"},
    };
  }

  [[nodiscard]] Json GetJson() const {
    Json json = Json::object();
    json[configkn::hostname] = request.hostname;
    json[configkn::username] = request.username;
    json[configkn::port] = request.port;
    json[configkn::password] = request.password;
    json[configkn::protocol] = AMStr::lowercase(AM_ENUM_NAME(request.protocol));
    json[configkn::buffer_size] = request.buffer_size;
    json[configkn::trash_dir] = request.trash_dir;
    json[configkn::login_dir] = metadata.login_dir;
    json[configkn::keyfile] = request.keyfile;
    json[configkn::compression] = request.compression;
    json[configkn::cmd_prefix] = metadata.cmd_prefix;
    json[configkn::wrap_cmd] = metadata.wrap_cmd;
    return json;
  }
  HostConfig() = default;

  HostConfig(const std::string &nickname, const Json &jsond) {
    if (!jsond.is_object()) {
      return;
    }

    if (!configkn::ValidateNickname(nickname)) {
      return;
    }

    this->request.nickname = nickname;

    if (!QueryKey(jsond, {configkn::hostname}, &this->request.hostname)) {
      return;
    }

    if (this->request.hostname.empty()) {
      return;
    }

    if (!QueryKey(jsond, {configkn::username}, &this->request.username)) {
      return;
    }

    if (this->request.username.empty()) {
      return;
    }

    std::string protocol_str;
    if (!QueryKey(jsond, {configkn::protocol}, &protocol_str)) {
      request.protocol = ClientProtocol::SFTP;
    } else {
      request.protocol = configkn::StrToProtocol(protocol_str);
    }

    int tmp_port = -1;
    QueryKey(jsond, {configkn::port}, &tmp_port);
    if (tmp_port <= 0 || tmp_port > 65535) {
      this->request.port = (this->request.protocol == ClientProtocol::FTP)
                               ? configkn::DefaultFTPPort
                               : configkn::DefaultSFTPPort;
    } else {
      this->request.port = tmp_port;
    }

    QueryKey(jsond, {configkn::password}, &this->request.password);
    QueryKey(jsond, {configkn::keyfile}, &this->request.keyfile);
    QueryKey(jsond, {configkn::compression}, &this->request.compression);
    QueryKey(jsond, {configkn::trash_dir}, &this->request.trash_dir);
    QueryKey(jsond, {configkn::login_dir}, &metadata.login_dir);
    QueryKey(jsond, {configkn::cmd_prefix}, &metadata.cmd_prefix);
    QueryKey(jsond, {configkn::wrap_cmd}, &metadata.wrap_cmd);

    int64_t tmp_size = -1;
    QueryKey(jsond, {configkn::buffer_size}, &tmp_size);
    if (tmp_size <= 0) {
      this->request.buffer_size = AMDefaultRemoteBufferSize;
    } else {
      this->request.buffer_size =
          std::min(std::max(tmp_size, static_cast<int64_t>(1)),
                   static_cast<int64_t>(AMMaxBufferSize));
    }
  };

  [[nodiscard]] bool IsValid() const {
    return request.IsValid() && request.protocol != ClientProtocol::Unknown &&
           request.buffer_size > 0;
  }
};

/** @brief Backward-compatible alias. Prefer HostConfig. */
using ClientConfig = HostConfig;

struct KnownHostEntry {
  std::string nickname = "";
  std::string hostname = "";
  int port = 0;
  std::string protocol = "";
  std::string fingerprint = "";
  KnownHostEntry() = default;
  KnownHostEntry(const Json &jsond) {
    if (!jsond.is_object()) {
      return;
    }
    QueryKey(jsond, {configkn::hostname}, &hostname);
    QueryKey(jsond, {configkn::port}, &port);
    QueryKey(jsond, {configkn::protocol}, &protocol);
    QueryKey(jsond, {configkn::fingerprint}, &fingerprint);
  }
  [[nodiscard]] bool IsValid() const {
    return !hostname.empty() && port > 0 && port <= 65535 &&
           !fingerprint.empty();
  }
};

class AMHostManager : public NonCopyableNonMovable {
public:
  explicit AMHostManager() = default;
  static AMHostManager &Instance() {
    static AMHostManager instance;
    return instance;
  }
  ECM Init() override {
    CollectHosts_();
    return Ok();
  };

  [[nodiscard]] std::pair<ECM, HostConfig>
  GetClientConfig(const std::string &nickname);
  /**
   * @brief Fetch local client config from storage and fall back to defaults.
   */
  [[nodiscard]] std::pair<ECM, HostConfig> GetLocalConfig();
  ECM UpsertHost(const HostConfig &entry, bool dump_now = true);

  [[nodiscard]] ECM FindKnownHost(KnownHostQuery &query) const;
  ECM UpsertKnownHost(const KnownHostQuery &query, bool dump_now = true);

  [[nodiscard]] bool HostExists(const std::string &nickname) const;

  [[nodiscard]] std::vector<std::string> ListNames() const;

  void CollectHosts_() const;

  [[nodiscard]] std::pair<ECM, std::vector<std::string>>
  PrivateKeys(bool print_sign = false) const;
  ECM List(bool detailed = true) const;
  ECM Add(const std::string &nickname = "");
  ECM Modify(const std::string &nickname);
  ECM Delete(const std::string &nickname);
  ECM Delete(const std::vector<std::string> &targets);
  ECM Query(const std::string &targets) const;
  ECM Query(const std::vector<std::string> &targets) const;
  ECM Rename(const std::string &old_nickname, const std::string &new_nickname);
  ECM Src() const;

  ECM SetHostValue(const std::string &nickname, const std::string &attrname,
                   const std::string &value_str);
  [[nodiscard]] ECM Save();

private:
  mutable std::unordered_map<std::string, HostConfig> host_configs = {};
  mutable std::unordered_map<std::string, KnownHostEntry> known_hosts = {};
  [[nodiscard]] ECM PrintHost_(const std::string &nickname,
                               const HostConfig &entry) const;
  ECM PromptAddFields_(const std::string &nickname, HostConfig &entry);
  ECM PromptModifyFields_(const std::string &nickname, HostConfig &entry);
  ECM AddHost_(const std::string &nickname, const HostConfig &entry);
  ECM RemoveHost_(const std::string &nickname);
  AMConfigManager &config_ = AMConfigManager::Instance();
  AMPromptManager &prompt_ = AMPromptManager::Instance();
};
