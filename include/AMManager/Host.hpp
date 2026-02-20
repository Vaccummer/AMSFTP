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

inline static const std::array<std::string, 10> fileds = {
    configkn::hostname,    configkn::username,  configkn::port,
    configkn::password,    configkn::protocol,  configkn::buffer_size,
    configkn::trash_dir,   configkn::login_dir, configkn::keyfile,
    configkn::compression,
};
} // namespace configkn

struct ClientConfig {
  ECM rcm = Ok();
  ConRequst request = {};
  ClientProtocol protocol = ClientProtocol::SFTP;
  int64_t buffer_size = -1;
  std::string login_dir = "";

  [[nodiscard]] std::unordered_map<std::string, std::string>
  GetStrDict() const {
    return {
        {"hostname", request.hostname},
        {"username", request.username},
        {"port", std::to_string(request.port)},
        {"password", request.password},
        {"protocol", AM_ENUM_NAME(protocol)},
        {"buffer_size", std::to_string(buffer_size)},
        {"trash_dir", request.trash_dir},
        {"login_dir", login_dir},
        {"keyfile", request.keyfile},
        {"compression", request.compression ? "true" : "false"},
    };
  }

  [[nodiscard]] Json GetJson() const {
    Json json = Json::object();
    json[configkn::hostname] = request.hostname;
    json[configkn::username] = request.username;
    json[configkn::port] = request.port;
    json[configkn::password] = request.password;
    json[configkn::protocol] = AMStr::lowercase(AM_ENUM_NAME(protocol));
    json[configkn::buffer_size] = buffer_size;
    json[configkn::trash_dir] = request.trash_dir;
    json[configkn::login_dir] = login_dir;
    json[configkn::keyfile] = request.keyfile;
    json[configkn::compression] = request.compression;
    return json;
  }
  ClientConfig() = default;

  ClientConfig(const std::string &nickname, const Json &jsond) {
    if (!jsond.is_object()) {
      rcm = {EC::InvalidArg, "config is not an object"};
      return;
    }

    if (!configkn::ValidateNickname(nickname)) {
      rcm = {EC::InvalidArg, "invalid nickname"};
      return;
    }

    this->request.nickname = nickname;

    if (!QueryKey(jsond, {configkn::hostname}, &this->request.hostname)) {
      rcm = {EC::InvalidArg, "hostname not found"};
      return;
    }

    if (this->request.hostname.empty()) {
      rcm = {EC::InvalidArg, "hostname is empty"};
      return;
    }

    if (!QueryKey(jsond, {configkn::username}, &this->request.username)) {
      rcm = {EC::InvalidArg, "username not found"};
      return;
    }

    if (this->request.username.empty()) {
      rcm = {EC::InvalidArg, "username is empty"};
      return;
    }

    std::string protocol_str;
    if (!QueryKey(jsond, {configkn::protocol}, &protocol_str)) {
      this->protocol = ClientProtocol::SFTP;
    } else {
      this->protocol = configkn::StrToProtocol(protocol_str);
    }

    int tmp_port = -1;
    QueryKey(jsond, {configkn::port}, &tmp_port);
    if (tmp_port <= 0 || tmp_port > 65535) {
      this->request.port = (this->protocol == ClientProtocol::FTP)
                               ? configkn::DefaultFTPPort
                               : configkn::DefaultSFTPPort;
    } else {
      this->request.port = tmp_port;
    }

    QueryKey(jsond, {configkn::password}, &this->request.password);
    QueryKey(jsond, {configkn::keyfile}, &this->request.keyfile);
    QueryKey(jsond, {configkn::compression}, &this->request.compression);
    QueryKey(jsond, {configkn::trash_dir}, &this->request.trash_dir);
    QueryKey(jsond, {configkn::login_dir}, &this->login_dir);

    int64_t tmp_size = -1;
    QueryKey(jsond, {configkn::buffer_size}, &tmp_size);
    if (tmp_size <= 0) {
      this->buffer_size = AMDefaultRemoteBufferSize;
    } else {
      this->buffer_size = std::min(std::max(tmp_size, static_cast<int64_t>(1)),
                                   static_cast<int64_t>(AMMaxBufferSize));
    }
  };

  [[nodiscard]] bool IsValid() const {
    return request.IsValid() && protocol != ClientProtocol::Unknown;
  }
};

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

  [[nodiscard]] std::pair<ECM, ClientConfig>
  GetClientConfig(const std::string &nickname);
  /**
   * @brief Fetch local client config from storage and fall back to defaults.
   */
  [[nodiscard]] std::pair<ECM, ClientConfig> GetLocalConfig();
  ECM UpsertHost(const ClientConfig &entry, bool dump_now = true);

  [[nodiscard]] ECM FindKnownHost(KnownHostQuery &query) const;
  ECM UpsertKnownHost(const KnownHostQuery &query, bool dump_now = true);

  [[nodiscard]] bool HostExists(const std::string &nickname) const;

  [[nodiscard]] std::vector<std::string> ListNames() const;

  void CollectHosts_() const;

  [[nodiscard]] std::pair<ECM, std::vector<std::string>>
  PrivateKeys(bool print_sign = false) const;
  ECM List(bool detailed = true) const;
  ECM Add();
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
  mutable std::unordered_map<std::string, ClientConfig> host_configs = {};
  mutable std::unordered_map<std::string, KnownHostEntry> known_hosts = {};
  [[nodiscard]] ECM PrintHost_(const std::string &nickname,
                               const ClientConfig &entry) const;
  ECM PromptAddFields_(const std::string &nickname, ClientConfig &entry);
  ECM PromptModifyFields_(const std::string &nickname, ClientConfig &entry);
  ECM AddHost_(const std::string &nickname, const ClientConfig &entry);
  ECM RemoveHost_(const std::string &nickname);
  AMConfigManager &config_ = AMConfigManager::Instance();
  AMPromptManager &prompt_ = AMPromptManager::Instance();
};
