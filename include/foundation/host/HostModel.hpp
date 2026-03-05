#pragma once

#include "foundation/DataClass.hpp"
#include "foundation/Enum.hpp"
#include "foundation/tools/json.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

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
  const static std::unordered_map<std::string, ClientProtocol> protocol_map = {
      {"sftp", ClientProtocol::SFTP},
      {"ftp", ClientProtocol::FTP},
      {"local", ClientProtocol::LOCAL},
  };
  auto it = protocol_map.find(AMStr::lowercase(protocol_str));
  if (it != protocol_map.end()) {
    return it->second;
  }
  return ClientProtocol::SFTP;
}

/**
 * @brief Hostname uniqueness checker callback signature.
 */
using HostnameExistsChecker = std::function<bool(const std::string &)>;

/**
 * @brief Bind hostname uniqueness checker used by validation.
 *
 * Domain validation does not depend on concrete config storage. The checker can
 * be provided by an upper layer when uniqueness validation is needed.
 */
void SetHostnameExistsChecker(HostnameExistsChecker checker);

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

/**
 * @brief Domain model for one host configuration entry.
 */
struct HostConfig {
  ConRequest request = {};
  ClientMetaData metadata = {};

  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  GetStrDict() const {
    auto pairs = request.GetStrDict();
    auto metadata_pairs = metadata.GetStrDict();
    pairs.insert(pairs.end(), metadata_pairs.begin(), metadata_pairs.end());
    return pairs;
  }

  [[nodiscard]] Json GetJson() const {
    Json json = Json::object();
    json[configkn::hostname] = request.hostname;
    json[configkn::username] = request.username;
    json[configkn::port] = request.port;
    json[configkn::password] = request.password;
    json[configkn::protocol] =
        AMStr::lowercase(AMStr::ToString(request.protocol));
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
    request.nickname = nickname;
    AMJson::QueryKey(jsond, {configkn::hostname}, &request.hostname);
    AMJson::QueryKey(jsond, {configkn::username}, &request.username);
    std::string protocol_str;
    AMJson::QueryKey(jsond, {configkn::protocol}, &protocol_str);
    request.protocol = configkn::StrToProtocol(protocol_str);

    int tmp_port = -1;
    AMJson::QueryKey(jsond, {configkn::port}, &tmp_port);
    if (tmp_port <= 0 || tmp_port > 65535) {
      request.port = (request.protocol == ClientProtocol::FTP)
                         ? configkn::DefaultFTPPort
                         : configkn::DefaultSFTPPort;
    } else {
      request.port = tmp_port;
    }

    AMJson::QueryKey(jsond, {configkn::password}, &request.password);
    AMJson::QueryKey(jsond, {configkn::keyfile}, &request.keyfile);
    AMJson::QueryKey(jsond, {configkn::compression}, &request.compression);
    AMJson::QueryKey(jsond, {configkn::trash_dir}, &request.trash_dir);
    AMJson::QueryKey(jsond, {configkn::login_dir}, &metadata.login_dir);
    AMJson::QueryKey(jsond, {configkn::cmd_prefix}, &metadata.cmd_prefix);
    AMJson::QueryKey(jsond, {configkn::wrap_cmd}, &metadata.wrap_cmd);

    int64_t tmp_size = -1;
    AMJson::QueryKey(jsond, {configkn::buffer_size}, &tmp_size);
    if (tmp_size <= 0) {
      request.buffer_size = AMDefaultRemoteBufferSize;
    } else {
      request.buffer_size =
          std::min(std::max(tmp_size, static_cast<int64_t>(1)),
                   static_cast<int64_t>(AMMaxBufferSize));
    }
  }

  [[nodiscard]] bool IsValid(std::string *error_info = nullptr) const {
    if (error_info) {
      error_info->clear();
    }
    if (!request.IsValid(error_info)) {
      return false;
    }
    if (!configkn::ValidateNickname(request.nickname)) {
      if (error_info) {
        *error_info = "nickname contains invalid characters";
      }
      return false;
    }
    return true;
  }
};

/** @brief Backward-compatible alias. Prefer HostConfig. */
using ClientConfig = HostConfig;
