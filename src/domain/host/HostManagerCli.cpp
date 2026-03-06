#include "domain/host/HostManager.hpp"
#include "interface/ApplicationAdapters.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/json.hpp"
#include <sstream>
#include <string>
#include <vector>

using cls = AMDomain::host::AMHostManager;

namespace {
/**
 * @brief Split one whitespace-delimited token string.
 */
std::vector<std::string> SplitTokens_(const std::string &text) {
  std::istringstream iss(text);
  std::vector<std::string> out;
  std::string token;
  while (iss >> token) {
    if (!token.empty()) {
      out.push_back(token);
    }
  }
  return out;
}
} // namespace

std::pair<ECM, std::vector<std::string>> cls::PrivateKeys(bool print_sign) const {
  (void)print_sign;
  std::vector<std::string> keys = {};
  if (!AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
           .ResolveArg(DocumentKind::Config, {configkn::keys}, &keys)) {
    return {Err(EC::CommonFailure,
                AMStr::fmt("Fail to read config attribute: {}", configkn::keys)),
            {}};
  }
  return {Ok(), keys};
}

ECM cls::List(bool detailed) const {
  (void)detailed;
  return Ok();
}

ECM cls::Delete(const std::string &nickname) {
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host name");
  }
  return Delete(SplitTokens_(nickname));
}

ECM cls::Delete(const std::vector<std::string> &targets) {
  std::vector<std::string> uniq_targets = AMJson::VectorDedup(targets);
  if (uniq_targets.empty()) {
    return Ok();
  }

  for (const auto &name : uniq_targets) {
    if (!HostExists(name)) {
      return Err(EC::HostConfigNotFound,
                 AMStr::fmt("host nickname not found: {}", name));
    }
  }

  for (const auto &name : uniq_targets) {
    ECM rcm = RemoveHost_(name);
    if (rcm.first != EC::Success) {
      return rcm;
    }
  }

  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
      DocumentKind::Config, "", true);
}

ECM cls::Query(const std::string &nickname) const {
  return Query(SplitTokens_(nickname));
}

ECM cls::Query(const std::vector<std::string> &targets) const {
  if (targets.empty()) {
    return Ok();
  }

  std::vector<std::string> uniq_targets = AMJson::VectorDedup(targets);
  for (const std::string &nickname : uniq_targets) {
    if (host_configs.find(nickname) == host_configs.end()) {
      return Err(EC::HostConfigNotFound,
                 AMStr::fmt("Host {} not found", nickname));
    }
  }
  return Ok();
}

ECM cls::Rename(const std::string &old_nickname,
                const std::string &new_nickname) {
  if (old_nickname.empty() || new_nickname.empty()) {
    return Err(EC::InvalidArg, "empty nickname");
  }
  if (old_nickname == new_nickname) {
    return Err(EC::InvalidArg, "new nickname same as old nickname");
  }
  if (!configkn::ValidateNickname(new_nickname)) {
    return Err(EC::InvalidArg,
               "invalid new nickname, pattern is [a-zA-Z0-9_-]+");
  }
  if (HostExists(new_nickname)) {
    return Err(EC::KeyAlreadyExists, "new nickname already exists");
  }
  if (!HostExists(old_nickname)) {
    return Err(EC::HostConfigNotFound, "old nickname not found");
  }

  HostConfig moved = host_configs[old_nickname];
  moved.request.nickname = new_nickname;

  host_configs[new_nickname] = moved;
  ECM rcm = AddHost_(new_nickname, moved);
  if (rcm.first != EC::Success) {
    host_configs.erase(new_nickname);
    return rcm;
  }

  host_configs.erase(old_nickname);
  rcm = RemoveHost_(old_nickname);
  return rcm;
}

ECM cls::Src() const { return Ok(); }

ECM cls::SetHostValue(const std::string &nickname, const std::string &attrname,
                      const std::string &value_str) {
  const std::string field = AMStr::lowercase(attrname);
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty nickname");
  }
  if (!HostExists(nickname)) {
    return Err(EC::HostConfigNotFound, "host not found");
  }

  bool field_validated = false;
  for (const std::string &allowed : configkn::fileds) {
    if (field == allowed) {
      field_validated = true;
      break;
    }
  }
  if (!field_validated) {
    return Err(EC::InvalidArg, "unsupported property name");
  }

  HostConfig &updated = host_configs[nickname];
  std::string new_value = "";
  if (field == configkn::hostname) {
    if (value_str.empty()) {
      return Err(EC::InvalidArg, "hostname cannot be empty");
    }
    updated.request.hostname = value_str;
    new_value = value_str;
  } else if (field == configkn::username) {
    if (value_str.empty()) {
      return Err(EC::InvalidArg, "username cannot be empty");
    }
    updated.request.username = value_str;
    new_value = value_str;
  } else if (field == configkn::port) {
    int64_t port = 0;
    if (!AMJson::StrValueParse(value_str, &port) || port <= 0 ||
        port > 65535) {
      return Err(EC::InvalidArg, "invalid port value");
    }
    updated.request.port = static_cast<int>(port);
    new_value = std::to_string(port);
  } else if (field == configkn::buffer_size) {
    int64_t buffer_size = 0;
    if (!AMJson::StrValueParse(value_str, &buffer_size)) {
      return Err(EC::InvalidArg, "Buffer size must be an positive integer");
    }
    if (buffer_size < AMMinBufferSize || buffer_size > AMMaxBufferSize) {
      return Err(EC::InvalidArg,
                 AMStr::fmt("Buffer size must be between {} and {}",
                            AMMinBufferSize, AMMaxBufferSize));
    }
    updated.request.buffer_size = buffer_size;
    new_value = std::to_string(buffer_size);
  } else if (field == configkn::compression) {
    bool compression = false;
    if (!AMJson::StrValueParse(value_str, &compression)) {
      return Err(EC::InvalidArg,
                 "compression value must be true or false");
    }
    updated.request.compression = compression;
    new_value = compression ? "true" : "false";
  } else if (field == configkn::cmd_prefix) {
    updated.metadata.cmd_prefix = value_str;
    new_value = value_str;
  } else if (field == configkn::wrap_cmd) {
    bool wrap_cmd = false;
    if (!AMJson::StrValueParse(value_str, &wrap_cmd)) {
      return Err(EC::InvalidArg, "wrap_cmd value must be true or false");
    }
    updated.metadata.wrap_cmd = wrap_cmd;
    new_value = wrap_cmd ? "true" : "false";
  } else if (field == configkn::protocol) {
    std::string protocol = AMStr::lowercase(AMStr::Strip(value_str));
    if (protocol != "sftp" && protocol != "ftp" && protocol != "local") {
      return Err(EC::InvalidArg, "protocol must be sftp, ftp or local");
    }
    updated.request.protocol = configkn::StrToProtocol(protocol);
    new_value = protocol;
  } else if (field == configkn::password) {
    std::string tmp_pswd = AMStr::Strip(value_str);
    if (tmp_pswd.empty()) {
      return Err(EC::InvalidArg, "password cannot be empty");
    }
    if (!AMAuth::IsEncrypted(tmp_pswd)) {
      tmp_pswd = AMAuth::EncryptPassword(tmp_pswd);
    }
    updated.request.password = tmp_pswd;
    new_value = tmp_pswd;
  } else if (field == configkn::keyfile) {
    updated.request.keyfile = value_str;
    new_value = value_str;
  } else if (field == configkn::trash_dir) {
    updated.request.trash_dir = value_str;
    new_value = value_str;
  } else if (field == configkn::login_dir) {
    updated.metadata.login_dir = value_str;
    new_value = value_str;
  } else {
    return Err(EC::InvalidArg,
               AMStr::fmt("unsupported property name: {}", field));
  }

  bool write_ok = false;
  if (field == configkn::port) {
    write_ok = AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
                   .SetArg(DocumentKind::Config,
                           {configkn::hosts, nickname, field},
                           static_cast<int64_t>(updated.request.port));
  } else if (field == configkn::buffer_size) {
    write_ok = AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
                   .SetArg(DocumentKind::Config,
                           {configkn::hosts, nickname, field},
                           static_cast<int64_t>(updated.request.buffer_size));
  } else if (field == configkn::compression) {
    write_ok = AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
                   .SetArg(DocumentKind::Config,
                           {configkn::hosts, nickname, field},
                           updated.request.compression);
  } else if (field == configkn::wrap_cmd) {
    write_ok = AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
                   .SetArg(DocumentKind::Config,
                           {configkn::hosts, nickname, field},
                           updated.metadata.wrap_cmd);
  } else {
    write_ok = AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow()
                   .SetArg(DocumentKind::Config,
                           {configkn::hosts, nickname, field}, new_value);
  }

  if (!write_ok) {
    return Err(EC::CommonFailure, "failed to write config");
  }

  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().Dump(
      DocumentKind::Config, "", true);
}
