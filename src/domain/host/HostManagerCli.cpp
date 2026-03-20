#include "domain/host/HostManager.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/enum_related.hpp"
#include <cstdint>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

using cls = AMDomain::host::AMHostConfigManager;
using EC = ErrorCode;

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

/**
 * @brief Deduplicate target nicknames while preserving first-seen order.
 */
std::vector<std::string> DedupTargets_(const std::vector<std::string> &targets) {
  std::vector<std::string> out;
  std::unordered_set<std::string> seen;
  out.reserve(targets.size());
  for (const auto &target : targets) {
    const std::string key = AMStr::Strip(target);
    if (key.empty()) {
      continue;
    }
    if (seen.insert(key).second) {
      out.push_back(key);
    }
  }
  return out;
}

/**
 * @brief Return true when nickname targets local host profile.
 */
bool IsLocalNickname_(const std::string &nickname) {
  return AMStr::lowercase(AMStr::Strip(nickname)) == "local";
}

/**
 * @brief Parse one signed integer from text.
 */
bool ParseInt64_(const std::string &text, int64_t *out) {
  if (!out) {
    return false;
  }
  const std::string trimmed = AMStr::Strip(text);
  if (trimmed.empty()) {
    return false;
  }
  std::istringstream iss(trimmed);
  int64_t value = 0;
  char extra = '\0';
  if (!(iss >> value)) {
    return false;
  }
  if (iss >> extra) {
    return false;
  }
  *out = value;
  return true;
}

/**
 * @brief Parse one boolean from text.
 */
bool ParseBool_(const std::string &text, bool *out) {
  if (!out) {
    return false;
  }
  const std::string lowered = AMStr::lowercase(AMStr::Strip(text));
  if (lowered == "true" || lowered == "1" || lowered == "yes" ||
      lowered == "on") {
    *out = true;
    return true;
  }
  if (lowered == "false" || lowered == "0" || lowered == "no" ||
      lowered == "off") {
    *out = false;
    return true;
  }
  return false;
}

} // namespace

/**
 * @brief Return cached private key list.
 */
std::vector<std::string> cls::PrivateKeys() const {
  (void)EnsureSnapshotLoaded_();
  return private_keys_;
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
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }

  std::vector<std::string> uniq_targets = DedupTargets_(targets);
  if (uniq_targets.empty()) {
    return Ok();
  }

  AMDomain::host::HostConfigArg next = SnapshotFromCache_();
  for (const auto &name : uniq_targets) {
    if (!HostExists(name)) {
      return Err(EC::HostConfigNotFound,
                 AMStr::fmt("host nickname not found: {}", name));
    }
    if (IsLocalNickname_(name)) {
      return Err(EC::OperationUnsupported, "local host cannot be removed");
    }
    if (next.host_configs.erase(name) == 0) {
      return Err(EC::HostConfigNotFound,
                 AMStr::fmt("host nickname not found: {}", name));
    }
  }

  return PersistSnapshot_(next, true);
}

ECM cls::Query(const std::string &nickname) const {
  return Query(SplitTokens_(nickname));
}

ECM cls::Query(const std::vector<std::string> &targets) const {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }
  if (targets.empty()) {
    return Ok();
  }

  std::vector<std::string> uniq_targets = DedupTargets_(targets);
  for (const std::string &nickname : uniq_targets) {
    if (IsLocalNickname_(nickname)) {
      continue;
    }
    if (host_configs_.find(nickname) == host_configs_.end()) {
      return Err(EC::HostConfigNotFound,
                 AMStr::fmt("Host {} not found", nickname));
    }
  }
  return Ok();
}

ECM cls::Rename(const std::string &old_nickname,
                const std::string &new_nickname) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }

  if (old_nickname.empty() || new_nickname.empty()) {
    return Err(EC::InvalidArg, "empty nickname");
  }
  if (old_nickname == new_nickname) {
    return Err(EC::InvalidArg, "new nickname same as old nickname");
  }
  if (IsLocalNickname_(old_nickname)) {
    return Err(EC::OperationUnsupported, "local host cannot be renamed");
  }
  if (!AMDomain::host::HostService::ValidateNickname(new_nickname)) {
    return Err(EC::InvalidArg,
               "invalid new nickname, pattern is [a-zA-Z0-9_-]+");
  }
  if (HostExists(new_nickname)) {
    return Err(EC::KeyAlreadyExists, "new nickname already exists");
  }
  if (!HostExists(old_nickname)) {
    return Err(EC::HostConfigNotFound, "old nickname not found");
  }

  AMDomain::host::HostConfigArg next = SnapshotFromCache_();
  auto old_it = next.host_configs.find(old_nickname);
  if (old_it == next.host_configs.end()) {
    return Err(EC::HostConfigNotFound, "old nickname not found");
  }

  HostConfig moved = old_it->second;
  moved.request.nickname = new_nickname;
  next.host_configs.erase(old_it);
  next.host_configs[new_nickname] = moved;
  return PersistSnapshot_(next, true);
}

ECM cls::Src() const { return Ok(); }

ECM cls::SetHostValue(const std::string &nickname, const std::string &attrname,
                      const std::string &value_str) {
  ECM load_rcm = EnsureSnapshotLoaded_();
  if (!isok(load_rcm)) {
    return load_rcm;
  }

  const std::string field = AMStr::lowercase(attrname);
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty nickname");
  }
  if (!HostExists(nickname)) {
    return Err(EC::HostConfigNotFound, "host not found");
  }

  static const std::vector<std::string> kAllowedFields = {
      "hostname",    "username",   "port",      "buffer_size",
      "compression", "cmd_prefix", "wrap_cmd",  "protocol",
      "password",    "keyfile",    "trash_dir", "login_dir"};
  bool field_validated = false;
  for (const std::string &allowed : kAllowedFields) {
    if (field == allowed) {
      field_validated = true;
      break;
    }
  }
  if (!field_validated) {
    return Err(EC::InvalidArg, "unsupported property name");
  }

  AMDomain::host::HostConfigArg next = SnapshotFromCache_();
  const bool is_local = IsLocalNickname_(nickname);
  HostConfig *target_cfg = nullptr;
  if (is_local) {
    target_cfg = &next.local_config;
  } else {
    auto it = next.host_configs.find(nickname);
    if (it == next.host_configs.end()) {
      return Err(EC::HostConfigNotFound, "host not found");
    }
    target_cfg = &it->second;
  }

  HostConfig &updated = *target_cfg;
  if (field == "hostname") {
    if (value_str.empty()) {
      return Err(EC::InvalidArg, "hostname cannot be empty");
    }
    updated.request.hostname = value_str;
  } else if (field == "username") {
    if (value_str.empty()) {
      return Err(EC::InvalidArg, "username cannot be empty");
    }
    updated.request.username = value_str;
  } else if (field == "port") {
    int64_t port = 0;
    if (!ParseInt64_(value_str, &port) || port <= 0 || port > 65535) {
      return Err(EC::InvalidArg, "invalid port value");
    }
    updated.request.port = static_cast<int>(port);
  } else if (field == "buffer_size") {
    int64_t buffer_size = 0;
    if (!ParseInt64_(value_str, &buffer_size)) {
      return Err(EC::InvalidArg, "Buffer size must be an positive integer");
    }
    if (buffer_size < AMMinBufferSize || buffer_size > AMMaxBufferSize) {
      return Err(EC::InvalidArg,
                 AMStr::fmt("Buffer size must be between {} and {}",
                            AMMinBufferSize, AMMaxBufferSize));
    }
    updated.request.buffer_size = buffer_size;
  } else if (field == "compression") {
    bool compression = false;
    if (!ParseBool_(value_str, &compression)) {
      return Err(EC::InvalidArg, "compression value must be true or false");
    }
    updated.request.compression = compression;
  } else if (field == "cmd_prefix") {
    updated.metadata.cmd_prefix = value_str;
  } else if (field == "wrap_cmd") {
    bool wrap_cmd = false;
    if (!ParseBool_(value_str, &wrap_cmd)) {
      return Err(EC::InvalidArg, "wrap_cmd value must be true or false");
    }
    updated.metadata.wrap_cmd = wrap_cmd;
  } else if (field == "protocol") {
    std::string protocol = AMStr::lowercase(AMStr::Strip(value_str));
    if (protocol != "sftp" && protocol != "ftp" && protocol != "local") {
      return Err(EC::InvalidArg, "protocol must be sftp, ftp or local");
    }
    updated.request.protocol = AMDomain::host::StrToProtocol(protocol);
  } else if (field == "password") {
    std::string tmp_pswd = AMStr::Strip(value_str);
    if (tmp_pswd.empty()) {
      return Err(EC::InvalidArg, "password cannot be empty");
    }
    if (!AMAuth::IsEncrypted(tmp_pswd)) {
      tmp_pswd = AMAuth::EncryptPassword(tmp_pswd);
    }
    updated.request.password = tmp_pswd;
  } else if (field == "keyfile") {
    updated.request.keyfile = value_str;
  } else if (field == "trash_dir") {
    updated.request.trash_dir = value_str;
  } else if (field == "login_dir") {
    updated.metadata.login_dir = value_str;
  } else {
    return Err(EC::InvalidArg,
               AMStr::fmt("unsupported property name: {}", field));
  }

  return PersistSnapshot_(next, true);
}
