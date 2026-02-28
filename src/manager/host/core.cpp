#include "AMBase/Path.hpp"
#include "AMBase/tools/auth.hpp"
#include "AMBase/tools/json.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Host.hpp"
#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>


namespace {
/**
 * @brief Resolve the local username from environment variables.
 */
std::string GetLocalUsername_() {
  std::string local_user = "";
#ifdef _WIN32
  AMStr::GetEnv("USERNAME", &local_user);
#else
  AMStr::GetEnv("USER", &local_user);
#endif
  if (local_user.empty()) {
    local_user = "local";
  }
  return local_user;
}

/**
 * @brief Return literal candidates for enum-like host attributes.
 */
const std::map<std::string, std::string> &
GetHostAttrLiterals_(configkn::HostAttr attr) {
  static const std::map<std::string, std::string> protocol_literals = {
      {"sftp", "SFTP protocol"},
      {"ftp", "FTP protocol"},
      {"local", "Local protocol"},
  };
  static const std::map<std::string, std::string> compression_literals = {
      {"true", "Enable compression"},
      {"false", "Disable compression"},
  };
  static const std::map<std::string, std::string> empty_literals = {};

  switch (attr) {
  case configkn::HostAttr::Protocol:
    return protocol_literals;
  case configkn::HostAttr::Compression:
    return compression_literals;
  default:
    return empty_literals;
  }
}

/**
 * @brief Prompt one host attribute, routing enum values to LiteralPrompt.
 */
bool PromptHostAttr_(AMPromptManager &prompt_mgr, configkn::HostAttr attr,
                     const std::string &prompt_text,
                     const std::string &placeholder, std::string *out_input,
                     bool allow_empty = true) {
  const auto &literals = GetHostAttrLiterals_(attr);
  if (!literals.empty()) {
    return prompt_mgr.LiteralPrompt(prompt_text, placeholder, out_input,
                                    literals);
  }

  std::function<bool(const std::string &)> checker = {};
  std::vector<std::string> candidates = {};

  auto add_candidate = [&candidates](const std::string &item) {
    if (item.empty()) {
      return;
    }
    for (const auto &existing : candidates) {
      if (existing == item) {
        return;
      }
    }
    candidates.push_back(item);
  };

  switch (attr) {
  case configkn::HostAttr::Nickname:
    checker = [allow_empty](const std::string &text) {
      const std::string v = AMStr::Strip(text);
      if (v.empty()) {
        return allow_empty;
      }
      if (!configkn::ValidateNickname(v)) {
        return false;
      }
      if (AMStr::lowercase(v) == "local") {
        return false;
      }
      return !AMHostManager::Instance().HostExists(v);
    };
    break;
  case configkn::HostAttr::Hostname:
    checker = [allow_empty](const std::string &text) {
      const std::string v = AMStr::Strip(text);
      return allow_empty ? true : !v.empty();
    };
    add_candidate("localhost");
    break;
  case configkn::HostAttr::Username:
    checker = [allow_empty](const std::string &text) {
      const std::string v = AMStr::Strip(text);
      return allow_empty ? true : !v.empty();
    };
    add_candidate(GetLocalUsername_());
    break;
  case configkn::HostAttr::Port:
    checker = [allow_empty](const std::string &text) {
      const std::string v = AMStr::Strip(text);
      if (v.empty()) {
        return allow_empty;
      }
      int64_t parsed = 0;
      return AMJson::StrValueParse(v, &parsed) && parsed > 0 && parsed <= 65535;
    };
    add_candidate(placeholder);
    add_candidate(std::to_string(configkn::DefaultSFTPPort));
    add_candidate(std::to_string(configkn::DefaultFTPPort));
    break;
  case configkn::HostAttr::BufferSize:
    checker = [allow_empty](const std::string &text) {
      const std::string v = AMStr::Strip(text);
      if (v.empty()) {
        return allow_empty;
      }
      int64_t parsed = 0;
      if (!AMJson::StrValueParse(v, &parsed)) {
        return false;
      }
      return parsed >= AMMinBufferSize && parsed <= AMMaxBufferSize;
    };
    add_candidate(placeholder);
    add_candidate(std::to_string(AMMinBufferSize));
    add_candidate(std::to_string(AMMaxBufferSize));
    break;
  case configkn::HostAttr::Keyfile:
    checker = [allow_empty](const std::string &text) {
      const std::string v = AMStr::Strip(text);
      if (v.empty()) {
        return allow_empty;
      }
      auto [rcm, info] = AMFS::stat(v, false);
      return isok(rcm) && info.type == PathType::FILE;
    };
    break;
  case configkn::HostAttr::TrashDir:
  case configkn::HostAttr::LoginDir:
  case configkn::HostAttr::Password:
    checker = {};
    break;
  default:
    checker = {};
    break;
  }

  return prompt_mgr.Prompt(prompt_text, placeholder, out_input, checker,
                           candidates);
}

/**
 * @brief Return protocol-based default port.
 */
int DefaultPortForProtocol_(ClientProtocol protocol) {
  if (protocol == ClientProtocol::FTP) {
    return configkn::DefaultFTPPort;
  }
  return configkn::DefaultSFTPPort;
}

/**
 * @brief Return whether the input is a local-loopback hostname.
 */
bool IsLocalHostname_(const std::string &hostname) {
  const std::string v = AMStr::lowercase(AMStr::Strip(hostname));
  return v == "localhost" || v == "127.0.0.1" || v == "::1";
}

/**
 * @brief Return whether one hostname already exists in configured host entries.
 */
bool HostnameExistsInConfig_(const std::string &hostname) {
  Json hosts_json;
  AMConfigManager &config = AMConfigManager::Instance();
  if (!config.ResolveArg(DocumentKind::Config, {configkn::hosts},
                         &hosts_json) ||
      !hosts_json.is_object()) {
    return false;
  }

  const std::string target = AMStr::lowercase(AMStr::Strip(hostname));
  for (auto it = hosts_json.begin(); it != hosts_json.end(); ++it) {
    if (!it.value().is_object()) {
      continue;
    }
    std::string existing_hostname;
    AMJson::QueryKey(it.value(), {configkn::hostname}, &existing_hostname);
    if (AMStr::lowercase(AMStr::Strip(existing_hostname)) == target) {
      return true;
    }
  }
  return false;
}
} // namespace

namespace configkn {
/**
 * @brief Validate one host attribute value.
 */
bool ValidateHostAttrValue(HostAttr attr, const std::string &value,
                           std::string *normalized, std::string *error_msg,
                           bool allow_exists_hostname,
                           bool allow_local_hostname, EC *code) {
  auto fail = [&error_msg, &code](EC ec, const std::string &msg) -> bool {
    if (code) {
      *code = ec;
    }
    if (error_msg) {
      *error_msg = msg;
    }
    return false;
  };

  auto set_norm = [&normalized](const std::string &v) {
    if (normalized) {
      *normalized = v;
    }
  };

  if (code) {
    *code = EC::Success;
  }

  switch (attr) {
  case HostAttr::Nickname: {
    const std::string v = AMStr::Strip(value);
    if (!ValidateNickname(v)) {
      return fail(EC::InvalidArg, "Nickname must match \\[A-Za-z0-9_-]+");
    }
    set_norm(v);
    return true;
  }
  case HostAttr::Hostname: {
    const std::string v = AMStr::Strip(value);
    if (v.empty()) {
      return fail(EC::InvalidArg, "Hostname cannot be empty");
    }
    if (!allow_local_hostname && IsLocalHostname_(v)) {
      return fail(EC::InvalidArg, "Local hostname is not allowed");
    }
    if (!allow_exists_hostname && HostnameExistsInConfig_(v)) {
      return fail(EC::KeyAlreadyExists, "Hostname already exists");
    }
    set_norm(v);
    return true;
  }
  case HostAttr::Username: {
    const std::string v = AMStr::Strip(value);
    if (v.empty()) {
      return fail(EC::InvalidArg, "Username cannot be empty");
    }
    set_norm(v);
    return true;
  }
  case HostAttr::Port: {
    const std::string v = AMStr::Strip(value);
    int64_t parsed = 0;
    if (!AMJson::StrValueParse(v, &parsed) || parsed <= 0 || parsed > 65535) {
      return fail(EC::InvalidArg,
                  "Port must be an integer between 1 and 65535");
    }
    set_norm(std::to_string(parsed));
    return true;
  }
  case HostAttr::Protocol: {
    const std::string v = AMStr::lowercase(AMStr::Strip(value));
    if (v == "sftp" || v == "ftp" || v == "local") {
      set_norm(v);
      return true;
    }
    return fail(EC::InvalidArg, "Protocol must be sftp, ftp, or local");
  }
  case HostAttr::BufferSize: {
    const std::string v = AMStr::Strip(value);
    int64_t parsed = 0;
    if (!AMJson::StrValueParse(v, &parsed) || parsed <= 0) {
      return fail(EC::InvalidArg, "Buffer size must be a positive integer");
    }
    set_norm(std::to_string(parsed));
    return true;
  }
  case HostAttr::Compression: {
    const std::string v = AMStr::Strip(value);
    bool parsed = false;
    if (!AMJson::StrValueParse(v, &parsed)) {
      return fail(EC::InvalidArg, "Compression must be true or false");
    }
    set_norm(parsed ? "true" : "false");
    return true;
  }
  case HostAttr::CmdPrefix:
    set_norm(value);
    return true;
  case HostAttr::WrapCmd: {
    const std::string v = AMStr::Strip(value);
    bool parsed = false;
    if (!AMJson::StrValueParse(v, &parsed)) {
      return fail(EC::InvalidArg, "wrap_cmd must be true or false");
    }
    set_norm(parsed ? "true" : "false");
    return true;
  }
  case HostAttr::Password:
  case HostAttr::TrashDir:
  case HostAttr::LoginDir:
  case HostAttr::Keyfile:
    set_norm(value);
    return true;
  default:
    return fail(EC::InvalidArg, "unsupported host attribute");
  }
}
} // namespace configkn

ECM AMHostManager::Save() {
  return config_.Dump(DocumentKind::Config, "", true);
}

void AMHostManager::CollectHosts_() const {
  host_configs.clear();
  Json hosts_json;
  if (!config_.ResolveArg(DocumentKind::Config, {configkn::hosts},
                          &hosts_json)) {
    return;
  }
  if (!hosts_json.is_object()) {
    return;
  }
  for (auto it = hosts_json.begin(); it != hosts_json.end(); ++it) {
    const std::string nickname = it.key();
    const std::string lowered = AMStr::lowercase(AMStr::Strip(nickname));
    const bool is_local = (lowered == "local");
    const std::string key = is_local ? "local" : nickname;
    auto cfg = HostConfig(nickname, it.value());
    if (is_local) {
      if (cfg.IsValid()) {
        cfg.request.username = GetLocalUsername_();
        host_configs[key] = cfg;
      } else {
        // Exempt local profile from strict host-json completeness checks:
        // synthesize a valid local config with runtime defaults.
        auto [rcm, local_cfg] =
            const_cast<AMHostManager *>(this)->GetLocalConfig();
        if (rcm.first == EC::Success && local_cfg.IsValid()) {
          host_configs[key] = local_cfg;
        }
      }
      continue;
    }
    if (cfg.IsValid()) {
      host_configs[key] = cfg;
    }
  }
}

std::pair<ECM, HostConfig>
AMHostManager::GetClientConfig(const std::string &nickname) {
  if (!HostExists(nickname)) {
    return {Err(EC::HostConfigNotFound,
                AMStr::fmt("host config not found: {}", nickname)),
            {}};
  }
  return {Ok(), host_configs[nickname]};
}

/**
 * @brief Get local client config from config storage or use defaults.
 */
std::pair<ECM, HostConfig> AMHostManager::GetLocalConfig() {
  HostConfig result;

  const std::string local_user = GetLocalUsername_();
  const std::string fallback_home = AMFS::HomePath();

  std::string root_dir = "";
  if (!AMStr::GetEnv("AMSFTP_ROOT", &root_dir) || root_dir.empty()) {
    root_dir = config_.ProjectRoot().string();
  }
  const std::string fallback_trash = AMPathStr::join(root_dir, "trash");

  Json host_json;
  if (config_.ResolveArg(DocumentKind::Config, {configkn::hosts, "local"},
                         &host_json) &&
      host_json.is_object()) {
    HostConfig stored("local", host_json);
    if (stored.IsValid()) {
      result = stored;
    }
  }

  if (result.request.nickname.empty()) {
    result.request.nickname = "local";
  }
  if (result.request.hostname.empty()) {
    result.request.hostname = "localhost";
  }
  if (result.request.username.empty()) {
    result.request.username = local_user;
  }
  if (result.request.port <= 0 || result.request.port > 65535) {
    result.request.port = configkn::DefaultSFTPPort;
  }

  result.request.protocol = ClientProtocol::LOCAL;

  if (result.request.buffer_size <= 0) {
    result.request.buffer_size = 64 * AMMB;
  } else {
    result.request.buffer_size =
        std::min(std::max(result.request.buffer_size,
                          static_cast<int64_t>(AMMinBufferSize)),
                 static_cast<int64_t>(AMMaxBufferSize));
  }

  if (result.metadata.login_dir.empty()) {
    result.metadata.login_dir = fallback_home;
  }
  if (result.request.trash_dir.empty()) {
    result.request.trash_dir = fallback_trash;
  }

  return {Ok(), result};
}

ECM AMHostManager::UpsertHost(const HostConfig &entry, bool dump_now) {
  if (!entry.IsValid()) {
    return Err(EC::InvalidArg, "invalid host config");
  }
  if (!configkn::ValidateNickname(entry.request.nickname)) {
    return Err(EC::InvalidArg, "invalid nickname");
  }
  ECM rcm = AddHost_(entry.request.nickname, entry);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (!dump_now) {
    return Ok();
  }
  return config_.Dump(DocumentKind::Config, "", true);
}

ECM AMHostManager::FindKnownHost(KnownHostQuery &query) const {
  if (!query.IsValid()) {
    return ECM{EC::InvalidArg, "invalid query args"};
  }
  std::string fingerprint = "";
  if (!config_.ResolveArg(DocumentKind::KnownHosts, query.GetPath(),
                          &fingerprint)) {
    return ECM{EC::HostConfigNotFound,
               "fingerprint not found for given host query"};
  }
  if (fingerprint.empty()) {
    return ECM{EC::InvalidArg, "fingerprint is found but empty"};
  }
  query.SetFingerprint(fingerprint);
  return Ok();
}

ECM AMHostManager::UpsertKnownHost(const KnownHostQuery &query, bool dump_now) {
  if (!query.IsValid()) {
    return Err(EC::InvalidArg, "invalid known-host query");
  }
  const std::string fingerprint = AMStr::Strip(query.GetFingerprint());
  if (fingerprint.empty()) {
    return Err(EC::InvalidArg, "empty fingerprint");
  }
  if (!config_.SetArg(DocumentKind::KnownHosts, query.GetPath(), fingerprint)) {
    return Err(EC::CommonFailure, "failed to write known_hosts data");
  }
  if (!dump_now) {
    return Ok();
  }
  return config_.Dump(DocumentKind::KnownHosts, "", true);
}

bool AMHostManager::HostExists(const std::string &nickname) const {
  if (nickname.empty()) {
    return false;
  }
  return host_configs.find(nickname) != host_configs.end();
}

std::vector<std::string> AMHostManager::ListNames() const {
  std::vector<std::string> names;
  names.reserve(host_configs.size());
  for (const auto &pair : host_configs) {
    names.push_back(pair.first);
  }
  std::sort(names.begin(), names.end());
  return names;
}

ECM AMHostManager::PromptAddFields_(const std::string &nickname,
                                    HostConfig &entry) {
  entry = HostConfig{};
  auto print_abort = [this]() {
    prompt_.Print(AMStr::fmt("{}\n", config_.Format("Input Abort", "abort")));
  };

  entry.request.nickname = nickname;
  const std::string default_protocol_placeholder = "sftp";
  const std::string default_buffer_placeholder = std::to_string(24 * AMMB);

  while (entry.request.nickname.empty()) {
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Nickname,
                         "Nickname: ", "", &entry.request.nickname, false)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Nickname,
                                         entry.request.nickname, &normalized,
                                         &err_msg, true, true, &err_code)) {
      if (!AMStr::Strip(entry.request.nickname).empty()) {
        prompt_.ErrorFormat(ECM{err_code, err_msg});
      }
      entry.request.nickname.clear();
      continue;
    }
    if (AMStr::lowercase(normalized) == "local") {
      prompt_.ErrorFormat(ECM{EC::InvalidArg, "Nickname 'local' is reserved"});
      entry.request.nickname.clear();
      continue;
    }
    entry.request.nickname = normalized;
  }
  {
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Nickname,
                                         entry.request.nickname, &normalized,
                                         &err_msg, true, true, &err_code)) {
      return Err(err_code, err_msg);
    }
    entry.request.nickname = normalized;
  }
  if (AMStr::lowercase(entry.request.nickname) == "local") {
    return Err(EC::InvalidArg, "Nickname 'local' is reserved");
  }
  if (HostExists(entry.request.nickname)) {
    return Err(EC::InvalidArg, "Nickname already exists");
  }

  while (true) {
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Hostname,
                         "Hostname: ", "", &entry.request.hostname, false)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Hostname,
                                        entry.request.hostname, &normalized,
                                        &err_msg, true, true, &err_code)) {
      entry.request.hostname = normalized;
      break;
    }
    prompt_.ErrorFormat(ECM{err_code, err_msg});
  }

  while (true) {
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Username,
                         "Username: ", "", &entry.request.username, false)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Username,
                                        entry.request.username, &normalized,
                                        &err_msg, true, true, &err_code)) {
      entry.request.username = normalized;
      break;
    }
    prompt_.ErrorFormat(ECM{err_code, err_msg});
  }

  std::string protocol = default_protocol_placeholder;
  while (true) {
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Protocol, "Protocol: ",
                         default_protocol_placeholder, &protocol)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Protocol, protocol,
                                        &normalized, &err_msg, true, true,
                                        &err_code)) {
      entry.request.protocol = configkn::StrToProtocol(normalized);
      break;
    }
    prompt_.ErrorFormat(ECM{err_code, err_msg});
  }

  const int protocol_default_port =
      DefaultPortForProtocol_(entry.request.protocol);
  const std::string default_port_for_protocol =
      std::to_string(protocol_default_port);
  std::string port_input;
  entry.request.port = protocol_default_port;
  while (true) {
    const std::string port_prompt =
        AMStr::fmt("port(default {}): ", protocol_default_port);
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Port, port_prompt,
                         default_port_for_protocol, &port_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    port_input = AMStr::Strip(port_input);
    if (port_input.empty()) {
      break;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Port, port_input,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      prompt_.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    int parsed_port = protocol_default_port;
    AMJson::StrValueParse(normalized, &parsed_port);
    entry.request.port = parsed_port;
    break;
  }

  std::string password;
  while (true) {
    std::string first;
    std::string second;
    if (!prompt_.SecurePrompt("password(optional): ", &first)) {
      return Err(EC::ConfigCanceled, "password input canceled");
    }
    if (!prompt_.SecurePrompt("confirm password: ", &second)) {
      AMAuth::SecureZero(first);
      return Err(EC::ConfigCanceled, "password input canceled");
    }
    if (first == second) {
      password = std::move(first);
      AMAuth::SecureZero(second);
      break;
    }
    AMAuth::SecureZero(first);
    AMAuth::SecureZero(second);
    prompt_.ErrorFormat(ECM{EC::InvalidArg, "Passwords do not match"});
  }
  entry.request.password = AMAuth::EncryptPassword(password);
  AMAuth::SecureZero(password);

  std::string buffer_input;
  entry.request.buffer_size = 24 * AMMB;
  while (true) {
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::BufferSize,
                         "Buffer size: ", default_buffer_placeholder,
                         &buffer_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    buffer_input = AMStr::Strip(buffer_input);
    if (buffer_input.empty()) {
      break;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::BufferSize,
                                         buffer_input, &normalized, &err_msg,
                                         true, true, &err_code)) {
      prompt_.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    int64_t parsed_buffer = entry.request.buffer_size;
    AMJson::StrValueParse(normalized, &parsed_buffer);
    if (parsed_buffer < AMMinBufferSize || parsed_buffer > AMMaxBufferSize) {
      prompt_.ErrorFormat(ECM{
          EC::InvalidArg, AMStr::fmt("Buffer size must be between {} and {}",
                                       AMMinBufferSize, AMMaxBufferSize)});
      continue;
    }
    entry.request.buffer_size = parsed_buffer;
    break;
  }

  if (!PromptHostAttr_(prompt_, configkn::HostAttr::TrashDir,
                       "trash_dir(optional): ", entry.request.trash_dir,
                       &entry.request.trash_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }
  if (!PromptHostAttr_(prompt_, configkn::HostAttr::LoginDir,
                       "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }
  while (true) {
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Keyfile,
                         "keyfile(optional): ", entry.request.keyfile,
                         &entry.request.keyfile)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    const std::string keyfile = AMStr::Strip(entry.request.keyfile);
    if (keyfile.empty()) {
      entry.request.keyfile.clear();
      break;
    }
    auto [key_rcm, key_info] = AMFS::stat(keyfile, false);
    if (!isok(key_rcm) || key_info.type != PathType::FILE) {
      prompt_.ErrorFormat(
          ECM{EC::InvalidArg, "keyfile must be an existing file path"});
      continue;
    }
    entry.request.keyfile = keyfile;
    break;
  }

  std::string compression_input = entry.request.compression ? "true" : "false";
  while (true) {
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Compression,
                         "compression: ", compression_input,
                         &compression_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Compression,
                                         compression_input, &normalized,
                                         &err_msg, true, true, &err_code)) {
      prompt_.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    bool parsed = false;
    AMJson::StrValueParse(normalized, &parsed);
    entry.request.compression = parsed;
    break;
  }
  return Ok();
}

ECM AMHostManager::PromptModifyFields_(const std::string &nickname,
                                       HostConfig &entry) {
  (void)nickname;
  static auto print_abort = [this]() {
    prompt_.Print(AMStr::fmt("{}\n", config_.Format("Input Abort", "abort")));
  };

  std::string hostname = entry.request.hostname;
  if (!PromptHostAttr_(prompt_, configkn::HostAttr::Hostname,
                       "Hostname: ", hostname, &hostname)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  if (AMStr::Strip(hostname).empty()) {
    hostname = entry.request.hostname;
  }
  {
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Hostname, hostname,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      return Err(err_code, err_msg);
    }
    hostname = normalized;
  }

  std::string username = entry.request.username;
  if (!PromptHostAttr_(prompt_, configkn::HostAttr::Username,
                       "Username: ", username, &username)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  if (AMStr::Strip(username).empty()) {
    username = entry.request.username;
  }
  {
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Username, username,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      return Err(err_code, err_msg);
    }
    username = normalized;
  }

  std::string protocol = AMStr::lowercase(AMStr::ToString(entry.request.protocol));

  while (true) {
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Protocol,
                         "Protocol: ", protocol, &protocol)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Protocol, protocol,
                                        &normalized, &err_msg, true, true,
                                        &err_code)) {
      protocol = normalized;
      break;
    }
    prompt_.ErrorFormat(ECM{err_code, err_msg});
  }

  const int protocol_default_port =
      DefaultPortForProtocol_(configkn::StrToProtocol(protocol));
  int port = protocol_default_port;
  const std::string default_port_for_protocol =
      std::to_string(protocol_default_port);
  while (true) {
    std::string port_input = default_port_for_protocol;
    const std::string port_prompt =
        AMStr::fmt("port(default {}): ", protocol_default_port);
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Port, port_prompt,
                         default_port_for_protocol, &port_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    port_input = AMStr::Strip(port_input);
    if (port_input.empty()) {
      break;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Port, port_input,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      prompt_.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    int parsed_port = protocol_default_port;
    AMJson::StrValueParse(normalized, &parsed_port);
    port = parsed_port;
    break;
  }

  bool canceled = false;
  const bool change_password =
      prompt_.PromptYesNo("Change password? (y/N): ", &canceled);
  if (canceled) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  if (change_password) {
    while (true) {
      std::string first;
      std::string second;
      if (!prompt_.SecurePrompt("password(optional): ", &first)) {
        return Err(EC::ConfigCanceled, "Password entry canceled");
      }
      if (!prompt_.SecurePrompt("confirm password: ", &second)) {
        AMAuth::SecureZero(first);
        return Err(EC::ConfigCanceled, "Password entry canceled");
      }
      if (first == second) {
        entry.request.password = AMAuth::EncryptPassword(first);
        AMAuth::SecureZero(first);
        AMAuth::SecureZero(second);
        break;
      }
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      prompt_.ErrorFormat(
          ECM{EC::InvalidArg, "Passwords do not match. Please try again."});
    }
  }

  int64_t buffer_size =
      entry.request.buffer_size > 0 ? entry.request.buffer_size : 24 * AMMB;
  while (true) {
    std::string buffer_input = std::to_string(buffer_size);
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::BufferSize,
                         "Buffer size: ", buffer_input, &buffer_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    buffer_input = AMStr::Strip(buffer_input);
    if (buffer_input.empty()) {
      break;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::BufferSize,
                                         buffer_input, &normalized, &err_msg,
                                         true, true, &err_code)) {
      prompt_.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    int64_t parsed_buffer = buffer_size;
    AMJson::StrValueParse(normalized, &parsed_buffer);
    buffer_size = parsed_buffer;
    break;
  }

  std::string trash_dir = entry.request.trash_dir;
  if (!PromptHostAttr_(prompt_, configkn::HostAttr::TrashDir,
                       "trash_dir(optional): ", trash_dir, &trash_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string login_dir = entry.metadata.login_dir;
  if (!PromptHostAttr_(prompt_, configkn::HostAttr::LoginDir,
                       "login_dir(optional): ", login_dir, &login_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string keyfile = entry.request.keyfile;
  if (!PromptHostAttr_(prompt_, configkn::HostAttr::Keyfile,
                       "keyfile(optional): ", keyfile, &keyfile)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  bool compression = entry.request.compression;
  while (true) {
    std::string compression_input = compression ? "true" : "false";
    if (!PromptHostAttr_(prompt_, configkn::HostAttr::Compression,
                         "Compression (true/false): ", compression_input,
                         &compression_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Compression,
                                         compression_input, &normalized,
                                         &err_msg, true, true, &err_code)) {
      prompt_.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    if (AMJson::StrValueParse(normalized, &compression)) {
      break;
    }
    prompt_.ErrorFormat(
        ECM{EC::InvalidArg, "Compression must be true or false"});
  }

  entry.request.hostname = hostname;
  entry.request.username = username;
  entry.request.port = port;
  entry.request.protocol = configkn::StrToProtocol(protocol);
  entry.request.buffer_size = buffer_size;
  entry.request.trash_dir = trash_dir;
  entry.metadata.login_dir = login_dir;
  entry.request.keyfile = keyfile;
  entry.request.compression = compression;
  return Ok();
}

ECM AMHostManager::PrintHost_(const std::string &nickname,
                              const HostConfig &entry) const {
  prompt_.Print("[!pre][" + nickname + "][/pre]");
  size_t width = 0;
  for (const auto &field : configkn::fileds)
    width = std::max(width, field.size());

  auto dict_f = entry.GetStrDict();

  for (const auto &field : configkn::fileds) {
    auto it = dict_f.find(field);
    if (it == dict_f.end())
      continue;
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field << " :   "
         << (it->second.empty() ? "\"\"" : it->second);
    prompt_.Print(line.str());
  }
  return Ok();
}

ECM AMHostManager::AddHost_(const std::string &nickname,
                            const HostConfig &entry) {
  host_configs[nickname] = entry;
  auto json_entry = entry.GetJson();
  if (!config_.SetArg(DocumentKind::Config, {configkn::hosts, nickname},
                      json_entry)) {
    return Err(EC::CommonFailure, "failed to set config in memory data");
  }
  return Ok();
}

ECM AMHostManager::RemoveHost_(const std::string &nickname) {
  CollectHosts_();
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host name");
  }
  if (host_configs.erase(nickname) == 0) {
    return Err(EC::HostConfigNotFound, "host config not found");
  }
  if (!config_.DelArg(DocumentKind::Config, {configkn::hosts, nickname})) {
    return Err(EC::CommonFailure, "failed to remove config in memory data");
  }
  return Ok();
}


