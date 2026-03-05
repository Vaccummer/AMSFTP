#include "foundation/Path.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/json.hpp"
#include "domain/host/HostDomainService.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Host.hpp"
#include "interface/Prompt.hpp"
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
 * @brief Return shared host domain service instance.
 */
AMDomain::host::HostDomainService &HostDomainService_() {
  static AMDomain::host::HostDomainService service;
  return service;
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
 * @brief Return protocol-based default username.
 */
std::string DefaultUsernameForProtocol_(ClientProtocol protocol) {
  if (protocol == ClientProtocol::FTP) {
    return "anonymous";
  }
  return GetLocalUsername_();
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

/**
 * @brief Bind manager-side hostname existence checker into domain validator.
 */
const bool kBindHostnameExistsChecker_ = []() {
  configkn::SetHostnameExistsChecker(HostnameExistsInConfig_);
  return true;
}();
} // namespace

ECM AMHostManager::Save() {
  return AMConfigManager::Instance().Dump(DocumentKind::Config, "", true);
}

void AMHostManager::CollectHosts_() const {
  Json hosts_json;
  if (!AMConfigManager::Instance().ResolveArg(DocumentKind::Config, {configkn::hosts},
                          &hosts_json)) {
    host_configs.clear();
    return;
  }

  HostConfig local_fallback;
  auto [local_rcm, local_cfg] = const_cast<AMHostManager *>(this)->GetLocalConfig();
  if (local_rcm.first == EC::Success && local_cfg.IsValid()) {
    local_fallback = local_cfg;
  }

  host_configs = HostDomainService_().CollectHosts(hosts_json, local_fallback,
                                                   GetLocalUsername_());
}

std::pair<ECM, HostConfig>
AMHostManager::GetClientConfig(const std::string &nickname) {
  return HostDomainService_().GetClientConfig(host_configs, nickname);
}

/**
 * @brief Get local client config from config storage or use defaults.
 */
std::pair<ECM, HostConfig> AMHostManager::GetLocalConfig() {
  const std::string local_user = GetLocalUsername_();
  const std::string fallback_home = AMFS::HomePath();

  std::string root_dir = "";
  if (!AMStr::GetEnv("AMSFTP_ROOT", &root_dir) || root_dir.empty()) {
    root_dir = AMConfigManager::Instance().ProjectRoot().string();
  }
  const std::string fallback_trash = AMPathStr::join(root_dir, "trash");

  Json host_json;
  Json *local_ptr = nullptr;
  if (AMConfigManager::Instance().ResolveArg(
          DocumentKind::Config, {configkn::hosts, "local"}, &host_json) &&
      host_json.is_object()) {
    local_ptr = &host_json;
  }

  return HostDomainService_().BuildLocalConfig(local_ptr, local_user,
                                               fallback_home, fallback_trash);
}

ECM AMHostManager::UpsertHost(const HostConfig &entry, bool dump_now) {
  ECM validate_rcm = HostDomainService_().ValidateHostUpsert(entry);
  if (validate_rcm.first != EC::Success) {
    return validate_rcm;
  }
  ECM rcm = AddHost_(entry.request.nickname, entry);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (!dump_now) {
    return Ok();
  }
  return AMConfigManager::Instance().Dump(DocumentKind::Config, "", true);
}

ECM AMHostManager::FindKnownHost(KnownHostQuery &query) const {
  std::string fingerprint = "";
  if (!AMConfigManager::Instance().ResolveArg(DocumentKind::KnownHosts, query.GetPath(),
                          &fingerprint)) {
    return ECM{EC::HostConfigNotFound,
               "fingerprint not found for given host query"};
  }
  return HostDomainService_().ResolveKnownHostQuery(&query, fingerprint);
}

ECM AMHostManager::UpsertKnownHost(const KnownHostQuery &query, bool dump_now) {
  std::string fingerprint;
  ECM validate_rcm =
      HostDomainService_().ValidateKnownHostUpsert(query, &fingerprint);
  if (validate_rcm.first != EC::Success) {
    return validate_rcm;
  }
  if (!AMConfigManager::Instance().SetArg(DocumentKind::KnownHosts, query.GetPath(), fingerprint)) {
    return Err(EC::CommonFailure, "failed to write known_hosts data");
  }
  if (!dump_now) {
    return Ok();
  }
  return AMConfigManager::Instance().Dump(DocumentKind::KnownHosts, "", true);
}

bool AMHostManager::HostExists(const std::string &nickname) const {
  return HostDomainService_().HostExists(host_configs, nickname);
}

std::vector<std::string> AMHostManager::ListNames() const {
  return HostDomainService_().ListNames(host_configs);
}

ECM AMHostManager::PromptAddFields_(const std::string &nickname,
                                    HostConfig &entry) {
  entry = HostConfig{};
  auto print_abort = [this]() {
    AMPromptManager::Instance().FmtPrint("{}\n", AMConfigManager::Instance().Format("Input Abort", "abort"));
  };

  entry.request.nickname = nickname;
  const std::string default_protocol_placeholder = "sftp";
  const std::string default_buffer_placeholder = std::to_string(24 * AMMB);

  while (entry.request.nickname.empty()) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Nickname,
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
        AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      }
      entry.request.nickname.clear();
      continue;
    }
    if (AMStr::lowercase(normalized) == "local") {
      AMPromptManager::Instance().ErrorFormat(ECM{EC::InvalidArg, "Nickname 'local' is reserved"});
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

  std::string protocol_input = default_protocol_placeholder;
  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Protocol, "Protocol: ",
                         default_protocol_placeholder, &protocol_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Protocol, protocol_input,
                                        &normalized, &err_msg, true, true,
                                        &err_code)) {
      entry.request.protocol = configkn::StrToProtocol(normalized);
      break;
    }
    AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
  }

  const bool hostname_required = entry.request.protocol != ClientProtocol::LOCAL;
  const int protocol_default_port =
      DefaultPortForProtocol_(entry.request.protocol);
  const std::string default_port_for_protocol =
      std::to_string(protocol_default_port);
  const std::string default_username_for_protocol =
      DefaultUsernameForProtocol_(entry.request.protocol);

  entry.request.username = default_username_for_protocol;
  entry.request.port = protocol_default_port;

  while (true) {
    std::string hostname_input = entry.request.hostname;
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Hostname,
                         "Hostname: ", hostname_input, &hostname_input, true)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    hostname_input = AMStr::Strip(hostname_input);
    if (hostname_input.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "Hostname cannot be empty"});
      continue;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Hostname,
                                        hostname_input, &normalized,
                                        &err_msg, true, true, &err_code)) {
      entry.request.hostname = normalized;
      break;
    }
    AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
  }

  while (true) {
    std::string username_input = entry.request.username;
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Username,
                         "Username: ", default_username_for_protocol,
                         &username_input, true)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    username_input = AMStr::Strip(username_input);
    if (username_input.empty()) {
      username_input = default_username_for_protocol;
    }
    if (username_input.empty() && hostname_required) {
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "Username cannot be empty"});
      continue;
    }
    if (username_input.empty()) {
      entry.request.username.clear();
      break;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Username,
                                        username_input, &normalized,
                                        &err_msg, true, true, &err_code)) {
      entry.request.username = normalized;
      break;
    }
    AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
  }

  std::string port_input;
  while (true) {
    const std::string port_prompt = AMStr::fmt("Port(default {}): ", protocol_default_port);
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Port, port_prompt,
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
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
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
    if (!AMPromptManager::Instance().SecurePrompt("password(optional): ", &first)) {
      return Err(EC::ConfigCanceled, "password input canceled");
    }
    if (!AMPromptManager::Instance().SecurePrompt("confirm password: ", &second)) {
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
    AMPromptManager::Instance().ErrorFormat(ECM{EC::InvalidArg, "Passwords do not match"});
  }
  entry.request.password = AMAuth::EncryptPassword(password);
  AMAuth::SecureZero(password);

  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Keyfile,
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
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "keyfile must be an existing file path"});
      continue;
    }
    entry.request.keyfile = keyfile;
    break;
  }

  std::string buffer_input;
  entry.request.buffer_size = 24 * AMMB;
  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::BufferSize,
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
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    int64_t parsed_buffer = entry.request.buffer_size;
    AMJson::StrValueParse(normalized, &parsed_buffer);
    if (parsed_buffer < AMMinBufferSize || parsed_buffer > AMMaxBufferSize) {
      AMPromptManager::Instance().ErrorFormat(ECM{
          EC::InvalidArg, AMStr::fmt("Buffer size must be between {} and {}",
                                       AMMinBufferSize, AMMaxBufferSize)});
      continue;
    }
    entry.request.buffer_size = parsed_buffer;
    break;
  }

  std::string compression_input = entry.request.compression ? "true" : "false";
  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Compression,
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
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    bool parsed = false;
    AMJson::StrValueParse(normalized, &parsed);
    entry.request.compression = parsed;
    break;
  }

  if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::TrashDir,
                       "trash_dir(optional): ", entry.request.trash_dir,
                       &entry.request.trash_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }
  if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::LoginDir,
                       "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }
  if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::CmdPrefix,
                       "cmd_prefix(optional): ", entry.metadata.cmd_prefix,
                       &entry.metadata.cmd_prefix)) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }
  std::string wrap_cmd_input = entry.metadata.wrap_cmd ? "true" : "false";
  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::WrapCmd,
                         "wrap_cmd(true/false): ", wrap_cmd_input,
                         &wrap_cmd_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::WrapCmd,
                                         wrap_cmd_input, &normalized,
                                         &err_msg, true, true, &err_code)) {
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    bool parsed = false;
    if (!AMJson::StrValueParse(normalized, &parsed)) {
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "wrap_cmd must be true or false"});
      continue;
    }
    entry.metadata.wrap_cmd = parsed;
    break;
  }
  return Ok();
}

ECM AMHostManager::PromptModifyFields_(const std::string &nickname,
                                       HostConfig &entry) {
  (void)nickname;
  static auto print_abort = [this]() {
    AMPromptManager::Instance().FmtPrint("{}\n", AMConfigManager::Instance().Format("Input Abort", "abort"));
  };

  std::string protocol = AMStr::lowercase(AMStr::ToString(entry.request.protocol));
  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Protocol,
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
    AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
  }

  const ClientProtocol selected_protocol = configkn::StrToProtocol(protocol);
  const bool protocol_changed = selected_protocol != entry.request.protocol;
  const bool hostname_required = selected_protocol != ClientProtocol::LOCAL;
  const std::string protocol_default_username =
      DefaultUsernameForProtocol_(selected_protocol);
  const int protocol_default_port = DefaultPortForProtocol_(selected_protocol);

  std::string hostname = entry.request.hostname;
  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Hostname,
                         "Hostname: ", hostname, &hostname, true)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        break;
      }
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "Hostname cannot be empty"});
      hostname = entry.request.hostname;
      continue;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Hostname, hostname,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      hostname = entry.request.hostname;
      continue;
    }
    hostname = normalized;
    break;
  }

  std::string username = entry.request.username;
  if (protocol_changed || username.empty()) {
    username = protocol_default_username;
  }
  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Username,
                         "Username: ", username, &username, true)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = protocol_default_username;
    }
    if (username.empty() && hostname_required) {
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "Username cannot be empty"});
      continue;
    }
    if (username.empty()) {
      break;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Username, username,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    username = normalized;
    break;
  }

  int port = entry.request.port;
  if (port <= 0 || port > 65535 || protocol_changed) {
    port = protocol_default_port;
  }
  const std::string default_port_for_protocol =
      std::to_string(protocol_default_port);
  while (true) {
    std::string port_input = std::to_string(port);
    const std::string port_prompt =
        AMStr::fmt("Port(default {}): ", protocol_default_port);
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Port, port_prompt,
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
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    int parsed_port = protocol_default_port;
    AMJson::StrValueParse(normalized, &parsed_port);
    port = parsed_port;
    break;
  }

  bool canceled = false;
  const bool change_password =
      AMPromptManager::Instance().PromptYesNo("Change password? (y/N): ", &canceled);
  if (canceled) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  if (change_password) {
    while (true) {
      std::string first;
      std::string second;
      if (!AMPromptManager::Instance().SecurePrompt("password(optional): ", &first)) {
        return Err(EC::ConfigCanceled, "Password entry canceled");
      }
      if (!AMPromptManager::Instance().SecurePrompt("confirm password: ", &second)) {
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
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "Passwords do not match. Please try again."});
    }
  }

  std::string keyfile = entry.request.keyfile;
  while (true) {
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Keyfile,
                         "keyfile(optional): ", keyfile, &keyfile)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    keyfile = AMStr::Strip(keyfile);
    if (keyfile.empty()) {
      break;
    }
    auto [key_rcm, key_info] = AMFS::stat(keyfile, false);
    if (!isok(key_rcm) || key_info.type != PathType::FILE) {
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "keyfile must be an existing file path"});
      continue;
    }
    break;
  }

  int64_t buffer_size =
      entry.request.buffer_size > 0 ? entry.request.buffer_size : 24 * AMMB;
  while (true) {
    std::string buffer_input = std::to_string(buffer_size);
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::BufferSize,
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
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    int64_t parsed_buffer = buffer_size;
    AMJson::StrValueParse(normalized, &parsed_buffer);
    buffer_size = parsed_buffer;
    break;
  }

  bool compression = entry.request.compression;
  while (true) {
    std::string compression_input = compression ? "true" : "false";
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::Compression,
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
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    if (AMJson::StrValueParse(normalized, &compression)) {
      break;
    }
    AMPromptManager::Instance().ErrorFormat(
        ECM{EC::InvalidArg, "Compression must be true or false"});
  }

  std::string trash_dir = entry.request.trash_dir;
  if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::TrashDir,
                       "trash_dir(optional): ", trash_dir, &trash_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string login_dir = entry.metadata.login_dir;
  if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::LoginDir,
                       "login_dir(optional): ", login_dir, &login_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string cmd_prefix = entry.metadata.cmd_prefix;
  if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::CmdPrefix,
                       "cmd_prefix(optional): ", cmd_prefix, &cmd_prefix)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  bool wrap_cmd = entry.metadata.wrap_cmd;
  while (true) {
    std::string wrap_cmd_input = wrap_cmd ? "true" : "false";
    if (!PromptHostAttr_(AMPromptManager::Instance(), configkn::HostAttr::WrapCmd,
                         "wrap_cmd(true/false): ", wrap_cmd_input,
                         &wrap_cmd_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::WrapCmd,
                                         wrap_cmd_input, &normalized,
                                         &err_msg, true, true, &err_code)) {
      AMPromptManager::Instance().ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    if (AMJson::StrValueParse(normalized, &wrap_cmd)) {
      break;
    }
    AMPromptManager::Instance().ErrorFormat(
        ECM{EC::InvalidArg, "wrap_cmd must be true or false"});
  }

  entry.request.hostname = hostname;
  entry.request.username = username;
  entry.request.port = port;
  entry.request.protocol = selected_protocol;
  entry.request.buffer_size = buffer_size;
  entry.request.trash_dir = trash_dir;
  entry.metadata.login_dir = login_dir;
  entry.request.keyfile = keyfile;
  entry.request.compression = compression;
  entry.metadata.cmd_prefix = cmd_prefix;
  entry.metadata.wrap_cmd = wrap_cmd;
  return Ok();
}

ECM AMHostManager::PrintHost_(const std::string &nickname,
                              const HostConfig &entry) const {
  const bool created =
      static_cast<bool>(AMClientManager::Instance().GetClient(nickname));
  const std::string style_key =
      created ? "nickname" : "unestablished_nickname";
  const std::string styled_nickname =
      AMConfigManager::Instance().Format(nickname, style_key);
  AMPromptManager::Instance().Print("[" + styled_nickname + "]");
  const auto dict_f = entry.GetStrDict();
  size_t width = 0;
  for (const auto &field : dict_f) {
    if (field.first == "nickname") {
      continue;
    }
    width = std::max(width, field.first.size());
  }

  for (const auto &field : dict_f) {
    if (field.first == "nickname") {
      continue;
    }
    std::string render_value = field.second;
    if (field.first == "cmd_prefix") {
      render_value = "\"" + render_value + "\"";
    } else if (render_value.empty()) {
      render_value = "\"\"";
    }
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field.first
         << " :   " << render_value;
    AMPromptManager::Instance().Print(line.str());
  }
  return Ok();
}

ECM AMHostManager::AddHost_(const std::string &nickname,
                            const HostConfig &entry) {
  ECM memory_rcm =
      HostDomainService_().UpsertHostInMemory(&host_configs, nickname, entry);
  if (memory_rcm.first != EC::Success) {
    return memory_rcm;
  }
  auto json_entry = entry.GetJson();
  if (!AMConfigManager::Instance().SetArg(DocumentKind::Config, {configkn::hosts, nickname},
                      json_entry)) {
    return Err(EC::CommonFailure, "failed to set config in memory data");
  }
  return Ok();
}

ECM AMHostManager::RemoveHost_(const std::string &nickname) {
  CollectHosts_();
  ECM memory_rcm = HostDomainService_().RemoveHostInMemory(&host_configs, nickname);
  if (memory_rcm.first != EC::Success) {
    return memory_rcm;
  }
  if (!AMConfigManager::Instance().DelArg(DocumentKind::Config, {configkn::hosts, nickname})) {
    return Err(EC::CommonFailure, "failed to remove config in memory data");
  }
  return Ok();
}


