#include "AMBase/CommonTools.hpp"
#include "AMBase/Path.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Host.hpp"
#include <cctype>
#include <string>
#include <vector>

namespace {
using Json = nlohmann::ordered_json;
using Value = AMHostManager::Value;

std::optional<std::string> GetStringField(const Json &obj,
                                          const std::string &key) {
  if (!obj.is_object()) {
    return std::nullopt;
  }
  auto it = obj.find(key);
  if (it == obj.end()) {
    return std::nullopt;
  }
  if (it->is_string()) {
    return it->get<std::string>();
  }
  if (it->is_number_integer()) {
    return std::to_string(it->get<int64_t>());
  }
  if (it->is_boolean()) {
    return it->get<bool>() ? "true" : "false";
  }
  return std::nullopt;
}

bool ProtocolMatch(const std::string &stored, const std::string &actual) {
  const std::string expected = AMStr::lowercase(stored);
  const std::string real = AMStr::lowercase(actual);
  if (expected == real) {
    return true;
  }
  const bool expected_is_rsa =
      expected == "rsa-sha2-256" || expected == "rsa-sha2-512";
  const bool real_is_rsa = real == "rsa-sha2-256" || real == "rsa-sha2-512";
  return (expected == "ssh-rsa" && real_is_rsa) ||
         (real == "ssh-rsa" && expected_is_rsa);
}

} // namespace

AMHostManager::AMHostManager(AMConfigManager &config)
    : config_(config), prompt_(AMPromptManager::Instance()) {}

std::pair<ECM, ClientConfig> BuildConfigFromJson(const Json &config_json,
                                                 const std::string &nickname) {
  ClientConfig cfg;
  if (!config_json.is_object()) {
    return {Err(EC::InvalidArg, "config is not an object"), {}};
  }
  if (!QueryKey(config_json, {"hostname"}, &cfg.request.hostname) ||
      cfg.request.hostname.empty()) {
    return {Err(EC::InvalidArg, "hostname is not valid"), {}};
  }
  if (!QueryKey(config_json, {"username"}, &cfg.request.username) ||
      cfg.request.username.empty()) {
    return {Err(EC::InvalidArg, "username is not valid"), {}};
  }
  cfg.request.nickname = nickname;
  QueryKey(config_json, {"port"}, &cfg.request.port);
  QueryKey(config_json, {"password"}, &cfg.request.password);
  QueryKey(config_json, {"keyfile"}, &cfg.request.keyfile);
  QueryKey(config_json, {"compression"}, &cfg.request.compression);
  QueryKey(config_json, {"trash_dir"}, &cfg.request.trash_dir);
  std::string protocol_str;
  if (!QueryKey(config_json, {"protocol"}, &protocol_str)) {
    cfg.protocol = ClientProtocol::SFTP;
  } else {
    auto it = protocol_map.find(AMStr::lowercase(protocol_str));
    if (it != protocol_map.end()) {
      cfg.protocol = it->second;
    } else {
      return {Err(EC::InvalidArg, "protocol is not valid"), {}};
    }
  }
  QueryKey(config_json, {"buffer_size"}, &cfg.buffer_size);
  QueryKey(config_json, {"login_dir"}, &cfg.login_dir);
  return {Ok(), cfg};
}

void AMHostManager::CollectHosts_() const {
  if (!host_configs.empty()) {
    return;
  }
  Json hosts_json;
  if (!config_.ResolveArg(DocumentKind::Config, {"HOSTS"}, &hosts_json)) {
    return;
  }
  if (!hosts_json.is_object()) {
    return;
  }
  for (auto it = hosts_json.begin(); it != hosts_json.end(); ++it) {
    const std::string nickname = it.key();
    const Json &config_json = it.value();
    auto [ecm, cfg] = BuildConfigFromJson(config_json, nickname);
    if (ecm.first == EC::Success) {
      host_configs[nickname] = cfg;
    }
  }
}

std::pair<ECM, ClientConfig>
AMHostManager::GetClientConfig(const std::string &nickname) {
  if (!HostExists(nickname)) {
    return {Err(EC::HostConfigNotFound,
                AMStr::amfmt("host config not found: {}", nickname)),
            {}};
  }
  return {Ok(), host_configs[nickname]};
}

std::pair<ECM, std::optional<KnownHostEntry>>
AMHostManager::FindKnownHost(const std::string &hostname, int port,
                             const std::string &protocol) const {
  Json hosts_it;
  if (!config_.ResolveArg(DocumentKind::KnownHosts,
                          {AMStr::amfmt("{}:{}", hostname, port)}, &hosts_it)) {
    return {{EC::HostConfigNotFound,
             AMStr::amfmt("known_host not found: {}:{}", hostname, port)},
            std::nullopt};
  }
  std::string fingerprint;
  if (!QueryKey(hosts_it, {"fingerprint"}, &fingerprint)) {
    return {{EC::HostConfigNotFound,
             AMStr::amfmt("known_host fingerprint not found: {}:{}", hostname,
                          port)},
            std::nullopt};
  }
  KnownHostEntry entry;
  entry.hostname = hostname;
  entry.port = port;
  entry.protocol = protocol;
  entry.fingerprint = fingerprint;
  return {Ok(), entry};
}

bool AMHostManager::HostExists(const std::string &nickname) const {
  if (nickname.empty()) {
    return false;
  }
  CollectHosts_();
  return host_configs.find(nickname) != host_configs.end();
}

bool AMHostManager::ValidateNickname(const std::string &nickname) const {
  // regex is "^[a-zA-Z0-9_-]+$" but use manual check to avoid regex overhead
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
}

std::vector<std::string> AMHostManager::ListHostnames() const {
  CollectHosts_();
  std::vector<std::string> names;
  names.reserve(host_configs.size());
  for (const auto &item : host_configs) {
    names.push_back(item.first);
  }
  return names;
}

ECM AMHostManager::SetHostConfigField(
    const std::string &nickname, const std::string &field,
    const std::variant<int64_t, bool, std::string, std::vector<std::string>>
        &value) {
  if (host_configs.find(nickname) == host_configs.end()) {
    return {EC::HostConfigNotFound, "host config not found"};
  }
  auto &entry = host_configs[nickname];
  auto field_f = AMStr::lowercase(field);
  if (field_f == "hostname" && std::holds_alternative<std::string>(value)) {
    entry.request.hostname = std::get<std::string>(value);
    return Ok();
  };
  if (field_f == "username" && std::holds_alternative<std::string>(value)) {
    entry.request.username = std::get<std::string>(value);
    return Ok();
  };
  if (field_f == "port" && std::holds_alternative<int64_t>(value)) {
    entry.request.port = static_cast<int>(std::get<int64_t>(value));
    return Ok();
  };
  if (field_f == "password" && std::holds_alternative<std::string>(value)) {
    entry.request.password = std::get<std::string>(value);
    return Ok();
  };
  if (field_f == "protocol" && std::holds_alternative<std::string>(value)) {
    entry.protocol = StrToProtocol(std::get<std::string>(value));
    return Ok();
  }
  if (field_f == "buffer_size" && std::holds_alternative<int64_t>(value)) {
    entry.buffer_size = std::get<int64_t>(value);
    return Ok();
  };
  if (field_f == "login_dir" && std::holds_alternative<std::string>(value)) {
    entry.login_dir = std::get<std::string>(value);
    return Ok();
  };
  if (field_f == "trash_dir" && std::holds_alternative<std::string>(value)) {
    entry.request.trash_dir = std::get<std::string>(value);
    return Ok();
  };
  if (field_f == "keyfile" && std::holds_alternative<std::string>(value)) {
    entry.request.keyfile = std::get<std::string>(value);
    return Ok();
  };
  if (field_f == "compression" && std::holds_alternative<bool>(value)) {
    entry.request.compression = std::get<bool>(value);
    return Ok();
  };
  return {EC::InvalidArg, "invalid field name or value type"};
}

ECM AMHostManager::PromptAddFields_(const std::string &nickname,
                                    ClientConfig &entry) {
  entry = ClientConfig{};
  auto print_abort = [this]() {
    prompt_.Print(AMStr::amfmt("{}\n", config_.Format("Input Abort", "abort")));
  };

  entry.request.nickname = nickname;
  while (entry.request.nickname.empty()) {
    if (!prompt_.Prompt("Nickname: ", "", &entry.request.nickname)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    entry.request.nickname = AMStr::Strip(entry.request.nickname);
    if (entry.request.nickname.empty()) {
      prompt_.ErrorFormat(ECM{EC::InvalidArg, "Nickname cannot be empty"});
    }
  }
  if (!ValidateNickname(entry.request.nickname)) {
    return Err(EC::InvalidArg, "Nickname must match [A-Za-z0-9_-]+");
  }
  if (HostExists(entry.request.nickname)) {
    return Err(EC::InvalidArg, "Nickname already exists");
  }

  while (true) {
    if (!prompt_.Prompt("Hostname: ", "", &entry.request.hostname)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    entry.request.hostname = AMStr::Strip(entry.request.hostname);
    if (!entry.request.hostname.empty()) {
      break;
    }
    prompt_.ErrorFormat(ECM{EC::InvalidArg, "Hostname cannot be empty"});
  }

  while (true) {
    if (!prompt_.Prompt("Username: ", "", &entry.request.username)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    entry.request.username = AMStr::Strip(entry.request.username);
    if (!entry.request.username.empty()) {
      break;
    }
    prompt_.ErrorFormat(ECM{EC::InvalidArg, "Username cannot be empty"});
  }

  std::string port_input;
  entry.request.port = 22;
  while (true) {
    if (!prompt_.Prompt("Port (default 22): ", "22", &port_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    port_input = AMStr::Strip(port_input);
    if (port_input.empty()) {
      break;
    }
    int parsed_port = 0;
    if (!StrValueParse(port_input, &parsed_port) || parsed_port <= 0) {
      prompt_.ErrorFormat(
          ECM{EC::InvalidArg, "Port must be a positive integer"});
      continue;
    }
    entry.request.port = parsed_port;
    break;
  }

  std::string password;
  while (true) {
    std::string first;
    std::string second;
    if (!prompt_.SecurePrompt("Password (optional): ", &first)) {
      return Err(EC::ConfigCanceled, "password input canceled");
    }
    if (!prompt_.SecurePrompt("Confirm password: ", &second)) {
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

  std::string protocol = "sftp";
  while (true) {
    if (!prompt_.Prompt("Protocol (sftp/ftp/local): ", protocol, &protocol)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    protocol = AMStr::lowercase(AMStr::Strip(protocol));
    if (protocol == "sftp" || protocol == "ftp" || protocol == "local") {
      entry.protocol = StrToProtocol(protocol);
      break;
    }
    prompt_.ErrorFormat(
        ECM{EC::InvalidArg, "Protocol must be sftp, ftp, or local"});
  }

  std::string buffer_input;
  entry.buffer_size = 24 * AMMB;
  while (true) {
    if (!prompt_.Prompt("Buffer size(Default 24MB): ",
                        std::to_string(entry.buffer_size), &buffer_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "add canceled");
    }
    buffer_input = AMStr::Strip(buffer_input);
    if (buffer_input.empty()) {
      break;
    }
    int64_t parsed_buffer = 0;
    if (!StrValueParse(buffer_input, &parsed_buffer) || parsed_buffer <= 0) {
      prompt_.ErrorFormat(
          ECM{EC::InvalidArg, "Buffer size must be a positive integer"});
      continue;
    }
    entry.buffer_size = parsed_buffer;
    break;
  }

  if (!prompt_.Prompt("Trash dir (optional): ", entry.request.trash_dir,
                      &entry.request.trash_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }
  if (!prompt_.Prompt("Login dir (optional): ", entry.login_dir,
                      &entry.login_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }
  if (!prompt_.Prompt("Keyfile (optional): ", entry.request.keyfile,
                      &entry.request.keyfile)) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }

  bool canceled = false;
  entry.request.compression =
      prompt_.PromptYesNo("Enable compression? (y/N): ", &canceled);
  if (canceled) {
    print_abort();
    return Err(EC::ConfigCanceled, "add canceled");
  }
  return Ok();
}

ECM AMHostManager::PromptModifyFields_(const std::string &nickname,
                                       ClientConfig &entry) {
  (void)nickname;
  auto print_abort = [this]() {
    prompt_.Print(AMStr::amfmt("{}\n", config_.Format("Input Abort", "abort")));
  };

  std::string hostname = entry.request.hostname;
  if (!prompt_.Prompt("Hostname: ", hostname, &hostname)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  hostname = AMStr::Strip(hostname);
  if (hostname.empty()) {
    hostname = entry.request.hostname;
  }
  if (hostname.empty()) {
    return Err(EC::InvalidArg, "Hostname cannot be empty");
  }

  std::string username = entry.request.username;
  if (!prompt_.Prompt("Username: ", username, &username)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  username = AMStr::Strip(username);
  if (username.empty()) {
    username = entry.request.username;
  }
  if (username.empty()) {
    return Err(EC::InvalidArg, "Username cannot be empty");
  }

  int port = entry.request.port > 0 ? entry.request.port : 22;
  while (true) {
    std::string port_input = std::to_string(port);
    if (!prompt_.Prompt("Port (default 22): ", port_input, &port_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    port_input = AMStr::Strip(port_input);
    if (port_input.empty()) {
      break;
    }
    int parsed_port = 0;
    if (!StrValueParse(port_input, &parsed_port) || parsed_port <= 0) {
      prompt_.ErrorFormat(
          ECM{EC::InvalidArg, "Port must be a positive integer"});
      continue;
    }
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
      if (!prompt_.SecurePrompt("Password (optional): ", &first)) {
        return Err(EC::ConfigCanceled, "Password entry canceled");
      }
      if (!prompt_.SecurePrompt("Confirm password: ", &second)) {
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

  std::string protocol = "sftp";
  for (const auto &item : protocol_map) {
    if (item.second == entry.protocol) {
      protocol = item.first;
      break;
    }
  }
  while (true) {
    if (!prompt_.Prompt("Protocol (sftp/ftp/local): ", protocol, &protocol)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    protocol = AMStr::lowercase(AMStr::Strip(protocol));
    if (protocol == "sftp" || protocol == "ftp" || protocol == "local") {
      break;
    }
    prompt_.ErrorFormat(
        ECM{EC::InvalidArg, "Protocol must be sftp, ftp, or local"});
  }

  int64_t buffer_size = entry.buffer_size > 0 ? entry.buffer_size : 24 * AMMB;
  while (true) {
    std::string buffer_input = std::to_string(buffer_size);
    if (!prompt_.Prompt("Buffer size: ", buffer_input, &buffer_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    buffer_input = AMStr::Strip(buffer_input);
    if (buffer_input.empty()) {
      break;
    }
    int64_t parsed_buffer = 0;
    if (!StrValueParse(buffer_input, &parsed_buffer) || parsed_buffer <= 0) {
      prompt_.ErrorFormat(
          ECM{EC::InvalidArg, "Buffer size must be a positive integer"});
      continue;
    }
    buffer_size = parsed_buffer;
    break;
  }

  std::string trash_dir = entry.request.trash_dir;
  if (!prompt_.Prompt("Trash dir (optional): ", trash_dir, &trash_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string login_dir = entry.login_dir;
  if (!prompt_.Prompt("Login dir (optional): ", login_dir, &login_dir)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string keyfile = entry.request.keyfile;
  if (!prompt_.Prompt("Keyfile (optional): ", keyfile, &keyfile)) {
    print_abort();
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  bool compression = entry.request.compression;
  while (true) {
    std::string compression_input = compression ? "true" : "false";
    if (!prompt_.Prompt("Compression (true/false): ", compression_input,
                        &compression_input)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    if (StrValueParse(compression_input, &entry.request.compression)) {
      break;
    }
    prompt_.ErrorFormat(
        ECM{EC::InvalidArg, "Compression must be true or false."});
  }

  entry.request.hostname = hostname;
  entry.request.username = username;
  entry.request.port = port;
  entry.protocol = StrToProtocol(protocol);
  entry.buffer_size = buffer_size;
  entry.request.trash_dir = trash_dir;
  entry.login_dir = login_dir;
  entry.request.keyfile = keyfile;
  entry.request.compression = compression;
  return Ok();
}

ECM AMHostManager::PrintHost_(const std::string &nickname,
                              const ClientConfig &entry) const {
  prompt_.Print("[!pre][" + nickname + "][/pre]");
  size_t width = 0;
  for (const auto &field : kHostFields)
    width = std::max(width, field.size());

  auto dict_f = entry.GetStrDict();

  for (const auto &field : kHostFields) {
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

ECM AMHostManager::RemoveHost_(const std::string &nickname) {
  CollectHosts_();
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host name");
  }
  if (host_configs.erase(nickname) == 0) {
    return Err(EC::HostConfigNotFound, "host config not found");
  }
  if (!config_.DelArg(DocumentKind::Config, {"HOSTS", nickname})) {
    return Err(EC::CommonFailure, "failed to remove config in memory data");
  }
  return Ok();
}

ECM AMHostManager::SaveConfig_(bool async) {
  return config_.Dump(DocumentKind::Config, "", async);
}

ECM AMHostManager::SaveAll_(bool async) { return config_.DumpAll(async); }

bool AMHostManager::GetDocumentJson_(DocumentKind kind, Json *value) const {
  if (!value) {
    return false;
  }
  return config_.GetJson(kind, value);
}

bool AMHostManager::GetDocumentPath_(DocumentKind kind,
                                     std::filesystem::path *value) const {
  if (!value) {
    return false;
  }
  return config_.GetDataPath(kind, value);
}

std::string AMHostManager::FormatValue_(const std::string &text,
                                        const std::string &style_name,
                                        const PathInfo *path_info) const {
  return config_.Format(text, style_name, path_info);
}

std::string AMHostManager::ProtocolToString_(ClientProtocol protocol) const {
  switch (protocol) {
  case ClientProtocol::SFTP:
    return "sftp";
  case ClientProtocol::FTP:
    return "ftp";
  case ClientProtocol::LOCAL:
    return "local";
  default:
    return "sftp";
  }
}

std::string AMHostManager::ValueToString_(const Value &value) const {
  if (std::holds_alternative<int64_t>(value)) {
    return std::to_string(std::get<int64_t>(value));
  }
  if (std::holds_alternative<bool>(value)) {
    return std::get<bool>(value) ? "true" : "false";
  }
  if (std::holds_alternative<std::string>(value)) {
    return std::get<std::string>(value);
  }
  if (std::holds_alternative<std::vector<std::string>>(value)) {
    const auto &items = std::get<std::vector<std::string>>(value);
    return AMStr::amfmt("[{}]", AMStr::join(items, ", "));
  }
  return "";
}

ECM AMHostManager::PersistHostConfig_(const std::string &nickname,
                                      const ClientConfig &entry,
                                      bool dump_now) {
  ECM set_status =
      SetHostField(nickname, "hostname", entry.request.hostname, false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status =
      SetHostField(nickname, "username", entry.request.username, false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status = SetHostField(nickname, "port",
                            static_cast<int64_t>(entry.request.port), false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status =
      SetHostField(nickname, "password", entry.request.password, false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status = SetHostField(nickname, "protocol",
                            ProtocolToString_(entry.protocol), false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status = SetHostField(nickname, "buffer_size", entry.buffer_size, false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status =
      SetHostField(nickname, "trash_dir", entry.request.trash_dir, false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status = SetHostField(nickname, "login_dir", entry.login_dir, false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status = SetHostField(nickname, "keyfile", entry.request.keyfile, false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  set_status =
      SetHostField(nickname, "compression", entry.request.compression, false);
  if (set_status.first != EC::Success) {
    return set_status;
  }
  if (dump_now) {
    return SaveConfig_(false);
  }
  return Ok();
}
