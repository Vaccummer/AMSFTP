#include "AMBase/CommonTools.hpp"
#include "AMBase/Path.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Host.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>

namespace {
/**
 * @brief Resolve the local username from environment variables.
 */
std::string GetLocalUsername_() {
  std::string local_user = "";
#ifdef _WIN32
  GetEnv("USERNAME", &local_user);
#else
  GetEnv("USER", &local_user);
#endif
  if (local_user.empty()) {
    local_user = "local";
  }
  return local_user;
}
} // namespace

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
    auto cfg = ClientConfig(nickname, it.value());
    if (cfg.IsValid()) {
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

/**
 * @brief Get local client config from config storage or use defaults.
 */
std::pair<ECM, ClientConfig> AMHostManager::GetLocalConfig() {
  ClientConfig result;

  const std::string local_user = GetLocalUsername_();
  const std::string fallback_home = AMFS::HomePath();

  std::string root_dir = "";
  if (!GetEnv("AMSFTP_ROOT", &root_dir) || root_dir.empty()) {
    root_dir = config_.ProjectRoot().string();
  }
  const std::string fallback_trash = AMPathStr::join(root_dir, "trash");

  Json host_json;
  if (config_.ResolveArg(DocumentKind::Config, {configkn::hosts, "local"},
                         &host_json) &&
      host_json.is_object()) {
    ClientConfig stored("local", host_json);
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

  result.protocol = ClientProtocol::LOCAL;

  if (result.buffer_size <= 0) {
    result.buffer_size = 64 * AMMB;
  } else {
    result.buffer_size = std::min(
        std::max(result.buffer_size, static_cast<int64_t>(AMMinBufferSize)),
        static_cast<int64_t>(AMMaxBufferSize));
  }

  if (result.login_dir.empty()) {
    result.login_dir = fallback_home;
  }
  if (result.request.trash_dir.empty()) {
    result.request.trash_dir = fallback_trash;
  }

  return {Ok(), result};
}

ECM AMHostManager::UpsertHost(const ClientConfig &entry, bool dump_now) {
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
  CollectHosts_();
  return host_configs.find(nickname) != host_configs.end();
}

std::vector<std::string> AMHostManager::ListNames() const {
  CollectHosts_();
  std::vector<std::string> names;
  names.reserve(host_configs.size());
  for (const auto &pair : host_configs) {
    names.push_back(pair.first);
  }
  std::sort(names.begin(), names.end());
  return names;
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
  if (!configkn::ValidateNickname(entry.request.nickname)) {
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
      entry.protocol = configkn::StrToProtocol(protocol);
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
  static auto print_abort = [this]() {
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

  std::string protocol = AMStr::lowercase(AM_ENUM_NAME(entry.protocol));

  while (true) {
    if (!prompt_.Prompt("Protocol (sftp/ftp): ", protocol, &protocol)) {
      print_abort();
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    protocol = AMStr::lowercase(AMStr::Strip(protocol));
    if (protocol == "sftp" || protocol == "ftp") {
      break;
    }
    prompt_.ErrorFormat(ECM{EC::InvalidArg, "Protocol must be sftp or ftp"});
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
  entry.protocol = configkn::StrToProtocol(protocol);
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
                            const ClientConfig &entry) {
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
