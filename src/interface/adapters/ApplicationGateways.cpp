#include "interface/ApplicationAdapters.hpp"
#include "interface/Completer/Proxy.hpp"
#include "interface/Prompt.hpp"
#include "foundation/Path.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/json.hpp"
#include "domain/client/ClientManager.hpp"
#include "domain/filesystem/FileSystemManager.hpp"
#include "domain/host/HostManager.hpp"
#include "domain/transfer/TransferManager.hpp"
#include "domain/var/VarManager.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace AMInterface::ApplicationAdapters {
namespace {
/**
 * @brief Resolve the local username from environment variables.
 */
std::string ResolveLocalUsername_() {
  std::string local_user = "";
#ifdef _WIN32
  AMStr::GetEnv("USERNAME", &local_user);
#else
  AMStr::GetEnv("USER", &local_user);
#endif
  return local_user.empty() ? std::string("local") : local_user;
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
  return ResolveLocalUsername_();
}

/**
 * @brief Return one styled nickname using active connection state.
 */
std::string StyledNickname_(const std::string &nickname) {
  const bool created = static_cast<bool>(Runtime::GetClient(nickname));
  const std::string style_key =
      created ? "nickname" : "unestablished_nickname";
  return Runtime::Format(nickname, style_key);
}

/**
 * @brief Print one host config in detailed format.
 */
void PrintHostDetail_(AMPromptManager &prompt, const std::string &nickname,
                      const HostConfig &entry) {
  const std::string styled_nickname = StyledNickname_(nickname);
  prompt.Print("[" + styled_nickname + "]");

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
    prompt.Print(line.str());
  }
}

/**
 * @brief Prompt one simple host text field.
 */
bool PromptHostText_(AMPromptManager &prompt, const std::string &label,
                     const std::string &placeholder, std::string *out,
                     bool allow_empty) {
  if (!out) {
    return false;
  }
  std::function<bool(const std::string &)> checker =
      [allow_empty](const std::string &text) {
        return allow_empty || !AMStr::Strip(text).empty();
      };
  return prompt.Prompt(label, placeholder, out, checker, {});
}

/**
 * @brief Prompt one boolean host field.
 */
bool PromptHostBool_(AMPromptManager &prompt, const std::string &label,
                     bool current, bool *out) {
  if (!out) {
    return false;
  }
  std::string input = current ? "true" : "false";
  const std::map<std::string, std::string> literals = {
      {"true", "Enable"}, {"false", "Disable"}};
  if (!prompt.LiteralPrompt(label, input, &input, literals)) {
    return false;
  }
  bool parsed = current;
  if (!AMJson::StrValueParse(AMStr::lowercase(AMStr::Strip(input)), &parsed)) {
    return false;
  }
  *out = parsed;
  return true;
}

/**
 * @brief Prompt one protocol literal.
 */
bool PromptHostProtocol_(AMPromptManager &prompt, ClientProtocol current,
                         ClientProtocol *out) {
  if (!out) {
    return false;
  }
  std::string input = AMStr::lowercase(AMStr::ToString(current));
  if (input.empty() || input == "unknown") {
    input = "sftp";
  }
  const std::map<std::string, std::string> literals = {
      {"sftp", "SFTP protocol"},
      {"ftp", "FTP protocol"},
      {"local", "Local protocol"},
  };
  if (!prompt.LiteralPrompt("Protocol: ", input, &input, literals)) {
    return false;
  }
  *out = configkn::StrToProtocol(AMStr::lowercase(AMStr::Strip(input)));
  return true;
}

/**
 * @brief Prompt one integer host field.
 */
bool PromptHostInt64_(AMPromptManager &prompt, const std::string &label,
                      int64_t current, int64_t min_v, int64_t max_v,
                      int64_t *out, bool allow_empty = false) {
  if (!out) {
    return false;
  }
  std::string input = std::to_string(current);
  auto checker = [min_v, max_v, allow_empty](const std::string &text) {
    if (allow_empty && AMStr::Strip(text).empty()) {
      return true;
    }
    int64_t parsed = 0;
    if (!AMJson::StrValueParse(AMStr::Strip(text), &parsed)) {
      return false;
    }
    return parsed >= min_v && parsed <= max_v;
  };
  if (!prompt.Prompt(label, input, &input, checker, {})) {
    return false;
  }
  if (allow_empty && AMStr::Strip(input).empty()) {
    return true;
  }
  int64_t parsed = current;
  if (!AMJson::StrValueParse(AMStr::Strip(input), &parsed)) {
    return false;
  }
  *out = parsed;
  return true;
}

/**
 * @brief Print one compact host-name list.
 */
void PrintHostCompact_(AMPromptManager &prompt,
                       const std::vector<std::string> &names) {
  if (names.empty()) {
    prompt.Print("");
    return;
  }
  const size_t max_width = 80;
  size_t current_width = 0;
  std::ostringstream line;
  for (const auto &nickname : names) {
    const std::string styled = StyledNickname_(nickname);
    const size_t display_len = nickname.size();
    const size_t separator_len = current_width == 0 ? 0 : 3;
    if (current_width + separator_len + display_len > max_width &&
        current_width > 0) {
      prompt.Print(line.str());
      line.str(std::string());
      line.clear();
      current_width = 0;
    }
    if (current_width > 0) {
      line << "   ";
      current_width += 3;
    }
    line << styled;
    current_width += display_len;
  }
  if (current_width > 0) {
    prompt.Print(line.str());
  }
}

/**
 * @brief Print one set-value summary display text.
 */
std::string HostFieldDisplay_(const HostConfig &entry,
                              const std::string &field) {
  if (field == configkn::hostname) {
    return entry.request.hostname;
  }
  if (field == configkn::username) {
    return entry.request.username;
  }
  if (field == configkn::port) {
    return std::to_string(entry.request.port);
  }
  if (field == configkn::protocol) {
    return AMStr::lowercase(AMStr::ToString(entry.request.protocol));
  }
  if (field == configkn::password) {
    return entry.request.password.empty() ? "\"\"" : "***";
  }
  if (field == configkn::buffer_size) {
    return std::to_string(entry.request.buffer_size);
  }
  if (field == configkn::compression) {
    return entry.request.compression ? "true" : "false";
  }
  if (field == configkn::cmd_prefix) {
    return entry.metadata.cmd_prefix;
  }
  if (field == configkn::wrap_cmd) {
    return entry.metadata.wrap_cmd ? "true" : "false";
  }
  if (field == configkn::keyfile) {
    return entry.request.keyfile;
  }
  if (field == configkn::trash_dir) {
    return entry.request.trash_dir;
  }
  if (field == configkn::login_dir) {
    return entry.metadata.login_dir;
  }
  return "";
}

/**
 * @brief Prompt full add payload for one host config.
 */
ECM PromptAddHostConfig_(AMPromptManager &prompt,
                         AMDomain::host::AMHostManager &host_manager,
                         const std::string &nickname, HostConfig *out) {
  if (!out) {
    return Err(EC::InvalidArg, "null host config");
  }
  HostConfig entry = {};

  std::string nickname_input = AMStr::Strip(nickname);
  while (true) {
    if (nickname_input.empty() &&
        !PromptHostText_(prompt, "Nickname: ", "", &nickname_input, false)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    nickname_input = AMStr::Strip(nickname_input);
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Nickname,
                                         nickname_input, &normalized, &err_msg,
                                         true, true, &err_code)) {
      prompt.ErrorFormat(ECM{err_code, err_msg});
      nickname_input.clear();
      continue;
    }
    if (AMStr::lowercase(normalized) == "local") {
      prompt.ErrorFormat(ECM{EC::InvalidArg, "Nickname 'local' is reserved"});
      nickname_input.clear();
      continue;
    }
    if (host_manager.HostExists(normalized)) {
      prompt.ErrorFormat(ECM{EC::KeyAlreadyExists, "nickname already exists"});
      nickname_input.clear();
      continue;
    }
    entry.request.nickname = normalized;
    break;
  }

  while (true) {
    if (!PromptHostProtocol_(prompt, ClientProtocol::SFTP,
                             &entry.request.protocol)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    const std::string protocol =
        AMStr::lowercase(AMStr::ToString(entry.request.protocol));
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Protocol, protocol,
                                        &normalized, &err_msg, true, true,
                                        &err_code)) {
      entry.request.protocol = configkn::StrToProtocol(normalized);
      break;
    }
    prompt.ErrorFormat(ECM{err_code, err_msg});
  }

  const bool hostname_required = entry.request.protocol != ClientProtocol::LOCAL;
  while (true) {
    std::string hostname = entry.request.hostname;
    if (!PromptHostText_(prompt, "Hostname: ", hostname, &hostname,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      prompt.ErrorFormat(ECM{EC::InvalidArg, "hostname cannot be empty"});
      continue;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Hostname, hostname,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      prompt.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    entry.request.hostname = normalized;
    break;
  }

  const std::string default_username =
      DefaultUsernameForProtocol_(entry.request.protocol);
  entry.request.username = default_username;
  while (true) {
    std::string username = entry.request.username;
    if (!PromptHostText_(prompt, "Username: ", default_username, &username,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = default_username;
    }
    if (hostname_required && username.empty()) {
      prompt.ErrorFormat(ECM{EC::InvalidArg, "username cannot be empty"});
      continue;
    }
    if (username.empty()) {
      entry.request.username.clear();
      break;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Username, username,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      prompt.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    entry.request.username = normalized;
    break;
  }

  int64_t port = DefaultPortForProtocol_(entry.request.protocol);
  if (!PromptHostInt64_(prompt, AMStr::fmt("Port(default {}): ", port), port, 1,
                        65535, &port, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  entry.request.port = static_cast<int>(port);

  while (true) {
    std::string first;
    std::string second;
    if (!prompt.SecurePrompt("password(optional): ", &first) ||
        !prompt.SecurePrompt("confirm password: ", &second)) {
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      return Err(EC::ConfigCanceled, "input canceled");
    }
    if (first != second) {
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      prompt.ErrorFormat(ECM{EC::InvalidArg, "Passwords do not match"});
      continue;
    }
    if (first.empty()) {
      entry.request.password.clear();
    } else {
      entry.request.password = AMAuth::EncryptPassword(first);
    }
    AMAuth::SecureZero(first);
    AMAuth::SecureZero(second);
    break;
  }

  while (true) {
    std::string keyfile = entry.request.keyfile;
    if (!PromptHostText_(prompt, "keyfile(optional): ", keyfile, &keyfile,
                         true)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    keyfile = AMStr::Strip(keyfile);
    if (keyfile.empty()) {
      entry.request.keyfile.clear();
      break;
    }
    auto [key_rcm, key_info] = AMFS::stat(keyfile, false);
    if (!isok(key_rcm) || key_info.type != PathType::FILE) {
      prompt.ErrorFormat(
          ECM{EC::InvalidArg, "keyfile must be an existing file path"});
      continue;
    }
    entry.request.keyfile = keyfile;
    break;
  }

  int64_t buffer_size = 24 * AMMB;
  if (!PromptHostInt64_(prompt, "Buffer size: ", buffer_size, AMMinBufferSize,
                        AMMaxBufferSize, &buffer_size, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  entry.request.buffer_size = buffer_size;

  if (!PromptHostBool_(prompt, "compression: ", false,
                       &entry.request.compression)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }

  if (!PromptHostText_(prompt, "trash_dir(optional): ", entry.request.trash_dir,
                       &entry.request.trash_dir, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "cmd_prefix(optional): ", entry.metadata.cmd_prefix,
                       &entry.metadata.cmd_prefix, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostBool_(prompt, "wrap_cmd(true/false): ",
                       entry.metadata.wrap_cmd, &entry.metadata.wrap_cmd)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  *out = entry;
  return Ok();
}

/**
 * @brief Prompt full edit payload for one existing host config.
 */
ECM PromptEditHostConfig_(AMPromptManager &prompt,
                          const std::string &nickname, HostConfig *inout) {
  if (!inout) {
    return Err(EC::InvalidArg, "null host config");
  }
  HostConfig entry = *inout;
  const ClientProtocol original_protocol = entry.request.protocol;

  while (true) {
    if (!PromptHostProtocol_(prompt, entry.request.protocol,
                             &entry.request.protocol)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    const std::string protocol =
        AMStr::lowercase(AMStr::ToString(entry.request.protocol));
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (configkn::ValidateHostAttrValue(configkn::HostAttr::Protocol, protocol,
                                        &normalized, &err_msg, true, true,
                                        &err_code)) {
      entry.request.protocol = configkn::StrToProtocol(normalized);
      break;
    }
    prompt.ErrorFormat(ECM{err_code, err_msg});
  }
  const ClientProtocol selected_protocol = entry.request.protocol;
  const bool protocol_changed = selected_protocol != original_protocol;
  const bool hostname_required = selected_protocol != ClientProtocol::LOCAL;
  const std::string default_username =
      DefaultUsernameForProtocol_(selected_protocol);
  const int default_port = DefaultPortForProtocol_(selected_protocol);

  while (true) {
    std::string hostname = entry.request.hostname;
    if (!PromptHostText_(prompt, "Hostname: ", hostname, &hostname,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      prompt.ErrorFormat(ECM{EC::InvalidArg, "hostname cannot be empty"});
      continue;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Hostname, hostname,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      prompt.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    entry.request.hostname = normalized;
    break;
  }

  while (true) {
    std::string username =
        (protocol_changed || entry.request.username.empty())
            ? default_username
            : entry.request.username;
    if (!PromptHostText_(prompt, "Username: ", username, &username,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = default_username;
    }
    if (hostname_required && username.empty()) {
      prompt.ErrorFormat(ECM{EC::InvalidArg, "username cannot be empty"});
      continue;
    }
    if (username.empty()) {
      entry.request.username.clear();
      break;
    }
    std::string normalized;
    std::string err_msg;
    EC err_code = EC::InvalidArg;
    if (!configkn::ValidateHostAttrValue(configkn::HostAttr::Username, username,
                                         &normalized, &err_msg, true, true,
                                         &err_code)) {
      prompt.ErrorFormat(ECM{err_code, err_msg});
      continue;
    }
    entry.request.username = normalized;
    break;
  }

  int64_t port = (protocol_changed || entry.request.port <= 0 ||
                  entry.request.port > 65535)
                     ? default_port
                     : entry.request.port;
  if (!PromptHostInt64_(prompt, AMStr::fmt("Port(default {}): ", default_port),
                        port, 1, 65535, &port, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  entry.request.port = static_cast<int>(port);

  bool canceled = false;
  const bool change_password = prompt.PromptYesNo("Change password? (y/N): ",
                                                  &canceled);
  if (canceled) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (change_password) {
    while (true) {
      std::string first;
      std::string second;
      if (!prompt.SecurePrompt("password(optional): ", &first) ||
          !prompt.SecurePrompt("confirm password: ", &second)) {
        AMAuth::SecureZero(first);
        AMAuth::SecureZero(second);
        return Err(EC::ConfigCanceled, "input canceled");
      }
      if (first != second) {
        AMAuth::SecureZero(first);
        AMAuth::SecureZero(second);
        prompt.ErrorFormat(ECM{EC::InvalidArg, "Passwords do not match"});
        continue;
      }
      entry.request.password =
          first.empty() ? std::string() : AMAuth::EncryptPassword(first);
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      break;
    }
  }

  while (true) {
    std::string keyfile = entry.request.keyfile;
    if (!PromptHostText_(prompt, "keyfile(optional): ", keyfile, &keyfile,
                         true)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    keyfile = AMStr::Strip(keyfile);
    if (keyfile.empty()) {
      entry.request.keyfile.clear();
      break;
    }
    auto [key_rcm, key_info] = AMFS::stat(keyfile, false);
    if (!isok(key_rcm) || key_info.type != PathType::FILE) {
      prompt.ErrorFormat(
          ECM{EC::InvalidArg, "keyfile must be an existing file path"});
      continue;
    }
    entry.request.keyfile = keyfile;
    break;
  }

  int64_t buffer_size =
      entry.request.buffer_size > 0 ? entry.request.buffer_size : 24 * AMMB;
  if (!PromptHostInt64_(prompt, "Buffer size: ", buffer_size, AMMinBufferSize,
                        AMMaxBufferSize, &buffer_size, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  entry.request.buffer_size = buffer_size;

  if (!PromptHostBool_(prompt, "Compression (true/false): ",
                       entry.request.compression, &entry.request.compression)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "trash_dir(optional): ", entry.request.trash_dir,
                       &entry.request.trash_dir, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "cmd_prefix(optional): ", entry.metadata.cmd_prefix,
                       &entry.metadata.cmd_prefix, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostBool_(prompt, "wrap_cmd(true/false): ",
                       entry.metadata.wrap_cmd, &entry.metadata.wrap_cmd)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }

  entry.request.nickname = nickname;
  *inout = entry;
  return Ok();
}
} // namespace

/**
 * @brief Construct host/profile gateway from legacy managers.
 */
HostProfileGateway::HostProfileGateway(AMDomain::host::AMHostManager &host_manager,
                                       AMPromptManager &prompt_manager)
    : host_manager_(host_manager), prompt_manager_(prompt_manager) {}

/**
 * @brief Return whether one host nickname exists.
 */
bool HostProfileGateway::HostExists(const std::string &nickname) const {
  return host_manager_.HostExists(nickname);
}

/**
 * @brief List hosts using host manager CLI surface.
 */
ECM HostProfileGateway::ListHosts(bool detail) {
  const std::vector<std::string> nicknames = host_manager_.ListNames();
  if (!detail) {
    PrintHostCompact_(prompt_manager_, nicknames);
    return Ok();
  }
  if (nicknames.empty()) {
    prompt_manager_.Print("");
    return Ok();
  }
  for (const auto &nickname : nicknames) {
    auto [rcm, entry] = host_manager_.GetClientConfig(nickname);
    if (!isok(rcm)) {
      return rcm;
    }
    PrintHostDetail_(prompt_manager_, nickname, entry);
    prompt_manager_.Print("");
  }
  return Ok();
}

/**
 * @brief List private keys through host manager.
 */
ECM HostProfileGateway::ListPrivateKeys(bool detail) {
  auto [rcm, keys] = host_manager_.PrivateKeys(false);
  if (!isok(rcm)) {
    return rcm;
  }
  if (!detail) {
    return Ok();
  }
  prompt_manager_.Print("[SSH Private Keys]");
  for (size_t i = 0; i < keys.size(); ++i) {
    const std::string abs_path = AMFS::abspath(keys[i], true, AMFS::HomePath());
    auto [stat_rcm, info] = AMFS::stat(abs_path, false);
    const PathInfo *info_ptr = isok(stat_rcm) ? &info : nullptr;
    const std::string styled_path = Runtime::Format(abs_path, "", info_ptr);
    prompt_manager_.Print(AMStr::fmt("[{}]  {}", i, styled_path));
  }
  return Ok();
}

/**
 * @brief Show host configuration source payload.
 */
ECM HostProfileGateway::ShowConfigSource() {
  const std::string config_label = AMStr::BBCEscape("[Config] ");
  const std::string settings_label = AMStr::BBCEscape("[Setting]");
  std::filesystem::path config_path_obj;
  std::filesystem::path settings_path_obj;

  if (Runtime::GetConfigDataPath(DocumentKind::Config, &config_path_obj)) {
    const std::string config_path = config_path_obj.string();
    auto [rcm, info] = AMFS::stat(config_path, false);
    const PathInfo *info_ptr = isok(rcm) ? &info : nullptr;
    prompt_manager_.Print(
        AMStr::fmt("{} = {}", config_label,
                   Runtime::Format(config_path, "dir", info_ptr)));
  }
  if (Runtime::GetConfigDataPath(DocumentKind::Settings, &settings_path_obj)) {
    const std::string settings_path = settings_path_obj.string();
    auto [rcm, info] = AMFS::stat(settings_path, false);
    const PathInfo *info_ptr = isok(rcm) ? &info : nullptr;
    prompt_manager_.Print(
        AMStr::fmt("{} = {}", settings_label,
                   Runtime::Format(settings_path, "dir", info_ptr)));
  }
  return Ok();
}

/**
 * @brief Query one or more host entries.
 */
ECM HostProfileGateway::QueryHosts(const std::vector<std::string> &nicknames) {
  const std::vector<std::string> targets = AMJson::VectorDedup(nicknames);
  if (targets.empty()) {
    return Ok();
  }
  for (const auto &nickname : targets) {
    auto [rcm, entry] = host_manager_.GetClientConfig(nickname);
    if (!isok(rcm)) {
      return Err(EC::HostConfigNotFound,
                 AMStr::fmt("Host {} not found", StyledNickname_(nickname)));
    }
    PrintHostDetail_(prompt_manager_, nickname, entry);
    prompt_manager_.Print("");
  }
  return Ok();
}

/**
 * @brief Add one host entry.
 */
ECM HostProfileGateway::AddHost(const std::string &nickname) {
  HostConfig entry;
  ECM prompt_rcm =
      PromptAddHostConfig_(prompt_manager_, host_manager_, nickname, &entry);
  if (!isok(prompt_rcm)) {
    return prompt_rcm;
  }
  return host_manager_.UpsertHost(entry, true);
}

/**
 * @brief Edit one host entry.
 */
ECM HostProfileGateway::EditHost(const std::string &nickname) {
  auto [get_rcm, entry] = host_manager_.GetClientConfig(nickname);
  if (!isok(get_rcm)) {
    return get_rcm;
  }
  ECM prompt_rcm = PromptEditHostConfig_(prompt_manager_, nickname, &entry);
  if (!isok(prompt_rcm)) {
    return prompt_rcm;
  }
  return host_manager_.UpsertHost(entry, true);
}

/**
 * @brief Rename one host entry.
 */
ECM HostProfileGateway::RenameHost(const std::string &old_name,
                                   const std::string &new_name) {
  return host_manager_.Rename(old_name, new_name);
}

/**
 * @brief Remove one or more host entries.
 */
ECM HostProfileGateway::RemoveHosts(const std::vector<std::string> &nicknames) {
  const std::vector<std::string> targets = AMJson::VectorDedup(nicknames);
  if (targets.empty()) {
    return Ok();
  }
  for (const auto &nickname : targets) {
    if (!host_manager_.HostExists(nickname)) {
      return Err(EC::HostConfigNotFound,
                 AMStr::fmt("host nickname not found: {}", nickname));
    }
  }

  std::string listing;
  for (size_t i = 0; i < targets.size(); ++i) {
    if (i > 0) {
      listing += ", ";
    }
    listing += StyledNickname_(targets[i]);
  }
  bool canceled = false;
  const bool confirmed = prompt_manager_.PromptYesNo(
      AMStr::fmt("Delete {} host(s): {} ? (y/N): ", targets.size(), listing),
      &canceled);
  if (canceled || !confirmed) {
    prompt_manager_.Print("Delete aborted.");
    return Ok();
  }
  return host_manager_.Delete(targets);
}

/**
 * @brief Set one host attribute value.
 */
ECM HostProfileGateway::SetHostValue(const std::string &nickname,
                                     const std::string &attrname,
                                     const std::string &value) {
  const std::string field = AMStr::lowercase(AMStr::Strip(attrname));
  auto [before_rcm, before] = host_manager_.GetClientConfig(nickname);
  if (!isok(before_rcm)) {
    return before_rcm;
  }

  std::string resolved_value = value;
  if (field == configkn::password && AMStr::Strip(resolved_value).empty()) {
    if (!prompt_manager_.SecurePrompt("Password: ", &resolved_value)) {
      return Err(EC::ConfigCanceled, "password input canceled");
    }
  }

  const std::string old_value = HostFieldDisplay_(before, field);
  ECM rcm = host_manager_.SetHostValue(nickname, attrname, resolved_value);
  if (!isok(rcm)) {
    return rcm;
  }

  auto [after_rcm, after] = host_manager_.GetClientConfig(nickname);
  const std::string new_value =
      isok(after_rcm) ? HostFieldDisplay_(after, field) : resolved_value;
  prompt_manager_.Print(
      AMStr::fmt("{}.{}: {} -> {}", nickname, field, old_value, new_value));
  return Ok();
}

/**
 * @brief Persist host configuration.
 */
ECM HostProfileGateway::SaveHosts() { return host_manager_.Save(); }

/**
 * @brief Edit prompt profile for one nickname.
 */
ECM HostProfileGateway::EditProfile(const std::string &nickname) {
  return prompt_manager_.Edit(nickname);
}

/**
 * @brief Query prompt profiles for nicknames.
 */
ECM HostProfileGateway::GetProfiles(const std::vector<std::string> &nicknames) {
  return prompt_manager_.Get(nicknames);
}

/**
 * @brief List all configured host nicknames.
 */
std::vector<std::string> HostProfileGateway::ListHostNames() const {
  return host_manager_.ListNames();
}

/**
 * @brief Construct current-client reader from client manager.
 */
CurrentClientPort::CurrentClientPort(AMDomain::client::AMClientManager &client_manager)
    : client_manager_(client_manager) {}

/**
 * @brief Return the active client nickname.
 */
std::string CurrentClientPort::CurrentNickname() const {
  return client_manager_.CurrentNickname();
}

/**
 * @brief Construct path helper from client manager.
 */
ClientPathGateway::ClientPathGateway(AMDomain::client::AMClientManager &client_manager)
    : client_manager_(client_manager) {}

/**
 * @brief Return current workdir or empty string when unavailable.
 */
std::string ClientPathGateway::CurrentWorkdir() const {
  auto client = client_manager_.CurrentClient();
  if (!client) {
    return "";
  }
  return client_manager_.GetOrInitWorkdir(client);
}

/**
 * @brief Construct host config saver from host manager.
 */
HostConfigSaver::HostConfigSaver(AMDomain::host::AMHostManager &host_manager)
    : host_manager_(host_manager) {}

/**
 * @brief Persist host configuration state.
 */
ECM HostConfigSaver::SaveHostConfig() { return host_manager_.Save(); }

/**
 * @brief Construct var config saver from var manager.
 */
VarConfigSaver::VarConfigSaver(AMDomain::var::VarCLISet &var_manager)
    : var_manager_(var_manager) {}

/**
 * @brief Persist variable state.
 *
 * `dump_now=true` maps to synchronous save.
 */
ECM VarConfigSaver::SaveVarConfig(bool dump_now) {
  Json snapshot = Json::object();
  const auto &dict = var_manager_.GetVarDict();
  for (const auto &domain_entry : dict) {
    Json section = Json::object();
    for (const auto &var_entry : domain_entry.second) {
      section[var_entry.first] = var_entry.second;
    }
    snapshot[domain_entry.first] = std::move(section);
  }
  if (!Runtime::ConfigManagerOrThrow().SetArg(DocumentKind::Settings,
                                              {varsetkn::kRoot}, snapshot)) {
    return Err(EC::CommonFailure, "failed to write UserVars into settings");
  }
  return Runtime::ConfigManagerOrThrow().Dump(DocumentKind::Settings, "",
                                              !dump_now);
}

/**
 * @brief Construct prompt config saver from prompt manager.
 */
PromptConfigSaver::PromptConfigSaver(AMPromptManager &prompt_manager)
    : prompt_manager_(prompt_manager) {}

/**
 * @brief Persist prompt state.
 *
 * Prompt manager persists history through FlushHistory.
 */
ECM PromptConfigSaver::SavePromptConfig(bool dump_now) {
  (void)dump_now;
  prompt_manager_.FlushHistory();
  return Ok();
}

/**
 * @brief Construct client-session gateway from filesystem manager.
 */
ClientSessionGateway::ClientSessionGateway(AMDomain::filesystem::AMFileSystem &filesystem)
    : filesystem_(filesystem) {}

/**
 * @brief Connect one configured nickname.
 */
ECM ClientSessionGateway::ConnectNickname(const std::string &nickname,
                                          bool force, bool switch_client,
                                          amf interrupt_flag) {
  return filesystem_.connect(nickname, force, interrupt_flag, switch_client);
}

/**
 * @brief Change current active client nickname.
 */
ECM ClientSessionGateway::ChangeCurrentClient(const std::string &nickname,
                                              amf interrupt_flag) {
  return filesystem_.change_client(nickname, interrupt_flag);
}

/**
 * @brief Connect one SFTP target.
 */
ECM ClientSessionGateway::ConnectSftp(const std::string &nickname,
                                      const std::string &user_at_host,
                                      int64_t port,
                                      const std::string &password,
                                      const std::string &keyfile,
                                      amf interrupt_flag) {
  return filesystem_.sftp(nickname, user_at_host, port, password, keyfile,
                          interrupt_flag);
}

/**
 * @brief Connect one FTP target.
 */
ECM ClientSessionGateway::ConnectFtp(const std::string &nickname,
                                     const std::string &user_at_host,
                                     int64_t port, const std::string &password,
                                     const std::string &keyfile,
                                     amf interrupt_flag) {
  return filesystem_.ftp(nickname, user_at_host, port, password, keyfile,
                         interrupt_flag);
}

/**
 * @brief Print current client table.
 */
ECM ClientSessionGateway::ListClients(bool detail, amf interrupt_flag) {
  return filesystem_.print_clients(detail, interrupt_flag);
}

/**
 * @brief Remove one or more clients by nickname list.
 */
ECM ClientSessionGateway::DisconnectClients(
    const std::vector<std::string> &nicknames) {
  std::string joined;
  for (size_t i = 0; i < nicknames.size(); ++i) {
    if (i > 0) {
      joined += " ";
    }
    joined += nicknames[i];
  }
  return filesystem_.remove_client(joined);
}

/**
 * @brief Print stat info for one or more resolved paths.
 */
ECM ClientSessionGateway::StatPaths(const std::vector<std::string> &paths,
                                    amf interrupt_flag) {
  return filesystem_.stat(paths, interrupt_flag);
}

/**
 * @brief List directory entries for one resolved path.
 */
ECM ClientSessionGateway::ListPath(const std::string &path, bool list_like,
                                   bool show_all, amf interrupt_flag) {
  return filesystem_.ls(path, list_like, show_all, interrupt_flag);
}

/**
 * @brief Construct filesystem command gateway from filesystem manager.
 */
FileCommandGateway::FileCommandGateway(AMDomain::filesystem::AMFileSystem &filesystem)
    : filesystem_(filesystem) {}

/**
 * @brief Check clients by nickname list.
 */
ECM FileCommandGateway::CheckClients(const std::vector<std::string> &nicknames,
                                     bool detail, amf interrupt_flag) {
  return filesystem_.check(nicknames, detail, interrupt_flag);
}

/**
 * @brief Print current clients.
 */
ECM FileCommandGateway::ListClients(bool detail, amf interrupt_flag) {
  return filesystem_.print_clients(detail, interrupt_flag);
}

/**
 * @brief Disconnect clients by nickname list.
 */
ECM FileCommandGateway::DisconnectClients(
    const std::vector<std::string> &nicknames) {
  return filesystem_.remove_client(JoinNicknames_(nicknames));
}

/**
 * @brief Print stat for one or more paths.
 */
ECM FileCommandGateway::StatPaths(const std::vector<std::string> &paths,
                                  amf interrupt_flag, int timeout_ms) {
  return filesystem_.stat(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief List one path.
 */
ECM FileCommandGateway::ListPath(const std::string &path, bool list_like,
                                 bool show_all, amf interrupt_flag,
                                 int timeout_ms) {
  return filesystem_.ls(path, list_like, show_all, interrupt_flag, timeout_ms);
}

/**
 * @brief Print size for one or more paths.
 */
ECM FileCommandGateway::GetSize(const std::vector<std::string> &paths,
                                amf interrupt_flag, int timeout_ms) {
  return filesystem_.getsize(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief Run find on one path.
 */
ECM FileCommandGateway::Find(const std::string &path, SearchType type,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_.find(path, type, interrupt_flag, timeout_ms);
}

/**
 * @brief Create directories for one or more paths.
 */
ECM FileCommandGateway::Mkdir(const std::vector<std::string> &paths,
                              amf interrupt_flag, int timeout_ms) {
  return filesystem_.mkdir(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief Remove one or more paths.
 */
ECM FileCommandGateway::Remove(const std::vector<std::string> &paths,
                               bool permanent, bool force, bool quiet,
                               amf interrupt_flag, int timeout_ms) {
  return filesystem_.rm(paths, permanent, force, quiet, interrupt_flag,
                        timeout_ms);
}

/**
 * @brief Walk one path.
 */
ECM FileCommandGateway::Walk(const std::string &path, bool only_file,
                             bool only_dir, bool show_all,
                             bool ignore_special_file, bool quiet,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_.walk(path, only_file, only_dir, show_all,
                          ignore_special_file, quiet, interrupt_flag,
                          timeout_ms);
}

/**
 * @brief Print one path tree.
 */
ECM FileCommandGateway::Tree(const std::string &path, int max_depth,
                             bool only_dir, bool show_all,
                             bool ignore_special_file, bool quiet,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_.tree(path, max_depth, only_dir, show_all,
                          ignore_special_file, quiet, interrupt_flag,
                          timeout_ms);
}

/**
 * @brief Resolve one real path.
 */
ECM FileCommandGateway::Realpath(const std::string &path, amf interrupt_flag,
                                 int timeout_ms) {
  return filesystem_.realpath(path, interrupt_flag, timeout_ms);
}

/**
 * @brief Measure RTT for current client.
 */
ECM FileCommandGateway::TestRtt(int times, amf interrupt_flag) {
  return filesystem_.TestRTT(times, interrupt_flag);
}

/**
 * @brief Change current workdir.
 */
ECM FileCommandGateway::Cd(const std::string &path, amf interrupt_flag,
                           bool from_history) {
  return filesystem_.cd(path, interrupt_flag, from_history);
}

/**
 * @brief Run one shell command.
 */
std::pair<ECM, std::pair<std::string, int>>
FileCommandGateway::ShellRun(const std::string &cmd, int max_time_ms,
                             amf interrupt_flag) {
  return filesystem_.ShellRun(cmd, max_time_ms, interrupt_flag);
}

/**
 * @brief Join nicknames for legacy remove-client API.
 */
std::string
FileCommandGateway::JoinNicknames_(const std::vector<std::string> &nicknames) const {
  std::string joined;
  for (size_t i = 0; i < nicknames.size(); ++i) {
    if (i > 0) {
      joined += " ";
    }
    joined += nicknames[i];
  }
  return joined;
}

/**
 * @brief Construct path-substitution port from var manager.
 */
PathSubstitutionPort::PathSubstitutionPort(AMDomain::var::VarCLISet &var_manager)
    : var_manager_(var_manager) {}

/**
 * @brief Substitute one path-like token.
 */
std::string PathSubstitutionPort::SubstitutePathLike(
    const std::string &raw) const {
  return var_manager_.SubstitutePathLike(raw);
}

/**
 * @brief Substitute path-like tokens in one vector.
 */
std::vector<std::string>
PathSubstitutionPort::SubstitutePathLike(
    const std::vector<std::string> &raw) const {
  std::vector<std::string> out = raw;
  var_manager_.SubstitutePathLike(&out);
  return out;
}

/**
 * @brief Construct variable gateway from var manager.
 */
VarGateway::VarGateway(AMDomain::var::VarCLISet &var_manager) : var_manager_(var_manager) {}

/**
 * @brief Substitute one path-like token.
 */
std::string VarGateway::SubstitutePathLike(const std::string &raw) const {
  return var_manager_.SubstitutePathLike(raw);
}

/**
 * @brief Substitute path-like tokens in one vector.
 */
std::vector<std::string>
VarGateway::SubstitutePathLike(const std::vector<std::string> &raw) const {
  std::vector<std::string> out = raw;
  var_manager_.SubstitutePathLike(&out);
  return out;
}

/**
 * @brief Query one variable by token name.
 */
ECM VarGateway::QueryByName(const std::string &token_name) const {
  return var_manager_.QueryByName(token_name);
}

/**
 * @brief Define one variable.
 */
ECM VarGateway::DefineVar(bool global, const std::string &name,
                          const std::string &value) const {
  return var_manager_.DefineVar(global, name, value);
}

/**
 * @brief Delete one variable by CLI args.
 */
ECM VarGateway::DeleteVarByCli(bool all, const std::string &section,
                               const std::string &varname) const {
  return var_manager_.DeleteVarByCli(all, section, varname);
}

/**
 * @brief List variables by domain filters.
 */
ECM VarGateway::ListVars(const std::vector<std::string> &domains) const {
  return var_manager_.ListVars(domains);
}

/**
 * @brief Return true when an active completer instance exists.
 */
bool CompletionGateway::HasActiveCompleter() const {
  return AMCompleter::Active() != nullptr;
}

/**
 * @brief Clear active completer cache.
 */
void CompletionGateway::ClearActiveCompleterCache() const {
  AMCompleter *completer = AMCompleter::Active();
  if (completer) {
    completer->ClearCache();
  }
}

/**
 * @brief Construct transfer executor from transfer manager.
 */
TransferExecutorPort::TransferExecutorPort(AMDomain::transfer::AMTransferManager &transfer_manager)
    : transfer_manager_(transfer_manager) {}

/**
 * @brief Execute transfer sets synchronously.
 */
ECM TransferExecutorPort::Transfer(const std::vector<UserTransferSet> &transfer_sets,
                                   bool quiet, amf interrupt_flag) {
  return transfer_manager_.transfer(transfer_sets, quiet, interrupt_flag);
}

/**
 * @brief Execute transfer sets asynchronously.
 */
ECM TransferExecutorPort::TransferAsync(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    amf interrupt_flag) {
  return transfer_manager_.transfer_async(transfer_sets, quiet, interrupt_flag);
}

/**
 * @brief Construct task gateway from transfer manager.
 */
TaskGateway::TaskGateway(AMDomain::transfer::AMTransferManager &transfer_manager)
    : transfer_manager_(transfer_manager) {}

/**
 * @brief List task states.
 */
ECM TaskGateway::ListTasks(bool pending, bool suspend, bool finished,
                           bool conducting, amf interrupt_flag) {
  return transfer_manager_.List(pending, suspend, finished, conducting,
                                interrupt_flag);
}

/**
 * @brief Show one or more tasks.
 */
ECM TaskGateway::ShowTasks(const std::vector<std::string> &ids,
                           amf interrupt_flag) {
  return transfer_manager_.Show(ids, interrupt_flag);
}

/**
 * @brief Inspect one task.
 */
ECM TaskGateway::InspectTask(const std::string &id, bool show_sets,
                             bool show_entries) {
  return transfer_manager_.Inspect(id, show_sets, show_entries);
}

/**
 * @brief Inspect transfer sets of one task.
 */
ECM TaskGateway::InspectTaskSets(const std::string &id) {
  return transfer_manager_.InspectTransferSets(id);
}

/**
 * @brief Inspect entries of one task.
 */
ECM TaskGateway::InspectTaskEntries(const std::string &id) {
  return transfer_manager_.InspectTaskEntries(id);
}

/**
 * @brief Query one task entry by id.
 */
ECM TaskGateway::QueryTaskEntry(const std::string &entry_id) {
  return transfer_manager_.QuerySetEntry(entry_id);
}

/**
 * @brief Query or set worker thread count.
 */
ECM TaskGateway::Thread(int num) { return transfer_manager_.Thread(num); }

/**
 * @brief Terminate tasks by ids.
 */
ECM TaskGateway::TerminateTasks(const std::vector<std::string> &ids) {
  return transfer_manager_.Terminate(ids);
}

/**
 * @brief Pause tasks by ids.
 */
ECM TaskGateway::PauseTasks(const std::vector<std::string> &ids) {
  return transfer_manager_.Pause(ids);
}

/**
 * @brief Resume tasks by ids.
 */
ECM TaskGateway::ResumeTasks(const std::vector<std::string> &ids) {
  return transfer_manager_.Resume(ids);
}

/**
 * @brief Retry a finished task.
 */
ECM TaskGateway::RetryTask(const std::string &id, bool is_async, bool quiet,
                           const std::vector<int> &indices) {
  return transfer_manager_.retry(id, is_async, quiet, indices);
}

/**
 * @brief Add one transfer set to cache.
 */
size_t TaskGateway::AddCachedTransferSet(const UserTransferSet &transfer_set) {
  return transfer_manager_.SubmitTransferSet(transfer_set);
}

/**
 * @brief Remove cached transfer sets.
 */
size_t
TaskGateway::RemoveCachedTransferSets(const std::vector<size_t> &indices) {
  return transfer_manager_.DeleteTransferSets(indices);
}

/**
 * @brief Clear all cached transfer sets.
 */
void TaskGateway::ClearCachedTransferSets() {
  transfer_manager_.ClearCachedTransferSets();
}

/**
 * @brief Submit cached transfer sets.
 */
ECM TaskGateway::SubmitCachedTransferSets(bool quiet, amf interrupt_flag,
                                          bool is_async) {
  return transfer_manager_.SubmitCachedTransferSets(quiet, interrupt_flag,
                                                    is_async);
}

/**
 * @brief Query one cached transfer set.
 */
ECM TaskGateway::QueryCachedTransferSet(size_t index) {
  return transfer_manager_.QueryCachedUserSet(index);
}

/**
 * @brief List cached transfer set ids.
 */
std::vector<size_t> TaskGateway::ListCachedTransferSetIds() const {
  return transfer_manager_.ListTransferSetIds();
}

} // namespace AMInterface::ApplicationAdapters
