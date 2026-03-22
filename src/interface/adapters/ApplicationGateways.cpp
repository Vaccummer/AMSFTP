#include "interface/adapters/ApplicationAdapters.hpp"
#include "interface/completion/Proxy.hpp"
#include "interface/prompt/Prompt.hpp"
#include "application/client/ClientAppService.hpp"
#include "infrastructure/controller/ClientControlTokenAdapter.hpp"
#include "application/config/ConfigPayloads.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/json.hpp"
#include "domain/host/HostManager.hpp"
#include "application/transfer/TransferAppService.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <tuple>
#include <unordered_set>

namespace AMInterface::ApplicationAdapters {
namespace {
using AMDomain::host::ClientProtocol;
using AMDomain::host::HostConfig;
using AMDomain::config::DocumentKind;
namespace configkn = AMDomain::host;

bool ParseBool_(const std::string &text, bool *out) {
  if (!out) {
    return false;
  }
  const std::string normalized = AMStr::lowercase(AMStr::Strip(text));
  if (normalized == "true" || normalized == "1" || normalized == "yes" ||
      normalized == "on") {
    *out = true;
    return true;
  }
  if (normalized == "false" || normalized == "0" || normalized == "no" ||
      normalized == "off") {
    *out = false;
    return true;
  }
  return false;
}

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

AMDomain::client::amf ToClientInterrupt_(const amf &interrupt_flag) {
  return AMInfra::controller::AdaptClientInterruptFlag(interrupt_flag);
}
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
  const AMInterface::style::StyleIndex style_index =
      created ? AMInterface::style::StyleIndex::Nickname
              : AMInterface::style::StyleIndex::UnestablishedNickname;
  return Runtime::Format(nickname, style_index);
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
  if (!ParseBool_(input, &parsed)) {
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
    if (!ParseInt64_(text, &parsed)) {
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
  if (!ParseInt64_(input, &parsed)) {
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
                         AMDomain::host::AMHostConfigManager &host_config_manager,
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
    if (host_config_manager.HostExists(normalized)) {
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
 * @brief Construct host/profile gateway from host config and prompt services.
 */
HostProfileGateway::HostProfileGateway(AMDomain::host::AMHostConfigManager &host_config_manager,
                                       AMPromptManager &prompt_manager)
    : host_config_manager_(host_config_manager), prompt_manager_(prompt_manager) {}

/**
 * @brief Return whether one host nickname exists.
 */
bool HostProfileGateway::HostExists(const std::string &nickname) const {
  return host_config_manager_.HostExists(nickname);
}

/**
 * @brief List hosts using host manager CLI surface.
 */
ECM HostProfileGateway::ListHosts(bool detail) {
  const std::vector<std::string> nicknames = host_config_manager_.ListNames();
  if (!detail) {
    PrintHostCompact_(prompt_manager_, nicknames);
    return Ok();
  }
  if (nicknames.empty()) {
    prompt_manager_.Print("");
    return Ok();
  }
  for (const auto &nickname : nicknames) {
    auto [rcm, entry] = host_config_manager_.GetClientConfig(nickname);
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
  const std::vector<std::string> keys = host_config_manager_.PrivateKeys();
  if (!detail) {
    return Ok();
  }
  prompt_manager_.Print("[SSH Private Keys]");
  for (size_t i = 0; i < keys.size(); ++i) {
    const std::string abs_path = AMFS::abspath(keys[i], true, AMFS::HomePath());
    auto [stat_rcm, info] = AMFS::stat(abs_path, false);
    const PathInfo *info_ptr = isok(stat_rcm) ? &info : nullptr;
    const std::string styled_path =
        Runtime::Format(abs_path, AMInterface::style::StyleIndex::None, info_ptr);
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
                   Runtime::Format(config_path, AMInterface::style::StyleIndex::None,
                                   info_ptr)));
  }
  if (Runtime::GetConfigDataPath(DocumentKind::Settings, &settings_path_obj)) {
    const std::string settings_path = settings_path_obj.string();
    auto [rcm, info] = AMFS::stat(settings_path, false);
    const PathInfo *info_ptr = isok(rcm) ? &info : nullptr;
    prompt_manager_.Print(
        AMStr::fmt("{} = {}", settings_label,
                   Runtime::Format(settings_path,
                                   AMInterface::style::StyleIndex::None,
                                   info_ptr)));
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
    auto [rcm, entry] = host_config_manager_.GetClientConfig(nickname);
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
      PromptAddHostConfig_(prompt_manager_, host_config_manager_, nickname, &entry);
  if (!isok(prompt_rcm)) {
    return prompt_rcm;
  }
  return host_config_manager_.AddHost(entry, true);
}

/**
 * @brief Edit one host entry.
 */
ECM HostProfileGateway::EditHost(const std::string &nickname) {
  auto [get_rcm, entry] = host_config_manager_.GetClientConfig(nickname);
  if (!isok(get_rcm)) {
    return get_rcm;
  }
  ECM prompt_rcm = PromptEditHostConfig_(prompt_manager_, nickname, &entry);
  if (!isok(prompt_rcm)) {
    return prompt_rcm;
  }
  return host_config_manager_.AddHost(entry, true);
}

/**
 * @brief Rename one host entry.
 */
ECM HostProfileGateway::RenameHost(const std::string &old_name,
                                   const std::string &new_name) {
  return host_config_manager_.Rename(old_name, new_name);
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
    if (!host_config_manager_.HostExists(nickname)) {
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
  return host_config_manager_.Delete(targets);
}

/**
 * @brief Set one host attribute value.
 */
ECM HostProfileGateway::SetHostValue(const std::string &nickname,
                                     const std::string &attrname,
                                     const std::string &value) {
  const std::string field = AMStr::lowercase(AMStr::Strip(attrname));
  auto [before_rcm, before] = host_config_manager_.GetClientConfig(nickname);
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
  ECM rcm = host_config_manager_.SetHostValue(nickname, attrname, resolved_value);
  if (!isok(rcm)) {
    return rcm;
  }

  auto [after_rcm, after] = host_config_manager_.GetClientConfig(nickname);
  const std::string new_value =
      isok(after_rcm) ? HostFieldDisplay_(after, field) : resolved_value;
  prompt_manager_.Print(
      AMStr::fmt("{}.{}: {} -> {}", nickname, field, old_value, new_value));
  return Ok();
}

/**
 * @brief Persist host configuration.
 */
ECM HostProfileGateway::SaveHosts() { return host_config_manager_.Save(); }

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
  return host_config_manager_.ListNames();
}

/**
 * @brief Construct current-client reader from client app service.
 */
CurrentClientPort::CurrentClientPort(
    AMApplication::client::ClientAppService &client_service)
    : client_service_(client_service) {}

/**
 * @brief Return the active client nickname.
 */
std::string CurrentClientPort::CurrentNickname() const {
  return client_service_.CurrentNickname();
}

/**
 * @brief Construct repository from config app service.
 */
ConfigBackedVarRepository::ConfigBackedVarRepository(
    AMApplication::config::AMConfigAppService &config_service)
    : config_service_(config_service) {}

/**
 * @brief Load variable state from settings into a domain dictionary.
 */
ECM ConfigBackedVarRepository::Load(
    AMDomain::var::VarDomainService::DomainDict *out_vars) {
  if (!out_vars) {
    return Err(EC::InvalidArg, "null variable dictionary output");
  }

  AMApplication::config::UserVarsSnapshot snapshot = {};
  (void)config_service_.Read(&snapshot);

  out_vars->clear();
  for (const auto &[domain, vars] : snapshot.domains) {
    auto &domain_vars = (*out_vars)[domain];
    for (const auto &[name, value] : vars) {
      domain_vars[name] = value;
    }
  }
  if (out_vars->find(varsetkn::kPublic) == out_vars->end()) {
    (*out_vars)[varsetkn::kPublic] = {};
  }
  return Ok();
}

/**
 * @brief Save variable state into settings-backed storage.
 */
ECM ConfigBackedVarRepository::Save(
    const AMDomain::var::VarDomainService::DomainDict &vars, bool async) {
  AMApplication::config::UserVarsSnapshot snapshot = {};
  for (const auto &[domain, domain_vars] : vars) {
    auto &out_vars = snapshot.domains[domain];
    for (const auto &[name, value] : domain_vars) {
      out_vars[name] = value;
    }
  }

  if (!config_service_.Write(snapshot)) {
    return Err(EC::CommonFailure, "failed to write UserVars into settings");
  }
  return config_service_.Dump(DocumentKind::Settings, "", async);
}

/**
 * @brief Construct provider from client app service.
 */
CurrentVarDomainProvider::CurrentVarDomainProvider(
    AMApplication::client::ClientAppService &client_service)
    : client_service_(client_service) {}

/**
 * @brief Return the active var domain with local fallback.
 */
std::string CurrentVarDomainProvider::CurrentDomain() const {
  std::string domain = AMStr::Strip(client_service_.CurrentNickname());
  if (domain.empty()) {
    domain = "local";
  }
  return domain;
}

/**
 * @brief Construct path helper from client app service.
 */
ClientPathGateway::ClientPathGateway(
    AMApplication::client::ClientAppService &client_service)
    : client_service_(client_service) {}

/**
 * @brief Return current workdir or empty string when unavailable.
 */
std::string ClientPathGateway::CurrentWorkdir() const {
  auto client = client_service_.GetCurrentClient();
  if (!client) {
    return "";
  }
  return client_service_.GetOrInitWorkdir(client);
}

/**
 * @brief Construct host config saver from host manager.
 */
HostConfigSaver::HostConfigSaver(AMDomain::host::AMHostConfigManager &host_config_manager)
    : host_config_manager_(host_config_manager) {}

/**
 * @brief Persist host configuration state.
 */
ECM HostConfigSaver::SaveHostConfig() { return host_config_manager_.Save(); }

/**
 * @brief Construct var config saver from var app service.
 */
VarConfigSaver::VarConfigSaver(AMApplication::VarWorkflow::VarAppService &var_service)
    : var_service_(var_service) {}

/**
 * @brief Persist variable state.
 *
 * `dump_now=true` maps to synchronous save.
 */
ECM VarConfigSaver::SaveVarConfig(bool dump_now) {
  return var_service_.SaveVars(!dump_now);
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
 * @brief Construct client-session gateway from client app service.
 */
ClientSessionGateway::ClientSessionGateway(
    AMApplication::client::ClientAppService &client_service)
    : client_service_(client_service) {}

/**
 * @brief Connect one configured nickname.
 */
ECM ClientSessionGateway::ConnectNickname(const std::string &nickname,
                                          bool force, bool switch_client,
                                          amf interrupt_flag) {
  const AMDomain::client::amf client_interrupt =
      ToClientInterrupt_(interrupt_flag);
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(client_interrupt);
  AMDomain::client::ClientConnectOptions options{};
  options.force = force;
  options.register_to_manager = true;
  auto [rcm, client] =
      client_service_.ConnectNickname(nickname, options, {}, control);
  if (!isok(rcm)) {
    return rcm;
  }
  if (switch_client) {
    client_service_.SetCurrentClient(client);
  }
  return Ok();
}

/**
 * @brief Change current active client nickname.
 */
ECM ClientSessionGateway::ChangeCurrentClient(const std::string &nickname,
                                              amf interrupt_flag) {
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(
          ToClientInterrupt_(interrupt_flag));
  auto [rcm, client] =
      client_service_.EnsureClient(nickname, control);
  if (!isok(rcm)) {
    return rcm;
  }
  client_service_.SetCurrentClient(client);
  return Ok();
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
  const AMDomain::client::amf client_interrupt =
      ToClientInterrupt_(interrupt_flag);
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(client_interrupt);
  const size_t at_pos = user_at_host.find('@');
  if (at_pos == std::string::npos || at_pos == 0 ||
      at_pos + 1 >= user_at_host.size()) {
    return Err(EC::InvalidArg, "Invalid user@host format");
  }
  AMDomain::client::ClientConnectContext context{};
  context.request.nickname = nickname;
  context.request.username = user_at_host.substr(0, at_pos);
  context.request.hostname = user_at_host.substr(at_pos + 1);
  context.request.protocol = ClientProtocol::SFTP;
  context.request.port = port;
  context.request.password = password;
  context.request.keyfile = keyfile;
  auto [rcm, client] =
      client_service_.ConnectRequest(context, {}, control);
  if (!isok(rcm)) {
    return rcm;
  }
  client_service_.SetCurrentClient(client);
  return Ok();
}

/**
 * @brief Connect one FTP target.
 */
ECM ClientSessionGateway::ConnectFtp(const std::string &nickname,
                                     const std::string &user_at_host,
                                     int64_t port, const std::string &password,
                                     const std::string &keyfile,
                                     amf interrupt_flag) {
  const AMDomain::client::amf client_interrupt =
      ToClientInterrupt_(interrupt_flag);
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(client_interrupt);
  const size_t at_pos = user_at_host.find('@');
  if (at_pos == std::string::npos || at_pos == 0 ||
      at_pos + 1 >= user_at_host.size()) {
    return Err(EC::InvalidArg, "Invalid user@host format");
  }
  AMDomain::client::ClientConnectContext context{};
  context.request.nickname = nickname;
  context.request.username = user_at_host.substr(0, at_pos);
  context.request.hostname = user_at_host.substr(at_pos + 1);
  context.request.protocol = ClientProtocol::FTP;
  context.request.port = port;
  context.request.password = password;
  context.request.keyfile = keyfile;
  auto [rcm, client] =
      client_service_.ConnectRequest(context, {}, control);
  if (!isok(rcm)) {
    return rcm;
  }
  client_service_.SetCurrentClient(client);
  return Ok();
}

/**
 * @brief Print current client table.
 */
ECM ClientSessionGateway::ListClients(bool detail, amf interrupt_flag) {
  const AMDomain::client::amf client_interrupt =
      ToClientInterrupt_(interrupt_flag);
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(client_interrupt);
  if (interrupt_flag && !interrupt_flag->IsRunning()) {
    return Err(EC::Terminate, "Interrupted by user");
  }

  const std::vector<std::string> names = client_service_.GetClientNames();
  if (names.empty()) {
    return Err(EC::ClientNotFound, "No client found");
  }

  ECM status = Ok();
  std::ostringstream report;
  for (const auto &name : names) {
    if (interrupt_flag && !interrupt_flag->IsRunning()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    const auto check_result =
        client_service_.CheckClient(name, false, detail, control);
    const ECM &check_rcm = check_result.rcm;
    if (!isok(check_rcm)) {
      status = check_rcm;
      report << name << " : " << check_rcm.second << '\n';
      continue;
    }
    report << name << '\n';
  }
  if (isok(status)) {
    return {EC::Success, report.str()};
  }
  return status;
}

/**
 * @brief Remove one or more clients by nickname list.
 */
ECM ClientSessionGateway::DisconnectClients(
    const std::vector<std::string> &nicknames) {
  ECM last = Ok();
  for (const auto &nickname : nicknames) {
    ECM rcm = client_service_.RemoveClient(nickname);
    if (!isok(rcm)) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Print stat info for one or more resolved paths.
 */
ECM ClientSessionGateway::StatPaths(const std::vector<std::string> &paths,
                                    amf interrupt_flag) {
  const AMDomain::client::amf client_interrupt =
      ToClientInterrupt_(interrupt_flag);
  if (paths.empty()) {
    return Err(EC::InvalidArg, "No path is given");
  }
  ECM status = Ok();
  for (const auto &raw : paths) {
    const auto parsed = client_service_.ParseScopedPath(raw, client_interrupt);
    const ECM parse_rcm = std::get<3>(parsed);
    if (!isok(parse_rcm)) {
      status = parse_rcm;
      continue;
    }
    std::string nickname = std::get<0>(parsed);
    std::string path = std::get<1>(parsed);
    AMDomain::client::ClientHandle client = std::get<2>(parsed);
    if (!client) {
      client = nickname.empty() ? client_service_.GetCurrentClient()
                                : client_service_.GetClient(nickname);
    }
    if (!client && nickname.empty()) {
      client = client_service_.GetLocalClient();
    }
    if (!client) {
      status = Err(EC::ClientNotFound, "Resolved client is null");
      continue;
    }
    if (path.empty()) {
      path = ".";
    }
    const std::string abs_path = client_service_.BuildAbsolutePath(client, path);
    auto [rcm, _info] =
        client->IOPort().stat(abs_path, false, -1, -1, client_interrupt);
    if (!isok(rcm)) {
      status = rcm;
    }
  }
  return status;
}

/**
 * @brief List directory entries for one resolved path.
 */
ECM ClientSessionGateway::ListPath(const std::string &path, bool list_like,
                                   bool show_all, amf interrupt_flag) {
  (void)list_like;
  const AMDomain::client::amf client_interrupt =
      ToClientInterrupt_(interrupt_flag);
  const std::string token = path.empty() ? "." : path;
  const auto parsed = client_service_.ParseScopedPath(token, client_interrupt);
  const ECM parse_rcm = std::get<3>(parsed);
  if (!isok(parse_rcm)) {
    return parse_rcm;
  }
  std::string nickname = std::get<0>(parsed);
  std::string resolved = std::get<1>(parsed);
  AMDomain::client::ClientHandle client = std::get<2>(parsed);
  if (!client) {
    client = nickname.empty() ? client_service_.GetCurrentClient()
                              : client_service_.GetClient(nickname);
  }
  if (!client && nickname.empty()) {
    client = client_service_.GetLocalClient();
  }
  if (!client) {
    return Err(EC::ClientNotFound, "Resolved client is null");
  }
  if (resolved.empty()) {
    resolved = ".";
  }
  const std::string abs_path = client_service_.BuildAbsolutePath(client, resolved);
  auto [stat_rcm, stat_info] =
      client->IOPort().stat(abs_path, false, -1, -1, client_interrupt);
  if (!isok(stat_rcm)) {
    return stat_rcm;
  }
  if (stat_info.type != PathType::DIR) {
    return Ok();
  }
  auto [list_rcm, entries] =
      client->IOPort().listdir(abs_path, -1, -1, client_interrupt);
  if (!isok(list_rcm)) {
    return list_rcm;
  }
  if (!show_all) {
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
                       [](const PathInfo &item) {
                         return item.name == "." || item.name == "..";
                       }),
        entries.end());
  }
  return Ok();
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
 * @brief Construct transfer executor from transfer app service.
 */
TransferExecutorPort::TransferExecutorPort(
    AMApplication::TransferWorkflow::TransferAppService &transfer_service,
    AMPromptManager &prompt_manager,
    AMApplication::TransferWorkflow::TransferConfirmPolicy confirm_policy,
    AMDomain::client::amf task_control_token)
    : transfer_service_(transfer_service), prompt_manager_(&prompt_manager),
      confirm_policy_(confirm_policy),
      task_control_token_(std::move(task_control_token)) {}

namespace {
/**
 * @brief Convert task status enum to stable display text.
 */
const char *TaskStatusText_(TaskStatus status) {
  switch (status) {
  case TaskStatus::Pending:
    return "Pending";
  case TaskStatus::Conducting:
    return "Conducting";
  case TaskStatus::Paused:
    return "Paused";
  case TaskStatus::Finished:
    return "Finished";
  default:
    return "Unknown";
  }
}

/**
 * @brief Convert transfer path type to display text.
 */
const char *PathTypeText_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return "FILE";
  case PathType::DIR:
    return "DIR";
  default:
    return "OTHER";
  }
}

/**
 * @brief Convert nickname to display host text with local fallback.
 */
std::string DisplayHost_(const std::string &nickname) {
  return nickname.empty() ? std::string("local") : nickname;
}

/**
 * @brief Render transfer endpoint in `nick@path` form.
 */
std::string RenderEndpoint_(const AMDomain::filesystem::ClientPath &endpoint) {
  return AMStr::fmt("{}@{}", DisplayHost_(endpoint.nickname), endpoint.path);
}

/**
 * @brief Parse entry id in `<task_id>:<1-based-index>` format.
 */
bool ParseEntryId_(const std::string &entry_id, std::string *task_id,
                   size_t *entry_index) {
  if (!task_id || !entry_index) {
    return false;
  }
  const size_t pos = entry_id.find(':');
  if (pos == std::string::npos || pos == 0 || pos + 1 >= entry_id.size()) {
    return false;
  }
  const std::string id_part = entry_id.substr(0, pos);
  const std::string index_part = entry_id.substr(pos + 1);
  try {
    const size_t parsed = static_cast<size_t>(std::stoul(index_part));
    if (parsed == 0) {
      return false;
    }
    *task_id = id_part;
    *entry_index = parsed;
    return true;
  } catch (...) {
    return false;
  }
}

/**
 * @brief Render one transfer set with current CLI output style.
 */
void PrintTransferSet_(AMPromptManager &prompt,
                       const AMApplication::TransferWorkflow::TransferSetView &set) {
  for (const auto &src : set.srcs) {
    prompt.Print(RenderEndpoint_(src));
  }
  prompt.FmtPrint(" ->  {}", RenderEndpoint_(set.dst));
  prompt.FmtPrint("clone = {}", set.clone ? "true" : "false");
  prompt.FmtPrint("mkdir = {}", set.mkdir ? "true" : "false");
  prompt.FmtPrint("overwrite = {}", set.overwrite ? "true" : "false");
  prompt.FmtPrint("no special = {}", set.ignore_special_file ? "true" : "false");
  prompt.FmtPrint("resume = {}", set.resume ? "true" : "false");
}

/**
 * @brief Build wildcard confirmation callback based on explicit policy.
 */
AMApplication::TransferWorkflow::TransferAppService::WildcardConfirmFn
BuildWildcardConfirmFn_(
    AMPromptManager *prompt,
    AMApplication::TransferWorkflow::TransferConfirmPolicy confirm_policy) {
  if (!prompt ||
      confirm_policy !=
          AMApplication::TransferWorkflow::TransferConfirmPolicy::
              RequireConfirm) {
    return {};
  }
  return [prompt](const std::vector<PathInfo> &matches,
                  const std::string &src_host, const std::string &dst_host) {
    if (!prompt || matches.empty()) {
      return false;
    }
    const std::string host_name = src_host.empty() ? "local" : src_host;
    const std::string dst_name = dst_host.empty() ? "local" : dst_host;
    prompt->FmtPrint("Found {} paths to transfer", std::to_string(matches.size()));

    std::vector<PathInfo> sorted = matches;
    std::sort(sorted.begin(), sorted.end(),
              [](const PathInfo &lhs, const PathInfo &rhs) {
                return lhs.type == PathType::DIR && rhs.type != PathType::DIR;
              });
    for (const auto &path : sorted) {
      if (path.type == PathType::DIR) {
        prompt->FmtPrint("📁   {}@{}", host_name, path.path);
      } else {
        prompt->FmtPrint("📑   {}@{}", host_name, path.path);
      }
    }

    bool canceled = false;
    const bool accepted = prompt->PromptYesNo(
        AMStr::fmt("Are you sure to transfer these paths to {}? (y/N): ",
                   dst_name),
        &canceled);
    return accepted && !canceled;
  };
}
} // namespace

/**
 * @brief Execute transfer sets synchronously.
 */
ECM TransferExecutorPort::Transfer(const std::vector<UserTransferSet> &transfer_sets,
                                   bool quiet) {
  std::vector<ECM> warnings = {};
  AMApplication::TransferWorkflow::TransferAppService::WildcardConfirmFn confirm =
      BuildWildcardConfirmFn_(prompt_manager_, confirm_policy_);
  ECM rcm = transfer_service_.TransferWithControl(
      transfer_sets, quiet, task_control_token_, confirm_policy_, confirm,
      &warnings);
  if (prompt_manager_) {
    for (const auto &warning : warnings) {
      prompt_manager_->ErrorFormat(warning);
    }
  }
  return rcm;
}

/**
 * @brief Execute transfer sets asynchronously.
 */
ECM TransferExecutorPort::TransferAsync(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet) {
  std::vector<ECM> warnings = {};
  AMApplication::TransferWorkflow::TransferAppService::WildcardConfirmFn confirm =
      BuildWildcardConfirmFn_(prompt_manager_, confirm_policy_);
  ECM rcm = transfer_service_.TransferAsyncWithControl(
      transfer_sets, quiet, task_control_token_, confirm_policy_, confirm,
      &warnings);
  if (prompt_manager_) {
    for (const auto &warning : warnings) {
      prompt_manager_->ErrorFormat(warning);
    }
  }
  return rcm;
}

/**
 * @brief Construct task gateway from transfer app service.
 */
TaskGateway::TaskGateway(
    AMApplication::TransferWorkflow::TransferAppService &transfer_service,
    AMPromptManager &prompt_manager,
    AMDomain::client::amf task_control_token)
    : transfer_service_(transfer_service), prompt_manager_(&prompt_manager),
      task_control_token_(std::move(task_control_token)) {}

/**
 * @brief Print compact task summary line.
 */
void TaskGateway::PrintTaskSummary_(
    const AMApplication::TransferWorkflow::TaskSummaryView &task_summary,
    bool verbose) const {
  if (!prompt_manager_) {
    return;
  }
  prompt_manager_->FmtPrint("Task {} [{}] files {}/{} size {}/{} result {} {}",
                            task_summary.id,
                            TaskStatusText_(task_summary.status),
                            std::to_string(task_summary.success_filenum),
                            std::to_string(task_summary.filenum),
                            AMStr::FormatSize(task_summary.total_transferred_size),
                            AMStr::FormatSize(task_summary.total_size),
                            AMStr::ToString(task_summary.result.first),
                            task_summary.result.second);
  if (!verbose) {
    return;
  }
  prompt_manager_->FmtPrint(
      "  submit={} start={} finish={} thread={}",
      std::to_string(task_summary.submit_time),
      std::to_string(task_summary.start_time),
      std::to_string(task_summary.finished_time),
      std::to_string(task_summary.running_thread));
}

/**
 * @brief Print transfer entry details for one task.
 */
void TaskGateway::PrintTaskEntries_(
    const AMApplication::TransferWorkflow::TaskView &task_view) const {
  if (!prompt_manager_) {
    return;
  }
  if (task_view.entries.empty()) {
    prompt_manager_->FmtPrint("Task {} has no entries.", task_view.summary.id);
    return;
  }
  for (const auto &entry : task_view.entries) {
    prompt_manager_->FmtPrint(
        "  [{}] {}:{} {}@{} -> {}@{} size={} transferred={} result={} {}",
        std::to_string(entry.index), task_view.summary.id,
        PathTypeText_(entry.path_type),
        DisplayHost_(entry.src_host), entry.src, DisplayHost_(entry.dst_host),
        entry.dst, AMStr::FormatSize(entry.size),
        AMStr::FormatSize(entry.transferred),
        AMStr::ToString(entry.result.first), entry.result.second);
  }
}

/**
 * @brief Print user transfer-set details for one task.
 */
void TaskGateway::PrintTaskSets_(
    const AMApplication::TransferWorkflow::TaskView &task_view) const {
  if (!prompt_manager_) {
    return;
  }
  if (task_view.transfer_sets.empty()) {
    prompt_manager_->FmtPrint("Task {} has no transfer sets.",
                              task_view.summary.id);
    return;
  }
  for (const auto &set : task_view.transfer_sets) {
    prompt_manager_->FmtPrint(
        "  Set {} dst={} clone={} mkdir={} overwrite={} ignore_special={} "
        "resume={}",
        std::to_string(set.index), RenderEndpoint_(set.dst),
        set.clone ? "true" : "false",
        set.mkdir ? "true" : "false", set.overwrite ? "true" : "false",
        set.ignore_special_file ? "true" : "false", set.resume ? "true" : "false");
    for (const auto &src : set.srcs) {
      prompt_manager_->FmtPrint("    src: {}", RenderEndpoint_(src));
    }
  }
}

/**
 * @brief List task states.
 */
ECM TaskGateway::ListTasks(bool pending, bool suspend, bool finished,
                           bool conducting) {
  const bool has_filter = pending || suspend || finished || conducting;
  if (!has_filter) {
    pending = true;
    suspend = true;
    finished = true;
    conducting = true;
  }
  std::vector<AMApplication::TransferWorkflow::TaskSummaryView> task_summaries = {};
  ECM list_rcm = transfer_service_.ListTaskSummaries(&task_summaries);
  if (!isok(list_rcm)) {
    return list_rcm;
  }
  size_t shown = 0;
  for (const auto &task_summary : task_summaries) {
    if (task_control_token_ && task_control_token_->IsInterrupted()) {
      return Err(EC::Terminate, "Task list interrupted");
    }
    const TaskStatus status = task_summary.status;
    const bool selected =
        (pending && status == TaskStatus::Pending) ||
        (suspend && status == TaskStatus::Paused) ||
        (finished && status == TaskStatus::Finished) ||
        (conducting && status == TaskStatus::Conducting);
    if (!selected) {
      continue;
    }
    PrintTaskSummary_(task_summary, false);
    ++shown;
  }
  if (shown == 0 && prompt_manager_) {
    prompt_manager_->Print("No transfer task matched.");
  }
  return Ok();
}

/**
 * @brief Show one or more tasks.
 */
ECM TaskGateway::ShowTasks(const std::vector<std::string> &ids) {
  if (ids.empty()) {
    return ListTasks(true, true, true, true);
  }
  ECM first_error = Ok();
  for (const auto &task_id : ids) {
    if (task_control_token_ && task_control_token_->IsInterrupted()) {
      return Err(EC::Terminate, "Task show interrupted");
    }
    AMApplication::TransferWorkflow::TaskView task_view = {};
    ECM rcm = transfer_service_.GetTaskView(task_id, false, true, &task_view);
    if (!isok(rcm)) {
      if (isok(first_error)) {
        first_error = rcm;
      }
      if (prompt_manager_) {
        prompt_manager_->ErrorFormat(rcm);
      }
      continue;
    }
    PrintTaskSummary_(task_view.summary, true);
    PrintTaskEntries_(task_view);
  }
  return first_error;
}

/**
 * @brief Inspect one task.
 */
ECM TaskGateway::InspectTask(const std::string &id, bool show_sets,
                             bool show_entries) {
  const bool include_sets = show_sets || (!show_sets && !show_entries);
  const bool include_entries = show_entries;
  AMApplication::TransferWorkflow::TaskView task_view = {};
  ECM rcm =
      transfer_service_.GetTaskView(id, include_sets, include_entries, &task_view);
  if (!isok(rcm)) {
    return rcm;
  }
  PrintTaskSummary_(task_view.summary, true);
  if (include_sets) {
    PrintTaskSets_(task_view);
  }
  if (include_entries) {
    PrintTaskEntries_(task_view);
  }
  return Ok();
}

/**
 * @brief Inspect transfer sets of one task.
 */
ECM TaskGateway::InspectTaskSets(const std::string &id) {
  AMApplication::TransferWorkflow::TaskView task_view = {};
  ECM rcm = transfer_service_.GetTaskView(id, true, false, &task_view);
  if (!isok(rcm)) {
    return rcm;
  }
  PrintTaskSets_(task_view);
  return Ok();
}

/**
 * @brief Inspect entries of one task.
 */
ECM TaskGateway::InspectTaskEntries(const std::string &id) {
  AMApplication::TransferWorkflow::TaskView task_view = {};
  ECM rcm = transfer_service_.GetTaskView(id, false, true, &task_view);
  if (!isok(rcm)) {
    return rcm;
  }
  PrintTaskEntries_(task_view);
  return Ok();
}

/**
 * @brief Query one task entry by id.
 */
ECM TaskGateway::QueryTaskEntry(const std::string &entry_id) {
  std::string task_id = {};
  size_t index = 0;
  if (!ParseEntryId_(entry_id, &task_id, &index)) {
    return Err(EC::InvalidArg, AMStr::fmt("Invalid task entry id: {}", entry_id));
  }
  AMApplication::TransferWorkflow::TaskView task_view = {};
  ECM rcm = transfer_service_.GetTaskView(task_id, false, true, &task_view);
  if (!isok(rcm)) {
    return rcm;
  }
  if (task_view.entries.empty()) {
    return Err(EC::TaskNotFound, AMStr::fmt("Task has no entries: {}", task_id));
  }
  if (index == 0 || index > task_view.entries.size()) {
    return Err(EC::InvalidArg,
               AMStr::fmt("Entry index out of range: {}", entry_id));
  }
  const auto &task = task_view.entries.at(index - 1);
  if (prompt_manager_) {
    prompt_manager_->FmtPrint(
        "Entry {}:{} [{}] {}@{} -> {}@{} size={} transferred={} result={} {}",
        task_id, std::to_string(index), PathTypeText_(task.path_type),
        DisplayHost_(task.src_host), task.src, DisplayHost_(task.dst_host),
        task.dst, AMStr::FormatSize(task.size),
        AMStr::FormatSize(task.transferred), AMStr::ToString(task.result.first),
        task.result.second);
  }
  return Ok();
}

/**
 * @brief Query or set worker thread count.
 */
ECM TaskGateway::Thread(int num) {
  ECM rcm = transfer_service_.Thread(num);
  if (!isok(rcm)) {
    return rcm;
  }
  if (!prompt_manager_) {
    return Ok();
  }
  if (num < 0) {
    prompt_manager_->FmtPrint("Current transfer thread count: {}",
                              rcm.second.empty() ? "0" : rcm.second);
    return Ok();
  }
  prompt_manager_->FmtPrint("Updated transfer thread count: {}",
                            rcm.second.empty() ? std::to_string(num)
                                               : rcm.second);
  return Ok();
}

/**
 * @brief Terminate tasks by ids.
 */
ECM TaskGateway::TerminateTasks(const std::vector<std::string> &ids) {
  return transfer_service_.Terminate(ids);
}

/**
 * @brief Pause tasks by ids.
 */
ECM TaskGateway::PauseTasks(const std::vector<std::string> &ids) {
  return transfer_service_.Pause(ids);
}

/**
 * @brief Resume tasks by ids.
 */
ECM TaskGateway::ResumeTasks(const std::vector<std::string> &ids) {
  return transfer_service_.Resume(ids);
}

/**
 * @brief Retry a finished task.
 */
ECM TaskGateway::RetryTask(const std::string &id, bool is_async, bool quiet,
                           const std::vector<int> &indices) {
  return transfer_service_.Retry(id, is_async, quiet, indices);
}

/**
 * @brief Add one transfer set to cache.
 */
size_t TaskGateway::AddCachedTransferSet(const UserTransferSet &transfer_set) {
  return transfer_service_.AddCachedTransferSet(transfer_set);
}

/**
 * @brief Remove cached transfer sets.
 */
size_t
TaskGateway::RemoveCachedTransferSets(const std::vector<size_t> &indices) {
  std::vector<ECM> warnings = {};
  const size_t removed =
      transfer_service_.RemoveCachedTransferSets(indices, &warnings);
  if (prompt_manager_) {
    for (const auto &warning : warnings) {
      prompt_manager_->ErrorFormat(warning);
    }
  }
  return removed;
}

/**
 * @brief Clear all cached transfer sets.
 */
void TaskGateway::ClearCachedTransferSets() {
  transfer_service_.ClearCachedTransferSets();
}

/**
 * @brief Submit cached transfer sets.
 */
ECM TaskGateway::SubmitCachedTransferSets(bool quiet, bool is_async) {
  const auto transfer_set_views = transfer_service_.SnapshotCachedTransferSetViews();
  if (transfer_set_views.empty()) {
    return Err(EC::InvalidArg, "Cached transfer set is empty");
  }

  if (!quiet && prompt_manager_) {
    for (const auto &set : transfer_set_views) {
      PrintTransferSet_(*prompt_manager_, set);
      prompt_manager_->Print("");
    }
    bool canceled = false;
    if (!prompt_manager_->PromptYesNo("Submit cached transfer sets? (y/N): ",
                                      &canceled)) {
      prompt_manager_->Print("Canceled.");
      return Err(EC::Terminate, "Task submission canceled");
    }
  }

  std::vector<ECM> warnings = {};
  const auto confirm_policy =
      quiet ? AMApplication::TransferWorkflow::TransferConfirmPolicy::AutoApprove
            : AMApplication::TransferWorkflow::TransferConfirmPolicy::
                  RequireConfirm;
  AMApplication::TransferWorkflow::TransferAppService::WildcardConfirmFn confirm =
      BuildWildcardConfirmFn_(prompt_manager_, confirm_policy);

  ECM rcm = transfer_service_.SubmitCachedTransferSetsWithControl(
      quiet, is_async, task_control_token_, confirm_policy, confirm, &warnings);
  if (prompt_manager_) {
    for (const auto &warning : warnings) {
      prompt_manager_->ErrorFormat(warning);
    }
  }
  return rcm;
}

/**
 * @brief Query one cached transfer set.
 */
ECM TaskGateway::QueryCachedTransferSet(size_t index) {
  AMApplication::TransferWorkflow::TransferSetView transfer_set = {};
  ECM rcm = transfer_service_.GetCachedTransferSetView(index, &transfer_set);
  if (!isok(rcm)) {
    return rcm;
  }
  if (prompt_manager_) {
    PrintTransferSet_(*prompt_manager_, transfer_set);
  }
  return Ok();
}

/**
 * @brief List cached transfer set ids.
 */
std::vector<size_t> TaskGateway::ListCachedTransferSetIds() const {
  return transfer_service_.ListCachedTransferSetIds();
}

} // namespace AMInterface::ApplicationAdapters





