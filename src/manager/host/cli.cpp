#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/Path.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Host.hpp"
#include <sstream>
#include <string>
#include <vector>

using cls = AMHostManager;

std::vector<std::string> SplitTokens(const std::string &text) {
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

std::pair<ECM, std::vector<std::string>>
cls::PrivateKeys(bool print_sign) const {
  std::vector<std::string> keys = {};
  ECM rcm = Ok();
  if (!config_.ResolveArg(DocumentKind::Config, {configkn::keys}, &keys)) {
    rcm = {EC::CommonFailure,
           AMStr::amfmt("Fail to read config attribute: {}", configkn::keys)};
    prompt_.ErrorFormat(rcm);
    return {rcm, keys};
  }
  if (!print_sign) {
    return {rcm, keys};
  }
  static const std::string key_sign =
      AMStr::BBCEscape(AMStr::amfmt("[{}]", configkn::keys));
  auto info = PathInfo();
  for (auto &key : keys) {
    info = AMFS::stat(key).second;
    prompt_.Print(config_.Format(key, "", &info));
  }
  return {rcm, keys};
}

/**
 * @brief List configured hosts in compact or detailed mode.
 */
ECM cls::List(bool detailed) const {
  if (host_configs.empty()) {
    prompt_.Print("");
    return Ok();
  }

  if (!detailed) {
    const size_t max_width = 80;
    size_t current_width = 0;
    std::ostringstream line;
    for (auto it = host_configs.begin(); it != host_configs.end(); ++it) {
      const std::string &nickname = it->first;
      const std::string styled = config_.Format(nickname, "nickname");
      const size_t display_len = nickname.size();
      const size_t separator_len = current_width == 0 ? 0 : 3;
      if (current_width + separator_len + display_len > max_width &&
          current_width > 0) {
        prompt_.Print(line.str());
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
      prompt_.Print(line.str());
    }
    return Ok();
  }

  for (const auto &item : host_configs) {
    ECM print_status = PrintHost_(item.first, item.second);
    if (print_status.first != EC::Success) {
      return print_status;
    }
    prompt_.Print("");
  }
  return Ok();
}

/**
 * @brief Prompt and add one host configuration.
 */
ECM cls::Add() {
  ClientConfig entry;
  ECM prompt_status = PromptAddFields_("", entry);
  if (prompt_status.first != EC::Success) {
    return prompt_status;
  }
  prompt_status = AddHost_(entry.request.nickname, entry);
  if (prompt_status.first != EC::Success) {
    prompt_.ErrorFormat(prompt_status);
    return prompt_status;
  }
  config_.Dump(DocumentKind::Config, "", true);
  return prompt_status;
}

/**
 * @brief Prompt and modify an existing host configuration.
 */
ECM cls::Modify(const std::string &nickname) {
  if (!HostExists(nickname)) {
    return Err(EC::HostConfigNotFound, "host not found");
  }
  ClientConfig updated = host_configs[nickname];
  ECM prompt_status = PromptModifyFields_(nickname, updated);
  if (prompt_status.first != EC::Success) {
    return prompt_status;
  }

  prompt_status = AddHost_(updated.request.nickname, updated);
  if (prompt_status.first != EC::Success) {
    prompt_.ErrorFormat(prompt_status);
    return prompt_status;
  }
  config_.Dump(DocumentKind::Config, "", true);
  return prompt_status;
}

/**
 * @brief Delete one or more hosts from a whitespace-separated list.
 */
ECM cls::Delete(const std::string &nickname) {
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty host name");
  }
  return Delete(SplitTokens(nickname));
}

/**
 * @brief Delete hosts from explicit target names.
 */
ECM cls::Delete(const std::vector<std::string> &targets) {
  std::vector<std::string> uniq_targets = VectorDedup(targets);

  if (uniq_targets.empty()) {
    return Ok();
  }
  ECM rcm = Ok();
  std::vector<std::string> valid_targets = {};

  for (const auto &name : uniq_targets) {
    if (!HostExists(name)) {
      rcm =
          Err(EC::InvalidArg, AMStr::amfmt("invalid host nickname: {}", name));
      prompt_.ErrorFormat(rcm);
      continue;
    }
    valid_targets.push_back(name);
  }
  if (valid_targets.empty()) {
    return rcm;
  }

  std::string listing;
  for (size_t i = 0; i < uniq_targets.size(); ++i) {
    if (i > 0) {
      listing += ", ";
    }
    listing += config_.Format(uniq_targets[i], "nickname");
  }

  bool canceled = false;
  const bool confirmed = prompt_.PromptYesNo(
      AMStr::amfmt("Delete {} host(s): {} ? (y/N): ", uniq_targets.size(),
                   listing),
      &canceled);

  if (canceled || !confirmed) {
    prompt_.Print("Delete aborted.");
    return Ok();
  }

  for (const auto &name : uniq_targets) {
    ECM rcm = RemoveHost_(name);
    if (rcm.first != EC::Success) {
      prompt_.ErrorFormat(rcm);
      return rcm;
    }
    // prompt_.Print(
    //     AMStr::amfmt("Deleted host: {}", config_.Format(name, "nickname")));
  }

  return config_.Dump(DocumentKind::Config, "", true);
}

/**
 * @brief Query one or more hosts from whitespace-separated names.
 */
ECM cls::Query(const std::string &nickname) const {
  return Query(SplitTokens(nickname));
}

/**
 * @brief Query one or more hosts and print detailed fields.
 */
ECM cls::Query(const std::vector<std::string> &targets) const {
  ECM rcm = Ok();
  if (host_configs.empty()) {
    rcm = Err(EC::HostConfigNotFound, "no hosts configured");
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  std::vector<std::string> uniq_targets = VectorDedup(targets);
  std::vector<std::string> valid_targets = {};

  for (const std::string &nickname : uniq_targets) {
    auto it = host_configs.find(nickname);
    if (it == host_configs.end()) {
      const std::string styled = config_.Format(nickname, "nickname");
      ECM err = Err(EC::HostConfigNotFound,
                    AMStr::amfmt("Host {} not found", styled));
      prompt_.ErrorFormat(err);
      return err;
    }
    valid_targets.push_back(nickname);
  }
  if (valid_targets.empty()) {
    return rcm;
  }

  ECM print_status = Ok();
  for (const std::string &nickname : valid_targets) {
    auto it = host_configs.find(nickname);
    print_status = PrintHost_(it->first, it->second);
    if (print_status.first != EC::Success) {
      prompt_.ErrorFormat(print_status);
      rcm = print_status;
    }
    prompt_.Print("");
  }
  return rcm;
}

/**
 * @brief Rename a host nickname.
 */
ECM cls::Rename(const std::string &old_nickname,
                const std::string &new_nickname) {
  ECM rcm = Ok();
  if (old_nickname.empty() || new_nickname.empty()) {
    rcm = Err(EC::InvalidArg, "empty nickname");
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  if (old_nickname == new_nickname) {
    rcm = Err(EC::InvalidArg, "new nickname same as old nickname");
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  if (!configkn::ValidateNickname(new_nickname)) {
    rcm =
        Err(EC::InvalidArg, "invalid new nickname, pattern is [a-zA-Z0-9_-]+");
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  if (HostExists(new_nickname)) {
    rcm = Err(EC::KeyAlreadyExists, "new nickname already exists");
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  if (!HostExists(old_nickname)) {
    rcm = Err(EC::HostConfigNotFound, "old nickname not found");
    prompt_.ErrorFormat(rcm);
    return rcm;
  }

  ClientConfig moved = host_configs[old_nickname];
  moved.request.nickname = new_nickname;

  host_configs[new_nickname] = moved;
  rcm = AddHost_(new_nickname, moved);

  if (rcm.first != EC::Success) {
    prompt_.ErrorFormat(rcm);
    host_configs.erase(new_nickname);
    return rcm;
  }

  host_configs.erase(old_nickname);

  rcm = RemoveHost_(old_nickname);
  if (rcm.first != EC::Success) {
    prompt_.ErrorFormat(rcm);
  }
  return rcm;
}

/**
 * @brief Print config and settings source paths.
 */
ECM cls::Src() const {
  static const std::string config_label = AMStr::BBCEscape("[Config] ");
  static const std::string settings_label = AMStr::BBCEscape("[Setting]");
  std::filesystem::path config_path_obj;
  std::filesystem::path settings_path_obj;
  std::string config_path = "";
  std::string settings_path = "";

  if (config_.GetDataPath(DocumentKind::Config, &config_path_obj)) {
    config_path = config_path_obj.string();
    auto [config_rcm, config_info] = AMFS::stat(config_path, false);
    prompt_.Print(
        AMStr::amfmt("{} = {}", config_label,
                     config_.Format(config_path, "dir", &config_info)));
  }
  if (config_.GetDataPath(DocumentKind::Settings, &settings_path_obj)) {
    settings_path = settings_path_obj.string();
    auto [settings_rcm, settings_info] = AMFS::stat(settings_path, false);
    prompt_.Print(
        AMStr::amfmt("{} = {}", settings_label,
                     config_.Format(settings_path, "dir", &settings_info)));
  }
  return Ok();
}

/**
 * @brief Set a single host field from CLI input.
 */
ECM cls::SetHostValue(const std::string &nickname, const std::string &attrname,
                      const std::string &value_str) {
  const std::string field = AMStr::lowercase(attrname);
  if (nickname.empty()) {
    ECM err = Err(EC::InvalidArg, "empty nickname");
    prompt_.ErrorFormat(err);
    return err;
  }
  if (!HostExists(nickname)) {
    ECM err = Err(EC::HostConfigNotFound, "host not found");
    prompt_.ErrorFormat(err);
    return err;
  }
  bool field_validated = false;

  for (const std::string &allowed : configkn::fileds) {
    if (field == allowed) {
      field_validated = true;
      break;
    }
  }

  if (!field_validated) {
    ECM err = Err(EC::InvalidArg, "unsupported property name");
    prompt_.ErrorFormat(err);
    return err;
  }

  ClientConfig &updated = host_configs[nickname];
  std::string old_value = "";
  std::string new_value = "";
  ECM set_status = Ok();
  if (field == configkn::hostname) {
    if (value_str.empty()) {
      set_status = Err(EC::InvalidArg, "hostname cannot be empty");
      prompt_.ErrorFormat(set_status);
      return set_status;
    }
    old_value = updated.request.hostname;
    updated.request.hostname = value_str;
    new_value = value_str;
  } else if (field == configkn::username) {
    if (value_str.empty()) {
      set_status = Err(EC::InvalidArg, "username cannot be empty");
      prompt_.ErrorFormat(set_status);
      return set_status;
    }
    old_value = updated.request.username;
    updated.request.username = value_str;
    new_value = value_str;
  } else if (field == configkn::port) {
    int64_t port = 0;
    if (!StrValueParse(value_str, &port) || port <= 0 || port > 65535) {
      set_status = Err(EC::InvalidArg, "invalid port value");
      prompt_.ErrorFormat(set_status);
      return set_status;
    }
    old_value = std::to_string(updated.request.port);
    updated.request.port = static_cast<int>(port);
    new_value = std::to_string(port);
  } else if (field == configkn::buffer_size) {
    int64_t buffer_size = 0;
    if (!StrValueParse(value_str, &buffer_size)) {
      set_status =
          Err(EC::InvalidArg, "Buffer size must be an positive integer");
      prompt_.ErrorFormat(set_status);
      return set_status;
    } else if (buffer_size < AMMinBufferSize || buffer_size > AMMaxBufferSize) {
      set_status = Err(EC::InvalidArg,
                       AMStr::amfmt("Buffer size must be between {} and {}",
                                    AMMinBufferSize, AMMaxBufferSize));
      prompt_.ErrorFormat(set_status);
      return set_status;
    }
    old_value = std::to_string(updated.buffer_size);
    updated.buffer_size = buffer_size;
    new_value = std::to_string(buffer_size);
  } else if (field == configkn::compression) {
    bool compression = false;
    if (!StrValueParse(value_str, &compression)) {
      set_status =
          Err(EC::InvalidArg, "compression value must be true or false");
      prompt_.ErrorFormat(set_status);
      return set_status;
    }
    old_value = updated.request.compression ? "true" : "false";
    updated.request.compression = compression;
    new_value = compression ? "true" : "false";

  } else if (field == configkn::protocol) {
    std::string protocol = AMStr::lowercase(AMStr::Strip(value_str));
    if (protocol != "sftp" && protocol != "ftp" && protocol != "local") {
      set_status = Err(EC::InvalidArg, "protocol must be sftp, ftp or local");
      prompt_.ErrorFormat(set_status);
      return set_status;
    }
    old_value = AMStr::lowercase(AM_ENUM_NAME(updated.protocol));
    updated.protocol = configkn::StrToProtocol(protocol);
    new_value = AMStr::lowercase(AM_ENUM_NAME(updated.protocol));

  } else if (field == configkn::password) {
    std::string tmp_pswd = AMStr::Strip(value_str);
    if (tmp_pswd.empty()) {
      if (!prompt_.SecurePrompt("Password: ", &tmp_pswd)) {
        set_status = Err(EC::ConfigCanceled, "password input canceled");
        prompt_.ErrorFormat(set_status);
        return set_status;
      }
    }
    if (tmp_pswd.empty()) {
      set_status = Err(EC::InvalidArg, "password cannot be empty");
      prompt_.ErrorFormat(set_status);
      return set_status;
    }
    if (!AMAuth::IsEncrypted(tmp_pswd)) {
      tmp_pswd = AMAuth::EncryptPassword(tmp_pswd);
    }
    old_value = updated.request.password.empty() ? "\"\"" : "***";
    updated.request.password = tmp_pswd;
    new_value = "***";
  } else if (field == configkn::keyfile) {
    old_value = updated.request.keyfile;
    updated.request.keyfile = value_str;
    new_value = value_str;
  } else if (field == configkn::trash_dir) {
    old_value = updated.request.trash_dir;
    updated.request.trash_dir = value_str;
    new_value = value_str;
  } else if (field == configkn::login_dir) {
    old_value = updated.login_dir;
    updated.login_dir = value_str;
    new_value = value_str;
  } else {
    set_status = Err(EC::InvalidArg,
                     AMStr::amfmt("unsupported property name: {}", field));
    prompt_.ErrorFormat(set_status);
    return set_status;
  }

  bool write_ok = false;
  if (field == configkn::port) {
    write_ok = config_.SetArg(DocumentKind::Config,
                              {configkn::hosts, nickname, field},
                              static_cast<int64_t>(updated.request.port));
  } else if (field == configkn::buffer_size) {
    write_ok = config_.SetArg(DocumentKind::Config,
                              {configkn::hosts, nickname, field},
                              static_cast<int64_t>(updated.buffer_size));
  } else if (field == configkn::compression) {
    write_ok = config_.SetArg(DocumentKind::Config,
                              {configkn::hosts, nickname, field},
                              updated.request.compression);
  } else {
    write_ok =
        config_.SetArg(DocumentKind::Config, {configkn::hosts, nickname, field},
                       new_value);
  }

  if (!write_ok) {
    set_status = Err(EC::CommonFailure, "failed to write config");
    prompt_.ErrorFormat(set_status);
    return set_status;
  }

  config_.Dump(DocumentKind::Config, "", true);
  prompt_.Print(
      AMStr::amfmt("{}.{}: {} -> {}", nickname, field, old_value, new_value));
  return set_status;
}
