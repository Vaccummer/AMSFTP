#include "AMBase/DataClass.hpp"
#include "AMBase/Path.hpp"
#include "AMManager/Host.hpp"
#include <algorithm>
#include <sstream>

using cls = AMHostManager;

namespace {

/**
 * @brief Print a line via the global prompt manager.
 */
void PrintLine(const std::string &value) {
  AMPromptManager::Instance().Print(value);
}

/**
 * @brief Parse human-friendly boolean tokens.
 */
bool ParseBoolToken(const std::string &input, bool *value) {
  if (!value) {
    return false;
  }
  const std::string token = AMStr::lowercase(AMStr::Strip(input));
  if (token == "true" || token == "1" || token == "yes" || token == "y") {
    *value = true;
    return true;
  }
  if (token == "false" || token == "0" || token == "no" || token == "n") {
    *value = false;
    return true;
  }
  return false;
}

/**
 * @brief Split whitespace-separated host names.
 */
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

/**
 * @brief Convert known config fields to their display value.
 */
std::string GetFieldString(const ClientConfig &entry,
                           const std::string &field) {
  if (field == "hostname") {
    return entry.request.hostname;
  }
  if (field == "username") {
    return entry.request.username;
  }
  if (field == "port") {
    return std::to_string(entry.request.port);
  }
  if (field == "password") {
    return entry.request.password;
  }
  if (field == "protocol") {
    switch (entry.protocol) {
    case ClientProtocol::SFTP:
      return "sftp";
    case ClientProtocol::FTP:
      return "ftp";
    case ClientProtocol::LOCAL:
      return "local";
    default:
      return "unknown";
    }
  }
  if (field == "buffer_size") {
    return std::to_string(entry.buffer_size);
  }
  if (field == "trash_dir") {
    return entry.request.trash_dir;
  }
  if (field == "login_dir") {
    return entry.login_dir;
  }
  if (field == "keyfile") {
    return entry.request.keyfile;
  }
  if (field == "compression") {
    return entry.request.compression ? "true" : "false";
  }
  return "";
}

} // namespace

/**
 * @brief List host nicknames only.
 */
ECM cls::ListName() const { return List(false); }

/**
 * @brief List configured hosts in compact or detailed mode.
 */
ECM cls::List(bool detailed) const {
  auto status = EnsureReady_("HostList");
  if (status.first != EC::Success) {
    return status;
  }
  CollectHosts_();

  if (host_configs.empty()) {
    PrintLine("");
    return Ok();
  }

  if (!detailed) {
    const size_t max_width = 80;
    size_t current_width = 0;
    std::ostringstream line;
    for (auto it = host_configs.begin(); it != host_configs.end(); ++it) {
      const std::string &nickname = it->first;
      const std::string styled = FormatValue_(nickname, "nickname");
      const size_t display_len = nickname.size();
      const size_t separator_len = current_width == 0 ? 0 : 3;
      if (current_width + separator_len + display_len > max_width &&
          current_width > 0) {
        PrintLine(line.str());
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
      PrintLine(line.str());
    }
    return Ok();
  }

  for (const auto &item : host_configs) {
    ECM print_status = PrintHost_(item.first, item.second);
    if (print_status.first != EC::Success) {
      return print_status;
    }
    PrintLine("");
  }
  return Ok();
}

/**
 * @brief Prompt and add one host configuration.
 */
ECM cls::Add() {
  ECM status = EnsureReady_("HostAdd");
  if (status.first != EC::Success) {
    return status;
  }
  CollectHosts_();

  ClientConfig entry;
  ECM prompt_status = PromptAddFields_("", entry);
  if (prompt_status.first != EC::Success) {
    return prompt_status;
  }

  entry.request.nickname = AMStr::Strip(entry.request.nickname);
  if (entry.request.nickname.empty()) {
    return Err(EC::InvalidArg, "empty nickname");
  }
  if (!ValidateNickname(entry.request.nickname)) {
    return Err(EC::InvalidArg, "invalid nickname");
  }
  if (HostExists(entry.request.nickname)) {
    return Err(EC::KeyAlreadyExists, "nickname already exists");
  }

  ECM persist_status = PersistHostConfig_(entry.request.nickname, entry, true);
  if (persist_status.first != EC::Success) {
    prompt_.ErrorFormat(persist_status);
    return persist_status;
  }
  host_configs[entry.request.nickname] = entry;

  PrintLine(FormatValue_(AMStr::amfmt("Added host: {}", entry.request.nickname),
                         "success"));
  return Ok();
}

/**
 * @brief Prompt and modify an existing host configuration.
 */
ECM cls::Modify(const std::string &nickname) {
  ECM status = EnsureReady_("HostModify");
  if (status.first != EC::Success) {
    return status;
  }
  CollectHosts_();

  if (!HostExists(nickname)) {
    return Err(EC::HostConfigNotFound, "host not found");
  }
  ClientConfig updated = host_configs[nickname];
  ECM prompt_status = PromptModifyFields_(nickname, updated);
  if (prompt_status.first != EC::Success) {
    return prompt_status;
  }

  ECM persist_status = PersistHostConfig_(nickname, updated, true);
  if (persist_status.first != EC::Success) {
    prompt_.ErrorFormat(persist_status);
    return persist_status;
  }
  host_configs[nickname] = updated;

  PrintLine(
      FormatValue_(AMStr::amfmt("Modified host: {}", nickname), "success"));
  return Ok();
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
  ECM status = EnsureReady_("HostDelete");
  if (status.first != EC::Success) {
    return status;
  }
  CollectHosts_();

  ECM overall = Ok();
  bool removed_any = false;
  for (const std::string &name : targets) {
    if (name.empty()) {
      continue;
    }
    ECM rm_status = RemoveHost_(name);
    if (rm_status.first != EC::Success) {
      prompt_.ErrorFormat(rm_status);
      overall = rm_status;
      continue;
    }
    removed_any = true;
  }

  if (removed_any) {
    ECM dump_status = SaveConfig_(false);
    if (dump_status.first != EC::Success) {
      prompt_.ErrorFormat(dump_status);
      return dump_status;
    }
  }
  return overall;
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
  ECM status = EnsureReady_("HostQuery");
  if (status.first != EC::Success) {
    return status;
  }
  CollectHosts_();

  if (host_configs.empty()) {
    PrintLine("");
    return Ok();
  }

  if (targets.empty()) {
    for (const auto &item : host_configs) {
      ECM print_status = PrintHost_(item.first, item.second);
      if (print_status.first != EC::Success) {
        return print_status;
      }
      PrintLine("");
    }
    return Ok();
  }

  for (const std::string &nickname : targets) {
    auto it = host_configs.find(nickname);
    if (it == host_configs.end()) {
      const std::string styled = FormatValue_(nickname, "nickname");
      ECM err = Err(EC::HostConfigNotFound,
                    AMStr::amfmt("Host {} not found", styled));
      prompt_.ErrorFormat(err);
      return err;
    }
    ECM print_status = PrintHost_(it->first, it->second);
    if (print_status.first != EC::Success) {
      return print_status;
    }
    PrintLine("");
  }
  return Ok();
}

/**
 * @brief Rename a host nickname.
 */
ECM cls::Rename(const std::string &old_nickname,
                const std::string &new_nickname) {
  ECM status = EnsureReady_("HostRename");
  if (status.first != EC::Success) {
    return status;
  }
  CollectHosts_();

  if (old_nickname.empty() || new_nickname.empty()) {
    ECM err = Err(EC::InvalidArg, "empty nickname");
    prompt_.ErrorFormat(err);
    return err;
  }
  if (old_nickname == new_nickname) {
    ECM err = Err(EC::InvalidArg, "new nickname same as old nickname");
    prompt_.ErrorFormat(err);
    return err;
  }
  if (!ValidateNickname(new_nickname)) {
    ECM err = Err(EC::InvalidArg, "invalid new nickname");
    prompt_.ErrorFormat(err);
    return err;
  }
  if (!HostExists(old_nickname)) {
    ECM err = Err(EC::HostConfigNotFound, "old nickname not found");
    prompt_.ErrorFormat(err);
    return err;
  }
  if (HostExists(new_nickname)) {
    ECM err = Err(EC::KeyAlreadyExists, "new nickname already exists");
    prompt_.ErrorFormat(err);
    return err;
  }

  ClientConfig moved = host_configs[old_nickname];
  moved.request.nickname = new_nickname;

  ECM write_new_status = PersistHostConfig_(new_nickname, moved, false);
  if (write_new_status.first != EC::Success) {
    prompt_.ErrorFormat(write_new_status);
    return write_new_status;
  }

  ECM remove_old_status = RemoveHost_(old_nickname);
  if (remove_old_status.first != EC::Success) {
    prompt_.ErrorFormat(remove_old_status);
    return remove_old_status;
  }

  ECM dump_status = SaveConfig_(false);
  if (dump_status.first != EC::Success) {
    prompt_.ErrorFormat(dump_status);
    return dump_status;
  }

  host_configs[new_nickname] = moved;
  PrintLine(AMStr::amfmt("Rename host: \x1b[9m{}\x1b[29m -> {}", old_nickname,
                         FormatValue_(new_nickname, "nickname")));
  return Ok();
}

/**
 * @brief Print config and settings source paths.
 */
ECM cls::Src() const {
  ECM status = EnsureReady_("HostSrc");
  if (status.first != EC::Success) {
    return status;
  }

  const std::string config_label = AMStr::BBCEscape("[Config]");
  const std::string settings_label = AMStr::BBCEscape("[Setting]");
  const size_t width = std::max(config_label.size(), settings_label.size());

  std::filesystem::path config_path_obj;
  std::filesystem::path settings_path_obj;
  std::string config_path;
  std::string settings_path;
  if (GetDocumentPath_(DocumentKind::Config, &config_path_obj)) {
    config_path = config_path_obj.string();
  }
  if (GetDocumentPath_(DocumentKind::Settings, &settings_path_obj)) {
    settings_path = settings_path_obj.string();
  }

  auto [config_rcm, config_info] = AMFS::stat(config_path, false);
  PathInfo missing_config_info;
  if (config_rcm.first != EC::Success) {
    missing_config_info.name = AMPathStr::basename(config_path);
  }
  const PathInfo *config_ptr =
      config_rcm.first == EC::Success ? &config_info : &missing_config_info;

  auto [settings_rcm, settings_info] = AMFS::stat(settings_path, false);
  PathInfo missing_settings_info;
  if (settings_rcm.first != EC::Success) {
    missing_settings_info.name = AMPathStr::basename(settings_path);
  }
  const PathInfo *settings_ptr = settings_rcm.first == EC::Success
                                     ? &settings_info
                                     : &missing_settings_info;

  PrintLine(AMStr::amfmt("{:<{}} : {}", config_label, width,
                         FormatValue_(config_path, "dir", config_ptr)));
  PrintLine(AMStr::amfmt("{:<{}} : {}", settings_label, width,
                         FormatValue_(settings_path, "dir", settings_ptr)));
  return Ok();
}

/**
 * @brief Set a single host field from CLI input.
 */
ECM cls::SetHostValue(const std::string &nickname, const std::string &attrname,
                      const std::string &value_str) {
  ECM status = EnsureReady_("SetHostValue");
  if (status.first != EC::Success) {
    prompt_.ErrorFormat(status);
    return status;
  }
  CollectHosts_();

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

  static const std::vector<std::string> allowed_fields = {
      "hostname",    "username",  "port",      "password", "protocol",
      "buffer_size", "trash_dir", "login_dir", "keyfile",  "compression"};
  if (std::find(allowed_fields.begin(), allowed_fields.end(), field) ==
      allowed_fields.end()) {
    ECM err = Err(EC::InvalidArg, "unsupported property name");
    prompt_.ErrorFormat(err);
    return err;
  }

  ClientConfig updated = host_configs[nickname];
  const std::string old_value = GetFieldString(updated, field);
  ECM set_status = Ok();

  if (field == "port") {
    int64_t port = 0;
    if (!StrValueParse(value_str, &port) || port <= 0 ||
        port > std::numeric_limits<int>::max()) {
      return Err(EC::InvalidArg, "invalid port value");
    }
    set_status = SetHostField(nickname, field, port, true);
    if (set_status.first == EC::Success) {
      updated.request.port = static_cast<int>(port);
    }
  } else if (field == "buffer_size") {
    int64_t buffer_size = 0;
    if (!StrValueParse(value_str, &buffer_size) ||
        (buffer_size != -1 && buffer_size <= 0)) {
      return Err(EC::InvalidArg, "invalid buffer_size value");
    }
    set_status = SetHostField(nickname, field, buffer_size, true);
    if (set_status.first == EC::Success) {
      updated.buffer_size = buffer_size;
    }
  } else if (field == "compression") {
    bool compression = false;
    if (!ParseBoolToken(value_str, &compression)) {
      return Err(EC::InvalidArg, "invalid compression value");
    }
    set_status = SetHostField(nickname, field, compression, true);
    if (set_status.first == EC::Success) {
      updated.request.compression = compression;
    }
  } else if (field == "protocol") {
    std::string protocol = AMStr::lowercase(AMStr::Strip(value_str));
    if (protocol != "sftp" && protocol != "ftp" && protocol != "local") {
      return Err(EC::InvalidArg, "invalid protocol value");
    }
    set_status = SetHostField(nickname, field, protocol, true);
    if (set_status.first == EC::Success) {
      updated.protocol = StrToProtocol(protocol);
    }
  } else if (field == "password") {
    std::string encrypted = AMAuth::EncryptPassword(value_str);
    set_status = SetHostField(nickname, field, encrypted, true);
    if (set_status.first == EC::Success) {
      updated.request.password = encrypted;
    }
  } else {
    set_status = SetHostField(nickname, field, value_str, true);
    if (set_status.first == EC::Success) {
      if (field == "hostname") {
        updated.request.hostname = value_str;
      } else if (field == "username") {
        updated.request.username = value_str;
      } else if (field == "trash_dir") {
        updated.request.trash_dir = value_str;
      } else if (field == "login_dir") {
        updated.login_dir = value_str;
      } else if (field == "keyfile") {
        updated.request.keyfile = value_str;
      }
    }
  }

  if (set_status.first != EC::Success) {
    prompt_.ErrorFormat(set_status);
    return set_status;
  }

  host_configs[nickname] = updated;
  const std::string new_value = GetFieldString(updated, field);
  PrintLine(
      AMStr::amfmt("{}.{}: {} -> {}", nickname, field, old_value, new_value));
  return Ok();
}

/**
 * @brief Read private key paths from config and optionally print them.
 */
std::pair<ECM, std::vector<std::string>>
cls::PrivateKeys(bool print_sign) const {
  ECM status = EnsureReady_("HostPrivateKeys");
  if (status.first != EC::Success) {
    return {status, {}};
  }

  nlohmann::ordered_json config_json;
  if (!GetDocumentJson_(DocumentKind::Config, &config_json)) {
    return {Ok(), {}};
  }

  std::vector<std::string> keys;
  const auto it = config_json.find("private_keys");
  if (it != config_json.end() && it->is_array()) {
    keys.reserve(it->size());
    for (const auto &item : *it) {
      if (item.is_string()) {
        keys.push_back(item.get<std::string>());
      }
    }
  }

  if (print_sign) {
    PrintLine("[!a][Private_keys][/a]");
    for (const std::string &path : keys) {
      auto [path_rcm, path_info] = AMFS::stat(path, false);
      PathInfo missing_info;
      if (path_rcm.first != EC::Success) {
        missing_info.name = AMPathStr::basename(path);
      }
      const PathInfo *path_ptr =
          path_rcm.first == EC::Success ? &path_info : &missing_info;
      PrintLine(FormatValue_(path, "dir", path_ptr));
    }
  }
  return {Ok(), keys};
}
