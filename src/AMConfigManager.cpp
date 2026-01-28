#include "AMConfigManager.hpp"
#include "base/AMEnum.hpp"
#include "base/AMPath.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <optional>
#include <regex>
#include <sstream>
#include <variant>

namespace {
using Status = AMConfigManager::Status;
using Path = AMConfigManager::Path;
using Value = AMConfigManager::Value;
using ClientConfig = AMConfigManager::ClientConfig;
using EC = ErrorCode;

Status Ok() { return {"", 0}; }
Status Err(const std::string &msg, int code = 1) { return {msg, code}; }

void PrintLine(const std::string &value) {
  AMPromptManager::Instance().Print(value);
}

std::string TrimCopy(const std::string &value) {
  std::string tmp = value;
  AMStr::VStrip(tmp);
  return tmp;
}

bool IsHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

bool ParseHexColor(const std::string &token, int *r, int *g, int *b) {
  if (token.size() != 7 || token[0] != '#')
    return false;
  for (size_t i = 1; i < token.size(); ++i) {
    if (!IsHexDigit(token[i]))
      return false;
  }
  *r = std::stoi(token.substr(1, 2), nullptr, 16);
  *g = std::stoi(token.substr(3, 2), nullptr, 16);
  *b = std::stoi(token.substr(5, 2), nullptr, 16);
  return true;
}

std::string ToLowerCopy(const std::string &value) {
  std::string out = value;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

std::optional<std::string> GetStringField(const toml::table &tbl,
                                          const std::string &key);
std::optional<int64_t> GetIntField(const toml::table &tbl,
                                   const std::string &key);

const std::vector<std::string> kHostFields = {
    "username", "hostname",  "port",     "keyfile",
    "password", "trash_dir", "protocol", "buffer_size",
};

const toml::array *GetHostsArray(const toml::table &root) {
  const toml::node *node = root.get("HOSTS");
  if (!node || !node->is_array()) {
    return nullptr;
  }
  return node->as_array();
}

bool IsHostValid(const toml::table &tbl) {
  auto nickname = GetStringField(tbl, "nickname");
  if (!nickname || nickname->empty())
    return false;
  auto hostname = GetStringField(tbl, "hostname");
  if (!hostname || hostname->empty())
    return false;
  return true;
}

toml::array *EnsureHostsArray(toml::table &root) {
  toml::node *node = root.get("HOSTS");
  if (node) {
    if (node->is_array()) {
      return node->as_array();
    }
    root.erase("HOSTS");
  }
  auto inserted = root.insert("HOSTS", toml::array{});
  return inserted.first->second.as_array();
}

const toml::table *FindHostTable(const toml::table &root,
                                 const std::string &nickname,
                                 std::size_t *out_index = nullptr) {
  const toml::array *arr = GetHostsArray(root);
  if (!arr)
    return nullptr;

  for (std::size_t i = 0; i < arr->size(); ++i) {
    const toml::node &node = (*arr)[i];
    if (!node.is_table())
      continue;
    const toml::table &tbl = *node.as_table();
    if (!IsHostValid(tbl))
      continue;
    auto name = GetStringField(tbl, "nickname");
    if (name && *name == nickname) {
      if (out_index)
        *out_index = i;
      return &tbl;
    }
  }
  return nullptr;
}

toml::table *FindHostTableMutable(toml::table &root,
                                  const std::string &nickname,
                                  std::size_t *out_index = nullptr) {
  toml::array *arr = EnsureHostsArray(root);
  if (!arr)
    return nullptr;

  for (std::size_t i = 0; i < arr->size(); ++i) {
    toml::node &node = (*arr)[i];
    if (!node.is_table())
      continue;
    toml::table &tbl = *node.as_table();
    auto name = GetStringField(tbl, "nickname");
    if (name && *name == nickname) {
      if (out_index)
        *out_index = i;
      return &tbl;
    }
  }
  return nullptr;
}

bool ParseIndex(const std::string &value, std::size_t *out) {
  if (value.empty())
    return false;
  std::size_t idx = 0;
  for (char c : value) {
    if (!std::isdigit(static_cast<unsigned char>(c)))
      return false;
    idx = idx * 10 + static_cast<std::size_t>(c - '0');
  }
  if (out)
    *out = idx;
  return true;
}

const toml::node *FindNode(const toml::table &root, const Path &path) {
  const toml::node *current = &root;
  for (const auto &seg : path) {
    if (current->is_table()) {
      const toml::table &tbl = *current->as_table();
      current = tbl.get(seg);
    } else if (current->is_array()) {
      std::size_t index = 0;
      if (!ParseIndex(seg, &index))
        return nullptr;
      const toml::array &arr = *current->as_array();
      if (index >= arr.size())
        return nullptr;
      current = &arr[index];
    } else {
      return nullptr;
    }
    if (!current)
      return nullptr;
  }
  return current;
}

bool NodeToValue(const toml::node &node, Value *out) {
  if (!out)
    return false;
  if (auto v = node.value<int64_t>()) {
    *out = *v;
    return true;
  }
  if (auto v = node.value<bool>()) {
    *out = *v;
    return true;
  }
  if (auto v = node.value<std::string>()) {
    *out = *v;
    return true;
  }
  if (auto v = node.value<double>()) {
    std::ostringstream oss;
    oss << *v;
    *out = oss.str();
    return true;
  }
  if (node.is_array()) {
    const toml::array &arr = *node.as_array();
    std::vector<std::string> items;
    items.reserve(arr.size());
    for (const auto &child : arr) {
      if (!child.is_value())
        return false;
      if (auto s = child.value<std::string>()) {
        items.push_back(*s);
        continue;
      }
      if (auto i = child.value<int64_t>()) {
        items.push_back(std::to_string(*i));
        continue;
      }
      if (auto b = child.value<bool>()) {
        items.push_back(*b ? "true" : "false");
        continue;
      }
      if (auto d = child.value<double>()) {
        std::ostringstream oss;
        oss << *d;
        items.push_back(oss.str());
        continue;
      }
      return false;
    }
    *out = std::move(items);
    return true;
  }
  return false;
}

std::optional<std::string> GetStringField(const toml::table &tbl,
                                          const std::string &key) {
  const toml::node *node = tbl.get(key);
  if (!node)
    return std::nullopt;
  if (auto value = node->value<std::string>()) {
    return *value;
  }
  if (auto value = node->value<int64_t>()) {
    return std::to_string(*value);
  }
  if (auto value = node->value<bool>()) {
    return *value ? "true" : "false";
  }
  return std::nullopt;
}

std::optional<int64_t> GetIntField(const toml::table &tbl,
                                   const std::string &key) {
  const toml::node *node = tbl.get(key);
  if (!node)
    return std::nullopt;
  if (auto value = node->value<int64_t>())
    return *value;
  if (auto value = node->value<std::string>()) {
    try {
      return std::stoll(*value);
    } catch (...) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

ClientProtocol ProtocolFromString(const std::string &value) {
  std::string lower = value;
  std::transform(
      lower.begin(), lower.end(), lower.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (lower == "sftp")
    return ClientProtocol::SFTP;
  if (lower == "ftp")
    return ClientProtocol::FTP;
  if (lower == "local")
    return ClientProtocol::LOCAL;
  return ClientProtocol::Unknown;
}

} // namespace

AMConfigManager &AMConfigManager::Instance() {
  static AMConfigManager instance;
  return instance;
}

AMConfigManager::Status
AMConfigManager::SetConfigFilters(const std::vector<FormatPath> &filters) {
  config_filters_ = filters;
  return Ok();
}

AMConfigManager::Status
AMConfigManager::SetSettingsFilters(const std::vector<FormatPath> &filters) {
  settings_filters_ = filters;
  return Ok();
}

AMConfigManager::Status AMConfigManager::Init() {
  const char *root_env = std::getenv("AMSFTP_ROOT");
  if (!root_env || std::string(root_env).empty()) {
    AM_PROMPT_ERROR("ConfigInit",
                    "$AMSFTP_ROOT environment variable is not set", true, 2);
    return Err("AMSFTP_ROOT environment variable is not set", 2);
  }

  root_dir_ = std::filesystem::path(root_env);
  // mkdirs, already exists is ok
  std::error_code ec;
  std::filesystem::create_directories(root_dir_, ec);
  if (ec) {
    AM_PROMPT_ERROR("ConfigInit",
                    "failed to create root directory " + root_dir_.string() +
                        ": " + ec.message(),
                    true, 2);
    return Err("failed to create root directory " + root_dir_.string() + ": " +
                   ec.message(),
               2);
  }

  config_path_ = root_dir_ / "config" / "config.toml";
  settings_path_ = root_dir_ / "config" / "settings.toml";
  config_schema_path_ = root_dir_ / "config" / "config.schema.json";
  settings_schema_path_ = root_dir_ / "config" / "settings.schema.json";

  if (std::filesystem::exists(config_path_)) {
    std::string error;
    toml::table table;
    if (!AMConfigProcessor::ReadTomlTableViaRust(config_path_.string(),
                                                 config_schema_path_.string(),
                                                 &table, &error)) {
      AM_PROMPT_ERROR("ConfigInit", "failed to parse config.toml: " + error,
                      true, 2);
      return Err("failed to parse config.toml: " + error, 2);
    }
    config_table_ = std::move(table);
  } else {
    config_table_.clear();
  }

  if (std::filesystem::exists(settings_path_)) {
    std::string error;
    toml::table table;
    if (!AMConfigProcessor::ReadTomlTableViaRust(settings_path_.string(),
                                                 settings_schema_path_.string(),
                                                 &table, &error)) {
      AM_PROMPT_ERROR("ConfigInit", "failed to parse settings.toml: " + error,
                      true, 2);
      return Err("failed to parse settings.toml: " + error, 2);
    }
    settings_table_ = std::move(table);
  } else {
    settings_table_.clear();
  }

  initialized_ = true;
  if (!exit_hook_installed_) {
    std::atexit(&AMConfigManager::OnExit);
    exit_hook_installed_ = true;
  }

  return Ok();
}

AMConfigManager::Status AMConfigManager::Dump() {
  auto status = EnsureInitialized("Dump");
  if (status.second != 0)
    return status;

  std::filesystem::path config_dir = root_dir_ / "config";
  std::error_code ec;
  std::filesystem::create_directories(config_dir, ec);
  if (ec) {
    AM_PROMPT_ERROR("ConfigDumpError",
                    "failed to create config directory: " + ec.message(), true,
                    2);
    return Err("failed to create config directory: " + ec.message(), 2);
  }

  std::string error;
  if (!AMConfigProcessor::WriteTomlToFile(config_table_, config_path_.string(),
                                          config_schema_path_.string(),
                                          &error)) {
    return Err("failed to dump config.toml: " + error);
  }
  if (!AMConfigProcessor::WriteTomlToFile(
          settings_table_, settings_path_.string(),
          settings_schema_path_.string(), &error)) {
    return Err("failed to dump settings.toml: " + error);
  }

  return Ok();
}

std::string AMConfigManager::Format(const std::string &ori_str,
                                    const std::string &style_name) const {
  auto status = EnsureInitialized("Format");
  if (status.second != 0)
    return ori_str;

  Path key = {"style", style_name};
  const toml::node *node = FindNode(settings_table_, key);
  if (!node)
    return ori_str;
  auto value = node->value<std::string>();
  if (!value)
    return ori_str;

  std::string raw = TrimCopy(*value);
  if (raw.empty())
    return "";
  if (raw.front() != '[' || raw.back() != ']')
    return ori_str;

  std::string inner = TrimCopy(raw.substr(1, raw.size() - 2));
  if (inner.empty())
    return "";

  std::istringstream iss(inner);
  std::string token;
  std::vector<std::string> codes;
  while (iss >> token) {
    if (token.empty())
      continue;
    int r = 0, g = 0, b = 0;
    if (ParseHexColor(token, &r, &g, &b)) {
      codes.push_back(AMStr::amfmt("38;2;{};{};{}", std::to_string(r),
                                   std::to_string(g), std::to_string(b)));
      continue;
    }
    std::string lower = ToLowerCopy(token);
    if (lower == "bold") {
      codes.push_back("1");
      continue;
    }
    if (lower == "underline") {
      codes.push_back("4");
      continue;
    }
    if (lower == "italic") {
      codes.push_back("3");
      continue;
    }
    if (lower == "dim") {
      codes.push_back("2");
      continue;
    }
    if (lower == "reverse") {
      codes.push_back("7");
      continue;
    }
    return ori_str;
  }

  if (codes.empty())
    return "";

  std::ostringstream oss;
  for (size_t i = 0; i < codes.size(); ++i) {
    if (i > 0)
      oss << ';';
    oss << codes[i];
  }

  return AMStr::amfmt("\033[{}m{}\033[0m", oss.str(), ori_str);
}

AMConfigManager::Status AMConfigManager::List() const {
  auto status = EnsureInitialized("List");
  if (status.second != 0)
    return status;

  auto hosts = CollectHosts();
  if (hosts.empty()) {
    PrintLine("No hosts found.");
    return Ok();
  }

  for (const auto &item : hosts) {
    auto print_status = PrintHost(item.first, item.second);
    if (print_status.second != 0)
      return print_status;
    PrintLine("");
  }
  return Ok();
}

AMConfigManager::Status AMConfigManager::ListName() const {
  auto status = EnsureInitialized("ListName");
  if (status.second != 0)
    return status;

  auto hosts = CollectHosts();
  if (hosts.empty()) {
    PrintLine("No hosts found.");
    return Ok();
  }

  const size_t max_width = 80;
  size_t current_width = 0;
  std::ostringstream line;

  for (auto it = hosts.begin(); it != hosts.end(); ++it) {
    const std::string &name = it->first;
    const std::string styled = StyledValue(name, "regular");
    size_t name_len = name.size();
    size_t extra = current_width == 0 ? 0 : 1;

    if (current_width + extra + name_len > max_width && current_width > 0) {
      PrintLine(line.str());
      line.str(std::string());
      line.clear();
      current_width = 0;
    }

    if (current_width > 0) {
      line << ' ';
      current_width += 1;
    }
    line << styled;
    current_width += name_len;
  }

  if (current_width > 0) {
    PrintLine(line.str());
  }
  return Ok();
}

std::pair<AMConfigManager::Status, std::vector<std::string>>
AMConfigManager::PrivateKeys(bool print_sign) const {
  auto status = EnsureInitialized("PrivateKeys");
  if (status.second != 0)
    return {status, {}};

  std::vector<std::string> keys;
  const toml::node *node = config_table_.get("private_keys");
  if (node && node->is_array()) {
    const toml::array &arr = *node->as_array();
    keys.reserve(arr.size());
    for (const auto &item : arr) {
      if (auto value = item.value<std::string>()) {
        keys.push_back(*value);
      }
    }
  }

  if (print_sign) {
    PrintLine("[Private_keys]");
    for (const auto &path : keys) {
      PrintLine(StyledValue(path, "dir"));
    }
  }

  return {Ok(), keys};
}

std::pair<AMConfigManager::Status, AMConfigManager::ClientConfig>
AMConfigManager::GetClientConfig(const std::string &nickname,
                                 bool use_compression) const {
  auto status = EnsureInitialized("GetClientConfig");
  if (status.second != 0)
    return {status, ClientConfig{}};

  const toml::table *tbl = FindHostTable(config_table_, nickname);
  if (!tbl) {
    return {Err("client config not found",
                static_cast<int>(EC::HostConfigNotFound)),
            ClientConfig{}};
  }

  if (!IsHostValid(*tbl)) {
    return {Err("invalid host entry", static_cast<int>(EC::HostConfigNotFound)),
            ClientConfig{}};
  }

  ClientConfig config;

  std::string hostname = GetStringField(*tbl, "hostname").value_or("");
  std::string username = GetStringField(*tbl, "username").value_or("");
  std::string password = GetStringField(*tbl, "password").value_or("");
  std::string keyfile = GetStringField(*tbl, "keyfile").value_or("");
  std::string trash_dir = GetStringField(*tbl, "trash_dir").value_or("");
  int64_t port = GetIntField(*tbl, "port").value_or(22);

  config.request =
      ConRequst(nickname, hostname, username, static_cast<int>(port), password,
                keyfile, use_compression, trash_dir);

  std::string protocol_str = GetStringField(*tbl, "protocol").value_or("sftp");
  config.protocol = ProtocolFromString(protocol_str);
  config.buffer_size = GetIntField(*tbl, "buffer_size").value_or(-1);

  return {Ok(), config};
}

int AMConfigManager::GetSettingInt(const Path &path, int default_value) const {
  auto status = EnsureInitialized("GetSettingInt");
  if (status.second != 0)
    return default_value;
  const toml::node *node = FindNode(settings_table_, path);
  if (!node)
    return default_value;
  if (auto value = node->value<int64_t>())
    return static_cast<int>(*value);
  if (auto value = node->value<std::string>()) {
    try {
      return std::stoi(*value);
    } catch (...) {
      return default_value;
    }
  }
  return default_value;
}

/** Return a string setting value or the provided default. */
std::string
AMConfigManager::GetSettingString(const Path &path,
                                  const std::string &default_value) const {
  auto status = EnsureInitialized("GetSettingString");
  if (status.second != 0)
    return default_value;
  const toml::node *node = FindNode(settings_table_, path);
  if (!node)
    return default_value;
  if (auto value = node->value<std::string>()) {
    return *value;
  }
  if (auto value = node->value<int64_t>()) {
    return std::to_string(*value);
  }
  if (auto value = node->value<bool>()) {
    return *value ? "true" : "false";
  }
  if (auto value = node->value<double>()) {
    std::ostringstream oss;
    oss << *value;
    return oss.str();
  }
  return default_value;
}

AMConfigManager::Status AMConfigManager::Src() const {
  auto status = EnsureInitialized("Src");
  if (status.second != 0)
    return status;

  const std::string config_label = "[Config]";
  const std::string settings_label = "[Setting]";
  size_t width = std::max(config_label.size(), settings_label.size());

  std::string config_path = config_path_.string();
  std::string settings_path = settings_path_.string();

  std::string styled_config = StyledValue(config_path, "dir");
  std::string styled_settings = StyledValue(settings_path, "dir");

  {
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << config_label
         << " = " << styled_config;
    PrintLine(line.str());
  }
  {
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << settings_label
         << " = " << styled_settings;
    PrintLine(line.str());
  }
  return Ok();
}

AMConfigManager::Status AMConfigManager::Delete(const std::string &nickname) {
  auto status = EnsureInitialized("Delete");
  if (status.second != 0)
    return status;

  if (!HostExists(nickname)) {
    PrintLine(MaybeStyle("Host not found: " + nickname, "error"));
    return Err("host not found", 2);
  }

  auto rm_status = RemoveHost(nickname);
  if (rm_status.second != 0)
    return rm_status;

  PrintLine(MaybeStyle("Deleted host: " + nickname, "success"));
  return Ok();
}

AMConfigManager::Status
AMConfigManager::Rename(const std::string &old_nickname,
                        const std::string &new_nickname) {
  auto status = EnsureInitialized("Rename");
  if (status.second != 0)
    return status;

  if (old_nickname == new_nickname) {
    return Ok();
  }

  if (!HostExists(old_nickname)) {
    PrintLine(MaybeStyle("Host not found: " + old_nickname, "error"));
    return Err("host not found", 2);
  }

  std::string error;
  std::regex pattern("^[A-Za-z0-9_]+$");
  if (new_nickname.empty() || !std::regex_match(new_nickname, pattern)) {
    return Err(
        "new nickname must contain only letters, numbers, and underscore", 3);
  }
  if (HostExists(new_nickname)) {
    return Err("new nickname already exists", 3);
  }

  toml::table *host_table = FindHostTableMutable(config_table_, old_nickname);
  if (!host_table) {
    return Err("invalid host entry", 4);
  }
  host_table->insert_or_assign("nickname", new_nickname);

  PrintLine(MaybeStyle("Renamed host: " + old_nickname + " -> " + new_nickname,
                       "success"));
  return Ok();
}

AMConfigManager::Status
AMConfigManager::Query(const std::string &nickname) const {
  auto status = EnsureInitialized("Query");
  if (status.second != 0)
    return status;

  auto hosts = CollectHosts();
  auto it = hosts.find(nickname);
  if (it == hosts.end()) {
    PrintLine(MaybeStyle("Host not found: " + nickname, "error"));
    return Err("host not found", 2);
  }

  return PrintHost(it->first, it->second);
}

AMConfigManager::Status AMConfigManager::Add() {
  auto status = EnsureInitialized("Add");
  if (status.second != 0)
    return status;

  std::string nickname;
  HostEntry entry;
  auto prompt_status = PromptAddFields(&nickname, &entry);
  if (prompt_status.second != 0)
    return prompt_status;

  bool canceled = false;
  if (!PromptYesNo("Save host? (y/N): ", &canceled) || canceled) {
    PrintLine("Add canceled.");
    return Err("add canceled", 3);
  }

  for (const auto &field : entry.fields) {
    auto up_status = UpsertHostField(nickname, field.first, field.second);
    if (up_status.second != 0)
      return up_status;
  }

  PrintLine(MaybeStyle("Added host: " + nickname, "success"));
  return Ok();
}

AMConfigManager::Status AMConfigManager::Modify(const std::string &nickname) {
  auto status = EnsureInitialized("Modify");
  if (status.second != 0)
    return status;

  if (!HostExists(nickname)) {
    PrintLine(MaybeStyle("Host not found: " + nickname, "error"));
    return Err("host not found", 2);
  }

  HostEntry entry;
  auto prompt_status = PromptModifyFields(nickname, &entry);
  if (prompt_status.second != 0)
    return prompt_status;

  bool canceled = false;
  if (!PromptYesNo("Apply changes? (y/N): ", &canceled) || canceled) {
    PrintLine("Modify canceled.");
    return Err("modify canceled", 3);
  }

  for (const auto &field : entry.fields) {
    auto up_status = UpsertHostField(nickname, field.first, field.second);
    if (up_status.second != 0)
      return up_status;
  }

  PrintLine(MaybeStyle("Modified host: " + nickname, "success"));
  return Ok();
}

/**
 * @brief Persist an encrypted password for a given client nickname.
 */
AMConfigManager::Status AMConfigManager::SetClientPasswordEncrypted(
    const std::string &nickname, const std::string &encrypted_password,
    bool dump_now) {
  auto status = EnsureInitialized("SetClientPasswordEncrypted");
  if (status.second != 0) {
    return status;
  }
  if (!HostExists(nickname)) {
    return Err("host not found", static_cast<int>(EC::HostConfigNotFound));
  }

  std::string stored = encrypted_password;
  if (!stored.empty() && !AMAuth::IsEncrypted(stored)) {
    stored = AMAuth::EncryptPassword(stored);
  }

  auto up_status = UpsertHostField(nickname, "password", stored);
  if (up_status.second != 0) {
    return up_status;
  }
  if (dump_now) {
    return Dump();
  }
  return Ok();
}

void AMConfigManager::OnExit() {
  try {
    (void)AMConfigManager::Instance().Dump();
  } catch (const std::exception &e) {
    std::cerr << "Config dump failed: " << e.what() << std::endl;
    std::terminate();
  }
}

AMConfigManager::Status
AMConfigManager::EnsureInitialized(const char *caller) const {
  if (!initialized_) {
    return Err(AMStr::amfmt("{} called before Init()", caller), 2);
  }
  return Ok();
}

std::string AMConfigManager::ValueToString(const Value &value) const {
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
    std::ostringstream oss;
    for (size_t i = 0; i < items.size(); ++i) {
      if (i > 0)
        oss << ", ";
      oss << items[i];
    }
    return oss.str();
  }
  return "";
}

std::string AMConfigManager::StyledValue(const std::string &value,
                                         const std::string &style_name) const {
  return Format(value, style_name);
}

std::string AMConfigManager::MaybeStyle(const std::string &value,
                                        const std::string &style_name) const {
  std::string styled = Format(value, style_name);
  if (styled.empty())
    return value;
  return styled;
}

std::map<std::string, AMConfigManager::HostEntry>
AMConfigManager::CollectHosts() const {
  std::map<std::string, HostEntry> hosts;
  const toml::array *arr = GetHostsArray(config_table_);
  if (!arr)
    return hosts;
  for (const auto &node : *arr) {
    if (!node.is_table())
      continue;
    const toml::table &host = *node.as_table();
    if (!IsHostValid(host))
      continue;
    auto nickname = GetStringField(host, "nickname");
    HostEntry entry;
    for (const auto &field : host) {
      Value value;
      if (!NodeToValue(field.second, &value))
        continue;
      entry.fields[std::string(field.first.str())] = std::move(value);
    }
    if (!entry.fields.empty())
      hosts[*nickname] = std::move(entry);
  }
  return hosts;
}

AMConfigManager::Status
AMConfigManager::PrintHost(const std::string &nickname,
                           const HostEntry &entry) const {
  PrintLine("[" + nickname + "]");
  size_t width = 0;
  for (const auto &field : kHostFields)
    width = std::max(width, field.size());

  for (const auto &field : kHostFields) {
    auto it = entry.fields.find(field);
    if (it == entry.fields.end())
      continue;
    std::string value = ValueToString(it->second);
    std::string styled_value = StyledValue(value, field);
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field << " :   "
         << styled_value;
    PrintLine(line.str());
  }
  return Ok();
}

bool AMConfigManager::HostExists(const std::string &nickname) const {
  return FindHostTable(config_table_, nickname) != nullptr;
}

AMConfigManager::Status
AMConfigManager::UpsertHostField(const std::string &nickname,
                                 const std::string &field, Value value) {
  toml::table *host_table = FindHostTableMutable(config_table_, nickname);
  if (!host_table) {
    toml::array *arr = EnsureHostsArray(config_table_);
    if (!arr)
      return Err("invalid host list", 2);
    toml::table new_host;
    new_host.insert_or_assign("nickname", nickname);
    arr->push_back(std::move(new_host));
    host_table = FindHostTableMutable(config_table_, nickname);
  }
  if (!host_table)
    return Err("invalid host table", 2);

  host_table->insert_or_assign("nickname", nickname);

  if (std::holds_alternative<int64_t>(value)) {
    host_table->insert_or_assign(field, std::get<int64_t>(value));
    return Ok();
  }
  if (std::holds_alternative<bool>(value)) {
    host_table->insert_or_assign(field, std::get<bool>(value));
    return Ok();
  }
  if (std::holds_alternative<std::string>(value)) {
    std::string str_value = std::get<std::string>(value);
    if (field == "password" && !str_value.empty() &&
        !AMAuth::IsEncrypted(str_value)) {
      str_value = AMAuth::EncryptPassword(str_value);
    }
    host_table->insert_or_assign(field, str_value);
    return Ok();
  }
  if (std::holds_alternative<std::vector<std::string>>(value)) {
    toml::array arr;
    for (const auto &item : std::get<std::vector<std::string>>(value))
      arr.push_back(item);
    host_table->insert_or_assign(field, std::move(arr));
    return Ok();
  }
  return Ok();
}

AMConfigManager::Status
AMConfigManager::RemoveHost(const std::string &nickname) {
  std::size_t index = 0;
  if (!FindHostTable(config_table_, nickname, &index))
    return Ok();
  toml::array *arr = EnsureHostsArray(config_table_);
  if (!arr || index >= arr->size())
    return Ok();
  arr->erase(arr->begin() + static_cast<std::ptrdiff_t>(index));
  return Ok();
}

AMConfigManager::Status AMConfigManager::PromptAddFields(std::string *nickname,
                                                         HostEntry *entry) {
  std::string error;
  bool canceled = false;
  while (true) {
    if (!PromptLine("Nickname: ", nickname, "", true, &canceled)) {
      if (canceled) {
        PrintLine("Add canceled.");
        return Err("add canceled", 3);
      }
      return Err("failed to read nickname", 4);
    }
    error.clear();
    if (ValidateNickname(*nickname, &error))
      break;
    PrintLine(MaybeStyle(error, "error"));
  }

  std::string username;
  while (true) {
    if (!PromptLine("Username: ", &username, "", true, &canceled)) {
      PrintLine("Add canceled.");
      return Err("add canceled", 3);
    }
    if (!username.empty())
      break;
    PrintLine(MaybeStyle("Username cannot be empty.", "error"));
  }

  std::string hostname;
  while (true) {
    if (!PromptLine("Hostname: ", &hostname, "", true, &canceled)) {
      PrintLine("Add canceled.");
      return Err("add canceled", 3);
    }
    if (!hostname.empty())
      break;
    PrintLine(MaybeStyle("Hostname cannot be empty.", "error"));
  }

  std::string protocol;
  while (true) {
    if (!PromptLine("Protocol (sftp/ftp): ", &protocol, "", true, &canceled)) {
      PrintLine("Add canceled.");
      return Err("add canceled", 3);
    }
    if (protocol.empty()) {
      PrintLine(MaybeStyle("Protocol cannot be empty.", "error"));
      continue;
    }
    protocol = ToLowerCopy(protocol);
    if (protocol == "sftp" || protocol == "ftp")
      break;
    PrintLine(MaybeStyle("Protocol must be sftp or ftp.", "error"));
  }

  std::string port_input;
  int64_t port = 22;
  while (true) {
    if (!PromptLine("Port (default 22): ", &port_input, "", true, &canceled)) {
      PrintLine("Add canceled.");
      return Err("add canceled", 3);
    }
    if (port_input.empty()) {
      PrintLine("Using default port 22.");
      break;
    }
    if (ParsePositiveInt(port_input, &port))
      break;
    PrintLine(MaybeStyle("Port must be a positive integer.", "error"));
  }

  std::string keyfile;
  if (!PromptLine("Keyfile (optional): ", &keyfile, "", true, &canceled)) {
    PrintLine("Add canceled.");
    return Err("add canceled", 3);
  }

  std::string password;
  if (!PromptLine("Password (optional): ", &password, "", true, &canceled)) {
    PrintLine("Add canceled.");
    return Err("add canceled", 3);
  }

  std::string trash_dir;
  if (!PromptLine("Trash dir (optional): ", &trash_dir, "", true, &canceled)) {
    PrintLine("Add canceled.");
    return Err("add canceled", 3);
  }

  std::string buffer_input;
  int64_t buffer_size = 24 * AMMB;
  while (true) {
    if (!PromptLine("Buffer size(Default 24MB): ", &buffer_input, "", true,
                    &canceled)) {
      PrintLine("Add canceled.");
      return Err("add canceled", 3);
    }
    if (buffer_input.empty()) {
      break;
    }
    if (ParsePositiveInt(buffer_input, &buffer_size))
      break;
    PrintLine(MaybeStyle("Buffer size must be a positive integer.", "error"));
  }

  entry->fields.clear();
  entry->fields["username"] = username;
  entry->fields["hostname"] = hostname;
  entry->fields["port"] = port;
  entry->fields["keyfile"] = keyfile;
  entry->fields["password"] = AMAuth::EncryptPassword(password);
  entry->fields["trash_dir"] = trash_dir;
  entry->fields["protocol"] = protocol;
  entry->fields["buffer_size"] = buffer_size;
  AMAuth::SecureZero(password);
  return Ok();
}

AMConfigManager::Status
AMConfigManager::PromptModifyFields(const std::string &nickname,
                                    HostEntry *entry) {
  auto hosts = CollectHosts();
  auto it = hosts.find(nickname);
  if (it == hosts.end())
    return Err("host not found", 2);

  bool canceled = false;
  HostEntry updated = it->second;

  auto get_value = [&](const std::string &field) {
    auto fit = updated.fields.find(field);
    if (fit == updated.fields.end())
      return std::string();
    return ValueToString(fit->second);
  };

  std::string username = get_value("username");
  if (!PromptLine("Username: ", &username, username, false, &canceled, false)) {
    PrintLine("Modify canceled.");
    return Err("modify canceled", 3);
  }

  std::string hostname = get_value("hostname");
  if (!PromptLine("Hostname: ", &hostname, hostname, false, &canceled, false)) {
    PrintLine("Modify canceled.");
    return Err("modify canceled", 3);
  }

  std::string protocol = get_value("protocol");
  while (true) {
    if (!PromptLine("Protocol (sftp/ftp): ", &protocol, protocol, false,
                    &canceled, false)) {
      PrintLine("Modify canceled.");
      return Err("modify canceled", 3);
    }
    protocol = ToLowerCopy(protocol);
    if (protocol == "sftp" || protocol == "ftp")
      break;
    PrintLine(MaybeStyle("Protocol must be sftp or ftp.", "error"));
  }

  std::string port_input = get_value("port");
  int64_t port = 22;
  if (!port_input.empty())
    ParsePositiveInt(port_input, &port);
  while (true) {
    if (!PromptLine("Port (default 22): ", &port_input, port_input, true,
                    &canceled, false)) {
      PrintLine("Modify canceled.");
      return Err("modify canceled", 3);
    }
    if (port_input.empty())
      break;
    if (ParsePositiveInt(port_input, &port))
      break;
    PrintLine(MaybeStyle("Port must be a positive integer.", "error"));
  }
  if (!port_input.empty())
    port = std::stoll(port_input);

  std::string keyfile = get_value("keyfile");
  if (!PromptLine("Keyfile (optional): ", &keyfile, keyfile, true, &canceled,
                  false)) {
    PrintLine("Modify canceled.");
    return Err("modify canceled", 3);
  }

  std::string password = get_value("password");
  if (AMAuth::IsEncrypted(password)) {
    password.clear();
  }
  if (!PromptLine("Password (optional): ", &password, "", true, &canceled,
                  false)) {
    PrintLine("Modify canceled.");
    return Err("modify canceled", 3);
  }

  std::string trash_dir = get_value("trash_dir");
  if (!PromptLine("Trash dir (optional): ", &trash_dir, trash_dir, true,
                  &canceled, false)) {
    PrintLine("Modify canceled.");
    return Err("modify canceled", 3);
  }

  std::string buffer_input = get_value("buffer_size");
  int64_t buffer_size = 24 * AMMB;
  if (!buffer_input.empty())
    ParsePositiveInt(buffer_input, &buffer_size);
  while (true) {
    if (!PromptLine("Buffer size: ", &buffer_input, buffer_input, false,
                    &canceled, false)) {
      PrintLine("Modify canceled.");
      return Err("modify canceled", 3);
    }
    if (buffer_input.empty())
      break;
    if (ParsePositiveInt(buffer_input, &buffer_size))
      break;
    PrintLine(MaybeStyle("Buffer size must be a positive integer.", "error"));
  }

  entry->fields.clear();
  entry->fields["username"] = username;
  entry->fields["hostname"] = hostname;
  entry->fields["port"] = port;
  entry->fields["keyfile"] = keyfile;
  entry->fields["password"] = AMAuth::EncryptPassword(password);
  entry->fields["trash_dir"] = trash_dir;
  entry->fields["protocol"] = protocol;
  entry->fields["buffer_size"] = buffer_size;
  AMAuth::SecureZero(password);
  return Ok();
}

bool AMConfigManager::PromptLine(const std::string &prompt, std::string *out,
                                 const std::string &default_value,
                                 bool allow_empty, bool *canceled,
                                 bool show_default) const {
  if (canceled)
    *canceled = false;

  std::string display_prompt = prompt;
  if (show_default && !default_value.empty()) {
    display_prompt = AMStr::amfmt("{}[{}] ", prompt, default_value);
  }

  std::string placeholder_value;
  if (!show_default && !default_value.empty()) {
    placeholder_value = default_value;
  }

  const bool was_canceled = AMPromptManager::Instance().Prompt(
      display_prompt, placeholder_value, out);
  if (was_canceled) {
    if (canceled)
      *canceled = true;
    return false;
  }

  if (out->empty() && !default_value.empty()) {
    *out = default_value;
  }

  if (!allow_empty && out->empty())
    return false;
  return true;
}

bool AMConfigManager::PromptYesNo(const std::string &prompt,
                                  bool *canceled) const {
  std::string answer;
  if (!PromptLine(prompt, &answer, "", true, canceled, false))
    return false;
  std::string lower = ToLowerCopy(answer);
  return lower == "y" || lower == "yes";
}

bool AMConfigManager::ParsePositiveInt(const std::string &input,
                                       int64_t *value) const {
  if (input.empty())
    return false;
  for (char c : input) {
    if (!std::isdigit(static_cast<unsigned char>(c)))
      return false;
  }
  try {
    int64_t parsed = std::stoll(input);
    if (parsed <= 0)
      return false;
    if (value)
      *value = parsed;
    return true;
  } catch (...) {
    return false;
  }
}

bool AMConfigManager::ValidateNickname(const std::string &nickname,
                                       std::string *error) const {
  if (nickname.empty()) {
    if (error)
      *error = "Nickname cannot be empty.";
    return false;
  }
  std::regex pattern("^[A-Za-z0-9_]+$");
  if (!std::regex_match(nickname, pattern)) {
    if (error)
      *error = "Nickname must contain only letters, numbers, and underscore.";
    return false;
  }
  if (HostExists(nickname)) {
    if (error)
      *error = "Nickname already exists.";
    return false;
  }
  return true;
}
