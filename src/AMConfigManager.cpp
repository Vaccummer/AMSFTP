#include "AMConfigManager.hpp"
#include "AMEnum.hpp"
#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>

#if __has_include(<replxx.hxx>)
#include <replxx.hxx>
#define AM_HAS_REPLXX 1
#else
#define AM_HAS_REPLXX 0
#endif

namespace {
using Status = AMConfigManager::Status;

std::atomic<bool> g_interrupted{false};

void SigIntHandler(int) { g_interrupted.store(true); }

struct ScopedSigIntHandler {
  using Handler = void (*)(int);
  Handler old_handler = nullptr;
  ScopedSigIntHandler() { old_handler = std::signal(SIGINT, SigIntHandler); }
  ~ScopedSigIntHandler() { std::signal(SIGINT, old_handler); }
};

Status Ok() { return {"", 0}; }
Status Err(const std::string &msg, int code = 1) { return {msg, code}; }

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

const std::vector<std::string> kHostFields = {
    "username", "hostname",  "port",     "keyfile",
    "password", "trash_dir", "protocol", "buffer_size",
};

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
    throw std::runtime_error("$AMSFTP_ROOT environment variable is not set");
    // return Err("AMSFTP_ROOT environment variable is not set");
  }

  root_dir_ = std::filesystem::path(root_env);
  // mkdirs, already exists is ok
  std::error_code ec;
  std::filesystem::create_directories(root_dir_, ec);
  if (ec) {
    throw std::runtime_error("failed to create root directory " +
                             root_dir_.string() + ": " + ec.message());
  }

  config_path_ = root_dir_ / "config" / "config.yaml";
  settings_path_ = root_dir_ / "config" / "settings.yaml";

  if (std::filesystem::exists(config_path_)) {
    config_map_ = AMConfigProcessor::ParseFile(config_path_.string());
    if (!config_filters_.empty())
      AMConfigProcessor::FilterKeys(config_map_, config_filters_);
  } else {
    config_map_.clear();
  }

  if (std::filesystem::exists(settings_path_)) {
    settings_map_ = AMConfigProcessor::ParseFile(settings_path_.string());
    if (!settings_filters_.empty())
      AMConfigProcessor::FilterKeys(settings_map_, settings_filters_);
  } else {
    settings_map_.clear();
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
    throw std::runtime_error("failed to create config directory: " +
                             ec.message());
  }

  std::string error;
  if (!AMConfigProcessor::DumpToFile(config_map_, config_path_.string(),
                                     &error)) {
    return Err("failed to dump config.yaml: " + error);
  }
  if (!AMConfigProcessor::DumpToFile(settings_map_, settings_path_.string(),
                                     &error)) {
    return Err("failed to dump settings.yaml: " + error);
  }

  return Ok();
}

std::string AMConfigManager::Format(const std::string &ori_str,
                                    const std::string &style_name) const {
  auto status = EnsureInitialized("Format");
  if (status.second != 0)
    return ori_str;

  Path key = {"style", style_name};
  const Value *value = AMConfigProcessor::Query(settings_map_, key);
  if (!value || !std::holds_alternative<std::string>(*value))
    return ori_str;

  std::string raw = TrimCopy(std::get<std::string>(*value));
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
    std::cout << "No hosts found." << std::endl;
    return Ok();
  }

  for (const auto &item : hosts) {
    auto print_status = PrintHost(item.first, item.second);
    if (print_status.second != 0)
      return print_status;
    std::cout << std::endl;
  }
  return Ok();
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

  std::cout << std::left << std::setw(static_cast<int>(width)) << config_label
            << " = " << styled_config << std::endl;
  std::cout << std::left << std::setw(static_cast<int>(width)) << settings_label
            << " = " << styled_settings << std::endl;
  return Ok();
}

AMConfigManager::Status AMConfigManager::Delete(const std::string &nickname) {
  auto status = EnsureInitialized("Delete");
  if (status.second != 0)
    return status;

  if (!HostExists(nickname)) {
    std::cout << MaybeStyle("Host not found: " + nickname, "error")
              << std::endl;
    return Err("host not found", 2);
  }

  auto rm_status = RemoveHost(nickname);
  if (rm_status.second != 0)
    return rm_status;

  std::cout << MaybeStyle("Deleted host: " + nickname, "success") << std::endl;
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
    std::cout << MaybeStyle("Host not found: " + nickname, "error")
              << std::endl;
    return Err("host not found", 2);
  }

  return PrintHost(it->first, it->second);
}

AMConfigManager::Status AMConfigManager::Add() {
  auto status = EnsureInitialized("Add");
  if (status.second != 0)
    return status;

  ScopedSigIntHandler guard;
  g_interrupted.store(false);

  std::string nickname;
  HostEntry entry;
  auto prompt_status = PromptAddFields(&nickname, &entry);
  if (prompt_status.second != 0)
    return prompt_status;

  bool canceled = false;
  if (!PromptYesNo("Save host? (y/N): ", &canceled) || canceled) {
    std::cout << "Add canceled." << std::endl;
    return Err("add canceled", 3);
  }

  for (const auto &field : entry.fields) {
    auto up_status = UpsertHostField(nickname, field.first, field.second);
    if (up_status.second != 0)
      return up_status;
  }

  std::cout << MaybeStyle("Added host: " + nickname, "success") << std::endl;
  return Ok();
}

AMConfigManager::Status AMConfigManager::Modify(const std::string &nickname) {
  auto status = EnsureInitialized("Modify");
  if (status.second != 0)
    return status;

  if (!HostExists(nickname)) {
    std::cout << MaybeStyle("Host not found: " + nickname, "error")
              << std::endl;
    return Err("host not found", 2);
  }

  ScopedSigIntHandler guard;
  g_interrupted.store(false);

  HostEntry entry;
  auto prompt_status = PromptModifyFields(nickname, &entry);
  if (prompt_status.second != 0)
    return prompt_status;

  bool canceled = false;
  if (!PromptYesNo("Apply changes? (y/N): ", &canceled) || canceled) {
    std::cout << "Modify canceled." << std::endl;
    return Err("modify canceled", 3);
  }

  for (const auto &field : entry.fields) {
    auto up_status = UpsertHostField(nickname, field.first, field.second);
    if (up_status.second != 0)
      return up_status;
  }

  std::cout << MaybeStyle("Modified host: " + nickname, "success") << std::endl;
  return Ok();
}

void AMConfigManager::OnExit() {
  try {
    // (void)AMConfigManager::Instance().Dump();
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
  for (const auto &item : config_map_) {
    if (item.first.size() != 2)
      continue;
    const std::string &nickname = item.first[0];
    const std::string &field = item.first[1];
    hosts[nickname].fields[field] = item.second;
  }
  return hosts;
}

AMConfigManager::Status
AMConfigManager::PrintHost(const std::string &nickname,
                           const HostEntry &entry) const {
  std::cout << "[" << nickname << "]" << std::endl;
  size_t width = 0;
  for (const auto &field : kHostFields)
    width = std::max(width, field.size());

  for (const auto &field : kHostFields) {
    auto it = entry.fields.find(field);
    if (it == entry.fields.end())
      continue;
    std::string value = ValueToString(it->second);
    std::string styled_value = StyledValue(value, field);
    std::cout << std::left << std::setw(static_cast<int>(width)) << field
              << " :   " << styled_value << std::endl;
  }
  return Ok();
}

bool AMConfigManager::HostExists(const std::string &nickname) const {
  for (const auto &item : config_map_) {
    if (item.first.size() == 2 && item.first[0] == nickname) {
      return true;
    }
  }
  return false;
}

AMConfigManager::Status
AMConfigManager::UpsertHostField(const std::string &nickname,
                                 const std::string &field, Value value) {
  Path key = {nickname, field};
  auto result = config_map_.emplace(key, std::move(value));
  if (!result.second)
    result.first->second = std::move(value);
  return Ok();
}

AMConfigManager::Status
AMConfigManager::RemoveHost(const std::string &nickname) {
  for (auto it = config_map_.begin(); it != config_map_.end();) {
    if (it->first.size() == 2 && it->first[0] == nickname) {
      it = config_map_.erase(it);
    } else {
      ++it;
    }
  }
  return Ok();
}

AMConfigManager::Status AMConfigManager::PromptAddFields(std::string *nickname,
                                                         HostEntry *entry) {
  std::string error;
  bool canceled = false;
  while (true) {
    if (g_interrupted.load()) {
      std::cout << "Add canceled." << std::endl;
      return Err("add canceled", 3);
    }
    if (!PromptLine("Nickname: ", nickname, "", true, &canceled)) {
      if (canceled || g_interrupted.load()) {
        std::cout << "Add canceled." << std::endl;
        return Err("add canceled", 3);
      }
      return Err("failed to read nickname", 4);
    }
    error.clear();
    if (ValidateNickname(*nickname, &error))
      break;
    std::cout << MaybeStyle(error, "error") << std::endl;
  }

  std::string username;
  while (true) {
    if (!PromptLine("Username: ", &username, "", true, &canceled)) {
      std::cout << "Add canceled." << std::endl;
      return Err("add canceled", 3);
    }
    if (!username.empty())
      break;
    std::cout << MaybeStyle("Username cannot be empty.", "error") << std::endl;
  }

  std::string hostname;
  while (true) {
    if (!PromptLine("Hostname: ", &hostname, "", true, &canceled)) {
      std::cout << "Add canceled." << std::endl;
      return Err("add canceled", 3);
    }
    if (!hostname.empty())
      break;
    std::cout << MaybeStyle("Hostname cannot be empty.", "error") << std::endl;
  }

  std::string protocol;
  while (true) {
    if (!PromptLine("Protocol (sftp/ftp): ", &protocol, "", true, &canceled)) {
      std::cout << "Add canceled." << std::endl;
      return Err("add canceled", 3);
    }
    if (protocol.empty()) {
      std::cout << MaybeStyle("Protocol cannot be empty.", "error")
                << std::endl;
      continue;
    }
    protocol = ToLowerCopy(protocol);
    if (protocol == "sftp" || protocol == "ftp")
      break;
    std::cout << MaybeStyle("Protocol must be sftp or ftp.", "error")
              << std::endl;
  }

  std::string port_input;
  int64_t port = 22;
  while (true) {
    if (!PromptLine("Port (default 22): ", &port_input, "", true, &canceled)) {
      std::cout << "Add canceled." << std::endl;
      return Err("add canceled", 3);
    }
    if (port_input.empty()) {
      std::cout << "Using default port 22." << std::endl;
      break;
    }
    if (ParsePositiveInt(port_input, &port))
      break;
    std::cout << MaybeStyle("Port must be a positive integer.", "error")
              << std::endl;
  }

  std::string keyfile;
  if (!PromptLine("Keyfile (optional): ", &keyfile, "", true, &canceled)) {
    std::cout << "Add canceled." << std::endl;
    return Err("add canceled", 3);
  }

  std::string password;
  if (!PromptLine("Password (optional): ", &password, "", true, &canceled)) {
    std::cout << "Add canceled." << std::endl;
    return Err("add canceled", 3);
  }

  std::string trash_dir;
  if (!PromptLine("Trash dir (optional): ", &trash_dir, "", true, &canceled)) {
    std::cout << "Add canceled." << std::endl;
    return Err("add canceled", 3);
  }

  std::string buffer_input;
  int64_t buffer_size = 24 * AMMB;
  while (true) {
    if (!PromptLine("Buffer size(Default 24MB): ", &buffer_input, "", true,
                    &canceled)) {
      std::cout << "Add canceled." << std::endl;
      return Err("add canceled", 3);
    }
    if (buffer_input.empty()) {
      break;
    }
    if (ParsePositiveInt(buffer_input, &buffer_size))
      break;
    std::cout << MaybeStyle("Buffer size must be a positive integer.", "error")
              << std::endl;
  }

  entry->fields.clear();
  entry->fields["username"] = username;
  entry->fields["hostname"] = hostname;
  entry->fields["port"] = port;
  entry->fields["keyfile"] = keyfile;
  entry->fields["password"] = password;
  entry->fields["trash_dir"] = trash_dir;
  entry->fields["protocol"] = protocol;
  entry->fields["buffer_size"] = buffer_size;
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
  if (!PromptLine("Username: ", &username, username, false, &canceled)) {
    std::cout << "Modify canceled." << std::endl;
    return Err("modify canceled", 3);
  }

  std::string hostname = get_value("hostname");
  if (!PromptLine("Hostname: ", &hostname, hostname, false, &canceled)) {
    std::cout << "Modify canceled." << std::endl;
    return Err("modify canceled", 3);
  }

  std::string protocol = get_value("protocol");
  while (true) {
    if (!PromptLine("Protocol (sftp/ftp): ", &protocol, protocol, false,
                    &canceled)) {
      std::cout << "Modify canceled." << std::endl;
      return Err("modify canceled", 3);
    }
    protocol = ToLowerCopy(protocol);
    if (protocol == "sftp" || protocol == "ftp")
      break;
    std::cout << MaybeStyle("Protocol must be sftp or ftp.", "error")
              << std::endl;
  }

  std::string port_input = get_value("port");
  int64_t port = 22;
  if (!port_input.empty())
    ParsePositiveInt(port_input, &port);
  while (true) {
    if (!PromptLine("Port (default 22): ", &port_input, port_input, true,
                    &canceled)) {
      std::cout << "Modify canceled." << std::endl;
      return Err("modify canceled", 3);
    }
    if (port_input.empty())
      break;
    if (ParsePositiveInt(port_input, &port))
      break;
    std::cout << MaybeStyle("Port must be a positive integer.", "error")
              << std::endl;
  }
  if (!port_input.empty())
    port = std::stoll(port_input);

  std::string keyfile = get_value("keyfile");
  if (!PromptLine("Keyfile (optional): ", &keyfile, keyfile, true, &canceled)) {
    std::cout << "Modify canceled." << std::endl;
    return Err("modify canceled", 3);
  }

  std::string password = get_value("password");
  if (!PromptLine("Password (optional): ", &password, password, true,
                  &canceled)) {
    std::cout << "Modify canceled." << std::endl;
    return Err("modify canceled", 3);
  }

  std::string trash_dir = get_value("trash_dir");
  if (!PromptLine("Trash dir (optional): ", &trash_dir, trash_dir, true,
                  &canceled)) {
    std::cout << "Modify canceled." << std::endl;
    return Err("modify canceled", 3);
  }

  std::string buffer_input = get_value("buffer_size");
  int64_t buffer_size = 24 * AMMB;
  if (!buffer_input.empty())
    ParsePositiveInt(buffer_input, &buffer_size);
  while (true) {
    if (!PromptLine("Buffer size: ", &buffer_input, buffer_input, false,
                    &canceled)) {
      std::cout << "Modify canceled." << std::endl;
      return Err("modify canceled", 3);
    }
    if (buffer_input.empty())
      break;
    if (ParsePositiveInt(buffer_input, &buffer_size))
      break;
    std::cout << MaybeStyle("Buffer size must be a positive integer.", "error")
              << std::endl;
  }

  entry->fields.clear();
  entry->fields["username"] = username;
  entry->fields["hostname"] = hostname;
  entry->fields["port"] = port;
  entry->fields["keyfile"] = keyfile;
  entry->fields["password"] = password;
  entry->fields["trash_dir"] = trash_dir;
  entry->fields["protocol"] = protocol;
  entry->fields["buffer_size"] = buffer_size;
  return Ok();
}

bool AMConfigManager::PromptLine(const std::string &prompt, std::string *out,
                                 const std::string &default_value,
                                 bool allow_empty, bool *canceled,
                                 bool show_default) const {
  if (canceled)
    *canceled = false;

  if (g_interrupted.load()) {
    if (canceled)
      *canceled = true;
    return false;
  }

  std::string display_prompt = prompt;
  if (show_default && !default_value.empty()) {
    display_prompt = AMStr::amfmt("{}[{}] ", prompt, default_value);
  }

#if AM_HAS_REPLXX
  replxx::Replxx rx;
  const char *line = rx.input(display_prompt.c_str());
  if (!line) {
    if (canceled)
      *canceled = true;
    return false;
  }
  *out = std::string(line);
#else
  std::cout << display_prompt;
  if (!std::getline(std::cin, *out)) {
    if (canceled)
      *canceled = true;
    return false;
  }
#endif

  if (g_interrupted.load()) {
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
