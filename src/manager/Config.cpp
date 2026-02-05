#include "AMManager/Config.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/Path.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Prompt.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <limits>
#include <optional>
#include <regex>
#include <sstream>
#include <variant>

namespace {
using Path = AMConfigManager::Path;
using Value = AMConfigManager::Value;
using ClientConfig = AMConfigManager::ClientConfig;
using EC = ErrorCode;
using Json = nlohmann::ordered_json;

ECM Ok() { return {EC::Success, ""}; }
ECM Err(EC code, const std::string &msg) { return {code, msg}; }

/**
 * @brief Remove duplicate targets while preserving the original order.
 */
std::vector<std::string>
UniqueTargetsKeepOrder(const std::vector<std::string> &targets) {
  std::vector<std::string> unique;
  unique.reserve(targets.size());
  for (const auto &target : targets) {
    if (std::find(unique.begin(), unique.end(), target) != unique.end()) {
      continue;
    }
    unique.push_back(target);
  }
  return unique;
}

bool JsonArrayAllScalar(const Json &arr) {
  for (const auto &child : arr) {
    if (!(child.is_null() || child.is_boolean() || child.is_number() ||
          child.is_string())) {
      return false;
    }
  }
  return true;
}

std::string JsonScalarToString(const Json &value) {
  if (value.is_string())
    return value.get<std::string>();
  if (value.is_boolean())
    return value.get<bool>() ? "true" : "false";
  if (value.is_number_integer())
    return std::to_string(value.get<int64_t>());
  if (value.is_number_unsigned())
    return std::to_string(value.get<size_t>());
  if (value.is_number_float()) {
    std::ostringstream oss;
    oss << value.get<double>();
    return oss.str();
  }
  if (value.is_null())
    return "null";
  return value.dump();
}

/**
 * @brief Convert a settings node into a typed value with a fallback default.
 */
template <typename T>
T GetSettingValueImpl(const Json *node, const T &default_value) {
  return default_value;
}

/**
 * @brief Convert a settings node into an integer value with parsing fallback.
 */
template <>
int GetSettingValueImpl<int>(const Json *node, const int &default_value) {
  if (!node) {
    return default_value;
  }
  if (node->is_number_integer())
    return static_cast<int>(node->get<int64_t>());
  if (node->is_number_unsigned()) {
    auto value = node->get<size_t>();
    if (value <= static_cast<size_t>(std::numeric_limits<int>::max()))
      return static_cast<int>(value);
  }
  if (node->is_string()) {
    try {
      return std::stoi(node->get<std::string>());
    } catch (...) {
      return default_value;
    }
  }
  return default_value;
}

/**
 * @brief Convert a settings node into a string value with formatting fallback.
 */
template <>
std::string GetSettingValueImpl<std::string>(const Json *node,
                                             const std::string &default_value) {
  if (!node) {
    return default_value;
  }
  if (node->is_string())
    return node->get<std::string>();
  if (node->is_number_integer())
    return std::to_string(node->get<int64_t>());
  if (node->is_number_unsigned())
    return std::to_string(node->get<size_t>());
  if (node->is_boolean())
    return node->get<bool>() ? "true" : "false";
  if (node->is_number_float()) {
    std::ostringstream oss;
    oss << node->get<double>();
    return oss.str();
  }
  return default_value;
}

void PrintLine(const std::string &value) {
  AMPromptManager::Instance().Print(value);
}

std::string TrimCopy(const std::string &value) {
  std::string tmp = value;
  AMStr::VStrip(tmp);
  return tmp;
}

/**
 * @brief Normalize a configured style into a bbcode opening tag.
 */
std::string NormalizeStyleTag_(const std::string &raw) {
  std::string trimmed = TrimCopy(raw);
  if (trimmed.empty()) {
    return "";
  }
  if (trimmed.find("[/") != std::string::npos) {
    return "";
  }
  if (trimmed.front() != '[') {
    trimmed.insert(trimmed.begin(), '[');
  }
  if (trimmed.back() != ']') {
    trimmed.push_back(']');
  }
  return trimmed;
}

/**
 * @brief Wrap text with a bbcode tag when provided.
 */
std::string ApplyStyleTag_(const std::string &tag, const std::string &text) {
  if (tag.empty()) {
    return text;
  }
  return tag + text + "[/]";
}

std::string ToLowerCopy(const std::string &value) {
  std::string out = value;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

/**
 * @brief Parse a boolean token from user input.
 */
bool ParseBoolToken(const std::string &input, bool *value) {
  std::string token = TrimCopy(input);
  if (token.empty()) {
    return false;
  }
  token = ToLowerCopy(token);
  if (token == "true" || token == "1" || token == "yes" || token == "y") {
    if (value) {
      *value = true;
    }
    return true;
  }
  if (token == "false" || token == "0" || token == "no" || token == "n") {
    if (value) {
      *value = false;
    }
    return true;
  }
  return false;
}

std::optional<std::string> GetStringField(const Json &obj,
                                          const std::string &key);
std::optional<int64_t> GetIntField(const Json &obj, const std::string &key);
/** @brief Read a boolean field from a JSON object when available. */
std::optional<bool> GetBoolField(const Json &obj, const std::string &key);

const std::vector<std::string> kHostFields = {
    "hostname",    "username",  "port",      "password", "protocol",
    "buffer_size", "trash_dir", "login_dir", "keyfile",  "compression",
};

/** @brief JSON schema used to validate .AMSFTP_History.toml. */
const char kHistorySchemaJson[] = R"json(
{
  "type": "object",
  "additionalProperties": {
    "type": "object",
    "properties": {
      "commands": {
        "type": "array",
        "items": {
          "type": "string"
        }
      }
    },
    "additionalProperties": false
  }
}
)json";

const Json *GetHostsArray(const Json &root) {
  if (!root.is_object())
    return nullptr;
  auto it = root.find("HOSTS");
  if (it == root.end() || !it->is_array())
    return nullptr;
  return &(*it);
}

bool IsHostValid(const Json &tbl) {
  auto nickname = GetStringField(tbl, "nickname");
  if (!nickname || nickname->empty())
    return false;
  auto hostname = GetStringField(tbl, "hostname");
  if (!hostname || hostname->empty())
    return false;
  return true;
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

bool ReadTextFile(const std::filesystem::path &path, std::string *out,
                  std::string *error) {
  if (!out) {
    if (error)
      *error = "null output buffer";
    return false;
  }
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in.is_open()) {
    if (error)
      *error = "failed to open file";
    return false;
  }
  std::ostringstream oss;
  oss << in.rdbuf();
  if (!in.good() && !in.eof()) {
    if (error)
      *error = "failed to read file";
    return false;
  }
  *out = oss.str();
  return true;
}

std::string LoadSchemaJson(const std::filesystem::path &schema_path,
                           std::string *error) {
  if (schema_path.empty())
    return "{}";
  std::string json;
  std::string read_error;
  if (!ReadTextFile(schema_path, &json, &read_error)) {
    if (error)
      *error = "failed to read schema: " + read_error;
    return "{}";
  }
  if (json.empty())
    return "{}";
  return json;
}

bool EnsureFileExists(const std::filesystem::path &path, std::string *error) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error)
      *error = ec.message();
    return false;
  }
  if (!std::filesystem::exists(path, ec)) {
    std::ofstream out(path);
    if (!out.is_open()) {
      if (error)
        *error = "failed to create file";
      return false;
    }
  }
  return true;
}

bool ParseJsonString(const std::string &text, Json *out, std::string *error) {
  if (!out) {
    if (error)
      *error = "null json output";
    return false;
  }
  try {
    *out = Json::parse(text);
    return true;
  } catch (const std::exception &e) {
    if (error)
      *error = e.what();
    return false;
  }
}

const Json *FindJsonNode(const Json &root, const Path &path) {
  const Json *node = &root;
  for (const auto &seg : path) {
    if (node->is_object()) {
      auto it = node->find(seg);
      if (it == node->end())
        return nullptr;
      node = &(*it);
      continue;
    }
    if (node->is_array()) {
      std::size_t idx = 0;
      if (!ParseIndex(seg, &idx) || idx >= node->size())
        return nullptr;
      node = &(*node)[idx];
      continue;
    }
    return nullptr;
  }
  return node;
}

bool NodeToValue(const Json &node, Value *out) {
  if (!out)
    return false;
  if (node.is_number_integer()) {
    *out = node.get<int64_t>();
    return true;
  }
  if (node.is_boolean()) {
    *out = node.get<bool>();
    return true;
  }
  if (node.is_string()) {
    *out = node.get<std::string>();
    return true;
  }
  if (node.is_number_float()) {
    std::ostringstream oss;
    oss << node.get<double>();
    *out = oss.str();
    return true;
  }
  if (node.is_array()) {
    const Json &arr = node;
    if (!JsonArrayAllScalar(arr))
      return false;
    std::vector<std::string> items;
    items.reserve(arr.size());
    for (const auto &child : arr) {
      items.push_back(JsonScalarToString(child));
    }
    *out = std::move(items);
    return true;
  }
  return false;
}

std::optional<std::string> GetStringField(const Json &obj,
                                          const std::string &key) {
  if (!obj.is_object())
    return std::nullopt;
  auto it = obj.find(key);
  if (it == obj.end())
    return std::nullopt;
  if (it->is_string())
    return it->get<std::string>();
  if (it->is_number_integer())
    return std::to_string(it->get<int64_t>());
  if (it->is_number_unsigned())
    return std::to_string(it->get<size_t>());
  if (it->is_boolean())
    return it->get<bool>() ? "true" : "false";
  return std::nullopt;
}

std::optional<int64_t> GetIntField(const Json &obj, const std::string &key) {
  if (!obj.is_object())
    return std::nullopt;
  auto it = obj.find(key);
  if (it == obj.end())
    return std::nullopt;
  if (it->is_number_integer())
    return it->get<int64_t>();
  if (it->is_number_unsigned()) {
    auto value = it->get<size_t>();
    if (value <= static_cast<size_t>(std::numeric_limits<int64_t>::max()))
      return static_cast<int64_t>(value);
    return std::nullopt;
  }
  if (it->is_string()) {
    try {
      return std::stoll(it->get<std::string>());
    } catch (...) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

/** @brief Read a boolean field from a JSON object when available. */
std::optional<bool> GetBoolField(const Json &obj, const std::string &key) {
  if (!obj.is_object())
    return std::nullopt;
  auto it = obj.find(key);
  if (it == obj.end())
    return std::nullopt;
  if (it->is_boolean())
    return it->get<bool>();
  if (it->is_number_integer())
    return it->get<int64_t>() != 0;
  if (it->is_number_unsigned())
    return it->get<size_t>() != 0;
  if (it->is_string()) {
    std::string value = it->get<std::string>();
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (value == "true")
      return true;
    if (value == "false")
      return false;
  }
  return std::nullopt;
}

/**
 * @brief Return true if the name starts with prefix and ends with suffix.
 */
bool MatchBackupName_(const std::string &name, const std::string &prefix,
                      const std::string &suffix) {
  if (name.size() < prefix.size() + suffix.size()) {
    return false;
  }
  if (name.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }
  return name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/**
 * @brief Remove oldest backups matching prefix/suffix to keep max_count files.
 */
void PruneBackupFiles_(const std::filesystem::path &dir,
                       const std::string &prefix, const std::string &suffix,
                       int64_t max_count) {
  if (max_count <= 0) {
    return;
  }
  std::error_code ec;
  if (!std::filesystem::exists(dir, ec) || ec) {
    return;
  }

  std::vector<std::filesystem::path> items;
  for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
    if (ec) {
      break;
    }
    if (!entry.is_regular_file(ec) || ec) {
      continue;
    }
    std::string name = entry.path().filename().string();
    if (MatchBackupName_(name, prefix, suffix)) {
      items.push_back(entry.path());
    }
  }

  if (items.size() <= static_cast<size_t>(max_count)) {
    return;
  }

  std::sort(items.begin(), items.end(),
            [](const std::filesystem::path &a, const std::filesystem::path &b) {
              return a.filename().string() < b.filename().string();
            });

  size_t remove_count = items.size() - static_cast<size_t>(max_count);
  for (size_t i = 0; i < remove_count; ++i) {
    std::filesystem::remove(items[i], ec);
  }
}

/**
 * @brief Ensure the KnownHosts array exists and return it for mutation.
 */
Json *EnsureKnownHostsArray(Json &root) {
  if (!root.is_object())
    root = Json::object();
  auto it = root.find("KnownHosts");
  if (it == root.end() || !it->is_array()) {
    root["KnownHosts"] = Json::array();
  }
  return &root["KnownHosts"];
}

/**
 * @brief Return the KnownHosts array when available.
 */
const Json *GetKnownHostsArray(const Json &root) {
  if (!root.is_object())
    return nullptr;
  auto it = root.find("KnownHosts");
  if (it == root.end() || !it->is_array())
    return nullptr;
  return &(*it);
}

/**
 * @brief Check whether a known_hosts item matches host, port, and protocol.
 *
 * RSA protocol variants are treated as compatible with "ssh-rsa".
 */
bool KnownHostMatch(const Json &item, const std::string &hostname, int port,
                    const std::string &protocol) {
  if (!item.is_object())
    return false;
  auto host_value = GetStringField(item, "hostname");
  if (!host_value || *host_value != hostname)
    return false;
  auto port_value = GetIntField(item, "port");
  if (!port_value.has_value() || *port_value != port)
    return false;
  auto protocol_value = GetStringField(item, "protocol");
  if (!protocol_value)
    return false;
  const std::string expected = ToLowerCopy(*protocol_value);
  const std::string actual = ToLowerCopy(protocol);
  if (expected == actual)
    return true;
  const bool expected_is_rsa =
      expected == "rsa-sha2-256" || expected == "rsa-sha2-512";
  const bool actual_is_rsa =
      actual == "rsa-sha2-256" || actual == "rsa-sha2-512";
  if ((expected == "ssh-rsa" && actual_is_rsa) ||
      (actual == "ssh-rsa" && expected_is_rsa)) {
    return true;
  }
  return false;
}

/**
 * @brief Normalize a known host nickname to match the schema pattern.
 */
std::string
NormalizeKnownHostNickname(const AMConfigManager::KnownHostEntry &entry) {
  std::string nickname =
      entry.nickname.empty() ? entry.hostname : entry.nickname;
  if (nickname.empty()) {
    nickname = "host";
  }
  for (char &c : nickname) {
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' ||
          c == '-')) {
      c = '_';
    }
  }
  if (nickname.empty()) {
    nickname = "host";
  }
  return nickname;
}

Json *EnsureHostsArray(Json &root) {
  if (!root.is_object())
    root = Json::object();
  auto it = root.find("HOSTS");
  if (it == root.end() || !it->is_array()) {
    root["HOSTS"] = Json::array();
  }
  return &root["HOSTS"];
}

const Json *FindHostJson(const Json &root, const std::string &nickname,
                         std::size_t *out_index = nullptr) {
  const Json *arr = GetHostsArray(root);
  if (!arr)
    return nullptr;
  for (std::size_t i = 0; i < arr->size(); ++i) {
    const Json &item = (*arr)[i];
    if (!item.is_object())
      continue;
    if (!IsHostValid(item))
      continue;
    auto name = GetStringField(item, "nickname");
    if (name && *name == nickname) {
      if (out_index)
        *out_index = i;
      return &item;
    }
  }
  return nullptr;
}

Json *FindHostJsonMutable(Json &root, const std::string &nickname,
                          std::size_t *out_index = nullptr) {
  Json *arr = EnsureHostsArray(root);
  if (!arr)
    return nullptr;
  for (std::size_t i = 0; i < arr->size(); ++i) {
    Json &item = (*arr)[i];
    if (!item.is_object())
      continue;
    auto name = GetStringField(item, "nickname");
    if (name && *name == nickname) {
      if (out_index)
        *out_index = i;
      return &item;
    }
  }
  return nullptr;
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

/** @brief Stop the background writer and release config handles. */
AMConfigManager::~AMConfigManager() { CloseHandles(); }

/** @brief Start the background writer thread if not running. */
void AMConfigManager::StartWriteThread_() {
  if (write_running_.load()) {
    return;
  }
  write_running_.store(true);
  write_thread_ = std::thread([this]() { WriteThreadLoop_(); });
}

/** @brief Stop the background writer thread and drain pending tasks. */
void AMConfigManager::StopWriteThread_() {
  write_running_.store(false);
  write_cv_.notify_all();
  if (write_thread_.joinable()) {
    write_thread_.join();
  }
}

/** @brief Background worker loop for serialized write tasks. */
void AMConfigManager::WriteThreadLoop_() {
  while (true) {
    std::function<void()> task;
    {
      std::unique_lock<std::mutex> lock(write_mtx_);
      write_cv_.wait(lock, [this]() {
        return !write_running_.load() || !write_queue_.empty();
      });
      if (!write_running_.load() && write_queue_.empty()) {
        break;
      }
      task = std::move(write_queue_.front());
      write_queue_.pop_front();
    }
    if (task) {
      try {
        task();
      } catch (...) {
        AM_PROMPT_ERROR("ConfigWriter", "background write task failed", false,
                        0);
      }
    }
  }
}

/**
 * @brief Write a TOML snapshot to a target path using the given handle.
 */
void AMConfigManager::WriteSnapshotToPath_(
    ConfigHandle *handle, const std::string &json,
    const std::filesystem::path &out_path) const {
  if (!handle) {
    return;
  }
  char *err = nullptr;
  int rc = cfgffi_write(handle, out_path.string().c_str(), json.c_str(), &err);
  if (err) {
    cfgffi_free_string(err);
  }
  (void)rc;
}

/**
 * @brief Submit a no-arg write task to the background writer thread.
 */
void AMConfigManager::SubmitWriteTask(std::function<void()> task) {
  if (!task) {
    return;
  }
  if (!write_running_.load()) {
    task();
    return;
  }
  {
    std::lock_guard<std::mutex> lock(write_mtx_);
    write_queue_.push_back(std::move(task));
  }
  write_cv_.notify_one();
}

ECM AMConfigManager::Init() {
  const std::string root_env = GetEnvCopy("AMSFTP_ROOT");
  if (root_env.empty()) {
    AM_PROMPT_ERROR("ConfigInit",
                    "$AMSFTP_ROOT environment variable is not set", true, 2);
    return Err(EC::ConfigInvalid,
               "AMSFTP_ROOT environment variable is not set");
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
    return Err(EC::ConfigLoadFailed, "failed to create root directory " +
                                         root_dir_.string() + ": " +
                                         ec.message());
  }

  config_path_ = root_dir_ / "config" / "config.toml";
  settings_path_ = root_dir_ / "config" / "settings.toml";
  known_hosts_path_ = root_dir_ / "config" / "known_hosts.toml";
  config_schema_path_ = root_dir_ / "config" / "config.schema.json";
  settings_schema_path_ = root_dir_ / "config" / "settings.schema.json";
  known_hosts_schema_path_ = root_dir_ / "config" / "known_hosts.schema.json";

  CloseHandles();
  config_json_ = Json::object();
  settings_json_ = Json::object();
  known_hosts_json_ = Json::object();
  history_json_ = Json::object();

  {
    std::string error;
    if (!EnsureFileExists(config_path_, &error)) {
      AM_PROMPT_ERROR("ConfigInit", "failed to create config file: " + error,
                      true, 2);
      return Err(EC::ConfigLoadFailed,
                 "failed to create config file: " + error);
    }
    const std::string schema_json = LoadSchemaJson(config_schema_path_, &error);
    char *err = nullptr;
    config_handle_ =
        cfgffi_read(config_path_.string().c_str(), schema_json.c_str(), &err);
    if (!config_handle_) {
      std::string msg = err ? err : "cfgffi_read failed";
      if (err)
        cfgffi_free_string(err);
      AM_PROMPT_ERROR("ConfigInit", "failed to parse config.toml: " + msg, true,
                      2);
      return Err(EC::ConfigLoadFailed, "failed to parse config.toml: " + msg);
    }
    if (err)
      cfgffi_free_string(err);
    char *json_c = cfgffi_get_json(config_handle_);
    if (!json_c) {
      return Err(EC::ConfigLoadFailed, "failed to read config json");
    }
    std::string json_str(json_c);
    cfgffi_free_string(json_c);
    if (!ParseJsonString(json_str, &config_json_, &error)) {
      return Err(EC::ConfigLoadFailed, "failed to parse config json: " + error);
    }
  }

  {
    std::string error;
    if (!EnsureFileExists(settings_path_, &error)) {
      AM_PROMPT_ERROR("ConfigInit", "failed to create settings file: " + error,
                      true, 2);
      return Err(EC::ConfigLoadFailed,
                 "failed to create settings file: " + error);
    }
    const std::string schema_json =
        LoadSchemaJson(settings_schema_path_, &error);
    char *err = nullptr;
    settings_handle_ =
        cfgffi_read(settings_path_.string().c_str(), schema_json.c_str(), &err);
    if (!settings_handle_) {
      std::string msg = err ? err : "cfgffi_read failed";
      if (err)
        cfgffi_free_string(err);
      AM_PROMPT_ERROR("ConfigInit", "failed to parse settings.toml: " + msg,
                      true, 2);
      return Err(EC::ConfigLoadFailed, "failed to parse settings.toml: " + msg);
    }
    if (err)
      cfgffi_free_string(err);
    char *json_c = cfgffi_get_json(settings_handle_);
    if (!json_c) {
      return Err(EC::ConfigLoadFailed, "failed to read settings json");
    }
    std::string json_str(json_c);
    cfgffi_free_string(json_c);
    if (!ParseJsonString(json_str, &settings_json_, &error)) {
      return Err(EC::ConfigLoadFailed,
                 "failed to parse settings json: " + error);
    }
  }

  {
    std::string error;
    if (!EnsureFileExists(known_hosts_path_, &error)) {
      AM_PROMPT_ERROR("ConfigInit",
                      "failed to create known_hosts file: " + error, true, 2);
      return Err(EC::ConfigLoadFailed,
                 "failed to create known_hosts file: " + error);
    }
    const std::string schema_json =
        LoadSchemaJson(known_hosts_schema_path_, &error);
    char *err = nullptr;
    known_hosts_handle_ = cfgffi_read(known_hosts_path_.string().c_str(),
                                      schema_json.c_str(), &err);
    if (!known_hosts_handle_) {
      std::string msg = err ? err : "cfgffi_read failed";
      if (err)
        cfgffi_free_string(err);
      AM_PROMPT_ERROR("ConfigInit", "failed to parse known_hosts.toml: " + msg,
                      true, 2);
      return Err(EC::ConfigLoadFailed,
                 "failed to parse known_hosts.toml: " + msg);
    }
    if (err)
      cfgffi_free_string(err);
    char *json_c = cfgffi_get_json(known_hosts_handle_);
    if (!json_c) {
      return Err(EC::ConfigLoadFailed, "failed to read known_hosts json");
    }
    std::string json_str(json_c);
    cfgffi_free_string(json_c);
    if (!ParseJsonString(json_str, &known_hosts_json_, &error)) {
      return Err(EC::ConfigLoadFailed,
                 "failed to parse known_hosts json: " + error);
    }
  }

  initialized_ = true;
  backup_prune_checked_ = false;
  if (!exit_hook_installed_) {
    std::atexit(&AMConfigManager::OnExit);
    exit_hook_installed_ = true;
  }

  StartWriteThread_();
  return Ok();
}

ECM AMConfigManager::Dump() {
  auto status = EnsureInitialized("Dump");
  if (status.first != EC::Success)
    return status;

  std::filesystem::path config_dir = root_dir_ / "config";
  std::error_code ec;
  std::filesystem::create_directories(config_dir, ec);
  if (ec) {
    AM_PROMPT_ERROR("ConfigDumpError",
                    "failed to create config directory: " + ec.message(), true,
                    2);
    return Err(EC::ConfigDumpFailed,
               "failed to create config directory: " + ec.message());
  }

  std::string error;
  std::string msg;
  if (!config_handle_) {
    return Err(EC::ConfigNotInitialized, "config handle not initialized");
  }
  if (!settings_handle_) {
    return Err(EC::ConfigNotInitialized, "settings handle not initialized");
  }
  if (!known_hosts_handle_) {
    return Err(EC::ConfigNotInitialized, "known_hosts handle not initialized");
  }
  std::lock_guard<std::mutex> lock(handle_mtx_);
  {
    std::string json = config_json_.dump(2);
    char *err = nullptr;
    int rc = cfgffi_write_inplace(config_handle_, json.c_str(), &err);
    if (rc != 0) {
      msg = err ? err : "Unknown Error";
      if (err) {
        cfgffi_free_string(err);
      }
      return Err(
          EC::ConfigDumpFailed,
          AMStr::amfmt("Failed to dump to {}: {}", config_path_.string(), msg));
    }
    if (err)
      cfgffi_free_string(err);
    char *json_c = cfgffi_get_json(config_handle_);
    if (json_c) {
      std::string json_str(json_c);
      cfgffi_free_string(json_c);
      (void)ParseJsonString(json_str, &config_json_, nullptr);
    }
  }
  {
    std::string json = settings_json_.dump(2);
    char *err = nullptr;
    int rc = cfgffi_write_inplace(settings_handle_, json.c_str(), &err);
    if (rc != 0) {
      msg = err ? err : "Unknown cfgffi_write Error";
      if (err)
        cfgffi_free_string(err);
      return Err(EC::ConfigDumpFailed,
                 AMStr::amfmt("Failed to dump to {}: {}",
                              settings_path_.string(), msg));
    }
    if (err)
      cfgffi_free_string(err);
    char *json_c = cfgffi_get_json(settings_handle_);
    if (json_c) {
      std::string json_str(json_c);
      cfgffi_free_string(json_c);
      (void)ParseJsonString(json_str, &settings_json_, nullptr);
    }
  }
  {
    std::string json = known_hosts_json_.dump(2);
    char *err = nullptr;
    int rc = cfgffi_write_inplace(known_hosts_handle_, json.c_str(), &err);
    if (rc != 0) {
      msg = err ? err : "Unknown cfgffi_write Error";
      if (err)
        cfgffi_free_string(err);
      return Err(EC::ConfigDumpFailed,
                 AMStr::amfmt("Failed to dump to {}: {}",
                              known_hosts_path_.string(), msg));
    }
    if (err)
      cfgffi_free_string(err);
    char *json_c = cfgffi_get_json(known_hosts_handle_);
    if (json_c) {
      std::string json_str(json_c);
      cfgffi_free_string(json_c);
      (void)ParseJsonString(json_str, &known_hosts_json_, nullptr);
    }
  }

  return Ok();
}

/**
 * @brief Load history data from .AMSFTP_History.toml into memory.
 */
ECM AMConfigManager::LoadHistory() {
  auto status = EnsureInitialized("LoadHistory");
  if (status.first != EC::Success) {
    return status;
  }
  if (history_handle_) {
    return Ok();
  }
  history_path_ = root_dir_ / ".AMSFTP_History.toml";
  history_json_ = Json::object();
  std::string error;
  if (!EnsureFileExists(history_path_, &error)) {
    return Err(EC::ConfigLoadFailed, "failed to create history file: " + error);
  }
  const std::string schema_json = kHistorySchemaJson;
  char *err = nullptr;
  {
    std::lock_guard<std::mutex> lock(handle_mtx_);
    history_handle_ =
        cfgffi_read(history_path_.string().c_str(), schema_json.c_str(), &err);
    if (!history_handle_) {
      std::string msg = err ? err : "cfgffi_read failed";
      if (err)
        cfgffi_free_string(err);
      return Err(EC::ConfigLoadFailed, "failed to parse history file: " + msg);
    }
    if (err)
      cfgffi_free_string(err);
    char *json_c = cfgffi_get_json(history_handle_);
    if (!json_c) {
      return Err(EC::ConfigLoadFailed, "failed to read history json");
    }
    std::string json_str(json_c);
    cfgffi_free_string(json_c);
    if (!ParseJsonString(json_str, &history_json_, &error)) {
      return Err(EC::ConfigLoadFailed,
                 "failed to parse history json: " + error);
    }
  }
  return Ok();
}

/**
 * @brief Fetch history commands for a nickname.
 */
ECM AMConfigManager::GetHistoryCommands(const std::string &nickname,
                                        std::vector<std::string> *out) {
  auto status = LoadHistory();
  if (status.first != EC::Success) {
    return status;
  }
  if (!out) {
    return Err(EC::InvalidArg, "null history output");
  }
  out->clear();
  if (nickname.empty()) {
    return Ok();
  }
  const Json *node = FindJsonNode(history_json_, {nickname, "commands"});
  if (!node || !node->is_array()) {
    return Ok();
  }
  for (const auto &item : *node) {
    if (item.is_string()) {
      out->push_back(item.get<std::string>());
    }
  }
  return Ok();
}

/**
 * @brief Store history commands for a nickname and optionally persist.
 */
ECM AMConfigManager::SetHistoryCommands(
    const std::string &nickname, const std::vector<std::string> &commands,
    bool dump_now) {
  auto status = LoadHistory();
  if (status.first != EC::Success) {
    return status;
  }
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty history nickname");
  }
  if (!history_json_.is_object()) {
    history_json_ = Json::object();
  }
  Json &node = history_json_[nickname];
  if (!node.is_object()) {
    node = Json::object();
  }
  node["commands"] = commands;
  if (dump_now) {
    return DumpHistory_();
  }
  return Ok();
}

/**
 * @brief Resolve history size limit from settings with minimum 10.
 */
int AMConfigManager::ResolveMaxHistoryCount(int default_value) const {
  int value = GetSettingInt({"InternalVars", "MaxHistoryCount"}, default_value);
  if (value < 10) {
    value = 10;
  }
  return value;
}

/**
 * @brief Persist in-memory history JSON to disk.
 */
ECM AMConfigManager::DumpHistory_() {
  if (!history_handle_) {
    return Err(EC::ConfigNotInitialized, "history handle not initialized");
  }
  std::string json = history_json_.dump(2);
  char *err = nullptr;
  {
    std::lock_guard<std::mutex> lock(handle_mtx_);
    int rc = cfgffi_write_inplace(history_handle_, json.c_str(), &err);
    if (rc != 0) {
      std::string msg = err ? err : "Unkown cfgffi_write Error";
      if (err)
        cfgffi_free_string(err);
      return Err(EC::ConfigDumpFailed,
                 AMStr::amfmt("Failed to dump to {}: {}",
                              history_path_.string(), msg));
    }
    if (err)
      cfgffi_free_string(err);
    char *json_c = cfgffi_get_json(history_handle_);
    if (json_c) {
      std::string json_str(json_c);
      cfgffi_free_string(json_c);
      (void)ParseJsonString(json_str, &history_json_, nullptr);
    }
  }
  return Ok();
}

/**
 * @brief Backup config/settings/known_hosts when the interval elapses.
 */
ECM AMConfigManager::ConfigBackupIfNeeded() {
  auto status = EnsureInitialized("ConfigBackupIfNeeded");
  if (status.first != EC::Success)
    return status;

  constexpr bool kDefaultEnabled = true;
  constexpr int64_t kDefaultIntervalS = 10;
  constexpr int64_t kDefaultLastBackupS = 0;
  constexpr int64_t kDefaultMaxBackupCount = 3;
  constexpr int64_t kMinIntervalS = 15;
  constexpr int64_t kNegativeIntervalFallbackS = 60;

  bool changed = false;
  if (!settings_json_.is_object()) {
    settings_json_ = Json::object();
    changed = true;
  }

  Json &backup_cfg = settings_json_["AutoConfigBackup"];
  if (!backup_cfg.is_object()) {
    backup_cfg = Json::object();
    changed = true;
  }

  bool enabled = kDefaultEnabled;
  if (auto v = GetBoolField(backup_cfg, "enabled")) {
    enabled = *v;
  } else {
    backup_cfg["enabled"] = kDefaultEnabled;
    changed = true;
  }

  int64_t interval_s = kNegativeIntervalFallbackS;
  if (auto v = GetIntField(backup_cfg, "interval_s")) {
    interval_s = *v;
  } else {
    changed = true;
  }
  if (interval_s == 0) {
    interval_s = kNegativeIntervalFallbackS;
    changed = true;
  } else if (interval_s < 0) {
    interval_s = kNegativeIntervalFallbackS;
    changed = true;
  } else if (interval_s > 0 && interval_s < kMinIntervalS) {
    interval_s = kMinIntervalS;
    changed = true;
  }
  backup_cfg["interval_s"] = interval_s;

  int64_t max_backup_count = kDefaultMaxBackupCount;
  if (auto v = GetIntField(backup_cfg, "max_backup_count")) {
    max_backup_count = *v;
  } else {
    changed = true;
  }
  if (max_backup_count < 1) {
    max_backup_count = 1;
    changed = true;
  }
  backup_cfg["max_backup_count"] = max_backup_count;

  const int64_t now_s = static_cast<int64_t>(timenow());
  int64_t last_backup_time_s = kDefaultLastBackupS;
  if (auto v = GetIntField(backup_cfg, "last_backup_time_s")) {
    last_backup_time_s = *v;
  } else {
    changed = true;
  }
  if (last_backup_time_s < 0) {
    last_backup_time_s = 0;
    changed = true;
  }
  if (last_backup_time_s > now_s) {
    last_backup_time_s = now_s;
    changed = true;
  }
  backup_cfg["last_backup_time_s"] = last_backup_time_s;

  if (!backup_prune_checked_) {
    std::filesystem::path backup_dir = root_dir_ / "config" / "bak";
    PruneBackupFiles_(backup_dir, "config-", ".toml.bak", max_backup_count);
    PruneBackupFiles_(backup_dir, "settings-", ".toml.bak", max_backup_count);
    PruneBackupFiles_(backup_dir, "known_hosts-", ".toml.bak",
                      max_backup_count);
    backup_prune_checked_ = true;
  }

  if (!enabled) {
    if (changed) {
      std::string settings_json = settings_json_.dump(2);
      SubmitWriteTask([this, settings_json]() {
        std::lock_guard<std::mutex> lock(handle_mtx_);
        WriteSnapshotToPath_(settings_handle_, settings_json, settings_path_);
      });
    }
    return Ok();
  }

  if (interval_s > 0 && (now_s - last_backup_time_s) < interval_s) {
    if (changed) {
      std::string settings_json = settings_json_.dump(2);
      SubmitWriteTask([this, settings_json]() {
        std::lock_guard<std::mutex> lock(handle_mtx_);
        WriteSnapshotToPath_(settings_handle_, settings_json, settings_path_);
      });
    }
    return Ok();
  }

  if (!config_handle_ || !settings_handle_ || !known_hosts_handle_) {
    return Err(EC::ConfigNotInitialized, "config handles not initialized");
  }

  backup_cfg["last_backup_time_s"] = now_s;
  changed = true;

  std::filesystem::path backup_dir = root_dir_ / "config" / "bak";
  std::error_code ec;
  std::filesystem::create_directories(backup_dir, ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed,
               "failed to create backup dir: " + ec.message());
  }

  const std::string stamp =
      FormatTime(static_cast<size_t>(now_s), "%Y-%m-%d-%H-%M");
  std::filesystem::path config_backup =
      backup_dir / ("config-" + stamp + ".toml.bak");
  std::filesystem::path settings_backup =
      backup_dir / ("settings-" + stamp + ".toml.bak");
  std::filesystem::path known_hosts_backup =
      backup_dir / ("known_hosts-" + stamp + ".toml.bak");

  std::string config_json = config_json_.dump(2);
  std::string settings_json = settings_json_.dump(2);
  std::string known_hosts_json = known_hosts_json_.dump(2);

  SubmitWriteTask([this, config_backup, settings_backup, known_hosts_backup,
                   config_json, settings_json, known_hosts_json]() {
    std::lock_guard<std::mutex> lock(handle_mtx_);
    WriteSnapshotToPath_(config_handle_, config_json, config_backup);
    WriteSnapshotToPath_(settings_handle_, settings_json, settings_backup);
    WriteSnapshotToPath_(known_hosts_handle_, known_hosts_json,
                         known_hosts_backup);
  });

  if (changed) {
    SubmitWriteTask([this, settings_json]() {
      std::lock_guard<std::mutex> lock(handle_mtx_);
      WriteSnapshotToPath_(settings_handle_, settings_json, settings_path_);
    });
  }

  return Ok();
}

/**
 * @brief Apply configured styles to text using path or input highlight rules.
 */
std::string AMConfigManager::Format(const std::string &ori_str_f,
                                    const std::string &style_name,
                                    const PathInfo *path_info) const {
  auto status = EnsureInitialized("Format");
  const std::string ori_str = AMStr::BBCEscape(ori_str_f);
  if (status.first != EC::Success) {
    return ori_str;
  }

  auto apply_input_style = [&](const std::string &name,
                               const std::string &text) -> std::string {
    if (name.empty()) {
      return text;
    }
    Path key = {"style", "InputHighlight", name};
    const Json *node = FindJsonNode(settings_json_, key);
    if (!node || !node->is_string()) {
      return text;
    }
    std::string raw = TrimCopy(node->get<std::string>());
    if (raw.empty()) {
      return text;
    }
    if (raw.front() != '[' || raw.back() != ']') {
      return text;
    }
    if (raw.find("[/") != std::string::npos) {
      return text;
    }
    return raw + text + "[/]";
  };

  if (!path_info) {
    return apply_input_style(style_name, ori_str);
  }

  std::string base_key = "regular";
  switch (path_info->type) {
  case PathType::DIR:
    base_key = "dir";
    break;
  case PathType::SYMLINK:
    base_key = "symlink";
    break;
  case PathType::FILE:
    base_key = "regular";
    break;
  default:
    base_key = "otherspecial";
    break;
  }

  std::string main_tag =
      NormalizeStyleTag_(GetSettingString({"style", "Path1", base_key}, ""));
  const std::string path_name =
      !path_info->name.empty()
          ? path_info->name
          : (ori_str_f.empty() ? std::string()
                               : AMPathStr::basename(ori_str_f));
  if (path_info->type == PathType::FILE) {
    const std::string ext = AMPathStr::extname(path_name);
    if (!ext.empty()) {
      std::string ext_tag =
          NormalizeStyleTag_(GetSettingString({"style", "File2", ext}, ""));
      if (!ext_tag.empty()) {
        main_tag = ext_tag;
      }
    }
  }

  std::string styled = main_tag.empty() ? apply_input_style(style_name, ori_str)
                                        : ApplyStyleTag_(main_tag, ori_str);

  const bool is_hidden = !path_name.empty() && path_name.front() == '.';
  const bool is_nowrite =
      path_info->mode_int != 0 && (path_info->mode_int & 0222) == 0;

  auto resolve_extra = [&](const std::string &key) -> std::string {
    std::string tag = NormalizeStyleTag_(
        GetSettingString({"style", "PathExtraStyle", key}, ""));
    if (!tag.empty()) {
      return tag;
    }
    return NormalizeStyleTag_(
        GetSettingString({"style", "PathSpecific3", key}, ""));
  };

  if (is_hidden) {
    const std::string extra_tag = resolve_extra("hidden");
    if (!extra_tag.empty()) {
      styled = ApplyStyleTag_(extra_tag, styled);
    }
  }
  if (is_nowrite) {
    const std::string extra_tag = resolve_extra("nowrite");
    if (!extra_tag.empty()) {
      styled = ApplyStyleTag_(extra_tag, styled);
    }
  }

  return styled;
}

ECM AMConfigManager::List() const {
  auto status = EnsureInitialized("List");
  if (status.first != EC::Success)
    return status;

  auto hosts = CollectHosts();
  if (hosts.empty()) {
    PrintLine("");
    return Ok();
  }

  for (const auto &item : hosts) {
    auto print_status = PrintHost(item.first, item.second);
    if (print_status.first != EC::Success)
      return print_status;
    PrintLine("");
  }
  return Ok();
}

ECM AMConfigManager::ListName() const {
  auto status = EnsureInitialized("ListName");
  if (status.first != EC::Success)
    return status;

  auto hosts = CollectHosts();
  if (hosts.empty()) {
    PrintLine("");
    return Ok();
  }

  const size_t max_width = 80;
  size_t current_width = 0;
  std::ostringstream line;

  for (auto it = hosts.begin(); it != hosts.end(); ++it) {
    const std::string &name = it->first;
    const std::string styled = Format(name, "nickname");
    size_t name_len = name.size();
    size_t extra = current_width == 0 ? 0 : 1;

    if (current_width + extra + name_len > max_width && current_width > 0) {
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
    current_width += name_len;
  }

  if (current_width > 0) {
    PrintLine(line.str());
  }
  return Ok();
}

std::pair<ECM, std::vector<std::string>>
AMConfigManager::PrivateKeys(bool print_sign) const {
  auto status = EnsureInitialized("PrivateKeys");
  if (status.first != EC::Success)
    return {status, {}};

  std::vector<std::string> keys;
  const Json *node = nullptr;
  if (config_json_.is_object()) {
    auto it = config_json_.find("private_keys");
    if (it != config_json_.end()) {
      node = &(*it);
    }
  }
  if (node && node->is_array()) {
    keys.reserve(node->size());
    for (const auto &item : *node) {
      if (item.is_string()) {
        keys.push_back(item.get<std::string>());
      }
    }
  }

  if (print_sign) {
    PrintLine("[!a][Private_keys][/a]");
    for (const auto &path : keys) {
      auto [path_rcm, path_info] = AMFS::stat(path, false);
      const PathInfo *path_ptr =
          path_rcm.first == EC::Success ? &path_info : nullptr;
      PrintLine(Format(path, "dir", path_ptr));
    }
  }

  return {Ok(), keys};
}

/**
 * @brief Find a known host entry by hostname, port, and protocol.
 */
std::pair<ECM, std::optional<AMConfigManager::KnownHostEntry>>
AMConfigManager::FindKnownHost(const std::string &hostname, int port,
                               const std::string &protocol) const {
  auto status = EnsureInitialized("FindKnownHost");
  if (status.first != EC::Success)
    return {status, std::nullopt};

  const Json *arr = GetKnownHostsArray(known_hosts_json_);
  if (!arr) {
    return {Ok(), std::nullopt};
  }

  for (const auto &item : *arr) {
    if (!KnownHostMatch(item, hostname, port, protocol)) {
      continue;
    }
    KnownHostEntry entry;
    if (auto nickname = GetStringField(item, "nickname")) {
      entry.nickname = *nickname;
    }
    if (auto host_value = GetStringField(item, "hostname")) {
      entry.hostname = *host_value;
    }
    if (auto port_value = GetIntField(item, "port")) {
      entry.port = static_cast<int>(*port_value);
    }
    if (auto protocol_value = GetStringField(item, "protocol")) {
      entry.protocol = *protocol_value;
    }
    if (auto fingerprint = GetStringField(item, "fingerprint")) {
      entry.fingerprint = *fingerprint;
    }
    return {Ok(), entry};
  }

  return {Ok(), std::nullopt};
}

/**
 * @brief Insert or update a known host entry and optionally persist it.
 */
ECM AMConfigManager::UpsertKnownHost(const KnownHostEntry &entry,
                                     bool dump_now) {
  auto status = EnsureInitialized("UpsertKnownHost");
  if (status.first != EC::Success) {
    return status;
  }

  if (entry.hostname.empty() || entry.protocol.empty() || entry.port <= 0) {
    return Err(EC::InvalidArg, "invalid known host entry");
  }

  Json *arr = EnsureKnownHostsArray(known_hosts_json_);
  if (!arr) {
    return Err(EC::ConfigInvalid, "known_hosts array not initialized");
  }

  Json *target = nullptr;
  for (auto &item : *arr) {
    if (KnownHostMatch(item, entry.hostname, entry.port, entry.protocol)) {
      target = &item;
      break;
    }
  }

  if (!target) {
    Json new_entry = Json::object();
    (*arr).push_back(new_entry);
    target = &(*arr)[arr->size() - 1];
  }

  (*target)["nickname"] = NormalizeKnownHostNickname(entry);
  (*target)["hostname"] = entry.hostname;
  (*target)["port"] = entry.port;
  (*target)["protocol"] = entry.protocol;
  (*target)["fingerprint"] = entry.fingerprint;

  if (dump_now) {
    return Dump();
  }
  return Ok();
}

/**
 * @brief Build a known host verification callback for SFTP clients.
 */
AMConfigManager::KnownHostCallback AMConfigManager::BuildKnownHostCallback() {
  if (known_host_cb_) {
    return known_host_cb_;
  }
  known_host_cb_ = [this](KnownHostEntry entry) -> ECM {
    auto status = EnsureInitialized("KnownHostCallback");
    if (status.first != EC::Success) {
      return status;
    }

    if (entry.hostname.empty() || entry.protocol.empty() || entry.port <= 0) {
      return Err(EC::InvalidArg, "invalid known host entry");
    }

    entry.fingerprint = AMStr::TrimWhitespaceCopy(entry.fingerprint);
    entry.fingerprint_sha256 =
        AMStr::TrimWhitespaceCopy(entry.fingerprint_sha256);
    if (entry.fingerprint.empty()) {
      return Err(EC::InvalidArg, "empty host fingerprint");
    }

    auto [find_status, existing] =
        FindKnownHost(entry.hostname, entry.port, entry.protocol);
    if (find_status.first != EC::Success) {
      return find_status;
    }

    if (!existing.has_value() ||
        AMStr::TrimWhitespaceCopy(existing->fingerprint).empty()) {
      AMPromptManager &prompt = AMPromptManager::Instance();
      bool canceled = false;
      const std::string question = AMStr::amfmt(
          "No known host fingerprint for {}:{} {}.\n"
          "Fingerprint: {}\nAdd it? (y/N): ",
          entry.hostname, entry.port, entry.protocol, entry.fingerprint);
      if (!prompt.PromptYesNo(question, &canceled)) {
        if (canceled) {
          return Err(EC::ConfigCanceled, "Known host fingerprint add canceled");
        }
        return Err(EC::HostConfigNotFound, "Known host fingerprint not found");
      }
      return UpsertKnownHost(entry, true);
    }

    const std::string expected_fp =
        AMStr::TrimWhitespaceCopy(existing->fingerprint);
    const std::string expected_lower = AMStr::lowercase(expected_fp);
    if (expected_lower.rfind("sha256:", 0) == 0) {
      const std::string expected_body =
          AMStr::TrimWhitespaceCopy(expected_fp.substr(7));
      if (entry.fingerprint_sha256.empty() ||
          expected_body != entry.fingerprint_sha256) {
        return {EC::HostFingerprintMismatch,
                AMStr::amfmt("{}:{} {} fingerprint mismatches", entry.hostname,
                             entry.port, entry.protocol)};
      }
      return Ok();
    }

    if (expected_fp != entry.fingerprint) {
      return {EC::HostFingerprintMismatch,
              AMStr::amfmt("{}:{} {} fingerprint mismatches", entry.hostname,
                           entry.port, entry.protocol)};
    }

    return Ok();
  };
  return known_host_cb_;
}

std::pair<ECM, AMConfigManager::ClientConfig>
AMConfigManager::GetClientConfig(const std::string &nickname) {
  auto status = EnsureInitialized("GetClientConfig");
  if (status.first != EC::Success)
    return {status, ClientConfig{}};

  Json *host = FindHostJsonMutable(config_json_, nickname);
  if (!host) {
    return {Err(EC::HostConfigNotFound, "client config not found"),
            ClientConfig{}};
  }

  if (!IsHostValid(*host)) {
    return {Err(EC::HostConfigNotFound, "invalid host entry"), ClientConfig{}};
  }

  ClientConfig config;
  bool updated = false;

  auto get_string = [&](const std::string &key,
                        const std::string &default_value) {
    auto value = GetStringField(*host, key);
    if (value) {
      return *value;
    }
    (*host)[key] = default_value;
    updated = true;
    return default_value;
  };

  auto get_int = [&](const std::string &key, int64_t default_value) {
    auto value = GetIntField(*host, key);
    if (value.has_value()) {
      return *value;
    }
    (*host)[key] = default_value;
    updated = true;
    return default_value;
  };

  (*host)["nickname"] = nickname;

  std::string hostname = get_string("hostname", "");
  std::string username = get_string("username", "");
  std::string password = get_string("password", "");
  std::string keyfile = get_string("keyfile", "");
  std::string trash_dir = get_string("trash_dir", "");
  std::string login_dir = get_string("login_dir", "");
  int64_t port = get_int("port", 22);
  bool compression = false;
  auto compression_it = host->find("compression");
  if (compression_it != host->end() && compression_it->is_boolean() &&
      compression_it->get<bool>()) {
    compression = true;
  } else {
    if (compression_it == host->end() || !compression_it->is_boolean() ||
        compression_it->get<bool>()) {
      (*host)["compression"] = false;
      updated = true;
    }
    compression = false;
  }

  config.request =
      ConRequst(nickname, hostname, username, static_cast<int>(port), password,
                keyfile, compression, trash_dir);

  std::string protocol_str = get_string("protocol", "sftp");
  config.protocol = ProtocolFromString(protocol_str);
  config.buffer_size = get_int("buffer_size", -1);
  config.login_dir = login_dir;

  if (updated) {
    (void)Dump();
  }

  return {Ok(), config};
}

int AMConfigManager::GetSettingInt(const Path &path, int default_value) const {
  auto status = EnsureInitialized("GetSettingInt");
  if (status.first != EC::Success)
    return default_value;
  const Json *node = FindJsonNode(settings_json_, path);
  return GetSettingValueImpl<int>(node, default_value);
}

/**
 * @brief Resolve network timeout from settings with a default fallback.
 */
int AMConfigManager::ResolveTimeoutMs(int default_timeout_ms) const {
  int timeout_ms = GetSettingInt({"client_manager", "timeout_ms"}, -1);
  if (timeout_ms <= 0) {
    timeout_ms = default_timeout_ms;
  }
  return timeout_ms;
}

/** Return a string setting value or the provided default. */
std::string
AMConfigManager::GetSettingString(const Path &path,
                                  const std::string &default_value) const {
  auto status = EnsureInitialized("GetSettingString");
  if (status.first != EC::Success)
    return default_value;
  const Json *node = FindJsonNode(settings_json_, path);
  return GetSettingValueImpl<std::string>(node, default_value);
}

/**
 * @brief Query a UserVars entry by name.
 */
bool AMConfigManager::GetUserVar(const std::string &name,
                                 std::string *value) const {
  auto status = EnsureInitialized("GetUserVar");
  if (status.first != EC::Success)
    return false;
  if (name.empty())
    return false;

  const Json *node = FindJsonNode(settings_json_, {"UserVars", name});
  if (!node)
    return false;

  if (value) {
    if (node->is_string()) {
      *value = node->get<std::string>();
    } else {
      *value = GetSettingString({"UserVars", name}, "");
    }
  }
  return true;
}

/**
 * @brief List all UserVars entries.
 */
std::vector<std::pair<std::string, std::string>>
AMConfigManager::ListUserVars() const {
  std::vector<std::pair<std::string, std::string>> entries;
  auto status = EnsureInitialized("ListUserVars");
  if (status.first != EC::Success)
    return entries;

  const Json *node = FindJsonNode(settings_json_, {"UserVars"});
  if (!node || !node->is_object())
    return entries;

  entries.reserve(node->size());
  for (auto it = node->begin(); it != node->end(); ++it) {
    if (it.value().is_string()) {
      entries.emplace_back(it.key(), it.value().get<std::string>());
    } else {
      entries.emplace_back(it.key(),
                           GetSettingString({"UserVars", it.key()}, ""));
    }
  }
  return entries;
}

/**
 * @brief Set a UserVars entry and optionally persist to settings.
 */
ECM AMConfigManager::SetUserVar(const std::string &name,
                                const std::string &value, bool dump_now) {
  auto status = EnsureInitialized("SetUserVar");
  if (status.first != EC::Success)
    return status;
  if (name.empty())
    return Err(EC::InvalidArg, "Empty variable name");

  SetKey(settings_json_, {"UserVars", name}, value);
  if (dump_now) {
    return Dump();
  }
  return Ok();
}

/** Return a list of configured host nicknames. */
std::vector<std::string> AMConfigManager::ListHostnames() const {
  std::vector<std::string> names;
  auto status = EnsureInitialized("ListHostnames");
  if (status.first != EC::Success)
    return names;
  auto hosts = CollectHosts();
  names.reserve(hosts.size());
  for (const auto &item : hosts) {
    names.push_back(item.first);
  }
  return names;
}

/**
 * @brief Remove a UserVars entry and optionally persist to settings.
 */
ECM AMConfigManager::RemoveUserVar(const std::string &name, bool dump_now) {
  auto status = EnsureInitialized("RemoveUserVar");
  if (status.first != EC::Success)
    return status;
  if (name.empty())
    return Err(EC::InvalidArg, "Empty variable name");

  Json *node = nullptr;
  if (settings_json_.contains("UserVars") &&
      settings_json_["UserVars"].is_object()) {
    node = &settings_json_["UserVars"];
  }

  if (!node || !node->contains(name)) {
    return Err(EC::InvalidArg, "Variable not found");
  }

  node->erase(name);
  if (dump_now) {
    return Dump();
  }
  return Ok();
}

bool AMConfigManager::QueryKey(const Json &root, const Path &path,
                               Value *value) const {
  const Json *node = FindJsonNode(root, path);
  if (!node) {
    return false;
  }
  return NodeToValue(*node, value);
}

ECM AMConfigManager::Src() const {
  auto status = EnsureInitialized("Src");
  if (status.first != EC::Success)
    return status;

  const std::string config_label = AMStr::BBCEscape("[Config]");
  const std::string settings_label = "[Setting]";
  size_t width = std::max(config_label.size(), settings_label.size());

  std::string config_path = config_path_.string();
  std::string settings_path = settings_path_.string();

  auto [config_rcm, config_info] = AMFS::stat(config_path, false);
  const PathInfo *config_ptr =
      config_rcm.first == EC::Success ? &config_info : nullptr;
  auto [settings_rcm, settings_info] = AMFS::stat(settings_path, false);
  const PathInfo *settings_ptr =
      settings_rcm.first == EC::Success ? &settings_info : nullptr;

  std::string styled_config = Format(config_path, "dir", config_ptr);
  std::string styled_settings = Format(settings_path, "dir", settings_ptr);

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

ECM AMConfigManager::Delete(const std::string &targets) {
  std::istringstream iss(targets);
  std::vector<std::string> names;
  std::string nickname;
  while (iss >> nickname) {
    names.push_back(nickname);
  }
  return Delete(names);
}

/** Delete hosts by nickname list without parsing input. */
ECM AMConfigManager::Delete(const std::vector<std::string> &targets) {
  auto status = EnsureInitialized("Delete");
  if (status.first != EC::Success)
    return status;

  std::vector<std::string> unique_targets = UniqueTargetsKeepOrder(targets);
  if (unique_targets.empty()) {
    return Err(EC::InvalidArg, "empty delete targets");
  }

  ECM last = Ok();
  std::string msg;
  for (const auto &nickname : unique_targets) {
    if (nickname.empty()) {
      msg = "Invalid Empty Hostname";
      last = Err(EC::InvalidArg, msg);
      AMPromptManager::Instance().ErrorFormat(AM_ENUM_NAME(EC::InvalidArg),
                                              msg);
      continue;
    }
    if (!HostExists(nickname)) {
      // EC::HostNotFound
      msg = AMStr::amfmt("Host {} not found in config", nickname);
      AMPromptManager::Instance().ErrorFormat(AM_ENUM_NAME(EC::InvalidArg),
                                              msg);
      last = Err(EC::HostConfigNotFound, msg);
      continue;
    }

    auto rm_status = RemoveHost(nickname);
    if (rm_status.first != EC::Success) {
      last = rm_status;
      AMPromptManager::Instance().ErrorFormat(AM_ENUM_NAME(rm_status.first),
                                              rm_status.second);
      continue;
    }

    PrintLine(Format("Deleted host: " + nickname, "success"));
  }

  return last;
}

ECM AMConfigManager::Rename(const std::string &old_nickname,
                            const std::string &new_nickname) {
  auto status = EnsureInitialized("Rename");
  if (status.first != EC::Success)
    return status;

  if (old_nickname == new_nickname) {
    return Ok();
  }

  if (!HostExists(old_nickname)) {
    PrintLine(Format("Host not found: " + old_nickname, "error"));
    return {EC::HostConfigNotFound, "host not found"};
  }

  std::string error;
  static std::regex pattern("^[A-Za-z0-9_]+$");
  if (new_nickname.empty() || !std::regex_match(new_nickname, pattern)) {
    return Err(
        EC::InvalidArg,
        "new nickname must contain only letters, numbers, and underscore");
  }
  if (HostExists(new_nickname)) {
    return Err(EC::KeyAlreadyExists, "new nickname already exists");
  }

  Json *host = FindHostJsonMutable(config_json_, old_nickname);
  if (!host) {
    return Err(EC::ConfigInvalid, "invalid host entry");
  }
  (*host)["nickname"] = new_nickname;

  PrintLine(Format("Renamed host: " + old_nickname + " -> " + new_nickname,
                   "success"));
  return Ok();
}

ECM AMConfigManager::Query(const std::string &targets) const {
  std::istringstream iss(targets);
  std::vector<std::string> names;
  std::string nickname;
  while (iss >> nickname) {
    names.push_back(nickname);
  }
  return Query(names);
}

/** Query hosts by nickname list without parsing input. */
ECM AMConfigManager::Query(const std::vector<std::string> &targets) const {
  auto status = EnsureInitialized("Query");
  if (status.first != EC::Success)
    return status;

  std::vector<std::string> unique_targets = UniqueTargetsKeepOrder(targets);
  if (unique_targets.empty()) {
    return Err(EC::InvalidArg, "empty query targets");
  }

  auto hosts = CollectHosts();
  ECM last = Ok();
  for (const auto &nickname : unique_targets) {
    if (nickname.empty()) {
      last = Err(EC::InvalidArg, "empty query target");
      continue;
    }
    auto it = hosts.find(nickname);
    if (it == hosts.end()) {
      PrintLine(Format("Host not found: " + nickname, "error"));
      last = Err(EC::HostConfigNotFound, "host not found");
      continue;
    }
    auto rcm = PrintHost(nickname, it->second);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }

  return last;
}

ECM AMConfigManager::Add() {
  auto status = EnsureInitialized("Add");
  if (status.first != EC::Success)
    return status;

  std::string nickname;
  HostEntry entry;
  auto prompt_status = PromptAddFields(&nickname, &entry);
  if (prompt_status.first != EC::Success)
    return prompt_status;

  bool canceled = false;
  if (!AMPromptManager::Instance().PromptYesNo("Save host? (y/N): ",
                                               &canceled) ||
      canceled) {
    PrintLine("Add canceled.");
    return Err(EC::ConfigCanceled, "add canceled");
  }

  for (const auto &field : entry.fields) {
    auto up_status = UpsertHostField(nickname, field.first, field.second);
    if (up_status.first != EC::Success)
      return up_status;
  }

  PrintLine(Format("Added host: " + nickname, "success"));
  return Ok();
}

ECM AMConfigManager::Modify(const std::string &nickname) {
  auto status = EnsureInitialized("Modify");
  if (status.first != EC::Success)
    return status;

  if (!HostExists(nickname)) {
    PrintLine(Format("Host not found: " + nickname, "error"));
    return Err(EC::HostConfigNotFound, "host not found");
  }

  HostEntry entry;
  auto prompt_status = PromptModifyFields(nickname, &entry);
  if (prompt_status.first != EC::Success)
    return prompt_status;

  bool canceled = false;
  if (!AMPromptManager::Instance().PromptYesNo("Apply changes? (y/N): ",
                                               &canceled) ||
      canceled) {
    PrintLine("Modify canceled.");
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  for (const auto &field : entry.fields) {
    auto up_status = UpsertHostField(nickname, field.first, field.second);
    if (up_status.first != EC::Success)
      return up_status;
  }

  PrintLine(Format("Modified host: " + nickname, "success"));
  return Ok();
}

/**
 * @brief Persist an encrypted password for a given client nickname.
 */
ECM AMConfigManager::SetClientPasswordEncrypted(
    const std::string &nickname, const std::string &encrypted_password,
    bool dump_now) {
  auto status = EnsureInitialized("SetClientPasswordEncrypted");
  if (status.first != EC::Success) {
    return status;
  }
  if (!HostExists(nickname)) {
    return Err(EC::HostConfigNotFound, "host not found");
  }

  std::string stored = encrypted_password;
  if (!stored.empty() && !AMAuth::IsEncrypted(stored)) {
    stored = AMAuth::EncryptPassword(stored);
  }

  auto up_status = UpsertHostField(nickname, "password", stored);
  if (up_status.first != EC::Success) {
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
    AMConfigManager::Instance().CloseHandles();
  } catch (const std::exception &e) {
    std::cerr << "❌ Config dump failed: " << e.what() << "\n";
    std::terminate();
  }
}

void AMConfigManager::CloseHandles() {
  StopWriteThread_();
  if (config_handle_) {
    cfgffi_free_handle(config_handle_);
    config_handle_ = nullptr;
  }
  if (settings_handle_) {
    cfgffi_free_handle(settings_handle_);
    settings_handle_ = nullptr;
  }
  if (known_hosts_handle_) {
    cfgffi_free_handle(known_hosts_handle_);
    known_hosts_handle_ = nullptr;
  }
  if (history_handle_) {
    cfgffi_free_handle(history_handle_);
    history_handle_ = nullptr;
  }
}

ECM AMConfigManager::EnsureInitialized(const char *caller) const {
  if (!initialized_) {
    return Err(EC::ConfigNotInitialized,
               AMStr::amfmt("{} called before Init()", caller));
  }
  return Ok();
}

ECM AMConfigManager::SetHostField(const std::string &nickname,
                                  const std::string &field, const Value &value,
                                  bool dump_now) {
  auto status = EnsureInitialized("SetHostField");
  if (status.first != EC::Success) {
    return status;
  }
  auto up_status = UpsertHostField(nickname, field, value);
  if (up_status.first != EC::Success) {
    return up_status;
  }
  if (dump_now) {
    return Dump();
  }
  return Ok();
}

/**
 * @brief Parse and set a host field from config set command arguments.
 */
ECM AMConfigManager::SetHostValue(const std::vector<std::string> &args) {
  auto status = EnsureInitialized("SetHostValue");
  if (status.first != EC::Success) {
    return status;
  }
  if (args.size() != 3) {
    return Err(EC::InvalidArg, "config set expects 3 arguments");
  }
  const std::string &nickname = args[0];
  std::string field = ToLowerCopy(args[1]);
  const std::string &value_str = args[2];

  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty nickname");
  }
  if (!HostExists(nickname)) {
    return Err(EC::HostConfigNotFound, "host not found");
  }

  const std::vector<std::string> allowed_fields = {
      "hostname",    "username",  "port",      "password", "protocol",
      "buffer_size", "trash_dir", "login_dir", "keyfile",  "compression"};
  if (std::find(allowed_fields.begin(), allowed_fields.end(), field) ==
      allowed_fields.end()) {
    return Err(EC::InvalidArg, "unsupported property name");
  }

  Value value;
  if (field == "port") {
    int64_t port = 0;
    if (!ParsePositiveInt(value_str, &port)) {
      return Err(EC::InvalidArg, "invalid port value");
    }
    value = port;
  } else if (field == "buffer_size") {
    try {
      int64_t parsed = std::stoll(value_str);
      if (parsed == 0 || parsed < -1) {
        return Err(EC::InvalidArg, "invalid buffer_size value");
      }
      value = parsed;
    } catch (...) {
      return Err(EC::InvalidArg, "invalid buffer_size value");
    }
  } else if (field == "compression") {
    bool parsed = false;
    if (!ParseBoolToken(value_str, &parsed)) {
      return Err(EC::InvalidArg, "invalid compression value");
    }
    value = parsed;
  } else if (field == "protocol") {
    std::string protocol = ToLowerCopy(value_str);
    if (protocol != "sftp" && protocol != "ftp" && protocol != "local") {
      return Err(EC::InvalidArg, "invalid protocol value");
    }
    value = protocol;
  } else {
    value = value_str;
  }

  std::string old_value;
  auto hosts = CollectHosts();
  auto host_it = hosts.find(nickname);
  if (host_it != hosts.end()) {
    auto field_it = host_it->second.fields.find(field);
    if (field_it != host_it->second.fields.end()) {
      old_value = ValueToString(field_it->second);
    }
  }

  ECM set_status = SetHostField(nickname, field, value, true);
  if (set_status.first != EC::Success) {
    return set_status;
  }

  const std::string new_value = ValueToString(value);
  PrintLine(
      AMStr::amfmt("{}.{}: {} -> {}", nickname, field, old_value, new_value));
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

std::map<std::string, AMConfigManager::HostEntry>
AMConfigManager::CollectHosts() const {
  std::map<std::string, HostEntry> hosts;
  const Json *arr = GetHostsArray(config_json_);
  if (!arr)
    return hosts;
  for (const auto &node : *arr) {
    if (!node.is_object())
      continue;
    const Json &host = node;
    if (!IsHostValid(host))
      continue;
    auto nickname = GetStringField(host, "nickname");
    HostEntry entry;
    for (auto it = host.begin(); it != host.end(); ++it) {
      Value value;
      if (!NodeToValue(it.value(), &value))
        continue;
      entry.fields[it.key()] = std::move(value);
    }
    if (!entry.fields.empty())
      hosts[*nickname] = std::move(entry);
  }
  return hosts;
}

ECM AMConfigManager::PrintHost(const std::string &nickname,
                               const HostEntry &entry) const {
  PrintLine("[!pre][" + nickname + "][/pre]");
  size_t width = 0;
  for (const auto &field : kHostFields)
    width = std::max(width, field.size());

  for (const auto &field : kHostFields) {
    auto it = entry.fields.find(field);
    if (it == entry.fields.end())
      continue;
    std::string value = ValueToString(it->second);
    // abort value style in config print
    // std::string styled_value = Format(value, field);
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field << " :   "
         << (value.empty() ? "\"\"" : value);
    PrintLine(line.str());
  }
  return Ok();
}

bool AMConfigManager::HostExists(const std::string &nickname) const {
  return FindHostJson(config_json_, nickname) != nullptr;
}

ECM AMConfigManager::UpsertHostField(const std::string &nickname,
                                     const std::string &field, Value value) {
  Json *host = FindHostJsonMutable(config_json_, nickname);
  if (!host) {
    Json *arr = EnsureHostsArray(config_json_);
    if (!arr)
      return Err(EC::ConfigInvalid, "invalid host list");
    Json new_host = Json::object();
    new_host["nickname"] = nickname;
    arr->push_back(std::move(new_host));
    host = FindHostJsonMutable(config_json_, nickname);
  }
  if (!host)
    return Err(EC::ConfigInvalid, "invalid host table");

  (*host)["nickname"] = nickname;

  if (std::holds_alternative<int64_t>(value)) {
    (*host)[field] = std::get<int64_t>(value);
    return Ok();
  }
  if (std::holds_alternative<bool>(value)) {
    (*host)[field] = std::get<bool>(value);
    return Ok();
  }
  if (std::holds_alternative<std::string>(value)) {
    std::string str_value = std::get<std::string>(value);
    if (field == "password" && !str_value.empty() &&
        !AMAuth::IsEncrypted(str_value)) {
      str_value = AMAuth::EncryptPassword(str_value);
    }
    (*host)[field] = str_value;
    return Ok();
  }
  if (std::holds_alternative<std::vector<std::string>>(value)) {
    Json arr = Json::array();
    for (const auto &item : std::get<std::vector<std::string>>(value))
      arr.push_back(item);
    (*host)[field] = std::move(arr);
    return Ok();
  }
  return Ok();
}

ECM AMConfigManager::RemoveHost(const std::string &nickname) {
  std::size_t index = 0;
  if (!FindHostJson(config_json_, nickname, &index))
    return Ok();
  Json *arr = EnsureHostsArray(config_json_);
  if (!arr || index >= arr->size())
    return Ok();
  arr->erase(arr->begin() + static_cast<std::ptrdiff_t>(index));
  return Ok();
}

ECM AMConfigManager::PromptAddFields(std::string *nickname, HostEntry *entry) {
  std::string error;
  bool canceled = false;
  while (true) {
    if (!AMPromptManager::Instance().PromptLine("Nickname: ", nickname, "",
                                                true, &canceled)) {
      if (canceled) {
        PrintLine("Add canceled.");
        return Err(EC::ConfigCanceled, "add canceled");
      }
      return Err(EC::ConfigInvalid, "failed to read nickname");
    }
    error.clear();
    if (ValidateNickname(*nickname, &error))
      break;
    PrintLine(Format(error, "error"));
  }

  std::string hostname;
  while (true) {
    if (!AMPromptManager::Instance().PromptLine("Hostname: ", &hostname, "",
                                                true, &canceled)) {
      PrintLine("Add canceled.");
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (!hostname.empty())
      break;
    PrintLine(Format("Hostname cannot be empty.", "error"));
  }

  std::string username;
  while (true) {
    if (!AMPromptManager::Instance().PromptLine("Username: ", &username, "",
                                                true, &canceled)) {
      PrintLine("Add canceled.");
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (!username.empty())
      break;
    PrintLine(Format("Username cannot be empty.", "error"));
  }

  std::string port_input;
  int64_t port = 22;
  while (true) {
    if (!AMPromptManager::Instance().PromptLine(
            "Port (default 22): ", &port_input, "", true, &canceled)) {
      PrintLine("Add canceled.");
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (port_input.empty()) {
      PrintLine("Using default port 22.");
      break;
    }
    if (ParsePositiveInt(port_input, &port))
      break;
    PrintLine(Format("Port must be a positive integer.", "error"));
  }

  std::string password;
  while (true) {
    std::string first =
        AMClientManager::ReadMaskedPassword("Password (optional): ");
    std::string second =
        AMClientManager::ReadMaskedPassword("Confirm password: ");
    if (first == second) {
      password = std::move(first);
      AMAuth::SecureZero(second);
      break;
    }
    AMAuth::SecureZero(first);
    AMAuth::SecureZero(second);
    PrintLine(Format("Passwords do not match. Please try again.", "error"));
  }

  std::string protocol;
  while (true) {
    if (!AMPromptManager::Instance().PromptLine(
            "Protocol (sftp/ftp): ", &protocol, "", true, &canceled)) {
      PrintLine("Add canceled.");
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (protocol.empty()) {
      PrintLine(Format("Protocol cannot be empty.", "error"));
      continue;
    }
    protocol = ToLowerCopy(protocol);
    if (protocol == "sftp" || protocol == "ftp")
      break;
    PrintLine(Format("Protocol must be sftp or ftp.", "error"));
  }

  std::string buffer_input;
  int64_t buffer_size = 24 * AMMB;
  while (true) {
    if (!AMPromptManager::Instance().PromptLine(
            "Buffer size(Default 24MB): ", &buffer_input, "", true,
            &canceled)) {
      PrintLine("Add canceled.");
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (buffer_input.empty()) {
      break;
    }
    if (ParsePositiveInt(buffer_input, &buffer_size))
      break;
    PrintLine(Format("Buffer size must be a positive integer.", "error"));
  }

  std::string trash_dir;
  if (!AMPromptManager::Instance().PromptLine(
          "Trash dir (optional): ", &trash_dir, "", true, &canceled)) {
    PrintLine("Add canceled.");
    return Err(EC::ConfigCanceled, "add canceled");
  }

  std::string login_dir;
  if (!AMPromptManager::Instance().PromptLine(
          "Login dir (optional): ", &login_dir, "", true, &canceled)) {
    PrintLine("Add canceled.");
    return Err(EC::ConfigCanceled, "add canceled");
  }

  std::string keyfile;
  if (!AMPromptManager::Instance().PromptLine("Keyfile (optional): ", &keyfile,
                                              "", true, &canceled)) {
    PrintLine("Add canceled.");
    return Err(EC::ConfigCanceled, "add canceled");
  }

  bool compression = false;
  compression = AMPromptManager::Instance().PromptYesNo(
      "Enable compression? (y/N): ", &canceled);
  if (canceled) {
    PrintLine("Add canceled.");
    return Err(EC::ConfigCanceled, "add canceled");
  }

  entry->fields.clear();
  entry->fields["hostname"] = hostname;
  entry->fields["username"] = username;
  entry->fields["port"] = port;
  entry->fields["password"] = AMAuth::EncryptPassword(password);
  entry->fields["protocol"] = protocol;
  entry->fields["buffer_size"] = buffer_size;
  entry->fields["trash_dir"] = trash_dir;
  entry->fields["login_dir"] = login_dir;
  entry->fields["keyfile"] = keyfile;
  entry->fields["compression"] = compression;
  AMAuth::SecureZero(password);
  return Ok();
}

ECM AMConfigManager::PromptModifyFields(const std::string &nickname,
                                        HostEntry *entry) {
  auto hosts = CollectHosts();
  auto it = hosts.find(nickname);
  if (it == hosts.end())
    return Err(EC::HostConfigNotFound, "host not found");

  bool canceled = false;
  HostEntry updated = it->second;

  auto get_value = [&](const std::string &field) {
    auto fit = updated.fields.find(field);
    if (fit == updated.fields.end())
      return std::string();
    return ValueToString(fit->second);
  };

  std::string hostname = get_value("hostname");
  if (!AMPromptManager::Instance().PromptLine("Hostname: ", &hostname, hostname,
                                              false, &canceled, false)) {
    PrintLine("Modify canceled.");
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string username = get_value("username");
  if (!AMPromptManager::Instance().PromptLine("Username: ", &username, username,
                                              false, &canceled, false)) {
    PrintLine("Modify canceled.");
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string port_input = get_value("port");
  int64_t port = 22;
  if (!port_input.empty())
    ParsePositiveInt(port_input, &port);
  while (true) {
    if (!AMPromptManager::Instance().PromptLine(
            "Port (default 22): ", &port_input, port_input, true, &canceled,
            false)) {
      PrintLine("Modify canceled.");
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    if (port_input.empty())
      break;
    if (ParsePositiveInt(port_input, &port))
      break;
    PrintLine(Format("Port must be a positive integer.", "error"));
  }
  if (!port_input.empty())
    port = std::stoll(port_input);

  Value password_value = std::string();
  auto pw_it = updated.fields.find("password");
  if (pw_it != updated.fields.end()) {
    password_value = pw_it->second;
  }
  bool change_password = AMPromptManager::Instance().PromptYesNo(
      "Change password? (y/N): ", &canceled);
  if (canceled) {
    PrintLine("Modify canceled.");
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  if (change_password) {
    std::string password;
    while (true) {
      std::string first =
          AMClientManager::ReadMaskedPassword("Password (optional): ");
      std::string second =
          AMClientManager::ReadMaskedPassword("Confirm password: ");
      if (first == second) {
        password = std::move(first);
        AMAuth::SecureZero(second);
        break;
      }
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      PrintLine(Format("Passwords do not match. Please try again.", "error"));
    }
    password_value = AMAuth::EncryptPassword(password);
    AMAuth::SecureZero(password);
  }

  std::string protocol = get_value("protocol");
  while (true) {
    if (!AMPromptManager::Instance().PromptLine(
            "Protocol (sftp/ftp): ", &protocol, protocol, false, &canceled,
            false)) {
      PrintLine("Modify canceled.");
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    protocol = ToLowerCopy(protocol);
    if (protocol == "sftp" || protocol == "ftp")
      break;
    PrintLine(Format("Protocol must be sftp or ftp.", "error"));
  }

  std::string buffer_input = get_value("buffer_size");
  int64_t buffer_size = 24 * AMMB;
  if (!buffer_input.empty())
    ParsePositiveInt(buffer_input, &buffer_size);
  while (true) {
    if (!AMPromptManager::Instance().PromptLine("Buffer size: ", &buffer_input,
                                                buffer_input, false, &canceled,
                                                false)) {
      PrintLine("Modify canceled.");
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    if (buffer_input.empty())
      break;
    if (ParsePositiveInt(buffer_input, &buffer_size))
      break;
    PrintLine(Format("Buffer size must be a positive integer.", "error"));
  }

  std::string trash_dir = get_value("trash_dir");
  if (!AMPromptManager::Instance().PromptLine(
          "Trash dir (optional): ", &trash_dir, trash_dir, true, &canceled,
          false)) {
    PrintLine("Modify canceled.");
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string login_dir = get_value("login_dir");
  if (!AMPromptManager::Instance().PromptLine(
          "Login dir (optional): ", &login_dir, login_dir, true, &canceled,
          false)) {
    PrintLine("Modify canceled.");
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string keyfile = get_value("keyfile");
  if (!AMPromptManager::Instance().PromptLine(
          "Keyfile (optional): ", &keyfile, keyfile, true, &canceled, false)) {
    PrintLine("Modify canceled.");
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  bool compression = false;
  bool current_compression = false;
  std::string compression_input = get_value("compression");
  if (ParseBoolToken(compression_input, &current_compression)) {
    compression_input = current_compression ? "true" : "false";
  } else {
    compression_input = "false";
  }
  while (true) {
    if (!AMPromptManager::Instance().PromptLine(
            "Compression (true/false): ", &compression_input, compression_input,
            true, &canceled, false)) {
      PrintLine("Modify canceled.");
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    if (ParseBoolToken(compression_input, &compression)) {
      break;
    }
    PrintLine(Format("Compression must be true or false.", "error"));
  }

  entry->fields.clear();
  entry->fields["hostname"] = hostname;
  entry->fields["username"] = username;
  entry->fields["port"] = port;
  entry->fields["password"] = password_value;
  entry->fields["protocol"] = protocol;
  entry->fields["buffer_size"] = buffer_size;
  entry->fields["trash_dir"] = trash_dir;
  entry->fields["login_dir"] = login_dir;
  entry->fields["keyfile"] = keyfile;
  entry->fields["compression"] = compression;
  return Ok();
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
      *error = "Nickname must contain only letters, numbers, and _ -.";
    return false;
  }
  if (HostExists(nickname)) {
    if (error)
      *error = "Nickname already exists.";
    return false;
  }
  return true;
}
