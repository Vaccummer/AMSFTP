#pragma once
#include "AMBase/CommonTools.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/Path.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <variant>

namespace AMConfigInternal {
using Path = AMConfigManager::Path;
using Value = AMConfigManager::Value;
using ClientConfig = AMConfigManager::ClientConfig;
using ResolveArgType = AMConfigManager::ResolveArgType;
using EC = ErrorCode;
using Json = nlohmann::ordered_json;

/** @brief Return a success ECM. */
inline ECM Ok() { return {EC::Success, ""}; }
/** @brief Build an error ECM with message. */
inline ECM Err(EC code, const std::string &msg) { return {code, msg}; }

/**
 * @brief Check whether every element in a JSON array is a scalar type.
 */
inline bool JsonArrayAllScalar(const Json &arr) {
  for (const auto &child : arr) {
    if (!(child.is_null() || child.is_boolean() || child.is_number() ||
          child.is_string())) {
      return false;
    }
  }
  return true;
}

/**
 * @brief Convert a JSON scalar value into a string representation.
 */
inline std::string JsonScalarToString(const Json &value) {
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
  (void)node;
  return default_value;
}

/**
 * @brief Convert a settings node into an integer value with parsing fallback.
 */
template <>
inline int GetSettingValueImpl<int>(const Json *node,
                                    const int &default_value) {
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
inline std::string
GetSettingValueImpl<std::string>(const Json *node,
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

/**
 * @brief Print a line through the global prompt manager.
 */
inline void PrintLine(const std::string &value) {
  AMPromptManager::Instance().Print(value);
}

/**
 * @brief Return a trimmed copy of the input string.
 */
inline std::string TrimCopy(const std::string &value) {
  std::string tmp = value;
  AMStr::VStrip(tmp);
  return tmp;
}

/**
 * @brief Normalize a configured style into a bbcode opening tag.
 */
inline std::string NormalizeStyleTag_(const std::string &raw) {
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
inline std::string ApplyStyleTag_(const std::string &tag,
                                  const std::string &text) {
  if (tag.empty()) {
    return text;
  }
  return tag + text + "[/]";
}

/**
 * @brief Return a lowercase copy of the input string.
 */
inline std::string ToLowerCopy(const std::string &value) {
  std::string out = value;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

/**
 * @brief Parse a hex color string (#RRGGBB) into an ANSI escape sequence.
 */
inline std::optional<std::string>
ParseHexColorToAnsi(const std::string &value) {
  std::string token = TrimCopy(value);
  if (token.empty()) {
    return std::nullopt;
  }
  if (token.rfind("#", 0) == 0) {
    token.erase(0, 1);
  }
  if (token.size() != 6) {
    return std::nullopt;
  }
  auto hex_to_int = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
      return 10 + (c - 'A');
    return -1;
  };
  int vals[6];
  for (size_t i = 0; i < 6; ++i) {
    vals[i] = hex_to_int(token[i]);
    if (vals[i] < 0) {
      return std::nullopt;
    }
  }
  int r = vals[0] * 16 + vals[1];
  int g = vals[2] * 16 + vals[3];
  int b = vals[4] * 16 + vals[5];
  return AMStr::amfmt("\x1b[38;2;{};{};{}m", r, g, b);
}

/**
 * @brief Map a progress bar color name or hex to indicators::Color/ANSI.
 */
inline std::variant<indicators::Color, std::string>
ParseProgressBarColor(const std::string &value) {
  const std::string trimmed = TrimCopy(value);
  if (trimmed.empty()) {
    return indicators::Color::unspecified;
  }
  if (!trimmed.empty() && trimmed[0] == '#') {
    auto ansi = ParseHexColorToAnsi(trimmed);
    if (ansi) {
      return *ansi;
    }
  }
  const std::string token = ToLowerCopy(trimmed);
  if (token == "grey") {
    return indicators::Color::grey;
  }
  if (token == "red") {
    return indicators::Color::red;
  }
  if (token == "green") {
    return indicators::Color::green;
  }
  if (token == "yellow") {
    return indicators::Color::yellow;
  }
  if (token == "blue") {
    return indicators::Color::blue;
  }
  if (token == "magenta") {
    return indicators::Color::magenta;
  }
  if (token == "cyan") {
    return indicators::Color::cyan;
  }
  if (token == "white") {
    return indicators::Color::white;
  }
  return indicators::Color::unspecified;
}

/**
 * @brief Parse a boolean token from user input.
 */
inline bool ParseBoolToken(const std::string &input, bool *value) {
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

/** @brief Read a field as a string when available. */
std::optional<std::string> GetStringField(const Json &obj,
                                          const std::string &key);
/** @brief Read a field as int64 when available. */
std::optional<int64_t> GetIntField(const Json &obj, const std::string &key);
/** @brief Read a boolean field from a JSON object when available. */
std::optional<bool> GetBoolField(const Json &obj, const std::string &key);

inline const std::vector<std::string> kHostFields = {
    "hostname",    "username",  "port",      "password", "protocol",
    "buffer_size", "trash_dir", "login_dir", "keyfile",  "compression",
};

/**
 * @brief Return the HOSTS array if present and valid.
 */
inline const Json *GetHostsArray(const Json &root) {
  if (!root.is_object())
    return nullptr;
  auto it = root.find("HOSTS");
  if (it == root.end() || !it->is_array())
    return nullptr;
  return &(*it);
}

/**
 * @brief Check whether a host table contains required fields.
 */
inline bool IsHostValid(const Json &tbl) {
  auto nickname = GetStringField(tbl, "nickname");
  if (!nickname || nickname->empty())
    return false;
  auto hostname = GetStringField(tbl, "hostname");
  if (!hostname || hostname->empty())
    return false;
  return true;
}

/**
 * @brief Parse a positive integer index from a string.
 */
inline bool ParseIndex(const std::string &value, std::size_t *out) {
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

/**
 * @brief Read a text file into a string buffer.
 */
inline bool ReadTextFile(const std::filesystem::path &path, std::string *out,
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

/**
 * @brief Load a JSON schema file or return an empty schema string.
 */
inline std::string LoadSchemaJson(const std::filesystem::path &schema_path,
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

/**
 * @brief Ensure a file exists by creating its parent directory and file.
 */
inline bool EnsureFileExists(const std::filesystem::path &path,
                             std::string *error) {
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

/**
 * @brief Parse a JSON string into an ordered_json structure.
 */
inline bool ParseJsonString(const std::string &text, Json *out,
                            std::string *error) {
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

/**
 * @brief Find a JSON node by walking the provided path.
 */
inline const Json *FindJsonNode(const Json &root, const Path &path) {
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

/**
 * @brief Convert a JSON node into a typed Value.
 */
inline bool NodeToValue(const Json &node, Value *out) {
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

/**
 * @brief Read a field as a string when available.
 */
inline std::optional<std::string> GetStringField(const Json &obj,
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

/**
 * @brief Read a field as int64 when available.
 */
inline std::optional<int64_t> GetIntField(const Json &obj,
                                          const std::string &key) {
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
inline std::optional<bool> GetBoolField(const Json &obj,
                                        const std::string &key) {
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
inline bool MatchBackupName_(const std::string &name, const std::string &prefix,
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
inline void PruneBackupFiles_(const std::filesystem::path &dir,
                              const std::string &prefix,
                              const std::string &suffix, int64_t max_count) {
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
inline Json *EnsureKnownHostsArray(Json &root) {
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
inline const Json *GetKnownHostsArray(const Json &root) {
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
inline bool KnownHostMatch(const Json &item, const std::string &hostname,
                           int port, const std::string &protocol) {
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
inline std::string
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

/**
 * @brief Ensure the HOSTS array exists and return it for mutation.
 */
inline Json *EnsureHostsArray(Json &root) {
  if (!root.is_object())
    root = Json::object();
  auto it = root.find("HOSTS");
  if (it == root.end() || !it->is_array()) {
    root["HOSTS"] = Json::array();
  }
  return &root["HOSTS"];
}

/**
 * @brief Locate a host entry by nickname.
 */
inline const Json *FindHostJson(const Json &root, const std::string &nickname,
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

/**
 * @brief Locate a mutable host entry by nickname.
 */
inline Json *FindHostJsonMutable(Json &root, const std::string &nickname,
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

/**
 * @brief Parse a client protocol enum from a string.
 */
inline ClientProtocol ProtocolFromString(const std::string &value) {
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
} // namespace AMConfigInternal
