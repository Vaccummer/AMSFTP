#include "internal_func.hpp"

using namespace AMConfigInternal;

/**
 * @brief Construct a core data layer with default rules.
 */
AMConfigCoreData::AMConfigCoreData() : nickname_pattern_("^[A-Za-z0-9_-]+$") {}

/**
 * @brief Bind the storage layer used for raw config access.
 */
void AMConfigCoreData::BindStorage(AMConfigStorage *storage) {
  storage_ = storage;
}

/**
 * @brief Report whether the layer has an attached storage instance.
 */
bool AMConfigCoreData::HasStorage() const { return storage_ != nullptr; }

/**
 * @brief Load history data into memory (in-memory only for now).
 */
ECM AMConfigCoreData::LoadHistory() {
  if (!storage_) {
    return Err(EC::ConfigNotInitialized, "config storage not initialized");
  }
  return storage_->Load(DocumentKind::History);
}

/**
 * @brief Fetch history commands for a nickname.
 */
ECM AMConfigCoreData::GetHistoryCommands(const std::string &nickname,
                                         std::vector<std::string> *out) const {
  if (!out) {
    return Err(EC::InvalidArg, "null history output");
  }
  out->clear();
  if (!storage_) {
    return Err(EC::ConfigNotInitialized, "config storage not initialized");
  }
  ECM load_status = storage_->Load(DocumentKind::History);
  if (load_status.first != EC::Success) {
    return load_status;
  }
  if (nickname.empty()) {
    return Ok();
  }
  const Json history = storage_->Snapshot(DocumentKind::History);
  const Json *node = FindJsonNode_(history, {nickname, "commands"});
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
ECM AMConfigCoreData::SetHistoryCommands(
    const std::string &nickname, const std::vector<std::string> &commands,
    bool dump_now) {
  if (!storage_) {
    return Err(EC::ConfigNotInitialized, "config storage not initialized");
  }
  ECM load_status = storage_->Load(DocumentKind::History);
  if (load_status.first != EC::Success) {
    return load_status;
  }
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "empty history nickname");
  }
  return storage_->Mutate(
      DocumentKind::History,
      [&](Json &history) {
        if (!history.is_object()) {
          history = Json::object();
        }
        Json &node = history[nickname];
        if (!node.is_object()) {
          node = Json::object();
        }
        node["commands"] = commands;
      },
      dump_now);
}

/**
 * @brief Resolve history size limit from settings with minimum 10.
 */
int AMConfigCoreData::ResolveMaxHistoryCount(int default_value) const {
  const int fallback = std::max(default_value, 10);
  if (!storage_) {
    return fallback;
  }
  AMConfigStorage::Value value;
  if (!storage_->QueryKey(storage_->GetJson(DocumentKind::Settings).value().get(),
                          {"InternalVars", "MaxHistoryCount"}, &value)) {
    return fallback;
  }
  if (std::holds_alternative<int64_t>(value)) {
    const int64_t raw = std::get<int64_t>(value);
    if (raw >= 10) {
      return static_cast<int>(raw);
    }
  }
  if (std::holds_alternative<std::string>(value)) {
    try {
      const int parsed = std::stoi(std::get<std::string>(value));
      return parsed >= 10 ? parsed : fallback;
    } catch (...) {
      return fallback;
    }
  }
  return fallback;
}

/**
 * @brief Check whether a host nickname exists in the configuration.
 */
bool AMConfigCoreData::HostExists(const std::string &nickname) const {
  if (!storage_ || nickname.empty()) {
    return false;
  }
  return FindHostJson(storage_->GetJson(DocumentKind::Config).value().get(),
                      nickname) != nullptr;
}

/**
 * @brief Validate whether a nickname is legal and not already used.
 */
bool AMConfigCoreData::ValidateNickname(const std::string &nickname,
                                        std::string *error) const {
  if (nickname.empty()) {
    if (error) {
      *error = "Nickname cannot be empty.";
    }
    return false;
  }
  if (!std::regex_match(nickname, nickname_pattern_)) {
    if (error) {
      *error = "Nickname must contain only letters, numbers, _ or -.";
    }
    return false;
  }
  if (HostExists(nickname)) {
    if (error) {
      *error = "Nickname already exists.";
    }
    return false;
  }
  return true;
}

/**
 * @brief Find a JSON node by walking a path.
 */
const nlohmann::ordered_json *
AMConfigCoreData::FindJsonNode_(const nlohmann::ordered_json &root,
                                const Path &path) const {
  const nlohmann::ordered_json *node = &root;
  for (const auto &seg : path) {
    if (!node->is_object()) {
      return nullptr;
    }
    auto it = node->find(seg);
    if (it == node->end()) {
      return nullptr;
    }
    node = &(*it);
  }
  return node;
}
