#include "internal_func.hpp"

using namespace AMConfigInternal;
using cls = AMConfigCoreData;

/**
 * @brief Construct a core data layer with default rules.
 */
cls::AMConfigCoreData() : nickname_pattern_("^[A-Za-z0-9_-]+$") {}

/**
 * @brief Bind the storage layer used for raw config access.
 */
void cls::BindStorage(AMConfigStorage *storage) { storage_ = storage; }

/**
 * @brief Report whether the layer has an attached storage instance.
 */
bool cls::HasStorage() const { return storage_ != nullptr; }

/**
 * @brief Load history data into memory (in-memory only for now).
 */
ECM cls::LoadHistory() {
  if (!storage_) {
    return Err(EC::ConfigNotInitialized, "config storage not initialized");
  }
  return storage_->Load(DocumentKind::History);
}

/**
 * @brief Fetch history commands for a nickname.
 */
ECM cls::GetHistoryCommands(std::string nickname,
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
    nickname = "local";
  }
  auto *node = storage_->ResolveArg<nlohmann::ordered_json *>(
      DocumentKind::History, {nickname, "commands"}, nullptr, {});
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
ECM cls::SetHistoryCommands(const std::string &nickname,
                            const std::vector<std::string> &commands,
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
 * @brief Check whether a host nickname exists in the configuration.
 */
bool cls::HostExists(const std::string &nickname) const {
  if (!storage_ || nickname.empty()) {
    return false;
  }
  auto *hosts = storage_->ResolveArg<nlohmann::ordered_json *>(
      DocumentKind::Config, {"HOSTS"}, nullptr, {});
  if (!hosts || !hosts->is_array()) {
    return false;
  }
  for (const auto &item : *hosts) {
    if (!item.is_object()) {
      continue;
    }
    if (!IsHostValid(item)) {
      continue;
    }
    auto name = GetStringField(item, "nickname");
    if (name && *name == nickname) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Validate whether a nickname is legal and not already used.
 */
bool cls::ValidateNickname(const std::string &nickname,
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
