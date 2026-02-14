#include "AMManager/Var.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMManager/Config.hpp"
#include <algorithm>
#include <unordered_set>

using EC = ErrorCode;
using Json = nlohmann::ordered_json;

/**
 * @brief Return true if an in-memory variable exists.
 */
bool AMVarManager::HasMemoryVar(const std::string &name) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return memory_vars_.find(name) != memory_vars_.end();
}

/**
 * @brief Query an in-memory variable.
 */
bool AMVarManager::GetMemVar(const std::string &name,
                             std::string *value) const {
  if (name.empty()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = memory_vars_.find(name);
  if (it == memory_vars_.end()) {
    return false;
  }
  if (value) {
    *value = it->second;
  }
  return true;
}

/**
 * @brief List variable names from memory and storage.
 */
std::vector<std::string> AMVarManager::ListNames() const {
  std::unordered_set<std::string> seen;
  std::vector<std::string> names;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    names.reserve(memory_vars_.size());
    for (const auto &item : memory_vars_) {
      if (seen.insert(item.first).second) {
        names.push_back(item.first);
      }
    }
  }

  auto stored = ListUserVars();
  names.reserve(names.size() + stored.size());
  for (const auto &item : stored) {
    if (seen.insert(item.first).second) {
      names.push_back(item.first);
    }
  }

  std::sort(names.begin(), names.end());
  return names;
}

/**
 * @brief Resolve a variable value from memory or settings.
 */
bool AMVarManager::Resolve(const std::string &name, std::string *value,
                           VarSource *source) const {
  if (name.empty()) {
    return false;
  }

  if (GetMemVar(name, value)) {
    if (source) {
      *source = VarSource::Memory;
    }
    return true;
  }

  std::string builtin_value;
  if (GetUserVar(name, &builtin_value)) {
    if (value) {
      *value = builtin_value;
    }
    if (source) {
      *source = VarSource::Builtin;
    }
    return true;
  }

  return false;
}

/**
 * @brief Query a persistent variable from storage.
 */
bool AMVarManager::GetUserVar(const std::string &name,
                              std::string *value) const {
  if (name.empty()) {
    return false;
  }
  std::string parsed;
  if (!config_manager_.ResolveArg(DocumentKind::Settings, {"UserVars", name},
                                  &parsed)) {
    return false;
  }
  if (value) {
    *value = std::move(parsed);
  }
  return true;
}

/**
 * @brief List all persistent variables from storage.
 */
std::vector<std::pair<std::string, std::string>>
AMVarManager::ListUserVars() const {
  std::vector<std::pair<std::string, std::string>> entries;

  Json user_vars;
  if (!config_manager_.ResolveArg(DocumentKind::Settings, {"UserVars"},
                                  &user_vars)) {
    return entries;
  }
  if (!user_vars.is_object()) {
    return entries;
  }

  entries.reserve(user_vars.size());
  for (auto it = user_vars.begin(); it != user_vars.end(); ++it) {
    std::string parsed;
    if (QueryKey(user_vars, {it.key()}, &parsed)) {
      entries.emplace_back(it.key(), std::move(parsed));
    }
  }
  return entries;
}

/**
 * @brief Set a persistent variable and optionally dump settings.
 */
ECM AMVarManager::SetUserVar(const std::string &name, const std::string &value,
                             bool dump_now) {
  if (name.empty()) {
    return Err(EC::InvalidArg, "Empty variable name");
  }
  if (!config_manager_.SetArg(DocumentKind::Settings, {"UserVars", name},
                              value)) {
    return Err(EC::ConfigInvalid, "failed to set UserVars");
  }
  if (dump_now) {
    return config_manager_.DumpAll();
  }
  return Ok();
}

/**
 * @brief Remove a persistent variable and optionally dump settings.
 */
ECM AMVarManager::RemoveUserVar(const std::string &name, bool dump_now) {
  if (name.empty()) {
    return Err(EC::InvalidArg, "Empty variable name");
  }

  Json settings_json;
  if (!config_manager_.ResolveArg(DocumentKind::Settings, {}, &settings_json)) {
    return Err(EC::ConfigNotInitialized, "settings document not initialized");
  }
  std::string parsed;
  if (!QueryKey(settings_json, {"UserVars", name}, &parsed)) {
    return Err(EC::InvalidArg, "Variable not found");
  }

  if (!config_manager_.DelArg(DocumentKind::Settings, {"UserVars", name})) {
    return Err(EC::ConfigInvalid, "failed to remove UserVars");
  }
  if (dump_now) {
    return config_manager_.DumpAll();
  }
  return Ok();
}

/**
 * @brief Set or overwrite an in-memory variable, confirming overwrites.
 */
ECM AMVarManager::SetMemoryVar(const std::string &name,
                               const std::string &value,
                               bool confirm_overwrite) {
  if (name.empty()) {
    return {EC::InvalidArg, "Empty variable name"};
  }

  const bool has_memory = HasMemoryVar(name);
  const bool has_builtin = GetUserVar(name, nullptr);
  if (confirm_overwrite && (has_memory || has_builtin)) {
    VarSource source = has_memory ? VarSource::Memory : VarSource::Builtin;
    ECM confirm = ConfirmOverwrite(name, source);
    if (confirm.first != EC::Success) {
      return confirm;
    }
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    memory_vars_[name] = value;
  }
  return {EC::Success, ""};
}

/**
 * @brief Set or overwrite a persistent variable in storage only.
 */
ECM AMVarManager::SetPersistentVar(const std::string &name,
                                   const std::string &value,
                                   bool confirm_overwrite) {
  if (name.empty()) {
    return {EC::InvalidArg, "Empty variable name"};
  }

  const bool has_memory = HasMemoryVar(name);
  const bool has_builtin = GetUserVar(name, nullptr);
  if (confirm_overwrite && (has_memory || has_builtin)) {
    VarSource source = has_memory ? VarSource::Memory : VarSource::Builtin;
    ECM confirm = ConfirmOverwrite(name, source);
    if (confirm.first != EC::Success) {
      return confirm;
    }
  }

  ECM rcm = SetUserVar(name, value, true);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  return {EC::Success, ""};
}
