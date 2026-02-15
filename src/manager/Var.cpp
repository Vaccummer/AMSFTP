#include "AMManager/Var.hpp"
#include "AMManager/Var.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include <algorithm>
#include <unordered_set>

using EC = ErrorCode;
using Json = nlohmann::ordered_json;

namespace {
constexpr const char *kPublicScope = "*";

/**
 * @brief Resolve the active nickname for private variables.
 */
std::string ResolvePrivateScope_() {
  auto current = AMClientManager::Instance().CurrentClient();
  std::string nickname = current ? current->GetNickname() : std::string();
  if (nickname.empty()) {
    nickname = "local";
  }
  return nickname;
}

/**
 * @brief Resolve a scoped variable from settings.
 */
bool ResolveScopedVar_(AMConfigManager &config_manager,
                       const std::string &scope, const std::string &name,
                       std::string *value) {
  std::string parsed;
  if (!config_manager.ResolveArg(DocumentKind::Settings,
                                 {"UserVars", scope, name}, &parsed)) {
    return false;
  }
  if (value) {
    *value = std::move(parsed);
  }
  return true;
}

/**
 * @brief Resolve private then public user variables.
 */
bool ResolveUserVar_(AMConfigManager &config_manager, const std::string &name,
                     std::string *value, AMVarManager::VarSource *source) {
  const std::string nickname = ResolvePrivateScope_();
  if (ResolveScopedVar_(config_manager, nickname, name, value)) {
    if (source) {
      *source = AMVarManager::VarSource::Private;
    }
    return true;
  }
  if (ResolveScopedVar_(config_manager, kPublicScope, name, value)) {
    if (source) {
      *source = AMVarManager::VarSource::Public;
    }
    return true;
  }
  return false;
}
} // namespace

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

  std::string storage_value;
  VarSource storage_source = VarSource::Public;
  if (ResolveUserVar_(config_manager_, name, &storage_value, &storage_source)) {
    if (value) {
      *value = storage_value;
    }
    if (source) {
      *source = storage_source;
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
  return ResolveUserVar_(config_manager_, name, value, nullptr);
}

/**
 * @brief List all persistent variables from storage.
 */
std::vector<std::pair<std::string, std::string>>
AMVarManager::ListUserVars() const {
  std::vector<std::pair<std::string, std::string>> entries;
  std::unordered_map<std::string, std::string> merged;
  const std::string nickname = ResolvePrivateScope_();

  Json public_vars;
  if (config_manager_.ResolveArg(DocumentKind::Settings,
                                 {"UserVars", kPublicScope}, &public_vars) &&
      public_vars.is_object()) {
    for (auto it = public_vars.begin(); it != public_vars.end(); ++it) {
      std::string parsed;
      if (QueryKey(public_vars, {it.key()}, &parsed)) {
        merged.emplace(it.key(), std::move(parsed));
      }
    }
  }

  Json private_vars;
  if (config_manager_.ResolveArg(DocumentKind::Settings,
                                 {"UserVars", nickname}, &private_vars) &&
      private_vars.is_object()) {
    for (auto it = private_vars.begin(); it != private_vars.end(); ++it) {
      std::string parsed;
      if (QueryKey(private_vars, {it.key()}, &parsed)) {
        merged[it.key()] = std::move(parsed);
      }
    }
  }

  entries.reserve(merged.size());
  for (const auto &item : merged) {
    entries.emplace_back(item.first, item.second);
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
  if (!config_manager_.SetArg(DocumentKind::Settings,
                              {"UserVars", kPublicScope, name}, value)) {
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
  const std::string nickname = ResolvePrivateScope_();
  std::string parsed;
  const bool has_private =
      QueryKey(settings_json, {"UserVars", nickname, name}, &parsed);
  const bool has_public =
      QueryKey(settings_json, {"UserVars", kPublicScope, name}, &parsed);
  if (!has_private && !has_public) {
    return Err(EC::InvalidArg, "Variable not found");
  }

  const std::vector<std::string> target_path =
      has_private ? std::vector<std::string>{"UserVars", nickname, name}
                  : std::vector<std::string>{"UserVars", kPublicScope, name};
  if (!config_manager_.DelArg(DocumentKind::Settings, target_path)) {
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
  VarSource storage_source = VarSource::Public;
  const bool has_storage =
      ResolveUserVar_(config_manager_, name, nullptr, &storage_source);
  if (confirm_overwrite && (has_memory || has_storage)) {
    VarSource source = has_memory ? VarSource::Memory : storage_source;
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
  VarSource storage_source = VarSource::Public;
  const bool has_storage =
      ResolveUserVar_(config_manager_, name, nullptr, &storage_source);
  if (confirm_overwrite && (has_memory || has_storage)) {
    VarSource source = has_memory ? VarSource::Memory : storage_source;
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
