#include "AMManager/Var.hpp"
#include "AMBase/CommonTools.hpp"
#include <algorithm>
#include <unordered_set>

using EC = ErrorCode;

namespace {
using Json = nlohmann::ordered_json;
using Path = std::vector<std::string>;

/**
 * @brief Find a JSON node by walking the provided path.
 */
const Json *FindJsonNode(const Json &root, const Path &path) {
  const Json *node = &root;
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
} // namespace

/**
 * @brief Return the singleton variable manager bound to a config manager.
 */
AMVarManager &AMVarManager::Instance(AMConfigManager &config_manager) {
  static AMVarManager instance(config_manager);
  return instance;
}

/**
 * @brief Construct a variable manager tied to the config manager.
 */
AMVarManager::AMVarManager(AMConfigManager &config_manager)
    : config_manager_(config_manager),
      prompt_manager_(AMPromptManager::Instance()) {}

/**
 * @brief Return true if an in-memory variable exists.
 */
bool AMVarManager::HasMemoryVar(const std::string &name) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return memory_vars_.find(name) != memory_vars_.end();
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

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = memory_vars_.find(name);
    if (it != memory_vars_.end()) {
      if (value) {
        *value = it->second;
      }
      if (source) {
        *source = VarSource::Memory;
      }
      return true;
    }
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
  Json settings_json;
  if (!config_manager_.GetJson(DocumentKind::Settings, &settings_json)) {
    return false;
  }
  const Json *node = FindJsonNode(settings_json, {"UserVars", name});
  if (!node) {
    return false;
  }
  if (value) {
    std::string parsed;
    if (!QueryKey(settings_json, {"UserVars", name}, &parsed)) {
      return false;
    }
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

  Json settings_json;
  if (!config_manager_.GetJson(DocumentKind::Settings, &settings_json)) {
    return entries;
  }
  const Json *node = FindJsonNode(settings_json, {"UserVars"});
  if (!node || !node->is_object()) {
    return entries;
  }

  entries.reserve(node->size());
  for (auto it = node->begin(); it != node->end(); ++it) {
    std::string parsed;
    if (QueryKey(settings_json, {"UserVars", it.key()}, &parsed)) {
      entries.emplace_back(it.key(), std::move(parsed));
    }
  }
  return entries;
}

/**
 * @brief Set a persistent variable and optionally dump settings.
 */
ECM AMVarManager::SetUserVar(const std::string &name,
                             const std::string &value, bool dump_now) {
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
  if (!config_manager_.GetJson(DocumentKind::Settings, &settings_json)) {
    return Err(EC::ConfigNotInitialized, "settings document not initialized");
  }
  const Json *node = FindJsonNode(settings_json, {"UserVars", name});
  if (!node) {
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
 * @brief Format a variable key/value using the UserVars style.
 */
std::string AMVarManager::FormatUserVarText(const std::string &text) const {
  return config_manager_.Format(text, "UserVars");
}

/**
 * @brief Print a formatted query line.
 */
void AMVarManager::PrintQueryLine(const std::string &scope,
                                  const std::string &name,
                                  const std::string &value) const {
  const std::string styled_key = FormatUserVarText("$" + name);
  const std::string styled_value = FormatUserVarText(value);
  prompt_manager_.Print(
      AMStr::amfmt("[{}] {} = {}", scope, styled_key, styled_value));
}

/**
 * @brief Print a formatted entry without a scope label.
 */
void AMVarManager::PrintEntry(const std::string &name,
                              const std::string &value) const {
  const std::string styled_key = FormatUserVarText("$" + name);
  const std::string styled_value = FormatUserVarText(value);
  prompt_manager_.Print(AMStr::amfmt("{} = {}", styled_key, styled_value));
}

/**
 * @brief Log a per-variable not found error.
 */
void AMVarManager::LogNotFound(const std::string &name) const {
  prompt_manager_.Print(AMStr::amfmt("❌ var: {} not found", name));
}

/**
 * @brief Ask the user to confirm deleting a variable.
 */
ECM AMVarManager::ConfirmDelete(const std::string &name, bool has_memory,
                                bool has_storage) const {
  std::string scope;
  if (has_memory && has_storage) {
    scope = "memory/storage";
  } else if (has_memory) {
    scope = "memory";
  } else {
    scope = "storage";
  }
  const std::string prompt =
      AMStr::amfmt("Delete variable '{}' from {}? (y/N): ", name, scope);
  bool canceled = false;
  if (!prompt_manager_.PromptYesNo(prompt, &canceled)) {
    if (canceled) {
      return {EC::Terminate, "Operation aborted"};
    }
    return {EC::InvalidArg, "Deletion canceled"};
  }
  return {EC::Success, ""};
}

/**
 * @brief Query variables in memory and storage, printing results.
 */
ECM AMVarManager::Query(const std::vector<std::string> &names) {
  ECM last_error = {EC::Success, ""};
  bool any_found = false;

  for (const auto &name : names) {
    bool found = false;
    std::string value;
    VarSource source = VarSource::Memory;
  if (Resolve(name, &value, &source)) {
      if (source == VarSource::Memory) {
        PrintQueryLine("InMemory", name, value);
      } else {
        PrintQueryLine("InStorage", name, value);
      }
      found = true;
      any_found = true;
    }

    if (source == VarSource::Memory) {
      std::string storage_value;
      if (GetUserVar(name, &storage_value)) {
        PrintQueryLine("InStorage", name, storage_value);
        found = true;
        any_found = true;
      }
    }

    if (!found) {
      LogNotFound(name);
      last_error = {EC::InvalidArg,
                    AMStr::amfmt("Variable not found: {}", name)};
    }
  }

  if (!any_found && last_error.first == EC::Success) {
    last_error = {EC::InvalidArg, "No matching variables"};
  }
  return last_error;
}

/**
 * @brief Delete variables from memory and storage, confirming per key.
 */
ECM AMVarManager::Delete(const std::vector<std::string> &names) {
  ECM last_error = {EC::Success, ""};
  bool storage_changed = false;

  for (const auto &name : names) {
    bool has_memory = false;
    bool has_storage = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      has_memory = memory_vars_.find(name) != memory_vars_.end();
    }
    has_storage = GetUserVar(name, nullptr);

    if (!has_memory && !has_storage) {
      LogNotFound(name);
      last_error = {EC::InvalidArg,
                    AMStr::amfmt("Variable not found: {}", name)};
      continue;
    }

    ECM confirm = ConfirmDelete(name, has_memory, has_storage);
    if (confirm.first != EC::Success) {
      last_error = confirm;
      if (confirm.first == EC::Terminate) {
        return confirm;
      }
      continue;
    }

    if (has_memory) {
      std::lock_guard<std::mutex> lock(mutex_);
      memory_vars_.erase(name);
    }
    if (has_storage) {
      ECM rcm = RemoveUserVar(name, false);
      if (rcm.first != EC::Success) {
        last_error = rcm;
      } else {
        storage_changed = true;
      }
    }
  }

  if (storage_changed) {
    ECM rcm = config_manager_.Dump();
    if (rcm.first != EC::Success) {
      last_error = rcm;
    }
  }

  return last_error;
}

/**
 * @brief Enumerate variables, printing memory entries then storage entries.
 */
ECM AMVarManager::Enumerate() {
  prompt_manager_.Print("[InMemory]");
  {
    std::vector<std::pair<std::string, std::string>> entries;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      entries.reserve(memory_vars_.size());
      for (const auto &item : memory_vars_) {
        entries.emplace_back(item.first, item.second);
      }
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    for (const auto &item : entries) {
      PrintEntry(item.first, item.second);
    }
  }

  prompt_manager_.Print("");
  prompt_manager_.Print("[InStorage]");
  {
    std::vector<std::pair<std::string, std::string>> entries = ListUserVars();
    std::sort(entries.begin(), entries.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    for (const auto &item : entries) {
      PrintEntry(item.first, item.second);
    }
  }
  return {EC::Success, ""};
}

/**
 * @brief Ask the user to confirm overwriting an existing variable.
 */
ECM AMVarManager::ConfirmOverwrite(const std::string &name,
                                   VarSource source) const {
  const std::string source_label =
      source == VarSource::Builtin ? "built-in" : "in-memory";
  const std::string prompt = AMStr::amfmt(
      "Variable '{}' already exists ({}). Overwrite? (y/N): ", name,
      source_label);
  bool canceled = false;
  if (!prompt_manager_.PromptYesNo(prompt, &canceled)) {
    return {EC::Terminate, "Operation aborted"};
  }
  return {EC::Success, ""};
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
