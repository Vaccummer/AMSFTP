#include "AMManager/Var.hpp"
#include "AMBase/CommonTools.hpp"
#include <algorithm>

using EC = ErrorCode;

namespace {
/**
 * @brief Return true if a character is valid inside a variable name.
 */
bool IsVarNameChar_(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}

/**
 * @brief Return true if a variable name is non-empty and valid.
 */
bool IsValidVarName_(const std::string &name) {
  if (name.empty()) {
    return false;
  }
  for (char c : name) {
    if (!IsVarNameChar_(c)) {
      return false;
    }
  }
  return true;
}

/**
 * @brief Parse a variable token like $name or ${ name }.
 */
ECM ParseVarToken_(const std::string &token, std::string *name) {
  if (!name) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  std::string trimmed = AMStr::Strip(token);
  if (trimmed.empty()) {
    return {EC::InvalidArg, "Empty variable token"};
  }
  if (trimmed.find('=') != std::string::npos) {
    return {EC::InvalidArg, "Invalid variable token"};
  }
  if (trimmed.front() != '$') {
    return {EC::InvalidArg, "Variable token must start with $"};
  }
  if (trimmed.size() < 2) {
    return {EC::InvalidArg, "Invalid variable token"};
  }

  if (trimmed[1] == '{') {
    if (trimmed.back() != '}') {
      return {EC::InvalidArg, "Unclosed ${...} expression"};
    }
    std::string inner = AMStr::Strip(trimmed.substr(2, trimmed.size() - 3));
    if (!IsValidVarName_(inner)) {
      return {EC::InvalidArg,
              "Invalid variable name: only letters, digits, and _ are "
              "allowed"};
    }
    *name = inner;
    return {EC::Success, ""};
  }

  std::string inner = trimmed.substr(1);
  if (!IsValidVarName_(inner)) {
    return {EC::InvalidArg,
            "Invalid variable name: only letters, digits, and _ are allowed"};
  }
  *name = inner;
  return {EC::Success, ""};
}

/**
 * @brief Normalize a raw value by trimming and stripping paired quotes.
 */
ECM ParseValue_(const std::string &input, std::string *value) {
  if (!value) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  std::string trimmed = AMStr::Strip(input);
  if (trimmed.empty()) {
    *value = "";
    return {EC::Success, ""};
  }

  const char first = trimmed.front();
  const char last = trimmed.back();
  const bool starts_quote = first == '"' || first == '\'';
  const bool ends_quote = last == '"' || last == '\'';

  if (starts_quote || ends_quote) {
    if (trimmed.size() < 2 || first != last) {
      return {EC::InvalidArg, "Malformed quoted value"};
    }
    *value = trimmed.substr(1, trimmed.size() - 2);
    if (!value->empty()) {
      std::string unescaped;
      unescaped.reserve(value->size());
      for (size_t i = 0; i < value->size(); ++i) {
        if ((*value)[i] == '`' && i + 1 < value->size() &&
            ((*value)[i + 1] == '"' || (*value)[i + 1] == '\'')) {
          unescaped.push_back((*value)[i + 1]);
          ++i;
          continue;
        }
        unescaped.push_back((*value)[i]);
      }
      *value = std::move(unescaped);
    }
    return {EC::Success, ""};
  }

  std::string unescaped;
  unescaped.reserve(trimmed.size());
  for (size_t i = 0; i < trimmed.size(); ++i) {
    if (trimmed[i] == '`' && i + 1 < trimmed.size() &&
        (trimmed[i + 1] == '"' || trimmed[i + 1] == '\'')) {
      unescaped.push_back(trimmed[i + 1]);
      ++i;
      continue;
    }
    unescaped.push_back(trimmed[i]);
  }
  *value = std::move(unescaped);
  return {EC::Success, ""};
}

/**
 * @brief Parse variable tokens into validated variable names.
 */
ECM ParseVarNames_(const std::vector<std::string> &tokens,
                   std::vector<std::string> *names) {
  if (!names) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  names->clear();
  names->reserve(tokens.size());
  for (const auto &token : tokens) {
    std::string name;
    ECM rcm = ParseVarToken_(token, &name);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    names->push_back(name);
  }
  return {EC::Success, ""};
}
} // namespace

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
      AMStr::amfmt("[!sl][{}][/sl] {} = {}", scope, styled_key, styled_value));
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
 * @brief Execute `var` command tokens (enumerate/query/assignment).
 */
ECM AMVarManager::ExecuteVarTokens(const std::vector<std::string> &tokens) {
  if (tokens.empty()) {
    return Enumerate();
  }

  const std::string remainder = AMStr::join(tokens, " ");
  const size_t eq_pos = remainder.find('=');
  if (eq_pos != std::string::npos) {
    const std::string left = AMStr::Strip(remainder.substr(0, eq_pos));
    const std::string right = remainder.substr(eq_pos + 1);
    std::string name;
    ECM rcm = ParseVarToken_(left, &name);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::string parsed_value;
    rcm = ParseValue_(right, &parsed_value);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    return SetPersistentVar(name, parsed_value, true);
  }

  std::vector<std::string> names;
  ECM rcm = ParseVarNames_(tokens, &names);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return Query(names);
}

/**
 * @brief Execute `del` command tokens (parse names then delete).
 */
ECM AMVarManager::ExecuteDelTokens(const std::vector<std::string> &tokens) {
  if (tokens.empty()) {
    return {EC::InvalidArg, "del requires variable names"};
  }
  std::vector<std::string> names;
  ECM rcm = ParseVarNames_(tokens, &names);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return Delete(names);
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
    ECM rcm = config_manager_.Dump(DocumentKind::Settings);
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
  std::string source_label = "storage";
  if (source == VarSource::Memory) {
    source_label = "in-memory";
  }
  const std::string prompt = AMStr::amfmt(
      "Variable '{}' already exists ({}). Overwrite? (y/N): ", name,
      source_label);
  bool canceled = false;
  if (!prompt_manager_.PromptYesNo(prompt, &canceled)) {
    return {EC::Terminate, "Operation aborted"};
  }
  return {EC::Success, ""};
}
