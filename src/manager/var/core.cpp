#include "AMBase/tools/auth.hpp"
#include "AMBase/tools/bar.hpp"
#include "AMBase/tools/json.hpp"
#include "AMBase/tools/time.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Var.hpp"
#include <algorithm>
#include <cctype>
#include <unordered_set>

using EC = ErrorCode;

namespace {
/**
 * @brief Convert JSON scalar into string form.
 */
std::string ToStringScalar_(const Json &value) {
  if (value.is_string()) {
    return value.get<std::string>();
  }
  if (value.is_boolean()) {
    return value.get<bool>() ? "true" : "false";
  }
  if (value.is_number_integer()) {
    return std::to_string(value.get<int64_t>());
  }
  if (value.is_number_unsigned()) {
    return std::to_string(value.get<size_t>());
  }
  if (value.is_number_float()) {
    return AMStr::amfmt("{}", value.get<double>());
  }
  if (value.is_null()) {
    return "";
  }
  return value.dump();
}

} // namespace

/**
 * @brief Reload [UserVars] from ConfigManager into domain dict.
 */
ECM AMVarManager::Reload() {
  Json user_vars = config_manager_.ResolveArg<Json>(
      DocumentKind::Settings, {varsetkn::kRoot}, Json::object(), {});
  if (!user_vars.is_object()) {
    user_vars = Json::object();
  }

  DomainDict parsed;
  parsed.reserve(user_vars.size() + 1);
  parsed[varsetkn::kPublic] = DomainVars{};

  for (auto it = user_vars.begin(); it != user_vars.end(); ++it) {
    if (it.value().is_object()) {
      if (!IsValidDomainName_(it.key())) {
        continue;
      }
      DomainVars &vars = parsed[it.key()];
      for (auto vit = it.value().begin(); vit != it.value().end(); ++vit) {
        if (!varsetkn::IsValidVarname(vit.key())) {
          continue;
        }
        vars[vit.key()] = ToStringScalar_(vit.value());
      }
      continue;
    }

    // Backward compatibility: old [UserVars] flat entries are public vars.
    if (!varsetkn::IsValidVarname(it.key())) {
      continue;
    }
    parsed[varsetkn::kPublic][it.key()] = ToStringScalar_(it.value());
  }

  std::lock_guard<std::mutex> lock(mutex_);
  vars_by_domain_ = std::move(parsed);
  ready_ = true;
  dirty_ = false;
  return Ok();
}

/**
 * @brief Persist variable dict to settings json and settings.toml.
 */
ECM AMVarManager::Save(bool async) {
  EnsureLoaded_();
  Json snapshot = Json::object();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!dirty_) {
      return Ok();
    }
    for (const auto &domain_entry : vars_by_domain_) {
      Json section = Json::object();
      for (const auto &var_entry : domain_entry.second) {
        section[var_entry.first] = var_entry.second;
      }
      snapshot[domain_entry.first] = std::move(section);
    }
  }

  if (!config_manager_.SetArg(DocumentKind::Settings, {varsetkn::kRoot},
                              snapshot)) {
    return Err(EC::CommonFailure, "failed to write UserVars into settings");
  }

  ECM rcm = config_manager_.Dump(DocumentKind::Settings, "", async);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  dirty_ = false;
  return Ok();
}

/**
 * @brief Return one variable from a specified domain.
 */
VarInfo AMVarManager::GetVar(const std::string &domain,
                             const std::string &name) const {
  if (!IsValidDomainName_(domain) || !varsetkn::IsValidVarname(name)) {
    return {};
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);

  auto domain_it = vars_by_domain_.find(domain);
  if (domain_it == vars_by_domain_.end()) {
    return {};
  }
  auto var_it = domain_it->second.find(name);
  if (var_it == domain_it->second.end()) {
    return {};
  }
  return {domain, name, var_it->second};
}

/**
 * @brief Find all variables with the given name across all domains.
 */
std::vector<VarInfo> AMVarManager::FindByName(const std::string &name) const {
  std::vector<VarInfo> out;
  if (!varsetkn::IsValidVarname(name)) {
    return out;
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  out.reserve(vars_by_domain_.size());
  for (const auto &domain_entry : vars_by_domain_) {
    auto it = domain_entry.second.find(name);
    if (it == domain_entry.second.end()) {
      continue;
    }
    out.push_back({domain_entry.first, name, it->second});
  }
  std::sort(out.begin(), out.end(), [](const VarInfo &a, const VarInfo &b) {
    return a.domain < b.domain;
  });
  return out;
}

/**
 * @brief List variables under one domain.
 */
std::vector<VarInfo>
AMVarManager::ListByDomain(const std::string &domain) const {
  std::vector<VarInfo> out;
  if (!IsValidDomainName_(domain)) {
    return out;
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  auto domain_it = vars_by_domain_.find(domain);
  if (domain_it == vars_by_domain_.end()) {
    return out;
  }
  out.reserve(domain_it->second.size());
  for (const auto &item : domain_it->second) {
    out.push_back({domain, item.first, item.second});
  }
  std::sort(out.begin(), out.end(), [](const VarInfo &a, const VarInfo &b) {
    return a.varname < b.varname;
  });
  return out;
}

/**
 * @brief List all domain names.
 */
std::vector<std::string> AMVarManager::ListDomains() const {
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> domains;
  domains.reserve(vars_by_domain_.size());
  for (const auto &item : vars_by_domain_) {
    domains.push_back(item.first);
  }
  std::sort(domains.begin(), domains.end());
  return domains;
}

/**
 * @brief Return true if one domain exists in the dict.
 */
bool AMVarManager::HasDomain(const std::string &domain) const {
  if (!IsValidDomainName_(domain)) {
    return false;
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  return vars_by_domain_.find(domain) != vars_by_domain_.end();
}

/**
 * @brief Return true if one variable exists in a domain.
 */
bool AMVarManager::HasVar(const std::string &domain,
                          const std::string &name) const {
  if (!IsValidDomainName_(domain) || !varsetkn::IsValidVarname(name)) {
    return false;
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  auto domain_it = vars_by_domain_.find(domain);
  if (domain_it == vars_by_domain_.end()) {
    return false;
  }
  return domain_it->second.find(name) != domain_it->second.end();
}

/**
 * @brief Upsert one variable into a target domain.
 */
ECM AMVarManager::SetVar(const VarInfo &info, bool create_domain) {
  ECM valid = info.IsValid();
  if (valid.first != EC::Success) {
    return valid;
  }
  if (!IsValidDomainName_(info.domain)) {
    return Err(EC::InvalidArg, "invalid domain");
  }
  if (!varsetkn::IsValidVarname(info.varname)) {
    return Err(EC::InvalidArg, "invalid variable name");
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  auto domain_it = vars_by_domain_.find(info.domain);
  if (domain_it == vars_by_domain_.end() && !create_domain) {
    return Err(EC::InvalidArg, "domain not found");
  }
  vars_by_domain_[info.domain][info.varname] = info.varvalue;
  dirty_ = true;
  return Ok();
}

/**
 * @brief Delete one variable from target domain.
 */
ECM AMVarManager::DeleteVar(const std::string &domain,
                            const std::string &name) {
  if (!IsValidDomainName_(domain) || !varsetkn::IsValidVarname(name)) {
    return Err(EC::InvalidArg, "invalid domain or variable name");
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  auto domain_it = vars_by_domain_.find(domain);
  if (domain_it == vars_by_domain_.end()) {
    return Err(EC::InvalidArg, "domain not found");
  }
  auto var_it = domain_it->second.find(name);
  if (var_it == domain_it->second.end()) {
    return Err(EC::InvalidArg, "variable not found");
  }
  domain_it->second.erase(var_it);
  dirty_ = true;
  return Ok();
}

/**
 * @brief Delete one variable from every domain.
 */
ECM AMVarManager::DeleteVarAll(const std::string &name,
                               std::vector<VarInfo> *removed) {
  if (!varsetkn::IsValidVarname(name)) {
    return Err(EC::InvalidArg, "invalid variable name");
  }
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  bool any_removed = false;
  for (auto &domain_entry : vars_by_domain_) {
    auto it = domain_entry.second.find(name);
    if (it == domain_entry.second.end()) {
      continue;
    }
    if (removed) {
      removed->push_back({domain_entry.first, it->first, it->second});
    }
    domain_entry.second.erase(it);
    any_removed = true;
  }
  if (!any_removed) {
    return Err(EC::InvalidArg, "variable not found");
  }
  dirty_ = true;
  return Ok();
}

/**
 * @brief Return all variable names deduplicated.
 */
std::vector<std::string> AMVarManager::ListNames() const {
  EnsureLoaded_();
  std::lock_guard<std::mutex> lock(mutex_);
  std::unordered_set<std::string> seen;
  std::vector<std::string> names;
  for (const auto &domain_entry : vars_by_domain_) {
    for (const auto &item : domain_entry.second) {
      if (seen.insert(item.first).second) {
        names.push_back(item.first);
      }
    }
  }
  std::sort(names.begin(), names.end());
  return names;
}

/**
 * @brief Return current private domain (current host nickname or local).
 */
std::string AMVarManager::CurrentDomain() const {
  std::string nickname = AMStr::Strip(client_manager_.CurrentNickname());
  if (nickname.empty()) {
    nickname = "local";
  }
  return nickname;
}

/**
 * @brief Replace one path-like argument using current-domain variables.
 */
std::string AMVarManager::SubstitutePathLike(const std::string &input) const {
  if (input.empty()) {
    return input;
  }
  EnsureLoaded_();
  const std::string domain = CurrentDomain();
  std::string output;
  output.reserve(input.size());

  std::lock_guard<std::mutex> lock(mutex_);
  auto append_lookup = [&](const varsetkn::VarRef &ref,
                           const std::string &fallback) {
    if (ref.varname.empty()) {
      output.append(fallback);
      return;
    }

    auto append_from_domain = [&](const std::string &target_domain) -> bool {
      auto domain_it = vars_by_domain_.find(target_domain);
      if (domain_it == vars_by_domain_.end()) {
        return false;
      }
      auto var_it = domain_it->second.find(ref.varname);
      if (var_it == domain_it->second.end()) {
        return false;
      }
      output.append(var_it->second);
      return true;
    };

    if (ref.explicit_domain) {
      if (append_from_domain(ref.domain)) {
        return;
      }
      output.append(fallback);
      return;
    }

    if (append_from_domain(domain)) {
      return;
    }
    if (append_from_domain(varsetkn::kPublic)) {
      return;
    }
    output.append(fallback);
  };

  for (size_t i = 0; i < input.size(); ++i) {
    const char ch = input[i];
    if (ch == '`' && i + 1 < input.size() && input[i + 1] == '$') {
      // Preserve escaped '$' as literal and never expand.
      output.push_back('$');
      ++i;
      continue;
    }
    if (ch != '$') {
      output.push_back(ch);
      continue;
    }
    if (i + 1 >= input.size()) {
      output.push_back('$');
      continue;
    }

    size_t ref_end = i;
    varsetkn::VarRef ref{};
    if (!varsetkn::ParseVarRefAt(input, i, input.size(), true, true, &ref_end,
                                 &ref) ||
        ref_end <= i) {
      output.push_back('$');
      continue;
    }

    const std::string token = input.substr(i, ref_end - i);
    append_lookup(ref, token);
    i = ref_end - 1;
  }

  return output;
}

/**
 * @brief Replace path-like arguments in place using current-domain variables.
 */
void AMVarManager::SubstitutePathLike(std::vector<std::string> *inputs) const {
  if (!inputs) {
    return;
  }
  for (std::string &item : *inputs) {
    item = SubstitutePathLike(item);
  }
}

/**
 * @brief Return true for valid domain names.
 */
bool AMVarManager::IsValidDomainName_(const std::string &domain) const {
  if (domain == varsetkn::kPublic) {
    return true;
  }
  return configkn::ValidateNickname(domain);
}

/**
 * @brief Ensure manager is loaded before access.
 */
void AMVarManager::EnsureLoaded_() const {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (ready_) {
      return;
    }
  }
  (void)const_cast<AMVarManager *>(this)->Reload();
}

