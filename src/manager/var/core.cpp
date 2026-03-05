#include "foundation/tools/json.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Var.hpp"
#include <algorithm>

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
    return AMStr::fmt("{}", value.get<double>());
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
  Json user_vars = AMConfigManager::Instance().ResolveArg<Json>(
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

  ECM apply_rcm = domain_service_.ReplaceAll(std::move(parsed));
  if (apply_rcm.first != EC::Success) {
    return apply_rcm;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  ready_ = true;
  dirty_ = false;
  return Ok();
}

/**
 * @brief Persist variable dict to settings json and settings.toml.
 */
ECM AMVarManager::Save(bool async) {
  EnsureLoaded_();

  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!dirty_) {
      return Ok();
    }
  }

  Json snapshot = Json::object();
  auto vars_snapshot = domain_service_.Snapshot();
  for (const auto &domain_entry : vars_snapshot) {
    Json section = Json::object();
    for (const auto &var_entry : domain_entry.second) {
      section[var_entry.first] = var_entry.second;
    }
    snapshot[domain_entry.first] = std::move(section);
  }

  if (!AMConfigManager::Instance().SetArg(DocumentKind::Settings,
                                          {varsetkn::kRoot}, snapshot)) {
    return Err(EC::CommonFailure, "failed to write UserVars into settings");
  }

  ECM rcm = AMConfigManager::Instance().Dump(DocumentKind::Settings, "", async);
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
  return domain_service_.GetVar(domain, name);
}

/**
 * @brief Find all variables with the given name across all domains.
 */
std::vector<VarInfo> AMVarManager::FindByName(const std::string &name) const {
  if (!varsetkn::IsValidVarname(name)) {
    return {};
  }
  EnsureLoaded_();
  return domain_service_.FindByName(name);
}

/**
 * @brief List variables under one domain.
 */
std::vector<VarInfo>
AMVarManager::ListByDomain(const std::string &domain) const {
  if (!IsValidDomainName_(domain)) {
    return {};
  }
  EnsureLoaded_();
  return domain_service_.ListByDomain(domain);
}

/**
 * @brief List all domain names.
 */
std::vector<std::string> AMVarManager::ListDomains() const {
  EnsureLoaded_();
  return domain_service_.ListDomains();
}

/**
 * @brief Return true if one domain exists in the dict.
 */
bool AMVarManager::HasDomain(const std::string &domain) const {
  if (!IsValidDomainName_(domain)) {
    return false;
  }
  EnsureLoaded_();
  return domain_service_.HasDomain(domain);
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
  return domain_service_.HasVar(domain, name);
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
  ECM rcm = domain_service_.SetVar(info, create_domain);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  std::lock_guard<std::mutex> lock(mutex_);
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
  ECM rcm = domain_service_.DeleteVar(domain, name);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  std::lock_guard<std::mutex> lock(mutex_);
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
  ECM rcm = domain_service_.DeleteVarAll(name, removed);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  dirty_ = true;
  return Ok();
}

/**
 * @brief Return all variable names deduplicated.
 */
std::vector<std::string> AMVarManager::ListNames() const {
  EnsureLoaded_();
  return domain_service_.ListNames();
}

/**
 * @brief Return current private domain (current host nickname or local).
 */
std::string AMVarManager::CurrentDomain() const {
  std::string nickname = AMStr::Strip(AMClientManager::Instance().CurrentNickname());
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
  return domain_service_.SubstitutePathLike(input, CurrentDomain());
}

/**
 * @brief Replace path-like arguments in place using current-domain variables.
 */
void AMVarManager::SubstitutePathLike(std::vector<std::string> *inputs) const {
  if (!inputs) {
    return;
  }
  EnsureLoaded_();
  domain_service_.SubstitutePathLike(inputs, CurrentDomain());
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
