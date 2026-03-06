#include "domain/client/ClientManager.hpp"
#include "domain/var/VarManager.hpp"
#include "foundation/host/HostModel.hpp"
#include "foundation/tools/enum_related.hpp"

using EC = ErrorCode;

/**
 * @brief Initialize in-memory variable dictionary from an external map.
 */
ECM AMDomain::var::AMVarManager::Init(DomainDict vars_by_domain) {
  return Reload(std::move(vars_by_domain));
}

/**
 * @brief Reload in-memory dictionary from an external map.
 */
ECM AMDomain::var::AMVarManager::Reload(DomainDict vars_by_domain) {
  ECM apply_rcm = domain_service_.ReplaceAll(std::move(vars_by_domain));
  if (apply_rcm.first != EC::Success) {
    return apply_rcm;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  ready_ = true;
  return Ok();
}

/**
 * @brief Return a const reference to current in-memory variable dictionary.
 */
const AMDomain::var::AMVarManager::DomainDict &
AMDomain::var::AMVarManager::GetVarDict() const {
  EnsureLoaded_();
  return domain_service_.ConstRef();
}

/**
 * @brief Return one variable from a specified domain.
 */
VarInfo AMDomain::var::AMVarManager::GetVar(const std::string &domain,
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
std::vector<VarInfo>
AMDomain::var::AMVarManager::FindByName(const std::string &name) const {
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
AMDomain::var::AMVarManager::ListByDomain(const std::string &domain) const {
  if (!IsValidDomainName_(domain)) {
    return {};
  }
  EnsureLoaded_();
  return domain_service_.ListByDomain(domain);
}

/**
 * @brief List all domain names.
 */
std::vector<std::string> AMDomain::var::AMVarManager::ListDomains() const {
  EnsureLoaded_();
  return domain_service_.ListDomains();
}

/**
 * @brief Return true if one domain exists in the dict.
 */
bool AMDomain::var::AMVarManager::HasDomain(const std::string &domain) const {
  if (!IsValidDomainName_(domain)) {
    return false;
  }
  EnsureLoaded_();
  return domain_service_.HasDomain(domain);
}

/**
 * @brief Return true if one variable exists in a domain.
 */
bool AMDomain::var::AMVarManager::HasVar(const std::string &domain,
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
ECM AMDomain::var::AMVarManager::SetVar(const VarInfo &info,
                                        bool create_domain) {
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
  return domain_service_.SetVar(info, create_domain);
}

/**
 * @brief Delete one variable from target domain.
 */
ECM AMDomain::var::AMVarManager::DeleteVar(const std::string &domain,
                                           const std::string &name) {
  if (!IsValidDomainName_(domain) || !varsetkn::IsValidVarname(name)) {
    return Err(EC::InvalidArg, "invalid domain or variable name");
  }

  EnsureLoaded_();
  return domain_service_.DeleteVar(domain, name);
}

/**
 * @brief Delete one variable from every domain.
 */
ECM AMDomain::var::AMVarManager::DeleteVarAll(const std::string &name,
                                              std::vector<VarInfo> *removed) {
  if (!varsetkn::IsValidVarname(name)) {
    return Err(EC::InvalidArg, "invalid variable name");
  }

  EnsureLoaded_();
  return domain_service_.DeleteVarAll(name, removed);
}

/**
 * @brief Return all variable names deduplicated.
 */
std::vector<std::string> AMDomain::var::AMVarManager::ListNames() const {
  EnsureLoaded_();
  return domain_service_.ListNames();
}

/**
 * @brief Return current private domain (current host nickname or local).
 */
std::string AMDomain::var::AMVarManager::CurrentDomain() const {
  std::string nickname = AMStr::Strip(
      AMDomain::client::AMClientManager::Instance().CurrentNickname());
  if (nickname.empty()) {
    nickname = "local";
  }
  return nickname;
}

/**
 * @brief Replace one path-like argument using current-domain variables.
 */
std::string AMDomain::var::AMVarManager::SubstitutePathLike(
    const std::string &input) const {
  if (input.empty()) {
    return input;
  }
  EnsureLoaded_();
  return domain_service_.SubstitutePathLike(input, CurrentDomain());
}

/**
 * @brief Replace path-like arguments in place using current-domain variables.
 */
void AMDomain::var::AMVarManager::SubstitutePathLike(
    std::vector<std::string> *inputs) const {
  if (!inputs) {
    return;
  }
  EnsureLoaded_();
  domain_service_.SubstitutePathLike(inputs, CurrentDomain());
}

/**
 * @brief Return true for valid domain names.
 */
bool AMDomain::var::AMVarManager::IsValidDomainName_(
    const std::string &domain) const {
  if (domain == varsetkn::kPublic) {
    return true;
  }
  return configkn::ValidateNickname(domain);
}

/**
 * @brief Ensure manager is loaded before access.
 */
void AMDomain::var::AMVarManager::EnsureLoaded_() const {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (ready_) {
      return;
    }
  }
  (void)const_cast<AMDomain::var::AMVarManager *>(this)->Reload(DomainDict{});
}
