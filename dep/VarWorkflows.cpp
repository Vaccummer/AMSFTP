#include "application/var/VarWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::VarWorkflow {
namespace {
using EC = ErrorCode;
using VarInfo = AMDomain::var::VarInfo;
using VarRef = AMDomain::var::VarRef;
using DomainDict = AMDomain::var::VarDomainService::DomainDict;
} // namespace

/**
 * @brief Construct service from persistence and current-domain ports.
 */
VarAppService::VarAppService(
    AMDomain::var::IVarRepository &repository,
    const AMDomain::var::ICurrentDomainProvider &current_domain_provider)
    : repository_(repository),
      current_domain_provider_(current_domain_provider),
      domain_service_() {}

/**
 * @brief Load variable state from repository into memory.
 */
ECM VarAppService::LoadVars() {
  DomainDict vars_by_domain = {};
  ECM rcm = repository_.Load(&vars_by_domain);
  if (!isok(rcm)) {
    return rcm;
  }
  return domain_service_.ReplaceAll(std::move(vars_by_domain));
}

/**
 * @brief Save current variable state into repository storage.
 */
ECM VarAppService::SaveVars(bool async) const {
  return repository_.Save(domain_service_.ConstRef(), async);
}

/**
 * @brief Return the current domain-aware lookup result for one variable token.
 */
VarInfo VarAppService::ResolveToken(const std::string &token_name,
                                    ECM *error) const {
  if (error) {
    *error = Ok();
  }

  VarRef ref{};
  ECM parsed = ParseVarToken_(token_name, &ref);
  if (!isok(parsed)) {
    if (error) {
      *error = parsed;
    }
    return {};
  }

  if (ref.explicit_domain) {
    VarInfo found = domain_service_.GetVar(ref.domain, ref.varname);
    if (found.IsValid().first == EC::Success) {
      return found;
    }
    if (error) {
      *error = Err(EC::InvalidArg,
                   AMStr::fmt("variable not found: {}",
                              AMDomain::var::BuildVarToken(ref)));
    }
    return {};
  }

  VarInfo found = domain_service_.GetVar(CurrentDomain(), ref.varname);
  if (found.IsValid().first != EC::Success) {
    found = domain_service_.GetVar(AMDomain::var::kPublic,
                                   ref.varname);
  }
  if (found.IsValid().first == EC::Success) {
    return found;
  }

  if (error) {
    *error = Err(EC::InvalidArg,
                 AMStr::fmt("variable not found: {}",
                            AMDomain::var::BuildVarToken(ref)));
  }
  return {};
}

/**
 * @brief Return the explicit-domain target for one define request.
 */
ECM VarAppService::ResolveDefineTarget(bool global,
                                       const std::string &token_name,
                                       VarInfo *target) const {
  if (!target) {
    return Err(EC::InvalidArg, "null target output");
  }

  VarRef ref{};
  ECM parsed = ParseVarToken_(token_name, &ref);
  if (!isok(parsed)) {
    return parsed;
  }
  if (global && ref.explicit_domain) {
    return Err(EC::InvalidArg, "cannot use --global with explicit zone token");
  }

  target->domain = ref.explicit_domain
                       ? ref.domain
                       : (global
                              ? std::string(AMDomain::var::kPublic)
                              : CurrentDomain());
  target->varname = ref.varname;
  target->varvalue.clear();
  return Ok();
}

/**
 * @brief Define or update one variable and keep it in memory.
 */
ECM VarAppService::DefineVar(const VarInfo &info) {
  return domain_service_.SetVar(info, true);
}

/**
 * @brief Delete one variable in a specific domain.
 */
ECM VarAppService::DeleteVar(const std::string &domain,
                             const std::string &name) {
  return domain_service_.DeleteVar(domain, name);
}

/**
 * @brief Delete one variable from every domain.
 */
ECM VarAppService::DeleteVarAll(const std::string &name,
                                std::vector<VarInfo> *removed) {
  return domain_service_.DeleteVarAll(name, removed);
}

/**
 * @brief Find one variable name across all domains.
 */
std::vector<VarInfo> VarAppService::FindByName(const std::string &name) const {
  return domain_service_.FindByName(name);
}

/**
 * @brief Return true when one variable domain exists.
 */
bool VarAppService::HasDomain(const std::string &domain) const {
  return domain_service_.HasDomain(domain);
}

/**
 * @brief Return all available variable domains.
 */
std::vector<std::string> VarAppService::ListDomains() const {
  return domain_service_.ListDomains();
}

/**
 * @brief Return variables in one domain.
 */
std::vector<VarInfo> VarAppService::ListByDomain(const std::string &domain) const {
  return domain_service_.ListByDomain(domain);
}

/**
 * @brief Return the current resolved variable domain.
 */
std::string VarAppService::CurrentDomain() const {
  std::string domain = AMStr::Strip(current_domain_provider_.CurrentDomain());
  if (domain.empty()) {
    domain = "local";
  }
  return domain;
}

/**
 * @brief Query one variable value by domain/name.
 */
VarInfo VarAppService::GetVar(const std::string &domain,
                              const std::string &name) const {
  return domain_service_.GetVar(domain, name);
}

/**
 * @brief Substitute one path-like token using current-domain policy.
 */
std::string VarAppService::SubstitutePathLike(const std::string &raw) const {
  return domain_service_.SubstitutePathLike(raw, CurrentDomain());
}

/**
 * @brief Substitute path-like tokens in a vector using current-domain policy.
 */
std::vector<std::string>
VarAppService::SubstitutePathLike(const std::vector<std::string> &raw) const {
  std::vector<std::string> out = raw;
  domain_service_.SubstitutePathLike(&out, CurrentDomain());
  return out;
}

/**
 * @brief Parse one full variable token.
 */
ECM VarAppService::ParseVarToken_(const std::string &token_name,
                                  VarRef *ref) const {
  if (!ref) {
    return Err(EC::InvalidArg, "null output variable");
  }
  const std::string trimmed = AMStr::Strip(token_name);
  if (trimmed.empty()) {
    return Err(EC::InvalidArg, "empty variable token");
  }

  VarRef parsed{};
  if (!AMDomain::var::ParseVarToken(trimmed, &parsed) ||
      !parsed.valid) {
    return Err(EC::InvalidArg, "invalid variable token");
  }
  if (parsed.varname.empty()) {
    return Err(EC::InvalidArg, "empty variable name");
  }
  *ref = std::move(parsed);
  return Ok();
}
} // namespace AMApplication::VarWorkflow

