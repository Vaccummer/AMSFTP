#pragma once

#include "domain/var/VarDomainService.hpp"
#include "domain/var/VarPorts.hpp"
#include "foundation/core/DataClass.hpp"
#include <string>
#include <vector>

namespace AMApplication::VarWorkflow {
/**
 * @brief Repository-backed var application service.
 */
class VarAppService final : public AMDomain::var::IVarQueryPort,
                            public AMDomain::var::IVarSubstitutionPort,
                            private NonCopyableNonMovable {
public:
  /**
   * @brief Construct service from persistence and current-domain ports.
   */
  VarAppService(
      AMDomain::var::IVarRepository &repository,
      const AMDomain::var::ICurrentDomainProvider &current_domain_provider);

  /**
   * @brief Load variable state from repository into memory.
   */
  ECM LoadVars();

  /**
   * @brief Save current variable state into repository storage.
   */
  ECM SaveVars(bool async = true) const;

  /**
   * @brief Return the current domain-aware lookup result for one variable
   * token.
   */
  [[nodiscard]] AMDomain::var::VarInfo
  ResolveToken(const std::string &token_name, ECM *error = nullptr) const;

  /**
   * @brief Return the explicit-domain target for one define request.
   */
  [[nodiscard]] ECM ResolveDefineTarget(
      bool global, const std::string &token_name,
      AMDomain::var::VarInfo *target) const;

  /**
   * @brief Define or update one variable and keep it in memory.
   */
  ECM DefineVar(const AMDomain::var::VarInfo &info);

  /**
   * @brief Delete one variable in a specific domain.
   */
  ECM DeleteVar(const std::string &domain, const std::string &name);

  /**
   * @brief Delete one variable from every domain.
   */
  ECM DeleteVarAll(const std::string &name,
                   std::vector<AMDomain::var::VarInfo> *removed);

  /**
   * @brief Find one variable name across all domains.
   */
  [[nodiscard]] std::vector<AMDomain::var::VarInfo>
  FindByName(const std::string &name) const;

  /**
   * @brief Return true when one variable domain exists.
   */
  [[nodiscard]] bool HasDomain(const std::string &domain) const override;

  /**
   * @brief Return all available variable domains.
   */
  [[nodiscard]] std::vector<std::string> ListDomains() const override;

  /**
   * @brief Return variables in one domain.
   */
  [[nodiscard]] std::vector<AMDomain::var::VarInfo>
  ListByDomain(const std::string &domain) const override;

  /**
   * @brief Return the current resolved variable domain.
   */
  [[nodiscard]] std::string CurrentDomain() const override;

  /**
   * @brief Query one variable value by domain/name.
   */
  [[nodiscard]] AMDomain::var::VarInfo
  GetVar(const std::string &domain, const std::string &name) const override;

  /**
   * @brief Substitute one path-like token using current-domain policy.
   */
  [[nodiscard]] std::string
  SubstitutePathLike(const std::string &raw) const override;

  /**
   * @brief Substitute path-like tokens in a vector using current-domain policy.
   */
  [[nodiscard]] std::vector<std::string>
  SubstitutePathLike(const std::vector<std::string> &raw) const override;

  /**
   * @brief Parse one full variable token.
   */
  [[nodiscard]] ECM ParseVarToken_(const std::string &token_name,
                                   AMDomain::var::VarRef *ref) const;

private:
  AMDomain::var::IVarRepository &repository_;
  const AMDomain::var::ICurrentDomainProvider &current_domain_provider_;
  AMDomain::var::VarDomainService domain_service_;
};
} // namespace AMApplication::VarWorkflow

