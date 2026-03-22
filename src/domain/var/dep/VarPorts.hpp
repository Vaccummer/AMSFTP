#pragma once
#include "domain/var/VarDomainService.hpp"

namespace AMDomain::var {
/**
 * @brief Port for variable persistence adapters.
 */
class IVarRepository {
public:
  virtual ~IVarRepository() = default;

  /**
   * @brief Load complete variable dictionary from adapter storage.
   */
  virtual ECM Load(VarDomainService::DomainDict *out_vars) = 0;

  /**
   * @brief Save complete variable dictionary to adapter storage.
   */
  virtual ECM Save(const VarDomainService::DomainDict &vars,
                   bool async = true) = 0;
};

/**
 * @brief Port that exposes current logical variable domain.
 */
class ICurrentDomainProvider {
public:
  virtual ~ICurrentDomainProvider() = default;

  /**
   * @brief Resolve current runtime domain identifier.
   */
  [[nodiscard]] virtual std::string CurrentDomain() const = 0;
};

/**
 * @brief Read-only port for resolved variable state queries.
 */
class IVarQueryPort {
public:
  virtual ~IVarQueryPort() = default;

  /**
   * @brief Return true when one variable domain exists.
   */
  [[nodiscard]] virtual bool HasDomain(const std::string &domain) const = 0;

  /**
   * @brief Return all available variable domains.
   */
  [[nodiscard]] virtual std::vector<std::string> ListDomains() const = 0;

  /**
   * @brief Return all variables under one domain.
   */
  [[nodiscard]] virtual std::vector<VarInfo>
  ListByDomain(const std::string &domain) const = 0;

  /**
   * @brief Return one variable value by domain/name.
   */
  [[nodiscard]] virtual VarInfo GetVar(const std::string &domain,
                                       const std::string &name) const = 0;

  /**
   * @brief Return the currently resolved variable domain.
   */
  [[nodiscard]] virtual std::string CurrentDomain() const = 0;
};

/**
 * @brief Port for path-like variable substitution.
 */
class IVarSubstitutionPort {
public:
  virtual ~IVarSubstitutionPort() = default;

  /**
   * @brief Substitute one path-like token using the current domain policy.
   */
  [[nodiscard]] virtual std::string
  SubstitutePathLike(const std::string &raw) const = 0;

  /**
   * @brief Substitute a path-like token list using the current domain policy.
   */
  [[nodiscard]] virtual std::vector<std::string>
  SubstitutePathLike(const std::vector<std::string> &raw) const = 0;
};
} // namespace AMDomain::var
