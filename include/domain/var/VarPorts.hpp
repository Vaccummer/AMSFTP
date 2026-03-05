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
} // namespace AMDomain::var
