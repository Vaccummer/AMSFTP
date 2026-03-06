#pragma once
#include "foundation/var/VarModel.hpp"
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace AMDomain::var {
/**
 * @brief Pure domain service for variable lookup and substitution.
 *
 * This service intentionally has no dependency on config persistence,
 * CLI rendering, or global singletons.
 */
class VarDomainService {
public:
  using DomainVars = std::unordered_map<std::string, std::string>;
  using DomainDict = std::unordered_map<std::string, DomainVars>;

  /**
   * @brief Replace the whole in-memory variable dictionary.
   */
  ECM ReplaceAll(DomainDict vars_by_domain);

  /**
   * @brief Return a full snapshot of current variable dictionary.
   */
  [[nodiscard]] DomainDict Snapshot() const;

  /**
   * @brief Return an internal const reference of current variable dictionary.
   *
   * This accessor is intentionally non-copying. Callers must ensure no
   * concurrent mutation happens while holding the returned reference.
   */
  [[nodiscard]] const DomainDict &ConstRef() const;

  /**
   * @brief Return one variable from a specified domain.
   */
  [[nodiscard]] VarInfo GetVar(const std::string &domain,
                               const std::string &name) const;

  /**
   * @brief Find all variables with the given name across all domains.
   */
  [[nodiscard]] std::vector<VarInfo> FindByName(const std::string &name) const;

  /**
   * @brief List variables under one domain.
   */
  [[nodiscard]] std::vector<VarInfo>
  ListByDomain(const std::string &domain) const;

  /**
   * @brief List all domain names.
   */
  [[nodiscard]] std::vector<std::string> ListDomains() const;

  /**
   * @brief Return true if one domain exists in the dict.
   */
  [[nodiscard]] bool HasDomain(const std::string &domain) const;

  /**
   * @brief Return true if one variable exists in a domain.
   */
  [[nodiscard]] bool HasVar(const std::string &domain,
                            const std::string &name) const;

  /**
   * @brief Upsert one variable into a target domain.
   */
  ECM SetVar(const VarInfo &info, bool create_domain = true);

  /**
   * @brief Delete one variable from target domain.
   */
  ECM DeleteVar(const std::string &domain, const std::string &name);

  /**
   * @brief Delete one variable from every domain.
   */
  ECM DeleteVarAll(const std::string &name, std::vector<VarInfo> *removed);

  /**
   * @brief Return all variable names deduplicated.
   */
  [[nodiscard]] std::vector<std::string> ListNames() const;

  /**
   * @brief Replace one path-like argument using provided current domain.
   */
  [[nodiscard]] std::string
  SubstitutePathLike(const std::string &input,
                     const std::string &current_domain) const;

  /**
   * @brief Replace path-like arguments in place using current-domain variables.
   */
  void SubstitutePathLike(std::vector<std::string> *inputs,
                          const std::string &current_domain) const;

private:
  /**
   * @brief Return true for valid domain names.
   */
  [[nodiscard]] bool IsValidDomainName_(const std::string &domain) const;

  mutable std::mutex mutex_;
  DomainDict vars_by_domain_ = {{varsetkn::kPublic, DomainVars{}}};
};
} // namespace AMDomain::var
