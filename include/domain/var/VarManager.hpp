#pragma once
#include "domain/var/VarDomainService.hpp"
#include "foundation/DataClass.hpp"
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace AMDomain::var {
class AMVarManager : private NonCopyableNonMovable {
public:
  using DomainVars = std::unordered_map<std::string, std::string>;
  using DomainDict = std::unordered_map<std::string, DomainVars>;

  /**
   * @brief Initialize in-memory variable dictionary to defaults.
   */
  ECM Init() override { return Init(DomainDict{}); }

  /**
   * @brief Initialize in-memory variable dictionary from an external map.
   */
  ECM Init(DomainDict vars_by_domain);

  /**
   * @brief Reload in-memory dictionary from an external map.
   */
  ECM Reload(DomainDict vars_by_domain);

  /**
   * @brief Return a const reference to current in-memory variable dictionary.
   */
  [[nodiscard]] const DomainDict &GetVarDict() const;

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
   * @brief Return current private domain (current host nickname or local).
   */
  [[nodiscard]] std::string CurrentDomain() const;

  /**
   * @brief Replace one path-like argument using current-domain variables.
   */
  [[nodiscard]] std::string SubstitutePathLike(const std::string &input) const;

  /**
   * @brief Replace path-like arguments in place using current-domain variables.
   */
  void SubstitutePathLike(std::vector<std::string> *inputs) const;

protected:
  /**
   * @brief Construct a variable manager.
   */
  explicit AMVarManager() = default;

  /**
   * @brief Return true for valid domain names.
   */
  [[nodiscard]] bool IsValidDomainName_(const std::string &domain) const;

  /**
   * @brief Ensure manager is loaded before access.
   */
  void EnsureLoaded_() const;

  VarDomainService domain_service_;
  mutable std::mutex mutex_;
  mutable bool ready_ = false;
};

/**
 * @brief CLI helper built on AMVarManager.
 */
class VarCLISet : public AMVarManager {
public:
  /**
   * @brief Return singleton CLI helper.
   */
  static VarCLISet &Instance() {
    static VarCLISet instance;
    return instance;
  }

  /**
   * @brief Handle `var get $name`.
   */
  ECM QueryByName(const std::string &token_name) const;

  /**
   * @brief Handle `var def [-g] $name value`.
   */
  ECM DefineVar(bool global, const std::string &token_name,
                const std::string &value);

  /**
   * @brief Handle `var del [-a] [domain] $name`.
   */
  ECM DeleteVarByCli(bool all, const std::string &domain,
                     const std::string &token_name);

  /**
   * @brief Handle `var ls [domain ...]`.
   */
  ECM ListVars(const std::vector<std::string> &domains) const;

private:
  /**
   * @brief Construct CLI helper.
   */
  VarCLISet() = default;

  /**
   * @brief Format variable output style.
   */
  [[nodiscard]] std::string FormatVarText_(const std::string &text) const;

  /**
   * @brief Format output value with empty-string rule.
   */
  [[nodiscard]] std::string RenderValue_(const std::string &value) const;

  /**
   * @brief Print one section with aligned `$name` column.
   */
  void PrintSection_(const std::string &domain,
                     const std::vector<VarInfo> &entries) const;
};
} // namespace AMDomain::var
