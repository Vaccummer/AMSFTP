#pragma once
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace varsetkn {
inline constexpr const char *kRoot = "UserVars";
inline constexpr const char *kPublic = "*";
} // namespace varsetkn

/**
 * @brief Single variable record identified by domain + var name.
 */
struct VarInfo {
  std::string domain = "";
  std::string varname = "";
  std::string varvalue = "";

  /**
   * @brief Return true when this variable belongs to public domain.
   */
  [[nodiscard]] bool IsPublic() const { return domain == varsetkn::kPublic; }

  /**
   * @brief Validate whether this VarInfo is initialized and usable.
   */
  [[nodiscard]] ECM IsValid() const {
    if (domain.empty() || varname.empty()) {
      return Err(EC::InvalidArg, "uninitialized VarInfo");
    }
    return Ok();
  }
};

class VarCLISet;

class AMVarManager : private NonCopyableNonMovable {
public:
  enum class VarSource { Public, Private };
  using DomainVars = std::unordered_map<std::string, std::string>;
  using DomainDict = std::unordered_map<std::string, DomainVars>;

  /**
   * @brief Return the singleton variable manager.
   */
  static AMVarManager &Instance();

  /**
   * @brief Initialize in-memory variable dict from ConfigManager.
   */
  ECM Init() override { return Reload(); }

  /**
   * @brief Reload [UserVars] from ConfigManager into domain dict.
   */
  ECM Reload();

  /**
   * @brief Persist variable dict to settings json and settings.toml.
   */
  ECM Save(bool async = true);

  /**
   * @brief Resolve variable by current scope (private first, then public).
   */
  bool Resolve(const std::string &name, std::string *value = nullptr,
               VarSource *source = nullptr) const;

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
   * @brief Legacy wrapper: set public variable.
   */
  ECM SetPersistentVar(const std::string &name, const std::string &value,
                       bool confirm_overwrite = true);

  /**
   * @brief Legacy wrapper: set current private variable.
   */
  ECM SetMemoryVar(const std::string &name, const std::string &value,
                   bool confirm_overwrite = true);

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
   * @brief Return true for valid variable names.
   */
  [[nodiscard]] bool IsValidVarName_(const std::string &name) const;

  /**
   * @brief Ensure manager is loaded before access.
   */
  void EnsureLoaded_() const;

  AMConfigManager &config_manager_ = AMConfigManager::Instance();
  AMPromptManager &prompt_manager_ = AMPromptManager::Instance();
  AMClientManager &client_manager_ = AMClientManager::Instance();
  mutable std::mutex mutex_;
  mutable bool ready_ = false;
  bool dirty_ = false;
  DomainDict vars_by_domain_ = {};
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
   * @brief Parse `$name` token into raw variable name.
   */
  static ECM ParseVarToken_(const std::string &token, std::string *name);

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
