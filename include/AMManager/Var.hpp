#pragma once
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <cctype>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace varsetkn {
inline constexpr const char *kRoot = "UserVars";
inline constexpr const char *kPublic = "*";
inline bool IsValidVarname(std::string_view varname) {
  if (varname.empty())
    return false;
  for (const auto &ch : varname) {
    if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_') {
      continue;
    }
    return false;
  }
  return true;
}

/**
 * @brief Return true when one zone/domain name is syntactically valid.
 *
 * Domain naming follows host nickname constraints: `[A-Za-z0-9_-]+`.
 */
inline bool IsValidZoneName(std::string_view zone_name) {
  if (zone_name.empty()) {
    return false;
  }
  for (const auto &ch : zone_name) {
    if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' ||
        ch == '-') {
      continue;
    }
    return false;
  }
  return true;
}

/**
 * @brief Parsed variable reference descriptor.
 *
 * Supported forms:
 * - `$var`
 * - `${var}`
 * - `$zone:var`
 * - `${zone:var}`
 * - `$:var` / `${:var}` (public-zone shorthand)
 */
struct VarRef {
  bool valid = false;
  bool braced = false;
  bool has_closing_brace = false;
  bool explicit_domain = false;
  std::string domain = "";
  std::string zone_token = "";
  std::string varname = "";
};

/**
 * @brief Build canonical variable token text from parsed fields.
 *
 * @param ref Parsed variable reference.
 * @param close_brace Whether to append `}` for braced output.
 * @return Canonical token text.
 */
inline std::string BuildVarToken(const VarRef &ref, bool close_brace = true) {
  std::string inner;
  if (ref.explicit_domain) {
    inner.append(ref.zone_token);
    inner.push_back(':');
  }
  inner.append(ref.varname);

  if (ref.braced) {
    return close_brace ? ("${" + inner + "}") : ("${" + inner);
  }
  return "$" + inner;
}

/**
 * @brief Parse a variable-expression payload without leading `$`/`${`.
 *
 * @param expr Expression body.
 * @param allow_empty_varname Whether empty varname is accepted.
 * @param out_ref Parsed output.
 * @return True when parsing succeeds.
 */
inline bool ParseVarRefExpr(std::string_view expr, bool allow_empty_varname,
                            VarRef *out_ref) {
  if (!out_ref) {
    return false;
  }

  VarRef out{};
  const size_t colon = expr.find(':');
  if (colon == std::string_view::npos) {
    if (expr.empty() && !allow_empty_varname) {
      return false;
    }
    if (!expr.empty() && !IsValidVarname(expr)) {
      return false;
    }
    out.varname = std::string(expr);
    out.valid = true;
    *out_ref = std::move(out);
    return true;
  }

  const std::string_view zone = expr.substr(0, colon);
  const std::string_view var = expr.substr(colon + 1);
  out.explicit_domain = true;
  out.zone_token = std::string(zone);
  if (zone.empty()) {
    out.domain = kPublic;
  } else {
    if (!IsValidZoneName(zone)) {
      return false;
    }
    out.domain = std::string(zone);
  }

  if (var.empty() && !allow_empty_varname) {
    return false;
  }
  if (!var.empty() && !IsValidVarname(var)) {
    return false;
  }
  out.varname = std::string(var);
  out.valid = true;
  *out_ref = std::move(out);
  return true;
}

/**
 * @brief Return true when one byte can appear in zone-name segments.
 */
inline bool IsZoneNameChar(char c) {
  const unsigned char ch = static_cast<unsigned char>(c);
  return std::isalnum(ch) || c == '_' || c == '-';
}

/**
 * @brief Return true when one byte can appear in variable-name segments.
 */
inline bool IsVarNameChar(char c) {
  const unsigned char ch = static_cast<unsigned char>(c);
  return std::isalnum(ch) || c == '_';
}

/**
 * @brief Parse one variable reference from a string slice.
 *
 * @param text Full input text.
 * @param pos Start position of `$`.
 * @param limit Exclusive parsing limit.
 * @param allow_incomplete_brace Accept `${...` without a closing `}`.
 * @param allow_empty_varname Accept empty variable name for prefix parsing.
 * @param out_end Optional output end position (exclusive).
 * @param out_ref Optional parsed output.
 * @return True when parsing succeeds.
 */
inline bool ParseVarRefAt(const std::string &text, size_t pos, size_t limit,
                          bool allow_incomplete_brace, bool allow_empty_varname,
                          size_t *out_end, VarRef *out_ref) {
  if (pos >= text.size() || pos >= limit || text[pos] != '$') {
    return false;
  }
  if (pos + 1 >= limit || pos + 1 >= text.size()) {
    return false;
  }

  VarRef parsed{};
  if (text[pos + 1] == '{') {
    parsed.braced = true;
    const size_t close = text.find('}', pos + 2);
    if (close == std::string::npos || close >= limit) {
      if (!allow_incomplete_brace) {
        return false;
      }
      const std::string_view inner(text.data() + pos + 2, limit - (pos + 2));
      if (!ParseVarRefExpr(inner, allow_empty_varname, &parsed)) {
        return false;
      }
      parsed.braced = true;
      parsed.has_closing_brace = false;
      parsed.valid = true;
      if (out_end) {
        *out_end = limit;
      }
      if (out_ref) {
        *out_ref = std::move(parsed);
      }
      return true;
    }

    const std::string_view inner(text.data() + pos + 2, close - (pos + 2));
    if (!ParseVarRefExpr(inner, allow_empty_varname, &parsed)) {
      return false;
    }
    parsed.braced = true;
    parsed.has_closing_brace = true;
    parsed.valid = true;
    if (out_end) {
      *out_end = close + 1;
    }
    if (out_ref) {
      *out_ref = std::move(parsed);
    }
    return true;
  }

  const size_t start = pos + 1;
  if (start >= limit || start >= text.size()) {
    return false;
  }

  if (text[start] == ':') {
    size_t var_end = start + 1;
    while (var_end < limit && var_end < text.size() &&
           IsVarNameChar(text[var_end])) {
      ++var_end;
    }
    const size_t expr_len = var_end - start;
    const std::string_view inner(text.data() + start, expr_len);
    if (!ParseVarRefExpr(inner, allow_empty_varname, &parsed)) {
      return false;
    }
    parsed.braced = false;
    parsed.has_closing_brace = false;
    parsed.valid = true;
    if (out_end) {
      *out_end = var_end;
    }
    if (out_ref) {
      *out_ref = std::move(parsed);
    }
    return true;
  }

  size_t seg_end = start;
  while (seg_end < limit && seg_end < text.size() && IsZoneNameChar(text[seg_end])) {
    ++seg_end;
  }
  if (seg_end == start) {
    return false;
  }

  if (seg_end < limit && seg_end < text.size() && text[seg_end] == ':') {
    size_t var_end = seg_end + 1;
    while (var_end < limit && var_end < text.size() &&
           IsVarNameChar(text[var_end])) {
      ++var_end;
    }
    const std::string_view inner(text.data() + start, var_end - start);
    if (!ParseVarRefExpr(inner, allow_empty_varname, &parsed)) {
      return false;
    }
    parsed.braced = false;
    parsed.has_closing_brace = false;
    parsed.valid = true;
    if (out_end) {
      *out_end = var_end;
    }
    if (out_ref) {
      *out_ref = std::move(parsed);
    }
    return true;
  }

  size_t var_end = start;
  while (var_end < limit && var_end < text.size() && IsVarNameChar(text[var_end])) {
    ++var_end;
  }
  const std::string_view inner(text.data() + start, var_end - start);
  if (!ParseVarRefExpr(inner, allow_empty_varname, &parsed)) {
    return false;
  }
  parsed.braced = false;
  parsed.has_closing_brace = false;
  parsed.valid = true;
  if (out_end) {
    *out_end = var_end;
  }
  if (out_ref) {
    *out_ref = std::move(parsed);
  }
  return true;
}

/**
 * @brief Parse one complete variable token.
 *
 * @param token Full token text.
 * @param out_ref Optional parsed output.
 * @return True when token is a valid complete var token.
 */
inline bool ParseVarToken(const std::string &token, VarRef *out_ref = nullptr) {
  if (token.empty()) {
    return false;
  }
  size_t end = 0;
  VarRef parsed{};
  if (!ParseVarRefAt(token, 0, token.size(), false, false, &end, &parsed)) {
    return false;
  }
  if (end != token.size()) {
    return false;
  }
  if (out_ref) {
    *out_ref = std::move(parsed);
  }
  return true;
}
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

class AMVarManager : private NonCopyableNonMovable {
public:
  using DomainVars = std::unordered_map<std::string, std::string>;
  using DomainDict = std::unordered_map<std::string, DomainVars>;

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
