#include "interface/adapters/var/VarInterfaceService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "foundation/tools/string.hpp"

namespace AMInterface::var {
namespace {
enum class ShortcutVarKind { None, GetVar, ListAll, ListDomain };

bool ParseShortcutVarToken_(const std::string &token, ShortcutVarKind *out_kind,
                            std::string *out_var_token,
                            std::string *out_domain) {
  if (!out_kind || !out_var_token || !out_domain) {
    return false;
  }
  *out_kind = ShortcutVarKind::None;
  out_var_token->clear();
  out_domain->clear();

  const std::string trimmed = AMStr::Strip(token);
  if (trimmed.empty()) {
    return false;
  }
  if (trimmed.size() >= 2 && trimmed[0] == '`' && trimmed[1] == '$') {
    return false;
  }
  if (trimmed == "$") {
    *out_kind = ShortcutVarKind::ListAll;
    return true;
  }
  if (trimmed.front() != '$') {
    return false;
  }

  size_t end = 0;
  AMDomain::var::VarRef ref = {};
  if (!AMDomain::var::ParseVarRefAt(trimmed, 0, trimmed.size(), false, true,
                                    &end, &ref) ||
      !ref.valid || end != trimmed.size()) {
    return false;
  }

  if (ref.varname.empty()) {
    if (!ref.explicit_domain) {
      return false;
    }
    *out_kind = ShortcutVarKind::ListDomain;
    *out_domain = ref.domain;
    return true;
  }

  *out_kind = ShortcutVarKind::GetVar;
  *out_var_token = AMDomain::var::BuildVarToken(ref);
  return true;
}

std::string JoinTokens_(const std::vector<std::string> &tokens, size_t begin) {
  if (begin >= tokens.size()) {
    return "";
  }
  std::string out = {};
  for (size_t i = begin; i < tokens.size(); ++i) {
    if (!out.empty()) {
      out.push_back(' ');
    }
    out.append(tokens[i]);
  }
  return out;
}

std::string JoinValueWithTail_(const std::string &first_segment,
                               const std::vector<std::string> &tokens,
                               size_t begin) {
  std::string out = first_segment;
  if (begin >= tokens.size()) {
    return out;
  }
  const std::string tail = JoinTokens_(tokens, begin);
  if (tail.empty()) {
    return out;
  }
  if (!out.empty()) {
    out.push_back(' ');
  }
  out.append(tail);
  return out;
}
} // namespace

VarInterfaceService::VarInterfaceService(VarAppService &var_service,
                                         ClientAppService &client_service,
                                         PromptIOManager &prompt_io_manager)
    : var_service_(var_service), client_service_(client_service),
      prompt_io_manager_(prompt_io_manager) {}

ECMData<ParsedVarToken>
VarInterfaceService::ParseVarTokenExpression(const std::string &expr) const {
  const std::string trimmed = AMStr::Strip(expr);
  if (trimmed.empty()) {
    return {{}, Err(EC::InvalidArg, "", "", "variable token is empty")};
  }

  size_t end = 0;
  ParsedVarToken parsed = {};
  if (!AMDomain::var::ParseVarRefAt(trimmed, 0, trimmed.size(), false, false,
                                    &end, &parsed) ||
      end != trimmed.size() || !parsed.valid || parsed.varname.empty()) {
    return {{}, Err(EC::InvalidArg, "", "", "invalid variable token")};
  }
  return {parsed, OK};
}

std::string VarInterfaceService::ResolveCurrentDomain_() const {
  std::string current = AMStr::Strip(client_service_.CurrentNickname());
  if (current.empty()) {
    current = "local";
  }
  return current;
}

ECMData<VarInfo>
VarInterfaceService::ResolveLookupToken(const std::string &token_expr) const {
  auto parsed = ParseVarTokenExpression(token_expr);
  if (!(parsed.rcm)) {
    return {{}, parsed.rcm};
  }

  if (parsed.data.explicit_domain) {
    const auto all_vars = var_service_.GetAllVar();
    if (!(all_vars.rcm)) {
      return {{}, all_vars.rcm};
    }
    const auto zone_it = all_vars.data.find(parsed.data.domain);
    if (zone_it == all_vars.data.end()) {
      return {{},
              Err(EC::InvalidArg, "", "", "target variable zone not found")};
    }
    const auto var_it = zone_it->second.find(parsed.data.varname);
    if (var_it == zone_it->second.end()) {
      return {{},
              Err(EC::InvalidArg, "", "", "variable not found in target zone")};
    }
    return {var_it->second, OK};
  }

  return var_service_.GetVar(ResolveCurrentDomain_(), parsed.data.varname);
}

ECMData<VarInfo>
VarInterfaceService::ResolveDefineTarget(bool global,
                                         const std::string &token_expr) const {
  auto parsed = ParseVarTokenExpression(token_expr);
  if (!(parsed.rcm)) {
    return {{}, parsed.rcm};
  }
  if (global && parsed.data.explicit_domain) {
    return {{},
            Err(EC::InvalidArg, "", "",
                "cannot combine --global with explicit zone")};
  }

  VarInfo target = {};
  target.domain = parsed.data.explicit_domain
                      ? parsed.data.domain
                      : (global ? std::string(AMDomain::var::kPublic)
                                : ResolveCurrentDomain_());
  target.varname = parsed.data.varname;
  target.varvalue = "";
  return {target, OK};
}

ECM VarInterfaceService::QueryAndPrintVar(const std::string &token_expr) const {
  auto info = ResolveLookupToken(token_expr);
  if (!(info.rcm)) {
    return info.rcm;
  }
  prompt_io_manager_.FmtPrint("[{}] ${} = {}", info.data.domain,
                              info.data.varname, info.data.varvalue);
  return OK;
}

ECM VarInterfaceService::DefineVar(bool global, const std::string &token_expr,
                                   const std::string &value) const {
  auto target = ResolveDefineTarget(global, token_expr);
  if (!(target.rcm)) {
    return target.rcm;
  }
  target.data.varvalue = value;
  return var_service_.AddVar(target.data);
}

ECM VarInterfaceService::DeleteVar(
    bool all, const std::vector<std::string> &tokens) const {
  if (tokens.empty() || tokens.size() > 2) {
    return Err(EC::InvalidArg, "", "",
               "var del requires one var token or [zone token]");
  }

  std::string zone_override = {};
  std::string token_expr = tokens.front();
  if (tokens.size() == 2) {
    zone_override = AMStr::Strip(tokens.front());
    token_expr = tokens.back();
  }

  auto parsed = ParseVarTokenExpression(token_expr);
  if (!(parsed.rcm)) {
    return parsed.rcm;
  }

  if (all) {
    auto all_vars = var_service_.GetAllVar();
    if (!(all_vars.rcm)) {
      return all_vars.rcm;
    }
    ECM last = OK;
    bool removed_any = false;
    for (const auto &[zone_name, zone_vars] : all_vars.data) {
      if (!zone_vars.contains(parsed.data.varname)) {
        continue;
      }
      ECM del_rcm = var_service_.DelVar(zone_name, parsed.data.varname);
      if (!(del_rcm)) {
        last = del_rcm;
        continue;
      }
      removed_any = true;
    }
    if (!removed_any) {
      return Err(EC::InvalidArg, "", "", "variable not found");
    }
    return last;
  }

  std::string resolved_zone = {};
  if (!zone_override.empty()) {
    resolved_zone = zone_override;
  } else if (parsed.data.explicit_domain) {
    resolved_zone = parsed.data.domain;
  } else {
    resolved_zone = AMStr::Strip(client_service_.CurrentNickname());
    if (resolved_zone.empty()) {
      resolved_zone = "local";
    }
  }
  return var_service_.DelVar(resolved_zone, parsed.data.varname);
}

ECM VarInterfaceService::ListVars(
    const std::vector<std::string> &sections) const {
  const auto print_zone =
      [this](const std::string &zone_name,
             const AMApplication::var::ZoneVarInfoMap &zone_vars) {
        prompt_io_manager_.FmtPrint("\\[{}]", zone_name);
        for (const auto &[name, info] : zone_vars) {
          (void)name;
          prompt_io_manager_.FmtPrint("${} = {}", info.varname, info.varvalue);
        }
      };

  if (sections.empty()) {
    auto all_vars = var_service_.GetAllVar();
    if (!(all_vars.rcm)) {
      return all_vars.rcm;
    }
    for (const auto &[zone_name, zone_vars] : all_vars.data) {
      print_zone(zone_name, zone_vars);
    }
    return OK;
  }

  ECM last = OK;
  for (const std::string &zone : sections) {
    auto zone_vars = var_service_.EnumerateZone(zone);
    if (!(zone_vars.rcm)) {
      last = zone_vars.rcm;
      continue;
    }
    print_zone(zone, zone_vars.data);
  }
  return last;
}

ECMData<std::string>
VarInterfaceService::LookupVarValue_(const ParsedVarToken &token,
                                     const AllVarInfoMap &all_vars) const {
  auto lookup_zone =
      [&](const std::string &zone) -> std::optional<std::string> {
    const auto zone_it = all_vars.find(zone);
    if (zone_it == all_vars.end()) {
      return std::nullopt;
    }
    const auto var_it = zone_it->second.find(token.varname);
    if (var_it == zone_it->second.end()) {
      return std::nullopt;
    }
    return var_it->second.varvalue;
  };

  if (token.explicit_domain) {
    auto explicit_value = lookup_zone(token.domain);
    if (!explicit_value.has_value()) {
      return {"", Err(EC::InvalidArg, "", "", "variable not found")};
    }
    return {explicit_value.value(), OK};
  }

  auto current_value = lookup_zone(ResolveCurrentDomain_());
  if (current_value.has_value()) {
    return {current_value.value(), OK};
  }
  return {"", Err(EC::InvalidArg, "", "", "variable not found")};
}

std::string VarInterfaceService::SubstitutePathLikeWithSnapshot_(
    const std::string &raw, const AllVarInfoMap &all_vars) const {
  if (raw.empty()) {
    return raw;
  }

  std::string out = {};
  out.reserve(raw.size());
  for (size_t i = 0; i < raw.size(); ++i) {
    const char ch = raw[i];
    if (ch == '`' && i + 1 < raw.size() && raw[i + 1] == '$') {
      out.push_back('$');
      ++i;
      continue;
    }
    if (ch != '$') {
      out.push_back(ch);
      continue;
    }
    if (i + 1 >= raw.size()) {
      out.push_back('$');
      continue;
    }

    size_t end = i;
    ParsedVarToken ref = {};
    if (!AMDomain::var::ParseVarRefAt(raw, i, raw.size(), true, true, &end,
                                      &ref) ||
        !ref.valid || end <= i || ref.varname.empty()) {
      out.push_back('$');
      continue;
    }

    const auto value = LookupVarValue_(ref, all_vars);
    if ((value.rcm)) {
      out.append(value.data);
    } else {
      out.append(raw.substr(i, end - i));
    }
    i = end - 1;
  }

  return out;
}

std::string
VarInterfaceService::SubstitutePathLike(const std::string &raw) const {
  auto all_vars = var_service_.GetAllVar();
  if (!(all_vars.rcm)) {
    return raw;
  }
  return SubstitutePathLikeWithSnapshot_(raw, all_vars.data);
}

std::vector<std::string> VarInterfaceService::SubstitutePathLike(
    const std::vector<std::string> &raw) const {
  auto all_vars = var_service_.GetAllVar();
  if (!(all_vars.rcm)) {
    return raw;
  }
  std::vector<std::string> out = raw;
  for (std::string &item : out) {
    item = SubstitutePathLikeWithSnapshot_(item, all_vars.data);
  }
  return out;
}

void VarInterfaceService::VSubstitutePathLike(std::string &raw) const {
  auto all_vars = var_service_.GetAllVar();
  if (!(all_vars.rcm)) {
    return;
  }
  raw = SubstitutePathLikeWithSnapshot_(raw, all_vars.data);
}

void VarInterfaceService::VSubstitutePathLike(
    std::vector<std::string> &raw) const {
  auto all_vars = var_service_.GetAllVar();
  if (!(all_vars.rcm)) {
    return;
  }
  for (std::string &item : raw) {
    item = SubstitutePathLikeWithSnapshot_(item, all_vars.data);
  }
}

bool VarInterfaceService::RewriteVarShortcutTokens(
    std::vector<std::string> *tokens) const {
  (void)prompt_io_manager_;
  if (!tokens || tokens->empty()) {
    return false;
  }

  const std::vector<std::string> src = *tokens;
  ShortcutVarKind kind = ShortcutVarKind::None;
  std::string var_token = {};
  std::string zone = {};

  if (src.size() == 1) {
    if (ParseShortcutVarToken_(src[0], &kind, &var_token, &zone)) {
      if (kind == ShortcutVarKind::GetVar) {
        *tokens = {"var", "get", var_token};
        return true;
      }
      if (kind == ShortcutVarKind::ListAll) {
        *tokens = {"var", "ls"};
        return true;
      }
      if (kind == ShortcutVarKind::ListDomain) {
        *tokens = {"var", "ls", zone};
        return true;
      }
    }

    const size_t eq = src[0].find('=');
    if (eq == std::string::npos) {
      return false;
    }
    if (!ParseShortcutVarToken_(src[0].substr(0, eq), &kind, &var_token,
                                &zone) ||
        kind != ShortcutVarKind::GetVar) {
      return false;
    }

    *tokens = {"var", "def", var_token, src[0].substr(eq + 1)};
    return true;
  }

  const size_t first_eq = src[0].find('=');
  if (first_eq != std::string::npos &&
      ParseShortcutVarToken_(src[0].substr(0, first_eq), &kind, &var_token,
                             &zone) &&
      kind == ShortcutVarKind::GetVar) {
    const std::string first_rhs = src[0].substr(first_eq + 1);
    *tokens = {"var", "def", var_token, JoinValueWithTail_(first_rhs, src, 1)};
    return true;
  }

  if (!ParseShortcutVarToken_(src[0], &kind, &var_token, &zone) ||
      kind != ShortcutVarKind::GetVar) {
    return false;
  }
  if (src[1] == "=") {
    *tokens = {"var", "def", var_token, JoinTokens_(src, 2)};
    return true;
  }
  if (!src[1].empty() && src[1].front() == '=') {
    const std::string first_rhs = src[1].substr(1);
    *tokens = {"var", "def", var_token, JoinValueWithTail_(first_rhs, src, 2)};
    return true;
  }
  return false;
}
} // namespace AMInterface::var
