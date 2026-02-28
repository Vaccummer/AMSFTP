#include "AMBase/tools/auth.hpp"
#include "AMBase/tools/bar.hpp"
#include "AMBase/tools/json.hpp"
#include "AMBase/tools/time.hpp"
#include "AMManager/Var.hpp"
#include <algorithm>

using EC = ErrorCode;

namespace {
/**
 * @brief Parse variable token into structured var reference.
 */
ECM ParseVarToken_(const std::string &token, varsetkn::VarRef *ref) {
  if (!ref) {
    return Err(EC::InvalidArg, "null output variable");
  }
  std::string trimmed = AMStr::Strip(token);
  if (trimmed.empty()) {
    return Err(EC::InvalidArg, "empty variable token");
  }
  varsetkn::VarRef parsed{};
  if (!varsetkn::ParseVarToken(trimmed, &parsed) || !parsed.valid) {
    return Err(EC::InvalidArg, "invalid variable token");
  }
  if (parsed.varname.empty()) {
    return Err(EC::InvalidArg, "empty variable name");
  }
  *ref = std::move(parsed);
  return Ok();
}
} // namespace

/**
 * @brief Format variable output style.
 */
std::string VarCLISet::FormatVarText_(const std::string &text) const {
  return config_manager_.Format(text, "UserVars");
}

/**
 * @brief Format output value with empty-string rule.
 */
std::string VarCLISet::RenderValue_(const std::string &value) const {
  if (value.empty()) {
    return "\"\"";
  }
  return value;
}

/**
 * @brief Print one section with aligned `$name` column.
 */
void VarCLISet::PrintSection_(const std::string &domain,
                              const std::vector<VarInfo> &entries) const {
  prompt_manager_.Print(AMStr::amfmt("\\[{}]", domain));
  size_t max_width = 0;
  for (const auto &item : entries) {
    max_width = std::max(max_width, item.varname.size() + 1);
  }

  for (const auto &item : entries) {
    std::string key = "$" + item.varname;
    if (key.size() < max_width) {
      key.append(max_width - key.size(), ' ');
    }
    prompt_manager_.Print(
        AMStr::amfmt("{} = {}", FormatVarText_(key),
                     FormatVarText_(RenderValue_(item.varvalue))));
  }
}

/**
 * @brief Handle `var get $name`.
 */
ECM VarCLISet::QueryByName(const std::string &token_name) const {
  VarCLISet &var_manager = VarCLISet::Instance();
  varsetkn::VarRef ref{};
  ECM parsed = ParseVarToken_(token_name, &ref);
  if (parsed.first != EC::Success) {
    return parsed;
  }

  if (ref.explicit_domain) {
    const VarInfo found = var_manager.GetVar(ref.domain, ref.varname);
    if (found.IsValid().first != EC::Success) {
      return Err(
          EC::InvalidArg,
          AMStr::amfmt("variable not found: {}", varsetkn::BuildVarToken(ref)));
    }
    prompt_manager_.Print(AMStr::amfmt(
        "\\[{}] {} = {}", found.domain, FormatVarText_("$" + found.varname),
        FormatVarText_(RenderValue_(found.varvalue))));
    return Ok();
  }

  const std::string current_domain = var_manager.CurrentDomain();
  VarInfo found = var_manager.GetVar(current_domain, ref.varname);
  if (found.IsValid().first != EC::Success) {
    found = var_manager.GetVar(varsetkn::kPublic, ref.varname);
  }
  if (found.IsValid().first != EC::Success) {
    return Err(
        EC::InvalidArg,
        AMStr::amfmt("variable not found: {}", varsetkn::BuildVarToken(ref)));
  }
  prompt_manager_.Print(AMStr::amfmt(
      "\\[{}] {} = {}", found.domain, FormatVarText_("$" + found.varname),
      FormatVarText_(RenderValue_(found.varvalue))));
  return Ok();
}

/**
 * @brief Handle `var def [-g] $name value`.
 */
ECM VarCLISet::DefineVar(bool global, const std::string &token_name,
                         const std::string &value) {
  VarCLISet &var_manager = VarCLISet::Instance();
  varsetkn::VarRef ref{};
  ECM parsed = ParseVarToken_(token_name, &ref);
  if (parsed.first != EC::Success) {
    return parsed;
  }
  if (global && ref.explicit_domain) {
    return Err(EC::InvalidArg, "cannot use --global with explicit zone token");
  }

  const std::string domain =
      ref.explicit_domain
          ? ref.domain
          : (global ? std::string(varsetkn::kPublic) : var_manager.CurrentDomain());

  if (domain != varsetkn::kPublic) {
    VarInfo old = var_manager.GetVar(domain, ref.varname);
    if (old.IsValid().first == EC::Success) {
      prompt_manager_.Print(AMStr::amfmt(
          "[{}] {} = {}", old.domain, FormatVarText_("$" + old.varname),
          FormatVarText_(RenderValue_(old.varvalue))));
      bool canceled = false;
      const bool overwrite = prompt_manager_.PromptYesNo(
          AMStr::amfmt("Overwrite [{}].${}? (y/N): ", domain, ref.varname),
          &canceled);
      if (canceled || !overwrite) {
        return Err(EC::Terminate, "operation canceled");
      }
    }
  }

  ECM rcm = var_manager.SetVar({domain, ref.varname, value}, true);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return var_manager.Save(true);
}

/**
 * @brief Handle `var del [-a] [domain] $name`.
 */
ECM VarCLISet::DeleteVarByCli(bool all, const std::string &domain,
                              const std::string &token_name) {
  VarCLISet &var_manager = VarCLISet::Instance();
  varsetkn::VarRef ref{};
  ECM parsed = ParseVarToken_(token_name, &ref);
  if (parsed.first != EC::Success) {
    return parsed;
  }

  const std::string trimmed_domain = AMStr::Strip(domain);
  if (all && (!trimmed_domain.empty() || ref.explicit_domain)) {
    return Err(EC::InvalidArg, "nickname cannot be used with --all");
  }

  if (all) {
    auto matches = var_manager.FindByName(ref.varname);
    if (matches.empty()) {
      return Err(EC::InvalidArg, "variable not found");
    }
    for (const auto &item : matches) {
      prompt_manager_.Print(AMStr::amfmt(
          "[{}] {} = {}", item.domain, FormatVarText_("$" + item.varname),
          FormatVarText_(RenderValue_(item.varvalue))));
    }
    bool canceled = false;
    const bool confirmed = prompt_manager_.PromptYesNo(
        AMStr::amfmt("Delete {} matched item(s)? (y/N): ", matches.size()),
        &canceled);
    if (canceled || !confirmed) {
      return Err(EC::Terminate, "operation canceled");
    }
    std::vector<VarInfo> removed;
    ECM rcm = var_manager.DeleteVarAll(ref.varname, &removed);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    return var_manager.Save(true);
  }

  std::string target_domain;
  if (ref.explicit_domain) {
    if (!trimmed_domain.empty() && trimmed_domain != ref.domain) {
      return Err(EC::InvalidArg,
                 "domain argument conflicts with token explicit zone");
    }
    target_domain = ref.domain;
  } else if (!trimmed_domain.empty()) {
    target_domain = trimmed_domain;
  } else {
    target_domain = var_manager.CurrentDomain();
  }
  if (!var_manager.HasDomain(target_domain)) {
    return Err(EC::InvalidArg,
               AMStr::amfmt("invalid section: {}", target_domain));
  }
  ECM rcm = var_manager.DeleteVar(target_domain, ref.varname);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return var_manager.Save(true);
}

/**
 * @brief Handle `var ls [domain ...]`.
 */
ECM VarCLISet::ListVars(const std::vector<std::string> &domains) const {
  VarCLISet &var_manager = VarCLISet::Instance();
  std::vector<std::string> targets = domains;
  ECM last = Ok();

  if (targets.empty()) {
    targets = var_manager.ListDomains();
  } else {
    targets = VectorDedup(targets);
  }

  std::vector<std::string> valid_targets;
  valid_targets.reserve(targets.size());
  for (const auto &raw : targets) {
    const std::string domain = AMStr::Strip(raw);
    if (!var_manager.HasDomain(domain)) {
      last = Err(EC::InvalidArg, AMStr::amfmt("invalid section: {}", raw));
      prompt_manager_.ErrorFormat(last);
      continue;
    }
    valid_targets.push_back(domain);
  }

  if (valid_targets.empty()) {
    return last.first == EC::Success ? Err(EC::InvalidArg, "no valid section")
                                     : last;
  }

  for (size_t i = 0; i < valid_targets.size(); ++i) {
    auto entries = var_manager.ListByDomain(valid_targets[i]);
    PrintSection_(valid_targets[i], entries);
    if (i + 1 < valid_targets.size()) {
      prompt_manager_.Print("");
    }
  }
  return last;
}

