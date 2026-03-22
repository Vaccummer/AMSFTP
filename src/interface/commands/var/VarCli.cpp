#include "interface/adapters/ApplicationAdapters.hpp"
#include "foundation/tools/json.hpp"
#include "foundation/tools/string.hpp"
#include "interface/prompt/Prompt.hpp"
#include <algorithm>

namespace AMInterface::ApplicationAdapters {
namespace {
using EC = ErrorCode;
using VarInfo = AMDomain::var::VarInfo;
using VarRef = AMDomain::var::varsetkn::VarRef;

/**
 * @brief Parse a complete variable token into a structured reference.
 */
ECM ParseVarToken_(const std::string &token, VarRef *ref) {
  if (!ref) {
    return Err(EC::InvalidArg, "null output variable");
  }
  const std::string trimmed = AMStr::Strip(token);
  if (trimmed.empty()) {
    return Err(EC::InvalidArg, "empty variable token");
  }
  VarRef parsed{};
  if (!AMDomain::var::varsetkn::ParseVarToken(trimmed, &parsed) ||
      !parsed.valid) {
    return Err(EC::InvalidArg, "invalid variable token");
  }
  if (parsed.varname.empty()) {
    return Err(EC::InvalidArg, "empty variable name");
  }
  *ref = std::move(parsed);
  return Ok();
}

/**
 * @brief Format variable output style.
 */
std::string FormatVarText_(const std::string &text) {
  return Runtime::Format(text, AMInterface::style::StyleIndex::None);
}

/**
 * @brief Format output value with empty-string rule.
 */
std::string RenderValue_(const std::string &value) {
  if (value.empty()) {
    return """";
  }
  return value;
}

/**
 * @brief Print one section with aligned `$name` column.
 */
void PrintSection_(AMPromptManager &prompt_manager, const std::string &domain,
                   const std::vector<VarInfo> &entries) {
  prompt_manager.FmtPrint("\[{}]", domain);
  size_t max_width = 0;
  for (const auto &item : entries) {
    max_width = std::max(max_width, item.varname.size() + 1);
  }

  for (const auto &item : entries) {
    std::string key = "$" + item.varname;
    if (key.size() < max_width) {
      key.append(max_width - key.size(), ' ');
    }
    prompt_manager.FmtPrint("{} = {}", FormatVarText_(key),
                            FormatVarText_(RenderValue_(item.varvalue)));
  }
}
} // namespace

/**
 * @brief Execute CLI `var get` against the var app service.
 */
ECM RunVarGet(AMApplication::VarWorkflow::VarAppService &var_service,
              AMPromptManager &prompt_manager,
              const std::string &token_name) {
  ECM rcm = Ok();
  const VarInfo found = var_service.ResolveToken(token_name, &rcm);
  if (!isok(rcm)) {
    return rcm;
  }
  prompt_manager.FmtPrint("\[{}] {} = {}", found.domain,
                          FormatVarText_("$" + found.varname),
                          FormatVarText_(RenderValue_(found.varvalue)));
  return Ok();
}

/**
 * @brief Execute CLI `var def` against the var app service.
 */
ECM RunVarDef(AMApplication::VarWorkflow::VarAppService &var_service,
              AMPromptManager &prompt_manager, bool global,
              const std::string &token_name, const std::string &value) {
  VarInfo target{};
  ECM rcm = var_service.ResolveDefineTarget(global, token_name, &target);
  if (!isok(rcm)) {
    return rcm;
  }

  if (target.domain != AMDomain::var::varsetkn::kPublic) {
    const VarInfo old = var_service.GetVar(target.domain, target.varname);
    if (old.IsValid().first == EC::Success) {
      prompt_manager.FmtPrint("[{}] {} = {}", old.domain,
                              FormatVarText_("$" + old.varname),
                              FormatVarText_(RenderValue_(old.varvalue)));
      bool canceled = false;
      const bool overwrite = prompt_manager.PromptYesNo(
          AMStr::fmt("Overwrite [{}].${}? (y/N): ", target.domain,
                     target.varname),
          &canceled);
      if (canceled || !overwrite) {
        return Err(EC::Terminate, "operation canceled");
      }
    }
  }

  target.varvalue = value;
  rcm = var_service.DefineVar(target);
  if (!isok(rcm)) {
    return rcm;
  }
  return var_service.SaveVars(true);
}

/**
 * @brief Execute CLI `var del` against the var app service.
 */
ECM RunVarDel(AMApplication::VarWorkflow::VarAppService &var_service,
              AMPromptManager &prompt_manager, bool all,
              const std::vector<std::string> &tokens) {
  std::string section = "";
  std::string varname = "";
  if (tokens.size() == 1) {
    varname = tokens[0];
  } else if (tokens.size() == 2) {
    section = tokens[0];
    varname = tokens[1];
  } else {
    return Err(EC::InvalidArg, "var del requires: [$section] $varname");
  }

  VarRef ref{};
  ECM parsed = ParseVarToken_(varname, &ref);
  if (!isok(parsed)) {
    return parsed;
  }

  const std::string trimmed_domain = AMStr::Strip(section);
  if (all && (!trimmed_domain.empty() || ref.explicit_domain)) {
    return Err(EC::InvalidArg, "nickname cannot be used with --all");
  }

  if (all) {
    auto matches = var_service.FindByName(ref.varname);
    if (matches.empty()) {
      return Err(EC::InvalidArg, "variable not found");
    }
    for (const auto &item : matches) {
      prompt_manager.FmtPrint("[{}] {} = {}", item.domain,
                              FormatVarText_("$" + item.varname),
                              FormatVarText_(RenderValue_(item.varvalue)));
    }
    bool canceled = false;
    const bool confirmed = prompt_manager.PromptYesNo(
        AMStr::fmt("Delete {} matched item(s)? (y/N): ", matches.size()),
        &canceled);
    if (canceled || !confirmed) {
      return Err(EC::Terminate, "operation canceled");
    }
    std::vector<VarInfo> removed;
    ECM rcm = var_service.DeleteVarAll(ref.varname, &removed);
    if (!isok(rcm)) {
      return rcm;
    }
    return var_service.SaveVars(true);
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
    target_domain = var_service.CurrentDomain();
  }
  if (!var_service.HasDomain(target_domain)) {
    return Err(EC::InvalidArg,
               AMStr::fmt("invalid section: {}", target_domain));
  }

  ECM rcm = var_service.DeleteVar(target_domain, ref.varname);
  if (!isok(rcm)) {
    return rcm;
  }
  return var_service.SaveVars(true);
}

/**
 * @brief Execute CLI `var ls` against the var app service.
 */
ECM RunVarLs(AMApplication::VarWorkflow::VarAppService &var_service,
             AMPromptManager &prompt_manager,
             const std::vector<std::string> &domains) {
  std::vector<std::string> targets = domains;
  ECM last = Ok();

  if (targets.empty()) {
    targets = var_service.ListDomains();
  } else {
    targets = AMJson::VectorDedup(targets);
  }

  std::vector<std::string> valid_targets;
  valid_targets.reserve(targets.size());
  for (const auto &raw : targets) {
    const std::string domain = AMStr::Strip(raw);
    if (!var_service.HasDomain(domain)) {
      last = Err(EC::InvalidArg, AMStr::fmt("invalid section: {}", raw));
      prompt_manager.ErrorFormat(last);
      continue;
    }
    valid_targets.push_back(domain);
  }

  if (valid_targets.empty()) {
    return last.first == EC::Success ? Err(EC::InvalidArg, "no valid section")
                                     : last;
  }

  for (size_t i = 0; i < valid_targets.size(); ++i) {
    auto entries = var_service.ListByDomain(valid_targets[i]);
    PrintSection_(prompt_manager, valid_targets[i], entries);
    if (i + 1 < valid_targets.size()) {
      prompt_manager.Print("");
    }
  }
  return last;
}
} // namespace AMInterface::ApplicationAdapters
