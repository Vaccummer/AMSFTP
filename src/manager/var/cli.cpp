#include "AMManager/Var.hpp"
#include "AMBase/CommonTools.hpp"
#include <algorithm>
#include <cctype>

using EC = ErrorCode;

namespace {
/**
 * @brief Parse `$name` token into raw variable name.
 */
ECM ParseVarToken_(const std::string &token, std::string *name) {
  if (!name) {
    return Err(EC::InvalidArg, "null output variable");
  }
  std::string trimmed = AMStr::Strip(token);
  if (trimmed.empty()) {
    return Err(EC::InvalidArg, "empty variable token");
  }
  if (trimmed.front() != '$') {
    return Err(EC::InvalidArg, "variable must start with $");
  }
  if (trimmed.size() >= 3 && trimmed[1] == '{' && trimmed.back() == '}') {
    trimmed = AMStr::Strip(trimmed.substr(2, trimmed.size() - 3));
  } else {
    trimmed = trimmed.substr(1);
  }
  if (trimmed.empty()) {
    return Err(EC::InvalidArg, "empty variable name");
  }
  if (!varsetkn::IsValidVarname(trimmed)) {
    return Err(EC::InvalidArg,
               "invalid variable name: only [A-Za-z0-9_] allowed");
  }
  *name = trimmed;
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
  prompt_manager_.Print(AMStr::amfmt("[{}]", domain));
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
        AMStr::amfmt("{} = {}", FormatVarText_(key), FormatVarText_(RenderValue_(item.varvalue))));
  }
}

/**
 * @brief Handle `var get $name`.
 */
ECM VarCLISet::QueryByName(const std::string &token_name) const {
  std::string name;
  ECM parsed = ParseVarToken_(token_name, &name);
  if (parsed.first != EC::Success) {
    return parsed;
  }

  auto entries = FindByName(name);
  if (entries.empty()) {
    return Err(EC::InvalidArg, AMStr::amfmt("variable not found: {}", token_name));
  }
  for (const auto &item : entries) {
    prompt_manager_.Print(AMStr::amfmt("[{}] {} = {}", item.domain,
                                       FormatVarText_("$" + item.varname),
                                       FormatVarText_(RenderValue_(item.varvalue))));
  }
  return Ok();
}

/**
 * @brief Handle `var def [-g] $name value`.
 */
ECM VarCLISet::DefineVar(bool global, const std::string &token_name,
                         const std::string &value) {
  std::string name;
  ECM parsed = ParseVarToken_(token_name, &name);
  if (parsed.first != EC::Success) {
    return parsed;
  }

  const std::string domain = global ? std::string(varsetkn::kPublic) : CurrentDomain();

  if (!global) {
    VarInfo old = GetVar(domain, name);
    if (old.IsValid().first == EC::Success) {
      prompt_manager_.Print(AMStr::amfmt("[{}] {} = {}", old.domain,
                                         FormatVarText_("$" + old.varname),
                                         FormatVarText_(RenderValue_(old.varvalue))));
      bool canceled = false;
      const bool overwrite = prompt_manager_.PromptYesNo(
          AMStr::amfmt("Overwrite [{}].${}? (y/N): ", domain, name), &canceled);
      if (canceled || !overwrite) {
        return Err(EC::Terminate, "operation canceled");
      }
    }
  }

  ECM rcm = SetVar({domain, name, value}, true);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return Save(true);
}

/**
 * @brief Handle `var del [-a] [domain] $name`.
 */
ECM VarCLISet::DeleteVarByCli(bool all, const std::string &domain,
                              const std::string &token_name) {
  std::string name;
  ECM parsed = ParseVarToken_(token_name, &name);
  if (parsed.first != EC::Success) {
    return parsed;
  }

  const std::string trimmed_domain = AMStr::Strip(domain);
  if (all && !trimmed_domain.empty()) {
    return Err(EC::InvalidArg, "nickname cannot be used with --all");
  }

  if (all) {
    auto matches = FindByName(name);
    if (matches.empty()) {
      return Err(EC::InvalidArg, "variable not found");
    }
    for (const auto &item : matches) {
      prompt_manager_.Print(AMStr::amfmt("[{}] {} = {}", item.domain,
                                         FormatVarText_("$" + item.varname),
                                         FormatVarText_(RenderValue_(item.varvalue))));
    }
    bool canceled = false;
    const bool confirmed =
        prompt_manager_.PromptYesNo(AMStr::amfmt("Delete {} matched item(s)? (y/N): ",
                                                 matches.size()),
                                    &canceled);
    if (canceled || !confirmed) {
      return Err(EC::Terminate, "operation canceled");
    }
    std::vector<VarInfo> removed;
    ECM rcm = DeleteVarAll(name, &removed);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    return Save(true);
  }

  std::string target_domain = trimmed_domain;
  if (target_domain.empty()) {
    target_domain = CurrentDomain();
  }
  if (!HasDomain(target_domain)) {
    return Err(EC::InvalidArg, AMStr::amfmt("invalid section: {}", target_domain));
  }
  ECM rcm = DeleteVar(target_domain, name);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  return Save(true);
}

/**
 * @brief Handle `var ls [domain ...]`.
 */
ECM VarCLISet::ListVars(const std::vector<std::string> &domains) const {
  std::vector<std::string> targets = domains;
  ECM last = Ok();

  if (targets.empty()) {
    targets = ListDomains();
  } else {
    targets = VectorDedup(targets);
  }

  std::vector<std::string> valid_targets;
  valid_targets.reserve(targets.size());
  for (const auto &raw : targets) {
    const std::string domain = AMStr::Strip(raw);
    if (!HasDomain(domain)) {
      last = Err(EC::InvalidArg, AMStr::amfmt("invalid section: {}", raw));
      prompt_manager_.ErrorFormat(last);
      continue;
    }
    valid_targets.push_back(domain);
  }

  if (valid_targets.empty()) {
    return last.first == EC::Success ? Err(EC::InvalidArg, "no valid section") : last;
  }

  for (size_t i = 0; i < valid_targets.size(); ++i) {
    auto entries = ListByDomain(valid_targets[i]);
    PrintSection_(valid_targets[i], entries);
    if (i + 1 < valid_targets.size()) {
      prompt_manager_.Print("");
    }
  }
  return last;
}
