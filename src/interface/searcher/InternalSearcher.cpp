#include "domain/host/HostDomainService.hpp"
#include "domain/var/VarDomainService.hpp"
#include "interface/searcher/Searcher.hpp"
#include "interface/searcher/SearcherCommon.hpp"
#include "interface/style/StyleManager.hpp"
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

using namespace AMInterface::searcher::detail;

using AMDomain::var::VarInfo;

namespace AMInterface::searcher {
namespace {
using AMDomain::transfer::TaskID;
enum class VarZonePrefixMode {
  Plain = 0,
  Dollar,
  BracedDollar,
};

/**
 * @brief Return display value for variable help (empty -> "").
 */
std::string RenderVarValue_(const std::string &value) {
  return value.empty() ? "\"\"" : value;
}

/**
 * @brief Return true when nickname completion is requested in path context.
 */
bool IsPathNicknameContext_(const AMCompletionContext &ctx) {
  return HasTarget(ctx, AMCompletionTarget::Path);
}

/**
 * @brief Collect merged host/client nicknames with created-first ordering.
 */
struct HostLikeNameInfo {
  std::string name;
  bool created = false;
};

/**
 * @brief Build unified nickname list: created clients first, then uncreated
 * configured hosts.
 */
std::vector<HostLikeNameInfo> CollectHostLikeNames_(
    const AMInterface::input::IInputSemanticRuntime *runtime) {
  std::vector<HostLikeNameInfo> names;
  if (!runtime) {
    return names;
  }
  std::unordered_set<std::string> seen;

  auto add_name = [&](const std::string &name, bool created) {
    const std::string key = AMStr::lowercase(name);
    if (key.empty() || !seen.insert(key).second) {
      return;
    }
    names.emplace_back(name, created);
  };

  std::vector<std::string> created_names = runtime->ListClientNames();
  std::ranges::sort(created_names.begin(), created_names.end());
  for (const auto &name : created_names) {
    add_name(name, true);
  }
  add_name("local", true);

  std::vector<std::string> configured_names = runtime->ListHostNames();
  std::ranges::sort(configured_names.begin(), configured_names.end());
  for (const auto &name : configured_names) {
    add_name(name, false);
  }

  return names;
}

std::vector<HostLikeNameInfo> CollectTerminalLikeNames_(
    const AMInterface::input::IInputSemanticRuntime *runtime) {
  std::vector<HostLikeNameInfo> names;
  if (!runtime) {
    return names;
  }
  std::unordered_set<std::string> seen;

  auto add_name = [&](const std::string &name, bool created) {
    const std::string key = AMStr::lowercase(name);
    if (key.empty() || !seen.insert(key).second) {
      return;
    }
    names.push_back({name, created});
  };

  std::vector<std::string> terminal_names = runtime->ListTerminalNames();
  std::ranges::sort(terminal_names.begin(), terminal_names.end());
  for (const auto &name : terminal_names) {
    const size_t at_pos = name.find('@');
    add_name(at_pos == std::string::npos ? name : name.substr(0, at_pos),
             true);
  }

  std::vector<std::string> host_names = runtime->ListHostNames();
  std::ranges::sort(host_names.begin(), host_names.end());
  for (const auto &name : host_names) {
    add_name(name, false);
  }
  return names;
}

enum class TargetSemantics_ {
  ExistingOnly = 0,
  NewOnly = 1,
  ExistingOrNew = 2,
};

struct TermTargetPrefix_ {
  std::string client_name = "local";
  std::string term_prefix = "";
  std::string insert_header = "";
  bool has_explicit_client = false;
};

TermTargetPrefix_ ParseTermTargetPrefix_(const std::string &raw_prefix,
                                         const std::string &current_nickname) {
  TermTargetPrefix_ out = {};
  out.client_name = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(current_nickname));
  if (out.client_name.empty()) {
    out.client_name = "local";
  }

  const std::string text = AMStr::Strip(raw_prefix);
  if (text.empty()) {
    return out;
  }

  const size_t at_pos = text.find('@');
  if (at_pos == std::string::npos) {
    out.term_prefix = text;
    return out;
  }

  out.has_explicit_client = true;
  const std::string client_part = AMStr::Strip(text.substr(0, at_pos));
  if (!client_part.empty()) {
    out.client_name =
        AMDomain::host::HostService::NormalizeNickname(client_part);
  }
  out.term_prefix = AMStr::Strip(text.substr(at_pos + 1));
  out.insert_header = client_part.empty() ? std::string("@") : (client_part + "@");
  return out;
}

std::string FormatWithStyle_(const AMCompletionContext &ctx,
                             const std::string &text,
                             AMInterface::style::StyleIndex style_index) {
  if (!ctx.style_service) {
    return text;
  }
  return ctx.style_service->Format(text, style_index);
}

/**
 * @brief Parse variable completion prefix from token prefix text.
 */
bool ParseVarCompletionPrefix_(const std::string &prefix,
                               AMDomain::var::VarRef *out_ref) {
  if (!out_ref || prefix.empty() || prefix.front() != '$') {
    return false;
  }
  if (prefix == "$") {
    out_ref->valid = true;
    out_ref->braced = false;
    out_ref->explicit_domain = false;
    out_ref->domain.clear();
    out_ref->varname.clear();
    return true;
  }
  if (prefix == "${") {
    out_ref->valid = true;
    out_ref->braced = true;
    out_ref->explicit_domain = false;
    out_ref->domain.clear();
    out_ref->varname.clear();
    return true;
  }
  size_t end = 0;
  AMDomain::var::VarRef ref{};
  if (!AMDomain::var::ParseVarRefAt(prefix, 0, prefix.size(), true, true, &end,
                                    &ref) ||
      !ref.valid || end != prefix.size()) {
    return false;
  }
  *out_ref = std::move(ref);
  return true;
}

/**
 * @brief Parse zone-name completion prefix for shorthand `$...` mode.
 */
bool ParseVarZonePrefix_(const std::string &prefix, std::string *out_prefix,
                         VarZonePrefixMode *out_mode) {
  if (!out_prefix || !out_mode) {
    return false;
  }
  *out_prefix = prefix;
  *out_mode = VarZonePrefixMode::Plain;
  if (prefix.empty()) {
    return true;
  }
  if (prefix.size() >= 2 && prefix[0] == '$' && prefix[1] == '{') {
    *out_mode = VarZonePrefixMode::BracedDollar;
    *out_prefix = prefix.substr(2);
    return true;
  }
  if (prefix.front() != '$') {
    return true;
  }
  *out_mode = VarZonePrefixMode::Dollar;
  *out_prefix = prefix.substr(1);
  return true;
}

AMInterface::style::StyleIndex TerminalStyleKey_(
    AMInterface::input::IInputSemanticRuntime::TerminalNameState state) {
  switch (state) {
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::OK:
    return AMInterface::style::StyleIndex::TerminalName;
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::
      Disconnected:
    return AMInterface::style::StyleIndex::DisconnectedTerminalName;
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::
      Nonexistent:
    return AMInterface::style::StyleIndex::NonexistentTerminalName;
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::ValidNew:
    return AMInterface::style::StyleIndex::ValidNewTerminalName;
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::
      InvalidNew:
  default:
    return AMInterface::style::StyleIndex::InvalidNewTerminalName;
  }
}

AMInterface::style::StyleIndex TerminalClientStyleKey_(
    AMInterface::input::IInputSemanticRuntime::TerminalNameState state) {
  switch (state) {
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::OK:
    return AMInterface::style::StyleIndex::Nickname;
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::
      Disconnected:
    return AMInterface::style::StyleIndex::DisconnectedNickname;
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::
      Unestablished:
    return AMInterface::style::StyleIndex::UnestablishedNickname;
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::
      Nonexistent:
  default:
    return AMInterface::style::StyleIndex::NonexistentNickname;
  }
}
} // namespace

/**
 * @brief Collect internal-value candidates.
 */
AMCompletionCandidates
AMInternalSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCandidates result;
  const auto *runtime = runtime_.get();
  if (!runtime) {
    return result;
  }
  const std::string prefix = ctx.token_prefix;

  if (HasTarget(ctx, AMCompletionTarget::VariableName)) {
    AMDomain::var::VarRef prefix_ref{};
    if (!ParseVarCompletionPrefix_(prefix, &prefix_ref)) {
      return result;
    }

    std::vector<VarInfo> items;
    if (prefix_ref.explicit_domain) {
      items = runtime->ListVarsByDomain(prefix_ref.domain);
    } else {
      const std::string current_domain = runtime->CurrentVarDomain();
      items = runtime->ListVarsByDomain(current_domain);
    }

    std::vector<std::string> keys;
    keys.reserve(items.size());
    for (const auto &item : items) {
      keys.push_back(item.varname);
    }

    const std::string name_prefix = prefix_ref.varname;
    for (const auto &match : BuildGeneralMatch(keys, name_prefix)) {
      const auto &item = items[match.index];
      AMDomain::var::VarRef candidate_ref = prefix_ref;
      if (candidate_ref.explicit_domain) {
        candidate_ref.domain = item.domain;
      }
      candidate_ref.varname = item.varname;
      AMCompletionCandidate candidate;
      candidate.insert_text = AMDomain::var::BuildVarToken(candidate_ref);
      candidate.display = FormatWithStyle_(
          ctx, candidate.insert_text,
          AMInterface::style::StyleIndex::PublicVarname);
      candidate.help =
          AMStr::fmt("[{}] {}", item.domain, RenderVarValue_(item.varvalue));
      candidate.kind = AMCompletionKind::VariableName;
      candidate.score = match.score_bias;
      result.items.push_back(std::move(candidate));
    }
    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
    }
    return result;
  }

  if (HasTarget(ctx, AMCompletionTarget::VarZone)) {
    std::string zone_prefix;
    VarZonePrefixMode mode = VarZonePrefixMode::Plain;
    if (!ParseVarZonePrefix_(prefix, &zone_prefix, &mode)) {
      return result;
    }

    struct ZoneInfo {
      std::string zone;
    };
    std::vector<ZoneInfo> zones;
    std::unordered_map<std::string, size_t> zone_index;
    zones.reserve(16);

    auto append_zone = [&](const std::string &zone) {
      if (zone_index.contains(zone)) {
        return;
      }
      zone_index[zone] = zones.size();
      zones.push_back({zone});
    };

    const auto domains = runtime->ListVarDomains();
    for (const auto &domain : domains) {
      append_zone(domain);
    }
    const auto hosts = runtime->ListHostNames();
    for (const auto &host : hosts) {
      append_zone(host);
    }
    append_zone(AMDomain::var::kPublic);

    std::vector<std::string> keys;
    keys.reserve(zones.size());
    for (const auto &item : zones) {
      keys.push_back(item.zone);
    }

    for (const auto &match : BuildGeneralMatch(keys, zone_prefix)) {
      const auto &item = zones[match.index];
      AMCompletionCandidate candidate;
      if (mode == VarZonePrefixMode::Dollar) {
        candidate.insert_text = (item.zone == AMDomain::var::kPublic)
                                    ? "$:"
                                    : ("$" + item.zone + ":");
      } else if (mode == VarZonePrefixMode::BracedDollar) {
        candidate.insert_text = (item.zone == AMDomain::var::kPublic)
                                    ? "${:"
                                    : ("${" + item.zone + ":");
      } else {
        candidate.insert_text = item.zone;
      }
      candidate.display = FormatWithStyle_(
          ctx, item.zone, AMInterface::style::StyleIndex::VarnameZone);
      candidate.kind = AMCompletionKind::VarZone;
      candidate.help.clear();
      candidate.score = match.score_bias;
      result.items.push_back(std::move(candidate));
    }
    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
    }
    return result;
  }

  if (HasTarget(ctx, AMCompletionTarget::ClientName)) {
    const bool path_nickname_context = IsPathNicknameContext_(ctx);
    std::string client_prefix = prefix;
    if (path_nickname_context) {
      const size_t at_pos = prefix.find('@');
      if (at_pos != std::string::npos) {
        client_prefix = prefix.substr(0, at_pos);
      }
    }

    std::vector<HostLikeNameInfo> names = CollectHostLikeNames_(runtime);

    std::vector<std::string> keys;
    keys.reserve(names.size());
    for (const auto &item : names) {
      keys.push_back(item.name);
    }

    for (const auto &match : BuildGeneralMatch(keys, client_prefix)) {
      const auto &name_item = names[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text =
          path_nickname_context ? name_item.name + "@" : name_item.name;
      const AMInterface::style::StyleIndex style_index =
          name_item.created
              ? AMInterface::style::StyleIndex::Nickname
              : AMInterface::style::StyleIndex::UnestablishedNickname;
      candidate.display = FormatWithStyle_(ctx, name_item.name, style_index);
      candidate.kind = AMCompletionKind::ClientName;
      const int uncreated_bias = name_item.created ? 0 : 100;
      candidate.score = match.score_bias + uncreated_bias;
      result.items.push_back(std::move(candidate));
    }
    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
    }
    return result;
  }

  if (HasTarget(ctx, AMCompletionTarget::PoolName)) {
    std::vector<std::string> names = runtime->ListPoolNames();
    std::sort(names.begin(), names.end());
    for (const auto &match : BuildGeneralMatch(names, prefix)) {
      const std::string &name = names[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = name;
      candidate.display = FormatWithStyle_(
          ctx, name, AMInterface::style::StyleIndex::Nickname);
      candidate.kind = AMCompletionKind::ClientName;
      candidate.score = match.score_bias;
      result.items.push_back(std::move(candidate));
    }
    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
    }
    return result;
  }

  if (HasTarget(ctx, AMCompletionTarget::HostNickname)) {
    const bool path_nickname_context = IsPathNicknameContext_(ctx);
    std::string host_prefix = prefix;
    if (path_nickname_context) {
      const size_t at_pos = prefix.find('@');
      if (at_pos != std::string::npos) {
        host_prefix = prefix.substr(0, at_pos);
      }
    }
    std::vector<HostLikeNameInfo> names = CollectHostLikeNames_(runtime);
    std::vector<std::string> keys;
    keys.reserve(names.size());
    for (const auto &item : names) {
      keys.push_back(item.name);
    }
    for (const auto &match : BuildGeneralMatch(keys, host_prefix)) {
      const auto &name_item = names[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text =
          path_nickname_context ? name_item.name + "@" : name_item.name;
      const AMInterface::style::StyleIndex style_index =
          name_item.created
              ? AMInterface::style::StyleIndex::Nickname
              : AMInterface::style::StyleIndex::UnestablishedNickname;
      candidate.display = FormatWithStyle_(ctx, name_item.name, style_index);
      candidate.kind = AMCompletionKind::HostNickname;
      const int uncreated_bias = name_item.created ? 0 : 100;
      candidate.score = match.score_bias + uncreated_bias;
      result.items.push_back(std::move(candidate));
    }
    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
    }
    return result;
  }

  if (HasTarget(ctx, AMCompletionTarget::TerminalName)) {
    std::vector<HostLikeNameInfo> names = CollectTerminalLikeNames_(runtime);
    std::vector<std::string> keys;
    keys.reserve(names.size());
    for (const auto &item : names) {
      keys.push_back(item.name);
    }
    for (const auto &match : BuildGeneralMatch(keys, prefix)) {
      const auto &name_item = names[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = name_item.name;
      const auto state = runtime->QueryTerminalClientNameState(name_item.name);
      candidate.display = FormatWithStyle_(ctx, name_item.name,
                                           TerminalClientStyleKey_(state));
      candidate.kind = AMCompletionKind::TerminalName;
      const int host_bias = name_item.created ? 0 : 100;
      candidate.score = match.score_bias + host_bias;
      result.items.push_back(std::move(candidate));
    }
    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
    }
    return result;
  }

  const bool term_existing_target =
      HasTarget(ctx, AMCompletionTarget::TermTargetExisting);
  const bool term_new_target = HasTarget(ctx, AMCompletionTarget::TermTargetNew);
  const bool term_create_or_use_target =
      HasTarget(ctx, AMCompletionTarget::SshTermTarget);
  if (term_existing_target || term_new_target || term_create_or_use_target) {
    const TargetSemantics_ semantics =
        term_existing_target
            ? TargetSemantics_::ExistingOnly
            : (term_new_target ? TargetSemantics_::NewOnly
                               : TargetSemantics_::ExistingOrNew);
    const TermTargetPrefix_ target =
        ParseTermTargetPrefix_(prefix, runtime->CurrentNickname());

    if (!target.has_explicit_client &&
        semantics != TargetSemantics_::ExistingOnly) {
      std::vector<HostLikeNameInfo> clients = CollectTerminalLikeNames_(runtime);
      std::vector<std::string> keys;
      keys.reserve(clients.size());
      for (const auto &item : clients) {
        keys.push_back(item.name);
      }

      for (const auto &match : BuildGeneralMatch(keys, target.term_prefix)) {
        const auto &client = clients[match.index];
        AMCompletionCandidate candidate;
        candidate.insert_text = client.name + "@";
        const auto state = runtime->QueryTerminalClientNameState(client.name);
        candidate.display =
            FormatWithStyle_(ctx, client.name, TerminalClientStyleKey_(state));
        candidate.kind = AMCompletionKind::TerminalName;
        const int host_bias = client.created ? 50 : 100;
        candidate.score = match.score_bias + host_bias;
        result.items.push_back(std::move(candidate));
      }
    }

    if (semantics != TargetSemantics_::NewOnly) {
      const std::vector<std::string> terms =
          runtime->ListTermNames(target.client_name);
      std::vector<std::string> keys;
      keys.reserve(terms.size());
      for (const auto &name : terms) {
        keys.push_back(name);
      }

      for (const auto &match : BuildGeneralMatch(keys, target.term_prefix)) {
        const std::string &term_name = terms[match.index];
        const auto state =
            runtime->QueryTermNameState(target.client_name, term_name, false);
        if (state == AMInterface::input::IInputSemanticRuntime::
                         TerminalNameState::Nonexistent) {
          continue;
        }
        AMCompletionCandidate candidate;
        candidate.insert_text = target.insert_header + term_name;
        candidate.display =
            FormatWithStyle_(ctx, term_name, TerminalStyleKey_(state));
        candidate.kind = AMCompletionKind::TerminalName;
        candidate.score = match.score_bias;
        result.items.push_back(std::move(candidate));
      }
    }

    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
    }
    return result;
  }

  if (HasTarget(ctx, AMCompletionTarget::HostAttr)) {
    const std::vector<std::string> &fields =
        AMDomain::host::HostService::EditableHostSetFieldNames();
    for (const auto &match : BuildGeneralMatch(fields, prefix)) {
      const std::string &field = fields[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = field;
      candidate.display = field;
      candidate.kind = AMCompletionKind::HostAttr;
      candidate.score = match.score_bias;
      result.items.push_back(std::move(candidate));
    }
    if (!result.items.empty()) {
      SortCandidates(ctx, result.items);
    }
    return result;
  }

  std::vector<TaskID> ids = {};
  if (HasTarget(ctx, AMCompletionTarget::PausedTaskId)) {
    ids = runtime->ListPausedTaskIDs();
  } else if (HasTarget(ctx, AMCompletionTarget::TaskId)) {
    ids = runtime->ListTaskIDs();
  }
  if (!ids.empty()) {
    std::vector<std::string> keys = {};
    keys.reserve(ids.size());
    for (const auto &id : ids) {
      keys.push_back(AMStr::ToString(id));
    }
    for (const auto &match : BuildGeneralMatch(keys, prefix)) {
      const TaskID &id = ids[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = AMStr::ToString(id);
      candidate.display = AMStr::ToString(id);
      candidate.kind = AMCompletionKind::TaskId;
      candidate.score = match.score_bias;
      result.items.push_back(std::move(candidate));
    }
  }

  if (!result.items.empty()) {
    SortCandidates(ctx, result.items);
  }
  return result;
}

std::shared_ptr<AMInterface::completer::ICompletionTask>
AMInternalSearchEngine::CreateTask(const AMCompletionContext &ctx) {
  return AMCompletionSearchEngine::CreateTask(ctx);
}

/**
 * @brief Sort internal-value candidates.
 */
void AMInternalSearchEngine::SortCandidates(
    const AMCompletionContext &ctx, std::vector<AMCompletionCandidate> &items) {
  (void)ctx;
  std::stable_sort(items.begin(), items.end(),
                   [](const auto &lhs, const auto &rhs) {
                     if (lhs.score != rhs.score) {
                       return lhs.score < rhs.score;
                     }
                     return lhs.insert_text < rhs.insert_text;
                   });
}

} // namespace AMInterface::searcher
