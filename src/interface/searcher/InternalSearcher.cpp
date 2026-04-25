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
    add_name(name, true);
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

struct TerminalChannelTarget_ {
  std::string terminal_name = "local";
  std::string channel_prefix = "";
  std::string insert_header = "";
};

TerminalChannelTarget_
ParseTerminalChannelTarget_(const std::string &raw_prefix,
                            const std::string &current_nickname) {
  TerminalChannelTarget_ out = {};
  out.terminal_name = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(current_nickname));
  if (out.terminal_name.empty()) {
    out.terminal_name = "local";
  }

  const std::string text = AMStr::Strip(raw_prefix);
  if (text.empty()) {
    return out;
  }

  const size_t at_pos = text.find('@');
  if (at_pos == std::string::npos) {
    out.channel_prefix = text;
    return out;
  }

  const std::string terminal_part = AMStr::Strip(text.substr(0, at_pos));
  if (!terminal_part.empty()) {
    out.terminal_name =
        AMDomain::host::HostService::NormalizeNickname(terminal_part);
  }
  out.channel_prefix = AMStr::Strip(text.substr(at_pos + 1));
  out.insert_header =
      terminal_part.empty() ? std::string("@") : (terminal_part + "@");
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
      Unestablished:
    return AMInterface::style::StyleIndex::UnestablishedTerminalName;
  case AMInterface::input::IInputSemanticRuntime::TerminalNameState::
      Nonexistent:
  default:
    return AMInterface::style::StyleIndex::NonexistentTerminalName;
  }
}

AMInterface::style::StyleIndex ChannelStyleKey_(
    AMInterface::input::IInputSemanticRuntime::ChannelNameState state) {
  switch (state) {
  case AMInterface::input::IInputSemanticRuntime::ChannelNameState::OK:
    return AMInterface::style::StyleIndex::ChannelName;
  case AMInterface::input::IInputSemanticRuntime::ChannelNameState::
      Disconnected:
    return AMInterface::style::StyleIndex::DisconnectedChannelName;
  case AMInterface::input::IInputSemanticRuntime::ChannelNameState::
      Nonexistent:
    return AMInterface::style::StyleIndex::NonexistentChannelName;
  case AMInterface::input::IInputSemanticRuntime::ChannelNameState::ValidNew:
    return AMInterface::style::StyleIndex::ValidNewChannelName;
  case AMInterface::input::IInputSemanticRuntime::ChannelNameState::
      InvalidNew:
  default:
    return AMInterface::style::StyleIndex::InvalidNewChannelName;
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
      const auto state = runtime->QueryTerminalNameState(name_item.name);
      candidate.display = FormatWithStyle_(ctx, name_item.name,
                                           TerminalStyleKey_(state));
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

  const bool channel_existing_target =
      HasTarget(ctx, AMCompletionTarget::ChannelTargetExisting);
  const bool channel_new_target =
      HasTarget(ctx, AMCompletionTarget::ChannelTargetNew);
  const bool channel_create_or_use_target =
      HasTarget(ctx, AMCompletionTarget::SshChannelTarget);
  if (channel_existing_target || channel_new_target ||
      channel_create_or_use_target) {
    if (channel_create_or_use_target && !channel_existing_target &&
        !channel_new_target) {
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
        const auto state = runtime->QueryTerminalNameState(name_item.name);
        candidate.display =
            FormatWithStyle_(ctx, name_item.name, TerminalStyleKey_(state));
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

    const TargetSemantics_ semantics =
        channel_existing_target
            ? TargetSemantics_::ExistingOnly
            : (channel_new_target ? TargetSemantics_::NewOnly
                                  : TargetSemantics_::ExistingOrNew);
    const TerminalChannelTarget_ target =
        ParseTerminalChannelTarget_(prefix, runtime->CurrentNickname());

    const std::vector<std::string> channels =
        runtime->ListChannelNames(target.terminal_name);
    std::vector<std::string> keys;
    keys.reserve(channels.size());
    for (const auto &name : channels) {
      keys.push_back(name);
    }

    for (const auto &match : BuildGeneralMatch(keys, target.channel_prefix)) {
      const std::string &channel_name = channels[match.index];
      auto state = runtime->QueryChannelNameState(target.terminal_name,
                                                  channel_name, false);
      if (semantics == TargetSemantics_::ExistingOnly &&
          state == AMInterface::input::IInputSemanticRuntime::
                       ChannelNameState::Nonexistent) {
        continue;
      }
      AMCompletionCandidate candidate;
      candidate.insert_text = target.insert_header + channel_name;
      candidate.display =
          FormatWithStyle_(ctx, channel_name, ChannelStyleKey_(state));
      candidate.kind = AMCompletionKind::ChannelName;
      candidate.score = match.score_bias;
      result.items.push_back(std::move(candidate));
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
