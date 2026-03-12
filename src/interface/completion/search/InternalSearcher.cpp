#include "interface/completion/Searcher.hpp"
#include "interface/completion/SearcherCommon.hpp"
#include "domain/host/HostModel.hpp"
#include "interface/adapters/ApplicationAdapters.hpp"
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

using namespace AMSearcherDetail;
namespace Runtime = AMInterface::ApplicationAdapters::Runtime;

using AMDomain::var::VarInfo;

namespace {
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
std::vector<HostLikeNameInfo> CollectHostLikeNames_() {
  std::vector<HostLikeNameInfo> names;
  std::unordered_set<std::string> seen;

  auto add_name = [&](const std::string &name, bool created) {
    const std::string key = AMStr::lowercase(name);
    if (key.empty() || !seen.insert(key).second) {
      return;
    }
    names.push_back({name, created});
  };

  std::vector<std::string> created_names = Runtime::ListClientNames();
  std::sort(created_names.begin(), created_names.end());
  for (const auto &name : created_names) {
    add_name(name, true);
  }
  add_name("local", true);

  std::vector<std::string> configured_names = Runtime::ListHostNames();
  std::sort(configured_names.begin(), configured_names.end());
  for (const auto &name : configured_names) {
    add_name(name, false);
  }

  return names;
}

/**
 * @brief Parse variable completion prefix from token prefix text.
 */
bool ParseVarCompletionPrefix_(const std::string &prefix,
                               varsetkn::VarRef *out_ref) {
  if (!out_ref || prefix.empty() || prefix.front() != '$') {
    return false;
  }
  if (prefix == "$") {
    out_ref->valid = true;
    out_ref->braced = false;
    out_ref->has_closing_brace = false;
    out_ref->explicit_domain = false;
    out_ref->domain.clear();
    out_ref->zone_token.clear();
    out_ref->varname.clear();
    return true;
  }
  if (prefix == "${") {
    out_ref->valid = true;
    out_ref->braced = true;
    out_ref->has_closing_brace = false;
    out_ref->explicit_domain = false;
    out_ref->domain.clear();
    out_ref->zone_token.clear();
    out_ref->varname.clear();
    return true;
  }
  size_t end = 0;
  varsetkn::VarRef ref{};
  if (!varsetkn::ParseVarRefAt(prefix, 0, prefix.size(), true, true, &end,
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

/**
 * @brief Classify one zone name into style key.
 */
std::string ZoneStyleKey_(const std::string &zone, bool domain_exists,
                          bool host_exists) {
  if (domain_exists || zone == varsetkn::kPublic) {
    return "nickname";
  }
  if (host_exists) {
    return "unestablished_nickname";
  }
  return "nonexistent_nickname";
}
} // namespace

/**
 * @brief Collect internal-value candidates.
 */
AMCompletionCollectResult
AMInternalSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCollectResult result;
  const std::string prefix = ctx.token_prefix;

  if (HasTarget(ctx, AMCompletionTarget::VariableName)) {
    varsetkn::VarRef prefix_ref{};
    if (!ParseVarCompletionPrefix_(prefix, &prefix_ref)) {
      return result;
    }

    std::vector<VarInfo> items;
    if (prefix_ref.explicit_domain) {
      items = Runtime::ListVarsByDomain(prefix_ref.domain);
    } else {
      const std::string current_domain = Runtime::CurrentVarDomain();
      std::unordered_map<std::string, VarInfo> by_name;
      auto private_vars = Runtime::ListVarsByDomain(current_domain);
      for (const auto &item : private_vars) {
        by_name[item.varname] = item;
      }
      auto public_vars = Runtime::ListVarsByDomain(varsetkn::kPublic);
      for (const auto &item : public_vars) {
        if (by_name.find(item.varname) == by_name.end()) {
          by_name[item.varname] = item;
        }
      }
      items.reserve(by_name.size());
      for (const auto &entry : by_name) {
        items.push_back(entry.second);
      }
      std::sort(items.begin(), items.end(),
                [](const VarInfo &lhs, const VarInfo &rhs) {
                  return lhs.varname < rhs.varname;
                });
    }

    std::vector<std::string> keys;
    keys.reserve(items.size());
    for (const auto &item : items) {
      keys.push_back(item.varname);
    }

    const std::string name_prefix = prefix_ref.varname;
    for (const auto &match : BuildGeneralMatch(keys, name_prefix)) {
      const auto &item = items[match.index];
      varsetkn::VarRef candidate_ref = prefix_ref;
      candidate_ref.varname = item.varname;
      AMCompletionCandidate candidate;
      candidate.insert_text = varsetkn::BuildVarToken(candidate_ref, true);
      candidate.display = Runtime::Format(candidate.insert_text, "public_varname");
      candidate.help =
          AMStr::fmt("[{}] {}", item.domain, RenderVarValue_(item.varvalue));
      candidate.kind = AMCompletionKind::VariableName;
      candidate.score = match.score_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
    if (!result.candidates.items.empty()) {
      SortCandidates(ctx, result.candidates.items);
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
      bool domain_exists = false;
      bool host_exists = false;
    };
    std::vector<ZoneInfo> zones;
    std::unordered_map<std::string, size_t> zone_index;
    zones.reserve(16);

    auto append_zone = [&](const std::string &zone, bool domain_exists,
                           bool host_exists) {
      const auto it = zone_index.find(zone);
      if (it != zone_index.end()) {
        auto &existing = zones[it->second];
        existing.domain_exists = existing.domain_exists || domain_exists;
        existing.host_exists = existing.host_exists || host_exists;
        return;
      }
      zone_index[zone] = zones.size();
      zones.push_back({zone, domain_exists, host_exists});
    };

    const auto domains = Runtime::ListVarDomains();
    for (const auto &domain : domains) {
      append_zone(domain, true, Runtime::HostExists(domain));
    }
    const auto hosts = Runtime::ListHostNames();
    for (const auto &host : hosts) {
      append_zone(host, Runtime::HasVarDomain(host), true);
    }
    append_zone(varsetkn::kPublic, true, true);

    std::vector<std::string> keys;
    keys.reserve(zones.size());
    for (const auto &item : zones) {
      keys.push_back(item.zone);
    }

    for (const auto &match : BuildGeneralMatch(keys, zone_prefix)) {
      const auto &item = zones[match.index];
      AMCompletionCandidate candidate;
      if (mode == VarZonePrefixMode::Dollar) {
        candidate.insert_text =
            (item.zone == varsetkn::kPublic) ? "$:" : ("$" + item.zone + ":");
      } else if (mode == VarZonePrefixMode::BracedDollar) {
        candidate.insert_text =
            (item.zone == varsetkn::kPublic) ? "${:" : ("${" + item.zone + ":");
      } else {
        candidate.insert_text = item.zone;
      }
      const std::string style_key =
          ZoneStyleKey_(item.zone, item.domain_exists, item.host_exists);
      candidate.display = Runtime::Format(item.zone, style_key);
      candidate.kind = AMCompletionKind::VarZone;
      candidate.help.clear();
      candidate.score = match.score_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
    if (!result.candidates.items.empty()) {
      SortCandidates(ctx, result.candidates.items);
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

    std::vector<HostLikeNameInfo> names = CollectHostLikeNames_();

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
      const std::string style_key =
          name_item.created ? "nickname" : "unestablished_nickname";
      candidate.display = Runtime::Format(name_item.name, style_key);
      candidate.kind = AMCompletionKind::ClientName;
      const int uncreated_bias = name_item.created ? 0 : 100;
      candidate.score = match.score_bias + uncreated_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
    if (!result.candidates.items.empty()) {
      SortCandidates(ctx, result.candidates.items);
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
    std::vector<HostLikeNameInfo> names = CollectHostLikeNames_();
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
      const std::string style_key =
          name_item.created ? "nickname" : "unestablished_nickname";
      candidate.display = Runtime::Format(name_item.name, style_key);
      candidate.kind = AMCompletionKind::HostNickname;
      const int uncreated_bias = name_item.created ? 0 : 100;
      candidate.score = match.score_bias + uncreated_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
    if (!result.candidates.items.empty()) {
      SortCandidates(ctx, result.candidates.items);
    }
    return result;
  }

  if (HasTarget(ctx, AMCompletionTarget::HostAttr)) {
    std::vector<std::string> fields(configkn::fileds.begin(),
                                    configkn::fileds.end());
    for (const auto &match : BuildGeneralMatch(fields, prefix)) {
      const std::string &field = fields[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = field;
      candidate.display = field;
      candidate.kind = AMCompletionKind::HostAttr;
      candidate.score = match.score_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
    if (!result.candidates.items.empty()) {
      SortCandidates(ctx, result.candidates.items);
    }
    return result;
  }

  if (HasTarget(ctx, AMCompletionTarget::TaskId)) {
    auto ids = Runtime::ListTaskIds();
    std::vector<std::string> keys = ids;
    for (const auto &match : BuildGeneralMatch(keys, prefix)) {
      const std::string &id = ids[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = id;
      candidate.display = id;
      candidate.kind = AMCompletionKind::TaskId;
      candidate.score = match.score_bias;
      result.candidates.items.push_back(std::move(candidate));
    }
  }

  if (!result.candidates.items.empty()) {
    SortCandidates(ctx, result.candidates.items);
  }
  return result;
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

