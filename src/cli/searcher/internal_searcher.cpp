#include "AMBase/CommonTools.hpp"
#include "AMCLI/Completer/Searcher.hpp"
#include "AMCLI/Completer/SearcherCommon.hpp"
#include <algorithm>
#include <unordered_map>

using namespace AMSearcherDetail;

namespace {
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
      items = var_manager_.ListByDomain(prefix_ref.domain);
    } else {
      const std::string current_domain = var_manager_.CurrentDomain();
      std::unordered_map<std::string, VarInfo> by_name;
      auto private_vars = var_manager_.ListByDomain(current_domain);
      for (const auto &item : private_vars) {
        by_name[item.varname] = item;
      }
      auto public_vars = var_manager_.ListByDomain(varsetkn::kPublic);
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
      candidate.display =
          config_manager_.Format(candidate.insert_text, "public_varname");
      candidate.help =
          AMStr::amfmt("[{}] {}", item.domain, RenderVarValue_(item.varvalue));
      candidate.kind = AMCompletionKind::VariableName;
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
    auto names = client_manager_.GetClientNames();
    std::vector<std::string> keys = names;
    for (const auto &match : BuildGeneralMatch(keys, client_prefix)) {
      const std::string &name = names[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = path_nickname_context ? name + "@" : name;
      candidate.display = name;
      candidate.kind = AMCompletionKind::ClientName;
      candidate.score = match.score_bias;
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
    auto names = host_manager_.ListNames();
    std::vector<std::string> keys = names;
    for (const auto &match : BuildGeneralMatch(keys, host_prefix)) {
      const std::string &name = names[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = path_nickname_context ? name + "@" : name;
      candidate.display = name;
      candidate.kind = AMCompletionKind::HostNickname;
      candidate.score = match.score_bias;
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
    auto ids = transfer_manager_.ListTaskIds();
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
