#include "AMCLI/Completer/Searcher.hpp"
#include "AMCLI/Completer/SearcherCommon.hpp"
#include "AMBase/CommonTools.hpp"
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
} // namespace

/**
 * @brief Collect internal-value candidates.
 */
AMCompletionCollectResult
AMInternalSearchEngine::CollectCandidates(const AMCompletionContext &ctx) {
  AMCompletionCollectResult result;
  const std::string prefix = ctx.token_prefix;

  if (HasTarget(ctx, AMCompletionTarget::VariableName)) {
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

    std::vector<VarInfo> items;
    std::vector<std::string> keys;
    items.reserve(by_name.size());
    keys.reserve(by_name.size());
    for (const auto &entry : by_name) {
      items.push_back(entry.second);
      keys.push_back("$" + entry.second.varname);
    }
    std::sort(items.begin(), items.end(),
              [](const VarInfo &lhs, const VarInfo &rhs) {
                return lhs.varname < rhs.varname;
              });
    keys.clear();
    keys.reserve(items.size());
    for (const auto &item : items) {
      keys.push_back("$" + item.varname);
    }

    for (const auto &match : BuildGeneralMatch(keys, prefix)) {
      const auto &item = items[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = "$" + item.varname;
      candidate.display = config_manager_.Format(candidate.insert_text,
                                                 "public_varname");
      candidate.help = AMStr::amfmt("[{}] {}", item.domain,
                                    RenderVarValue_(item.varvalue));
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
    bool append_at = false;
    std::string client_prefix = prefix;
    if (HasTarget(ctx, AMCompletionTarget::Path)) {
      const size_t at_pos = prefix.find('@');
      if (at_pos != std::string::npos) {
        client_prefix = prefix.substr(0, at_pos);
        append_at = true;
      } else if (prefix.empty() || !IsPathLikeText(prefix)) {
        append_at = true;
      }
    }
    auto names = client_manager_.GetClientNames();
    std::vector<std::string> keys = names;
    for (const auto &match : BuildGeneralMatch(keys, client_prefix)) {
      const std::string &name = names[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = append_at ? name + "@" : name;
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
    bool append_at = false;
    std::string host_prefix = prefix;
    if (HasTarget(ctx, AMCompletionTarget::Path)) {
      const size_t at_pos = prefix.find('@');
      if (at_pos != std::string::npos) {
        host_prefix = prefix.substr(0, at_pos);
        append_at = true;
      } else if (prefix.empty() || !IsPathLikeText(prefix)) {
        append_at = true;
      }
    }
    auto names = host_manager_.ListNames();
    std::vector<std::string> keys = names;
    for (const auto &match : BuildGeneralMatch(keys, host_prefix)) {
      const std::string &name = names[match.index];
      AMCompletionCandidate candidate;
      candidate.insert_text = append_at ? name + "@" : name;
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
