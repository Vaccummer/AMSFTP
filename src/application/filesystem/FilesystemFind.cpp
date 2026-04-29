#include "application/filesystem/FileSystemAppService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <deque>
#include <optional>
#include <regex>
#include <unordered_map>
#include <unordered_set>

namespace AMApplication::filesystem {

using AMDomain::filesystem::SearchType;

namespace {
using ClientMetaData = AMDomain::host::ClientMetaData;
enum class SegmentKind { Literal = 0, Pattern = 1, DoubleStar = 2 };
struct CompiledSegment {
  SegmentKind kind = SegmentKind::Literal;
  std::string raw = "";
  std::shared_ptr<std::wregex> regex = nullptr;
};
struct Cursor {
  PathInfo node = {};
  size_t segment_index = 0;
};

std::optional<ECM> BuildFindStopECM_(const ControlComponent &control,
                                     const std::string &operation,
                                     const std::string &target = "") {
  if (auto stop_rcm = control.BuildRequestECM(operation, target);
      stop_rcm.has_value()) {
    return stop_rcm;
  }
  return control.BuildECM(operation, target);
}

bool TypeMatches_(SearchType type, PathType node_type) {
  return type == SearchType::All ||
         (type == SearchType::Directory && node_type == PathType::DIR) ||
         (type == SearchType::File && node_type == PathType::FILE);
}

bool IsMatchPattern_(const std::string &segment) {
  return segment.find('*') != std::string::npos ||
         (segment.find('<') != std::string::npos &&
          segment.find('>') != std::string::npos);
}

void AppendEscapedRegexChar_(std::string *regex, char c) {
  if (!regex) {
    return;
  }
  switch (c) {
  case '\\':
  case '^':
  case '$':
  case '.':
  case '|':
  case '?':
  case '+':
  case '(':
  case ')':
  case '[':
  case ']':
  case '{':
  case '}':
    regex->push_back('\\');
    break;
  default:
    break;
  }
  regex->push_back(c);
}

std::wstring BuildSegmentRegex_(const std::string &segment) {
  std::string regex = "^";
  for (size_t i = 0; i < segment.size(); ++i) {
    const char c = segment[i];
    if (c == '*') {
      regex += ".*";
      continue;
    }
    if (c == '<') {
      const size_t close = segment.find('>', i + 1);
      if (close != std::string::npos && close > i + 1) {
        regex.push_back('[');
        regex += segment.substr(i + 1, close - i - 1);
        regex.push_back(']');
        i = close;
        continue;
      }
    }
    AppendEscapedRegexChar_(&regex, c);
  }
  regex.push_back('$');
  return AMStr::wstr(regex);
}

CompiledSegment CompileSegment_(const std::string &segment) {
  CompiledSegment out = {};
  out.raw = segment;
  if (segment == "**") {
    out.kind = SegmentKind::DoubleStar;
    return out;
  }
  if (!IsMatchPattern_(segment)) {
    out.kind = SegmentKind::Literal;
    return out;
  }
  out.kind = SegmentKind::Pattern;
  try {
    out.regex = std::make_shared<std::wregex>(BuildSegmentRegex_(segment));
  } catch (const std::regex_error &) {
    out.regex = nullptr;
  }
  return out;
}

bool SegmentHit_(const CompiledSegment &segment, const std::string &name) {
  if (segment.kind == SegmentKind::DoubleStar) {
    return true;
  }
  if (segment.kind == SegmentKind::Literal) {
    return name == segment.raw;
  }
  if (!segment.regex) {
    return false;
  }
  try {
    return std::regex_match(AMStr::wstr(name), *segment.regex);
  } catch (const std::regex_error &) {
    return false;
  }
}

std::string ResolveWorkdirFromMeta_(const ClientMetaData &meta,
                                    const std::string &home) {
  const std::string normalized_cwd =
      AMDomain::filesystem::service::NormalizePath(AMStr::Strip(meta.cwd));
  if (!normalized_cwd.empty()) {
    return normalized_cwd;
  }

  const std::string normalized_login_dir =
      AMDomain::filesystem::service::NormalizePath(
          AMStr::Strip(meta.login_dir));
  if (!normalized_login_dir.empty()) {
    return normalized_login_dir;
  }

  const std::string normalized_home =
      AMDomain::filesystem::service::NormalizePath(AMStr::Strip(home));
  if (!normalized_home.empty()) {
    return normalized_home;
  }
  return ".";
}

PathTarget BuildPathTarget_(const std::string &nickname,
                            const std::string &path) {
  PathTarget out = {};
  out.nickname = nickname;
  out.path = path;
  return out;
}

std::pair<std::string, std::vector<std::string>>
SplitLiteralRootAndSegments_(const std::string &abs_pattern) {
  std::string literal_root = ".";
  std::vector<std::string> segments = {};
  const std::vector<std::string> parts = AMPath::split(abs_pattern);
  if (parts.empty()) {
    return {literal_root, segments};
  }
  if (parts.size() == 1 && IsMatchPattern_(parts[0])) {
    segments.push_back(parts[0]);
    return {literal_root, segments};
  }

  literal_root = parts[0];
  bool wildcard_started = false;
  for (size_t i = 1; i < parts.size(); ++i) {
    if (!wildcard_started && !IsMatchPattern_(parts[i])) {
      literal_root = AMPath::join(literal_root, parts[i]);
      continue;
    }
    wildcard_started = true;
    segments.push_back(parts[i]);
  }
  return {literal_root, segments};
}

std::vector<CompiledSegment>
CompileSegments_(const std::vector<std::string> &segments) {
  std::vector<CompiledSegment> compiled = {};
  compiled.reserve(segments.size());
  for (const auto &seg : segments) {
    CompiledSegment one = CompileSegment_(seg);
    if (!compiled.empty() && compiled.back().kind == SegmentKind::DoubleStar &&
        one.kind == SegmentKind::DoubleStar) {
      continue;
    }
    compiled.push_back(std::move(one));
  }
  return compiled;
}

void SortAndDedupResults_(std::vector<PathInfo> *results) {
  if (!results) {
    return;
  }
  std::ranges::sort(*results, {}, &PathInfo::path);
  *results = AMStr::DedupVectorKeepOrder(
      *results, [](const PathInfo &info) { return info.path; });
}
} // namespace

ECMData<std::vector<PathInfo>> FilesystemAppService::find(
    const PathTarget &path, SearchType type, const ControlComponent &control,
    std::function<void(const PathTarget &)> on_enter_dir,
    std::function<void(const PathTarget &, ECM)> on_error,
    std::function<bool(const PathTarget &)> on_match) {
  auto notify_error = [&](const PathTarget &cp, ECM rcm) -> ECM {
    const ECM cb_rcm = CallCallbackSafe(on_error, cp, rcm);
    return (cb_rcm) ? OK : cb_rcm;
  };
  auto notify_enter = [&](const PathTarget &cp) -> ECM {
    const ECM cb_rcm = CallCallbackSafe(on_enter_dir, cp);
    return (cb_rcm) ? OK : cb_rcm;
  };
  auto notify_match = [&](const PathTarget &cp) -> ECMData<bool> {
    if (!on_match) {
      return {true, OK};
    }
    auto [keep_going, cb_rcm] = CallCallbackSafeRet<bool>(on_match, cp);
    if (!(cb_rcm)) {
      return {false, cb_rcm};
    }
    return {keep_going, OK};
  };

  auto resolved_result = ResolvePath_(path, control);
  if (!(resolved_result.rcm) || !resolved_result.data.client) {
    const ECM rcm =
        (resolved_result.rcm) ? Err(EC::InvalidHandle, "find.resolve", "",
                                    "Resolved client is null")
                              : resolved_result.rcm;
    TraceFs_(rcm, path, "filesystem.find", "resolve failed");
    return {{}, rcm};
  }
  const auto &resolved = resolved_result.data;

  AMDomain::client::ClientHandle client = resolved.client;
  std::string nickname = resolved.target.nickname;
  if (nickname.empty()) {
    nickname = "local";
  }
  std::string raw_pattern = resolved.abs_path.empty() ? "." : resolved.abs_path;

  ClientMetaData metadata = {};
  auto metadata_value = ClientAppService::GetClientMetadata(client);
  if (metadata_value.has_value()) {
    metadata = *metadata_value;
  }
  const std::string home_dir = client->ConfigPort().GetHomeDir();
  const std::string cwd = ResolveWorkdirFromMeta_(metadata, home_dir);
  const std::string abs_pattern =
      AMPath::abspath(raw_pattern, true, home_dir, cwd);

  auto [literal_root, segments] = SplitLiteralRootAndSegments_(abs_pattern);
  std::vector<CompiledSegment> compiled = CompileSegments_(segments);

  ECM final_rcm = OK;
  bool match_requested_stop = false;
  std::vector<PathInfo> results = {};
  std::unordered_set<std::string> matched_paths = {};
  const auto push_result = [&](const PathInfo &node) -> bool {
    if (!TypeMatches_(type, node.type)) {
      return true;
    }
    if (!matched_paths.insert(node.path).second) {
      return true;
    }
    results.push_back(node);
    auto match_rcm = notify_match(BuildPathTarget_(nickname, node.path));
    if (!(match_rcm.rcm)) {
      final_rcm = match_rcm.rcm;
      match_requested_stop = true;
      return false;
    }
    if (!match_rcm.data) {
      final_rcm = Err(EC::Terminate, "find.on_match", "",
                      "Find terminated by on_match callback");
      match_requested_stop = true;
      return false;
    }
    return true;
  };

  auto stat_result = BaseStat(client, nickname, literal_root, control);
  if (!(stat_result.rcm)) {
    PathTarget error_path = BuildPathTarget_(nickname, literal_root);
    const ECM cb_rcm = notify_error(error_path, stat_result.rcm);
    if (!(cb_rcm)) {
      TraceFs_(cb_rcm, path, "filesystem.find", "error callback failed");
      return {std::move(results), cb_rcm};
    }
    TraceFs_(stat_result.rcm, path, "filesystem.find", "root stat failed");
    return {std::move(results), stat_result.rcm};
  }

  if (compiled.empty()) {
    (void)push_result(stat_result.data);
    SortAndDedupResults_(&results);
    TraceFs_(final_rcm, path, "filesystem.find",
             AMStr::fmt("matches={}", results.size()));
    return {std::move(results), final_rcm};
  }

  std::deque<Cursor> pending = {};
  std::unordered_set<std::string> visited = {};
  std::unordered_map<std::string, std::vector<PathInfo>> dir_cache = {};
  const auto push_state = [&](const Cursor &cursor) {
    const std::string key =
        cursor.node.path + '\x1F' + std::to_string(cursor.segment_index);
    if (!visited.insert(key).second) {
      return;
    }
    pending.push_back(cursor);
  };
  const auto load_children =
      [&](const Cursor &cursor) -> ECMData<std::vector<PathInfo> *> {
    if (auto stop_rcm =
            BuildFindStopECM_(control, "find.listdir",
                              cursor.node.path);
        stop_rcm.has_value()) {
      return {nullptr, *stop_rcm};
    }

    auto cache_it = dir_cache.find(cursor.node.path);
    if (cache_it != dir_cache.end()) {
      return {&(cache_it->second), OK};
    }

    const ECM enter_cb_rcm =
        notify_enter(BuildPathTarget_(nickname, cursor.node.path));
    if (!(enter_cb_rcm)) {
      return {nullptr, enter_cb_rcm};
    }

    auto list_result = BaseListdir(client, nickname, cursor.node.path, control);
    if (!(list_result.rcm)) {
      if ((final_rcm)) {
        final_rcm = list_result.rcm;
      }
      const ECM error_cb_rcm = notify_error(
          BuildPathTarget_(nickname, cursor.node.path), list_result.rcm);
      if (!(error_cb_rcm)) {
        return {nullptr, error_cb_rcm};
      }
      return {nullptr, OK};
    }

    auto insert_it =
        dir_cache.emplace(cursor.node.path, std::move(list_result.data)).first;
    return {&(insert_it->second), OK};
  };
  push_state(Cursor(stat_result.data, 0));

  while (!pending.empty()) {
    if (match_requested_stop) {
      break;
    }
    if (auto stop_rcm =
            BuildFindStopECM_(control, "find.traverse",
                              pending.front().node.path);
        stop_rcm.has_value()) {
      final_rcm = *stop_rcm;
      break;
    }
    Cursor cur = pending.front();
    pending.pop_front();

    if (cur.segment_index >= compiled.size()) {
      if (!push_result(cur.node)) {
        break;
      }
      continue;
    }

    const CompiledSegment &seg = compiled[cur.segment_index];
    if (seg.kind == SegmentKind::DoubleStar) {
      push_state(Cursor(cur.node, cur.segment_index + 1));
      if (cur.node.type != PathType::DIR) {
        continue;
      }

      auto children_result = load_children(cur);
      if (!(children_result.rcm)) {
        return {std::move(results), children_result.rcm};
      }
      if (children_result.data == nullptr) {
        continue;
      }
      for (const auto &child : *children_result.data) {
        if (match_requested_stop) {
          break;
        }
        if (auto stop_rcm =
                BuildFindStopECM_(control, "find.walk-double-star",
                                  child.path);
            stop_rcm.has_value()) {
          final_rcm = *stop_rcm;
          break;
        }
        push_state(Cursor(child, cur.segment_index));
      }
      continue;
    }

    if (cur.node.type != PathType::DIR) {
      continue;
    }

    auto children_result = load_children(cur);
    if (!(children_result.rcm)) {
      return {std::move(results), children_result.rcm};
    }
    if (children_result.data == nullptr) {
      continue;
    }

    for (const auto &child : *children_result.data) {
      if (match_requested_stop) {
        break;
      }
      if (auto stop_rcm =
              BuildFindStopECM_(control, "find.match-segment",
                                child.path);
          stop_rcm.has_value()) {
        final_rcm = *stop_rcm;
        break;
      }
      if (!SegmentHit_(seg, child.name)) {
        continue;
      }
      push_state(Cursor(child, cur.segment_index + 1));
    }
  }

  SortAndDedupResults_(&results);
  TraceFs_(final_rcm, path, "filesystem.find",
           AMStr::fmt("matches={}", results.size()));
  return {std::move(results), final_rcm};
}
} // namespace AMApplication::filesystem
