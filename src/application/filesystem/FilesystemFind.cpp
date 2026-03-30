#include "application/filesystem/FilesystemAppService.hpp"

#include "domain/host/HostModel.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <deque>
#include <regex>
#include <unordered_map>
#include <unordered_set>

namespace AMApplication::filesystem {
ECMData<std::vector<PathInfo>> FilesystemAppService::find(
    const ClientPath &path, SearchType type,
    const ClientControlComponent &control,
    std::function<void(const ClientPath &)> on_enter_dir,
    std::function<void(const ClientPath &, ECM)> on_error,
    std::function<bool(const ClientPath &)> on_match) {
  using ClientMetaData = AMDomain::host::ClientMetaData;
  enum SegmentKind { Literal = 0, Pattern = 1, DoubleStar = 2 };
  struct CompiledSegment {
    SegmentKind kind = Literal;
    std::string raw = "";
    std::shared_ptr<std::wregex> regex = nullptr;
  };
  struct Cursor {
    PathInfo node = {};
    size_t segment_index = 0;
  };

  const auto current_stop_error = [&control]() -> ECM {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Operation interrupted");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "Operation timed out");
    }
    return Ok();
  };
  auto notify_error = [&](const ClientPath &cp, ECM rcm) -> ECM {
    const ECM cb_rcm = CallCallbackSafe(on_error, cp, rcm);
    return isok(cb_rcm) ? Ok() : cb_rcm;
  };
  auto notify_enter = [&](const ClientPath &cp) -> ECM {
    const ECM cb_rcm = CallCallbackSafe(on_enter_dir, cp);
    return isok(cb_rcm) ? Ok() : cb_rcm;
  };
  auto notify_match = [&](const ClientPath &cp) -> ECMData<bool> {
    if (!on_match) {
      return {true, Ok()};
    }
    auto [keep_going, cb_rcm] = CallCallbackSafeRet<bool>(on_match, cp);
    if (!isok(cb_rcm)) {
      return {false, cb_rcm};
    }
    return {keep_going, Ok()};
  };
  const auto build_regex = [](const std::string &segment) -> std::wstring {
    std::string regex = "^";
    const auto append_escaped = [&regex](char c) {
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
        regex.push_back('\\');
        break;
      default:
        break;
      }
      regex.push_back(c);
    };

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
      append_escaped(c);
    }
    regex.push_back('$');
    return AMStr::wstr(regex);
  };
  const auto segment_hit = [](const CompiledSegment &segment,
                              const std::string &name) -> bool {
    if (segment.kind == DoubleStar) {
      return true;
    }
    if (segment.kind == Literal) {
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
  };
  const auto is_match_pattern = [](const std::string &segment) -> bool {
    return segment.find('*') != std::string::npos ||
           (segment.find('<') != std::string::npos &&
            segment.find('>') != std::string::npos);
  };
  const auto compile_segment =
      [&](const std::string &segment) -> CompiledSegment {
    CompiledSegment out = {};
    out.raw = segment;
    if (segment == "**") {
      out.kind = DoubleStar;
      return out;
    }
    if (!is_match_pattern(segment)) {
      out.kind = Literal;
      return out;
    }
    out.kind = Pattern;
    try {
      out.regex = std::make_shared<std::wregex>(build_regex(segment));
    } catch (const std::regex_error &) {
      out.regex = nullptr;
    }
    return out;
  };
  const auto workdir_from_meta = [](const ClientMetaData &meta,
                                    const std::string &home) -> std::string {
    if (!meta.cwd.empty()) {
      return meta.cwd;
    }
    if (!meta.login_dir.empty()) {
      return meta.login_dir;
    }
    if (!home.empty()) {
      return home;
    }
    return ".";
  };
  const auto normalize_nickname =
      [](const std::string &nickname) -> std::string {
    const std::string trimmed = AMStr::Strip(nickname);
    if (trimmed.empty()) {
      return "local";
    }
    return trimmed;
  };
  const auto type_ok = [type](PathType node_type) -> bool {
    return type == SearchType::All ||
           (type == SearchType::Directory && node_type == PathType::DIR) ||
           (type == SearchType::File && node_type == PathType::FILE);
  };
  const auto should_stop = [&]() -> bool {
    const ECM stop_rcm = current_stop_error();
    return !isok(stop_rcm);
  };

  std::vector<ClientPath> resolved = {path};
  ECM resolve_rcm = ResolvePath(resolved, control, true);
  if (!isok(resolve_rcm) || resolved.empty() || !resolved[0].client) {
    return {{},
            isok(resolve_rcm)
                ? Err(EC::InvalidHandle, "Resolved client is null")
                : resolve_rcm};
  }

  AMDomain::client::ClientHandle client = resolved[0].client;
  std::string nickname = normalize_nickname(resolved[0].nickname);
  std::string raw_pattern = resolved[0].path.empty() ? "." : resolved[0].path;

  ClientMetaData metadata = {};
  {
    auto &meta_port = client->MetaDataPort();
    auto lock = meta_port.GetLockGaurd();
    if (auto *value = meta_port.QueryTypedValue<ClientMetaData>(); value) {
      metadata = *value;
    }
  }
  const std::string home_dir = client->ConfigPort().GetHomeDir();
  const std::string cwd = workdir_from_meta(metadata, home_dir);
  const std::string abs_pattern =
      AMFS::abspath(raw_pattern, true, home_dir, cwd);

  std::string literal_root = ".";
  std::vector<std::string> segments = {};
  {
    const std::vector<std::string> parts = AMPathStr::split(abs_pattern);
    if (!parts.empty()) {
      if (parts.size() == 1 && is_match_pattern(parts[0])) {
        literal_root = ".";
        segments.push_back(parts[0]);
      } else {
        literal_root = parts[0];
        bool wildcard_started = false;
        for (size_t i = 1; i < parts.size(); ++i) {
          if (!wildcard_started && !is_match_pattern(parts[i])) {
            literal_root = AMPathStr::join(literal_root, parts[i]);
          } else {
            wildcard_started = true;
            segments.push_back(parts[i]);
          }
        }
      }
    }
  }

  std::vector<CompiledSegment> compiled = {};
  compiled.reserve(segments.size());
  for (const auto &seg : segments) {
    CompiledSegment one = compile_segment(seg);
    if (!compiled.empty() && compiled.back().kind == DoubleStar &&
        one.kind == DoubleStar) {
      continue;
    }
    compiled.push_back(std::move(one));
  }

  ECM final_rcm = Ok();
  bool match_requested_stop = false;
  std::vector<PathInfo> results = {};
  std::unordered_set<std::string> matched_paths = {};
  const auto make_client_path = [&](const std::string &p,
                                    ECM rcm) -> ClientPath {
    ClientPath cp = {};
    cp.nickname = nickname;
    cp.path = p;
    cp.client = client;
    cp.rcm = std::move(rcm);
    cp.is_wildcard = false;
    cp.userpath = false;
    return cp;
  };
  const auto push_result = [&](const PathInfo &node) -> bool {
    if (!type_ok(node.type)) {
      return true;
    }
    if (!matched_paths.insert(node.path).second) {
      return true;
    }
    results.push_back(node);
    auto match_rcm = notify_match(make_client_path(node.path, Ok()));
    if (!isok(match_rcm.rcm)) {
      final_rcm = match_rcm.rcm;
      match_requested_stop = true;
      return false;
    }
    if (!match_rcm.data) {
      final_rcm = Err(EC::Terminate, "Find terminated by on_match callback");
      match_requested_stop = true;
      return false;
    }
    return true;
  };

  auto stat_result = BaseStat(client, nickname, literal_root, control);
  if (!isok(stat_result.rcm)) {
    ClientPath error_path = make_client_path(literal_root, stat_result.rcm);
    const ECM cb_rcm = notify_error(error_path, stat_result.rcm);
    if (!isok(cb_rcm)) {
      return {std::move(results), cb_rcm};
    }
    return {std::move(results), stat_result.rcm};
  }

  if (compiled.empty()) {
    (void)push_result(stat_result.data);
    std::stable_sort(
        results.begin(), results.end(),
        [](const PathInfo &a, const PathInfo &b) { return a.path < b.path; });
    results.erase(std::unique(results.begin(), results.end(),
                              [](const PathInfo &a, const PathInfo &b) {
                                return a.path == b.path;
                              }),
                  results.end());
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
  push_state(Cursor{stat_result.data, 0});

  while (!pending.empty()) {
    if (match_requested_stop) {
      break;
    }
    if (should_stop()) {
      final_rcm = current_stop_error();
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
    if (seg.kind == DoubleStar) {
      push_state(Cursor{cur.node, cur.segment_index + 1});
      if (cur.node.type != PathType::DIR) {
        continue;
      }

      std::vector<PathInfo> *children = nullptr;
      auto cache_it = dir_cache.find(cur.node.path);
      if (cache_it != dir_cache.end()) {
        children = &(cache_it->second);
      } else {
        ClientPath enter_dir = make_client_path(cur.node.path, Ok());
        const ECM enter_cb_rcm = notify_enter(enter_dir);
        if (!isok(enter_cb_rcm)) {
          return {std::move(results), enter_cb_rcm};
        }

        auto list_result =
            BaseListdir(client, nickname, cur.node.path, control);
        if (!isok(list_result.rcm)) {
          if (isok(final_rcm)) {
            final_rcm = list_result.rcm;
          }
          ClientPath error_path =
              make_client_path(cur.node.path, list_result.rcm);
          const ECM error_cb_rcm = notify_error(error_path, list_result.rcm);
          if (!isok(error_cb_rcm)) {
            return {std::move(results), error_cb_rcm};
          }
          continue;
        }
        auto insert_it =
            dir_cache.emplace(cur.node.path, std::move(list_result.data))
                .first;
        children = &(insert_it->second);
      }

      for (const auto &child : *children) {
        if (match_requested_stop) {
          break;
        }
        if (should_stop()) {
          final_rcm = current_stop_error();
          break;
        }
        push_state(Cursor{child, cur.segment_index});
      }
      continue;
    }

    if (cur.node.type != PathType::DIR) {
      continue;
    }

    std::vector<PathInfo> *children = nullptr;
    auto cache_it = dir_cache.find(cur.node.path);
    if (cache_it != dir_cache.end()) {
      children = &(cache_it->second);
    } else {
      ClientPath enter_dir = make_client_path(cur.node.path, Ok());
      const ECM enter_cb_rcm = notify_enter(enter_dir);
      if (!isok(enter_cb_rcm)) {
        return {std::move(results), enter_cb_rcm};
      }

      auto list_result = BaseListdir(client, nickname, cur.node.path, control);
      if (!isok(list_result.rcm)) {
        if (isok(final_rcm)) {
          final_rcm = list_result.rcm;
        }
        ClientPath error_path =
            make_client_path(cur.node.path, list_result.rcm);
        const ECM error_cb_rcm = notify_error(error_path, list_result.rcm);
        if (!isok(error_cb_rcm)) {
          return {std::move(results), error_cb_rcm};
        }
        continue;
      }
      auto insert_it =
          dir_cache.emplace(cur.node.path, std::move(list_result.data))
              .first;
      children = &(insert_it->second);
    }

    for (const auto &child : *children) {
      if (match_requested_stop) {
        break;
      }
      if (should_stop()) {
        final_rcm = current_stop_error();
        break;
      }
      if (!segment_hit(seg, child.name)) {
        continue;
      }
      push_state(Cursor{child, cur.segment_index + 1});
    }
  }

  std::stable_sort(
      results.begin(), results.end(),
      [](const PathInfo &a, const PathInfo &b) { return a.path < b.path; });
  results.erase(std::unique(results.begin(), results.end(),
                            [](const PathInfo &a, const PathInfo &b) {
                              return a.path == b.path;
                            }),
                results.end());
  return {std::move(results), final_rcm};
}
} // namespace AMApplication::filesystem
