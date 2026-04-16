#include "application/filesystem/FilesystemAppService.hpp"
#include "foundation/tools/path.hpp"

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_set>

namespace AMApplication::filesystem {
namespace {

ECM CurrentStopError_(const ClientControlComponent &control) {
  if (control.IsInterrupted()) {
    return {EC::Terminate, "", "", "Operation interrupted"};
  }
  if (control.IsTimeout()) {
    return {EC::OperationTimeout, "", "", "Operation timed out"};
  }
  return OK;
}

void UpdateLastError_(ECM *last_error, const ECM &next) {
  if (last_error == nullptr || (next)) {
    return;
  }
  *last_error = next;
}

std::string ResolveEntryPath_(const std::string &parent,
                              const PathInfo &entry) {
  if (!entry.path.empty()) {
    return entry.path;
  }
  if (entry.name.empty()) {
    return parent;
  }
  if (parent.empty()) {
    return entry.name;
  }
  return AMPath::join(parent, entry.name);
}

PathTarget BuildCallbackPath_(const std::string &nickname,
                              const std::string &path) {
  PathTarget out = {};
  out.nickname = nickname;
  out.path = path;
  return out;
}

} // namespace

ECMData<int64_t> FilesystemAppService::GetSize(
    const PathTarget &path, const ClientControlComponent &control,
    std::function<bool(const PathTarget &, int64_t)> on_progress,
    std::function<void(const PathTarget &, ECM)> on_error) {
  int64_t total_size = 0;
  ECM last_error = OK;

  auto resolved_result = ResolvePath(path, control);
  if (!(resolved_result.rcm) || !resolved_result.data.client) {
    return {total_size, (resolved_result.rcm) ? Err(EC::InvalidHandle, "", "",
                                                    "Resolved client is null")
                                              : resolved_result.rcm};
  }
  const auto &resolved = resolved_result.data;

  ClientHandle client = resolved.client;
  std::string nickname = resolved.target.nickname;
  if (nickname.empty()) {
    nickname = client->ConfigPort().GetNickname();
  }
  if (nickname.empty()) {
    nickname = "local";
  }

  const auto notify_error = [&](const std::string &error_path,
                                const ECM &rcm) -> ECM {
    UpdateLastError_(&last_error, rcm);
    const PathTarget callback_path = BuildCallbackPath_(nickname, error_path);
    const ECM cb_rcm = CallCallbackSafe(on_error, callback_path, rcm);
    if (!(cb_rcm)) {
      UpdateLastError_(&last_error, cb_rcm);
      return cb_rcm;
    }
    return OK;
  };

  const auto notify_progress = [&](const std::string &current_path) -> ECM {
    if (!on_progress) {
      return OK;
    }
    const PathTarget callback_path = BuildCallbackPath_(nickname, current_path);
    auto [keep_going, cb_rcm] =
        CallCallbackSafeRet<bool>(on_progress, callback_path, total_size);
    if (!(cb_rcm)) {
      UpdateLastError_(&last_error, cb_rcm);
      return cb_rcm;
    }
    if (!keep_going) {
      const ECM stop_rcm = Err(EC::Terminate, "", "",
                               "GetSize terminated by on_progress callback");
      UpdateLastError_(&last_error, stop_rcm);
      return stop_rcm;
    }
    return OK;
  };

  const ECM stop_rcm = CurrentStopError_(control);
  if (!(stop_rcm)) {
    return {total_size, stop_rcm};
  }

  auto root_stat =
      BaseStat(client, nickname, resolved.abs_path, control, false);
  if (!(root_stat.rcm)) {
    const ECM cb_rcm = notify_error(resolved.abs_path, root_stat.rcm);
    if (!(cb_rcm)) {
      return {total_size, cb_rcm};
    }
    return {total_size, last_error};
  }

  if (root_stat.data.type != PathType::DIR) {
    total_size = static_cast<int64_t>(root_stat.data.size);
    const ECM cb_rcm = notify_progress(resolved.abs_path);
    if (!(cb_rcm)) {
      return {total_size, cb_rcm};
    }
    return {total_size, last_error};
  }

  std::string root_dir = root_stat.data.path;
  if (root_dir.empty()) {
    root_dir = resolved.abs_path.empty() ? "." : resolved.abs_path;
  }

  std::deque<std::string> pending_dirs = {root_dir};
  std::unordered_set<std::string> visited_dirs = {root_dir};

  while (!pending_dirs.empty()) {
    const ECM loop_stop_rcm = CurrentStopError_(control);
    if (!loop_stop_rcm) {
      UpdateLastError_(&last_error, loop_stop_rcm);
      return {total_size, last_error};
    }

    std::string current_dir = std::move(pending_dirs.front());
    pending_dirs.pop_front();

    auto list_result = BaseListdir(client, nickname, current_dir, control);
    if (!list_result.rcm) {
      const ECM cb_rcm = notify_error(current_dir, list_result.rcm);
      if (!(cb_rcm)) {
        return {total_size, cb_rcm};
      }
      continue;
    }

    for (const auto &entry : list_result.data) {
      const ECM item_stop_rcm = CurrentStopError_(control);
      if (!(item_stop_rcm)) {
        UpdateLastError_(&last_error, item_stop_rcm);
        return {total_size, last_error};
      }

      const std::string entry_path = ResolveEntryPath_(current_dir, entry);
      if (entry.type == PathType::DIR) {
        if (!entry_path.empty() && visited_dirs.insert(entry_path).second) {
          pending_dirs.push_back(entry_path);
        }
        continue;
      }

      if (entry.type != PathType::FILE) {
        continue;
      }

      const int64_t previous = total_size;
      total_size += static_cast<int64_t>(entry.size);
      if (total_size != previous) {
        const ECM cb_rcm =
            notify_progress(entry_path.empty() ? current_dir : entry_path);
        if (!(cb_rcm)) {
          return {total_size, cb_rcm};
        }
      }
    }
  }

  return {total_size, last_error};
}

} // namespace AMApplication::filesystem


