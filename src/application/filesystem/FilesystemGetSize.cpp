#include "application/filesystem/FilesystemAppService.hpp"

#include "foundation/tools/path.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_set>

namespace AMApplication::filesystem {
namespace {

ECM CurrentStopError_(const ClientControlComponent &control) {
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, "Operation interrupted");
  }
  if (control.IsTimeout()) {
    return Err(EC::OperationTimeout, "Operation timed out");
  }
  return Ok();
}

void UpdateLastError_(ECM *last_error, const ECM &next) {
  if (last_error == nullptr || isok(next)) {
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

ClientPath BuildCallbackPath_(const std::string &nickname, ClientHandle client,
                              const std::string &path, const ECM &rcm) {
  ClientPath out = {};
  out.nickname = nickname;
  out.path = path;
  out.client = client;
  out.rcm = rcm;
  return out;
}

} // namespace

ECMData<int64_t> FilesystemAppService::GetSize(
    ClientPath path, const ClientControlComponent &control,
    std::function<bool(const ClientPath &, int64_t)> on_progress,
    std::function<void(const ClientPath &, ECM)> on_error) {
  int64_t total_size = 0;
  ECM last_error = Ok();

  const ECM resolve_rcm = ResolvePath(path, control);
  if (!isok(resolve_rcm) || !path.client) {
    return {total_size,
            isok(resolve_rcm)
                ? Err(EC::InvalidHandle, "Resolved client is null")
                : resolve_rcm};
  }

  ClientHandle client = path.client;
  std::string nickname = AMStr::Strip(path.nickname);
  if (nickname.empty()) {
    nickname = AMStr::Strip(client->ConfigPort().GetNickname());
  }
  if (nickname.empty()) {
    nickname = "local";
  }

  const auto notify_error = [&](const std::string &error_path,
                                const ECM &rcm) -> ECM {
    UpdateLastError_(&last_error, rcm);
    const ClientPath callback_path =
        BuildCallbackPath_(nickname, client, error_path, rcm);
    const ECM cb_rcm = CallCallbackSafe(on_error, callback_path, rcm);
    if (!isok(cb_rcm)) {
      UpdateLastError_(&last_error, cb_rcm);
      return cb_rcm;
    }
    return Ok();
  };

  const auto notify_progress = [&](const std::string &current_path) -> ECM {
    if (!on_progress) {
      return Ok();
    }
    const ClientPath callback_path =
        BuildCallbackPath_(nickname, client, current_path, Ok());
    auto [keep_going, cb_rcm] =
        CallCallbackSafeRet<bool>(on_progress, callback_path, total_size);
    if (!isok(cb_rcm)) {
      UpdateLastError_(&last_error, cb_rcm);
      return cb_rcm;
    }
    if (!keep_going) {
      const ECM stop_rcm =
          Err(EC::Terminate, "GetSize terminated by on_progress callback");
      UpdateLastError_(&last_error, stop_rcm);
      return stop_rcm;
    }
    return Ok();
  };

  const ECM stop_rcm = CurrentStopError_(control);
  if (!isok(stop_rcm)) {
    return {total_size, stop_rcm};
  }

  auto root_stat = BaseStat(client, nickname, path.path, control, false);
  if (!isok(root_stat.rcm)) {
    const ECM cb_rcm = notify_error(path.path, root_stat.rcm);
    if (!isok(cb_rcm)) {
      return {total_size, cb_rcm};
    }
    return {total_size, last_error};
  }

  if (root_stat.data.type != PathType::DIR) {
    total_size = static_cast<int64_t>(root_stat.data.size);
    const ECM cb_rcm = notify_progress(path.path);
    if (!isok(cb_rcm)) {
      return {total_size, cb_rcm};
    }
    return {total_size, last_error};
  }

  std::string root_dir = root_stat.data.path;
  if (root_dir.empty()) {
    root_dir = path.path;
  }
  if (root_dir.empty()) {
    root_dir = ".";
  }

  std::deque<std::string> pending_dirs = {root_dir};
  std::unordered_set<std::string> visited_dirs = {root_dir};

  while (!pending_dirs.empty()) {
    const ECM loop_stop_rcm = CurrentStopError_(control);
    if (!isok(loop_stop_rcm)) {
      UpdateLastError_(&last_error, loop_stop_rcm);
      return {total_size, last_error};
    }

    std::string current_dir = std::move(pending_dirs.front());
    pending_dirs.pop_front();

    auto list_result = BaseListdir(client, nickname, current_dir, control);
    if (!isok(list_result.rcm)) {
      const ECM cb_rcm = notify_error(current_dir, list_result.rcm);
      if (!isok(cb_rcm)) {
        return {total_size, cb_rcm};
      }
      continue;
    }

    for (const auto &entry : list_result.data) {
      const ECM item_stop_rcm = CurrentStopError_(control);
      if (!isok(item_stop_rcm)) {
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
        if (!isok(cb_rcm)) {
          return {total_size, cb_rcm};
        }
      }
    }
  }

  return {total_size, last_error};
}

} // namespace AMApplication::filesystem
