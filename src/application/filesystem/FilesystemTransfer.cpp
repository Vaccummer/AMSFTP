#include "application/filesystem/FilesystemAppService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"

#include "foundation/tools/path.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <deque>
#include <unordered_set>

namespace AMApplication::filesystem {
namespace {
using EC = ErrorCode;
using ClientHandle = AMDomain::client::ClientHandle;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;

bool IsStopError_(ErrorCode ec) {
  return ec == ErrorCode::Terminate || ec == ErrorCode::OperationTimeout;
}

std::string JoinPathParts_(const std::vector<std::string> &parts,
                           size_t begin) {
  if (begin >= parts.size()) {
    return "";
  }
  std::string out = parts[begin];
  for (size_t i = begin + 1; i < parts.size(); ++i) {
    out = AMPath::join(out, parts[i]);
  }
  return out;
}

std::string RelativeFrom_(const std::string &root, const std::string &target) {
  if (root == target) {
    return "";
  }
  const std::vector<std::string> root_parts = AMPath::split(root);
  const std::vector<std::string> target_parts = AMPath::split(target);
  if (!root_parts.empty() && !target_parts.empty() &&
      target_parts.size() >= root_parts.size()) {
    bool is_prefix = true;
    for (size_t i = 0; i < root_parts.size(); ++i) {
      if (root_parts[i] != target_parts[i]) {
        is_prefix = false;
        break;
      }
    }
    if (is_prefix) {
      return JoinPathParts_(target_parts, root_parts.size());
    }
  }
  return AMPath::basename(target);
}

std::string BuildTaskKey_(const AMDomain::transfer::TransferTask &task) {
  return AMStr::fmt("{}\t{}\t{}\t{}\t{}\t{}\t{}", task.src_host, task.src,
                    task.dst_host, task.dst, static_cast<int>(task.path_type),
                    task.overwrite ? 1 : 0, task.transferred);
}

void DedupAndSortTasks_(std::vector<AMDomain::transfer::TransferTask> *tasks) {
  if (!tasks || tasks->empty()) {
    return;
  }
  std::stable_sort(tasks->begin(), tasks->end(),
                   [](const AMDomain::transfer::TransferTask &lhs,
                      const AMDomain::transfer::TransferTask &rhs) {
                     if (lhs.dst_host != rhs.dst_host) {
                       return lhs.dst_host < rhs.dst_host;
                     }
                     if (lhs.dst != rhs.dst) {
                       return lhs.dst < rhs.dst;
                     }
                     if (lhs.src_host != rhs.src_host) {
                       return lhs.src_host < rhs.src_host;
                     }
                     if (lhs.src != rhs.src) {
                       return lhs.src < rhs.src;
                     }
                     return static_cast<int>(lhs.path_type) <
                            static_cast<int>(rhs.path_type);
                   });

  std::unordered_set<std::string> seen = {};
  seen.reserve(tasks->size());
  std::vector<AMDomain::transfer::TransferTask> uniq = {};
  uniq.reserve(tasks->size());
  for (const auto &task : *tasks) {
    const std::string key = BuildTaskKey_(task);
    if (seen.insert(key).second) {
      uniq.push_back(task);
    }
  }
  tasks->swap(uniq);
}

ECMData<ClientHandle>
AcquireSourceTransferClient_(FilesystemAppService *service,
                             TransferClientContainer *clients,
                             const std::string &nickname) {
  if (!service || !clients) {
    return {nullptr, Err(EC::InvalidArg, "Transfer resolver deps are null")};
  }
  if (nickname.empty()) {
    return {nullptr, Err(EC::InvalidArg, "Source nickname is empty")};
  }

  if (auto existing = clients->GetSrcClient(nickname)) {
    return {existing, Ok()};
  }

  auto first = service->GetTransferClient(nickname);
  if (!isok(first.rcm) || !first.data) {
    return first;
  }
  const ECM add_first_rcm = clients->AddSrcClient(nickname, first.data);
  if (isok(add_first_rcm)) {
    return first;
  }
  if (add_first_rcm.first != EC::InvalidArg) {
    return {nullptr, add_first_rcm};
  }

  auto second = service->GetTransferClient(nickname);
  if (!isok(second.rcm) || !second.data) {
    return second;
  }
  const ECM add_second_rcm = clients->AddSrcClient(nickname, second.data);
  if (!isok(add_second_rcm)) {
    return {nullptr, add_second_rcm};
  }
  return second;
}
} // namespace

ECMData<DstResolveResult> FilesystemAppService::ResolveTransferDst(
    PathTarget dst, TransferClientContainer *clients,
    const ClientControlComponent &control) {
  if (!clients) {
    return {DstResolveResult{},
            Err(EC::InvalidArg, "Transfer client container pointer is null")};
  }

  DstResolveResult out = {};

  auto transfer_client = GetTransferClient(dst.nickname);
  if (!isok(transfer_client.rcm) || !transfer_client.data) {
    return {std::move(out), transfer_client.rcm};
  }

  ECM add_dst_rcm = clients->AddDstClient(dst.nickname, transfer_client.data);
  if (!isok(add_dst_rcm) && add_dst_rcm.first == EC::InvalidArg) {
    auto second_client = GetTransferClient(dst.nickname);
    if (!isok(second_client.rcm) || !second_client.data) {
      return {std::move(out), second_client.rcm};
    }
    add_dst_rcm = clients->AddDstClient(dst.nickname, second_client.data);
    if (!isok(add_dst_rcm)) {
      return {std::move(out), add_dst_rcm};
    }
    transfer_client = second_client;
  } else if (!isok(add_dst_rcm)) {
    return {std::move(out), add_dst_rcm};
  }

  auto abs_result = ResolveAbsolutePath(transfer_client.data, dst.path, control);
  if (!isok(abs_result.rcm)) {
    return {std::move(out), abs_result.rcm};
  }

  dst.path = abs_result.data;
  out.target = dst;
  out.resolved_target.target = dst;
  out.resolved_target.abs_path = dst.path;
  out.resolved_target.client = transfer_client.data;
  out.resolved_target.is_wildcard =
      AMDomain::filesystem::services::HasWildcard(dst.path);
  out.resolved_target.is_user_path =
      !dst.path.empty() && dst.path.front() == '~';

  auto stat_result =
      BaseStat(transfer_client.data, dst.nickname, dst.path, control);
  if (isok(stat_result.rcm)) {
    out.dst_info = stat_result.data;
    return {std::move(out), Ok()};
  }
  if (AMDomain::filesystem::services::IsPathNotExistError(
          stat_result.rcm.first)) {
    return {std::move(out), Ok()};
  }
  return {std::move(out), stat_result.rcm};
}

ECMData<SourceResolveResult> FilesystemAppService::ResolveTransferSrc(
    std::vector<PathTarget> srcs, TransferClientContainer *clients,
    const ClientControlComponent &control, bool error_stop) {
  SourceResolveResult out = {};
  if (!clients) {
    return {std::move(out),
            Err(EC::InvalidArg, "Transfer client container pointer is null")};
  }
  if (srcs.empty()) {
    return {std::move(out), Err(EC::InvalidArg, "Source path list is empty")};
  }

  ECM first_error = Ok();
  const auto mark_error = [&](const std::string &nickname,
                              const PathTarget &error_path,
                              const ECM &rcm) {
    const std::string key = nickname.empty() ? std::string("local") : nickname;
    out.error_data[key].push_back({error_path, rcm});
    if (isok(first_error)) {
      first_error = rcm;
    }
  };

  for (auto &src : srcs) {
    if (src.nickname.empty()) {
      const ECM rcm = Err(EC::InvalidArg, "Source nickname is empty");
      mark_error(src.nickname, src, rcm);
      if (error_stop) {
        return {std::move(out), rcm};
      }
      continue;
    }

    auto src_transfer =
        AcquireSourceTransferClient_(this, clients, src.nickname);
    if (!isok(src_transfer.rcm) || !src_transfer.data) {
      mark_error(src.nickname, src, src_transfer.rcm);
      if (error_stop) {
        return {std::move(out), src_transfer.rcm};
      }
      continue;
    }

    src.path = src.path.empty() ? "." : src.path;
    const bool is_wildcard =
        AMDomain::filesystem::services::HasWildcard(src.path);
    auto abs_result = ResolveAbsolutePath(src_transfer.data, src.path, control);
    if (!isok(abs_result.rcm)) {
      mark_error(src.nickname, src, abs_result.rcm);
      if (error_stop) {
        return {std::move(out), abs_result.rcm};
      }
      continue;
    }
    src.path = abs_result.data;

    auto &host_entry = out.data[src.nickname];
    if (!host_entry.resolved_target.client) {
      host_entry.resolved_target.target = src;
      host_entry.resolved_target.abs_path = src.path;
      host_entry.resolved_target.client = src_transfer.data;
      host_entry.resolved_target.is_wildcard = is_wildcard;
      host_entry.resolved_target.is_user_path =
          !src.path.empty() && src.path.front() == '~';
    }

    if (is_wildcard) {
      auto find_result = find(src, SearchType::All, control);
      if (!isok(find_result.rcm)) {
        mark_error(src.nickname, src, find_result.rcm);
        if (error_stop) {
          return {std::move(out), find_result.rcm};
        }
        continue;
      }
      if (find_result.data.empty()) {
        const ECM miss_rcm =
            Err(EC::PathNotExist,
                AMStr::fmt("Source wildcard path matched no entries: {}",
                           src.path));
        mark_error(src.nickname, src, miss_rcm);
        continue;
      }
      host_entry.raw_paths.insert(host_entry.raw_paths.end(),
                                  find_result.data.begin(),
                                  find_result.data.end());
      continue;
    }

    auto stat_result =
        BaseStat(src_transfer.data, src.nickname, src.path, control);
    if (!isok(stat_result.rcm)) {
      mark_error(src.nickname, src, stat_result.rcm);
      if (error_stop) {
        return {std::move(out), stat_result.rcm};
      }
      continue;
    }
    host_entry.raw_paths.push_back(stat_result.data);
  }

  for (auto &[nickname, source_data] : out.data) {
    source_data.paths = CompactMatchedPaths_(source_data.raw_paths);
    if (source_data.paths.empty()) {
      PathTarget err_path = source_data.resolved_target.target;
      if (err_path.path.empty()) {
        err_path.path = ".";
      }
      mark_error(nickname, err_path,
                 Err(EC::PathNotExist,
                     AMStr::fmt("No valid source entries remain for {}",
                                nickname)));
    }
  }

  return {std::move(out), first_error};
}

ECMData<BuildTransferTaskResult>
FilesystemAppService::BuildTransferTasks(const SourceResolveResult &src,
                                         const DstResolveResult &dst,
                                         const ClientControlComponent &control,
                                         const BuildTransferTaskOptions &opt) {
  BuildTransferTaskResult out = {};

  if (!dst.resolved_target.client) {
    return {std::move(out),
            Err(EC::InvalidHandle, "Destination client is null")};
  }
  if (dst.target.path.empty()) {
    return {std::move(out), Err(EC::InvalidArg, "Destination path is empty")};
  }

  const std::string dst_host = dst.target.nickname;
  const auto check_stop = [&control]() -> ECM {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "BuildTransferTasks interrupted");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "BuildTransferTasks timed out");
    }
    return Ok();
  };
  auto append_warning = [&out](std::string src_path, std::string dst_path,
                               ECM rcm) {
    if (!isok(rcm)) {
      out.warnings.push_back(
          {std::move(src_path), std::move(dst_path), std::move(rcm)});
    }
  };

  struct PendingState {
    std::string src_host = {};
    ClientHandle src_client = nullptr;
    PathInfo root = {};
    PathInfo node = {};
    std::string mapped_root = {};
  };

  std::deque<PendingState> pending = {};

  if (opt.clone) {
    if (src.data.size() != 1) {
      return {std::move(out),
              Err(EC::InvalidArg,
                  AMStr::fmt("Clone mode requires exactly one source host, got "
                             "{}",
                             src.data.size()))};
    }
    const auto &[src_host, source_data] = *src.data.begin();
    if (!source_data.resolved_target.client) {
      return {std::move(out),
              Err(EC::InvalidHandle,
                  AMStr::fmt("Clone source client is null: {}", src_host))};
    }
    if (source_data.paths.size() != 1) {
      return {std::move(out),
              Err(EC::InvalidArg,
                  AMStr::fmt("Clone mode requires exactly one compacted source "
                             "path, got {}",
                             source_data.paths.size()))};
    }

    const PathInfo source_root = source_data.paths.front();
    if (opt.ignore_special_file && source_root.is_special()) {
      return {std::move(out),
              Err(EC::NotAFile,
                  AMStr::fmt("Unsupported source type: {}", source_root.path))};
    }

    if (dst.dst_info.has_value()) {
      const bool src_is_dir = source_root.type == PathType::DIR;
      const bool dst_is_dir = dst.dst_info->type == PathType::DIR;
      if (src_is_dir != dst_is_dir) {
        return {std::move(out),
                Err(EC::NotADirectory,
                    AMStr::fmt("Clone type conflict: src {} -> dst {}",
                               source_root.path, dst.target.path))};
      }
    }

    pending.push_back(PendingState{src_host, source_data.resolved_target.client,
                                   source_root, source_root, dst.target.path});
  } else {
    for (const auto &[src_host, source_data] : src.data) {
      const ECM stop_rcm = check_stop();
      if (!isok(stop_rcm)) {
        return {std::move(out), stop_rcm};
      }
      if (!source_data.resolved_target.client) {
        append_warning(
            "", source_data.resolved_target.target.path,
            Err(EC::InvalidHandle,
                AMStr::fmt("Source client is null for host {}", src_host)));
        continue;
      }
      for (const auto &source_root : source_data.paths) {
        if (opt.ignore_special_file && source_root.is_special()) {
          append_warning(
              source_root.path, "",
              Err(EC::NotAFile,
                  AMStr::fmt("Unsupported source type: {}", source_root.path)));
          continue;
        }
        const std::string mapped_root =
            AMPath::join(dst.target.path, AMPath::basename(source_root.path));
        pending.push_back(PendingState{src_host, source_data.resolved_target.client,
                                       source_root, source_root, mapped_root});
      }
    }
  }

  while (!pending.empty()) {
    const ECM stop_rcm = check_stop();
    if (!isok(stop_rcm)) {
      return {std::move(out), stop_rcm};
    }

    PendingState state = pending.front();
    pending.pop_front();
    if (!state.src_client) {
      append_warning("", state.node.path,
                     Err(EC::InvalidHandle, "Source client is null"));
      continue;
    }
    const std::string rel = RelativeFrom_(state.root.path, state.node.path);
    const std::string mapped_dst =
        rel.empty() ? state.mapped_root
                    : AMPath::join(state.mapped_root, rel);

    if (state.src_host == dst_host && state.node.path == mapped_dst) {
      continue;
    }

    if (opt.ignore_special_file && state.node.is_special()) {
      append_warning(
          state.node.path, mapped_dst,
          Err(EC::NotAFile,
              AMStr::fmt("Unsupported source node type: {}", state.node.path)));
      continue;
    }

    if (state.node.type == PathType::DIR) {
      auto dst_stat =
          BaseStat(dst.resolved_target.client, dst_host, mapped_dst, control);
      const bool dst_exists = isok(dst_stat.rcm);
      if (dst_exists && dst_stat.data.type != PathType::DIR) {
        append_warning(state.node.path, mapped_dst,
                       Err(EC::NotADirectory,
                           AMStr::fmt("Directory/file type conflict: {} -> {}",
                                      state.node.path, mapped_dst)));
        continue;
      }
      if (!dst_exists && !AMDomain::filesystem::services::IsPathNotExistError(
                             dst_stat.rcm.first)) {
        if (IsStopError_(dst_stat.rcm.first)) {
          return {std::move(out), dst_stat.rcm};
        }
        append_warning(state.node.path, mapped_dst, dst_stat.rcm);
        continue;
      }

      auto list_result = BaseListdir(state.src_client, state.src_host,
                                     state.node.path, control);
      if (!isok(list_result.rcm)) {
        if (IsStopError_(list_result.rcm.first)) {
          return {std::move(out), list_result.rcm};
        }
        append_warning(state.node.path, mapped_dst, list_result.rcm);
        continue;
      }

      if (list_result.data.empty()) {
        if (!opt.mkdir) {
          append_warning(
              state.node.path, mapped_dst,
              Err(EC::ParentDirectoryNotExist,
                  AMStr::fmt("Skip empty directory {} because mkdir=false",
                             mapped_dst)));
          continue;
        }
        if (!dst_exists) {
          AMDomain::transfer::TransferTask dir_task(state.node.path, mapped_dst,
                                                    state.src_host, dst_host, 0,
                                                    PathType::DIR);
          dir_task.overwrite = false;
          dir_task.transferred = 0;
          out.dir_tasks.push_back(std::move(dir_task));
        }
        continue;
      }

      for (const auto &child : list_result.data) {
        pending.push_back(PendingState{state.src_host, state.src_client,
                                       state.root, child, state.mapped_root});
      }
      continue;
    }

    if (!state.node.is_regular()) {
      append_warning(
          state.node.path, mapped_dst,
          Err(EC::NotAFile,
              AMStr::fmt("Unsupported source file type: {}", state.node.path)));
      continue;
    }

    const std::string parent_path = AMPath::dirname(mapped_dst).empty()
                                        ? "."
                                        : AMPath::dirname(mapped_dst);
    auto parent_stat =
        BaseStat(dst.resolved_target.client, dst_host, parent_path, control);
    if (isok(parent_stat.rcm)) {
      if (parent_stat.data.type != PathType::DIR) {
        append_warning(state.node.path, mapped_dst,
                       Err(EC::NotADirectory,
                           AMStr::fmt("Destination parent is not directory: {}",
                                      parent_path)));
        continue;
      }
    } else if (!AMDomain::filesystem::services::IsPathNotExistError(
                   parent_stat.rcm.first)) {
      if (IsStopError_(parent_stat.rcm.first)) {
        return {std::move(out), parent_stat.rcm};
      }
      append_warning(state.node.path, mapped_dst, parent_stat.rcm);
      continue;
    } else if (!opt.mkdir) {
      append_warning(state.node.path, mapped_dst,
                     Err(EC::ParentDirectoryNotExist,
                         AMStr::fmt("Destination parent does not exist: {}",
                                    parent_path)));
      continue;
    }

    auto dst_stat =
        BaseStat(dst.resolved_target.client, dst_host, mapped_dst, control);
    const bool dst_exists = isok(dst_stat.rcm);
    if (dst_exists && dst_stat.data.type == PathType::DIR) {
      append_warning(
          state.node.path, mapped_dst,
          Err(EC::NotAFile,
              AMStr::fmt("Destination is directory: {}", mapped_dst)));
      continue;
    }
    if (!dst_exists && !AMDomain::filesystem::services::IsPathNotExistError(
                           dst_stat.rcm.first)) {
      if (IsStopError_(dst_stat.rcm.first)) {
        return {std::move(out), dst_stat.rcm};
      }
      append_warning(state.node.path, mapped_dst, dst_stat.rcm);
      continue;
    }
    if (dst_exists && !dst_stat.data.is_regular()) {
      append_warning(
          state.node.path, mapped_dst,
          Err(EC::NotAFile,
              AMStr::fmt("Destination type mismatch: {}", mapped_dst)));
      continue;
    }

    AMDomain::transfer::TransferTask file_task(
        state.node.path, mapped_dst, state.src_host, dst_host, state.node.size,
        state.node.type);
    file_task.overwrite = dst_exists && dst_stat.data.is_regular();

    if (opt.resume) {
      if (state.node.type != PathType::FILE) {
        append_warning(
            state.node.path, mapped_dst,
            Err(EC::NotAFile, AMStr::fmt("Resume only supports file source: {}",
                                         state.node.path)));
        continue;
      }
      if (!dst_exists) {
        append_warning(state.node.path, mapped_dst,
                       Err(EC::PathNotExist,
                           AMStr::fmt("Resume requires destination file: {}",
                                      mapped_dst)));
        continue;
      }
      if (dst_stat.data.type != PathType::FILE) {
        append_warning(
            state.node.path, mapped_dst,
            Err(EC::NotAFile, AMStr::fmt("Resume requires destination file: {}",
                                         mapped_dst)));
        continue;
      }
      if (dst_stat.data.size > state.node.size) {
        append_warning(
            state.node.path, mapped_dst,
            Err(EC::InvalidArg,
                AMStr::fmt("Resume invalid: dst {} > src {} for {}",
                           dst_stat.data.size, state.node.size, mapped_dst)));
        continue;
      }
      if (dst_stat.data.size == state.node.size) {
        continue;
      }
      file_task.transferred = dst_stat.data.size;
    }

    out.file_tasks.push_back(std::move(file_task));
  }

  DedupAndSortTasks_(&out.dir_tasks);
  DedupAndSortTasks_(&out.file_tasks);
  return {std::move(out), Ok()};
}
} // namespace AMApplication::filesystem
