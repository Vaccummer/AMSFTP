#include "application/filesystem/FilesystemAppService.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"

#include "foundation/core/Path.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <deque>
#include <unordered_set>
#include <variant>

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
    out = AMPathStr::join(out, parts[i]);
  }
  return out;
}

ECM PutSingleClientToContainer_(TransferClientContainer *clients,
                                const std::string &nickname,
                                ClientHandle client) {
  if (!clients) {
    return Err(EC::InvalidArg, "Transfer client container pointer is null");
  }
  if (nickname.empty()) {
    return Err(EC::InvalidArg, "Client nickname is empty");
  }
  if (!client) {
    return Err(EC::InvalidHandle, "Client handle is null");
  }
  auto &slot = (*clients)[nickname];
  if (std::holds_alternative<ClientHandle>(slot)) {
    auto &primary = std::get<ClientHandle>(slot);
    if (!primary) {
      primary = client;
    }
    return Ok();
  }
  auto &pair_slot = std::get<std::pair<ClientHandle, ClientHandle>>(slot);
  if (!pair_slot.first) {
    pair_slot.first = client;
  }
  return Ok();
}

bool RecordFirstErrorPath_(std::map<std::string, ClientPath> *error_data,
                           const std::string &nickname, const ClientPath &path,
                           const ECM &rcm) {
  if (!error_data) {
    return false;
  }
  ClientPath error_path = path;
  error_path.rcm = rcm;
  return error_data->emplace(nickname, std::move(error_path)).second;
}

std::string RelativeFrom_(const std::string &root, const std::string &target) {
  if (root == target) {
    return "";
  }
  const std::vector<std::string> root_parts = AMPathStr::split(root);
  const std::vector<std::string> target_parts = AMPathStr::split(target);
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
  return AMPathStr::basename(target);
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
} // namespace

ECMData<TransferPath> FilesystemAppService::ResolveTransferDst(
    ClientPath dst, const ClientControlComponent &control) {
  TransferPath out = {};

  auto transfer_client = GetTransferClient(dst.nickname);
  if (!isok(transfer_client.rcm) || !transfer_client.data) {
    out.target = std::move(dst);
    out.rcm = transfer_client.rcm;
    return {std::move(out), out.rcm};
  }

  dst.client = transfer_client.data;
  dst.resolved = true;
  out.client = transfer_client.data;
  ECM abs_rcm = ClientOperationHelper::AbsolutePath(dst);
  if (!isok(abs_rcm)) {
    out.target = std::move(dst);
    out.rcm = abs_rcm;
    return {std::move(out), out.rcm};
  }
  out.target = dst;

  auto stat_result = BaseStat(out.client, dst.nickname, dst.path, control);
  if (isok(stat_result.rcm)) {
    out.paths.push_back(std::move(stat_result.data));
    out.rcm = Ok();
    return {std::move(out), Ok()};
  }
  if (AMDomain::filesystem::services::IsPathNotExistError(
          stat_result.rcm.first)) {
    out.paths.clear();
    out.rcm = Ok();
    return {std::move(out), Ok()};
  }
  out.rcm = stat_result.rcm;
  return {std::move(out), out.rcm};
}

ECMData<SourceResolveResult> FilesystemAppService::ResolveTransferSrc(
    std::vector<ClientPath> srcs, TransferClientContainer *clients,
    const ClientControlComponent &control, bool error_stop) {
  SourceResolveResult out = {};
  if (!clients) {
    out.rcm = Err(EC::InvalidArg, "Transfer client container pointer is null");
    return {std::move(out), out.rcm};
  }
  if (srcs.empty()) {
    out.rcm = Err(EC::InvalidArg, "Source path list is empty");
    return {std::move(out), out.rcm};
  }

  ECM first_error = Ok();
  const auto get_container_client =
      [&](const std::string &nickname) -> ClientHandle {
    if (!clients) {
      return nullptr;
    }
    const auto it = clients->find(nickname);
    if (it == clients->end()) {
      return nullptr;
    }
    if (std::holds_alternative<ClientHandle>(it->second)) {
      return std::get<ClientHandle>(it->second);
    }
    const auto &pair_slot =
        std::get<std::pair<ClientHandle, ClientHandle>>(it->second);
    if (pair_slot.first) {
      return pair_slot.first;
    }
    return pair_slot.second;
  };
  auto get_or_prepare_transfer_client =
      [&](const std::string &nickname) -> ECMData<ClientHandle> {
    if (auto cached = get_container_client(nickname)) {
      return {cached, Ok()};
    }
    auto transfer_client = GetTransferClient(nickname);
    if (!isok(transfer_client.rcm) || !transfer_client.data) {
      return transfer_client;
    }
    const ECM put_rcm =
        PutSingleClientToContainer_(clients, nickname, transfer_client.data);
    if (!isok(put_rcm)) {
      return {nullptr, put_rcm};
    }
    return transfer_client;
  };

  const auto mark_error = [&](const std::string &nickname,
                              const ClientPath &error_path, ECM rcm) {
    if (nickname.empty()) {
      if (isok(first_error)) {
        first_error = rcm;
      }
      return;
    }
    (void)RecordFirstErrorPath_(&out.error_data, nickname, error_path, rcm);
    auto data_it = out.data.find(nickname);
    if (data_it != out.data.end() && isok(data_it->second.rcm)) {
      data_it->second.rcm = rcm;
    }
    if (isok(first_error)) {
      first_error = rcm;
    }
  };

  for (auto &src : srcs) {
    std::string nickname = src.nickname;
    if (nickname.empty()) {
      mark_error(nickname, src,
                 Err(EC::InvalidArg, "Source nickname is empty"));
      if (error_stop) {
        out.rcm = first_error;
        return {std::move(out), out.rcm};
      }
      continue;
    }
    src.nickname = nickname;

    auto src_transfer = get_or_prepare_transfer_client(src.nickname);
    if (!isok(src_transfer.rcm) || !src_transfer.data) {
      mark_error(src.nickname, src, src_transfer.rcm);
      if (error_stop) {
        out.rcm = first_error;
        return {std::move(out), out.rcm};
      }
      continue;
    }
    src.client = src_transfer.data;
    src.resolved = true;

    src.path = src.path.empty() ? "." : src.path;
    src.is_wildcard = src.is_wildcard ||
                      AMDomain::filesystem::services::HasWildcard(src.path);
    src.userpath = !src.path.empty() && src.path.front() == '~';
    ECM abs_rcm = ClientOperationHelper::AbsolutePath(src);
    if (!isok(abs_rcm)) {
      mark_error(src.nickname, src, abs_rcm);
      if (error_stop) {
        out.rcm = first_error;
        return {std::move(out), out.rcm};
      }
      continue;
    }
    src.resolved = true;

    auto &host_entry = out.data[src.nickname];
    if (!host_entry.client) {
      host_entry.client = src.client;
      host_entry.target = src;
      host_entry.rcm = Ok();
    }

    if (src.is_wildcard) {
      auto find_result = find(src, SearchType::All, control);
      if (!isok(find_result.rcm)) {
        mark_error(src.nickname, src, find_result.rcm);
        if (error_stop) {
          out.rcm = first_error;
          return {std::move(out), out.rcm};
        }
        continue;
      }
      if (find_result.data.empty()) {
        ECM miss_rcm =
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

    auto stat_result = BaseStat(src.client, src.nickname, src.path, control);
    if (!isok(stat_result.rcm)) {
      mark_error(src.nickname, src, stat_result.rcm);
      if (error_stop) {
        out.rcm = first_error;
        return {std::move(out), out.rcm};
      }
      continue;
    }
    host_entry.raw_paths.push_back(stat_result.data);
  }

  for (auto &[nickname, transfer_path] : out.data) {
    transfer_path.paths = CompactMatchedPaths_(transfer_path.raw_paths);
    if (transfer_path.paths.empty() && isok(transfer_path.rcm)) {
      transfer_path.rcm =
          Err(EC::PathNotExist,
              AMStr::fmt("No valid source entries remain for {}", nickname));
    }
  }

  out.rcm = first_error;
  return {std::move(out), out.rcm};
}

ECMData<BuildTransferTaskResult>
FilesystemAppService::BuildTransferTasks(const SourceResolveResult &src,
                                         const TransferPath &dst,
                                         const ClientControlComponent &control,
                                         const BuildTransferTaskOptions &opt) {
  BuildTransferTaskResult out = {};

  if (!dst.client) {
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

  if (src.rcm) {
    append_warning("", dst.target.path, src.rcm);
  }
  if (dst.rcm) {
    append_warning("", dst.target.path, dst.rcm);
  }
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
    const auto &[src_host, transfer_path] = *src.data.begin();
    if (!transfer_path.client) {
      return {std::move(out),
              Err(EC::InvalidHandle,
                  AMStr::fmt("Clone source client is null: {}", src_host))};
    }
    if (transfer_path.paths.size() != 1) {
      return {std::move(out),
              Err(EC::InvalidArg,
                  AMStr::fmt("Clone mode requires exactly one compacted source "
                             "path, got {}",
                             transfer_path.paths.size()))};
    }

    const PathInfo source_root = transfer_path.paths.front();
    if (opt.ignore_special_file && source_root.is_special()) {
      return {std::move(out),
              Err(EC::NotAFile,
                  AMStr::fmt("Unsupported source type: {}", source_root.path))};
    }

    auto dst_root_stat =
        BaseStat(dst.client, dst_host, dst.target.path, control);
    if (!isok(dst_root_stat.rcm) &&
        !AMDomain::filesystem::services::IsPathNotExistError(
            dst_root_stat.rcm.first)) {
      return {std::move(out), dst_root_stat.rcm};
    }
    if (isok(dst_root_stat.rcm)) {
      const bool src_is_dir = source_root.type == PathType::DIR;
      const bool dst_is_dir = dst_root_stat.data.type == PathType::DIR;
      if (src_is_dir != dst_is_dir) {
        return {std::move(out),
                Err(EC::NotADirectory,
                    AMStr::fmt("Clone type conflict: src {} -> dst {}",
                               source_root.path, dst.target.path))};
      }
    }

    pending.push_back(PendingState{src_host, transfer_path.client, source_root,
                                   source_root, dst.target.path});
  } else {
    for (const auto &[src_host, transfer_path] : src.data) {
      const ECM stop_rcm = check_stop();
      if (!isok(stop_rcm)) {
        return {std::move(out), stop_rcm};
      }
      if (!transfer_path.client) {
        append_warning(
            "", transfer_path.target.path,
            Err(EC::InvalidHandle,
                AMStr::fmt("Source client is null for host {}", src_host)));
        continue;
      }
      for (const auto &source_root : transfer_path.paths) {
        if (opt.ignore_special_file && source_root.is_special()) {
          append_warning(
              source_root.path, "",
              Err(EC::NotAFile,
                  AMStr::fmt("Unsupported source type: {}", source_root.path)));
          continue;
        }
        const std::string mapped_root = AMPathStr::join(
            dst.target.path, AMPathStr::basename(source_root.path));
        pending.push_back(PendingState{src_host, transfer_path.client,
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
                    : AMPathStr::join(state.mapped_root, rel);

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
      auto dst_stat = BaseStat(dst.client, dst_host, mapped_dst, control);
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

    const std::string parent_path = AMPathStr::dirname(mapped_dst).empty()
                                        ? "."
                                        : AMPathStr::dirname(mapped_dst);
    auto parent_stat = BaseStat(dst.client, dst_host, parent_path, control);
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

    auto dst_stat = BaseStat(dst.client, dst_host, mapped_dst, control);
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
