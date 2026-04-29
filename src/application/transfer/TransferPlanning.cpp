#include "application/transfer/TransferAppService.hpp"

#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <deque>
#include <unordered_map>
#include <unordered_set>

namespace AMApplication::transfer {
namespace {
using EC = ErrorCode;
using ClientHandle = AMDomain::client::ClientHandle;
using SearchType = AMDomain::filesystem::SearchType;
using AMDomain::filesystem::service::HasWildcard;
using AMDomain::filesystem::service::IsPathNotExistError;

bool IsStopError_(ErrorCode ec) {
  return ec == ErrorCode::Terminate || ec == ErrorCode::OperationTimeout;
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

  *tasks = AMStr::DedupVectorKeepOrder(
      *tasks, [](const AMDomain::transfer::TransferTask &task) {
        return BuildTaskKey_(task);
      });
}
} // namespace

ECMData<TransferClientContainer>
TransferAppService::RecollectTransferClients_(const TaskHandle &task_info) {
  TransferClientContainer out = {};
  if (!task_info) {
    return {std::move(out), Err(EC::InvalidArg, "", "", "Task info is null")};
  }

  std::unordered_set<std::string> src_hosts = {};
  std::unordered_set<std::string> dst_hosts = {};
  {
    auto dir_tasks = task_info->Core.dir_tasks.lock();
    for (const auto &task : *dir_tasks) {
      if (!AMStr::Strip(task.src_host).empty()) {
        src_hosts.insert(task.src_host);
      }
      if (!AMStr::Strip(task.dst_host).empty()) {
        dst_hosts.insert(task.dst_host);
      }
    }
  }
  {
    auto file_tasks = task_info->Core.file_tasks.lock();
    for (const auto &task : *file_tasks) {
      if (!AMStr::Strip(task.src_host).empty()) {
        src_hosts.insert(task.src_host);
      }
      if (!AMStr::Strip(task.dst_host).empty()) {
        dst_hosts.insert(task.dst_host);
      }
    }
  }

  for (const auto &nickname : src_hosts) {
    auto first = client_service_.AcquireTransferClient(nickname);
    if (!(first.rcm) || !first.data) {
      out.ReleaseAll();
      return {std::move(out), first.rcm};
    }
    ECM add_rcm = out.AddSrcClient(nickname, first.data);
    if (!(add_rcm) && add_rcm.code == EC::InvalidArg) {
      auto second = client_service_.AcquireTransferClient(nickname);
      if (!(second.rcm) || !second.data) {
        out.ReleaseAll();
        return {std::move(out), second.rcm};
      }
      add_rcm = out.AddSrcClient(nickname, second.data);
    }
    if (!(add_rcm)) {
      out.ReleaseAll();
      return {std::move(out), add_rcm};
    }
  }

  for (const auto &nickname : dst_hosts) {
    auto first = client_service_.AcquireTransferClient(nickname);
    if (!(first.rcm) || !first.data) {
      out.ReleaseAll();
      return {std::move(out), first.rcm};
    }
    ECM add_rcm = out.AddDstClient(nickname, first.data);
    if (!(add_rcm) && add_rcm.code == EC::InvalidArg) {
      auto second = client_service_.AcquireTransferClient(nickname);
      if (!(second.rcm) || !second.data) {
        out.ReleaseAll();
        return {std::move(out), second.rcm};
      }
      add_rcm = out.AddDstClient(nickname, second.data);
    }
    if (!(add_rcm)) {
      out.ReleaseAll();
      return {std::move(out), add_rcm};
    }
  }

  return {std::move(out), OK};
}

ECMData<DstResolveResult>
TransferAppService::ResolveTransferDst(PathTarget dst,
                                       TransferClientContainer *clients,
                                       const ControlComponent &control) {
  if (!clients) {
    return {Err(EC::InvalidArg, "", "",
                "Transfer client container pointer is null")};
  }

  DstResolveResult out = {};
  auto transfer_client = client_service_.AcquireTransferClient(dst.nickname);
  if (!(transfer_client.rcm) || !transfer_client.data) {
    return {std::move(out), transfer_client.rcm};
  }

  ECM add_dst_rcm = clients->AddDstClient(dst.nickname, transfer_client.data);
  if (!(add_dst_rcm) && add_dst_rcm.code == EC::InvalidArg) {
    auto second_client = client_service_.AcquireTransferClient(dst.nickname);
    if (!(second_client.rcm) || !second_client.data) {
      return {std::move(out), second_client.rcm};
    }
    add_dst_rcm = clients->AddDstClient(dst.nickname, second_client.data);
    if (!(add_dst_rcm)) {
      return {std::move(out), add_dst_rcm};
    }
    transfer_client = second_client;
  } else if (!(add_dst_rcm)) {
    return {std::move(out), add_dst_rcm};
  }

  auto abs_result = AMApplication::filesystem::FileSystemAppService::
      ResolveAbsolutePath(transfer_client.data, dst.path, control);
  if (!(abs_result.rcm)) {
    return {std::move(out), abs_result.rcm};
  }

  dst.path = abs_result.data;
  dst.is_wildcard = HasWildcard(dst.path);
  dst.is_user_path = !dst.path.empty() && dst.path.front() == '~';
  out.target = dst;
  out.resolved_target.target = dst;
  out.resolved_target.abs_path = dst.path;
  out.resolved_target.client = transfer_client.data;

  auto stat_result =
      filesystem_service_.Stat(dst, control, false, transfer_client.data);
  if ((stat_result.rcm)) {
    out.dst_info = stat_result.data;
    return {std::move(out), OK};
  }
  if (IsPathNotExistError(stat_result.rcm.code)) {
    return {std::move(out), OK};
  }
  return {std::move(out), stat_result.rcm};
}

ECMData<SourceResolveResult> TransferAppService::ResolveTransferSrc(
    std::vector<PathTarget> srcs, TransferClientContainer *clients,
    const ControlComponent &control, bool error_stop) {
  SourceResolveResult out = {};
  if (!clients) {
    return {std::move(out), Err(EC::InvalidArg, "", "",
                                "Transfer client container pointer is null")};
  }
  if (srcs.empty()) {
    return {std::move(out),
            Err(EC::InvalidArg, "", "", "Source path list is empty")};
  }

  ECM first_error = OK;
  const auto mark_error = [&](const std::string &nickname,
                              const PathTarget &error_path, const ECM &rcm) {
    const std::string key = nickname.empty() ? std::string("local") : nickname;
    out.error_data[key].emplace_back(error_path, rcm);
    if ((first_error)) {
      first_error = rcm;
    }
  };
  const auto acquire_source_transfer_client =
      [&](const std::string &nickname) -> ECMData<ClientHandle> {
    if (nickname.empty()) {
      return {nullptr,
              Err(EC::InvalidArg, "", "", "Source nickname is empty")};
    }
    if (auto existing = clients->GetSrcClient(nickname)) {
      return {existing, OK};
    }

    auto first = client_service_.AcquireTransferClient(nickname);
    if (!(first.rcm) || !first.data) {
      return first;
    }
    const ECM add_first_rcm = clients->AddSrcClient(nickname, first.data);
    if ((add_first_rcm)) {
      return first;
    }
    if (add_first_rcm.code != EC::InvalidArg) {
      return {nullptr, add_first_rcm};
    }

    auto second = client_service_.AcquireTransferClient(nickname);
    if (!(second.rcm) || !second.data) {
      return second;
    }
    const ECM add_second_rcm = clients->AddSrcClient(nickname, second.data);
    if (!(add_second_rcm)) {
      return {nullptr, add_second_rcm};
    }
    return second;
  };

  for (auto &src : srcs) {
    if (src.nickname.empty()) {
      const ECM rcm = Err(EC::InvalidArg, "", "", "Source nickname is empty");
      mark_error(src.nickname, src, rcm);
      if (error_stop) {
        return {std::move(out), rcm};
      }
      continue;
    }

    auto src_transfer = acquire_source_transfer_client(src.nickname);
    if (!(src_transfer.rcm) || !src_transfer.data) {
      mark_error(src.nickname, src, src_transfer.rcm);
      if (error_stop) {
        return {std::move(out), src_transfer.rcm};
      }
      continue;
    }

    src.path = src.path.empty() ? "." : src.path;
    const bool is_wildcard = HasWildcard(src.path);
    auto abs_result = AMApplication::filesystem::FileSystemAppService::
        ResolveAbsolutePath(src_transfer.data, src.path, control);
    if (!(abs_result.rcm)) {
      mark_error(src.nickname, src, abs_result.rcm);
      if (error_stop) {
        return {std::move(out), abs_result.rcm};
      }
      continue;
    }
    src.path = abs_result.data;
    src.is_wildcard = is_wildcard;
    src.is_user_path = !src.path.empty() && src.path.front() == '~';

    auto &host_entry = out.data[src.nickname];
    if (!host_entry.resolved_target.client) {
      host_entry.resolved_target.target = src;
      host_entry.resolved_target.abs_path = src.path;
      host_entry.resolved_target.client = src_transfer.data;
    }

    if (is_wildcard) {
      auto find_result = filesystem_service_.find(src, SearchType::All, control);
      if (!(find_result.rcm)) {
        mark_error(src.nickname, src, find_result.rcm);
        if (error_stop) {
          return {std::move(out), find_result.rcm};
        }
        continue;
      }
      if (find_result.data.empty()) {
        const ECM miss_rcm =
            Err(EC::PathNotExist, "", "",
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
        filesystem_service_.Stat(src, control, false, src_transfer.data);
    if (!(stat_result.rcm)) {
      mark_error(src.nickname, src, stat_result.rcm);
      if (error_stop) {
        return {std::move(out), stat_result.rcm};
      }
      continue;
    }
    host_entry.raw_paths.push_back(stat_result.data);
  }

  for (auto &[nickname, source_data] : out.data) {
    source_data.paths = AMPath::CompactMatchedPaths(source_data.raw_paths);
    if (source_data.paths.empty()) {
      PathTarget err_path = source_data.resolved_target.target;
      if (err_path.path.empty()) {
        err_path.path = ".";
      }
      mark_error(
          nickname, err_path,
          Err(EC::PathNotExist, "", "",
              AMStr::fmt("No valid source entries remain for {}", nickname)));
    }
  }

  return {std::move(out), first_error};
}

ECMData<BuildTransferTaskResult> TransferAppService::BuildTransferTasks(
    const SourceResolveResult &src, const DstResolveResult &dst,
    const ControlComponent &control, const BuildTransferTaskOptions &opt) {
  BuildTransferTaskResult out = {};
  if (!dst.resolved_target.client) {
    return {std::move(out),
            Err(EC::InvalidHandle, "", "", "Destination client is null")};
  }
  if (dst.target.path.empty()) {
    return {std::move(out),
            Err(EC::InvalidArg, "", "", "Destination path is empty")};
  }

  const std::string dst_host = dst.target.nickname;
  auto append_warning = [&out](std::string src_path, std::string dst_path,
                               ECM rcm) {
    if (!(rcm)) {
      out.warnings.emplace_back(std::move(src_path), std::move(dst_path),
                                std::move(rcm));
    }
  };
  const auto query_dst_stat = [&](const std::string &path) -> ECMData<PathInfo> {
    PathTarget target = {};
    target.nickname = dst_host;
    target.path = path;
    return filesystem_service_.Stat(target, control, false,
                                    dst.resolved_target.client);
  };
  const auto query_src_listdir =
      [&](const std::string &host, const ClientHandle &client,
          const std::string &path) -> ECMData<std::vector<PathInfo>> {
    PathTarget target = {};
    target.nickname = host;
    target.path = path;
    return filesystem_service_.Listdir(target, control, client);
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
              Err(EC::InvalidArg, "", "",
                  AMStr::fmt("Clone mode requires exactly one source host, got "
                             "{}",
                             src.data.size()))};
    }
    const auto &[src_host, source_data] = *src.data.begin();
    if (!source_data.resolved_target.client) {
      return {std::move(out),
              Err(EC::InvalidHandle, "", "",
                  AMStr::fmt("Clone source client is null: {}", src_host))};
    }
    if (source_data.paths.size() != 1) {
      return {std::move(out),
              Err(EC::InvalidArg, "", "",
                  AMStr::fmt("Clone mode requires exactly one compacted source "
                             "path, got {}",
                             source_data.paths.size()))};
    }

    const PathInfo source_root = source_data.paths.front();
    if (opt.ignore_special_file && source_root.is_special()) {
      return {std::move(out),
              Err(EC::NotAFile, "", "",
                  AMStr::fmt("Unsupported source type: {}", source_root.path))};
    }
    if (dst.dst_info.has_value()) {
      const bool src_is_dir = source_root.type == PathType::DIR;
      const bool dst_is_dir = dst.dst_info->type == PathType::DIR;
      if (src_is_dir != dst_is_dir) {
        return {std::move(out),
                Err(EC::NotADirectory, "", "",
                    AMStr::fmt("Clone type conflict: src {} -> dst {}",
                               source_root.path, dst.target.path))};
      }
    }

    pending.emplace_back(src_host, source_data.resolved_target.client,
                         source_root, source_root, dst.target.path);
  } else {
    for (const auto &[src_host, source_data] : src.data) {
      if (auto stop_rcm = control.BuildRequestECM(); stop_rcm.has_value()) {
        return {std::move(out), *stop_rcm};
      }
      if (!source_data.resolved_target.client) {
        append_warning(
            "", source_data.resolved_target.target.path,
            Err(EC::InvalidHandle, "", "",
                AMStr::fmt("Source client is null for host {}", src_host)));
        continue;
      }
      for (const auto &source_root : source_data.paths) {
        if (opt.ignore_special_file && source_root.is_special()) {
          append_warning(
              source_root.path, "",
              Err(EC::NotAFile, "", "",
                  AMStr::fmt("Unsupported source type: {}", source_root.path)));
          continue;
        }
        const std::string mapped_root =
            AMPath::join(dst.target.path, AMPath::basename(source_root.path));
        pending.emplace_back(src_host, source_data.resolved_target.client,
                             source_root, source_root, mapped_root);
      }
    }
  }

  while (!pending.empty()) {
    if (auto stop_rcm = control.BuildRequestECM(); stop_rcm.has_value()) {
      return {std::move(out), *stop_rcm};
    }

    PendingState state = pending.front();
    pending.pop_front();
    if (!state.src_client) {
      append_warning("", state.node.path,
                     Err(EC::InvalidHandle, "", "", "Source client is null"));
      continue;
    }
    const std::string rel = AMPath::RelativeFrom(state.root.path, state.node.path);
    const std::string mapped_dst =
        rel.empty() ? state.mapped_root : AMPath::join(state.mapped_root, rel);

    if (state.src_host == dst_host && state.node.path == mapped_dst) {
      continue;
    }
    if (opt.ignore_special_file && state.node.is_special()) {
      append_warning(
          state.node.path, mapped_dst,
          Err(EC::NotAFile, "", "",
              AMStr::fmt("Unsupported source node type: {}", state.node.path)));
      continue;
    }

    if (state.node.type == PathType::DIR) {
      auto dst_stat = query_dst_stat(mapped_dst);
      const bool dst_exists = (dst_stat.rcm);
      if (dst_exists && dst_stat.data.type != PathType::DIR) {
        append_warning(state.node.path, mapped_dst,
                       Err(EC::NotADirectory, "", "",
                           AMStr::fmt("Directory/file type conflict: {} -> {}",
                                      state.node.path, mapped_dst)));
        continue;
      }
      if (!dst_exists && !IsPathNotExistError(dst_stat.rcm.code)) {
        if (IsStopError_(dst_stat.rcm.code)) {
          return {std::move(out), dst_stat.rcm};
        }
        append_warning(state.node.path, mapped_dst, dst_stat.rcm);
        continue;
      }

      auto list_result =
          query_src_listdir(state.src_host, state.src_client, state.node.path);
      if (!(list_result.rcm)) {
        if (IsStopError_(list_result.rcm.code)) {
          return {std::move(out), list_result.rcm};
        }
        append_warning(state.node.path, mapped_dst, list_result.rcm);
        continue;
      }

      if (list_result.data.empty()) {
        if (!opt.mkdir) {
          append_warning(
              state.node.path, mapped_dst,
              Err(EC::ParentDirectoryNotExist, "", "",
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
          Err(EC::NotAFile, "", "",
              AMStr::fmt("Unsupported source file type: {}", state.node.path)));
      continue;
    }

    const std::string parent_path =
        AMPath::dirname(mapped_dst).empty() ? "." : AMPath::dirname(mapped_dst);
    auto parent_stat = query_dst_stat(parent_path);
    if ((parent_stat.rcm)) {
      if (parent_stat.data.type != PathType::DIR) {
        append_warning(state.node.path, mapped_dst,
                       Err(EC::NotADirectory, "", "",
                           AMStr::fmt("Destination parent is not directory: {}",
                                      parent_path)));
        continue;
      }
    } else if (!IsPathNotExistError(parent_stat.rcm.code)) {
      if (IsStopError_(parent_stat.rcm.code)) {
        return {std::move(out), parent_stat.rcm};
      }
      append_warning(state.node.path, mapped_dst, parent_stat.rcm);
      continue;
    } else if (!opt.mkdir) {
      append_warning(state.node.path, mapped_dst,
                     Err(EC::ParentDirectoryNotExist, "", "",
                         AMStr::fmt("Destination parent does not exist: {}",
                                    parent_path)));
      continue;
    }

    auto dst_stat = query_dst_stat(mapped_dst);
    const bool dst_exists = (dst_stat.rcm);
    if (dst_exists && dst_stat.data.type == PathType::DIR) {
      append_warning(
          state.node.path, mapped_dst,
          Err(EC::NotAFile, "", "",
              AMStr::fmt("Destination is directory: {}", mapped_dst)));
      continue;
    }
    if (!dst_exists && !IsPathNotExistError(dst_stat.rcm.code)) {
      if (IsStopError_(dst_stat.rcm.code)) {
        return {std::move(out), dst_stat.rcm};
      }
      append_warning(state.node.path, mapped_dst, dst_stat.rcm);
      continue;
    }
    if (dst_exists && !dst_stat.data.is_regular()) {
      append_warning(
          state.node.path, mapped_dst,
          Err(EC::NotAFile, "", "",
              AMStr::fmt("Destination type mismatch: {}", mapped_dst)));
      continue;
    }

    AMDomain::transfer::TransferTask file_task(
        state.node.path, mapped_dst, state.src_host, dst_host, state.node.size,
        state.node.type);
    file_task.overwrite = dst_exists && dst_stat.data.is_regular();

    if (opt.resume) {
      if (state.node.type != PathType::FILE) {
        append_warning(state.node.path, mapped_dst,
                       Err(EC::NotAFile, "", "",
                           AMStr::fmt("Resume only supports file source: {}",
                                      state.node.path)));
        continue;
      }
      if (!dst_exists) {
        append_warning(state.node.path, mapped_dst,
                       Err(EC::PathNotExist, "", "",
                           AMStr::fmt("Resume requires destination file: {}",
                                      mapped_dst)));
        continue;
      }
      if (dst_stat.data.type != PathType::FILE) {
        append_warning(state.node.path, mapped_dst,
                       Err(EC::NotAFile, "", "",
                           AMStr::fmt("Resume requires destination file: {}",
                                      mapped_dst)));
        continue;
      }
      if (dst_stat.data.size > state.node.size) {
        append_warning(
            state.node.path, mapped_dst,
            Err(EC::InvalidArg, "", "",
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
  return {std::move(out), OK};
}

ECMData<HttpDownloadPlan> TransferAppService::BuildHttpDownloadPlan(
    const std::optional<PathTarget> &dst_target,
    const std::string &suggested_filename, const ControlComponent &control) {
  HttpDownloadPlan out = {};
  PathTarget base_target = {};
  const bool use_cwd_default = !dst_target.has_value();

  if (dst_target.has_value()) {
    base_target = *dst_target;
  } else {
    auto cwd_result = filesystem_service_.GetCwd(control);
    if (!(cwd_result.rcm)) {
      return {std::move(out), cwd_result.rcm};
    }
    base_target = cwd_result.data;
  }
  if (base_target.nickname.empty()) {
    base_target.nickname = filesystem_service_.CurrentNickname();
  }
  if (base_target.path.empty()) {
    base_target.path = ".";
  }
  if (base_target.is_wildcard ||
      HasWildcard(base_target.path)) {
    return {std::move(out),
            Err(EC::InvalidArg, "", "", "wget destination cannot be wildcard")};
  }

  auto client_result = filesystem_service_.GetClient(base_target.nickname, control);
  if (!(client_result.rcm) || !client_result.data) {
    return {std::move(out), (client_result.rcm) ? Err(EC::InvalidHandle, "", "",
                                                      "Destination client is null")
                                                : client_result.rcm};
  }
  auto abs_result = AMApplication::filesystem::FileSystemAppService::
      ResolveAbsolutePath(client_result.data, base_target.path, control);
  if (!(abs_result.rcm)) {
    return {std::move(out), abs_result.rcm};
  }

  base_target.path = abs_result.data;
  base_target.is_wildcard = false;
  base_target.is_user_path =
      !base_target.path.empty() && base_target.path.front() == '~';

  const std::string final_name = AMStr::Strip(suggested_filename).empty()
                                     ? "download.bin"
                                     : suggested_filename;
  PathTarget final_target = base_target;
  std::string final_abs_path = base_target.path;

  auto base_stat =
      filesystem_service_.Stat(base_target, control, false, client_result.data);
  if (use_cwd_default) {
    if (!(base_stat.rcm)) {
      return {std::move(out), base_stat.rcm};
    }
    if (base_stat.data.type != PathType::DIR) {
      return {std::move(out), Err(EC::NotADirectory, "", "",
                                  AMStr::fmt("cwd is not directory: {}",
                                             base_target.path))};
    }
    final_abs_path = AMPath::join(base_target.path, final_name);
    final_target.path = final_abs_path;
    final_target.is_wildcard = false;
    final_target.is_user_path = false;
  } else if ((base_stat.rcm) && base_stat.data.type == PathType::DIR) {
    final_abs_path = AMPath::join(base_target.path, final_name);
    final_target.path = final_abs_path;
    final_target.is_wildcard = false;
    final_target.is_user_path = false;
  } else if (!(base_stat.rcm) &&
             !IsPathNotExistError(base_stat.rcm.code)) {
    return {std::move(out), base_stat.rcm};
  }

  out.final_target = final_target;
  out.resolved_target.target = final_target;
  out.resolved_target.abs_path = final_abs_path;
  out.resolved_target.client = client_result.data;

  auto final_stat =
      filesystem_service_.Stat(final_target, control, false, client_result.data);
  if ((final_stat.rcm)) {
    out.dst_info = final_stat.data;
    if (out.dst_info->type == PathType::DIR) {
      return {std::move(out),
              Err(EC::NotAFile, "", "",
                  AMStr::fmt("Destination is directory: {}", final_abs_path))};
    }
    return {std::move(out), OK};
  }
  if (IsPathNotExistError(final_stat.rcm.code)) {
    out.dst_info = std::nullopt;
    return {std::move(out), OK};
  }
  return {std::move(out), final_stat.rcm};
}
} // namespace AMApplication::transfer
