#include "TaskPlanner.hpp"

#include "foundation/core/Path.hpp"
#include "foundation/tools/time.hpp"

#include <filesystem>
#include <utility>

namespace AMApplication::TransferRuntime {

/**
 * @brief Plan concrete transfer tasks from source/destination paths and
 * prepared client handles.
 */
std::pair<TaskPlanner::ECM, TASKS>
TaskPlanner::LoadTasks(const std::string &src, const std::string &dst,
                       const AMDomain::client::ClientHandle &src_client,
                       const AMDomain::client::ClientHandle &dst_client,
                       const std::string &src_host, const std::string &dst_host,
                       bool clone, bool overwrite, bool mkdir,
                       bool ignore_special_file, bool resume,
                       AMDomain::client::amf control_token,
                       int timeout_ms, int64_t start_time) {
  using EC = ErrorCode;
  start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
  TASKS tasks = {};

  if (!src_client || !dst_client) {
    return {ECM{EC::InvalidHandle, "LoadTasks requires ready client handles"},
            tasks};
  }

  auto [rc3, src_stat] =
      src_client->IOPort().stat(src, false, timeout_ms, start_time,
                                control_token);
  if (rc3.first != EC::Success) {
    return {rc3, tasks};
  }

  if (resume && src_stat.type == PathType::DIR) {
    return {ECM{EC::NotAFile,
                AMStr::fmt("Resume requires src to be a file: {}", src)},
            tasks};
  }

  auto dstf = dst;
  auto srcf = src;
  bool is_dst_file = resume || clone;
  if (!is_dst_file && src_stat.type == PathType::FILE) {
    const std::string dst_ext = AMPathStr::extname(dstf);
    if (AMPathStr::extname(srcf) == dst_ext && !dst_ext.empty()) {
      is_dst_file = true;
    }
  }

  if (src_stat.type != PathType::DIR) {
    if (ignore_special_file && src_stat.type != PathType::FILE) {
      return {ECM{EC::NotAFile, AMStr::fmt("Src is not a common file and "
                                           "ignore_special_file is true: {}",
                                           srcf)},
              {}};
    }

    if (resume) {
      if (src_stat.type != PathType::FILE) {
        return {ECM{EC::NotAFile,
                    AMStr::fmt("Resume requires src to be a file: {}", srcf)},
                tasks};
      }
      auto [dst_stat_rcm, dst_info] =
          dst_client->IOPort().stat(dstf, false, timeout_ms, start_time,
                                    control_token);
      if (dst_stat_rcm.first != EC::Success) {
        return {ECM{EC::PathNotExist,
                    AMStr::fmt("Resume requires dst to exist: {}", dstf)},
                tasks};
      }
      if (dst_info.type != PathType::FILE) {
        return {ECM{EC::NotAFile,
                    AMStr::fmt("Resume requires dst to be a file: {}", dstf)},
                tasks};
      }
      if (dst_info.size > src_stat.size) {
        return {ECM{EC::InvalidArg,
                    AMStr::fmt("Resume requires dst size <= src size: {} > {}",
                               dst_info.size, src_stat.size)},
                tasks};
      }
    }

    if (!is_dst_file) {
      dstf = AMPathStr::join(dstf, AMPathStr::basename(srcf));
    }

    auto [rcm4, dst_parent_info] = dst_client->IOPort().stat(
        AMPathStr::dirname(dstf), false, timeout_ms, start_time,
        control_token);
    if (rcm4.first != EC::Success && !mkdir) {
      return {ECM{EC::ParentDirectoryNotExist,
                  AMStr::fmt("Dst parent path not exists: {}",
                             AMPathStr::dirname(dstf))},
              tasks};
    }
    if (rcm4.first == EC::Success && dst_parent_info.type != PathType::DIR) {
      return {ECM{EC::NotADirectory,
                  AMStr::fmt("Dst parent path is not a directory: {}",
                             dst_parent_info.path)},
              tasks};
    }

    if (rcm4.first == EC::Success) {
      auto [rcm5, dst_info] =
          dst_client->IOPort().stat(dstf, false, timeout_ms, start_time,
                                    control_token);
      if (rcm5.first == EC::Success) {
        if (dst_info.type == PathType::DIR) {
          return {ECM{EC::NotAFile,
                      AMStr::fmt("Dst already exists and is a directory: {}",
                                 dstf)},
                  tasks};
        }
        if (!overwrite && !resume) {
          return {ECM{EC::PathAlreadyExists,
                      AMStr::fmt("Dst already exists: {}", dstf)},
                  tasks};
        }
      }
    }

    tasks.emplace_back(srcf, dstf, src_host, dst_host, src_stat.size,
                       src_stat.type);
    if (resume) {
      auto [dst_stat_rcm, dst_info] =
          dst_client->IOPort().stat(dstf, false, timeout_ms, start_time,
                                    control_token);
      if (dst_stat_rcm.first != EC::Success ||
          dst_info.type != PathType::FILE) {
        return {ECM{EC::InvalidArg,
                    AMStr::fmt("Resume requires dst to be a file: {}", dstf)},
                tasks};
      }
      tasks.back().transferred = dst_info.size;
    }
    return {ECM{EC::Success, ""}, tasks};
  }

  auto [rcm6, dst_info] =
      dst_client->IOPort().stat(dstf, false, timeout_ms, start_time,
                                control_token);
  if (rcm6.first != EC::Success && !mkdir) {
    return {ECM{EC::ParentDirectoryNotExist,
                AMStr::fmt("Dst parent path not exists: {}", dstf)},
            tasks};
  }
  if (rcm6.first == EC::Success && dst_info.type != PathType::DIR) {
    return {
        ECM{EC::NotADirectory,
            AMStr::fmt("Dst already exists and is not a directory: {}", dstf)},
        tasks};
  }

  auto [rcm7, src_pack] = src_client->IOPort().iwalk(srcf, true, false, nullptr,
                                                     timeout_ms, start_time,
                                                     control_token);
  if (rcm7.first != EC::Success) {
    return {rcm7, tasks};
  }

  const auto &src_paths = src_pack.first;
  tasks.reserve(src_paths.size());

  TransferTask taskt;
  std::string dst_n;
  for (auto &item : src_paths) {
    if (control_token && control_token->IsInterrupted()) {
      return {ECM{EC::Terminate, "Load tasks interrupted by user"}, tasks};
    }
    if (timeout_ms > 0 && AMTime::miliseconds() - start_time >= timeout_ms) {
      return {ECM{EC::OperationTimeout, "Load tasks timeout"}, tasks};
    }

    const std::string base_path = clone ? srcf : AMPathStr::dirname(srcf);
    dst_n = AMPathStr::join(
        dstf, std::filesystem::relative(item.path, base_path).string());
    auto [rcm8, dst_info2] =
        dst_client->IOPort().stat(dst_n, false, timeout_ms, start_time,
                                  control_token);
    if (rcm8.first == EC::Success) {
      if (dst_info2.type == PathType::DIR) {
        taskt = TransferTask(item.path, dst_n, src_host, dst_host, item.size,
                             item.type);
        taskt.IsFinished = true;
        taskt.rcm = ECM{EC::NotAFile, "Dst already exists and is a directory"};
      } else if (!overwrite) {
        taskt = TransferTask(item.path, dst_n, src_host, dst_host, item.size,
                             item.type);
        taskt.IsFinished = true;
        taskt.rcm = ECM{EC::PathAlreadyExists, "Dst already exists"};
      } else {
        taskt = TransferTask(item.path, dst_n, src_host, dst_host, item.size,
                             item.type);
      }
      tasks.push_back(taskt);
      continue;
    }
    tasks.emplace_back(item.path, dst_n, src_host, dst_host, item.size,
                       item.type);
  }
  return {ECM{EC::Success, ""}, tasks};
}

} // namespace AMApplication::TransferRuntime
