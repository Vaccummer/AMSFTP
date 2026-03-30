#pragma once

#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <cstddef>
#include <string>
#include <vector>

namespace AMApplication::TransferWorkflow {
/**
 * @brief Application-owned summary DTO for one transfer task.
 */
struct TaskSummaryView {
  std::string id;
  TaskStatus status = TaskStatus::Pending;
  ECM result = {EC::Success, ""};
  size_t success_filenum = 0;
  size_t filenum = 0;
  size_t total_transferred_size = 0;
  size_t total_size = 0;
  double submit_time = 0;
  double start_time = 0;
  double finished_time = 0;
  int running_thread = -1;
};

/**
 * @brief Application-owned DTO for one transfer task entry.
 */
struct TaskEntryView {
  size_t index = 0;
  PathType path_type = PathType::FILE;
  std::string src_host;
  std::string src;
  std::string dst_host;
  std::string dst;
  size_t size = 0;
  size_t transferred = 0;
  ECM result = {EC::Success, ""};
};

/**
 * @brief Application-owned DTO for one transfer-set item.
 */
struct TransferSetView {
  size_t index = 0;
  std::vector<AMDomain::filesystem::ClientPath> srcs;
  AMDomain::filesystem::ClientPath dst;
  bool clone = false;
  bool mkdir = true;
  bool overwrite = false;
  bool ignore_special_file = true;
  bool resume = false;
};

/**
 * @brief Application-owned aggregate DTO for one transfer task detail.
 */
struct TaskView {
  TaskSummaryView summary;
  std::vector<TaskEntryView> entries;
  std::vector<TransferSetView> transfer_sets;
};
} // namespace AMApplication::TransferWorkflow
