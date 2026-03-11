#pragma once

#include "application/client/runtime/ClientMaintainer.hpp"
#include "foundation/DataClass.hpp"

#include <memory>
#include <string>
#include <utility>

namespace AMApplication::TransferRuntime {

class TaskPlanner {
public:
  using ECM = std::pair<ErrorCode, std::string>;

  /**
   * @brief Plan concrete transfer tasks from source/destination paths and
   * client context.
   */
  static std::pair<ECM, TASKS>
  LoadTasks(const std::string &src, const std::string &dst,
            const std::shared_ptr<ClientMaintainer> &hostm,
            const std::string &src_host = "", const std::string &dst_host = "",
            bool clone = false, bool overwrite = false, bool mkdir = true,
            bool ignore_sepcial_file = true, bool resume = false,
            std::shared_ptr<TaskControlToken> control_token = nullptr,
            int timeout_ms = -1, int64_t start_time = -1);
};

} // namespace AMApplication::TransferRuntime
