#pragma once

#include "domain/client/ClientPort.hpp"
#include "foundation/core/DataClass.hpp"

#include <memory>
#include <string>
#include <utility>

namespace AMApplication::TransferRuntime {

class TaskPlanner {
public:
  using ECM = std::pair<ErrorCode, std::string>;

  /**
 * @brief Plan concrete transfer tasks from source/destination paths and
 * prepared client handles.
 */
  static std::pair<ECM, TASKS>
  LoadTasks(const std::string &src, const std::string &dst,
            const AMDomain::client::ClientHandle &src_client,
            const AMDomain::client::ClientHandle &dst_client,
            const std::string &src_host = "", const std::string &dst_host = "",
            bool clone = false, bool overwrite = false, bool mkdir = true,
            bool ignore_special_file = true, bool resume = false,
            AMDomain::client::amf control_token = nullptr,
            int timeout_ms = -1, int64_t start_time = -1);
};

} // namespace AMApplication::TransferRuntime
