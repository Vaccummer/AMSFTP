#pragma once
#include "foundation/DataClass.hpp"
#include <memory>
#include <string>
#include <vector>

namespace AMDomain::transfer {
/**
 * @brief Transfer execution port for sync/async task submission.
 */
class ITransferExecutorPort {
public:
  virtual ~ITransferExecutorPort() = default;

  /**
   * @brief Execute transfer sets synchronously.
   */
  virtual ECM Transfer(const std::vector<UserTransferSet> &transfer_sets,
                       bool quiet, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Execute transfer sets asynchronously.
   */
  virtual ECM TransferAsync(const std::vector<UserTransferSet> &transfer_sets,
                            bool quiet, amf interrupt_flag = nullptr) = 0;
};

/**
 * @brief Transfer task query/control port.
 */
class ITransferTaskPort {
public:
  virtual ~ITransferTaskPort() = default;

  /**
   * @brief List all transfer task identifiers.
   */
  [[nodiscard]] virtual std::vector<std::string> ListTaskIds() const = 0;

  /**
   * @brief Resolve one task by identifier.
   */
  [[nodiscard]] virtual std::shared_ptr<TaskInfo>
  FindTask(const std::string &task_id) const = 0;

  /**
   * @brief Pause one task.
   */
  virtual ECM Pause(const std::string &task_id) = 0;

  /**
   * @brief Resume one paused task.
   */
  virtual ECM Resume(const std::string &task_id) = 0;

  /**
   * @brief Terminate one task.
   */
  virtual ECM Terminate(const std::string &task_id, int timeout_ms = 5000) = 0;
};
} // namespace AMDomain::transfer
