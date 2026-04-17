#pragma once

#include "domain/transfer/TransferDomainModel.hpp"
#include <memory>
#include <unordered_map>

namespace AMDomain::transfer {
enum class ActiveStopReason { Pause, Terminate };

class ITransferPoolPort {
public:
  virtual ~ITransferPoolPort() = default;

  virtual ECM Shutdown(int timeout_ms = 5000) = 0;

  virtual size_t ThreadCount(size_t new_count = 0) = 0;

  virtual size_t MaxThreadCount(size_t new_max = 0) = 0;
  [[nodiscard]] virtual std::unordered_map<size_t, bool>
  GetThreadIDs() const = 0;

  virtual ECM Submit(std::shared_ptr<TaskInfo> task_info) = 0;

  [[nodiscard]] virtual std::optional<TaskStatus>
  GetStatus(const TaskInfo::ID &id) const = 0;

  [[nodiscard]] virtual std::shared_ptr<TaskInfo>
  GetActiveTask(const TaskInfo::ID &id) const = 0;

  [[nodiscard]] virtual std::unordered_map<TaskInfo::ID,
                                           std::shared_ptr<TaskInfo>>
  GetAllActiveTasks() const = 0;

  [[nodiscard]] virtual std::unordered_map<TaskInfo::ID,
                                           std::shared_ptr<TaskInfo>>
  GetPendingTasks() const = 0;

  [[nodiscard]] virtual std::unordered_map<TaskInfo::ID,
                                           std::shared_ptr<TaskInfo>>
  GetConductingTasks() const = 0;

  virtual std::pair<std::shared_ptr<TaskInfo>, ECM>
  StopActive(const TaskInfo::ID &id, ActiveStopReason reason,
             int timeout_ms = 5000, int grace_period_ms = 1500) = 0;

  virtual std::pair<std::shared_ptr<TaskInfo>, ECM>
  Terminate(const TaskInfo::ID &id, int timeout_ms = 5000,
            int grace_period_ms = 1500) = 0;
};

std::unique_ptr<ITransferPoolPort>
CreateTransferPoolPort(const TransferManagerArg &arg = {});
} // namespace AMDomain::transfer

