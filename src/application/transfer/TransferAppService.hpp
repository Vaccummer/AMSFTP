#pragma once

#include "application/filesystem/FilesystemAppService.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/core/DataClass.hpp"

#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

namespace AMApplication::transfer {

class TransferAppService final : public NonCopyableNonMovable {
public:
  using TaskInfo = AMDomain::transfer::TaskInfo;
  using TaskId = TaskInfo::ID;
  using TaskHandle = std::shared_ptr<TaskInfo>;
  using TaskStatus = AMDomain::transfer::TaskStatus;

  TransferAppService(AMDomain::transfer::ITransferPoolPort &transfer_pool,
                     AMApplication::filesystem::FilesystemAppService &filesystem_service);
  ~TransferAppService() override = default;

  ECM Submit(const TaskHandle &task_info);

  ECM Pause(TaskId id, int timeout_ms = 5000);
  ECM Resume(TaskId id, int timeout_ms = 5000);
  std::pair<TaskHandle, ECM> Terminate(TaskId id, int timeout_ms = 5000);

  [[nodiscard]] std::optional<TaskStatus> GetStatus(TaskId id) const;
  [[nodiscard]] TaskHandle FindTask(TaskId id) const;
  [[nodiscard]] TaskHandle GetActiveTask(TaskId id) const;

  [[nodiscard]] std::unordered_map<TaskId, TaskHandle> GetAllActiveTasks() const;
  [[nodiscard]] std::unordered_map<TaskId, TaskHandle> GetAllHistoryTasks() const;
  [[nodiscard]] std::unordered_map<TaskId, TaskHandle> GetPendingTasks() const;
  [[nodiscard]] std::unordered_map<TaskId, TaskHandle> GetConductingTasks() const;
  [[nodiscard]] std::unordered_map<TaskId, TaskHandle> GetPausedTasks() const;
  [[nodiscard]] std::unordered_map<TaskId, TaskHandle> GetFinishedTasks() const;

  [[nodiscard]] TaskHandle GetFinishedTask(TaskId id, bool remove = true);
  [[nodiscard]] TaskHandle GetResultTask(TaskId id, bool remove = true);
  bool RemoveFinished(TaskId id);
  void ClearFinished();

  [[nodiscard]] std::vector<TaskId> ListTaskIds() const;

private:
  void OnTaskCompleted_(const TaskHandle &task_info);
  static void MarkUnfinishedEntries_(const TaskHandle &task_info,
                                     const ECM &entry_rcm);
  static void ReleaseClients_(const TaskHandle &task_info);
  void StorePaused_(const TaskHandle &task_info);
  void StoreFinished_(const TaskHandle &task_info);

private:
  AMDomain::transfer::ITransferPoolPort &transfer_pool_;
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  mutable AMAtomic<std::unordered_map<TaskId, TaskHandle>> paused_tasks_ = {};
  mutable AMAtomic<std::unordered_map<TaskId, TaskHandle>> finished_tasks_ = {};
};

} // namespace AMApplication::transfer
