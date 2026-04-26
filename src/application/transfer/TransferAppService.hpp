#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FileSystemAppService.hpp"
#include "application/transfer/TransferAppDTO.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/core/DataClass.hpp"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace AMApplication::log {
class LoggerAppService;
}

namespace AMApplication::transfer {

class TransferAppService final : public NonCopyableNonMovable {
public:
  using TaskID = AMDomain::transfer::TaskID;
  using TaskHandle = std::shared_ptr<AMDomain::transfer::TaskInfo>;
  using TaskStatus = AMDomain::transfer::TaskStatus;

  TransferAppService(
      AMDomain::transfer::ITransferPoolPort &transfer_pool,
      AMApplication::client::ClientAppService &client_service,
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMApplication::log::LoggerAppService *logger = nullptr);
  ~TransferAppService() override = default;

  ECM Submit(const TaskHandle &task_info);

  ECM Pause(TaskID id, int timeout_ms = 5000, int grace_period_ms = 1500);
  ECM Resume(TaskID id, int timeout_ms = 5000);
  std::pair<TaskHandle, ECM> Terminate(TaskID id, int timeout_ms = 5000,
                                       int grace_period_ms = 1500);

  [[nodiscard]] std::optional<TaskStatus> GetStatus(TaskID id) const;
  [[nodiscard]] TaskHandle FindTask(TaskID id) const;
  [[nodiscard]] TaskHandle GetActiveTask(TaskID id) const;

  [[nodiscard]] std::unordered_map<TaskID, TaskHandle>
  GetAllActiveTasks() const;
  [[nodiscard]] std::unordered_map<TaskID, TaskHandle>
  GetAllHistoryTasks() const;
  [[nodiscard]] std::unordered_map<TaskID, TaskHandle> GetPendingTasks() const;
  [[nodiscard]] std::unordered_map<TaskID, TaskHandle>
  GetConductingTasks() const;
  [[nodiscard]] std::unordered_map<TaskID, TaskHandle> GetPausedTasks() const;
  [[nodiscard]] std::unordered_map<TaskID, TaskHandle> GetFinishedTasks() const;

  [[nodiscard]] TaskHandle GetFinishedTask(TaskID id, bool remove = true);
  [[nodiscard]] TaskHandle GetResultTask(TaskID id, bool remove = true);
  bool RemoveFinished(TaskID id);
  void ClearFinished();

  [[nodiscard]] std::vector<TaskID> ListTaskIDs() const;
  [[nodiscard]] ECMData<DstResolveResult>
  ResolveTransferDst(PathTarget dst, TransferClientContainer *clients,
                     const ControlComponent &control);
  [[nodiscard]] ECMData<SourceResolveResult>
  ResolveTransferSrc(std::vector<PathTarget> srcs,
                     TransferClientContainer *clients,
                     const ControlComponent &control, bool error_stop = true);
  [[nodiscard]] ECMData<BuildTransferTaskResult> BuildTransferTasks(
      const SourceResolveResult &src, const DstResolveResult &dst,
      const ControlComponent &control, const BuildTransferTaskOptions &opt);
  [[nodiscard]] ECMData<HttpDownloadPlan>
  BuildHttpDownloadPlan(const std::optional<PathTarget> &dst_target,
                        const std::string &suggested_filename,
                        const ControlComponent &control);

private:
  void OnTaskCompleted_(const TaskHandle &task_info);
  static void MarkUnfinishedEntries_(const TaskHandle &task_info,
                                     const ECM &entry_rcm);
  static void ReleaseClients_(const TaskHandle &task_info);
  [[nodiscard]] ECMData<AMDomain::transfer::TransferClientContainer>
  RecollectTransferClients_(const TaskHandle &task_info);
  void TraceTask_(AMDomain::client::TraceLevel level, EC code, TaskID id,
                  const std::string &action,
                  const std::string &message = "") const;
  void TraceTask_(AMDomain::client::TraceLevel level, const ECM &rcm, TaskID id,
                  const std::string &action,
                  const std::string &message = "") const;
  void TraceTask_(AMDomain::client::TraceLevel level, const ECM &rcm,
                  const TaskHandle &task_info, const std::string &action,
                  const std::string &message = "") const;
  void StorePaused_(const TaskHandle &task_info);
  void StoreFinished_(const TaskHandle &task_info);

private:
  AMDomain::transfer::ITransferPoolPort &transfer_pool_;
  AMApplication::client::ClientAppService &client_service_;
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMApplication::log::LoggerAppService *logger_ = nullptr;
  mutable AMAtomic<std::unordered_map<TaskID, TaskHandle>> paused_tasks_ = {};
  mutable AMAtomic<std::unordered_map<TaskID, TaskHandle>> finished_tasks_ = {};
};

} // namespace AMApplication::transfer
