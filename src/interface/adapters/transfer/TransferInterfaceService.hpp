#pragma once

#include "application/filesystem/FilesystemAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "interface/prompt/Prompt.hpp"
#include <functional>
#include <string>
#include <vector>

namespace AMInterface::style {
class AMStyleService;
}

namespace AMInterface::transfer {
enum class TransferConfirmPolicy {
  RequireConfirm,
  AutoApprove,
  DenyIfConfirmNeeded
};

struct TransferRunArg {
  std::vector<AMDomain::transfer::UserTransferSet> transfer_sets = {};
  bool quiet = false;
  bool run_async = false;
  AMDomain::client::amf control_token = nullptr;
  TransferConfirmPolicy confirm_policy = TransferConfirmPolicy::RequireConfirm;
};

struct TransferTaskListArg {
  bool pending = false;
  bool suspend = false;
  bool finished = false;
  bool conducting = false;
};

struct TransferTaskShowArg {
  std::vector<std::string> ids = {};
};

struct TransferTaskControlArg {
  std::vector<std::string> ids = {};
  int timeout_ms = 5000;
};

struct TransferTaskInspectArg {
  std::string id = {};
  bool show_sets = true;
  bool show_entries = true;
};

struct TransferTaskResultArg {
  std::vector<std::string> ids = {};
  bool remove = false;
};

class TransferInterfaceService final : public NonCopyableNonMovable {
public:
  TransferInterfaceService(
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
      AMDomain::transfer::ITransferPoolPort &transfer_pool,
      std::function<
          AMDomain::client::ClientControlComponent(AMDomain::client::amf)>
          control_component_factory = {},
      AMInterface::style::AMStyleService *style_service = nullptr);
  ~TransferInterfaceService() override = default;

  ECM Transfer(const TransferRunArg &arg) const;
  ECM TaskList(const TransferTaskListArg &arg) const;
  ECM TaskShow(const TransferTaskShowArg &arg) const;
  ECM TaskPause(const TransferTaskControlArg &arg) const;
  ECM TaskResume(const TransferTaskControlArg &arg) const;
  ECM TaskTerminate(const TransferTaskControlArg &arg) const;
  ECM TaskInspect(const TransferTaskInspectArg &arg) const;
  ECM TaskResult(const TransferTaskResultArg &arg) const;
  void GetTaskCounts(size_t *pending_count, size_t *conducting_count) const;

private:
  struct WildcardConfirmRequest {
    std::vector<PathInfo> matches = {};
    std::string src_host = {};
    std::string dst_host = {};
  };

  static const char *TaskStatusText_(AMDomain::transfer::TaskStatus status);
  static const char *PathTypeText_(PathType type);
  void PrintTaskSummary_(
      const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const;
  void PrintTaskSummaryDetailed_(
      const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const;
  void PrintTaskEntries_(
      const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const;
  void PrintTaskSets_(
      const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) const;
  [[nodiscard]] AMDomain::client::ClientControlComponent
  ResolveControl_(AMDomain::client::amf token) const;
  [[nodiscard]] ECM
  ConfirmWildcard_(const std::vector<WildcardConfirmRequest> &requests,
                   TransferConfirmPolicy policy) const;
  [[nodiscard]] ECM
  BuildTaskInfo_(const TransferRunArg &arg,
                 const AMDomain::client::ClientControlComponent &control,
                 std::shared_ptr<AMDomain::transfer::TaskInfo> *out_task_info,
                 std::vector<ECM> *warnings) const;
  [[nodiscard]] ECM
  WaitTask_(const AMDomain::transfer::TaskInfo::ID &task_id,
            const AMDomain::client::ClientControlComponent &control) const;
  [[nodiscard]] std::shared_ptr<AMDomain::transfer::TaskInfo>
  FindTask_(const std::string &task_id) const;

private:
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
  AMDomain::transfer::ITransferPoolPort &transfer_pool_;
  AMInterface::style::AMStyleService *style_service_ = nullptr;
};
} // namespace AMInterface::transfer
