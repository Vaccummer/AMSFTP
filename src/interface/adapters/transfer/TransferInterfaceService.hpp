#pragma once

#include "application/filesystem/FilesystemAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "interface/prompt/Prompt.hpp"
#include <functional>
#include <optional>
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
  int timeout_ms = -1;
  TransferConfirmPolicy confirm_policy = TransferConfirmPolicy::RequireConfirm;
};

struct HttpGetArg {
  std::string src_url = {};
  std::optional<AMDomain::filesystem::PathTarget> dst_target = std::nullopt;
  std::string proxy = {};
  std::string https_proxy = {};
  std::string bear_token = {};
  bool resume = false;
  bool overwrite = false;
  bool quiet = false;
  bool run_async = false;
  int timeout_ms = -1;
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

  void SetDefaultControlToken(const AMDomain::client::amf &token);
  [[nodiscard]] AMDomain::client::amf GetDefaultControlToken() const;

  ECM Transfer(
      const TransferRunArg &arg,
      const std::optional<AMDomain::client::ClientControlComponent> &component =
          std::nullopt) const;
  ECM HttpGet(
      const HttpGetArg &arg,
      const std::optional<AMDomain::client::ClientControlComponent> &component =
          std::nullopt) const;
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
  ResolveControl_(
      const std::optional<AMDomain::client::ClientControlComponent> &component,
      int timeout_ms) const;
  [[nodiscard]] ECM
  ConfirmWildcard_(const std::vector<WildcardConfirmRequest> &requests,
                   TransferConfirmPolicy policy) const;
  [[nodiscard]] ECM
  BuildTaskInfo_(const TransferRunArg &arg,
                 const AMDomain::client::ClientControlComponent &control,
                 std::shared_ptr<AMDomain::transfer::TaskInfo> *out_task_info,
                 std::vector<ECM> *warnings) const;
  [[nodiscard]] ECM
  WaitTask_(const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info,
            const AMDomain::client::ClientControlComponent &control) const;
  [[nodiscard]] std::shared_ptr<AMDomain::transfer::TaskInfo>
  FindTask_(const std::string &task_id) const;

private:
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
  AMDomain::transfer::ITransferPoolPort &transfer_pool_;
  AMInterface::style::AMStyleService *style_service_ = nullptr;
  AMDomain::client::amf default_control_token_ = nullptr;
};
} // namespace AMInterface::transfer
