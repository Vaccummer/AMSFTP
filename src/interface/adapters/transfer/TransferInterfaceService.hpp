#pragma once

#include "application/filesystem/FilesystemAppService.hpp"
#include "application/transfer/TransferAppService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "interface/adapters/transfer/TransferInterfaceDTO.hpp"
#include "interface/prompt/Prompt.hpp"
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::style {
class AMStyleService;
}

namespace AMInterface::transfer {
class TransferInterfaceService final : public NonCopyableNonMovable {
public:
  TransferInterfaceService(
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMApplication::transfer::TransferAppService &transfer_service,
      AMInterface::prompt::PromptIOManager &prompt_io_manager,
      std::function<ControlComponent(AMDomain::client::amf)>
          control_component_factory = {},
      AMInterface::style::AMStyleService *style_service = nullptr,
      int transfer_bar_refresh_interval_ms = 0);
  ~TransferInterfaceService() override = default;

  void SetDefaultControlToken(const AMDomain::client::amf &token);
  [[nodiscard]] AMDomain::client::amf GetDefaultControlToken() const;

  ECM Transfer(
      const TransferRunArg &arg,
      const std::optional<ControlComponent> &component = std::nullopt) const;
  ECM HttpGet(
      const HttpGetArg &arg,
      const std::optional<ControlComponent> &component = std::nullopt) const;
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
  [[nodiscard]] ControlComponent
  ResolveControl_(const std::optional<ControlComponent> &component,
                  int timeout_ms) const;
  [[nodiscard]] ECM
  ConfirmWildcard_(const std::vector<WildcardConfirmRequest> &requests,
                   TransferConfirmPolicy policy) const;
  [[nodiscard]] ECM BuildTaskInfo_(
      const TransferRunArg &arg, const ControlComponent &control,
      std::shared_ptr<AMDomain::transfer::TaskInfo> *out_task_info,
      std::vector<ECM> *warnings,
      const std::function<void(const std::string &)> &stage_reporter = {})
      const;
  [[nodiscard]] ECM
  WaitTask_(const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info,
            const ControlComponent &control) const;
  [[nodiscard]] std::shared_ptr<AMDomain::transfer::TaskInfo>
  FindTask_(AMDomain::transfer::TaskID task_id) const;

private:
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::prompt::PromptIOManager &prompt_io_manager_;
  AMApplication::transfer::TransferAppService &transfer_app_service_;
  AMInterface::style::AMStyleService *style_service_ = nullptr;
  int transfer_bar_refresh_interval_ms_ = 0;
  AMDomain::client::amf default_control_token_ = nullptr;
};
} // namespace AMInterface::transfer
