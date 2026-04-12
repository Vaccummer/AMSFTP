#pragma once

#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include "interface/prompt/Prompt.hpp"
#include <string>
#include <vector>

namespace AMInterface::cli {
namespace task_arg_detail {

inline ECM UnsupportedCommand(AMInterface::prompt::AMPromptIOManager &prompt,
                              const std::string &message) {
  (void)prompt;
  const ECM rcm = Err(EC::OperationUnsupported, __func__, "", message);
  return rcm;
}

} // namespace task_arg_detail

/**
 * @brief CLI argument container for task list.
 */
struct TaskListArgs : BaseArgStruct {
  bool pending = false;
  bool suspend = false;
  bool finished = false;
  bool conducting = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::transfer::TransferTaskListArg arg = {};
    arg.pending = pending;
    arg.suspend = suspend;
    arg.finished = finished;
    arg.conducting = conducting;
    return managers.interfaces.transfer_service->TaskList(arg);
  }
  void reset() override {
    pending = false;
    suspend = false;
    finished = false;
    conducting = false;
  }
};

/**
 * @brief CLI argument container for task show.
 */
struct TaskShowArgs : BaseArgStruct {
  std::vector<size_t> ids = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::transfer::TransferTaskShowArg arg = {};
    arg.ids = ids;
    return managers.interfaces.transfer_service->TaskShow(arg);
  }
  void reset() override { ids.clear(); }
};

/**
 * @brief CLI argument container for task inspect.
 */
struct TaskInspectArgs : BaseArgStruct {
  size_t id = 0;
  bool set = false;
  bool entry = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::transfer::TransferTaskInspectArg arg = {};
    arg.id = id;
    if (!set && !entry) {
      arg.show_sets = true;
      arg.show_entries = true;
    } else {
      arg.show_sets = set;
      arg.show_entries = entry;
    }
    return managers.interfaces.transfer_service->TaskInspect(arg);
  }
  void reset() override {
    id = 0;
    set = false;
    entry = false;
  }
};

/**
 * @brief CLI argument container for task thread.
 */
struct TaskThreadArgs : BaseArgStruct {
  int num = -1;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    (void)num;
    return task_arg_detail::UnsupportedCommand(
        managers.interfaces.prompt_io_manager,
        "task thread is deprecated; configure transfer "
        "pool via runtime settings");
  }
  void reset() override { num = -1; }
};

/**
 * @brief CLI argument container for task query.
 */
struct TaskEntryArgs : BaseArgStruct {
  std::vector<size_t> ids = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::transfer::TransferTaskShowArg arg = {};
    arg.ids = ids;
    return managers.interfaces.transfer_service->TaskShow(arg);
  }
  void reset() override { ids.clear(); }
};

/**
 * @brief CLI argument container for task control.
 */
struct TaskControlArgs : BaseArgStruct {
  enum class Action { Terminate, Pause, Resume };
  std::vector<size_t> ids = {};
  Action action = Action::Terminate;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::transfer::TransferTaskControlArg arg = {};
    arg.ids = ids;
    arg.timeout_ms = 5000;
    switch (action) {
    case TaskControlArgs::Action::Terminate:
      return managers.interfaces.transfer_service->TaskTerminate(arg);
    case TaskControlArgs::Action::Pause:
      return managers.interfaces.transfer_service->TaskPause(arg);
    case TaskControlArgs::Action::Resume:
      return managers.interfaces.transfer_service->TaskResume(arg);
    default:
      return Err(EC::InvalidArg, __func__, "", "Unknown task control action");
    }
  }
  void reset() override { ids.clear(); }
};

/**
 * @brief CLI argument container for task retry (failed tasks).
 */
struct TaskRetryArgs : BaseArgStruct {
  std::string id = {};
  bool is_async = false;
  bool quiet = false;
  std::vector<int> indices = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    (void)id;
    (void)is_async;
    (void)quiet;
    (void)indices;
    return task_arg_detail::UnsupportedCommand(
        managers.interfaces.prompt_io_manager,
        "task retry is deprecated in current service mode");
  }
  void reset() override {
    id.clear();
    is_async = false;
    quiet = false;
    indices.clear();
  }
};

} // namespace AMInterface::cli



