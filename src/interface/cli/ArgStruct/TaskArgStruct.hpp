#pragma once

#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include "interface/prompt/Prompt.hpp"
#include <string>
#include <vector>

namespace AMInterface::cli {
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
  std::vector<AMDomain::transfer::TaskID> ids = {};
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
    if (!managers.domain.transfer_pool.IsReady()) {
      return Err(EC::InvalidHandle, "", "transfer_pool",
                 "Transfer pool is not initialized");
    }

    if (num < 0) {
      const size_t current_num = managers.domain.transfer_pool->ThreadCount();
      const size_t max_num = managers.domain.transfer_pool->MaxThreadCount();
      managers.interfaces.prompt_io_manager->FmtPrint(
          "Current Thread Num : {}    Max Thread Num : {}", current_num,
          max_num);
      return OK;
    }

    if (num <= 0) {
      return Err(EC::InvalidArg, "", std::to_string(num),
                 "Thread num must be > 0");
    }

    const size_t old_max = managers.domain.transfer_pool->MaxThreadCount();
    const size_t new_max =
        managers.domain.transfer_pool->MaxThreadCount(static_cast<size_t>(num));
    managers.interfaces.prompt_io_manager->FmtPrint("Max Thread Num {} -> {}",
                                                    old_max, new_max);
    return OK;
  }
  void reset() override { num = -1; }
};

/**
 * @brief CLI argument container for task query.
 */
struct TaskEntryArgs : BaseArgStruct {
  std::vector<AMDomain::transfer::TaskID> ids = {};
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
  std::vector<AMDomain::transfer::TaskID> ids = {};
  int grace_period_ms = 1500;
  Action action = Action::Terminate;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::transfer::TransferTaskControlArg arg = {};
    arg.ids = ids;
    arg.timeout_ms = 5000;
    arg.grace_period_ms = grace_period_ms;
    switch (action) {
    case TaskControlArgs::Action::Terminate:
      return managers.interfaces.transfer_service->TaskTerminate(arg);
    case TaskControlArgs::Action::Pause:
      return managers.interfaces.transfer_service->TaskPause(arg);
    case TaskControlArgs::Action::Resume:
      return managers.interfaces.transfer_service->TaskResume(arg);
    default:
      return Err(EC::InvalidArg, "", "", "Unknown task control action");
    }
  }
  void reset() override {
    ids.clear();
    grace_period_ms = 1500;
  }
};

} // namespace AMInterface::cli
