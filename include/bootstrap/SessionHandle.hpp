#pragma once

#include "interface/CLIArg.hpp"
#include <atomic>
#include <memory>

namespace AMBootstrap {
/**
 * @brief Session-lifetime execution context for one CLI run/loop.
 */
struct SessionHandle : NonCopyableNonMovable {
  /**
   * @brief Construct session handle with one dedicated task-control token.
   */
  SessionHandle() : task_control_token(TaskControlToken::CreateShared()) {}

  /**
   * @brief Reset command runtime state before dispatch/interactive entry.
   */
  void ResetRunContext() {
    if (!task_control_token) {
      task_control_token = TaskControlToken::CreateShared();
    }
    task_control_token->Reset();
    run_context.rcm = {EC::Success, ""};
    run_context.async = false;
    run_context.enforce_interactive = false;
    run_context.command_name.clear();
    run_context.enter_interactive = false;
    run_context.request_exit = false;
    run_context.skip_loop_exit_callbacks = false;
    run_context.task_control_token = task_control_token;
    if (!run_context.exit_code) {
      run_context.exit_code = std::make_shared<std::atomic<int>>(0);
    }
    run_context.exit_code->store(0, std::memory_order_relaxed);
  }

  amf task_control_token = nullptr;
  CliRunContext run_context;
};
} // namespace AMBootstrap
