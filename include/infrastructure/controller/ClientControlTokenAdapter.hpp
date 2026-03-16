#pragma once

#include "domain/client/ClientPort.hpp"
#include "foundation/DataClass.hpp"

#include <memory>
#include <utility>

namespace AMInfra::controller {
/**
 * @brief Adapter that exposes TaskControlToken through IClientTaskControlPort.
 */
class TaskControlToClientControlAdapter final
    : public AMDomain::client::IClientTaskControlPort {
public:
  /**
   * @brief Construct adapter from one optional task-control token.
   */
  explicit TaskControlToClientControlAdapter(::amf task_token)
      : task_token_(std::move(task_token)) {}

  /**
   * @brief Request interruption on adapted task token.
   */
  void RequestInterrupt() override {
    if (!task_token_) {
      return;
    }
    (void)task_token_->Kill(TaskControlSignal::SigInt);
  }

  /**
   * @brief Clear interruption state on adapted task token.
   */
  void ClearInterrupt() override {
    if (!task_token_) {
      return;
    }
    (void)task_token_->Reset();
  }

  /**
   * @brief Return true when adapted task token is interrupted.
   */
  [[nodiscard]] bool IsInterrupted() const override {
    return task_token_ && !task_token_->IsRunning();
  }

  /**
   * @brief Register wakeup callback on adapted task token.
   */
  size_t RegisterWakeup(std::function<void()> wake_cb) override {
    if (!task_token_ || !wake_cb) {
      return 0;
    }
    return task_token_->RegisterWakeup(std::move(wake_cb));
  }

  /**
   * @brief Unregister wakeup callback on adapted task token.
   */
  void UnregisterWakeup(size_t token) override {
    if (!task_token_ || token == 0) {
      return;
    }
    task_token_->UnregisterWakeup(token);
  }

private:
  ::amf task_token_ = nullptr;
};

/**
 * @brief Convert one task token into client control token port.
 */
inline AMDomain::client::amf AdaptClientInterruptFlag(::amf task_token) {
  if (!task_token) {
    return nullptr;
  }
  return std::make_shared<TaskControlToClientControlAdapter>(
      std::move(task_token));
}
} // namespace AMInfra::controller
