#pragma once

#include "foundation/DataClass.hpp"
#include <functional>

/**
 * @brief Domain port for asynchronous write task scheduling.
 */
class AMAsyncWriteSchedulerPort : NonCopyableNonMovable {
public:
  using Task = std::function<void()>;

  ~AMAsyncWriteSchedulerPort() override = default;

  /**
   * @brief Start the worker loop.
   */
  virtual void Start() = 0;

  /**
   * @brief Stop the worker loop and drain pending tasks.
   */
  virtual void Stop() = 0;

  /**
   * @brief Submit one task for asynchronous execution.
   */
  virtual void Submit(Task task) = 0;

  /**
   * @brief Wait until queued and in-flight tasks are fully drained.
   */
  virtual void WaitIdle() = 0;

  /**
   * @brief Return whether scheduler worker is currently running.
   */
  [[nodiscard]] virtual bool IsRunning() const = 0;
};

