#pragma once
#include "foundation/core/DataClass.hpp"
#include <functional>

namespace AMDomain::writer {
/**
 * @brief Domain port for asynchronous write task scheduling.
 */
class IWriteSchedulerPort : NonCopyableNonMovable {
public:
  using Task = std::function<void()>;
  IWriteSchedulerPort() = default;
  virtual ~IWriteSchedulerPort() = default;

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
} // namespace AMDomain::writer

/**
 * @brief Global convenience alias for the domain write scheduler port.
 */
using IWriteSchedulerPort = AMDomain::writer::IWriteSchedulerPort;
