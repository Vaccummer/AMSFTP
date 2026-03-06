#pragma once

#include "foundation/DataClass.hpp"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

/**
 * @brief Background task dispatcher used by config storage write operations.
 */
class AMInfraConfigWriteDispatcher : NonCopyableNonMovable {
public:
  /**
   * @brief Construct an idle dispatcher.
   */
  AMInfraConfigWriteDispatcher() = default;

  /**
   * @brief Ensure worker thread is stopped before destruction.
   */
  ~AMInfraConfigWriteDispatcher() { Stop(); }

  /**
   * @brief Start worker thread when not already running.
   */
  void Start();

  /**
   * @brief Stop worker thread and wait for completion.
   */
  void Stop();

  /**
   * @brief Enqueue one task for worker execution.
   */
  void Submit(std::function<void()> task);

  /**
   * @brief Return whether worker thread is running.
   */
  [[nodiscard]] bool IsRunning() const;

private:
  /**
   * @brief Worker loop that drains queued tasks.
   */
  void Loop_();

  mutable std::mutex mtx_;
  std::condition_variable cv_;
  std::queue<std::function<void()>> queue_;
  std::thread worker_;
  std::atomic<bool> running_{false};
  std::atomic<bool> shutdown_requested_{false};
};

