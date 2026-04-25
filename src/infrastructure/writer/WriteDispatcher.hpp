#pragma once
#include "domain/writer/IWriteSchedulerPort.hpp"
#include <atomic>
#include <mutex>
#include <queue>
#include <semaphore>
#include <stop_token>
#include <thread>

/**
 * @brief Infrastructure async writer for config/log persistence tasks.
 */
class AMInfraAsyncWriter final
    : public AMDomain::writer::IWriteSchedulerPort {
public:
  /**
   * @brief Construct an idle dispatcher.
   */
  AMInfraAsyncWriter() = default;

  /**
   * @brief Ensure worker thread is stopped before destruction.
   */
  ~AMInfraAsyncWriter() override { Stop(); }

  /**
   * @brief Start worker thread when not already running.
   */
  void Start() override;

  /**
   * @brief Stop worker thread and wait for completion.
   */
  void Stop() override;

  /**
   * @brief Enqueue one task for worker execution.
   */
  void Submit(Task task) override;

  /**
   * @brief Wait until queued and active tasks are fully drained.
   */
  void WaitIdle() override;

  /**
   * @brief Return whether worker thread is running.
   */
  [[nodiscard]] bool IsRunning() const override;

private:
  /**
   * @brief Worker loop that drains queued tasks.
   */
  void Loop_(std::stop_token stop_token);

  mutable std::mutex mtx_;
  std::queue<Task> queue_;
  std::counting_semaphore<> task_ready_{0};
  std::jthread worker_;
  std::atomic<bool> running_{false};
  std::atomic<size_t> pending_tasks_{0};
};
