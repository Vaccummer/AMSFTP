#pragma once
#include "domain/writer/AsyncWriteSchedulerPort.hpp"
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

/**
 * @brief Infrastructure async writer for config/log persistence tasks.
 */
class AMInfraAsyncWriter final : public AMDomain::writer::AMAsyncWriteSchedulerPort {
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
  void Loop_();

  mutable std::mutex mtx_;
  std::condition_variable cv_;
  std::condition_variable idle_cv_;
  std::queue<Task> queue_;
  std::thread worker_;
  std::atomic<bool> running_{false};
  std::atomic<bool> shutdown_requested_{false};
  size_t active_tasks_ = 0;
};

/**
 * @brief Backward compatibility alias used by current config storage code.
 */
using AMInfraConfigWriteDispatcher = AMInfraAsyncWriter;

