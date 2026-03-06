#include "infrastructure/writer/WriteDispatcher.hpp"

/**
 * @brief Start worker thread when not already running.
 */
void AMInfraAsyncWriter::Start() {
  if (running_.load(std::memory_order_relaxed)) {
    return;
  }
  shutdown_requested_.store(false, std::memory_order_relaxed);
  running_.store(true, std::memory_order_relaxed);
  worker_ = std::thread([this]() { Loop_(); });
}

/**
 * @brief Stop worker thread and wait for completion.
 */
void AMInfraAsyncWriter::Stop() {
  shutdown_requested_.store(true, std::memory_order_relaxed);
  cv_.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
  running_.store(false, std::memory_order_relaxed);
  WaitIdle();
}

/**
 * @brief Enqueue one task for worker execution.
 */
void AMInfraAsyncWriter::Submit(Task task) {
  if (!task) {
    return;
  }
  if (!running_.load(std::memory_order_relaxed)) {
    task();
    return;
  }
  {
    std::lock_guard<std::mutex> lock(mtx_);
    queue_.push(std::move(task));
  }
  cv_.notify_one();
}

/**
 * @brief Return whether worker thread is running.
 */
bool AMInfraAsyncWriter::IsRunning() const {
  return running_.load(std::memory_order_relaxed);
}

/**
 * @brief Wait until queued and active tasks are fully drained.
 */
void AMInfraAsyncWriter::WaitIdle() {
  std::unique_lock<std::mutex> lock(mtx_);
  idle_cv_.wait(lock, [this]() { return queue_.empty() && active_tasks_ == 0; });
}

/**
 * @brief Worker loop that drains queued tasks.
 */
void AMInfraAsyncWriter::Loop_() {
  while (true) {
    Task task;
    {
      std::unique_lock<std::mutex> lock(mtx_);
      cv_.wait(lock, [this]() {
        return shutdown_requested_.load(std::memory_order_relaxed) ||
               !queue_.empty();
      });
      if (shutdown_requested_.load(std::memory_order_relaxed) &&
          queue_.empty()) {
        break;
      }
      task = std::move(queue_.front());
      queue_.pop();
      ++active_tasks_;
    }
    if (task) {
      task();
    }
    {
      std::lock_guard<std::mutex> lock(mtx_);
      if (active_tasks_ > 0) {
        --active_tasks_;
      }
      if (queue_.empty() && active_tasks_ == 0) {
        idle_cv_.notify_all();
      }
    }
  }
  {
    std::lock_guard<std::mutex> lock(mtx_);
    if (queue_.empty() && active_tasks_ == 0) {
      idle_cv_.notify_all();
    }
  }
  running_.store(false, std::memory_order_relaxed);
}
