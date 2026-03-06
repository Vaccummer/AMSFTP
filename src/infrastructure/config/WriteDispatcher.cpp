#include "infrastructure/config/WriteDispatcher.hpp"

/**
 * @brief Start worker thread when not already running.
 */
void AMInfraConfigWriteDispatcher::Start() {
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
void AMInfraConfigWriteDispatcher::Stop() {
  shutdown_requested_.store(true, std::memory_order_relaxed);
  cv_.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
  running_.store(false, std::memory_order_relaxed);
}

/**
 * @brief Enqueue one task for worker execution.
 */
void AMInfraConfigWriteDispatcher::Submit(std::function<void()> task) {
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
bool AMInfraConfigWriteDispatcher::IsRunning() const {
  return running_.load(std::memory_order_relaxed);
}

/**
 * @brief Worker loop that drains queued tasks.
 */
void AMInfraConfigWriteDispatcher::Loop_() {
  while (true) {
    std::function<void()> task;
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
    }
    if (task) {
      task();
    }
  }
  running_.store(false, std::memory_order_relaxed);
}

