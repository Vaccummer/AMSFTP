#include "infrastructure/writer/WriteDispatcher.hpp"

/**
 * @brief Start worker thread when not already running.
 */
void AMInfraAsyncWriter::Start() {
  if (running_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  stop_requested_.store(false, std::memory_order_release);
  worker_ = std::thread([this]() { Loop_(); });
}

/**
 * @brief Stop worker thread and wait for completion.
 */
void AMInfraAsyncWriter::Stop() {
  running_.store(false, std::memory_order_release);
  stop_requested_.store(true, std::memory_order_release);
  task_ready_.release();
  if (worker_.joinable()) {
    worker_.join();
  }
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
  pending_tasks_.fetch_add(1, std::memory_order_acq_rel);
  {
    std::lock_guard<std::mutex> lock(mtx_);
    queue_.push(std::move(task));
  }
  task_ready_.release();
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
  while (true) {
    const size_t pending = pending_tasks_.load(std::memory_order_acquire);
    if (pending == 0) {
      return;
    }
    pending_tasks_.wait(pending, std::memory_order_acquire);
  }
}

/**
 * @brief Worker loop that drains queued tasks.
 */
void AMInfraAsyncWriter::Loop_() {
  while (true) {
    task_ready_.acquire();
    if (stop_requested_.load(std::memory_order_acquire)) {
      std::lock_guard<std::mutex> lock(mtx_);
      if (queue_.empty()) {
        break;
      }
    }

    Task task;
    {
      std::lock_guard<std::mutex> lock(mtx_);
      if (queue_.empty()) {
        if (stop_requested_.load(std::memory_order_acquire)) {
          break;
        }
        continue;
      }
      task = std::move(queue_.front());
      queue_.pop();
    }
    if (task) {
      task();
    }
    const size_t previous =
        pending_tasks_.fetch_sub(1, std::memory_order_acq_rel);
    if (previous == 1) {
      pending_tasks_.notify_all();
    }
  }
  running_.store(false, std::memory_order_release);
  pending_tasks_.notify_all();
}
