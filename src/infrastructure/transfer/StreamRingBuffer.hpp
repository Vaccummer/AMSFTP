#pragma once

#include <condition_variable>
#include <functional>
#include <span>

namespace AMInfra::transfer {
class StreamRingBuffer {
private:
  std::vector<char> buffer_ = {};
  size_t capacity_ = 0;
  std::atomic<size_t> head_{0};
  std::atomic<size_t> tail_{0};
  mutable std::mutex wait_mtx_ = {};
  mutable std::condition_variable wait_cv_ = {};

public:
  explicit StreamRingBuffer(size_t size)
      : capacity_(std::max<size_t>(size, 1)) {
    buffer_.resize(capacity_);
  }

  [[nodiscard]] size_t available() const {
    return tail_.load(std::memory_order_acquire) -
           head_.load(std::memory_order_relaxed);
  }

  [[nodiscard]] size_t writable() const { return capacity_ - available(); }

  [[nodiscard]] std::span<char> get_write_span() {
    const size_t t = tail_.load(std::memory_order_relaxed);
    const size_t h = head_.load(std::memory_order_acquire);
    const size_t pos = t % capacity_;
    const size_t used = t - h;
    const size_t free_space = capacity_ - used;
    const size_t contig =
        capacity_ - pos > free_space ? free_space : capacity_ - pos;
    return std::span<char>(buffer_.data() + pos, contig);
  }

  [[nodiscard]] std::pair<char *, size_t> get_write_ptr() {
    auto span = get_write_span();
    return {span.data(), span.size()};
  }

  void commit_write(size_t len) {
    tail_.fetch_add(len, std::memory_order_release);
    wait_cv_.notify_all();
  }

  [[nodiscard]] std::span<char> get_read_span() {
    const size_t h = head_.load(std::memory_order_relaxed);
    const size_t t = tail_.load(std::memory_order_acquire);
    const size_t pos = h % capacity_;
    const size_t avail = t - h;
    const size_t contig = capacity_ - pos > avail ? avail : capacity_ - pos;
    return std::span<char>(buffer_.data() + pos, contig);
  }

  [[nodiscard]] std::pair<char *, size_t> get_read_ptr() {
    auto span = get_read_span();
    return {span.data(), span.size()};
  }

  void commit_read(size_t len) {
    head_.fetch_add(len, std::memory_order_release);
    wait_cv_.notify_all();
  }

  [[nodiscard]] bool empty() const { return available() == 0; }

  [[nodiscard]] bool full() const { return writable() == 0; }

  [[nodiscard]] size_t get_capacity() const { return capacity_; }

  void Reset() {
    head_.store(0, std::memory_order_relaxed);
    tail_.store(0, std::memory_order_relaxed);
    NotifyAll();
  }

  void NotifyAll() const { wait_cv_.notify_all(); }

  bool WaitWritable(std::function<bool()> should_stop = {},
                    int wait_ms = 50) const {
    if (writable() > 0) {
      return true;
    }
    std::unique_lock<std::mutex> lock(wait_mtx_);
    wait_cv_.wait_for(
        lock, std::chrono::milliseconds(std::max(1, wait_ms)),
        [&]() { return writable() > 0 || (should_stop && should_stop()); });
    return writable() > 0;
  }

  bool WaitReadable(std::function<bool()> should_stop = {},
                    int wait_ms = 50) const {
    if (available() > 0) {
      return true;
    }
    std::unique_lock<std::mutex> lock(wait_mtx_);
    wait_cv_.wait_for(
        lock, std::chrono::milliseconds(std::max(1, wait_ms)),
        [&]() { return available() > 0 || (should_stop && should_stop()); });
    return available() > 0;
  }
};
} // namespace AMInfra::transfer
