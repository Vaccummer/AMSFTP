#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace AMFoundation {

template <typename T, size_t Capacity> class SPSCRingBuffer {
  static_assert((Capacity & (Capacity - 1)) == 0,
                "Capacity must be a power of 2");
  static constexpr size_t kMask = Capacity - 1;

  // Decoder: which value field does T have?
  template <typename U>
  static constexpr bool has_transferred_v =
      requires(U u) { u.transferred; };

  static int64_t extract_val(const T &item) {
    if constexpr (has_transferred_v<T>) {
      return static_cast<int64_t>(item.transferred);
    } else {
      return static_cast<int64_t>(item.value);
    }
  }

  static T make_item(int64_t ts, int64_t val) {
    using TP = std::chrono::steady_clock::time_point;
    if constexpr (has_transferred_v<T>) {
      return T{TP(std::chrono::nanoseconds(ts)), static_cast<size_t>(val)};
    } else {
      return T{TP(std::chrono::nanoseconds(ts)), val};
    }
  }

public:
  SPSCRingBuffer() = default;

  void push(const T &item) { push_impl_(item); }
  void push(T &&item) { push_impl_(std::move(item)); }

  [[nodiscard]] size_t count() const {
    const size_t head = head_.load(std::memory_order_acquire);
    const size_t tail = tail_.load(std::memory_order_acquire);
    return tail - head;
  }

  [[nodiscard]] bool empty() const { return count() == 0; }

  [[nodiscard]] std::optional<T> front() const {
    const size_t head = head_.load(std::memory_order_acquire);
    const size_t tail = tail_.load(std::memory_order_acquire);
    if (head == tail)
      return std::nullopt;
    return load_item(head & kMask);
  }

  [[nodiscard]] std::optional<T> back() const {
    const size_t head = head_.load(std::memory_order_acquire);
    const size_t tail = tail_.load(std::memory_order_acquire);
    if (head == tail)
      return std::nullopt;
    return load_item((tail - 1) & kMask);
  }

  void clear() {
    head_.store(tail_.load(std::memory_order_acquire),
                std::memory_order_release);
  }

  template <typename F> void for_each(F &&func) const {
    const size_t head = head_.load(std::memory_order_acquire);
    const size_t tail = tail_.load(std::memory_order_acquire);
    for (size_t i = head; i < tail; ++i) {
      func(load_item(i & kMask));
    }
  }

  template <typename Pred>
  [[nodiscard]] std::optional<T> find_first(Pred &&pred) const {
    const size_t head = head_.load(std::memory_order_acquire);
    const size_t tail = tail_.load(std::memory_order_acquire);
    for (size_t i = head; i < tail; ++i) {
      T item = load_item(i & kMask);
      if (pred(item)) {
        return item;
      }
    }
    return std::nullopt;
  }

private:
  template <typename U> void push_impl_(U item) {
    const size_t tail = tail_.load(std::memory_order_relaxed);
    const int64_t ts = item.when.time_since_epoch().count();
    const int64_t val = extract_val(item);
    timestamps_[tail & kMask].store(ts, std::memory_order_release);
    values_[tail & kMask].store(val, std::memory_order_release);
    tail_.store(tail + 1, std::memory_order_release);

    const size_t head = head_.load(std::memory_order_relaxed);
    if (tail - head >= Capacity) {
      head_.store(tail - Capacity + 1, std::memory_order_release);
    }
  }

  T load_item(size_t idx) const {
    const int64_t ts =
        timestamps_[idx].load(std::memory_order_relaxed);
    const int64_t val =
        values_[idx].load(std::memory_order_relaxed);
    return make_item(ts, val);
  }

  std::array<std::atomic<int64_t>, Capacity> timestamps_{};
  std::array<std::atomic<int64_t>, Capacity> values_{};
  std::atomic<size_t> head_{0};
  std::atomic<size_t> tail_{0};
};

} // namespace AMFoundation
