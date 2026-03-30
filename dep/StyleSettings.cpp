#include "application/config/StyleSettings.hpp"

#include <algorithm>
#include <limits>

namespace {
/**
 * @brief Clamp signed integer into inclusive range.
 */
int64_t ClampInt64_(int64_t value, int64_t min_value, int64_t max_value) {
  if (min_value > max_value) {
    std::swap(min_value, max_value);
  }
  if (value < min_value) {
    return min_value;
  }
  if (value > max_value) {
    return max_value;
  }
  return value;
}
} // namespace

namespace AMApplication::config {
/**
 * @brief Clamp complete-menu arguments into runtime-safe range.
 */
void AMStyleCompleteMenuArgs::Normalize() {
  maxnum = std::max<int64_t>(1, maxnum);
  maxrows_perpage = std::max<int64_t>(1, maxrows_perpage);
  async_workers = std::max<int64_t>(1, async_workers);
  complete_delay_ms =
      ClampInt64_(complete_delay_ms, 0, std::numeric_limits<int64_t>::max());
}

/**
 * @brief Clamp table arguments into runtime-safe range.
 */
void AMStyleTableArgs::Normalize() {
  left_padding = std::max<int64_t>(0, left_padding);
  right_padding = std::max<int64_t>(0, right_padding);
  top_padding = std::max<int64_t>(0, top_padding);
  bottom_padding = std::max<int64_t>(0, bottom_padding);
  refresh_interval_ms = std::max<int64_t>(1, refresh_interval_ms);
  speed_window_size = std::max<int64_t>(1, speed_window_size);
}

/**
 * @brief Clamp progress-bar arguments into runtime-safe range.
 */
void AMStyleProgressBarArgs::Normalize() {
  if (fill.empty()) {
    fill = "█";
  }
  if (lead.empty()) {
    lead = "▓";
  }
  if (remaining.empty()) {
    remaining = " ";
  }
  bar_width = std::max<int64_t>(1, bar_width);
  refresh_interval_ms = std::max<int64_t>(1, refresh_interval_ms);
  speed_window_size = std::max<int64_t>(1, speed_window_size);
}

/**
 * @brief Clamp whole style snapshot into runtime-safe values.
 */
void AMStyleSnapshot::Normalize() {
  complete_menu.Normalize();
  table.Normalize();
  progress_bar.Normalize();
}
} // namespace AMApplication::config
