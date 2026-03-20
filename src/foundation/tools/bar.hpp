#pragma once
#define _WINSOCKAPI_

#include "foundation/tools/string.hpp"
#include "Isocline/isocline.h"
#include "third_party/indicators/color.hpp"
#include "third_party/indicators/cursor_control.hpp"
#include "third_party/indicators/progress_bar.hpp"
#include "third_party/indicators/setting.hpp"
#include "third_party/indicators/terminal_size.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <iomanip>
#include <mutex>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace AMBar {
class ProgressBar {
public:
  explicit ProgressBar(size_t total_size = 0, std::string unit = "B",
                       size_t bar_width = 50, bool show_eta = true,
                       bool colored = true)
      : total_(total_size), unit_(std::move(unit)), bar_width_(bar_width),
        show_eta_(show_eta), colored_(colored),
        start_time_(std::chrono::steady_clock::now()) {}

  // Added: dynamically set total size (optionally reset timer)
  void set_total(size_t new_total, bool reset_timer = false) {
    total_ = new_total;
    if (reset_timer) {
      start_time_ = std::chrono::steady_clock::now();
    }
    // If current progress exceeds new total, adjust automatically
    if (current_ > total_) {
      current_ = total_;
    }
    redraw();
  }

  // Update current progress
  void update(size_t current) {
    if (total_ == 0) {
      // If total is unknown, estimate using current as a known maximum
      if (current > current_) {
        total_ = current * 2; // Heuristic: assume final total is 2x current
      }
    }
    if (current > total_)
      current = total_;
    current_ = current;
    redraw();
  }

  void finish() {
    if (total_ == 0)
      total_ = current_; // Prevent division by zero
    update(total_);
    std::cout << "\n";
  }

private:
  void redraw() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_)
            .count();
    double elapsed_sec = elapsed_ms / 1000.0;

    double percent =
        (total_ == 0) ? 0.0 : (static_cast<double>(current_) / total_) * 100.0;
    if (percent > 100.0)
      percent = 100.0;

    double speed = (elapsed_sec > 0) ? current_ / elapsed_sec : 0.0;
    double eta_sec = (speed > 0 && current_ < total_ && total_ > 0)
                         ? (total_ - current_) / speed
                         : 0.0;

    auto [current_str, unit_scale] = format_size(current_);
    auto [total_str, _] = format_size(total_);

    size_t filled =
        (total_ == 0) ? 0 : static_cast<size_t>(percent / 100.0 * bar_width_);
    if (filled > bar_width_)
      filled = bar_width_;

    std::string bar = std::string(filled, '=');
    if (filled < bar_width_) {
      bar += '>';
      bar.resize(bar_width_, ' ');
    } else {
      bar.resize(bar_width_, '=');
    }

    const char *reset = colored_ ? "\033[0m" : "";
    const char *green = colored_ ? "\033[32m" : "";
    const char *yellow = colored_ ? "\033[33m" : "";

    std::cout << "\r";
    std::cout << "[" << green << bar << reset << "] ";

    if (total_ == 0) {
      std::cout << "?% " << current_str << " " << unit_scale;
    } else {
      std::cout << std::fixed << std::setprecision(1) << percent << "% ";
      std::cout << current_str << "/" << total_str << " " << unit_scale;
    }

    if (speed > 0) {
      auto [speed_str, speed_unit] = format_size(static_cast<size_t>(speed));
      std::cout << " " << speed_str << speed_unit << "/s";
    }

    if (show_eta_ && eta_sec > 0) {
      int eta = static_cast<int>(eta_sec);
      int h = eta / 3600, m = (eta % 3600) / 60, s = eta % 60;
      std::cout << " ETA: " << yellow;
      if (h > 0)
        std::cout << h << "h ";
      if (m > 0)
        std::cout << m << "m ";
      std::cout << s << "s" << reset;
    }

    std::cout << std::flush;
  }

  std::pair<std::string, std::string> format_size(size_t size) const {
    if (size == 0)
      return {"0", unit_};

    const char *units[] = {"", "K", "M", "G", "T"};
    int idx = 0;
    double val = static_cast<double>(size);

    while (val >= 1024.0 && idx < 4) {
      val /= 1024.0;
      idx++;
    }

    std::ostringstream oss;
    if (val == static_cast<long long>(val)) {
      oss << static_cast<long long>(val);
    } else {
      oss << std::fixed << std::setprecision(1) << val;
    }

    return {oss.str(), std::string(units[idx]) + unit_};
  }

private:
  size_t total_ = 0;
  size_t current_ = 0;
  std::string unit_;
  size_t bar_width_;
  bool show_eta_;
  bool colored_;
  std::chrono::steady_clock::time_point start_time_;

  ProgressBar(const ProgressBar &) = delete;
  ProgressBar &operator=(const ProgressBar &) = delete;
};

struct AMProgressBarStyle {
  size_t bar_width = 30;
  std::string start = "[";
  std::string end = "]";
  std::string fill = "=";
  std::string lead = ">";
  std::string remainder = " ";
  std::variant<indicators::Color, std::string> color = indicators::Color::blue;
  int width_offset = 30;
  bool show_percentage = true;
  bool show_elapsed_time = true;
  bool show_remaining_time = true;
};

/**
 * @brief Progress bar wrapper that updates its text using
 * indicators::ProgressBar.
 *
 * The bar itself does not print unless it is managed by a group refresh.
 */
class AMProgressBar {
public:
  inline static std::atomic<int> active_count_{0};
  /**
   * @brief Construct a progress bar with a total size and prefix.
   * @param total_size Total number of bytes to complete.
   * @param prefix Display prefix.
   */
  explicit AMProgressBar(int64_t total_size = 0, std::string prefix = "",
                         AMProgressBarStyle style = {})
      : total_size_(std::max<int64_t>(0, total_size)),
        prefix_(std::move(prefix)), prefix_field_(), postfix_(),
        bar_width_(style.bar_width > 0 ? style.bar_width : 30),
        start_token_(style.start), end_token_(style.end),
        show_percentage_(style.show_percentage),
        show_elapsed_time_(style.show_elapsed_time),
        show_remaining_time_(style.show_remaining_time),
        width_offset_(style.width_offset),
        start_time_(std::chrono::steady_clock::now()),
        last_update_time_(start_time_),
        bar_(indicators::option::BarWidth{bar_width_},
             indicators::option::Start{start_token_},
             indicators::option::Fill{style.fill.empty() ? "=" : style.fill},
             indicators::option::Lead{style.lead.empty() ? ">" : style.lead},
             indicators::option::Remainder{
                 style.remainder.empty() ? " " : style.remainder},
             indicators::option::End{end_token_},
             indicators::option::PrefixText{prefix_},
             indicators::option::ForegroundColor{style.color},
             indicators::option::PostfixText{""},
             indicators::option::MaxProgress{static_cast<size_t>(total_size_)},
             indicators::option::ShowPercentage{false},
             indicators::option::ShowElapsedTime{false},
             indicators::option::ShowRemainingTime{false}) {
    std::lock_guard<std::mutex> lock(mtx_);
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
  }

  /**
   * @brief Set or update the total size.
   * @param total_size Total number of bytes.
   * @param reset_timer Whether to reset elapsed time origin.
   */
  void SetTotal(int64_t total_size, bool reset_timer = false) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_size_ = std::max<int64_t>(0, total_size);
    if (current_size_ > total_size_) {
      current_size_ = total_size_;
    }
    if (reset_timer) {
      start_time_ = std::chrono::steady_clock::now();
      last_update_time_ = start_time_;
      last_update_size_ = current_size_;
      speed_samples_.clear();
      speed_bps_ = 0.0;
    }
    bar_.set_option(
        indicators::option::MaxProgress{static_cast<size_t>(total_size_)});
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
  }

  /**
   * @brief Set the display prefix.
   * @param prefix Prefix text.
   */
  void SetPrefix(std::string prefix) {
    std::lock_guard<std::mutex> lock(mtx_);
    prefix_ = std::move(prefix);
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
  }

  /**
   * @brief Advance progress by a delta in bytes.
   * @param delta Bytes to add.
   */
  void Advance(int64_t delta) {
    if (delta <= 0) {
      return;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = std::min<int64_t>(total_size_, current_size_ + delta);
    UpdateSpeedLocked_();
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
    bar_.set_progress(static_cast<size_t>(current_size_));
  }

  /**
   * @brief Set the current progress in bytes.
   * @param current_size Accumulated size in bytes.
   */
  void SetProgress(int64_t current_size) {
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = std::clamp<int64_t>(current_size, 0, total_size_);
    UpdateSpeedLocked_();
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
    bar_.set_progress(static_cast<size_t>(current_size_));
  }

  /**
   * @brief Set the start time using a Unix epoch timestamp (seconds).
   * @param epoch_seconds Unix epoch time in seconds.
   */
  void SetStartTimeEpoch(double epoch_seconds) {
    std::lock_guard<std::mutex> lock(mtx_);
    const auto sys_now = std::chrono::system_clock::now();
    const auto steady_now = std::chrono::steady_clock::now();
    const auto epoch_now =
        std::chrono::duration<double>(sys_now.time_since_epoch()).count();
    const auto delta = epoch_seconds - epoch_now;
    start_time_ =
        steady_now +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::duration<double>(delta));
    last_update_time_ = steady_now;
    last_update_size_ = current_size_;
    speed_samples_.clear();
    speed_bps_ = 0.0;
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
  }

  void SetCursorVisible(bool sign) { indicators::show_console_cursor(sign); }

  /**
   * @brief Set the maximum window size for speed calculation.
   * @param window_size Maximum number of samples to keep.
   */
  void SetSpeedWindowSize(size_t window_size) {
    std::lock_guard<std::mutex> lock(mtx_);
    speed_window_size_ = std::max<size_t>(1, window_size);
    while (speed_samples_.size() > speed_window_size_) {
      speed_samples_.pop_front();
    }
    UpdateSpeedLocked_();
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
  }

  /**
   * @brief Render the progress bar in-place.
   * @param from_group Whether the render is driven by a group.
   */
  void Print(bool from_group = false) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!from_group && !showing_) {
      showing_ = true;
      active_count_.fetch_add(1, std::memory_order_relaxed);
    }
    if (!from_group && !cursor_hidden_) {
      indicators::show_console_cursor(false);
      cursor_hidden_ = true;
    }
    bar_.print_progress(from_group);
  }

  /**
   * @brief Restore cursor visibility if it was hidden by this bar.
   */
  void EndDisplay() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (cursor_hidden_) {
      indicators::show_console_cursor(true);
      cursor_hidden_ = false;
    }
    if (showing_) {
      showing_ = false;
      active_count_.fetch_sub(1, std::memory_order_relaxed);
    }
  }

  /**
   * @brief Mark the bar as completed and clamp to total size.
   */
  void Finish() {
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = total_size_;
    UpdateSpeedLocked_();
    UpdatePostfixLocked_();
    UpdatePrefixLocked_();
    bar_.set_option(indicators::option::PrefixText{prefix_field_});
    bar_.set_option(indicators::option::PostfixText{postfix_});
    bar_.set_option(indicators::option::Completed{true});
    if (cursor_hidden_) {
      indicators::show_console_cursor(true);
      cursor_hidden_ = false;
    }
    if (showing_) {
      showing_ = false;
      active_count_.fetch_sub(1, std::memory_order_relaxed);
    }
    ic_print("\x1b[0m");
  }

  /**
   * @brief Return whether the bar has finished.
   * @return True if finished.
   */
  bool IsFinished() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return bar_.is_completed();
  }

  /**
   * @brief Check whether any progress bar is currently showing.
   */
  static bool IsAnyBarShowing() {
    return active_count_.load(std::memory_order_relaxed) > 0;
  }

private:
  /**
   * @brief Print progress through indicators without ending the line.
   * @param from_group Whether we are called from a group render.
   */
  void PrintLocked_(bool from_group) { bar_.print_progress(from_group); }

  /**
   * @brief Update speed sampling information while holding the lock.
   */
  void UpdateSpeedLocked_() {
    const auto now = std::chrono::steady_clock::now();
    speed_samples_.push_back({now, current_size_});
    while (speed_samples_.size() > speed_window_size_) {
      speed_samples_.pop_front();
    }
    if (speed_samples_.size() >= 2) {
      const auto &first = speed_samples_.front();
      const auto &last = speed_samples_.back();
      const double dt =
          std::chrono::duration<double>(last.when - first.when).count();
      if (dt > 0.0) {
        speed_bps_ = static_cast<double>(last.value - first.value) / dt;
      } else {
        speed_bps_ = 0.0;
      }
    } else {
      speed_bps_ = 0.0;
    }
    last_update_time_ = now;
    last_update_size_ = current_size_;
  }

  /**
   * @brief Compute the postfix string with size, percentage, and speed.
   */
  void UpdatePostfixLocked_() {
    const double percent = (total_size_ <= 0)
                               ? 0.0
                               : (static_cast<double>(current_size_) /
                                  static_cast<double>(total_size_)) *
                                     100.0;
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time_);
    const int64_t elapsed_sec = std::max<int64_t>(0, elapsed.count());
    const double speed_bps = speed_bps_;
    const int64_t remaining_bytes =
        (total_size_ > current_size_) ? (total_size_ - current_size_) : 0;
    const int64_t remain_sec =
        (speed_bps > 0.0) ? static_cast<int64_t>(remaining_bytes / speed_bps)
                          : 0;

    std::string size_part = AMStr::fmt("{}/{}", FormatSize_(current_size_, 2),
                                         FormatSize_(total_size_, 2));
    std::vector<std::string> bracket_parts;
    if (show_elapsed_time_ || show_remaining_time_) {
      std::string time_part;
      if (show_elapsed_time_) {
        time_part = FormatTimeMMSS_(elapsed_sec);
      }
      if (show_remaining_time_) {
        if (!time_part.empty()) {
          time_part += "<";
        }
        time_part += FormatTimeMMSS_(remain_sec);
      }
      if (!time_part.empty()) {
        bracket_parts.push_back(std::move(time_part));
      }
    }
    bracket_parts.push_back(FormatSpeed_(speed_bps));
    std::ostringstream bracket_oss;
    for (size_t i = 0; i < bracket_parts.size(); ++i) {
      if (i > 0) {
        bracket_oss << ' ';
      }
      bracket_oss << bracket_parts[i];
    }
    if (show_percentage_) {
      postfix_ = AMStr::fmt("{} | {} [{}]", FormatPercent_(percent),
                              size_part, bracket_oss.str());
    } else {
      postfix_ = AMStr::fmt("{} [{}]", size_part, bracket_oss.str());
    }
  }

  /**
   * @brief Update the prefix field to a fixed width based on terminal size.
   */
  void UpdatePrefixLocked_() {
    const size_t term_width = indicators::terminal_width();
    const size_t postfix_len = postfix_.size();
    const size_t start_len = start_token_.size();
    const size_t end_len = end_token_.size();
    int max_prefix =
        static_cast<int>(term_width) -
        static_cast<int>(bar_width_ + start_len + end_len + postfix_len) -
        width_offset_;

    prefix_field_ = PadRight_(prefix_, max_prefix > 0 ? max_prefix : 0);
  }

  /**
   * @brief Right pad a string to a given width.
   * @param value Input string.
   * @param width Target width.
   * @return Padded string.
   */
  static std::string PadRight_(std::string_view value, size_t width) {
    if (width == 0) {
      return {};
    }
    if (value.size() >= width) {
      return std::string(value.substr(0, width));
    }
    std::string out(value);
    out.append(width - value.size(), ' ');
    return out;
  }

  static std::string PadLeft_(std::string_view value, size_t width) {
    if (width == 0) {
      return {};
    }
    if (value.size() >= width) {
      return std::string(value);
    }
    std::string out;
    out.append(width - value.size(), ' ');
    out.append(value);
    return out;
  }

  /**
   * @brief Format percentage as a fixed-width string.
   * @param percent Percentage value in [0, 100].
   * @return Formatted percentage string with one decimal place.
   */
  static std::string FormatPercent_(double percent) {
    const double clamped = std::clamp(percent, 0.0, 100.0);
    if (clamped >= 100.0) {
      return PadLeft_("100%", 5);
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << clamped << "%";
    return PadLeft_(oss.str(), 5);
  }

  /**
   * @brief Format bytes into a human readable size.
   * @param bytes Input size in bytes.
   * @param precision Decimal digits.
   * @return Formatted size string.
   */
  static std::string FormatSize_(int64_t bytes, int precision = 1) {
    const char *suffixes[] = {"B", "KB", "MB", "GB", "TB"};
    double size = static_cast<double>(std::max<int64_t>(0, bytes));
    int idx = 0;
    while (size >= 1024.0 && idx < 4) {
      size /= 1024.0;
      ++idx;
    }
    std::ostringstream oss;
    if (idx == 0) {
      oss << static_cast<int64_t>(size);
    } else {
      oss << std::fixed << std::setprecision(precision) << size;
    }
    std::string out = AMStr::fmt("{}{}", oss.str(), suffixes[idx]);
    return PadLeft_(out, 7);
  }

  static std::string FormatSizeNoSpace_(int64_t bytes, int precision = 1) {
    const char *suffixes[] = {"B", "KB", "MB", "GB", "TB"};
    double size = static_cast<double>(std::max<int64_t>(0, bytes));
    int idx = 0;
    while (size >= 1024.0 && idx < 4) {
      size /= 1024.0;
      ++idx;
    }
    std::ostringstream oss;
    if (idx == 0) {
      oss << static_cast<int64_t>(size);
    } else {
      oss << std::fixed << std::setprecision(precision) << size;
    }
    const std::string out = AMStr::fmt("{}{}", oss.str(), suffixes[idx]);
    return PadLeft_(out, 7);
  }

  /**
   * @brief Format elapsed seconds into MM:SS.
   * @param seconds Elapsed seconds.
   * @return Formatted time string.
   */
  static std::string FormatTimeMMSS_(int64_t seconds) {
    const int64_t clamped = std::max<int64_t>(0, seconds);
    const int64_t hours = clamped / 3600;
    const int64_t minutes = (clamped % 3600) / 60;
    const int64_t secs = clamped % 60;
    std::ostringstream oss;
    if (hours > 0) {
      oss << hours << ":" << std::setw(2) << std::setfill('0') << minutes << ":"
          << std::setw(2) << std::setfill('0') << secs;
      return oss.str();
    }
    oss << std::setw(2) << std::setfill('0') << minutes << ":" << std::setw(2)
        << std::setfill('0') << secs;
    return PadLeft_(oss.str(), 7);
  }

  /**
   * @brief Format speed in bytes per second.
   * @param bps Speed in bytes/sec.
   * @return Formatted speed string.
   */
  static std::string FormatSpeed_(double bps) {
    const std::string size = FormatSizeNoSpace_(static_cast<int64_t>(bps), 1);
    return PadLeft_(size + "/s", 9);
  }

private:
  mutable std::mutex mtx_;
  int64_t total_size_ = 0;
  int64_t current_size_ = 0;
  std::string prefix_;
  std::string prefix_field_;
  std::string postfix_;
  const size_t bar_width_;
  const std::string start_token_;
  const std::string end_token_;
  const bool show_percentage_;
  const bool show_elapsed_time_;
  const bool show_remaining_time_;
  const int width_offset_;
  std::chrono::steady_clock::time_point start_time_;
  std::chrono::steady_clock::time_point last_update_time_;
  int64_t last_update_size_ = 0;
  struct SpeedSample {
    std::chrono::steady_clock::time_point when;
    int64_t value = 0;
  };
  std::deque<SpeedSample> speed_samples_;
  size_t speed_window_size_ = 10;
  double speed_bps_ = 0.0;
  bool cursor_hidden_ = false;
  bool showing_ = false;
  indicators::ProgressBar bar_;
};
} // namespace AMBar

using ProgressBar = AMBar::ProgressBar;
using AMProgressBarStyle = AMBar::AMProgressBarStyle;
using AMProgressBar = AMBar::AMProgressBar;
