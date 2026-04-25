#pragma once
#define _WINSOCKAPI_

#include "foundation/tools/prompt_ui.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/core/SPSCRingBuffer.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace AMBar {
struct AMProgressBarStyle {
  std::string prefix_template = "{$filename}";
  std::string bar_template =
      "{$progressbar} {$percentage}%!{$transferred}/{$total} "
      "\\[{$elapsed}<{$remaining} {$speed}\\]";
  int64_t refresh_interval_ms = 300;
  int prefix_fixed_width = 20;
  std::string fill = "=";
  std::string lead = ">";
  std::string remaining = " ";
  size_t bar_width = 30;
  size_t speed_num_fixed_width = 7;
  int speed_num_max_float_digits = 1;
  int64_t speed_window_ms = 7000;
  size_t totol_size_fixed_width = 5;
  int totol_size_max_float_digits = 1;
  size_t transferred_size_fixed_width = 5;
  int transferred_size_max_float_digits = 1;
};

/**
 * @brief Self-rendered progress bar used by transfer refresh output.
 */
class BaseProgressBar {
public:
  struct RenderArgs {
    std::string src_host = {};
    std::string dst_host = {};
    std::string filename = {};
    int64_t transferred = -1;
    int64_t total = -1;
    double speed_bps = -1.0;
    int64_t elapsed_ms = -1;
  };

  explicit BaseProgressBar(AMProgressBarStyle style = {})
      : style_(std::move(style)), start_time_(std::chrono::steady_clock::now()),
        last_update_time_(start_time_) {
    if (style_.prefix_template.empty()) {
      style_.prefix_template = "{$filename}";
    }
    if (style_.bar_template.empty()) {
      style_.bar_template =
          "{$progressbar} {$percentage}%!{$transferred}/{$total} "
          "\\[{$elapsed}<{$remaining} {$speed}\\]";
    }
    if (style_.fill.empty()) {
      style_.fill = "=";
    }
    if (style_.lead.empty()) {
      style_.lead = ">";
    }
    if (style_.remaining.empty()) {
      style_.remaining = " ";
    }
    if (style_.bar_width == 0) {
      style_.bar_width = 30;
    }
    style_.refresh_interval_ms =
        std::max<int64_t>(1, style_.refresh_interval_ms);
    style_.prefix_fixed_width = std::max<int>(0, style_.prefix_fixed_width);
    style_.speed_window_ms = std::max<int64_t>(1, style_.speed_window_ms);
    style_.speed_num_max_float_digits =
        std::max<int>(0, style_.speed_num_max_float_digits);
    style_.totol_size_max_float_digits =
        std::max<int>(0, style_.totol_size_max_float_digits);
    style_.transferred_size_max_float_digits =
        std::max<int>(0, style_.transferred_size_max_float_digits);
    if (style_.speed_num_fixed_width > 64) {
      style_.speed_num_fixed_width = 64;
    }
    if (style_.totol_size_fixed_width > 64) {
      style_.totol_size_fixed_width = 64;
    }
    if (style_.transferred_size_fixed_width > 64) {
      style_.transferred_size_fixed_width = 64;
    }
  }

  /**
   * @brief Set or update the total size.
   * @param total_size Total number of bytes.
   */
  void SetTotal(int64_t total_size) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_size_ = std::max<int64_t>(0, total_size);
    if (current_size_ > total_size_) {
      current_size_ = total_size_;
    }
  }

  void StartTrace() {
    std::lock_guard<std::mutex> lock(mtx_);
    start_time_ = std::chrono::steady_clock::now();
    last_update_time_ = start_time_;
    last_update_size_ = current_size_;
    speed_samples_.clear();
    speed_bps_ = 0.0;
  }

  /**
   * @brief Start tracing with a pre-existing elapsed duration.
   * @param elapsed_ms Elapsed milliseconds already consumed by the task.
   */
  void StartTraceWithElapsedMs(int64_t elapsed_ms) {
    std::lock_guard<std::mutex> lock(mtx_);
    const auto now = std::chrono::steady_clock::now();
    const int64_t clamped_elapsed_ms = std::max<int64_t>(0, elapsed_ms);
    start_time_ = now - std::chrono::milliseconds(clamped_elapsed_ms);
    last_update_time_ = now;
    last_update_size_ = current_size_;
    speed_samples_.clear();
    speed_bps_ = 0.0;
  }

  std::string Render(const RenderArgs &args) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (args.total >= 0) {
      total_size_ = std::max<int64_t>(0, args.total);
    }
    if (args.transferred >= 0) {
      current_size_ =
          (total_size_ > 0)
              ? std::clamp<int64_t>(args.transferred, 0, total_size_)
              : std::max<int64_t>(0, args.transferred);
    }
    const bool use_external_speed = args.speed_bps >= 0.0;
    if (!use_external_speed) {
      UpdateSpeedLocked_();
    }
    return BuildLineLocked_(
        args, use_external_speed ? args.speed_bps : speed_bps_,
        args.elapsed_ms);
  }

  std::string RenderFinal(const std::string &prefix, int64_t transferred) {
    std::lock_guard<std::mutex> lock(mtx_);
    current_size_ = std::max<int64_t>(0, transferred);
    if (total_size_ > 0) {
      current_size_ = std::min<int64_t>(current_size_, total_size_);
    }
    UpdateSpeedLocked_();
    RenderArgs args = {};
    args.filename = prefix;
    args.total = total_size_;
    args.transferred = current_size_;
    return BuildLineLocked_(args, speed_bps_, -1);
  }

private:
  std::string BuildBarPartLocked_(size_t bar_width) const {
    size_t filled = 0;
    if (total_size_ > 0) {
      const double ratio =
          static_cast<double>(current_size_) /
          static_cast<double>(std::max<int64_t>(1, total_size_));
      filled = static_cast<size_t>(
          std::clamp<double>(ratio * static_cast<double>(bar_width), 0.0,
                             static_cast<double>(bar_width)));
    }

    std::string inner = {};
    if (filled >= bar_width) {
      for (size_t i = 0; i < bar_width; ++i) {
        inner += style_.fill;
      }
    } else {
      for (size_t i = 0; i < filled; ++i) {
        inner += style_.fill;
      }
      inner += style_.lead;
      const size_t used = filled + 1;
      if (used < bar_width) {
        for (size_t i = 0; i < (bar_width - used); ++i) {
          inner += style_.remaining;
        }
      }
    }
    return inner;
  }

  /**
   * @brief Update speed sampling information while holding the lock.
   */
  void UpdateSpeedLocked_() {
    const auto now = std::chrono::steady_clock::now();
    speed_samples_.push({now, current_size_});
    auto latest = speed_samples_.back();
    if (latest.has_value() && speed_samples_.count() >= 2) {
      const auto cutoff = now - std::chrono::milliseconds(style_.speed_window_ms);
      SpeedSample first = *latest;
      speed_samples_.for_each([&](const SpeedSample &s) {
        if (s.when <= cutoff) {
          first = s;
        }
      });
      if (first.when == latest->when) {
        if (auto oldest = speed_samples_.front(); oldest.has_value()) {
          first = *oldest;
        }
      }
      const double dt =
          std::chrono::duration<double>(latest->when - first.when).count();
      speed_bps_ =
          (dt > 0.0) ? static_cast<double>(latest->value - first.value) / dt : 0.0;
    } else {
      speed_bps_ = 0.0;
    }
    last_update_time_ = now;
    last_update_size_ = current_size_;
  }

  std::string BuildLineLocked_(const RenderArgs &args, double speed_bps,
                               int64_t elapsed_ms) const {
    const double percent = (total_size_ <= 0)
                               ? 0.0
                               : (static_cast<double>(current_size_) /
                                  static_cast<double>(total_size_)) *
                                     100.0;
    const auto elapsed =
        (elapsed_ms >= 0)
            ? std::chrono::seconds(std::max<int64_t>(0, elapsed_ms / 1000))
            : std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::steady_clock::now() - start_time_);
    const int64_t elapsed_sec = std::max<int64_t>(0, elapsed.count());
    const int64_t remaining_bytes =
        (total_size_ > current_size_) ? (total_size_ - current_size_) : 0;
    const int64_t remain_sec =
        (speed_bps > 0.0) ? static_cast<int64_t>(remaining_bytes / speed_bps)
                          : 0;
    std::vector<std::pair<std::string, std::string>> vars = {
        {"src_host", args.src_host},
        {"dst_host", args.dst_host},
        {"filename", args.filename},
        {"progressbar", ""},
        {"percentage", FormatPercent_(percent)},
        {"elapsed", FormatTimeMMSS_(elapsed_sec)},
        {"remaining", FormatTimeMMSS_(remain_sec)},
        {"total", FormatTotal_(total_size_)},
        {"transferred", FormatTransferred_(current_size_)},
        {"speed", FormatSpeed_(speed_bps)}};

    const std::string raw_prefix =
        ResolveTemplate_(style_.prefix_template, vars);
    const std::string prefix = BuildPrefixFieldLocked_(raw_prefix);
    const std::string fixed_bar_text =
        EscapeLiteralBrackets_(ResolveTemplate_(style_.bar_template, vars));
    const size_t dynamic_bar_width =
        ResolveBarWidthLocked(prefix, fixed_bar_text);
    for (auto &entry : vars) {
      if (entry.first == "progressbar") {
        entry.second = BuildBarPartLocked_(dynamic_bar_width);
        break;
      }
    }
    const std::string bar_text =
        EscapeLiteralBrackets_(ResolveTemplate_(style_.bar_template, vars));
    if (prefix.empty()) {
      return bar_text;
    }
    return prefix + bar_text;
  }

  std::string BuildPrefixFieldLocked_(const std::string &prefix) const {
    const size_t target_width =
        static_cast<size_t>(std::max<int>(0, style_.prefix_fixed_width));
    if (target_width == 0) {
      return prefix;
    }
    const size_t current_width = MeasureDisplayWidth_(prefix);
    if (current_width >= target_width) {
      return prefix;
    }
    return prefix + std::string(target_width - current_width, ' ');
  }

  size_t ResolveBarWidthLocked(const std::string &prefix,
                               const std::string &fixed_bar_text) const {
    const int terminal_cols =
        std::max(1, AMTerminalTools::GetTerminalViewportInfo().cols);
    const size_t reserved_width =
        MeasureDisplayWidth_(prefix) + MeasureDisplayWidth_(fixed_bar_text);
    const size_t terminal_width = static_cast<size_t>(terminal_cols);
    if (terminal_width <= reserved_width) {
      return 1;
    }
    return std::max<size_t>(1, terminal_width - reserved_width);
  }

  static std::string ResolveTemplate_(
      const std::string &templ,
      const std::vector<std::pair<std::string, std::string>> &vars) {
    std::string out = templ;
    for (const auto &it : vars) {
      out = AMStr::replace_all(out, AMStr::fmt("{{${}}}", it.first), it.second);
    }
    return out;
  }

  static std::string EscapeLiteralBrackets_(const std::string &in) {
    if (in.empty()) {
      return in;
    }
    std::string out = {};
    out.reserve(in.size() + 8);
    for (size_t i = 0; i < in.size(); ++i) {
      const char c = in[i];
      if (c == '[') {
        const bool escaped = (i > 0 && in[i - 1] == '\\');
        if (!escaped) {
          const char next = (i + 1 < in.size()) ? in[i + 1] : '\0';
          const bool looks_like_bbcode_tag =
              (next == '#') || (next == '/') ||
              std::isalpha(static_cast<unsigned char>(next));
          if (!looks_like_bbcode_tag) {
            out.push_back('\\');
          }
        }
      }
      out.push_back(c);
    }
    return out;
  }

  static size_t MeasureDisplayWidth_(const std::string &text) {
    const std::string plain = AMPromptUI::NormalizeMeasureLine(
        AMPromptUI::StripStyleForMeasure(text));
    return AMStr::DisplayWidthUtf8(plain);
  }

  /**
   * @brief Format percentage as a fixed-width string.
   * @param percent Percentage value in [0, 100].
   * @return Formatted percentage string with one decimal place.
   */
  static std::string FormatPercent_(double percent) {
    const double clamped = std::clamp(percent, 0.0, 100.0);
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << clamped;
    return AMStr::PadLeftAscii(oss.str(), 5);
  }

  /**
   * @brief Format bytes into a human readable size.
   * @param bytes Input size in bytes.
   * @param precision Decimal digits.
   * @return Formatted size string.
   */
  std::string FormatTransferred_(int64_t bytes) const {
    return AMStr::FormatSize(bytes, 3, style_.transferred_size_max_float_digits,
                             style_.transferred_size_fixed_width, true);
  }

  std::string FormatTotal_(int64_t bytes) const {
    return AMStr::FormatSize(bytes, 3, style_.totol_size_max_float_digits,
                             style_.totol_size_fixed_width, true);
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
      oss << std::setw(2) << std::setfill('0') << hours << ":" << std::setw(2)
          << std::setfill('0') << minutes << ":" << std::setw(2)
          << std::setfill('0') << secs;
      return oss.str();
    }
    oss << std::setw(2) << std::setfill('0') << minutes << ":" << std::setw(2)
        << std::setfill('0') << secs;
    return oss.str();
  }

  /**
   * @brief Format speed in bytes per second.
   * @param bps Speed in bytes/sec.
   * @return Formatted speed string.
   */
  std::string FormatSpeed_(double bps) const {
    return AMStr::FormatSpeed(bps, 3, style_.speed_num_max_float_digits,
                              style_.speed_num_fixed_width, true);
  }

private:
  mutable std::mutex mtx_;
  AMProgressBarStyle style_ = {};
  int64_t total_size_ = 0;
  int64_t current_size_ = 0;
  std::chrono::steady_clock::time_point start_time_;
  std::chrono::steady_clock::time_point last_update_time_;
  int64_t last_update_size_ = 0;
  struct SpeedSample {
    std::chrono::steady_clock::time_point when;
    int64_t value = 0;
  };
  AMFoundation::SPSCRingBuffer<SpeedSample, 256> speed_samples_{};
  double speed_bps_ = 0.0;
};
} // namespace AMBar
