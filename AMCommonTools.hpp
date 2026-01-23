#pragma once
#include <chrono>
#define _WINSOCKAPI_
#include <indicators/progress_bar.hpp> // win 平台上该库会包含 windows.h
#include <iomanip>
#include <iostream>
#include <sstream>

class ProgressBar {
public:
  explicit ProgressBar(uint64_t total_size = 0, std::string unit = "B",
                       size_t bar_width = 50, bool show_eta = true,
                       bool colored = true)
      : total_(total_size), unit_(std::move(unit)), bar_width_(bar_width),
        show_eta_(show_eta), colored_(colored),
        start_time_(std::chrono::steady_clock::now()) {}

  // ✅ 新增：动态设置总大小（可选是否重置计时器）
  void set_total(uint64_t new_total, bool reset_timer = false) {
    total_ = new_total;
    if (reset_timer) {
      start_time_ = std::chrono::steady_clock::now();
    }
    // 如果当前进度超过新 total，自动修正
    if (current_ > total_) {
      current_ = total_;
    }
    redraw();
  }

  // 更新当前进度
  void update(uint64_t current) {
    if (total_ == 0) {
      // 如果 total 未知，以 current 作为“已知最大值”估算
      if (current > current_) {
        total_ = current * 2; // 启发式：假设最终是当前的2倍
      }
    }
    if (current > total_)
      current = total_;
    current_ = current;
    redraw();
  }

  void finish() {
    if (total_ == 0)
      total_ = current_; // 防止除零
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
      auto [speed_str, speed_unit] = format_size(static_cast<uint64_t>(speed));
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

  std::pair<std::string, std::string> format_size(uint64_t size) const {
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
  uint64_t total_ = 0;
  uint64_t current_ = 0;
  std::string unit_;
  size_t bar_width_;
  bool show_eta_;
  bool colored_;
  std::chrono::steady_clock::time_point start_time_;

  ProgressBar(const ProgressBar &) = delete;
  ProgressBar &operator=(const ProgressBar &) = delete;
};

class AMProgressBar : public indicators::ProgressBar {
public:
  AMProgressBar(uint64_t total_size = 0, std::string prefix = "",
                std::string unit = "B", size_t bar_width = 50,
                bool show_eta = true,
                indicators::Color color = indicators::Color::green)
      : indicators::ProgressBar(
            indicators::option::BarWidth{bar_width},
            indicators::option::Start{"["}, indicators::option::Fill{"█"},
            indicators::option::Lead{"█"}, indicators::option::End{"]"},
            indicators::option::PostfixText{prefix},
            indicators::option::MaxProgress{total_size},
            indicators::option::ShowElapsedTime{show_eta},
            indicators::option::ShowRemainingTime{show_eta},
            // indicators::option::ShowRate{true},
            // indicators::option::SampleCount{10},
            indicators::option::ForegroundColor{color}) {}
  void setTotoalSize(uint64_t total_size) {
    this->set_option(indicators::option::MaxProgress{total_size});
  }
  void setPrefix(std::string prefix) {
    this->set_option(indicators::option::PostfixText{prefix});
  }
  void setColor(indicators::Color color) {
    this->set_option(indicators::option::ForegroundColor{color});
  }
  void setPostfix(std::string prefix) {
    this->set_option(indicators::option::PostfixText{prefix});
  }
  void taskDone() {
    this->set_option(indicators::option::Completed{true});
    this->print_progress();
  }
  void updateProgress(uint64_t current) {
    this->set_progress(current);
    this->print_progress();
  }
};

inline void print(const std::string &str) { std::cout << str << std::endl; }