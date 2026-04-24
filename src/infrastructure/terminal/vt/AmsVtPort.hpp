#pragma once

#include "domain/terminal/TerminalModel.hpp"
#include "domain/terminal/VtPort.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

#ifdef AMSFTP_VT_STATIC
#include "AmsVt.h"
#endif

namespace AMInfra::terminal::vt {
namespace AMT = AMDomain::terminal;

class AmsVtPort final : public AMT::IVtPort {
public:
  explicit AmsVtPort(AMT::TerminalManagerArg terminal_manager_arg = {})
      : terminal_manager_arg_(std::move(terminal_manager_arg)) {
    AMT::NormalizeTerminalManagerArg(&terminal_manager_arg_);
  }

  ~AmsVtPort() override { Reset(); }

  AmsVtPort(const AmsVtPort &) = delete;
  AmsVtPort &operator=(const AmsVtPort &) = delete;
  AmsVtPort(AmsVtPort &&) = delete;
  AmsVtPort &operator=(AmsVtPort &&) = delete;

  void SetTerminalManagerArg(AMT::TerminalManagerArg terminal_manager_arg) {
    AMT::NormalizeTerminalManagerArg(&terminal_manager_arg);
    terminal_manager_arg_ = std::move(terminal_manager_arg);
  }

  void Ensure(int cols, int rows) {
    cols_ = std::max(1, cols);
    rows_ = std::max(1, rows);
#ifdef AMSFTP_VT_STATIC
    if (handle_ != nullptr) {
      return;
    }
    const uint64_t scrollback_limit = std::clamp<uint64_t>(
        terminal_manager_arg_.channel_cache_threshold_bytes.terminate /
            static_cast<size_t>(std::max(1, cols_)),
        10000U, 500000U);
    handle_ = AmsVtCreate(rows_, cols_, scrollback_limit);
#endif
  }

  void Feed(std::string_view bytes) override {
    if (bytes.empty()) {
      return;
    }
#ifdef AMSFTP_VT_STATIC
    Ensure(cols_, rows_);
    if (handle_ == nullptr) {
      return;
    }
    AmsVtFeed(handle_, reinterpret_cast<const uint8_t *>(bytes.data()),
              bytes.size());
#else
    (void)bytes;
#endif
  }

  void Resize(int cols, int rows) override {
    cols_ = std::max(1, cols);
    rows_ = std::max(1, rows);
#ifdef AMSFTP_VT_STATIC
    Ensure(cols_, rows_);
    if (handle_ != nullptr) {
      AmsVtResize(handle_, rows_, cols_);
    }
#endif
  }

  void Clear() override {
    Reset();
    Ensure(cols_, rows_);
  }

  void Reset() {
#ifdef AMSFTP_VT_STATIC
    if (handle_ != nullptr) {
      AmsVtFree(handle_);
      handle_ = nullptr;
    }
#endif
  }

  void FeedScreenToggle(bool to_alternate) {
    static constexpr std::string_view kEnterAlt = "\x1b[?1049h";
    static constexpr std::string_view kExitAlt = "\x1b[?1049l";
    Feed(to_alternate ? kEnterAlt : kExitAlt);
  }

  [[nodiscard]] AMT::ChannelVtSnapshot Snapshot() const override {
    AMT::ChannelVtSnapshot out = {};
#ifdef AMSFTP_VT_STATIC
    if (handle_ == nullptr) {
      return out;
    }
    const AmsVtSnapshot snapshot = AmsVtGetSnapshot(handle_);
    out.available = true;
    out.rows = snapshot.rows;
    out.cols = snapshot.cols;
    out.cursor_row = snapshot.cursor_row;
    out.cursor_col = snapshot.cursor_col;
    out.history_lines = snapshot.history_lines;
    out.total_lines = snapshot.total_lines;
    out.display_offset = snapshot.display_offset;
    out.damage_serial = snapshot.damage_serial;
    out.in_alternate_screen = snapshot.in_alternate_screen != 0U;
    out.cursor_visible = snapshot.cursor_visible != 0U;
    out.mouse_reporting_active = snapshot.mouse_reporting_active != 0U;
    out.mouse_report_click = snapshot.mouse_report_click != 0U;
    out.mouse_drag = snapshot.mouse_drag != 0U;
    out.mouse_motion = snapshot.mouse_motion != 0U;
    out.mouse_sgr_encoding = snapshot.mouse_sgr_encoding != 0U;
    out.mouse_utf8_encoding = snapshot.mouse_utf8_encoding != 0U;
    out.app_cursor_keys = snapshot.app_cursor_keys != 0U;
    out.app_keypad = snapshot.app_keypad != 0U;
    out.alternate_scroll = snapshot.alternate_scroll != 0U;
    out.rendered_main_rows = static_cast<size_t>(std::min<uint64_t>(
        snapshot.rendered_main_rows,
        static_cast<uint64_t>(std::numeric_limits<size_t>::max())));
#endif
    return out;
  }

  [[nodiscard]] std::string RenderMainReplayAnsi() const override {
#ifdef AMSFTP_VT_STATIC
    if (handle_ == nullptr) {
      return {};
    }
    const AmsVtSnapshot snapshot = AmsVtGetSnapshot(handle_);
    if (snapshot.in_alternate_screen != 0U) {
      return {};
    }
    return TakeAmsVtString_(AmsVtRenderMainReplayAnsiUtf8(handle_));
#else
    return {};
#endif
  }

  [[nodiscard]] std::string
  RenderVisibleFrameAnsi(uint64_t viewport_offset = 0) const override {
#ifdef AMSFTP_VT_STATIC
    if (handle_ == nullptr) {
      return {};
    }
    return TakeAmsVtString_(
        AmsVtRenderVisibleFrameWithOffsetAnsiUtf8(handle_, viewport_offset));
#else
    (void)viewport_offset;
    return {};
#endif
  }

private:
#ifdef AMSFTP_VT_STATIC
  [[nodiscard]] static std::string TakeAmsVtString_(char *rendered) {
    if (rendered == nullptr) {
      return {};
    }
    std::string out(rendered);
    AmsVtFreeString(rendered);
    return out;
  }
#endif

private:
  AMT::TerminalManagerArg terminal_manager_arg_ = {};
  int cols_ = 80;
  int rows_ = 24;
#ifdef AMSFTP_VT_STATIC
  AmsVtHandle *handle_ = nullptr;
#endif
};

} // namespace AMInfra::terminal::vt
