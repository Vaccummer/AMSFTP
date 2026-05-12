#pragma once

#include "foundation/core/DataClass.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace AMDomain::terminal {

struct ChannelVtSnapshot {
  bool available = false;
  int rows = 0;
  int cols = 0;
  int cursor_row = 0;
  int cursor_col = 0;
  uint64_t history_lines = 0;
  uint64_t total_lines = 0;
  uint64_t display_offset = 0;
  uint64_t damage_serial = 0;
  bool in_alternate_screen = false;
  bool cursor_visible = false;
  bool mouse_reporting_active = false;
  bool mouse_report_click = false;
  bool mouse_drag = false;
  bool mouse_motion = false;
  bool mouse_sgr_encoding = false;
  bool mouse_utf8_encoding = false;
  bool app_cursor_keys = false;
  bool app_keypad = false;
  bool alternate_scroll = false;
  size_t rendered_main_rows = 0;
};

struct ChannelVtRenderRun {
  int row = 0;
  int col = 0;
  std::string sgr = {};
  std::string text = {};
};

struct ChannelRenderFrameResult {
  bool in_alternate_screen = false;
  ChannelVtSnapshot vt_snapshot = {};
  std::string vt_main_replay_ansi = {};
  std::string vt_visible_frame_ansi = {};
  bool vt_visible_frame_runs_available = false;
  std::vector<ChannelVtRenderRun> vt_visible_frame_runs = {};
};

struct ChannelRenderFrameArgs {
  uint64_t viewport_offset = 0;
};

class IVtPort {
public:
  virtual ~IVtPort() = default;

  virtual void Feed(std::string_view bytes) = 0;
  virtual void Resize(int cols, int rows) = 0;
  virtual void Clear() = 0;
  [[nodiscard]] virtual std::string TakePendingPtyWrite() = 0;

  [[nodiscard]] virtual ChannelVtSnapshot Snapshot() const = 0;
  [[nodiscard]] virtual std::string RenderMainReplayAnsi() const = 0;
  [[nodiscard]] virtual std::string RenderPlainTextHistory() const = 0;
  [[nodiscard]] virtual std::string
  RenderVisibleFrameAnsi(uint64_t viewport_offset = 0) const = 0;
  [[nodiscard]] virtual std::optional<std::vector<ChannelVtRenderRun>>
  RenderVisibleFrameRuns(uint64_t viewport_offset = 0) const = 0;
};

class IVtFramePort {
public:
  virtual ~IVtFramePort() = default;

  [[nodiscard]] virtual ChannelVtSnapshot Snapshot() const = 0;
  [[nodiscard]] virtual std::string RenderPlainTextHistory() const = 0;
  [[nodiscard]] virtual ECMData<ChannelRenderFrameResult>
  RenderFrame(const ChannelRenderFrameArgs &render_args = {}) const = 0;
};

} // namespace AMDomain::terminal
