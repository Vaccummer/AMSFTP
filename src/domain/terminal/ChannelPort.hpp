#pragma once

#include "domain/terminal/TerminalModel.hpp"
#include "foundation/core/DataClass.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <winsock2.h>

namespace AMDomain::terminal {
class IChannelPort;
using ChannelOutputProcessor = std::function<void(std::string_view)>;
using ChannelPortHandle = std::shared_ptr<IChannelPort>;

enum class ScreenKind { Main, Alternate };

struct OutputBlock {
  ScreenKind screen = ScreenKind::Main;
  std::string data = {};
};

struct ChannelCacheReplayResult {
  size_t replayed_bytes = 0;
  size_t fallback_bytes = 0;
  size_t soft_limit_threshold_bytes = 0;
  size_t hard_limit_threshold_bytes = 0;
  bool in_alternate_screen = false;
  bool soft_limit_hit = false;
  bool hard_limit_hit = false;
  bool closed = false;
  ECM last_error = OK;
};

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
  size_t rendered_main_rows = 0;
};

struct ChannelReadWrappedResult {
  std::string output = {};
  std::string channel_name = {};
  bool eof = false;
  bool in_alternate_screen = false;
  bool soft_limit_hit_now = false;
  bool hard_limit_hit = false;
  ECM last_error = OK;
};

struct ChannelCacheCopyResult {
  std::vector<OutputBlock> blocks = {};
  bool in_alternate_screen = false;
  std::string latest_output = {};
  size_t cached_bytes = 0;
  ChannelVtSnapshot vt_snapshot = {};
  std::string vt_main_replay_ansi = {};
  std::string vt_visible_frame_ansi = {};
};

struct ChannelCacheTruncateArgs {
  size_t desired_size = 32U * 1024U * 1024U;
  bool truncate_at_newline = true;
};

struct ChannelCacheTruncateResult {
  size_t cached_bytes = 0;
  size_t removed_bytes = 0;
  bool truncated = false;
};

enum class BufferExceedThresholdKind { Soft, Hard };

struct BufferExceedEvent {
  std::string terminal_key = {};
  std::string channel_name = {};
  BufferExceedThresholdKind threshold_kind = BufferExceedThresholdKind::Soft;
  size_t cached_bytes = 0;
  size_t threshold_bytes = 0;
  bool in_alternate_screen = false;
  ECM last_error = OK;
};

using BufferExceedCallback = std::function<void(const BufferExceedEvent &)>;

struct ChannelPortState {
  bool attached = false;
  bool closed = false;
  bool in_alternate_screen = false;
  bool soft_limit_hit = false;
  bool hard_limit_hit = false;
  size_t cached_bytes = 0;
  ECM last_error = OK;
};

struct ChannelInitArgs {
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
  std::string term = "xterm-256color";
};

struct ChannelLoopStartArgs {
  ControlComponent control = {};
  int write_kick_timeout_ms = 0;
};

struct ChannelForegroundBindArgs {
  ChannelOutputProcessor processor = {};
  SOCKET key_event_handle = INVALID_SOCKET;
  AMAtomic<std::vector<char>> *key_cache = nullptr;
  ControlComponent control = {};
  int write_kick_timeout_ms = 0;
};

struct ChannelLoopState {
  bool loop_running = false;
  bool foreground_bound = false;
  bool closed = false;
  bool detach_requested = false;
  bool has_error = false;
  SOCKET state_wait_handle = INVALID_SOCKET;
  ECM last_error = OK;
};

class IChannelPort {
public:
  virtual ~IChannelPort() = default;

  [[nodiscard]] virtual std::string GetTerminalKey() const = 0;
  [[nodiscard]] virtual std::string GetChannelName() const = 0;

  [[nodiscard]] virtual ECMData<SOCKET> GetWaitHandle() const = 0;

  virtual ECM Init(const ChannelInitArgs &init_args,
                   const ControlComponent &control = {}) = 0;

  virtual ECM Rename(const std::string &new_channel_name) = 0;

  [[nodiscard]] virtual ECMData<ChannelCacheReplayResult>
  AttachConsumer(ChannelOutputProcessor processor) = 0;

  virtual ECM DetachConsumer() = 0;

  [[nodiscard]] virtual ECMData<ChannelReadWrappedResult>
  ReadWrapped(const ChannelReadArgs &read_args,
              const ControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ECMData<ChannelWriteResult>
  WriteRaw(const ChannelWriteArgs &write_args,
           const ControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ECMData<ChannelResizeResult>
  Resize(const ChannelResizeArgs &resize_args,
         const ControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ECMData<ChannelCloseResult>
  Close(bool force, int grace_period_ms = 1500,
        const ControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ChannelPortState GetState() const = 0;

  [[nodiscard]] virtual ECMData<ChannelCacheCopyResult>
  GetCacheCopy() const = 0;

  virtual ECM ClearCache() = 0;

  [[nodiscard]] virtual ECMData<ChannelCacheTruncateResult>
  TruncateCache(const ChannelCacheTruncateArgs &truncate_args = {}) = 0;

  virtual ECM
  EnsureLoopStarted(const ChannelLoopStartArgs &start_args = {}) = 0;

  [[nodiscard]] virtual ECMData<ChannelCacheReplayResult>
  BindForeground(const ChannelForegroundBindArgs &bind_args) = 0;

  virtual ECM UnbindForeground() = 0;

  virtual ECM RequestForegroundDetach() = 0;

  [[nodiscard]] virtual ChannelLoopState GetLoopState() const = 0;
};

} // namespace AMDomain::terminal
