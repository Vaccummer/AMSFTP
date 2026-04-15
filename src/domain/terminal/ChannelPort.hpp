#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/terminal/TerminalModel.hpp"
#include "foundation/core/DataClass.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace AMDomain::terminal {
using ClientControlComponent = AMDomain::client::ClientControlComponent;

enum class ScreenKind { Main, Alternate };

struct OutputBlock {
  ScreenKind screen = ScreenKind::Main;
  std::string data = {};
};

struct ChannelCacheReplayResult {
  size_t replayed_bytes = 0;
  size_t fallback_bytes = 0;
  bool in_alternate_screen = false;
  bool soft_limit_hit = false;
  bool hard_limit_hit = false;
  bool closed = false;
  ECM last_error = OK;
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

struct ChannelPortState {
  bool attached = false;
  bool closed = false;
  bool in_alternate_screen = false;
  bool soft_limit_hit = false;
  bool hard_limit_hit = false;
  size_t cached_bytes = 0;
  ECM last_error = OK;
};

using ChannelOutputProcessor = std::function<void(std::string_view)>;

struct ChannelLoopStartArgs {
  AMDomain::client::ClientControlComponent control = {};
  int write_kick_timeout_ms = 100;
};

struct ChannelForegroundBindArgs {
  ChannelOutputProcessor processor = {};
  std::intptr_t key_event_handle = -1;
  AMAtomic<std::vector<char>> *key_cache = nullptr;
  AMDomain::client::ClientControlComponent control = {};
  int write_kick_timeout_ms = 100;
};

struct ChannelLoopState {
  bool loop_running = false;
  bool foreground_bound = false;
  bool closed = false;
  bool detach_requested = false;
  bool has_error = false;
  std::intptr_t state_wait_handle = -1;
  ECM last_error = OK;
};

class IChannelPort {
public:
  virtual ~IChannelPort() = default;

  [[nodiscard]] virtual std::string GetTerminalKey() const = 0;
  [[nodiscard]] virtual std::string GetChannelName() const = 0;

  [[nodiscard]] virtual ECMData<std::intptr_t> GetWaitHandle() const = 0;

  [[nodiscard]] virtual ECMData<ChannelCacheReplayResult>
  AttachConsumer(ChannelOutputProcessor processor) = 0;

  virtual ECM DetachConsumer() = 0;

  [[nodiscard]] virtual ECMData<ChannelReadWrappedResult>
  ReadWrapped(const ChannelReadArgs &read_args,
              const ClientControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ECMData<ChannelWriteResult>
  WriteRaw(const ChannelWriteArgs &write_args,
           const ClientControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ECMData<ChannelResizeResult>
  Resize(const ChannelResizeArgs &resize_args,
         const ClientControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ECMData<ChannelCloseResult>
  Close(bool force, const ClientControlComponent &control = {}) = 0;

  [[nodiscard]] virtual ChannelPortState GetState() const = 0;

  [[nodiscard]] virtual ECMData<ChannelCacheCopyResult> GetCacheCopy() const = 0;

  virtual ECM ClearCache() = 0;

  [[nodiscard]] virtual ECMData<ChannelCacheTruncateResult>
  TruncateCache(const ChannelCacheTruncateArgs &truncate_args = {}) = 0;

  virtual ECM EnsureLoopStarted(const ChannelLoopStartArgs &start_args = {}) = 0;

  [[nodiscard]] virtual ECMData<ChannelCacheReplayResult>
  BindForeground(const ChannelForegroundBindArgs &bind_args) = 0;

  virtual ECM UnbindForeground() = 0;

  virtual ECM RequestForegroundDetach() = 0;

  [[nodiscard]] virtual ChannelLoopState GetLoopState() const = 0;
};

using ChannelPortHandle = std::shared_ptr<IChannelPort>;

} // namespace AMDomain::terminal

