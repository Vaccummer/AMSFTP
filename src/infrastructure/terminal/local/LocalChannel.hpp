#pragma once

#include "foundation/tools/string.hpp"
#include "infrastructure/terminal/ChannelCachePort.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace AMInfra::client::LOCAL::terminal {
namespace AMT = AMDomain::terminal;

class ILocalTerminalChannelOwner {
public:
  virtual ~ILocalTerminalChannelOwner() = default;

  virtual ECMData<AMT::ChannelReadResult>
  ReadChannel(const AMT::ChannelReadArgs &read_args,
              const ControlComponent &control,
              const std::optional<std::string> &bound_channel_name) = 0;

  virtual ECMData<AMT::ChannelWriteResult>
  WriteChannel(const AMT::ChannelWriteArgs &write_args,
               const ControlComponent &control,
               const std::optional<std::string> &bound_channel_name) = 0;

  virtual ECMData<AMT::ChannelResizeResult>
  ResizeChannel(const AMT::ChannelResizeArgs &resize_args,
                const ControlComponent &control,
                const std::optional<std::string> &bound_channel_name) = 0;

  virtual ECMData<AMT::ChannelCloseResult>
  CloseChannel(const AMT::ChannelCloseArgs &close_args,
               const ControlComponent &control) = 0;

  [[nodiscard]] virtual std::optional<ECM>
  GetChannelState(const std::string &channel_name) const = 0;

  [[nodiscard]] virtual ECMData<std::intptr_t> GetChannelWaitHandle(
      const std::optional<std::string> &channel_name) const = 0;
};

class LocalChannelPort final : public AMT::IChannelPort {
public:
  using ControlComponent = ::ControlComponent;

  LocalChannelPort(std::string terminal_key, std::string channel_name,
                   ILocalTerminalChannelOwner *owner)
      : terminal_key_(std::move(terminal_key)),
        channel_name_(std::move(channel_name)), owner_(owner),
        cache_(channel_name_) {}

  ~LocalChannelPort() override {
    RequestStop_();
    JoinLoop_();
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    CloseStateWaitHandle_();
  }

  [[nodiscard]] std::string GetTerminalKey() const override {
    return terminal_key_;
  }

  [[nodiscard]] std::string GetChannelName() const override {
    return channel_name_;
  }

  [[nodiscard]] ECMData<std::intptr_t> GetWaitHandle() const override {
    if (owner_ == nullptr) {
      return {static_cast<std::intptr_t>(-1),
              Err(EC::InvalidHandle, "terminal.channel.wait_handle",
                  channel_name_, "Local channel owner is null")};
    }
    return owner_->GetChannelWaitHandle(
        std::optional<std::string>(channel_name_));
  }

  ECM Init(const AMT::ChannelInitArgs &init_args,
           const ControlComponent &control = {}) override {
    (void)init_args;
    (void)control;
    return OK;
  }

  ECM Rename(const std::string &new_channel_name) override {
    const std::string renamed = AMStr::Strip(new_channel_name);
    if (renamed.empty()) {
      return Err(EC::InvalidArg, "terminal.channel.rename", channel_name_,
                 "new channel name is empty");
    }
    channel_name_ = renamed;
    cache_.SetChannelName(channel_name_);
    return OK;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheReplayResult>
  AttachConsumer(AMT::ChannelOutputProcessor processor) override {
    return cache_.AttachConsumer(std::move(processor));
  }

  ECM DetachConsumer() override { return cache_.DetachConsumer(); }

  [[nodiscard]] ECMData<AMT::ChannelReadWrappedResult>
  ReadWrapped(const AMT::ChannelReadArgs &read_args,
              const ControlComponent &control = {}) override {
    if (owner_ == nullptr) {
      return {AMT::ChannelReadWrappedResult{},
              Err(EC::InvalidHandle, "terminal.channel.read", channel_name_,
                  "Local channel owner is null")};
    }
    auto raw_read = owner_->ReadChannel(
        read_args, control, std::optional<std::string>(channel_name_));
    return cache_.WrapReadResultFromRaw(raw_read);
  }

  [[nodiscard]] ECMData<AMT::ChannelWriteResult>
  WriteRaw(const AMT::ChannelWriteArgs &write_args,
           const ControlComponent &control = {}) override {
    if (owner_ == nullptr) {
      return {AMT::ChannelWriteResult{},
              Err(EC::InvalidHandle, "terminal.channel.write", channel_name_,
                  "Local channel owner is null")};
    }
    return owner_->WriteChannel(write_args, control,
                                std::optional<std::string>(channel_name_));
  }

  [[nodiscard]] ECMData<AMT::ChannelResizeResult>
  Resize(const AMT::ChannelResizeArgs &resize_args,
         const ControlComponent &control = {}) override {
    if (owner_ == nullptr) {
      return {AMT::ChannelResizeResult{},
              Err(EC::InvalidHandle, "terminal.channel.resize", channel_name_,
                  "Local channel owner is null")};
    }
    return owner_->ResizeChannel(resize_args, control,
                                 std::optional<std::string>(channel_name_));
  }

  [[nodiscard]] ECMData<AMT::ChannelCloseResult>
  Close(bool force, const ControlComponent &control = {}) override {
    RequestStop_();
    JoinLoop_();

    if (owner_ == nullptr) {
      return {AMT::ChannelCloseResult{},
              Err(EC::InvalidHandle, "terminal.channel.close", channel_name_,
                  "Local channel owner is null")};
    }
    auto close_result = owner_->CloseChannel({channel_name_, force}, control);
    if (!(close_result.rcm)) {
      cache_.MarkChannelClosed(close_result.rcm);
    } else {
      cache_.MarkChannelClosed(OK);
    }
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      closed_ = true;
      foreground_bound_ = false;
      detach_requested_ = false;
      loop_running_ = false;
      loop_started_ = false;
      key_event_handle_ = -1;
      key_cache_ = nullptr;
      send_buffer_.clear();
      key_ctrl_state_.store(false, std::memory_order_release);
      last_error_ = close_result.rcm;
      SignalLoopStateChanged_();
    }
    return close_result;
  }

  [[nodiscard]] AMT::ChannelPortState GetState() const override {
    auto state = cache_.GetState();
    if (owner_ != nullptr) {
      auto channel_state = owner_->GetChannelState(channel_name_);
      if (!channel_state.has_value()) {
        state.closed = true;
      } else if (!(*channel_state)) {
        state.closed = true;
        state.last_error = *channel_state;
      }
    } else {
      state.closed = true;
    }
    state.closed = state.closed || closed_;
    return state;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheCopyResult>
  GetCacheCopy() const override {
    return cache_.GetCacheCopy();
  }

  ECM ClearCache() override { return cache_.ClearCache(); }

  [[nodiscard]] ECMData<AMT::ChannelCacheTruncateResult> TruncateCache(
      const AMT::ChannelCacheTruncateArgs &truncate_args = {}) override {
    return cache_.TruncateCache(truncate_args);
  }

  ECM EnsureLoopStarted(
      const AMT::ChannelLoopStartArgs &start_args = {}) override {
    (void)start_args;
    if (owner_ == nullptr) {
      const ECM rcm = Err(EC::InvalidHandle, "terminal.channel.loop.start",
                          channel_name_, "Local channel owner is null");
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      last_error_ = rcm;
      return rcm;
    }

    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (closed_) {
        last_error_ = Err(EC::NoConnection, "terminal.channel.loop.start",
                          channel_name_, "Channel is closed");
        return last_error_;
      }

#ifdef _WIN32
      if (state_wait_handle_ == nullptr) {
        state_wait_handle_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (state_wait_handle_ == nullptr) {
          last_error_ = Err(EC::CommonFailure, "terminal.channel.loop.start",
                            channel_name_,
                            "Failed to create local loop state wait handle");
          return last_error_;
        }
      }
#endif

      if (loop_started_ && loop_thread_.joinable()) {
        loop_running_ = true;
        last_error_ = OK;
        return OK;
      }

      stop_requested_.store(false, std::memory_order_release);
      loop_started_ = true;
      loop_running_ = true;
      detach_requested_ = false;
      last_error_ = OK;
    }

    try {
      loop_thread_ = std::thread([this]() { RunLoop_(); });
    } catch (...) {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      loop_started_ = false;
      loop_running_ = false;
      last_error_ = Err(EC::CommonFailure, "terminal.channel.loop.start",
                        channel_name_, "Failed to create local loop thread");
      return last_error_;
    }

    SignalLoopStateChanged_();
    return OK;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheReplayResult>
  BindForeground(const AMT::ChannelForegroundBindArgs &bind_args) override {
    if (!bind_args.processor || bind_args.key_cache == nullptr) {
      const ECM rcm =
          Err(EC::InvalidArg, "terminal.channel.bind", channel_name_,
              "Foreground binding arguments are invalid");
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      last_error_ = rcm;
      return {AMT::ChannelCacheReplayResult{}, rcm};
    }

    const ECM loop_rcm =
        EnsureLoopStarted({bind_args.control, bind_args.write_kick_timeout_ms});
    if (!(loop_rcm)) {
      return {AMT::ChannelCacheReplayResult{}, loop_rcm};
    }

    auto result = AttachConsumer(bind_args.processor);
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (result.rcm) {
        foreground_bound_ = true;
        detach_requested_ = false;
        key_event_handle_ = bind_args.key_event_handle;
        key_cache_ = bind_args.key_cache;
        key_ctrl_state_.store(false, std::memory_order_release);
        last_error_ = OK;
      } else {
        last_error_ = result.rcm;
      }
      SignalLoopStateChanged_();
    }
    return result;
  }

  ECM UnbindForeground() override {
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      foreground_bound_ = false;
      detach_requested_ = false;
      key_event_handle_ = -1;
      key_cache_ = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      SignalLoopStateChanged_();
    }
    RequestStop_();
    JoinLoop_();
    return DetachConsumer();
  }

  ECM RequestForegroundDetach() override {
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      foreground_bound_ = false;
      detach_requested_ = true;
      key_event_handle_ = -1;
      key_cache_ = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      SignalLoopStateChanged_();
    }
    RequestStop_();
    JoinLoop_();
    return DetachConsumer();
  }

  [[nodiscard]] AMT::ChannelLoopState GetLoopState() const override {
    AMT::ChannelLoopState state = {};
    AMT::ChannelPortState const port_state = GetState();
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    state.closed = closed_ || port_state.closed;
    state.loop_running = loop_running_ && !state.closed;
    state.foreground_bound = foreground_bound_;
    state.detach_requested = detach_requested_;
#ifdef _WIN32
    state.state_wait_handle =
        state_wait_handle_ != nullptr
            ? reinterpret_cast<std::intptr_t>(state_wait_handle_)
            : static_cast<std::intptr_t>(-1);
#else
    state.state_wait_handle = static_cast<std::intptr_t>(-1);
#endif
    state.last_error = last_error_;
    if (!(state.last_error) && port_state.last_error) {
      state.last_error = port_state.last_error;
    }
    state.has_error = !(state.last_error);
    return state;
  }

private:
  [[nodiscard]] static bool IsConnectionBrokenCode_(ErrorCode code) {
    return code == EC::NoConnection || code == EC::ConnectionLost ||
           code == EC::NoSession || code == EC::ClientNotFound;
  }

  void RequestStop_() {
    stop_requested_.store(true, std::memory_order_release);
    SignalLoopStateChanged_();
  }

  void JoinLoop_() {
    if (!loop_thread_.joinable()) {
      return;
    }
    if (std::this_thread::get_id() == loop_thread_id_) {
      return;
    }
    loop_thread_.join();
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    loop_started_ = false;
    loop_running_ = false;
    loop_thread_id_ = std::thread::id{};
    SignalLoopStateChanged_();
  }

  bool DrainKeyInput_() {
    AMAtomic<std::vector<char>> *key_cache = nullptr;
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (!foreground_bound_ || key_cache_ == nullptr || closed_) {
        return false;
      }
      key_cache = key_cache_;
    }

    std::vector<char> keys = {};
    {
      auto guard = key_cache->lock();
      if (guard->empty()) {
        return false;
      }
      keys.swap(*guard);
    }

    bool changed = false;
    bool detach = false;
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      for (char const ch : keys) {
        if (!key_ctrl_state_.load(std::memory_order_acquire)) {
          if (ch == '\x1d') {
            key_ctrl_state_.store(true, std::memory_order_release);
            continue;
          }
          send_buffer_.push_back(ch);
          changed = true;
          continue;
        }

        if (ch == 'q' || ch == 'Q') {
          detach = true;
          key_ctrl_state_.store(false, std::memory_order_release);
          continue;
        }

        key_ctrl_state_.store(false, std::memory_order_release);
        send_buffer_.push_back(ch);
        changed = true;
      }
    }

    if (detach) {
      (void)RequestForegroundDetach();
      return true;
    }
    return changed;
  }

  bool FlushSend_() {
    std::string chunk = {};
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (send_buffer_.empty() || !foreground_bound_ || closed_) {
        return false;
      }
      const size_t n = std::min<size_t>(send_buffer_.size(), 32U * 1024U);
      chunk.assign(send_buffer_.data(), n);
    }

    auto write_result = WriteRaw({chunk}, {});
    if (!(write_result.rcm)) {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      last_error_ = write_result.rcm;
      if (IsConnectionBrokenCode_(write_result.rcm.code)) {
        closed_ = true;
      }
      if (closed_) {
        stop_requested_.store(true, std::memory_order_release);
      }
      SignalLoopStateChanged_();
      return false;
    }

    const size_t consumed = std::min(
        chunk.size(), static_cast<size_t>(write_result.data.bytes_written));
    if (consumed == 0U) {
      return false;
    }

    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (consumed <= send_buffer_.size()) {
        send_buffer_.erase(0, consumed);
      } else {
        send_buffer_.clear();
      }
    }
    return true;
  }

  void RunLoop_() {
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      loop_thread_id_ = std::this_thread::get_id();
      loop_running_ = true;
      loop_started_ = true;
      SignalLoopStateChanged_();
    }

    while (!stop_requested_.load(std::memory_order_acquire)) {
      bool active_foreground = false;
      bool is_closed = false;
      {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        active_foreground = foreground_bound_;
        is_closed = closed_;
      }
      if (is_closed) {
        break;
      }

      bool progressed = false;
      if (active_foreground) {
        if (DrainKeyInput_()) {
          progressed = true;
        }

        if (FlushSend_()) {
          progressed = true;
        }

        auto read_result = ReadWrapped({32U * 1024U}, {});
        if (!(read_result.rcm)) {
          std::lock_guard<std::recursive_mutex> lock(mutex_);
          last_error_ = read_result.rcm;
          closed_ = true;
          stop_requested_.store(true, std::memory_order_release);
          SignalLoopStateChanged_();
          break;
        }

        if (!read_result.data.output.empty()) {
          progressed = true;
        }

        if (!(read_result.data.last_error)) {
          std::lock_guard<std::recursive_mutex> lock(mutex_);
          last_error_ = read_result.data.last_error;
          SignalLoopStateChanged_();
        }

        if (read_result.data.hard_limit_hit || read_result.data.eof) {
          std::lock_guard<std::recursive_mutex> lock(mutex_);
          closed_ = true;
          if (!(read_result.data.last_error)) {
            last_error_ = read_result.data.last_error;
          }
          stop_requested_.store(true, std::memory_order_release);
          SignalLoopStateChanged_();
          break;
        }
      }

      if (!progressed) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }

    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      loop_running_ = false;
      loop_started_ = false;
      foreground_bound_ = false;
      key_event_handle_ = -1;
      key_cache_ = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      loop_thread_id_ = std::thread::id{};
      SignalLoopStateChanged_();
    }
  }

  void SignalLoopStateChanged_() {
#ifdef _WIN32
    if (state_wait_handle_ != nullptr) {
      (void)SetEvent(state_wait_handle_);
    }
#endif
  }

  void CloseStateWaitHandle_() {
#ifdef _WIN32
    if (state_wait_handle_ != nullptr) {
      (void)CloseHandle(state_wait_handle_);
      state_wait_handle_ = nullptr;
    }
#endif
  }

  std::string terminal_key_ = {};
  std::string channel_name_ = {};
  ILocalTerminalChannelOwner *owner_ = nullptr;
  AMInfra::terminal::ChannelCacheStore cache_;
  mutable std::recursive_mutex mutex_ = {};
  std::thread loop_thread_ = {};
  std::thread::id loop_thread_id_ = {};
  std::atomic<bool> stop_requested_ = false;
  std::atomic<bool> key_ctrl_state_ = false;
  std::intptr_t key_event_handle_ = -1;
  AMAtomic<std::vector<char>> *key_cache_ = nullptr;
  std::string send_buffer_ = {};
  bool foreground_bound_ = false;
  bool detach_requested_ = false;
  bool loop_running_ = false;
  bool loop_started_ = false;
  bool closed_ = false;
  ECM last_error_ = OK;
#ifdef _WIN32
  HANDLE state_wait_handle_ = nullptr;
#endif
};

} // namespace AMInfra::client::LOCAL::terminal
