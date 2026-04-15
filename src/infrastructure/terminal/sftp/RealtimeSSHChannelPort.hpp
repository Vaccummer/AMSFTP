#pragma once

#include "foundation/tools/string.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"
#include "infrastructure/terminal/ChannelCachePort.hpp"

#include <array>
#include <atomic>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <type_traits>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

namespace AMInfra::terminal {
namespace AMT = AMDomain::terminal;
namespace AMSFTP = AMInfra::client::SFTP;

struct RealtimeSSHChannelBinding {
  std::recursive_mutex *core_mutex = nullptr;
  AMSFTP::AMSFTPIOCore *sftp_core = nullptr;
  std::unique_ptr<AMSFTP::detail::SafeChannel> *channel_holder = nullptr;

  bool *eof = nullptr;
  int *exit_status = nullptr;
  ECM *state = nullptr;

  int *window_cols = nullptr;
  int *window_rows = nullptr;
  int *window_width = nullptr;
  int *window_height = nullptr;

  std::string host = {};
};

class RealtimeSSHChannelPort final : public AMT::IChannelPort {
public:
  using ClientControlComponent = AMDomain::client::ClientControlComponent;

  RealtimeSSHChannelPort(std::string terminal_key, std::string channel_name,
                         RealtimeSSHChannelBinding binding)
      : terminal_key_(std::move(terminal_key)),
        channel_name_(std::move(channel_name)),
        cache_(channel_name_),
        binding_(std::move(binding)) {}

  ~RealtimeSSHChannelPort() override {
    RequestStop_();
    JoinLoop_();
    CloseLoopEvents_();
  }

  [[nodiscard]] std::string GetTerminalKey() const override {
    return terminal_key_;
  }

  [[nodiscard]] std::string GetChannelName() const override {
    return channel_name_;
  }

  [[nodiscard]] ECMData<std::intptr_t> GetWaitHandle() const override {
    if (binding_.sftp_core == nullptr) {
      return {static_cast<std::intptr_t>(-1),
              Err(EC::NoSession, "terminal.channel.wait_handle", GetChannelName(),
                  "SFTP IO core is unavailable")};
    }
    std::intptr_t const handle = binding_.sftp_core->RemoteSocketHandle();
    if (handle < 0) {
      return {handle,
              Err(EC::NoConnection, "terminal.channel.wait_handle",
                  GetChannelName(), "Remote socket is unavailable")};
    }
    return {handle, OK};
  }

  [[nodiscard]] ECMData<AMT::ChannelReadWrappedResult>
  ReadWrapped(const AMT::ChannelReadArgs &read_args,
              const ClientControlComponent &control = {}) override {
    auto raw_read = RawRead_(read_args, control);
    return cache_.WrapReadResultFromRaw(raw_read);
  }

  [[nodiscard]] ECMData<AMT::ChannelWriteResult>
  WriteRaw(const AMT::ChannelWriteArgs &write_args,
           const ClientControlComponent &control = {}) override {
    return RawWrite_(write_args, control);
  }

  [[nodiscard]] ECMData<AMT::ChannelResizeResult>
  Resize(const AMT::ChannelResizeArgs &resize_args,
         const ClientControlComponent &control = {}) override {
    return RawResize_(resize_args, control);
  }

  [[nodiscard]] ECMData<AMT::ChannelCloseResult>
  Close(bool force, const ClientControlComponent &control = {}) override {
    RequestStop_();
    JoinLoop_();
    auto close_result = RawClose_(force, control);
    if (!(close_result.rcm)) {
      cache_.MarkChannelClosed(close_result.rcm);
      std::lock_guard<std::mutex> lock(mutex_);
      last_error_ = close_result.rcm;
      closed_ = true;
    } else {
      cache_.MarkChannelClosed(OK);
      std::lock_guard<std::mutex> lock(mutex_);
      closed_ = true;
    }
    NotifyState_();
    return close_result;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheReplayResult>
  AttachConsumer(AMT::ChannelOutputProcessor processor) override {
    return cache_.AttachConsumer(std::move(processor));
  }

  ECM DetachConsumer() override { return cache_.DetachConsumer(); }

  [[nodiscard]] AMT::ChannelPortState GetState() const override {
    return cache_.GetState();
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheCopyResult> GetCacheCopy() const override {
    return cache_.GetCacheCopy();
  }

  ECM ClearCache() override { return cache_.ClearCache(); }

  [[nodiscard]] ECMData<AMT::ChannelCacheTruncateResult>
  TruncateCache(const AMT::ChannelCacheTruncateArgs &truncate_args = {}) override {
    return cache_.TruncateCache(truncate_args);
  }

  ECM EnsureLoopStarted(const AMT::ChannelLoopStartArgs &start_args = {}) override {
#ifdef _WIN32
    auto socket_result = GetWaitHandle();
    if (!(socket_result.rcm) || socket_result.data < 0) {
      return socket_result.rcm
                 ? Err(EC::NoConnection, "terminal.channel.loop.start",
                       GetChannelName(), "Remote socket is invalid")
                 : socket_result.rcm;
    }

    remote_socket_ = static_cast<SOCKET>(socket_result.data);
    if (remote_socket_ == INVALID_SOCKET) {
      return Err(EC::NoConnection, "terminal.channel.loop.start", GetChannelName(),
                 "Remote socket is invalid");
    }

    if (!EnsureLoopEvents_()) {
      return Err(EC::CommonFailure, "terminal.channel.loop.start", GetChannelName(),
                 "Failed to initialize loop events");
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (start_args.write_kick_timeout_ms > 0) {
        write_kick_timeout_ms_ = start_args.write_kick_timeout_ms;
      }
    }

    if (loop_started_.load(std::memory_order_acquire)) {
      return OK;
    }

    stop_requested_.store(false, std::memory_order_release);
    (void)ResetEvent(stop_event_);
    (void)ResetEvent(wake_event_);
    loop_thread_ = std::thread([this]() { RunLoop_(); });
    loop_started_.store(true, std::memory_order_release);
    NotifyState_();
    return OK;
#else
    (void)start_args;
    return Err(EC::OperationUnsupported, "terminal.channel.loop.start",
               GetChannelName(), "Realtime loop is Windows-only");
#endif
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheReplayResult>
  BindForeground(const AMT::ChannelForegroundBindArgs &bind_args) override {
    ECMData<AMT::ChannelCacheReplayResult> out = {};
    if (!bind_args.processor || bind_args.key_cache == nullptr ||
        bind_args.key_event_handle <= 0) {
      out.rcm = Err(EC::InvalidArg, "terminal.channel.bind", GetChannelName(),
                    "Foreground binding arguments are invalid");
      return out;
    }

    ECM const start_rcm =
        EnsureLoopStarted({bind_args.control, bind_args.write_kick_timeout_ms});
    if (!(start_rcm)) {
      out.rcm = start_rcm;
      return out;
    }

    out = AttachConsumer(bind_args.processor);
    if (!(out.rcm)) {
      return out;
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      foreground_bound_ = true;
      detach_requested_ = false;
      key_event_handle_ = bind_args.key_event_handle;
      key_cache_ = bind_args.key_cache;
      write_kick_timeout_ms_ = std::max(1, bind_args.write_kick_timeout_ms);
      key_ctrl_state_.store(false, std::memory_order_release);
      control_token_ = bind_args.control.ControlToken();
#ifdef _WIN32
      foreground_wake_guard_.reset();
      if (interrupt_event_ != nullptr && control_token_) {
        foreground_wake_guard_ =
            std::make_unique<AMDomain::client::ControlTokenWakeupSafeGaurd>(
                control_token_, [this]() { (void)SetEvent(interrupt_event_); });
      }
#endif
    }
    NotifyWake_();
    NotifyState_();
    return out;
  }

  ECM UnbindForeground() override {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      foreground_bound_ = false;
      detach_requested_ = false;
      key_event_handle_ = -1;
      key_cache_ = nullptr;
      control_token_ = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      foreground_wake_guard_.reset();
    }
    (void)DetachConsumer();
    NotifyWake_();
    NotifyState_();
    return OK;
  }

  ECM RequestForegroundDetach() override {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      foreground_bound_ = false;
      detach_requested_ = true;
      key_event_handle_ = -1;
      key_cache_ = nullptr;
      control_token_ = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      foreground_wake_guard_.reset();
    }
    (void)DetachConsumer();
    NotifyWake_();
    NotifyState_();
    return OK;
  }

  [[nodiscard]] AMT::ChannelLoopState GetLoopState() const override {
    AMT::ChannelLoopState out = {};
    std::lock_guard<std::mutex> lock(mutex_);
    out.loop_running = loop_running_.load(std::memory_order_acquire);
    out.foreground_bound = foreground_bound_;
    out.closed = closed_;
    out.detach_requested = detach_requested_;
    out.last_error = last_error_;
    out.has_error = !(last_error_);
#ifdef _WIN32
    out.state_wait_handle = reinterpret_cast<std::intptr_t>(state_event_);
#else
    out.state_wait_handle = -1;
#endif
    return out;
  }

private:
  [[nodiscard]] bool HasBinding_() const {
    return binding_.core_mutex != nullptr && binding_.sftp_core != nullptr &&
           binding_.channel_holder != nullptr && binding_.eof != nullptr &&
           binding_.exit_status != nullptr && binding_.state != nullptr &&
           binding_.window_cols != nullptr && binding_.window_rows != nullptr &&
           binding_.window_width != nullptr && binding_.window_height != nullptr;
  }

  [[nodiscard]] ErrorCode LastEC_() const {
    if (binding_.sftp_core == nullptr) {
      return ErrorCode::NoSession;
    }
    return binding_.sftp_core->GetLastEC();
  }

  [[nodiscard]] std::string LastError_() const {
    if (binding_.sftp_core == nullptr) {
      return "Session not initialized";
    }
    return binding_.sftp_core->GetLastErrorMsg();
  }

  [[nodiscard]] static int TimeoutMs_(ClientControlComponent const &control) {
    auto const remain_opt = control.RemainingTimeMs();
    if (!remain_opt.has_value()) {
      return -1;
    }
    return static_cast<int>(std::min<unsigned int>(
        *remain_opt,
        static_cast<unsigned int>((std::numeric_limits<int>::max)())));
  }

  [[nodiscard]] WaitResult
  WaitSocket_(AMSFTP::detail::SocketWaitType wait_type,
              ClientControlComponent const &control) {
    if (binding_.sftp_core == nullptr) {
      return WaitResult::Error;
    }
    return binding_.sftp_core->wait_for_socket(wait_type, control);
  }

  template <typename Func>
  [[nodiscard]] auto NBCall_(ClientControlComponent const &control, Func &&func)
      -> NBResult<decltype(func())> {
    using RetType = decltype(func());
    if (control.IsInterrupted()) {
      return {RetType{}, WaitResult::Interrupted};
    }
    if (control.IsTimeout()) {
      return {RetType{}, WaitResult::Timeout};
    }

    while (true) {
      RetType rc = func();
      bool retry = false;
      if constexpr (std::is_same_v<RetType, int> ||
                    std::is_same_v<RetType, ssize_t>) {
        retry = (rc == LIBSSH2_ERROR_EAGAIN);
      } else if constexpr (std::is_pointer_v<RetType>) {
        auto *session = (binding_.sftp_core == nullptr) ? nullptr
                                                        : binding_.sftp_core->session;
        retry = (rc == nullptr && session != nullptr &&
                 libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN);
      }
      if (!retry) {
        return {rc, WaitResult::Ready};
      }
      WaitResult const wr =
          WaitSocket_(AMSFTP::detail::SocketWaitType::Auto, control);
      if (wr != WaitResult::Ready) {
        return {RetType{}, wr};
      }
    }
  }

  [[nodiscard]] bool IsChannelAliveUnlocked_() {
    if (!HasBinding_()) {
      return false;
    }
    auto &holder = *binding_.channel_holder;
    if (!holder || !holder->channel) {
      return false;
    }
    if (holder->closed) {
      *binding_.eof = true;
      return false;
    }
    if (libssh2_channel_eof(holder->channel) != 0) {
      *binding_.eof = true;
      *binding_.exit_status = libssh2_channel_get_exit_status(holder->channel);
      return false;
    }
    return true;
  }

  [[nodiscard]] ECM ReadChunk_(std::string *output, size_t max_bytes,
                               ClientControlComponent const &control,
                               ssize_t (*reader)(LIBSSH2_CHANNEL *, char *, size_t)) {
    if (!HasBinding_() || output == nullptr) {
      return Err(EC::InvalidArg, "terminal.channel.read", GetChannelName(),
                 "Invalid read state");
    }
    auto &holder = *binding_.channel_holder;
    if (!holder || !holder->channel) {
      return Err(EC::NoConnection, "terminal.channel.read", GetChannelName(),
                 "Channel is closed");
    }

    std::array<char, 4096> buffer = {};
    while (output->size() < max_bytes) {
      size_t const left = max_bytes - output->size();
      size_t const cap = std::min(buffer.size(), left);
      ssize_t const rc = reader(holder->channel, buffer.data(), cap);
      if (rc > 0) {
        output->append(buffer.data(), static_cast<size_t>(rc));
        continue;
      }
      if (rc == 0 || rc == LIBSSH2_ERROR_EAGAIN) {
        *binding_.eof = libssh2_channel_eof(holder->channel) != 0;
        if (*binding_.eof) {
          *binding_.exit_status = libssh2_channel_get_exit_status(holder->channel);
        }
        return OK;
      }
      if (control.IsInterrupted()) {
        return Err(EC::Terminate, "terminal.channel.read", GetChannelName(),
                   "Interrupted");
      }
      if (control.IsTimeout()) {
        return Err(EC::OperationTimeout, "terminal.channel.read", GetChannelName(),
                   "Timed out");
      }
      return Err(LastEC_(), "terminal.channel.read", GetChannelName(), LastError_());
    }
    return OK;
  }

  [[nodiscard]] ECMData<AMT::ChannelReadResult>
  RawRead_(AMT::ChannelReadArgs const &read_args,
           ClientControlComponent const &control) {
    ECMData<AMT::ChannelReadResult> out = {};
    out.data.channel_name = GetChannelName();

    if (!HasBinding_()) {
      out.rcm = Err(EC::InvalidHandle, "terminal.channel.read", GetChannelName(),
                    "Channel binding is invalid");
      out.data.eof = true;
      return out;
    }

    std::lock_guard<std::recursive_mutex> lock(*binding_.core_mutex);
    if (!IsChannelAliveUnlocked_()) {
      out.rcm = Err(EC::NoConnection, "terminal.channel.read", GetChannelName(),
                    "Interactive channel not initialized");
      out.data.eof = true;
      return out;
    }

    size_t const max_bytes =
        (read_args.max_bytes == 0U ? static_cast<size_t>(32 * AMKB)
                                   : read_args.max_bytes);

    auto drain_output = [&]() -> ECM {
      ECM read_rcm =
          ReadChunk_(&out.data.output, max_bytes, control,
                     [](LIBSSH2_CHANNEL *channel, char *buf, size_t size) {
                       return libssh2_channel_read(channel, buf, size);
                     });
      if (!(read_rcm)) {
        return read_rcm;
      }
      if (out.data.output.size() >= max_bytes || *binding_.eof) {
        return OK;
      }
      ECM stderr_rcm =
          ReadChunk_(&out.data.output, max_bytes, control,
                     [](LIBSSH2_CHANNEL *channel, char *buf, size_t size) {
                       return libssh2_channel_read_stderr(channel, buf, size);
                     });
      if (!(stderr_rcm)) {
        return stderr_rcm;
      }
      return OK;
    };

    out.rcm = drain_output();
    if (!(out.rcm)) {
      out.data.eof = *binding_.eof;
      return out;
    }

    if (!out.data.output.empty() || *binding_.eof) {
      out.data.eof = *binding_.eof;
      return out;
    }

    if (control.RemainingTimeMs().has_value()) {
      WaitResult const wr =
          WaitSocket_(AMSFTP::detail::SocketWaitType::Read, control);
      if (wr == WaitResult::Interrupted) {
        out.rcm = Err(EC::Terminate, "terminal.channel.read", GetChannelName(),
                      "Interrupted while waiting output");
        out.data.eof = *binding_.eof;
        return out;
      }
      if (wr == WaitResult::Timeout) {
        out.rcm = Err(EC::OperationTimeout, "terminal.channel.read", GetChannelName(),
                      "Timed out while waiting output");
        out.data.eof = *binding_.eof;
        return out;
      }
      if (wr == WaitResult::Error) {
        out.rcm = Err(EC::SocketRecvError, "terminal.channel.read", GetChannelName(),
                      "Socket error while waiting output");
        out.data.eof = *binding_.eof;
        return out;
      }
      out.rcm = drain_output();
    }

    out.data.eof = *binding_.eof;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelWriteResult>
  RawWrite_(AMT::ChannelWriteArgs const &write_args,
            ClientControlComponent const &control) {
    ECMData<AMT::ChannelWriteResult> out = {};
    out.data.channel_name = GetChannelName();

    if (!HasBinding_()) {
      out.rcm = Err(EC::InvalidHandle, "terminal.channel.write", GetChannelName(),
                    "Channel binding is invalid");
      return out;
    }

    std::lock_guard<std::recursive_mutex> lock(*binding_.core_mutex);
    if (!IsChannelAliveUnlocked_()) {
      out.rcm = Err(EC::NoConnection, "terminal.channel.write", GetChannelName(),
                    "Interactive channel not initialized");
      return out;
    }

    auto &holder = *binding_.channel_holder;
    size_t offset = 0;
    while (offset < write_args.input.size()) {
      ssize_t const rc = libssh2_channel_write(
          holder->channel, write_args.input.data() + offset,
          static_cast<int>(write_args.input.size() - offset));
      if (rc > 0) {
        offset += static_cast<size_t>(rc);
        continue;
      }
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        WaitResult const wr =
            WaitSocket_(AMSFTP::detail::SocketWaitType::Write, control);
        if (wr == WaitResult::Ready) {
          continue;
        }
        if (wr == WaitResult::Interrupted) {
          out.rcm = Err(EC::Terminate, "terminal.channel.write", GetChannelName(),
                        "Interrupted while waiting write");
        } else if (wr == WaitResult::Timeout) {
          out.rcm = Err(EC::OperationTimeout, "terminal.channel.write", GetChannelName(),
                        "Timed out while waiting write");
        } else {
          out.rcm = Err(EC::SocketRecvError, "terminal.channel.write", GetChannelName(),
                        "Socket error while waiting write");
        }
        out.data.bytes_written = offset;
        return out;
      }

      out.rcm = Err(LastEC_(), "terminal.channel.write", GetChannelName(), LastError_());
      out.data.bytes_written = offset;
      return out;
    }

    out.rcm = OK;
    out.data.bytes_written = offset;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelResizeResult>
  RawResize_(AMT::ChannelResizeArgs const &resize_args,
             ClientControlComponent const &control) {
    ECMData<AMT::ChannelResizeResult> out = {};
    out.data.channel_name = GetChannelName();

    if (!HasBinding_()) {
      out.rcm = Err(EC::InvalidHandle, "terminal.channel.resize", GetChannelName(),
                    "Channel binding is invalid");
      return out;
    }

    std::lock_guard<std::recursive_mutex> lock(*binding_.core_mutex);
    *binding_.window_cols = resize_args.cols;
    *binding_.window_rows = resize_args.rows;
    *binding_.window_width = resize_args.width;
    *binding_.window_height = resize_args.height;

    if (!IsChannelAliveUnlocked_()) {
      out.rcm = OK;
      out.data.resized = false;
      return out;
    }

    auto &holder = *binding_.channel_holder;
    auto resize_res = NBCall_(control, [&]() {
      return libssh2_channel_request_pty_size_ex(
          holder->channel, *binding_.window_cols, *binding_.window_rows,
          *binding_.window_width, *binding_.window_height);
    });
    if (!resize_res || resize_res.value != 0) {
      out.rcm = Err(LastEC_(), "terminal.channel.resize", GetChannelName(), LastError_());
      out.data.resized = false;
      return out;
    }

    out.rcm = OK;
    out.data.resized = true;
    return out;
  }

  void BindCloseControl_(AMSFTP::detail::SafeChannel *channel,
                         ClientControlComponent const &control) {
    if (channel == nullptr) {
      return;
    }
    auto const control_token = control.ControlToken();
    auto is_interrupted = [control_token]() -> bool {
      return control_token && control_token->IsInterrupted();
    };
    int const timeout_ms = TimeoutMs_(control);
    channel->SetControlContext(std::move(is_interrupted),
                               timeout_ms >= 0 ? timeout_ms : kDefaultCloseTimeoutMs_,
                               AMTime::miliseconds());
  }

  [[nodiscard]] ECMData<AMT::ChannelCloseResult>
  RawClose_(bool force, ClientControlComponent const &control) {
    ECMData<AMT::ChannelCloseResult> out = {};
    out.data.channel_name = GetChannelName();

    if (!HasBinding_()) {
      out.rcm = Err(EC::InvalidHandle, "terminal.channel.close", GetChannelName(),
                    "Channel binding is invalid");
      return out;
    }

    std::lock_guard<std::recursive_mutex> lock(*binding_.core_mutex);
    auto &holder = *binding_.channel_holder;
    if (holder && holder->channel) {
      *binding_.exit_status = libssh2_channel_get_exit_status(holder->channel);
      BindCloseControl_(holder.get(), control);
      out.rcm = holder->graceful_exit(!force, 50, true);
      holder->closed = true;
      holder.reset();
    } else {
      out.rcm = OK;
    }

    *binding_.eof = true;
    out.data.exit_code = *binding_.exit_status;
    out.data.closed = true;

    if (out.rcm.code == ErrorCode::Success || out.rcm.code == ErrorCode::Terminate ||
        out.rcm.code == ErrorCode::OperationTimeout) {
      out.rcm = OK;
    }

    if (out.rcm) {
      *binding_.state = Err(EC::NoConnection, "terminal.channel.state", GetChannelName(),
                            "Channel is closed");
    } else {
      *binding_.state = out.rcm;
    }
    return out;
  }

private:
#ifdef _WIN32
  bool EnsureLoopEvents_() {
    if (state_event_ == nullptr) {
      state_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }
    if (wake_event_ == nullptr) {
      wake_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }
    if (stop_event_ == nullptr) {
      stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }
    if (interrupt_event_ == nullptr) {
      interrupt_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }
    if (socket_event_ == WSA_INVALID_EVENT) {
      socket_event_ = WSACreateEvent();
    }
    return state_event_ != nullptr && wake_event_ != nullptr &&
           stop_event_ != nullptr && interrupt_event_ != nullptr &&
           socket_event_ != WSA_INVALID_EVENT;
  }

  void CloseLoopEvents_() {
    foreground_wake_guard_.reset();
    if (socket_event_ != WSA_INVALID_EVENT) {
      (void)WSACloseEvent(socket_event_);
      socket_event_ = WSA_INVALID_EVENT;
    }
    if (interrupt_event_ != nullptr) {
      (void)CloseHandle(interrupt_event_);
      interrupt_event_ = nullptr;
    }
    if (stop_event_ != nullptr) {
      (void)CloseHandle(stop_event_);
      stop_event_ = nullptr;
    }
    if (wake_event_ != nullptr) {
      (void)CloseHandle(wake_event_);
      wake_event_ = nullptr;
    }
    if (state_event_ != nullptr) {
      (void)CloseHandle(state_event_);
      state_event_ = nullptr;
    }
  }

  void NotifyState_() const {
    if (state_event_ != nullptr) {
      (void)SetEvent(state_event_);
    }
  }

  void NotifyWake_() const {
    if (wake_event_ != nullptr) {
      (void)SetEvent(wake_event_);
    }
  }

  void RequestStop_() {
    stop_requested_.store(true, std::memory_order_release);
    if (stop_event_ != nullptr) {
      (void)SetEvent(stop_event_);
    }
    NotifyWake_();
  }

  void JoinLoop_() {
    if (loop_thread_.joinable()) {
      loop_thread_.join();
    }
    loop_running_.store(false, std::memory_order_release);
    loop_started_.store(false, std::memory_order_release);
  }

  void RunLoop_() {
    loop_running_.store(true, std::memory_order_release);
    NotifyState_();

    while (!stop_requested_.load(std::memory_order_acquire)) {
      bool fg = false;
      std::intptr_t key_handle = -1;
      AMAtomic<std::vector<char>> *key_cache = nullptr;
      int write_kick_timeout_ms = 100;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        fg = foreground_bound_;
        key_handle = key_event_handle_;
        key_cache = key_cache_;
        write_kick_timeout_ms = write_kick_timeout_ms_;
        if (closed_) {
          break;
        }
      }

      long mask = FD_READ | FD_CLOSE;
      if (!send_buffer_.empty()) {
        mask |= FD_WRITE;
      }
      if (WSAEventSelect(remote_socket_, socket_event_, mask) == SOCKET_ERROR) {
        std::lock_guard<std::mutex> lock(mutex_);
        last_error_ = Err(EC::SocketRecvError, "terminal.channel.loop.wait_mask",
                          GetChannelName(),
                          AMStr::fmt("WSAEventSelect failed: {}", WSAGetLastError()));
        closed_ = true;
        break;
      }

      std::array<HANDLE, 5> handles = {stop_event_, wake_event_,
                                       reinterpret_cast<HANDLE>(socket_event_),
                                       nullptr, nullptr};
      DWORD count = 3;
      DWORD key_idx = static_cast<DWORD>(-1);
      DWORD interrupt_idx = static_cast<DWORD>(-1);
      if (fg && key_handle > 0) {
        key_idx = count;
        handles[count++] = reinterpret_cast<HANDLE>(key_handle);
      }
      if (fg && interrupt_event_ != nullptr) {
        interrupt_idx = count;
        handles[count++] = interrupt_event_;
      }

      DWORD const wait_rc =
          WaitForMultipleObjects(count, handles.data(), FALSE, INFINITE);
      if (wait_rc == WAIT_FAILED) {
        std::lock_guard<std::mutex> lock(mutex_);
        last_error_ = Err(EC::CommonFailure, "terminal.channel.loop.wait", GetChannelName(),
                          AMStr::fmt("WaitForMultipleObjects failed: {}", GetLastError()));
        closed_ = true;
        break;
      }
      DWORD const idx = wait_rc - WAIT_OBJECT_0;
      if (idx == 0U) {
        break;
      }
      if (idx == 1U) {
        continue;
      }
      if (interrupt_idx != static_cast<DWORD>(-1) && idx == interrupt_idx) {
        (void)RequestForegroundDetach();
        continue;
      }
      if (key_idx != static_cast<DWORD>(-1) && idx == key_idx) {
        HandleKeyInput_(key_cache, write_kick_timeout_ms);
      }

      bool const socket_ready =
          (idx == 2U) ||
          (WSAWaitForMultipleEvents(1, &socket_event_, FALSE, 0, FALSE) ==
           WSA_WAIT_EVENT_0);
      if (!socket_ready) {
        continue;
      }

      WSANETWORKEVENTS events = {};
      if (WSAEnumNetworkEvents(remote_socket_, socket_event_, &events) ==
          SOCKET_ERROR) {
        std::lock_guard<std::mutex> lock(mutex_);
        last_error_ = Err(
            EC::SocketRecvError, "terminal.channel.loop.socket_events",
            GetChannelName(),
            AMStr::fmt("WSAEnumNetworkEvents failed: {}", WSAGetLastError()));
        closed_ = true;
        break;
      }

      bool const read_ready = (events.lNetworkEvents & (FD_READ | FD_CLOSE)) != 0;
      bool const write_ready = (events.lNetworkEvents & FD_WRITE) != 0;
      if (read_ready) {
        DrainRemote_();
      }
      if (write_ready && !send_buffer_.empty()) {
        FlushSend_();
      }
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      foreground_bound_ = false;
      key_event_handle_ = -1;
      key_cache_ = nullptr;
      control_token_ = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      closed_ = true;
      foreground_wake_guard_.reset();
    }
    (void)DetachConsumer();
    loop_running_.store(false, std::memory_order_release);
    loop_started_.store(false, std::memory_order_release);
    cache_.MarkChannelClosed(last_error_);
    NotifyState_();
  }

  void DrainRemote_() {
    for (int i = 0; i < 32; ++i) {
      auto r = ReadWrapped({32U * 1024U}, {});
      if (!(r.rcm) || r.data.eof || r.data.hard_limit_hit) {
        if (r.data.hard_limit_hit) {
          (void)RawClose_(true, {});
        }
        std::lock_guard<std::mutex> lock(mutex_);
        if (!(r.rcm)) {
          last_error_ = r.rcm;
        } else if (!(r.data.last_error)) {
          last_error_ = r.data.last_error;
        }
        if (!(r.rcm) || r.data.eof || r.data.hard_limit_hit) {
          closed_ = true;
          stop_requested_.store(true, std::memory_order_release);
          (void)SetEvent(stop_event_);
          NotifyState_();
        }
        return;
      }
      if (r.data.output.empty()) {
        return;
      }
    }
  }

  void HandleResizeBeforeWrite_() {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == nullptr || out == INVALID_HANDLE_VALUE) {
      return;
    }
    CONSOLE_SCREEN_BUFFER_INFO info = {};
    if (GetConsoleScreenBufferInfo(out, &info) == 0) {
      return;
    }
    int const cols =
        static_cast<int>(info.srWindow.Right - info.srWindow.Left + 1);
    int const rows =
        static_cast<int>(info.srWindow.Bottom - info.srWindow.Top + 1);
    if (cols <= 0 || rows <= 0) {
      return;
    }
    if (cols == last_cols_ && rows == last_rows_) {
      return;
    }
    auto resize_result = Resize({cols, rows, 0, 0}, {});
    if (resize_result.rcm) {
      last_cols_ = cols;
      last_rows_ = rows;
    }
  }

  void FlushSend_() {
    for (int i = 0; i < 16 && !send_buffer_.empty(); ++i) {
      HandleResizeBeforeWrite_();
      size_t const n = std::min<size_t>(32U * 1024U, send_buffer_.size());
      std::string const chunk(send_buffer_.data(), n);
      auto w = WriteRaw({chunk}, {});
      if (!(w.rcm)) {
        std::lock_guard<std::mutex> lock(mutex_);
        last_error_ = w.rcm;
        if (w.rcm.code == EC::NoConnection || w.rcm.code == EC::ConnectionLost ||
            w.rcm.code == EC::NoSession || w.rcm.code == EC::ClientNotFound) {
          closed_ = true;
          stop_requested_.store(true, std::memory_order_release);
          (void)SetEvent(stop_event_);
          NotifyState_();
        }
        return;
      }
      size_t const consumed =
          std::min(chunk.size(), static_cast<size_t>(w.data.bytes_written));
      if (consumed == 0U) {
        return;
      }
      send_buffer_.erase(0, consumed);
      if (consumed < chunk.size()) {
        return;
      }
    }
  }

  void HandleKeyInput_(AMAtomic<std::vector<char>> *key_cache,
                       int kick_timeout_ms) {
    if (key_cache == nullptr) {
      return;
    }
    std::vector<char> keys = {};
    {
      auto guard = key_cache->lock();
      if (!guard->empty()) {
        keys.swap(*guard);
      }
    }
    if (keys.empty()) {
      return;
    }

    for (char const ch : keys) {
      if (!key_ctrl_state_.load(std::memory_order_acquire)) {
        if (ch == '\x1d') {
          key_ctrl_state_.store(true, std::memory_order_release);
          continue;
        }
        send_buffer_.push_back(ch);
        continue;
      }

      if (ch == 'q' || ch == 'Q') {
        (void)RequestForegroundDetach();
        return;
      }

      key_ctrl_state_.store(false, std::memory_order_release);
      send_buffer_.push_back(ch);
    }

    if (send_buffer_.empty()) {
      return;
    }

    if (kick_timeout_ms > 0) {
      long const mask = FD_READ | FD_CLOSE | FD_WRITE;
      (void)WSAEventSelect(remote_socket_, socket_event_, mask);
      std::array<HANDLE, 4> waiters = {stop_event_, wake_event_,
                                       reinterpret_cast<HANDLE>(socket_event_),
                                       interrupt_event_};
      DWORD const kick_rc = WaitForMultipleObjects(
          static_cast<DWORD>(waiters.size()), waiters.data(), FALSE,
          static_cast<DWORD>(kick_timeout_ms));
      if (kick_rc == WAIT_OBJECT_0 + 3U) {
        (void)RequestForegroundDetach();
      }
    }
    FlushSend_();
  }
#else
  void CloseLoopEvents_() {}
  void RequestStop_() {}
  void JoinLoop_() {}
  void NotifyState_() const {}
  void NotifyWake_() const {}
#endif

private:
  static constexpr int kDefaultCloseTimeoutMs_ = 1500;

  std::string terminal_key_ = {};
  std::string channel_name_ = {};
  ChannelCacheStore cache_;

  RealtimeSSHChannelBinding binding_ = {};
  mutable std::mutex mutex_ = {};

  std::thread loop_thread_ = {};
  std::atomic<bool> loop_started_ = false;
  std::atomic<bool> loop_running_ = false;
  std::atomic<bool> stop_requested_ = false;

  std::string send_buffer_ = {};
  std::atomic<bool> key_ctrl_state_ = false;
  int last_cols_ = -1;
  int last_rows_ = -1;

  bool foreground_bound_ = false;
  bool detach_requested_ = false;
  bool closed_ = false;
  ECM last_error_ = OK;
  std::intptr_t key_event_handle_ = -1;
  AMAtomic<std::vector<char>> *key_cache_ = nullptr;
  int write_kick_timeout_ms_ = 100;
  AMDomain::client::amf control_token_ = nullptr;

#ifdef _WIN32
  SOCKET remote_socket_ = INVALID_SOCKET;
  WSAEVENT socket_event_ = WSA_INVALID_EVENT;
  HANDLE wake_event_ = nullptr;
  HANDLE stop_event_ = nullptr;
  HANDLE state_event_ = nullptr;
  HANDLE interrupt_event_ = nullptr;
  std::unique_ptr<AMDomain::client::ControlTokenWakeupSafeGaurd>
      foreground_wake_guard_ = nullptr;
#endif
};

} // namespace AMInfra::terminal




