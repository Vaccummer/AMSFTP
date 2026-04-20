#pragma once

#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"
#include "infrastructure/terminal/ChannelCachePort.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>

#endif

namespace AMInfra::terminal::SFTP {
using AMDomain::client::ClientHandle;
using AMInfra::client::SFTP::ChannelHandle;
namespace AMT = AMDomain::terminal;
namespace AMSFTP = AMInfra::client::SFTP;

namespace detail {

struct ChannelBinding_ {
  ClientHandle owner_client = nullptr;
  AMSFTP::AMSFTPIOCore *sftp_core = nullptr;
};

struct ChannelIdentity_ {
  std::string terminal_key = {};
  std::string channel_name = {};
};

struct ChannelRuntimeAttrs_ {
  ChannelHandle channel_holder = {};
  bool eof = false;
  int exit_status = -1;
  ECM state = OK;
  int window_cols = 80;
  int window_rows = 24;
  int window_width = 0;
  int window_height = 0;
  std::string term = "xterm-256color";
};

struct ChannelForegroundAttrs_ {
  std::string send_buffer = {};
  int last_cols = -1;
  int last_rows = -1;
  bool foreground_bound = false;
  bool detach_requested = false;
  bool closed = false;
  ECM last_error = OK;
  std::intptr_t key_event_handle = -1;
  AMAtomic<std::vector<char>> *key_cache = nullptr;
  int write_kick_timeout_ms = 0;
  AMDomain::client::amf control_token = nullptr;
};

#ifdef _WIN32
struct ChannelLoopEvents_ {
  SOCKET remote_socket = INVALID_SOCKET;
  WSAEVENT socket_event = WSA_INVALID_EVENT;
  HANDLE wake_event = nullptr;
  HANDLE stop_event = nullptr;
  HANDLE state_event = nullptr;
  HANDLE interrupt_event = nullptr;
  std::unique_ptr<AMDomain::client::InterruptWakeupSafeGuard>
      foreground_wake_guard = nullptr;
};
#endif

[[nodiscard]] inline std::string
ResolveTerminalKey_(const ClientHandle &owner_client) {
  if (!owner_client) {
    return {};
  }
  auto const &config = owner_client->ConfigPort();
  std::string const raw_nickname =
      AMStr::Strip(config.GetNickname().empty() ? config.GetRequest().nickname
                                                : config.GetNickname());
  if (raw_nickname.empty()) {
    return {};
  }
  return AMDomain::host::HostService::NormalizeNickname(raw_nickname);
}

[[nodiscard]] inline ChannelBinding_
ResolveChannelBinding_(const ClientHandle &owner_client) {
  ChannelBinding_ binding = {};
  binding.owner_client = owner_client;
  if (!owner_client) {
    return binding;
  }
  if (owner_client->ConfigPort().GetProtocol() !=
      AMDomain::host::ClientProtocol::SFTP) {
    return binding;
  }
  binding.sftp_core =
      dynamic_cast<AMSFTP::AMSFTPIOCore *>(&owner_client->IOPort());
  return binding;
}

[[nodiscard]] inline ECM ValidateChannelBinding_(const ChannelBinding_ &binding,
                                                 const char *operation,
                                                 const std::string &target) {
  if (!binding.owner_client) {
    return Err(EC::InvalidHandle, operation, target, "Client handle is null");
  }
  if (binding.owner_client->ConfigPort().GetProtocol() !=
      AMDomain::host::ClientProtocol::SFTP) {
    return Err(EC::OperationUnsupported, operation, target,
               "Client protocol is not SFTP");
  }
  if (binding.sftp_core == nullptr) {
    return Err(EC::InvalidHandle, operation, target,
               "Client IOPort is not compatible with AMSFTPIOCore");
  }
  return OK;
}

[[nodiscard]] inline ECM ContextualizeRCM_(ECM rcm, std::string operation,
                                           const std::string &target) {
  rcm.operation = std::move(operation);
  rcm.target = target;
  return rcm;
}

} // namespace detail

class RealtimeSSHChannelPort final : public AMT::IChannelPort {
public:
  RealtimeSSHChannelPort(
      ClientHandle owner_client, std::string channel_name,
      AMT::BufferExceedCallback buffer_exceed_callback = {})
      : binding_(detail::ResolveChannelBinding_(std::move(owner_client))),
        identity_(detail::ResolveTerminalKey_(binding_.owner_client),
                  AMStr::Strip(channel_name)),
        cache_(identity_.terminal_key, identity_.channel_name,
               std::move(buffer_exceed_callback)) {}

  ~RealtimeSSHChannelPort() override {
    RequestStop_();
    JoinLoop_();
    CloseLoopEvents_();
  }

  [[nodiscard]] std::string GetTerminalKey() const override {
    return identity_.terminal_key;
  }

  [[nodiscard]] std::string GetChannelName() const override {
    return identity_.channel_name;
  }

  [[nodiscard]] ECMData<SOCKET> GetWaitHandle() const override {
    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.wait_handle", GetChannelName());
    if (!binding_rcm) {
      return {INVALID_SOCKET, binding_rcm};
    }
    auto const handle = binding_.sftp_core->Socket();
    if (handle < 0) {
      return {handle, Err(EC::NoConnection, "terminal.channel.wait_handle",
                          GetChannelName(), "Remote socket is unavailable")};
    }
    return {handle, OK};
  }

  ECM Init(const AMT::ChannelInitArgs &init_args,
           const ControlComponent &control = {}) override {
    if (identity_.channel_name.empty()) {
      return {EC::InvalidArg, "terminal.channel.init", identity_.channel_name,
              "channel_name is empty"};
    }

    binding_ = detail::ResolveChannelBinding_(binding_.owner_client);
    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.init", GetChannelName());
    if (!binding_rcm) {
      return binding_rcm;
    }
    identity_.terminal_key = detail::ResolveTerminalKey_(binding_.owner_client);

    std::lock_guard<std::recursive_mutex> lock(
        binding_.sftp_core->TransferMutex());
    LIBSSH2_SESSION *session = binding_.sftp_core->Session();
    if (session == nullptr) {
      return {EC::NoConnection, "terminal.channel.init", GetChannelName(),
              "Client session is not connected"};
    }

    if (runtime_.channel_holder && runtime_.channel_holder->IsOpen() &&
        !runtime_.eof) {
      return {EC::TargetAlreadyExists, "terminal.channel.init",
              GetChannelName(), "Channel is already initialized"};
    }

    runtime_.window_cols = std::max(1, init_args.cols);
    runtime_.window_rows = std::max(1, init_args.rows);
    runtime_.window_width = std::max(0, init_args.width);
    runtime_.window_height = std::max(0, init_args.height);
    runtime_.term = init_args.term.empty() ? "xterm-256color" : init_args.term;

    runtime_.eof = false;
    runtime_.exit_status = -1;
    runtime_.state = OK;
    auto create_res = binding_.sftp_core->CreateChannel(control);
    if (!(create_res.rcm)) {
      runtime_.channel_holder.reset();
      runtime_.eof = true;
      runtime_.state = create_res.rcm;
      return create_res.rcm;
    }
    runtime_.channel_holder = std::move(create_res.data);

    libssh2_session_set_blocking(session, 0);
    auto pty_res = binding_.sftp_core->NBPerform(control, [&]() {
      return libssh2_channel_request_pty_ex(
          runtime_.channel_holder->Raw(), runtime_.term.c_str(),
          static_cast<unsigned int>(runtime_.term.size()), nullptr, 0,
          runtime_.window_cols, runtime_.window_rows, runtime_.window_width,
          runtime_.window_height);
    });
    if (!pty_res) {
      ECM ecm = detail::ContextualizeRCM_(
          pty_res.rcm, "terminal.channel.init.pty", GetChannelName());
      runtime_.channel_holder.reset();
      runtime_.eof = true;
      runtime_.state = ecm;
      return ecm;
    }
    if (pty_res.value != 0) {
      ECM ecm =
          Err(binding_.sftp_core->GetLastEC(), "terminal.channel.init.pty",
              GetChannelName(), binding_.sftp_core->GetLastErrorMsg());
      runtime_.channel_holder.reset();
      runtime_.eof = true;
      runtime_.state = ecm;
      return ecm;
    }

    auto shell_res = binding_.sftp_core->NBPerform(control, [&]() {
      return libssh2_channel_shell(runtime_.channel_holder->Raw());
    });
    if (!shell_res) {
      ECM ecm = detail::ContextualizeRCM_(
          shell_res.rcm, "terminal.channel.init.shell", GetChannelName());
      runtime_.channel_holder.reset();
      runtime_.eof = true;
      runtime_.state = ecm;
      return ecm;
    }
    if (shell_res.value != 0) {
      ECM ecm =
          Err(binding_.sftp_core->GetLastEC(), "terminal.channel.init.shell",
              GetChannelName(), binding_.sftp_core->GetLastErrorMsg());
      runtime_.channel_holder.reset();
      runtime_.eof = true;
      runtime_.state = ecm;
      return ecm;
    }

    runtime_.state = OK;
    runtime_.eof = false;
    return OK;
  }

  ECM Rename(const std::string &new_channel_name) override {
    std::string renamed = AMStr::Strip(new_channel_name);
    if (renamed.empty()) {
      return {EC::InvalidArg, "terminal.channel.rename", GetChannelName(),
              "new channel name is empty"};
    }
    identity_.channel_name = renamed;
    cache_.SetChannelName(identity_.channel_name);
    return OK;
  }

  [[nodiscard]] ECMData<AMT::ChannelReadWrappedResult>
  ReadWrapped(const AMT::ChannelReadArgs &read_args,
              const ControlComponent &control = {}) override {
    auto raw_read = RawRead_(read_args, control);
    return cache_.WrapReadResultFromRaw(raw_read);
  }

  [[nodiscard]] ECMData<AMT::ChannelWriteResult>
  WriteRaw(const AMT::ChannelWriteArgs &write_args,
           const ControlComponent &control = {}) override {
    return RawWrite_(write_args, control);
  }

  [[nodiscard]] ECMData<AMT::ChannelResizeResult>
  Resize(const AMT::ChannelResizeArgs &resize_args,
         const ControlComponent &control = {}) override {
    return RawResize_(resize_args, control);
  }

  [[nodiscard]] ECMData<AMT::ChannelCloseResult>
  Close(bool force, const ControlComponent &control = {}) override {
    RequestStop_();
    JoinLoop_();
    auto close_result = RawClose_(force, control);
    if (!(close_result.rcm)) {
      cache_.MarkChannelClosed(close_result.rcm);
      std::lock_guard<std::mutex> lock(mutex_);
      foreground_.last_error = close_result.rcm;
      foreground_.closed = true;
    } else {
      cache_.MarkChannelClosed(OK);
      std::lock_guard<std::mutex> lock(mutex_);
      foreground_.closed = true;
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
    auto state = cache_.GetState();
    std::lock_guard<std::mutex> lock(mutex_);
    if (foreground_.closed) {
      state.closed = true;
    }
    if (!(runtime_.state)) {
      state.last_error = runtime_.state;
    }
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
#ifdef _WIN32
    auto socket_result = GetWaitHandle();
    if (!socket_result.rcm || socket_result.data != INVALID_SOCKET) {
      return socket_result.rcm
                 ? Err(EC::NoConnection, "terminal.channel.loop.start",
                       GetChannelName(), "Remote socket is invalid")
                 : socket_result.rcm;
    }

    loop_events_.remote_socket = socket_result.data;

    if (!EnsureLoopEvents_()) {
      return Err(EC::CommonFailure, "terminal.channel.loop.start",
                 GetChannelName(), "Failed to initialize loop events");
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (start_args.write_kick_timeout_ms >= 0) {
        foreground_.write_kick_timeout_ms = start_args.write_kick_timeout_ms;
      }
    }

    if (loop_started_.load(std::memory_order_acquire)) {
      return OK;
    }

    stop_requested_.store(false, std::memory_order_release);
    (void)ResetEvent(loop_events_.stop_event);
    (void)ResetEvent(loop_events_.wake_event);
    loop_thread_ = std::jthread(
        [this](std::stop_token stop_token) { RunLoop_(stop_token); });
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
      foreground_.foreground_bound = true;
      foreground_.detach_requested = false;
      foreground_.key_event_handle = bind_args.key_event_handle;
      foreground_.key_cache = bind_args.key_cache;
      foreground_.write_kick_timeout_ms =
          std::max(0, bind_args.write_kick_timeout_ms);
      key_ctrl_state_.store(false, std::memory_order_release);
      foreground_.control_token = bind_args.control.ControlToken();
#ifdef _WIN32
      loop_events_.foreground_wake_guard.reset();
      if (loop_events_.interrupt_event != nullptr &&
          foreground_.control_token) {
        loop_events_.foreground_wake_guard =
            std::make_unique<AMDomain::client::InterruptWakeupSafeGuard>(
                foreground_.control_token,
                [this]() { (void)SetEvent(loop_events_.interrupt_event); });
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
      foreground_.foreground_bound = false;
      foreground_.detach_requested = false;
      foreground_.key_event_handle = -1;
      foreground_.key_cache = nullptr;
      foreground_.control_token = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
#ifdef _WIN32
      loop_events_.foreground_wake_guard.reset();
#endif
    }
    (void)DetachConsumer();
    NotifyWake_();
    NotifyState_();
    return OK;
  }

  ECM RequestForegroundDetach() override {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      foreground_.foreground_bound = false;
      foreground_.detach_requested = true;
      foreground_.key_event_handle = -1;
      foreground_.key_cache = nullptr;
      foreground_.control_token = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
#ifdef _WIN32
      loop_events_.foreground_wake_guard.reset();
#endif
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
    out.foreground_bound = foreground_.foreground_bound;
    out.closed = foreground_.closed;
    out.detach_requested = foreground_.detach_requested;
    out.last_error = foreground_.last_error;
    out.has_error = !(foreground_.last_error);
#ifdef _WIN32
    out.state_wait_handle =
        reinterpret_cast<std::intptr_t>(loop_events_.state_event);
#else
    out.state_wait_handle = -1;
#endif
    return out;
  }

private:
  [[nodiscard]] ECM WaitUntilReadable_(ControlComponent const &control) {
    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.read", GetChannelName());
    if (!binding_rcm) {
      return binding_rcm;
    }
    auto &holder = runtime_.channel_holder;
    if (!holder || !holder->IsOpen()) {
      return Err(EC::NoConnection, "terminal.channel.read", GetChannelName(),
                 "Channel is closed");
    }

    auto wait_res = binding_.sftp_core->NBPerform(control, [&]() {
      if (libssh2_channel_eof(holder->Raw()) != 0) {
        return 1;
      }
      if (libssh2_poll_channel_read(holder->Raw(), 0) > 0 ||
          libssh2_poll_channel_read(holder->Raw(), 1) > 0) {
        return 1;
      }
      return LIBSSH2_ERROR_EAGAIN;
    });
    if (!wait_res) {
      return detail::ContextualizeRCM_(wait_res.rcm, "terminal.channel.read",
                                       GetChannelName());
    }
    return OK;
  }

  [[nodiscard]] bool IsChannelAliveUnlocked_() {
    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.state", GetChannelName());
    if (!binding_rcm) {
      return false;
    }
    auto &holder = runtime_.channel_holder;
    if (!holder || !holder->IsOpen()) {
      runtime_.eof = true;
      return false;
    }
    if (libssh2_channel_eof(holder->Raw()) != 0) {
      runtime_.eof = true;
      runtime_.exit_status = holder->ExitStatus();
      return false;
    }
    return true;
  }

  [[nodiscard]] ECM ReadChunk_(std::string *output, size_t max_bytes,
                               ssize_t (*reader)(LIBSSH2_CHANNEL *, char *,
                                                 size_t)) {
    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.read", GetChannelName());
    if (!binding_rcm) {
      return binding_rcm;
    }
    if (output == nullptr) {
      return Err(EC::InvalidArg, "terminal.channel.read", GetChannelName(),
                 "Invalid read state");
    }
    auto &holder = runtime_.channel_holder;
    if (!holder || !holder->IsOpen()) {
      return Err(EC::NoConnection, "terminal.channel.read", GetChannelName(),
                 "Channel is closed");
    }

    std::array<char, 4096> buffer = {};
    while (output->size() < max_bytes) {
      size_t const left = max_bytes - output->size();
      size_t const cap = std::min(buffer.size(), left);
      ssize_t const rc = reader(holder->Raw(), buffer.data(), cap);
      if (rc > 0) {
        if (binding_.sftp_core != nullptr) {
          binding_.sftp_core->TouchLastIO();
        }
        output->append(buffer.data(), static_cast<size_t>(rc));
        continue;
      }
      if (rc == 0 || rc == LIBSSH2_ERROR_EAGAIN) {
        runtime_.eof = libssh2_channel_eof(holder->Raw()) != 0;
        if (runtime_.eof) {
          runtime_.exit_status = holder->ExitStatus();
        }
        return OK;
      }
      return Err(binding_.sftp_core->GetLastEC(), "terminal.channel.read",
                 GetChannelName(), binding_.sftp_core->GetLastErrorMsg());
    }
    return OK;
  }

  [[nodiscard]] ECMData<AMT::ChannelReadResult>
  RawRead_(AMT::ChannelReadArgs const &read_args,
           ControlComponent const &control) {
    ECMData<AMT::ChannelReadResult> out = {};
    out.data.channel_name = GetChannelName();

    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.read", GetChannelName());
    if (!binding_rcm) {
      out.rcm = binding_rcm;
      out.data.eof = true;
      return out;
    }

    std::lock_guard<std::recursive_mutex> lock(
        binding_.sftp_core->TransferMutex());
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
          ReadChunk_(&out.data.output, max_bytes,
                     [](LIBSSH2_CHANNEL *channel, char *buf, size_t size) {
                       return libssh2_channel_read(channel, buf, size);
                     });
      if (!(read_rcm)) {
        return read_rcm;
      }
      if (out.data.output.size() >= max_bytes || runtime_.eof) {
        return OK;
      }
      ECM stderr_rcm =
          ReadChunk_(&out.data.output, max_bytes,
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
      out.data.eof = runtime_.eof;
      return out;
    }

    if (!out.data.output.empty() || runtime_.eof) {
      out.data.eof = runtime_.eof;
      return out;
    }

    if (control.RemainingTimeMs().has_value()) {
      out.rcm = WaitUntilReadable_(control);
      if (!(out.rcm)) {
        out.data.eof = runtime_.eof;
        return out;
      }
      out.rcm = drain_output();
    }

    out.data.eof = runtime_.eof;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelWriteResult>
  RawWrite_(AMT::ChannelWriteArgs const &write_args,
            ControlComponent const &control) {
    ECMData<AMT::ChannelWriteResult> out = {};
    out.data.channel_name = GetChannelName();

    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.write", GetChannelName());
    if (!binding_rcm) {
      out.rcm = binding_rcm;
      return out;
    }

    std::lock_guard<std::recursive_mutex> lock(
        binding_.sftp_core->TransferMutex());
    if (!IsChannelAliveUnlocked_()) {
      out.rcm = Err(EC::NoConnection, "terminal.channel.write",
                    GetChannelName(), "Interactive channel not initialized");
      return out;
    }

    auto &holder = runtime_.channel_holder;
    size_t offset = 0;
    while (offset < write_args.input.size()) {
      auto write_res = binding_.sftp_core->NBPerform(control, [&]() {
        return libssh2_channel_write(
            holder->Raw(), write_args.input.data() + offset,
            static_cast<int>(write_args.input.size() - offset));
      });
      if (!write_res) {
        out.rcm = detail::ContextualizeRCM_(
            write_res.rcm, "terminal.channel.write", GetChannelName());
        out.data.bytes_written = offset;
        return out;
      }
      if (write_res.value > 0) {
        offset += static_cast<size_t>(write_res.value);
        continue;
      }
      out.rcm = Err(binding_.sftp_core->GetLastEC(), "terminal.channel.write",
                    GetChannelName(), binding_.sftp_core->GetLastErrorMsg());
      out.data.bytes_written = offset;
      return out;
    }

    out.rcm = OK;
    out.data.bytes_written = offset;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelResizeResult>
  RawResize_(AMT::ChannelResizeArgs const &resize_args,
             ControlComponent const &control) {
    ECMData<AMT::ChannelResizeResult> out = {};
    out.data.channel_name = GetChannelName();

    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.resize", GetChannelName());
    if (!binding_rcm) {
      out.rcm = binding_rcm;
      return out;
    }

    std::lock_guard<std::recursive_mutex> lock(
        binding_.sftp_core->TransferMutex());
    runtime_.window_cols = resize_args.cols;
    runtime_.window_rows = resize_args.rows;
    runtime_.window_width = resize_args.width;
    runtime_.window_height = resize_args.height;

    if (!IsChannelAliveUnlocked_()) {
      out.rcm = OK;
      out.data.resized = false;
      return out;
    }

    auto &holder = runtime_.channel_holder;
    auto resize_res = binding_.sftp_core->NBPerform(control, [&]() {
      return libssh2_channel_request_pty_size_ex(
          holder->Raw(), runtime_.window_cols, runtime_.window_rows,
          runtime_.window_width, runtime_.window_height);
    });
    if (!resize_res) {
      out.rcm = detail::ContextualizeRCM_(
          resize_res.rcm, "terminal.channel.resize", GetChannelName());
      out.data.resized = false;
      return out;
    }
    if (resize_res.value != 0) {
      out.rcm = Err(binding_.sftp_core->GetLastEC(), "terminal.channel.resize",
                    GetChannelName(), binding_.sftp_core->GetLastErrorMsg());
      out.data.resized = false;
      return out;
    }

    out.rcm = OK;
    out.data.resized = true;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelCloseResult>
  RawClose_(bool force, ControlComponent const &control) {
    ECMData<AMT::ChannelCloseResult> out = {};
    out.data.channel_name = GetChannelName();

    ECM const binding_rcm = detail::ValidateChannelBinding_(
        binding_, "terminal.channel.close", GetChannelName());
    if (!binding_rcm) {
      out.rcm = binding_rcm;
      return out;
    }

    std::lock_guard<std::recursive_mutex> lock(
        binding_.sftp_core->TransferMutex());
    auto &holder = runtime_.channel_holder;
    if (holder && holder->Raw() != nullptr) {
      runtime_.exit_status = holder->ExitStatus();
      out.rcm = binding_.sftp_core->CloseChannel(holder, force, control);
    } else {
      out.rcm = OK;
    }

    runtime_.eof = true;
    out.data.exit_code = runtime_.exit_status;
    out.data.closed = true;

    if (out.rcm.code == ErrorCode::Success ||
        out.rcm.code == ErrorCode::Terminate ||
        out.rcm.code == ErrorCode::OperationTimeout) {
      out.rcm = OK;
    }

    if (out.rcm) {
      runtime_.state = Err(EC::NoConnection, "terminal.channel.state",
                           GetChannelName(), "Channel is closed");
    } else {
      runtime_.state = out.rcm;
    }
    return out;
  }

private:
#ifdef _WIN32
  bool EnsureLoopEvents_() {
    if (loop_events_.state_event == nullptr) {
      loop_events_.state_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }
    if (loop_events_.wake_event == nullptr) {
      loop_events_.wake_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }
    if (loop_events_.stop_event == nullptr) {
      loop_events_.stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }
    if (loop_events_.interrupt_event == nullptr) {
      loop_events_.interrupt_event =
          CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }
    if (loop_events_.socket_event == WSA_INVALID_EVENT) {
      loop_events_.socket_event = WSACreateEvent();
    }
    return loop_events_.state_event != nullptr &&
           loop_events_.wake_event != nullptr &&
           loop_events_.stop_event != nullptr &&
           loop_events_.interrupt_event != nullptr &&
           loop_events_.socket_event != WSA_INVALID_EVENT;
  }

  void CloseLoopEvents_() {
    loop_events_.foreground_wake_guard.reset();
    if (loop_events_.socket_event != WSA_INVALID_EVENT) {
      (void)WSACloseEvent(loop_events_.socket_event);
      loop_events_.socket_event = WSA_INVALID_EVENT;
    }
    if (loop_events_.interrupt_event != nullptr) {
      (void)CloseHandle(loop_events_.interrupt_event);
      loop_events_.interrupt_event = nullptr;
    }
    if (loop_events_.stop_event != nullptr) {
      (void)CloseHandle(loop_events_.stop_event);
      loop_events_.stop_event = nullptr;
    }
    if (loop_events_.wake_event != nullptr) {
      (void)CloseHandle(loop_events_.wake_event);
      loop_events_.wake_event = nullptr;
    }
    if (loop_events_.state_event != nullptr) {
      (void)CloseHandle(loop_events_.state_event);
      loop_events_.state_event = nullptr;
    }
  }

  void NotifyState_() const {
    if (loop_events_.state_event != nullptr) {
      (void)SetEvent(loop_events_.state_event);
    }
  }

  void NotifyWake_() const {
    if (loop_events_.wake_event != nullptr) {
      (void)SetEvent(loop_events_.wake_event);
    }
  }

  void RequestStop_() {
    stop_requested_.store(true, std::memory_order_release);
    if (loop_thread_.joinable()) {
      loop_thread_.request_stop();
    }
    if (loop_events_.stop_event != nullptr) {
      (void)SetEvent(loop_events_.stop_event);
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

  void RunLoop_(std::stop_token stop_token) {
    loop_running_.store(true, std::memory_order_release);
    NotifyState_();

    while (!stop_requested_.load(std::memory_order_acquire) &&
           !stop_token.stop_requested()) {
      bool fg = false;
      std::intptr_t key_handle = -1;
      AMAtomic<std::vector<char>> *key_cache = nullptr;
      int write_kick_timeout_ms = 0;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        fg = foreground_.foreground_bound;
        key_handle = foreground_.key_event_handle;
        key_cache = foreground_.key_cache;
        write_kick_timeout_ms = foreground_.write_kick_timeout_ms;
        if (foreground_.closed) {
          break;
        }
      }

      long mask = FD_READ | FD_CLOSE;
      if (!foreground_.send_buffer.empty()) {
        mask |= FD_WRITE;
      }
      if (WSAEventSelect(loop_events_.remote_socket, loop_events_.socket_event,
                         mask) == SOCKET_ERROR) {
        std::lock_guard<std::mutex> lock(mutex_);
        foreground_.last_error =
            Err(EC::SocketRecvError, "terminal.channel.loop.wait_mask",
                GetChannelName(),
                AMStr::fmt("WSAEventSelect failed: {}", WSAGetLastError()));
        foreground_.closed = true;
        break;
      }

      std::array<HANDLE, 5> handles = {
          loop_events_.stop_event, loop_events_.wake_event,
          reinterpret_cast<HANDLE>(loop_events_.socket_event), nullptr,
          nullptr};
      DWORD count = 3;
      DWORD key_idx = static_cast<DWORD>(-1);
      DWORD interrupt_idx = static_cast<DWORD>(-1);
      if (fg && key_handle > 0) {
        key_idx = count;
        handles[count++] = reinterpret_cast<HANDLE>(key_handle);
      }
      if (fg && loop_events_.interrupt_event != nullptr) {
        interrupt_idx = count;
        handles[count++] = loop_events_.interrupt_event;
      }

      DWORD const wait_rc =
          WaitForMultipleObjects(count, handles.data(), FALSE, INFINITE);
      if (wait_rc == WAIT_FAILED) {
        std::lock_guard<std::mutex> lock(mutex_);
        foreground_.last_error = Err(
            EC::CommonFailure, "terminal.channel.loop.wait", GetChannelName(),
            AMStr::fmt("WaitForMultipleObjects failed: {}", GetLastError()));
        foreground_.closed = true;
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
          (WSAWaitForMultipleEvents(1, &loop_events_.socket_event, FALSE, 0,
                                    FALSE) == WSA_WAIT_EVENT_0);
      if (!socket_ready) {
        continue;
      }

      WSANETWORKEVENTS events = {};
      if (WSAEnumNetworkEvents(loop_events_.remote_socket,
                               loop_events_.socket_event,
                               &events) == SOCKET_ERROR) {
        std::lock_guard<std::mutex> lock(mutex_);
        foreground_.last_error = Err(
            EC::SocketRecvError, "terminal.channel.loop.socket_events",
            GetChannelName(),
            AMStr::fmt("WSAEnumNetworkEvents failed: {}", WSAGetLastError()));
        foreground_.closed = true;
        break;
      }

      bool const read_ready =
          (events.lNetworkEvents & (FD_READ | FD_CLOSE)) != 0;
      bool const write_ready = (events.lNetworkEvents & FD_WRITE) != 0;
      if (read_ready) {
        DrainRemote_();
      }
      if (write_ready && !foreground_.send_buffer.empty()) {
        FlushSend_();
      }
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      foreground_.foreground_bound = false;
      foreground_.key_event_handle = -1;
      foreground_.key_cache = nullptr;
      foreground_.control_token = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      foreground_.closed = true;
      loop_events_.foreground_wake_guard.reset();
    }
    (void)DetachConsumer();
    loop_running_.store(false, std::memory_order_release);
    loop_started_.store(false, std::memory_order_release);
    cache_.MarkChannelClosed(foreground_.last_error);
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
          foreground_.last_error = r.rcm;
        } else if (!(r.data.last_error)) {
          foreground_.last_error = r.data.last_error;
        }
        if (!(r.rcm) || r.data.eof || r.data.hard_limit_hit) {
          foreground_.closed = true;
          stop_requested_.store(true, std::memory_order_release);
          (void)SetEvent(loop_events_.stop_event);
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
    if (cols == foreground_.last_cols && rows == foreground_.last_rows) {
      return;
    }
    auto resize_result = Resize({cols, rows, 0, 0}, {});
    if (resize_result.rcm) {
      foreground_.last_cols = cols;
      foreground_.last_rows = rows;
    }
  }

  void FlushSend_() {
    for (int i = 0; i < 16 && !foreground_.send_buffer.empty(); ++i) {
      HandleResizeBeforeWrite_();
      size_t const n =
          std::min<size_t>(32U * 1024U, foreground_.send_buffer.size());
      std::string const chunk(foreground_.send_buffer.data(), n);
      auto w = WriteRaw({chunk}, {});
      if (!(w.rcm)) {
        std::lock_guard<std::mutex> lock(mutex_);
        foreground_.last_error = w.rcm;
        if (w.rcm.code == EC::NoConnection ||
            w.rcm.code == EC::ConnectionLost || w.rcm.code == EC::NoSession ||
            w.rcm.code == EC::ClientNotFound) {
          foreground_.closed = true;
          stop_requested_.store(true, std::memory_order_release);
          (void)SetEvent(loop_events_.stop_event);
          NotifyState_();
        }
        return;
      }
      size_t const consumed =
          std::min(chunk.size(), static_cast<size_t>(w.data.bytes_written));
      if (consumed == 0U) {
        return;
      }
      foreground_.send_buffer.erase(0, consumed);
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
        foreground_.send_buffer.push_back(ch);
        continue;
      }

      if (ch == 'q' || ch == 'Q') {
        (void)RequestForegroundDetach();
        return;
      }

      key_ctrl_state_.store(false, std::memory_order_release);
      foreground_.send_buffer.push_back(ch);
    }

    if (foreground_.send_buffer.empty()) {
      return;
    }

    if (kick_timeout_ms > 0) {
      long const mask = FD_READ | FD_CLOSE | FD_WRITE;
      (void)WSAEventSelect(loop_events_.remote_socket,
                           loop_events_.socket_event, mask);
      std::array<HANDLE, 4> waiters = {
          loop_events_.stop_event, loop_events_.wake_event,
          reinterpret_cast<HANDLE>(loop_events_.socket_event),
          loop_events_.interrupt_event};
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

  detail::ChannelBinding_ binding_ = {};
  detail::ChannelIdentity_ identity_ = {};
  ChannelCacheStore cache_;
  detail::ChannelRuntimeAttrs_ runtime_ = {};
  detail::ChannelForegroundAttrs_ foreground_ = {};

  mutable std::mutex mutex_ = {};

  std::jthread loop_thread_ = {};
  std::atomic<bool> loop_started_ = false;
  std::atomic<bool> loop_running_ = false;
  std::atomic<bool> stop_requested_ = false;
  std::atomic<bool> key_ctrl_state_ = false;

#ifdef _WIN32
  detail::ChannelLoopEvents_ loop_events_ = {};
#endif
};

} // namespace AMInfra::terminal::SFTP
