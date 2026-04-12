#pragma once

#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/client/local/Local.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
#else
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__linux__)
#include <pty.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <util.h>
#endif
#endif

namespace AMInfra::client::LOCAL::terminal {
namespace AMT = AMDomain::terminal;

class LocalTerminalPort final : public AMT::ITerminalPort {
private:
  struct TerminalWindowInfo_ {
    int cols = 80;
    int rows = 24;
    int width = 0;
    int height = 0;
    std::string term = "xterm-256color";
  };

  struct ChannelCtx_ {
    TerminalWindowInfo_ window = {};
    bool eof = false;
    bool process_exited = false;
    int exit_status = -1;
    ECM state = OK;
#ifdef _WIN32
    void *pseudo_console = nullptr;
    HANDLE input_write = INVALID_HANDLE_VALUE;
    HANDLE output_read = INVALID_HANDLE_VALUE;
    HANDLE process_handle = INVALID_HANDLE_VALUE;
#else
    int master_fd = -1;
    pid_t child_pid = -1;
#endif
  };

  struct TerminalStateCache_ {
    AMDomain::filesystem::CheckResult session_state =
        AMDomain::filesystem::CheckResult(
            AMDomain::client::ClientStatus::NotInitialized);
    std::optional<std::string> current_channel = std::nullopt;
    std::unordered_map<std::string, ECM> channel_states = {};
  };

  mutable AMAtomic<TerminalStateCache_> attr_cache_ =
      AMAtomic<TerminalStateCache_>(TerminalStateCache_{});

  ConRequest request_ = {};
  AMT::ClientHandle owner_client_ = nullptr;
  AMLocalIOCore *local_core_ = nullptr;
  mutable std::recursive_mutex mutex_ = {};
  std::map<std::string, ChannelCtx_> channels_ = {};
  std::optional<std::string> current_channel_ = std::nullopt;

#ifdef _WIN32
  struct ConPTYApi_ {
    using CreatePseudoConsoleFn =
        HRESULT(WINAPI *)(COORD, HANDLE, HANDLE, DWORD, void **);
    using ResizePseudoConsoleFn = HRESULT(WINAPI *)(void *, COORD);
    using ClosePseudoConsoleFn = void(WINAPI *)(void *);

    HMODULE kernel = nullptr;
    CreatePseudoConsoleFn create = nullptr;
    ResizePseudoConsoleFn resize = nullptr;
    ClosePseudoConsoleFn close = nullptr;

    ConPTYApi_();
    [[nodiscard]] bool IsAvailable() const;
  };

  [[nodiscard]] static const ConPTYApi_ &ConPTYApiInstance_();
  static void CloseHandleSafe_(HANDLE *handle);
  static void ClosePseudoConsoleSafe_(void **pseudo_console);
  static void UpdateWindowsProcessState_(ChannelCtx_ *ctx);
  static bool DrainWindowsOutput_(ChannelCtx_ *ctx, std::string *output,
                                  size_t max_bytes);
  static bool WaitReadableWindows_(
      ChannelCtx_ *ctx, const AMDomain::client::ClientControlComponent &control,
      bool *timed_out);
  static ECM OpenOneChannelWindows_(ChannelCtx_ *ctx,
                                    const AMT::ChannelOpenArgs &open_args);
#else
  static void UpdatePosixProcessState_(ChannelCtx_ *ctx);
  static bool DrainPosixOutput_(ChannelCtx_ *ctx, std::string *output,
                                size_t max_bytes);
  static bool WaitReadablePosix_(
      ChannelCtx_ *ctx, const AMDomain::client::ClientControlComponent &control,
      bool *timed_out);
  static ECM OpenOneChannelPosix_(ChannelCtx_ *ctx,
                                  const AMT::ChannelOpenArgs &open_args);
#endif

  [[nodiscard]] static TerminalWindowInfo_
  OpenWindow_(const AMT::ChannelOpenArgs &open_args,
              const TerminalWindowInfo_ &fallback);
  static void ResizeWindow_(const AMT::ChannelResizeArgs &resize_args,
                            TerminalWindowInfo_ *window);
  [[nodiscard]] static std::string ResolveTargetChannelName_(
      const std::optional<std::string> &requested_name,
      const std::optional<std::string> &current_channel);
  [[nodiscard]] std::string ResolveTargetChannelName_(
      const std::optional<std::string> &requested_name) const;
  [[nodiscard]] std::string
  ResolveTargetChannelName_(const std::string &requested_name) const;
  [[nodiscard]] ECMData<ChannelCtx_ *>
  ResolveChannelForOp_(const std::optional<std::string> &requested_name,
                       const char *action_name);
  [[nodiscard]] ECM
  ValidateSessionReady_(const AMDomain::client::ClientControlComponent &control,
                        const char *action) const;
  void CloseChannelRuntime_(ChannelCtx_ *ctx, bool force);

  [[nodiscard]] AMDomain::filesystem::CheckResult
  ReadSessionStateFromClient_() const;
  void SyncCacheFromRuntimeUnlocked_();

  struct CacheSyncGuard_ {
    LocalTerminalPort *self = nullptr;
    ~CacheSyncGuard_() {
      if (self) {
        self->SyncCacheFromRuntimeUnlocked_();
      }
    }
  };

public:
  LocalTerminalPort(AMT::ClientHandle owner_client, const ConRequest &request,
                    AMLocalIOCore *local_core)
      : request_(request), owner_client_(std::move(owner_client)),
        local_core_(local_core) {
    SyncCacheFromRuntimeUnlocked_();
  }

  ~LocalTerminalPort() override;

  [[nodiscard]] ConRequest GetRequest() const override;

  ECMData<AMT::ChannelOpenResult>
  OpenChannel(const AMT::ChannelOpenArgs &open_args,
              const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelActiveResult>
  ActiveChannel(const AMT::ChannelActiveArgs &active_args,
                const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelReadResult>
  ReadChannel(const AMT::ChannelReadArgs &read_args,
              const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelWriteResult>
  WriteChannel(const AMT::ChannelWriteArgs &write_args,
               const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelResizeResult>
  ResizeChannel(const AMT::ChannelResizeArgs &resize_args,
                const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelCloseResult>
  CloseChannel(const AMT::ChannelCloseArgs &close_args,
               const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelRenameResult>
  RenameChannel(const AMT::ChannelRenameArgs &rename_args,
                const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelListResult>
  ListChannels(const AMT::ChannelListArgs &list_args,
               const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::CheckSessionResult>
  CheckSession(const AMT::CheckSessionArgs &check_args,
               const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelCheckResult>
  CheckChannel(const AMT::ChannelCheckArgs &check_args,
               const AMDomain::client::ClientControlComponent &control) override;

  [[nodiscard]] AMDomain::filesystem::CheckResult
  GetSessionState() const override;

  [[nodiscard]] std::optional<ECM>
  GetChannelState(const std::string &channel_name) const override;

  [[nodiscard]] std::vector<std::string>
  GetCachedChannelNames() const override;

  [[nodiscard]] ECMData<std::intptr_t> GetRemoteSocketHandle() const override;
};

inline LocalTerminalPort::~LocalTerminalPort() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  for (auto &entry : channels_) {
    CloseChannelRuntime_(&(entry.second), true);
  }
  channels_.clear();
  current_channel_ = std::nullopt;
  SyncCacheFromRuntimeUnlocked_();
}

inline ConRequest LocalTerminalPort::GetRequest() const { return request_; }

inline AMDomain::filesystem::CheckResult
LocalTerminalPort::ReadSessionStateFromClient_() const {
  if (!owner_client_) {
    return AMDomain::filesystem::CheckResult(
        AMDomain::client::ClientStatus::NotInitialized);
  }
  auto state = owner_client_->ConfigPort().GetState();
  if (!state.rcm) {
    return AMDomain::filesystem::CheckResult(
        AMDomain::client::ClientStatus::NotInitialized);
  }
  return AMDomain::filesystem::CheckResult(state.data.status);
}

inline void LocalTerminalPort::SyncCacheFromRuntimeUnlocked_() {
  auto guard = attr_cache_.lock();
  (*guard).session_state = ReadSessionStateFromClient_();
  (*guard).current_channel = current_channel_;
  (*guard).channel_states.clear();
  for (const auto &entry : channels_) {
    const auto &ctx = entry.second;
    ECM state = ctx.state;
    if (ctx.eof || ctx.process_exited) {
      state = Err(EC::NoConnection, "terminal.channel.state", entry.first,
                  "Channel is closed");
    }
    (*guard).channel_states[entry.first] = state;
  }
}

inline LocalTerminalPort::TerminalWindowInfo_
LocalTerminalPort::OpenWindow_(const AMT::ChannelOpenArgs &open_args,
                               const TerminalWindowInfo_ &fallback) {
  TerminalWindowInfo_ out = fallback;
  out.cols = open_args.cols;
  out.rows = open_args.rows;
  out.width = open_args.width;
  out.height = open_args.height;
  if (!open_args.term.empty()) {
    out.term = open_args.term;
  }
  if (out.term.empty()) {
    out.term = "xterm-256color";
  }
  return out;
}

inline void
LocalTerminalPort::ResizeWindow_(const AMT::ChannelResizeArgs &resize_args,
                                 TerminalWindowInfo_ *window) {
  if (window == nullptr) {
    return;
  }
  window->cols = resize_args.cols;
  window->rows = resize_args.rows;
  window->width = resize_args.width;
  window->height = resize_args.height;
}

inline std::string LocalTerminalPort::ResolveTargetChannelName_(
    const std::optional<std::string> &requested_name,
    const std::optional<std::string> &current_channel) {
  const std::string requested =
      requested_name.has_value() ? AMStr::Strip(*requested_name) : "";
  if (!requested.empty()) {
    return requested;
  }
  if (current_channel.has_value()) {
    return *current_channel;
  }
  return "";
}

inline std::string LocalTerminalPort::ResolveTargetChannelName_(
    const std::optional<std::string> &requested_name) const {
  return ResolveTargetChannelName_(requested_name, current_channel_);
}

inline std::string
LocalTerminalPort::ResolveTargetChannelName_(const std::string &requested_name) const {
  return ResolveTargetChannelName_(std::optional<std::string>(requested_name),
                                   current_channel_);
}

inline ECMData<LocalTerminalPort::ChannelCtx_ *>
LocalTerminalPort::ResolveChannelForOp_(
    const std::optional<std::string> &requested_name,
    const char *action_name) {
  const std::string target_name = ResolveTargetChannelName_(requested_name);
  if (target_name.empty()) {
    return {nullptr,
            Err(EC::InvalidArg, action_name, "channel_name",
                "No channel_name provided and no active channel set")};
  }
  auto it = channels_.find(target_name);
  if (it == channels_.end()) {
    return {nullptr, Err(EC::InvalidArg, action_name, target_name,
                         "Target channel does not exist")};
  }
  return {&(it->second), OK};
}

inline ECM LocalTerminalPort::ValidateSessionReady_(
    const AMDomain::client::ClientControlComponent &control,
    const char *action) const {
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, action, request_.nickname, "Interrupted by user");
  }
  if (control.IsTimeout()) {
    return Err(EC::OperationTimeout, action, request_.nickname,
               "Operation timed out");
  }
  if (!owner_client_) {
    return Err(EC::InvalidHandle, action, request_.nickname,
               "Client handle is null");
  }
  if (local_core_ == nullptr) {
    return Err(EC::InvalidHandle, action, request_.nickname,
               "Local IO core is unavailable");
  }
  const auto state = owner_client_->ConfigPort().GetState();
  if (!state.rcm) {
    return state.rcm;
  }
  if (state.data.status != AMDomain::client::ClientStatus::OK) {
    return Err(EC::NoConnection, action, request_.nickname,
               "Local client session is not ready");
  }
  return OK;
}

inline ECMData<AMT::ChannelOpenResult> LocalTerminalPort::OpenChannel(
    const AMT::ChannelOpenArgs &open_args,
    const AMDomain::client::ClientControlComponent &control) {
  ECMData<AMT::ChannelOpenResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  const std::string channel_name = AMStr::Strip(open_args.channel_name);
  if (channel_name.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.open", "channel_name",
                  "channel_name is required");
    return out;
  }
  if (!AMDomain::host::HostService::ValidateNickname(channel_name)) {
    out.rcm = Err(EC::InvalidArg, "terminal.open", channel_name,
                  "Invalid channel_name literal");
    return out;
  }
  if (channels_.find(channel_name) != channels_.end()) {
    out.rcm = Err(EC::TargetAlreadyExists, "terminal.open", channel_name,
                  "Channel name already exists");
    return out;
  }
  out.rcm = ValidateSessionReady_(control, "terminal.open");
  if (!out.rcm) {
    return out;
  }

  ChannelCtx_ ctx = {};
  ctx.window = OpenWindow_(open_args, ctx.window);
#ifdef _WIN32
  out.rcm = OpenOneChannelWindows_(&ctx, open_args);
#else
  out.rcm = OpenOneChannelPosix_(&ctx, open_args);
#endif
  if (!out.rcm) {
    return out;
  }

  channels_.emplace(channel_name, std::move(ctx));
  out.data.channel_name = channel_name;
  out.data.opened = true;
  out.rcm = OK;
  return out;
}

inline ECMData<AMT::ChannelActiveResult> LocalTerminalPort::ActiveChannel(
    const AMT::ChannelActiveArgs &active_args,
    const AMDomain::client::ClientControlComponent &control) {
  (void)control;
  ECMData<AMT::ChannelActiveResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  const std::string channel_name = AMStr::Strip(active_args.channel_name);
  if (channel_name.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.active", "channel_name",
                  "channel_name is required");
    return out;
  }
  auto it = channels_.find(channel_name);
  if (it == channels_.end()) {
    out.rcm = Err(EC::InvalidArg, "terminal.active", channel_name,
                  "Target channel does not exist");
    return out;
  }
  current_channel_ = channel_name;
  out.data.channel_name = channel_name;
  out.data.activated = true;
  out.rcm = OK;
  return out;
}

inline ECMData<AMT::ChannelReadResult> LocalTerminalPort::ReadChannel(
    const AMT::ChannelReadArgs &read_args,
    const AMDomain::client::ClientControlComponent &control) {
  ECMData<AMT::ChannelReadResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  auto resolve_result = ResolveChannelForOp_(read_args.channel_name, "terminal.read");
  if (!resolve_result.rcm || resolve_result.data == nullptr) {
    out.rcm = resolve_result.rcm;
    out.data.eof = true;
    return out;
  }

  const std::string target_name = ResolveTargetChannelName_(read_args.channel_name);
  ChannelCtx_ *ctx = resolve_result.data;
  out.data.channel_name = target_name;
  const size_t max_bytes =
      (read_args.max_bytes == 0U ? static_cast<size_t>(32 * AMKB) : read_args.max_bytes);

#ifdef _WIN32
  UpdateWindowsProcessState_(ctx);
  (void)DrainWindowsOutput_(ctx, &out.data.output, max_bytes);
  if (!out.data.output.empty()) {
    out.rcm = OK;
    out.data.eof = ctx->eof;
    return out;
  }
  if (ctx->eof || ctx->process_exited) {
    ctx->eof = true;
    out.rcm = OK;
    out.data.eof = true;
    return out;
  }
  bool timed_out = false;
  const bool ready = WaitReadableWindows_(ctx, control, &timed_out);
  if (!ready) {
    if (control.IsInterrupted()) {
      out.rcm = Err(EC::Terminate, "terminal.read", target_name,
                    "Interrupted while waiting output");
    } else if (timed_out || control.IsTimeout()) {
      out.rcm = Err(EC::OperationTimeout, "terminal.read", target_name,
                    "Timed out while waiting output");
    } else {
      out.rcm = Err(EC::SocketRecvError, "terminal.read", target_name,
                    "Failed while waiting local terminal output");
    }
    out.data.eof = ctx->eof;
    return out;
  }
  UpdateWindowsProcessState_(ctx);
  (void)DrainWindowsOutput_(ctx, &out.data.output, max_bytes);
  if (ctx->process_exited && out.data.output.empty()) {
    ctx->eof = true;
  }
#else
  UpdatePosixProcessState_(ctx);
  (void)DrainPosixOutput_(ctx, &out.data.output, max_bytes);
  if (!out.data.output.empty()) {
    out.rcm = OK;
    out.data.eof = ctx->eof;
    return out;
  }
  if (ctx->eof) {
    out.rcm = OK;
    out.data.eof = true;
    return out;
  }
  bool timed_out = false;
  const bool ready = WaitReadablePosix_(ctx, control, &timed_out);
  if (!ready) {
    if (control.IsInterrupted()) {
      out.rcm = Err(EC::Terminate, "terminal.read", target_name,
                    "Interrupted while waiting output");
    } else if (timed_out || control.IsTimeout()) {
      out.rcm = Err(EC::OperationTimeout, "terminal.read", target_name,
                    "Timed out while waiting output");
    } else {
      out.rcm = Err(EC::SocketRecvError, "terminal.read", target_name,
                    "Failed while waiting local terminal output");
    }
    out.data.eof = ctx->eof;
    return out;
  }
  UpdatePosixProcessState_(ctx);
  (void)DrainPosixOutput_(ctx, &out.data.output, max_bytes);
#endif

  out.rcm = OK;
  out.data.eof = ctx->eof;
  return out;
}

inline ECMData<AMT::ChannelWriteResult> LocalTerminalPort::WriteChannel(
    const AMT::ChannelWriteArgs &write_args,
    const AMDomain::client::ClientControlComponent &control) {
  ECMData<AMT::ChannelWriteResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  auto resolve_result = ResolveChannelForOp_(write_args.channel_name, "terminal.write");
  if (!resolve_result.rcm || resolve_result.data == nullptr) {
    out.rcm = resolve_result.rcm;
    return out;
  }

  const std::string target_name = ResolveTargetChannelName_(write_args.channel_name);
  ChannelCtx_ *ctx = resolve_result.data;
  out.data.channel_name = target_name;
  if (write_args.input.empty()) {
    out.rcm = OK;
    out.data.bytes_written = 0;
    return out;
  }

#ifdef _WIN32
  UpdateWindowsProcessState_(ctx);
  if (ctx->process_exited || ctx->input_write == INVALID_HANDLE_VALUE) {
    out.rcm = Err(EC::NoConnection, "terminal.write", target_name,
                  "Interactive channel not initialized");
    return out;
  }
  size_t offset = 0;
  while (offset < write_args.input.size()) {
    if (control.IsInterrupted()) {
      out.rcm = Err(EC::Terminate, "terminal.write", target_name,
                    "Interrupted while waiting write");
      out.data.bytes_written = offset;
      return out;
    }
    if (control.IsTimeout()) {
      out.rcm = Err(EC::OperationTimeout, "terminal.write", target_name,
                    "Timed out while waiting write");
      out.data.bytes_written = offset;
      return out;
    }
    const DWORD want = static_cast<DWORD>(
        std::min<size_t>(static_cast<size_t>((std::numeric_limits<DWORD>::max)()),
                         write_args.input.size() - offset));
    DWORD wrote = 0;
    if (WriteFile(ctx->input_write, write_args.input.data() + offset, want, &wrote,
                  nullptr) == 0) {
      out.rcm = Err(EC::SocketSendError, "terminal.write", target_name,
                    "WriteFile failed for local terminal input");
      out.data.bytes_written = offset;
      return out;
    }
    if (wrote == 0) {
      out.rcm = Err(EC::SocketSendError, "terminal.write", target_name,
                    "WriteFile wrote zero bytes");
      out.data.bytes_written = offset;
      return out;
    }
    offset += static_cast<size_t>(wrote);
  }
  out.data.bytes_written = offset;
#else
  UpdatePosixProcessState_(ctx);
  if (ctx->eof || ctx->master_fd < 0) {
    out.rcm = Err(EC::NoConnection, "terminal.write", target_name,
                  "Interactive channel not initialized");
    return out;
  }
  size_t offset = 0;
  while (offset < write_args.input.size()) {
    if (control.IsInterrupted()) {
      out.rcm = Err(EC::Terminate, "terminal.write", target_name,
                    "Interrupted while waiting write");
      out.data.bytes_written = offset;
      return out;
    }
    if (control.IsTimeout()) {
      out.rcm = Err(EC::OperationTimeout, "terminal.write", target_name,
                    "Timed out while waiting write");
      out.data.bytes_written = offset;
      return out;
    }
    const ssize_t n = write(ctx->master_fd, write_args.input.data() + offset,
                            write_args.input.size() - offset);
    if (n > 0) {
      offset += static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      fd_set wfds = {};
      FD_ZERO(&wfds);
      FD_SET(ctx->master_fd, &wfds);
      timeval tv = {};
      timeval *tv_ptr = nullptr;
      const auto remain = control.RemainingTimeMs();
      if (remain.has_value()) {
        tv.tv_sec = static_cast<time_t>(*remain / 1000U);
        tv.tv_usec = static_cast<suseconds_t>((*remain % 1000U) * 1000U);
        tv_ptr = &tv;
      }
      const int rc = select(ctx->master_fd + 1, nullptr, &wfds, nullptr, tv_ptr);
      if (rc == 0) {
        out.rcm = Err(EC::OperationTimeout, "terminal.write", target_name,
                      "Timed out while waiting write");
        out.data.bytes_written = offset;
        return out;
      }
      if (rc < 0 && errno != EINTR) {
        out.rcm = Err(fec(std::error_code(errno, std::generic_category())),
                      "terminal.write", target_name, std::strerror(errno));
        out.data.bytes_written = offset;
        return out;
      }
      continue;
    }
    out.rcm = Err(fec(std::error_code(errno, std::generic_category())),
                  "terminal.write", target_name, std::strerror(errno));
    out.data.bytes_written = offset;
    return out;
  }
  out.data.bytes_written = offset;
#endif

  out.rcm = OK;
  return out;
}

inline ECMData<AMT::ChannelResizeResult> LocalTerminalPort::ResizeChannel(
    const AMT::ChannelResizeArgs &resize_args,
    const AMDomain::client::ClientControlComponent &control) {
  (void)control;
  ECMData<AMT::ChannelResizeResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  auto resolve_result = ResolveChannelForOp_(resize_args.channel_name, "terminal.resize");
  if (!resolve_result.rcm || resolve_result.data == nullptr) {
    out.rcm = resolve_result.rcm;
    return out;
  }

  const std::string target_name = ResolveTargetChannelName_(resize_args.channel_name);
  ChannelCtx_ *ctx = resolve_result.data;
  out.data.channel_name = target_name;
  ResizeWindow_(resize_args, &ctx->window);

#ifdef _WIN32
  const auto &api = ConPTYApiInstance_();
  if (!api.IsAvailable() || ctx->pseudo_console == nullptr) {
    out.rcm = Err(EC::NoConnection, "terminal.resize", target_name,
                  "Pseudo console is unavailable");
    out.data.resized = false;
    return out;
  }
  COORD size = {};
  size.X = static_cast<SHORT>(std::max(1, ctx->window.cols));
  size.Y = static_cast<SHORT>(std::max(1, ctx->window.rows));
  const HRESULT hr = api.resize(ctx->pseudo_console, size);
  if (FAILED(hr)) {
    out.rcm = Err(EC::CommonFailure, "terminal.resize", target_name,
                  AMStr::fmt("ResizePseudoConsole failed (hr=0x{:08X})",
                             static_cast<unsigned int>(hr)));
    out.data.resized = false;
    return out;
  }
#else
  if (ctx->master_fd < 0) {
    out.rcm = Err(EC::NoConnection, "terminal.resize", target_name,
                  "PTY fd is unavailable");
    out.data.resized = false;
    return out;
  }
  winsize ws = {};
  ws.ws_col = static_cast<unsigned short>(std::max(1, ctx->window.cols));
  ws.ws_row = static_cast<unsigned short>(std::max(1, ctx->window.rows));
  ws.ws_xpixel = static_cast<unsigned short>(std::max(0, ctx->window.width));
  ws.ws_ypixel = static_cast<unsigned short>(std::max(0, ctx->window.height));
  if (ioctl(ctx->master_fd, TIOCSWINSZ, &ws) != 0) {
    out.rcm = Err(fec(std::error_code(errno, std::generic_category())),
                  "terminal.resize", target_name, std::strerror(errno));
    out.data.resized = false;
    return out;
  }
#endif

  out.rcm = OK;
  out.data.resized = true;
  return out;
}

inline ECMData<AMT::ChannelCloseResult> LocalTerminalPort::CloseChannel(
    const AMT::ChannelCloseArgs &close_args,
    const AMDomain::client::ClientControlComponent &control) {
  (void)control;
  ECMData<AMT::ChannelCloseResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  const std::string target_name = ResolveTargetChannelName_(close_args.channel_name);
  if (target_name.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.close", "channel_name",
                  "No channel_name provided and no active channel set");
    return out;
  }

  auto it = channels_.find(target_name);
  if (it == channels_.end()) {
    out.rcm = Err(EC::InvalidArg, "terminal.close", target_name,
                  "Target channel does not exist");
    return out;
  }

  out.data.channel_name = target_name;
  CloseChannelRuntime_(&(it->second), close_args.force);
  out.data.exit_code = it->second.exit_status;
  channels_.erase(it);
  if (current_channel_.has_value() && *current_channel_ == target_name) {
    current_channel_ = std::nullopt;
  }
  out.data.closed = channels_.find(target_name) == channels_.end();
  out.rcm = OK;
  return out;
}

inline ECMData<AMT::ChannelRenameResult> LocalTerminalPort::RenameChannel(
    const AMT::ChannelRenameArgs &rename_args,
    const AMDomain::client::ClientControlComponent &control) {
  (void)control;
  ECMData<AMT::ChannelRenameResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  const std::string src_name = AMStr::Strip(rename_args.src_channel_name);
  const std::string dst_name = AMStr::Strip(rename_args.dst_channel_name);
  out.data.src_channel_name = src_name;
  out.data.dst_channel_name = dst_name;
  if (src_name.empty() || dst_name.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.rename", "channel_name",
                  "src_channel_name and dst_channel_name must be non-empty");
    return out;
  }
  if (!AMDomain::host::HostService::ValidateNickname(src_name) ||
      !AMDomain::host::HostService::ValidateNickname(dst_name)) {
    out.rcm = Err(EC::InvalidArg, "terminal.rename", src_name + "->" + dst_name,
                  "Channel names must be valid nicknames");
    return out;
  }
  if (src_name == dst_name) {
    out.rcm = OK;
    out.data.renamed = true;
    return out;
  }

  auto src_it = channels_.find(src_name);
  if (src_it == channels_.end()) {
    out.rcm = Err(EC::ClientNotFound, "terminal.rename", src_name,
                  "Source channel does not exist");
    return out;
  }
  if (channels_.find(dst_name) != channels_.end()) {
    out.rcm = Err(EC::TargetAlreadyExists, "terminal.rename", dst_name,
                  "Target channel already exists");
    return out;
  }

  channels_.emplace(dst_name, std::move(src_it->second));
  channels_.erase(src_it);
  if (current_channel_.has_value() && *current_channel_ == src_name) {
    current_channel_ = dst_name;
  }
  out.rcm = OK;
  out.data.renamed = true;
  return out;
}

inline ECMData<AMT::ChannelListResult> LocalTerminalPort::ListChannels(
    const AMT::ChannelListArgs &list_args,
    const AMDomain::client::ClientControlComponent &control) {
  (void)list_args;
  (void)control;
  ECMData<AMT::ChannelListResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};
  for (const auto &entry : channels_) {
    out.data.channel_names.push_back(entry.first);
  }
  if (current_channel_.has_value()) {
    out.data.current_channel = *current_channel_;
  }
  out.rcm = OK;
  return out;
}

inline ECMData<AMT::CheckSessionResult> LocalTerminalPort::CheckSession(
    const AMT::CheckSessionArgs &check_args,
    const AMDomain::client::ClientControlComponent &control) {
  (void)check_args;
  (void)control;
  ECMData<AMT::CheckSessionResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  out.data.is_supported = true;
  out.data.can_resize = true;
  if (current_channel_.has_value()) {
    out.data.current_channel = *current_channel_;
  }
  if (!owner_client_) {
    out.rcm = Err(EC::InvalidHandle, "terminal.check_session", request_.nickname,
                  "Client handle is null");
    out.data.status = AMDomain::client::ClientStatus::NotInitialized;
    return out;
  }

  const auto state = owner_client_->ConfigPort().GetState();
  if (!state.rcm) {
    out.rcm = state.rcm;
    out.data.status = state.data.status;
    return out;
  }
  out.data.status = state.data.status;
  if (current_channel_.has_value()) {
    auto it = channels_.find(*current_channel_);
    out.data.is_open = (it != channels_.end()) && !it->second.eof;
  } else {
    out.data.is_open = false;
  }
  out.rcm = OK;
  return out;
}

inline ECMData<AMT::ChannelCheckResult> LocalTerminalPort::CheckChannel(
    const AMT::ChannelCheckArgs &check_args,
    const AMDomain::client::ClientControlComponent &control) {
  (void)control;
  ECMData<AMT::ChannelCheckResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  const std::string target_name = ResolveTargetChannelName_(check_args.channel_name);
  if (target_name.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.check_channel", "channel_name",
                  "No channel_name provided and no active channel set");
    return out;
  }

  out.data.channel_name = target_name;
  auto it = channels_.find(target_name);
  if (it == channels_.end()) {
    out.rcm = Err(EC::ClientNotFound, "terminal.check_channel", target_name,
                  "Target channel does not exist");
    return out;
  }
#ifdef _WIN32
  UpdateWindowsProcessState_(&(it->second));
#else
  UpdatePosixProcessState_(&(it->second));
#endif
  out.data.exists = true;
  out.data.is_open = !it->second.eof;
  out.data.is_active =
      current_channel_.has_value() && (*current_channel_ == target_name);
  out.rcm = OK;
  return out;
}

inline AMDomain::filesystem::CheckResult
LocalTerminalPort::GetSessionState() const {
  auto guard = const_cast<AMAtomic<TerminalStateCache_> &>(attr_cache_).lock();
  return (*guard).session_state;
}

inline std::optional<ECM>
LocalTerminalPort::GetChannelState(const std::string &channel_name) const {
  auto guard = const_cast<AMAtomic<TerminalStateCache_> &>(attr_cache_).lock();
  std::string target_name = AMStr::Strip(channel_name);
  if (target_name.empty() && (*guard).current_channel.has_value()) {
    target_name = *(*guard).current_channel;
  }
  if (target_name.empty()) {
    return std::nullopt;
  }
  auto it = (*guard).channel_states.find(target_name);
  if (it == (*guard).channel_states.end()) {
    return std::nullopt;
  }
  return it->second;
}

inline std::vector<std::string> LocalTerminalPort::GetCachedChannelNames() const {
  auto guard = const_cast<AMAtomic<TerminalStateCache_> &>(attr_cache_).lock();
  std::vector<std::string> names = {};
  names.reserve((*guard).channel_states.size());
  for (const auto &entry : (*guard).channel_states) {
    names.push_back(entry.first);
  }
  return names;
}

inline ECMData<std::intptr_t> LocalTerminalPort::GetRemoteSocketHandle() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  const std::string target_name =
      ResolveTargetChannelName_(std::optional<std::string>(std::nullopt));
  if (target_name.empty()) {
    return {static_cast<std::intptr_t>(-1),
            Err(EC::NoConnection, "terminal.remote_socket", request_.nickname,
                "No active channel available")};
  }
  auto it = channels_.find(target_name);
  if (it == channels_.end()) {
    return {static_cast<std::intptr_t>(-1),
            Err(EC::NoConnection, "terminal.remote_socket", request_.nickname,
                "Active channel not found")};
  }
#ifdef _WIN32
  if (it->second.output_read == INVALID_HANDLE_VALUE) {
    return {static_cast<std::intptr_t>(-1),
            Err(EC::NoConnection, "terminal.remote_socket", request_.nickname,
                "Channel output handle is unavailable")};
  }
  return {
      static_cast<std::intptr_t>(reinterpret_cast<std::intptr_t>(it->second.output_read)),
      OK};
#else
  if (it->second.master_fd < 0) {
    return {static_cast<std::intptr_t>(-1),
            Err(EC::NoConnection, "terminal.remote_socket", request_.nickname,
                "Channel PTY fd is unavailable")};
  }
  return {static_cast<std::intptr_t>(it->second.master_fd), OK};
#endif
}

#ifdef _WIN32
inline LocalTerminalPort::ConPTYApi_::ConPTYApi_() {
  kernel = GetModuleHandleW(L"kernel32.dll");
  if (kernel == nullptr) {
    return;
  }
  create = reinterpret_cast<CreatePseudoConsoleFn>(
      GetProcAddress(kernel, "CreatePseudoConsole"));
  resize = reinterpret_cast<ResizePseudoConsoleFn>(
      GetProcAddress(kernel, "ResizePseudoConsole"));
  close = reinterpret_cast<ClosePseudoConsoleFn>(
      GetProcAddress(kernel, "ClosePseudoConsole"));
}

inline bool LocalTerminalPort::ConPTYApi_::IsAvailable() const {
  return create != nullptr && resize != nullptr && close != nullptr;
}

inline const LocalTerminalPort::ConPTYApi_ &
LocalTerminalPort::ConPTYApiInstance_() {
  static const ConPTYApi_ api = {};
  return api;
}

inline void LocalTerminalPort::CloseHandleSafe_(HANDLE *handle) {
  if (handle != nullptr && *handle != nullptr && *handle != INVALID_HANDLE_VALUE) {
    (void)CloseHandle(*handle);
    *handle = INVALID_HANDLE_VALUE;
  }
}

inline void LocalTerminalPort::ClosePseudoConsoleSafe_(void **pseudo_console) {
  if (pseudo_console == nullptr || *pseudo_console == nullptr) {
    return;
  }
  const auto &api = ConPTYApiInstance_();
  if (api.close != nullptr) {
    api.close(*pseudo_console);
  }
  *pseudo_console = nullptr;
}

inline void LocalTerminalPort::UpdateWindowsProcessState_(ChannelCtx_ *ctx) {
  if (ctx == nullptr || ctx->process_handle == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD code = STILL_ACTIVE;
  if (GetExitCodeProcess(ctx->process_handle, &code) == 0) {
    return;
  }
  if (code != STILL_ACTIVE) {
    ctx->process_exited = true;
    ctx->exit_status = static_cast<int>(code);
  }
}

inline bool LocalTerminalPort::DrainWindowsOutput_(ChannelCtx_ *ctx,
                                                   std::string *output,
                                                   size_t max_bytes) {
  if (ctx == nullptr || output == nullptr || ctx->output_read == INVALID_HANDLE_VALUE ||
      max_bytes == 0U) {
    return false;
  }
  bool wrote = false;
  std::array<char, 4096> buffer = {};
  while (output->size() < max_bytes) {
    DWORD available = 0;
    if (PeekNamedPipe(ctx->output_read, nullptr, 0, nullptr, &available,
                      nullptr) == 0) {
      ctx->eof = true;
      break;
    }
    if (available == 0) {
      break;
    }
    const DWORD want = static_cast<DWORD>(std::min<size_t>(
        static_cast<size_t>(available),
        std::min<size_t>(buffer.size(), max_bytes - output->size())));
    DWORD nread = 0;
    if (ReadFile(ctx->output_read, buffer.data(), want, &nread, nullptr) == 0) {
      ctx->eof = true;
      break;
    }
    if (nread == 0) {
      break;
    }
    output->append(buffer.data(), static_cast<size_t>(nread));
    wrote = true;
  }
  return wrote;
}

inline bool LocalTerminalPort::WaitReadableWindows_(
    ChannelCtx_ *ctx, const AMDomain::client::ClientControlComponent &control,
    bool *timed_out) {
  if (timed_out != nullptr) {
    *timed_out = false;
  }
  if (ctx == nullptr) {
    if (timed_out != nullptr) {
      *timed_out = true;
    }
    return false;
  }
  auto deadline = std::chrono::steady_clock::time_point::max();
  const auto remain_opt = control.RemainingTimeMs();
  if (remain_opt.has_value()) {
    deadline = std::chrono::steady_clock::now() +
               std::chrono::milliseconds(*remain_opt);
  }

  while (true) {
    if (control.IsInterrupted()) {
      return false;
    }
    if (control.IsTimeout()) {
      if (timed_out != nullptr) {
        *timed_out = true;
      }
      return false;
    }

    std::array<HANDLE, 2> handles = {ctx->output_read, ctx->process_handle};
    DWORD count = 0;
    if (ctx->output_read != INVALID_HANDLE_VALUE) {
      handles[count++] = ctx->output_read;
    }
    if (ctx->process_handle != INVALID_HANDLE_VALUE) {
      handles[count++] = ctx->process_handle;
    }
    if (count == 0) {
      if (timed_out != nullptr) {
        *timed_out = true;
      }
      return false;
    }

    DWORD slice = 100;
    if (deadline != std::chrono::steady_clock::time_point::max()) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        if (timed_out != nullptr) {
          *timed_out = true;
        }
        return false;
      }
      const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - now);
      slice = static_cast<DWORD>(std::min<int64_t>(
          static_cast<int64_t>(slice), std::max<int64_t>(1, remain.count())));
    }

    const DWORD wait_rc =
        WaitForMultipleObjects(count, handles.data(), FALSE, slice);
    if (wait_rc == WAIT_TIMEOUT) {
      continue;
    }
    if (wait_rc >= WAIT_OBJECT_0 && wait_rc < WAIT_OBJECT_0 + count) {
      return true;
    }
    if (wait_rc == WAIT_FAILED) {
      return false;
    }
  }
}

inline ECM LocalTerminalPort::OpenOneChannelWindows_(
    ChannelCtx_ *ctx, const AMT::ChannelOpenArgs &open_args) {
  if (ctx == nullptr) {
    return Err(EC::InvalidArg, "terminal.open", "channel", "Channel is null");
  }
  const auto &api = ConPTYApiInstance_();
  if (!api.IsAvailable()) {
    return Err(EC::OperationUnsupported, "terminal.open", "conpty",
               "ConPTY API is unavailable on current Windows runtime");
  }

  SECURITY_ATTRIBUTES sa = {};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = nullptr;

  HANDLE input_read = INVALID_HANDLE_VALUE;
  HANDLE input_write = INVALID_HANDLE_VALUE;
  HANDLE output_read = INVALID_HANDLE_VALUE;
  HANDLE output_write = INVALID_HANDLE_VALUE;
  if (CreatePipe(&input_read, &input_write, &sa, 0) == 0) {
    return Err(EC::CommonFailure, "terminal.open", "conpty",
               "CreatePipe failed for terminal input");
  }
  if (CreatePipe(&output_read, &output_write, &sa, 0) == 0) {
    CloseHandleSafe_(&input_read);
    CloseHandleSafe_(&input_write);
    return Err(EC::CommonFailure, "terminal.open", "conpty",
               "CreatePipe failed for terminal output");
  }
  (void)SetHandleInformation(input_write, HANDLE_FLAG_INHERIT, 0);
  (void)SetHandleInformation(output_read, HANDLE_FLAG_INHERIT, 0);

  COORD size = {};
  size.X = static_cast<SHORT>(std::max(1, open_args.cols));
  size.Y = static_cast<SHORT>(std::max(1, open_args.rows));

  void *pseudo_console = nullptr;
  const HRESULT create_hr =
      api.create(size, input_read, output_write, 0, &pseudo_console);
  CloseHandleSafe_(&input_read);
  CloseHandleSafe_(&output_write);
  if (FAILED(create_hr) || pseudo_console == nullptr) {
    CloseHandleSafe_(&input_write);
    CloseHandleSafe_(&output_read);
    return Err(EC::OperationUnsupported, "terminal.open", "conpty",
               AMStr::fmt("CreatePseudoConsole failed (hr=0x{:08X})",
                          static_cast<unsigned int>(create_hr)));
  }

  SIZE_T attr_size = 0;
  (void)InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
  std::vector<char> attr_buffer(attr_size);
  auto *attr_list =
      reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attr_buffer.data());
  if (InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size) == 0) {
    ClosePseudoConsoleSafe_(&pseudo_console);
    CloseHandleSafe_(&input_write);
    CloseHandleSafe_(&output_read);
    return Err(EC::CommonFailure, "terminal.open", "conpty",
               "InitializeProcThreadAttributeList failed");
  }

  const BOOL update_ok = UpdateProcThreadAttribute(
      attr_list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, pseudo_console,
      sizeof(pseudo_console), nullptr, nullptr);
  if (update_ok == 0) {
    DeleteProcThreadAttributeList(attr_list);
    ClosePseudoConsoleSafe_(&pseudo_console);
    CloseHandleSafe_(&input_write);
    CloseHandleSafe_(&output_read);
    return Err(EC::CommonFailure, "terminal.open", "conpty",
               "UpdateProcThreadAttribute failed");
  }

  STARTUPINFOEXW startup = {};
  startup.StartupInfo.cb = sizeof(STARTUPINFOEXW);
  startup.lpAttributeList = attr_list;
  PROCESS_INFORMATION proc = {};
  std::wstring cmd = L"cmd.exe";
  const BOOL created =
      CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                     EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                     &startup.StartupInfo, &proc);
  DeleteProcThreadAttributeList(attr_list);
  if (created == 0) {
    ClosePseudoConsoleSafe_(&pseudo_console);
    CloseHandleSafe_(&input_write);
    CloseHandleSafe_(&output_read);
    return Err(EC::CommonFailure, "terminal.open", "cmd.exe",
               "CreateProcessW failed");
  }

  CloseHandleSafe_(&proc.hThread);
  ctx->pseudo_console = pseudo_console;
  ctx->input_write = input_write;
  ctx->output_read = output_read;
  ctx->process_handle = proc.hProcess;
  ctx->process_exited = false;
  ctx->eof = false;
  ctx->exit_status = -1;
  return OK;
}
#else
inline void LocalTerminalPort::UpdatePosixProcessState_(ChannelCtx_ *ctx) {
  if (ctx == nullptr || ctx->child_pid <= 0 || ctx->process_exited) {
    return;
  }
  int status = 0;
  const pid_t rc = waitpid(ctx->child_pid, &status, WNOHANG);
  if (rc != ctx->child_pid) {
    return;
  }
  ctx->process_exited = true;
  if (WIFEXITED(status)) {
    ctx->exit_status = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    ctx->exit_status = 128 + WTERMSIG(status);
  } else {
    ctx->exit_status = -1;
  }
  ctx->child_pid = -1;
}

inline bool LocalTerminalPort::DrainPosixOutput_(ChannelCtx_ *ctx,
                                                 std::string *output,
                                                 size_t max_bytes) {
  if (ctx == nullptr || output == nullptr || ctx->master_fd < 0 || max_bytes == 0U) {
    return false;
  }
  bool wrote = false;
  std::array<char, 4096> buffer = {};
  while (output->size() < max_bytes) {
    const size_t cap = std::min<size_t>(buffer.size(), max_bytes - output->size());
    const ssize_t n = read(ctx->master_fd, buffer.data(), cap);
    if (n > 0) {
      output->append(buffer.data(), static_cast<size_t>(n));
      wrote = true;
      continue;
    }
    if (n == 0) {
      ctx->eof = true;
    }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      ctx->eof = true;
    }
    break;
  }
  return wrote;
}

inline bool LocalTerminalPort::WaitReadablePosix_(
    ChannelCtx_ *ctx, const AMDomain::client::ClientControlComponent &control,
    bool *timed_out) {
  if (timed_out != nullptr) {
    *timed_out = false;
  }
  if (ctx == nullptr || ctx->master_fd < 0) {
    if (timed_out != nullptr) {
      *timed_out = true;
    }
    return false;
  }
  auto deadline = std::chrono::steady_clock::time_point::max();
  const auto remain_opt = control.RemainingTimeMs();
  if (remain_opt.has_value()) {
    deadline = std::chrono::steady_clock::now() +
               std::chrono::milliseconds(*remain_opt);
  }

  while (true) {
    if (control.IsInterrupted()) {
      return false;
    }
    if (control.IsTimeout()) {
      if (timed_out != nullptr) {
        *timed_out = true;
      }
      return false;
    }
    fd_set readfds = {};
    FD_ZERO(&readfds);
    FD_SET(ctx->master_fd, &readfds);
    timeval tv = {};
    timeval *tv_ptr = nullptr;
    if (deadline != std::chrono::steady_clock::time_point::max()) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        if (timed_out != nullptr) {
          *timed_out = true;
        }
        return false;
      }
      const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - now);
      tv.tv_sec = static_cast<time_t>(remain.count() / 1000);
      tv.tv_usec = static_cast<suseconds_t>((remain.count() % 1000) * 1000);
      tv_ptr = &tv;
    }
    const int rc = select(ctx->master_fd + 1, &readfds, nullptr, nullptr, tv_ptr);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (rc == 0) {
      if (timed_out != nullptr) {
        *timed_out = true;
      }
      return false;
    }
    return true;
  }
}

inline ECM LocalTerminalPort::OpenOneChannelPosix_(
    ChannelCtx_ *ctx, const AMT::ChannelOpenArgs &open_args) {
  if (ctx == nullptr) {
    return Err(EC::InvalidArg, "terminal.open", "channel", "Channel is null");
  }
  winsize ws = {};
  ws.ws_col = static_cast<unsigned short>(std::max(1, open_args.cols));
  ws.ws_row = static_cast<unsigned short>(std::max(1, open_args.rows));
  ws.ws_xpixel = static_cast<unsigned short>(std::max(0, open_args.width));
  ws.ws_ypixel = static_cast<unsigned short>(std::max(0, open_args.height));
  int master_fd = -1;
  const pid_t pid = forkpty(&master_fd, nullptr, nullptr, &ws);
  if (pid < 0) {
    return Err(fec(std::error_code(errno, std::generic_category())),
               "terminal.open", "/bin/sh", std::strerror(errno));
  }
  if (pid == 0) {
    execl("/bin/sh", "sh", static_cast<char *>(nullptr));
    _exit(127);
  }
  const int flags = fcntl(master_fd, F_GETFL, 0);
  if (flags >= 0) {
    (void)fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
  }
  ctx->master_fd = master_fd;
  ctx->child_pid = pid;
  ctx->process_exited = false;
  ctx->eof = false;
  ctx->exit_status = -1;
  return OK;
}
#endif

inline void LocalTerminalPort::CloseChannelRuntime_(ChannelCtx_ *ctx, bool force) {
  if (ctx == nullptr) {
    return;
  }
#ifdef _WIN32
  UpdateWindowsProcessState_(ctx);
  if (!ctx->process_exited && ctx->process_handle != INVALID_HANDLE_VALUE) {
    if (!force && ctx->input_write != INVALID_HANDLE_VALUE) {
      const std::string exit_cmd = "exit\r\n";
      DWORD wrote = 0;
      (void)WriteFile(ctx->input_write, exit_cmd.data(),
                      static_cast<DWORD>(exit_cmd.size()), &wrote, nullptr);
    }
    DWORD wait_rc = WaitForSingleObject(ctx->process_handle, force ? 10 : 300);
    if (wait_rc == WAIT_TIMEOUT) {
      (void)TerminateProcess(ctx->process_handle, 1);
      (void)WaitForSingleObject(ctx->process_handle, 300);
    }
  }
  UpdateWindowsProcessState_(ctx);
  CloseHandleSafe_(&ctx->input_write);
  CloseHandleSafe_(&ctx->output_read);
  CloseHandleSafe_(&ctx->process_handle);
  ClosePseudoConsoleSafe_(&ctx->pseudo_console);
#else
  UpdatePosixProcessState_(ctx);
  if (!ctx->process_exited && ctx->child_pid > 0) {
    if (!force && ctx->master_fd >= 0) {
      const std::string exit_cmd = "exit\n";
      (void)write(ctx->master_fd, exit_cmd.data(), exit_cmd.size());
    }
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(force ? 20 : 300);
    while (std::chrono::steady_clock::now() < deadline) {
      UpdatePosixProcessState_(ctx);
      if (ctx->process_exited) {
        break;
      }
      usleep(10000);
    }
    if (!ctx->process_exited && ctx->child_pid > 0) {
      (void)kill(ctx->child_pid, force ? SIGKILL : SIGTERM);
      const auto kill_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::milliseconds(300);
      while (std::chrono::steady_clock::now() < kill_deadline) {
        UpdatePosixProcessState_(ctx);
        if (ctx->process_exited) {
          break;
        }
        usleep(10000);
      }
    }
    if (!ctx->process_exited && ctx->child_pid > 0) {
      (void)kill(ctx->child_pid, SIGKILL);
      UpdatePosixProcessState_(ctx);
    }
  }
  if (ctx->master_fd >= 0) {
    (void)close(ctx->master_fd);
    ctx->master_fd = -1;
  }
#endif
  ctx->eof = true;
}

} // namespace AMInfra::client::LOCAL::terminal

