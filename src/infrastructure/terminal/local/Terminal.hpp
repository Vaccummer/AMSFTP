#pragma once

#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/client/local/Local.hpp"
#include "infrastructure/terminal/ChannelCachePort.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
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

  struct ChannelRuntime_ {
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
  std::map<std::string, ChannelRuntime_> channel_runtimes_ = {};
  std::map<std::string, AMT::ChannelPortHandle> channels_ = {};
  std::optional<std::string> current_channel_ = std::nullopt;

#ifdef _WIN32
  struct ConPTYApi_ {
    using CreatePseudoConsoleFn = HRESULT(WINAPI *)(COORD, HANDLE, HANDLE,
                                                    DWORD, void **);
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
  static void UpdateWindowsProcessState_(ChannelRuntime_ *ctx);
  static bool DrainWindowsOutput_(ChannelRuntime_ *ctx, std::string *output,
                                  size_t max_bytes);
  static bool
  WaitReadableWindows_(ChannelRuntime_ *ctx,
                       const AMDomain::client::ClientControlComponent &control,
                       bool *timed_out);
  static ECM OpenOneChannelWindows_(ChannelRuntime_ *ctx,
                                    const AMT::ChannelOpenArgs &open_args);
#else
  static void UpdatePosixProcessState_(ChannelRuntime_ *ctx);
  static bool DrainPosixOutput_(ChannelRuntime_ *ctx, std::string *output,
                                size_t max_bytes);
  static bool
  WaitReadablePosix_(ChannelRuntime_ *ctx,
                     const AMDomain::client::ClientControlComponent &control,
                     bool *timed_out);
  static ECM OpenOneChannelPosix_(ChannelRuntime_ *ctx,
                                  const AMT::ChannelOpenArgs &open_args);
#endif

  [[nodiscard]] static TerminalWindowInfo_
  OpenWindow_(const AMT::ChannelOpenArgs &open_args,
              const TerminalWindowInfo_ &fallback);
  static void ResizeWindow_(const AMT::ChannelResizeArgs &resize_args,
                            TerminalWindowInfo_ *window);
  [[nodiscard]] static std::string
  ResolveTargetChannelName_(const std::optional<std::string> &requested_name,
                            const std::optional<std::string> &current_channel);
  [[nodiscard]] std::string ResolveTargetChannelName_(
      const std::optional<std::string> &requested_name) const;
  [[nodiscard]] std::string
  ResolveTargetChannelName_(const std::string &requested_name) const;
  [[nodiscard]] ECMData<ChannelRuntime_ *>
  ResolveChannelForOp_(const std::optional<std::string> &requested_name,
                       const char *action_name);
  [[nodiscard]] ECM
  ValidateSessionReady_(const AMDomain::client::ClientControlComponent &control,
                        const char *action) const;
  void CloseChannelRuntime_(ChannelRuntime_ *ctx, bool force);

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

  ECMData<AMT::ChannelActiveResult> ActiveChannel(
      const AMT::ChannelActiveArgs &active_args,
      const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelPortHandle> GetChannelPort(
      const std::optional<std::string> &channel_name,
      const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelReadResult> ReadChannel(
      const AMT::ChannelReadArgs &read_args,
      const AMDomain::client::ClientControlComponent &control,
      const std::optional<std::string> &bound_channel_name = std::nullopt);

  ECMData<AMT::ChannelWriteResult> WriteChannel(
      const AMT::ChannelWriteArgs &write_args,
      const AMDomain::client::ClientControlComponent &control,
      const std::optional<std::string> &bound_channel_name = std::nullopt);

  ECMData<AMT::ChannelResizeResult> ResizeChannel(
      const AMT::ChannelResizeArgs &resize_args,
      const AMDomain::client::ClientControlComponent &control,
      const std::optional<std::string> &bound_channel_name = std::nullopt);

  ECMData<AMT::ChannelCloseResult> CloseChannel(
      const AMT::ChannelCloseArgs &close_args,
      const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelRenameResult> RenameChannel(
      const AMT::ChannelRenameArgs &rename_args,
      const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelListResult> ListChannels(
      const AMT::ChannelListArgs &list_args,
      const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::CheckSessionResult> CheckSession(
      const AMT::CheckSessionArgs &check_args,
      const AMDomain::client::ClientControlComponent &control) override;

  ECMData<AMT::ChannelCheckResult> CheckChannel(
      const AMT::ChannelCheckArgs &check_args,
      const AMDomain::client::ClientControlComponent &control) override;

  [[nodiscard]] AMDomain::filesystem::CheckResult
  GetSessionState() const override;

  [[nodiscard]] std::optional<ECM>
  GetChannelState(const std::string &channel_name) const override;

  [[nodiscard]] std::vector<std::string> GetCachedChannelNames() const override;

  [[nodiscard]] ECMData<std::intptr_t>
  GetChannelWaitHandle(const std::optional<std::string> &channel_name) const;

  [[nodiscard]] ECMData<std::intptr_t> GetRemoteSocketHandle() const;
};

class LocalChannelPort final : public AMT::IChannelPort {
public:
  using ClientControlComponent = AMDomain::client::ClientControlComponent;

  LocalChannelPort(std::string terminal_key, std::string channel_name,
                   LocalTerminalPort *owner)
      : terminal_key_(std::move(terminal_key)),
        channel_name_(std::move(channel_name)), owner_(owner),
        cache_(channel_name_) {}

  ~LocalChannelPort() override = default;

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
           const ClientControlComponent &control = {}) override {
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
              const ClientControlComponent &control = {}) override {
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
           const ClientControlComponent &control = {}) override {
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
         const ClientControlComponent &control = {}) override {
    if (owner_ == nullptr) {
      return {AMT::ChannelResizeResult{},
              Err(EC::InvalidHandle, "terminal.channel.resize", channel_name_,
                  "Local channel owner is null")};
    }
    return owner_->ResizeChannel(resize_args, control,
                                 std::optional<std::string>(channel_name_));
  }

  [[nodiscard]] ECMData<AMT::ChannelCloseResult>
  Close(bool force, const ClientControlComponent &control = {}) override {
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
    closed_ = true;
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
    return Err(EC::OperationUnsupported, "terminal.channel.loop.start",
               channel_name_,
               "Realtime loop is unsupported for local channels");
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheReplayResult>
  BindForeground(const AMT::ChannelForegroundBindArgs &bind_args) override {
    if (!bind_args.processor) {
      return {AMT::ChannelCacheReplayResult{},
              Err(EC::InvalidArg, "terminal.channel.bind", channel_name_,
                  "Foreground output processor is empty")};
    }
    auto result = AttachConsumer(bind_args.processor);
    if (result.rcm) {
      foreground_bound_ = true;
      detach_requested_ = false;
    }
    return result;
  }

  ECM UnbindForeground() override {
    foreground_bound_ = false;
    detach_requested_ = false;
    return DetachConsumer();
  }

  ECM RequestForegroundDetach() override {
    foreground_bound_ = false;
    detach_requested_ = true;
    return DetachConsumer();
  }

  [[nodiscard]] AMT::ChannelLoopState GetLoopState() const override {
    AMT::ChannelLoopState state = {};
    AMT::ChannelPortState const port_state = GetState();
    state.loop_running = false;
    state.foreground_bound = foreground_bound_;
    state.closed = port_state.closed;
    state.detach_requested = detach_requested_;
    state.state_wait_handle = -1;
    state.last_error = port_state.last_error;
    state.has_error = !(state.last_error);
    return state;
  }

private:
  std::string terminal_key_ = {};
  std::string channel_name_ = {};
  LocalTerminalPort *owner_ = nullptr;
  AMInfra::terminal::ChannelCacheStore cache_;
  bool foreground_bound_ = false;
  bool detach_requested_ = false;
  bool closed_ = false;
};

inline LocalTerminalPort::~LocalTerminalPort() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  for (auto &entry : channel_runtimes_) {
    CloseChannelRuntime_(&(entry.second), true);
  }
  channel_runtimes_.clear();
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
  for (const auto &entry : channel_runtimes_) {
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

inline std::string LocalTerminalPort::ResolveTargetChannelName_(
    const std::string &requested_name) const {
  return ResolveTargetChannelName_(std::optional<std::string>(requested_name),
                                   current_channel_);
}

inline ECMData<LocalTerminalPort::ChannelRuntime_ *>
LocalTerminalPort::ResolveChannelForOp_(
    const std::optional<std::string> &requested_name, const char *action_name) {
  const std::string target_name = ResolveTargetChannelName_(requested_name);
  if (target_name.empty()) {
    return {nullptr, Err(EC::InvalidArg, action_name, "channel_name",
                         "No channel_name provided and no active channel set")};
  }
  auto it = channel_runtimes_.find(target_name);
  if (it == channel_runtimes_.end()) {
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
  if (channel_runtimes_.contains(channel_name)) {
    out.rcm = Err(EC::TargetAlreadyExists, "terminal.open", channel_name,
                  "Channel name already exists");
    return out;
  }
  out.rcm = ValidateSessionReady_(control, "terminal.open");
  if (!out.rcm) {
    return out;
  }

  ChannelRuntime_ ctx = {};
  ctx.window = OpenWindow_(open_args, ctx.window);
#ifdef _WIN32
  out.rcm = OpenOneChannelWindows_(&ctx, open_args);
#else
  out.rcm = OpenOneChannelPosix_(&ctx, open_args);
#endif
  if (!out.rcm) {
    return out;
  }

  channel_runtimes_.emplace(channel_name, std::move(ctx));
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
  auto it = channel_runtimes_.find(channel_name);
  if (it == channel_runtimes_.end()) {
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

inline ECMData<AMT::ChannelPortHandle> LocalTerminalPort::GetChannelPort(
    const std::optional<std::string> &channel_name,
    const AMDomain::client::ClientControlComponent &control) {
  (void)control;
  ECMData<AMT::ChannelPortHandle> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  const std::string target_name = ResolveTargetChannelName_(channel_name);
  if (target_name.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.channel_port", "channel_name",
                  "No channel_name provided and no active channel set");
    return out;
  }

  auto channel_it = channel_runtimes_.find(target_name);
  if (channel_it == channel_runtimes_.end()) {
    out.rcm = Err(EC::ClientNotFound, "terminal.channel_port", target_name,
                  "Target channel does not exist");
    return out;
  }

  auto port_it = channels_.find(target_name);
  if (port_it != channels_.end() && port_it->second) {
    out.data = port_it->second;
    out.rcm = OK;
    return out;
  }

  const std::string terminal_key =
      AMDomain::host::HostService::NormalizeNickname(request_.nickname);
  auto port =
      std::make_shared<LocalChannelPort>(terminal_key, target_name, this);
  if (!port) {
    out.rcm = Err(EC::InvalidHandle, "terminal.channel_port", target_name,
                  "Failed to create channel port");
    return out;
  }

  channels_[target_name] = port;
  out.data = std::move(port);
  out.rcm = OK;
  return out;
}

inline ECMData<AMT::ChannelReadResult> LocalTerminalPort::ReadChannel(
    const AMT::ChannelReadArgs &read_args,
    const AMDomain::client::ClientControlComponent &control,
    const std::optional<std::string> &bound_channel_name) {
  ECMData<AMT::ChannelReadResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  auto channel_result =
      ResolveChannelForOp_(bound_channel_name, "terminal.channel.read");
  if (!(channel_result.rcm) || channel_result.data == nullptr) {
    out.rcm = channel_result.rcm;
    out.data.eof = true;
    return out;
  }

  ChannelRuntime_ *ctx = channel_result.data;
  const std::string target_name = ResolveTargetChannelName_(bound_channel_name);
  out.data.channel_name = target_name;

  if (control.IsInterrupted()) {
    out.rcm = Err(EC::Terminate, "terminal.channel.read", target_name,
                  "Interrupted by user");
    out.data.eof = true;
    return out;
  }
  if (control.IsTimeout()) {
    out.rcm = Err(EC::OperationTimeout, "terminal.channel.read", target_name,
                  "Operation timed out");
    out.data.eof = true;
    return out;
  }

#ifdef _WIN32
  UpdateWindowsProcessState_(ctx);
#else
  UpdatePosixProcessState_(ctx);
#endif
  if (ctx->process_exited) {
    ctx->eof = true;
  }

  size_t const max_bytes =
      (read_args.max_bytes == 0U ? static_cast<size_t>(32U * AMKB)
                                 : read_args.max_bytes);
#ifdef _WIN32
  bool wrote = DrainWindowsOutput_(ctx, &(out.data.output), max_bytes);
#else
  bool wrote = DrainPosixOutput_(ctx, &(out.data.output), max_bytes);
#endif
  if (!wrote && !ctx->eof && control.RemainingTimeMs().has_value()) {
    bool timed_out = false;
#ifdef _WIN32
    bool const wait_ok = WaitReadableWindows_(ctx, control, &timed_out);
#else
    bool const wait_ok = WaitReadablePosix_(ctx, control, &timed_out);
#endif
    if (!wait_ok) {
      if (control.IsInterrupted()) {
        out.rcm = Err(EC::Terminate, "terminal.channel.read", target_name,
                      "Interrupted while waiting terminal output");
      } else if (timed_out || control.IsTimeout()) {
        out.rcm = Err(EC::OperationTimeout, "terminal.channel.read",
                      target_name, "Timed out while waiting terminal output");
      } else if (ctx->eof || ctx->process_exited) {
        out.rcm = OK;
      } else {
        out.rcm = Err(EC::NoConnection, "terminal.channel.read", target_name,
                      "Failed while waiting terminal output");
      }
      out.data.eof = ctx->eof || ctx->process_exited;
      return out;
    }
#ifdef _WIN32
    (void)DrainWindowsOutput_(ctx, &(out.data.output), max_bytes);
#else
    (void)DrainPosixOutput_(ctx, &(out.data.output), max_bytes);
#endif
  }

#ifdef _WIN32
  UpdateWindowsProcessState_(ctx);
#else
  UpdatePosixProcessState_(ctx);
#endif
  if (ctx->process_exited) {
    ctx->eof = true;
  }
  out.data.eof = ctx->eof;
  out.rcm = OK;
  return out;
}

inline ECMData<AMT::ChannelWriteResult> LocalTerminalPort::WriteChannel(
    const AMT::ChannelWriteArgs &write_args,
    const AMDomain::client::ClientControlComponent &control,
    const std::optional<std::string> &bound_channel_name) {
  ECMData<AMT::ChannelWriteResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  auto channel_result =
      ResolveChannelForOp_(bound_channel_name, "terminal.channel.write");
  if (!(channel_result.rcm) || channel_result.data == nullptr) {
    out.rcm = channel_result.rcm;
    return out;
  }

  ChannelRuntime_ *ctx = channel_result.data;
  const std::string target_name = ResolveTargetChannelName_(bound_channel_name);
  out.data.channel_name = target_name;
  out.data.bytes_written = 0U;

  if (write_args.input.empty()) {
    out.rcm = OK;
    return out;
  }
  if (control.IsInterrupted()) {
    out.rcm = Err(EC::Terminate, "terminal.channel.write", target_name,
                  "Interrupted by user");
    return out;
  }
  if (control.IsTimeout()) {
    out.rcm = Err(EC::OperationTimeout, "terminal.channel.write", target_name,
                  "Operation timed out");
    return out;
  }

#ifdef _WIN32
  UpdateWindowsProcessState_(ctx);
#else
  UpdatePosixProcessState_(ctx);
#endif
  if (ctx->process_exited || ctx->eof) {
    out.rcm = Err(EC::NoConnection, "terminal.channel.write", target_name,
                  "Target channel is closed");
    return out;
  }

#ifdef _WIN32
  if (ctx->input_write == INVALID_HANDLE_VALUE) {
    out.rcm = Err(EC::InvalidHandle, "terminal.channel.write", target_name,
                  "Terminal input handle is unavailable");
    return out;
  }
  DWORD wrote = 0;
  const BOOL write_ok =
      WriteFile(ctx->input_write, write_args.input.data(),
                static_cast<DWORD>(write_args.input.size()), &wrote, nullptr);
  out.data.bytes_written = static_cast<size_t>(wrote);
  out.rcm = write_ok ? OK
                     : Err(EC::SocketSendError, "terminal.channel.write",
                           target_name, "Failed to write to terminal");
  return out;
#else
  if (ctx->master_fd < 0) {
    out.rcm = Err(EC::InvalidHandle, "terminal.channel.write", target_name,
                  "PTY handle is unavailable");
    return out;
  }

  auto deadline = std::chrono::steady_clock::time_point::max();
  auto remain_opt = control.RemainingTimeMs();
  if (remain_opt.has_value()) {
    deadline = std::chrono::steady_clock::now() +
               std::chrono::milliseconds(*remain_opt);
  }

  while (out.data.bytes_written < write_args.input.size()) {
    ssize_t const rc =
        write(ctx->master_fd, write_args.input.data() + out.data.bytes_written,
              write_args.input.size() - out.data.bytes_written);
    if (rc > 0) {
      out.data.bytes_written += static_cast<size_t>(rc);
      continue;
    }
    if (rc < 0 && errno == EINTR) {
      continue;
    }
    if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (control.IsInterrupted()) {
        out.rcm = Err(EC::Terminate, "terminal.channel.write", target_name,
                      "Interrupted while waiting terminal write");
        return out;
      }
      if (control.IsTimeout()) {
        out.rcm = Err(EC::OperationTimeout, "terminal.channel.write",
                      target_name, "Timed out while waiting terminal write");
        return out;
      }
      if (deadline != std::chrono::steady_clock::time_point::max() &&
          std::chrono::steady_clock::now() >= deadline) {
        out.rcm = Err(EC::OperationTimeout, "terminal.channel.write",
                      target_name, "Timed out while waiting terminal write");
        return out;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      continue;
    }
    out.rcm = Err(fec(std::error_code(errno, std::generic_category())),
                  "terminal.channel.write", target_name, std::strerror(errno));
    return out;
  }
  out.rcm = OK;
  return out;
#endif
}

inline ECMData<AMT::ChannelResizeResult> LocalTerminalPort::ResizeChannel(
    const AMT::ChannelResizeArgs &resize_args,
    const AMDomain::client::ClientControlComponent &control,
    const std::optional<std::string> &bound_channel_name) {
  (void)control;
  ECMData<AMT::ChannelResizeResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  auto channel_result =
      ResolveChannelForOp_(bound_channel_name, "terminal.channel.resize");
  if (!(channel_result.rcm) || channel_result.data == nullptr) {
    out.rcm = channel_result.rcm;
    return out;
  }

  ChannelRuntime_ *ctx = channel_result.data;
  const std::string target_name = ResolveTargetChannelName_(bound_channel_name);
  out.data.channel_name = target_name;
  ResizeWindow_(resize_args, &(ctx->window));

  if (ctx->eof || ctx->process_exited) {
    out.data.resized = false;
    out.rcm = OK;
    return out;
  }

#ifdef _WIN32
  const auto &api = ConPTYApiInstance_();
  if (ctx->pseudo_console == nullptr || !api.IsAvailable() ||
      api.resize == nullptr) {
    out.data.resized = false;
    out.rcm = OK;
    return out;
  }
  COORD size = {};
  size.X = static_cast<SHORT>(std::max(1, resize_args.cols));
  size.Y = static_cast<SHORT>(std::max(1, resize_args.rows));
  const HRESULT hr = api.resize(ctx->pseudo_console, size);
  if (FAILED(hr)) {
    out.data.resized = false;
    out.rcm = Err(EC::OperationUnsupported, "terminal.channel.resize",
                  target_name, "ConPTY resize failed");
    return out;
  }
  out.data.resized = true;
  out.rcm = OK;
  return out;
#else
  if (ctx->master_fd < 0) {
    out.data.resized = false;
    out.rcm = OK;
    return out;
  }
  winsize ws = {};
  ws.ws_col = static_cast<unsigned short>(std::max(1, resize_args.cols));
  ws.ws_row = static_cast<unsigned short>(std::max(1, resize_args.rows));
  ws.ws_xpixel = static_cast<unsigned short>(std::max(0, resize_args.width));
  ws.ws_ypixel = static_cast<unsigned short>(std::max(0, resize_args.height));
  if (ioctl(ctx->master_fd, TIOCSWINSZ, &ws) != 0) {
    out.data.resized = false;
    out.rcm = Err(fec(std::error_code(errno, std::generic_category())),
                  "terminal.channel.resize", target_name, std::strerror(errno));
    return out;
  }
  out.data.resized = true;
  out.rcm = OK;
  return out;
#endif
}

inline ECMData<AMT::ChannelCloseResult> LocalTerminalPort::CloseChannel(
    const AMT::ChannelCloseArgs &close_args,
    const AMDomain::client::ClientControlComponent &control) {
  (void)control;
  ECMData<AMT::ChannelCloseResult> out = {};
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  CacheSyncGuard_ cache_sync{this};

  const std::string target_name =
      ResolveTargetChannelName_(close_args.channel_name);
  if (target_name.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.close", "channel_name",
                  "No channel_name provided and no active channel set");
    return out;
  }

  auto it = channel_runtimes_.find(target_name);
  if (it == channel_runtimes_.end()) {
    out.rcm = Err(EC::InvalidArg, "terminal.close", target_name,
                  "Target channel does not exist");
    return out;
  }

  out.data.channel_name = target_name;
  CloseChannelRuntime_(&(it->second), close_args.force);
  out.data.exit_code = it->second.exit_status;
  channel_runtimes_.erase(it);
  channels_.erase(target_name);
  if (current_channel_.has_value() && *current_channel_ == target_name) {
    current_channel_ = std::nullopt;
  }
  out.data.closed =
      !channel_runtimes_.contains(target_name);
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

  auto src_it = channel_runtimes_.find(src_name);
  if (src_it == channel_runtimes_.end()) {
    out.rcm = Err(EC::ClientNotFound, "terminal.rename", src_name,
                  "Source channel does not exist");
    return out;
  }
  if (channel_runtimes_.contains(dst_name)) {
    out.rcm = Err(EC::TargetAlreadyExists, "terminal.rename", dst_name,
                  "Target channel already exists");
    return out;
  }

  channel_runtimes_.emplace(dst_name, std::move(src_it->second));
  channel_runtimes_.erase(src_it);
  auto src_port_it = channels_.find(src_name);
  if (src_port_it != channels_.end()) {
    channels_.erase(src_port_it);
  }
  auto channel_port_result =
      GetChannelPort(std::optional<std::string>(dst_name), control);
  if (!(channel_port_result.rcm)) {
    out.rcm = channel_port_result.rcm;
    return out;
  }
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
  for (const auto &entry : channel_runtimes_) {
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
    out.rcm = Err(EC::InvalidHandle, "terminal.check_session",
                  request_.nickname, "Client handle is null");
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
    auto it = channel_runtimes_.find(*current_channel_);
    out.data.is_open = (it != channel_runtimes_.end()) && !it->second.eof;
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

  const std::string target_name =
      ResolveTargetChannelName_(check_args.channel_name);
  if (target_name.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.check_channel", "channel_name",
                  "No channel_name provided and no active channel set");
    return out;
  }

  out.data.channel_name = target_name;
  auto it = channel_runtimes_.find(target_name);
  if (it == channel_runtimes_.end()) {
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

inline std::vector<std::string>
LocalTerminalPort::GetCachedChannelNames() const {
  auto guard = const_cast<AMAtomic<TerminalStateCache_> &>(attr_cache_).lock();
  std::vector<std::string> names = {};
  names.reserve((*guard).channel_states.size());
  for (const auto &entry : (*guard).channel_states) {
    names.push_back(entry.first);
  }
  return names;
}

inline ECMData<std::intptr_t> LocalTerminalPort::GetChannelWaitHandle(
    const std::optional<std::string> &channel_name) const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  const std::string target_name = ResolveTargetChannelName_(channel_name);
  if (target_name.empty()) {
    return {static_cast<std::intptr_t>(-1),
            Err(EC::NoConnection, "terminal.channel.wait_handle",
                request_.nickname, "No active channel available")};
  }
  auto it = channel_runtimes_.find(target_name);
  if (it == channel_runtimes_.end()) {
    return {static_cast<std::intptr_t>(-1),
            Err(EC::NoConnection, "terminal.channel.wait_handle",
                request_.nickname, "Target channel not found")};
  }
#ifdef _WIN32
  if (it->second.output_read == INVALID_HANDLE_VALUE) {
    return {static_cast<std::intptr_t>(-1),
            Err(EC::NoConnection, "terminal.channel.wait_handle",
                request_.nickname, "Channel output handle is unavailable")};
  }
  return {static_cast<std::intptr_t>(
              reinterpret_cast<std::intptr_t>(it->second.output_read)),
          OK};
#else
  if (it->second.master_fd < 0) {
    return {static_cast<std::intptr_t>(-1),
            Err(EC::NoConnection, "terminal.channel.wait_handle",
                request_.nickname, "Channel PTY fd is unavailable")};
  }
  return {static_cast<std::intptr_t>(it->second.master_fd), OK};
#endif
}

inline ECMData<std::intptr_t> LocalTerminalPort::GetRemoteSocketHandle() const {
  return GetChannelWaitHandle(std::nullopt);
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
  if (handle != nullptr && *handle != nullptr &&
      *handle != INVALID_HANDLE_VALUE) {
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

inline void
LocalTerminalPort::UpdateWindowsProcessState_(ChannelRuntime_ *ctx) {
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

inline bool LocalTerminalPort::DrainWindowsOutput_(ChannelRuntime_ *ctx,
                                                   std::string *output,
                                                   size_t max_bytes) {
  if (ctx == nullptr || output == nullptr ||
      ctx->output_read == INVALID_HANDLE_VALUE || max_bytes == 0U) {
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
    ChannelRuntime_ *ctx,
    const AMDomain::client::ClientControlComponent &control, bool *timed_out) {
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
      const auto remain =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
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
    ChannelRuntime_ *ctx, const AMT::ChannelOpenArgs &open_args) {
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
inline void LocalTerminalPort::UpdatePosixProcessState_(ChannelRuntime_ *ctx) {
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

inline bool LocalTerminalPort::DrainPosixOutput_(ChannelRuntime_ *ctx,
                                                 std::string *output,
                                                 size_t max_bytes) {
  if (ctx == nullptr || output == nullptr || ctx->master_fd < 0 ||
      max_bytes == 0U) {
    return false;
  }
  bool wrote = false;
  std::array<char, 4096> buffer = {};
  while (output->size() < max_bytes) {
    const size_t cap =
        std::min<size_t>(buffer.size(), max_bytes - output->size());
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
    ChannelRuntime_ *ctx,
    const AMDomain::client::ClientControlComponent &control, bool *timed_out) {
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
      const auto remain =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      tv.tv_sec = static_cast<time_t>(remain.count() / 1000);
      tv.tv_usec = static_cast<suseconds_t>((remain.count() % 1000) * 1000);
      tv_ptr = &tv;
    }
    const int rc =
        select(ctx->master_fd + 1, &readfds, nullptr, nullptr, tv_ptr);
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

inline ECM
LocalTerminalPort::OpenOneChannelPosix_(ChannelRuntime_ *ctx,
                                        const AMT::ChannelOpenArgs &open_args) {
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

inline void LocalTerminalPort::CloseChannelRuntime_(ChannelRuntime_ *ctx,
                                                    bool force) {
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
      const auto kill_deadline =
          std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
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

