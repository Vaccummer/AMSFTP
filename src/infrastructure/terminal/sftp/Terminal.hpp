#pragma once
#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"
#include "infrastructure/terminal/sftp/RealtimeSSHChannelPort.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace AMInfra::client::SFTP::terminal {
namespace AMT = AMDomain::terminal;

class TerminalPortBase : public AMT::ITerminalPort {
protected:
  struct TerminalWindowInfo {
    int cols = 80;
    int rows = 24;
    int width = 0;
    int height = 0;
    std::string term = "xterm-256color";
  };

  [[nodiscard]] static TerminalWindowInfo
  OpenWindow_(const AMT::ChannelOpenArgs &open_args,
              const TerminalWindowInfo &fallback) {
    TerminalWindowInfo out = fallback;
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

  static void ResizeWindow_(const AMT::ChannelResizeArgs &resize_args,
                            TerminalWindowInfo *window) {
    if (!window) {
      return;
    }
    window->cols = resize_args.cols;
    window->rows = resize_args.rows;
    window->width = resize_args.width;
    window->height = resize_args.height;
  }

  [[nodiscard]] static AMDomain::client::ClientStatus
  StatusFromEC_(ErrorCode code) {
    if (code == ErrorCode::Success) {
      return AMDomain::client::ClientStatus::OK;
    }
    if (code == ErrorCode::NotInitialized) {
      return AMDomain::client::ClientStatus::NotInitialized;
    }
    if (code == ErrorCode::NoConnection) {
      return AMDomain::client::ClientStatus::NoConnection;
    }
    return AMDomain::client::ClientStatus::ConnectionBroken;
  }

  [[nodiscard]] static int
  TimeoutMs_(const AMDomain::client::ClientControlComponent &control) {
    const auto remain_opt = control.RemainingTimeMs();
    if (!remain_opt.has_value()) {
      return -1;
    }
    return static_cast<int>(std::min<unsigned int>(
        *remain_opt,
        static_cast<unsigned int>((std::numeric_limits<int>::max)())));
  }
};

class SSHTerminalPort final : public TerminalPortBase {
private:
  struct ChannelRuntime_ {
    std::unique_ptr<detail::SafeChannel> channel = {};
    TerminalWindowInfo window = {};
    bool eof = false;
    int exit_status = -1;
    ECM state = OK;
  };

  struct TerminalStateCache {
    AMDomain::filesystem::CheckResult session_state =
        AMDomain::filesystem::CheckResult(
            AMDomain::client::ClientStatus::NotInitialized);
    std::optional<std::string> current_channel = std::nullopt;
    std::unordered_map<std::string, ECM> channel_states = {};
  };

  mutable AMAtomic<TerminalStateCache> attr_cache_ =
      AMAtomic<TerminalStateCache>(TerminalStateCache{});

  ConRequest request_ = {};
  AMT::ClientHandle owner_client_ = nullptr;
  AMSFTPIOCore *sftp_core_ = nullptr;
  mutable std::recursive_mutex fallback_mtx_ = {};
  LIBSSH2_SESSION *session_ = nullptr;
  std::map<std::string, ChannelRuntime_> channel_runtimes_ = {};
  std::map<std::string, AMT::ChannelPortHandle> channels_ = {};
  std::optional<std::string> current_channel_ = std::nullopt;
  static constexpr int kDefaultCloseTimeoutMs_ = 1500;

  struct CacheSyncGuard_ {
    SSHTerminalPort *self = nullptr;
    ~CacheSyncGuard_() {
      if (self) {
        self->SyncCacheFromRuntimeUnlocked_();
      }
    }
  };

  [[nodiscard]] std::recursive_mutex &CoreMutex_() const {
    if (sftp_core_) {
      return sftp_core_->TransferMutex();
    }
    return fallback_mtx_;
  }

  void SyncCoreHandles_() {
    session_ = (sftp_core_ != nullptr) ? sftp_core_->session : nullptr;
  }

  [[nodiscard]] AMDomain::filesystem::CheckResult
  ReadSessionStateFromClient_() const {
    if (!owner_client_) {
      return AMDomain::filesystem::CheckResult(
          AMDomain::client::ClientStatus::NotInitialized);
    }
    auto state = owner_client_->ConfigPort().GetState();
    if (!state.rcm) {
      return AMDomain::filesystem::CheckResult(
          AMDomain::client::ClientStatus::NotInitialized);
    }
    return {state.data.status};
  }

  void SyncCacheFromRuntimeUnlocked_() {
    auto guard = attr_cache_.lock();
    (*guard).session_state = ReadSessionStateFromClient_();
    (*guard).current_channel = current_channel_;
    (*guard).channel_states.clear();
    for (const auto &entry : channel_runtimes_) {
      const auto &ctx = entry.second;
      ECM state = ctx.state;
      if (ctx.eof || !ctx.channel || !ctx.channel->channel ||
          ctx.channel->closed) {
        state = Err(EC::NoConnection, "terminal.channel.state", entry.first,
                    "Channel is closed");
      }
      (*guard).channel_states[entry.first] = state;
    }
  }

  [[nodiscard]] ErrorCode LastEC_() const {
    if (!sftp_core_) {
      return ErrorCode::NoSession;
    }
    return sftp_core_->GetLastEC();
  }

  [[nodiscard]] std::string LastError_() const {
    if (!sftp_core_) {
      return "Session not initialized";
    }
    return sftp_core_->GetLastErrorMsg();
  }

  [[nodiscard]] bool IsChannelAlive_(ChannelRuntime_ *ctx) {
    if (!ctx || !ctx->channel || !ctx->channel->channel) {
      return false;
    }
    if (ctx->channel->closed) {
      ctx->eof = true;
      return false;
    }
    if (libssh2_channel_eof(ctx->channel->channel) != 0) {
      ctx->eof = true;
      ctx->exit_status = libssh2_channel_get_exit_status(ctx->channel->channel);
      return false;
    }
    return true;
  }

  void
  CloseAllChannels_(bool send_exit,
                    const AMDomain::client::ClientControlComponent &control) {
    std::vector<AMT::ChannelPortHandle> ports = {};
    {
      std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
      ports.reserve(channels_.size());
      for (auto const &entry : channels_) {
        if (entry.second) {
          ports.push_back(entry.second);
        }
      }
    }

    for (auto &port : ports) {
      if (port) {
        (void)port->Close(!send_exit, control);
      }
    }

    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
    channel_runtimes_.clear();
    channels_.clear();
    current_channel_ = std::nullopt;
  }

  void CloseTerminal_(const AMDomain::client::ClientControlComponent &control) {
    CloseAllChannels_(true, control);
    session_ = nullptr;
  }

  [[nodiscard]] WaitResult
  WaitSocket_(detail::SocketWaitType wait_type,
              const AMDomain::client::ClientControlComponent &control) {
    if (!sftp_core_) {
      return WaitResult::Error;
    }
    return sftp_core_->wait_for_socket(wait_type, control);
  }

  template <typename Func>
  [[nodiscard]] auto
  NBCall_(const AMDomain::client::ClientControlComponent &control, Func &&func)
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
        retry = (rc == nullptr && session_ &&
                 libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN);
      }
      if (!retry) {
        return {rc, WaitResult::Ready};
      }
      WaitResult wr = WaitSocket_(detail::SocketWaitType::Auto, control);
      if (wr != WaitResult::Ready) {
        return {RetType{}, wr};
      }
    }
  }

  [[nodiscard]] ECM
  EnsureSessionReady_(const AMDomain::client::ClientControlComponent &control) {
    if (control.IsInterrupted()) {
      return {ErrorCode::Terminate, "terminal.session", request_.hostname,
              "Interrupted by user"};
    }
    if (control.IsTimeout()) {
      return {ErrorCode::OperationTimeout, "terminal.session",
              request_.hostname, "Operation timed out"};
    }
    if (!sftp_core_) {
      return {ErrorCode::NoSession, "terminal.session", request_.hostname,
              "SFTP IO core is unavailable"};
    }
    SyncCoreHandles_();
    if (!session_) {
      return {ErrorCode::NoConnection, "terminal.session", request_.hostname,
              "Client session is not connected"};
    }
    return OK;
  }

  [[nodiscard]] std::string ResolveTargetChannelName_(
      const std::optional<std::string> &requested_name) const {
    const std::string requested =
        requested_name.has_value() ? AMStr::Strip(*requested_name) : "";
    if (!requested.empty()) {
      return requested;
    }
    if (current_channel_.has_value()) {
      return *current_channel_;
    }
    return "";
  }

  [[nodiscard]] std::string
  ResolveTargetChannelName_(const std::string &requested_name) const {
    return ResolveTargetChannelName_(
        std::optional<std::string>(requested_name));
  }

  [[nodiscard]] ECM
  OpenOneChannel_(ChannelRuntime_ *ctx,
                  const AMDomain::client::ClientControlComponent &control) {
    if (!ctx) {
      return {ErrorCode::InvalidArg, "terminal.open", request_.hostname,
              "Invalid channel context"};
    }
    std::lock_guard<std::recursive_mutex> lock(sftp_core_->TransferMutex());
    if (!session_) {
      return {ErrorCode::NoSession, "terminal.open", request_.hostname,
              "Session is null"};
    }

    ctx->channel = std::make_unique<detail::SafeChannel>();
    ctx->eof = false;
    ctx->exit_status = -1;

    const AMDomain::client::amf control_token = control.ControlToken();
    auto is_interrupted = [control_token]() -> bool {
      return control_token && control_token->IsInterrupted();
    };

    ECM init_ecm =
        ctx->channel->Init(session_, std::move(is_interrupted),
                           TimeoutMs_(control), AMTime::miliseconds());
    if (init_ecm.code != ErrorCode::Success) {
      ctx->channel.reset();
      return init_ecm;
    }

    libssh2_session_set_blocking(session_, 0);

    auto pty_res = NBCall_(control, [&]() {
      return libssh2_channel_request_pty_ex(
          ctx->channel->channel, ctx->window.term.c_str(),
          static_cast<unsigned int>(ctx->window.term.size()), nullptr, 0,
          ctx->window.cols, ctx->window.rows, ctx->window.width,
          ctx->window.height);
    });
    if (!pty_res || pty_res.value != 0) {
      ECM ecm = {LastEC_(), "terminal.request_pty", ctx->window.term,
                 LastError_()};
      ctx->channel.reset();
      return ecm;
    }

    auto shell_res = NBCall_(control, [&]() {
      return libssh2_channel_shell(ctx->channel->channel);
    });
    if (!shell_res || shell_res.value != 0) {
      ECM ecm = {LastEC_(), "terminal.start_shell", ctx->window.term,
                 LastError_()};
      ctx->channel.reset();
      return ecm;
    }

    return OK;
  }

public:
  SSHTerminalPort(AMT::ClientHandle owner_client, ConRequest request,
                  AMSFTPIOCore *sftp_core)
      : request_(std::move(request)), owner_client_(std::move(owner_client)),
        sftp_core_(sftp_core) {
    SyncCoreHandles_();
    SyncCacheFromRuntimeUnlocked_();
  }

  ~SSHTerminalPort() override {
    AMDomain::client::ClientControlComponent close_control(
        nullptr, kDefaultCloseTimeoutMs_);
    CloseTerminal_(close_control);
    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
    SyncCacheFromRuntimeUnlocked_();
  }

  [[nodiscard]] ConRequest GetRequest() const override { return request_; }

  ECMData<AMT::ChannelOpenResult> OpenChannel(
      const AMT::ChannelOpenArgs &open_args,
      const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMT::ChannelOpenResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
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
    if (channel_runtimes_.find(channel_name) != channel_runtimes_.end()) {
      out.rcm = Err(EC::TargetAlreadyExists, "terminal.open", channel_name,
                    "Channel name already exists");
      return out;
    }

    out.rcm = EnsureSessionReady_(control);
    if (!(out.rcm)) {
      return out;
    }

    ChannelRuntime_ ctx = {};
    ctx.window = OpenWindow_(open_args, ctx.window);
    out.rcm = OpenOneChannel_(&ctx, control);
    if (!(out.rcm)) {
      return out;
    }

    channel_runtimes_.emplace(channel_name, std::move(ctx));

    auto channel_port_result =
        GetChannelPort(std::optional<std::string>(channel_name), control);
    if (!(channel_port_result.rcm) || !channel_port_result.data) {
      channel_runtimes_.erase(channel_name);
      out.rcm = channel_port_result.rcm
                    ? Err(EC::InvalidHandle, "terminal.open", channel_name,
                          "Failed to initialize channel port")
                    : channel_port_result.rcm;
      return out;
    }

    const ECM loop_rcm = channel_port_result.data->EnsureLoopStarted(
        AMT::ChannelLoopStartArgs{});
    if (!(loop_rcm)) {
      (void)CloseChannel({channel_name, true}, control);
      out.rcm = loop_rcm;
      return out;
    }
    out.data.channel_name = channel_name;
    out.data.opened = true;
    return out;
  }

  ECMData<AMT::ChannelActiveResult> ActiveChannel(
      const AMT::ChannelActiveArgs &active_args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)control;
    ECMData<AMT::ChannelActiveResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
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
    if (!IsChannelAlive_(&(it->second))) {
      out.rcm = Err(EC::NoConnection, "terminal.active", channel_name,
                    "Target channel is not alive");
      return out;
    }

    current_channel_ = channel_name;
    out.data.channel_name = channel_name;
    out.data.activated = true;
    out.rcm = OK;
    return out;
  }

  ECMData<AMT::ChannelPortHandle> GetChannelPort(
      const std::optional<std::string> &channel_name,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)control;
    ECMData<AMT::ChannelPortHandle> out = {};
    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
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

    auto &runtime = channel_it->second;
    AMInfra::terminal::RealtimeSSHChannelBinding binding = {};
    binding.core_mutex = std::addressof(CoreMutex_());
    binding.sftp_core = sftp_core_;
    binding.channel_holder = std::addressof(runtime.channel);
    binding.eof = std::addressof(runtime.eof);
    binding.exit_status = std::addressof(runtime.exit_status);
    binding.state = std::addressof(runtime.state);
    binding.window_cols = std::addressof(runtime.window.cols);
    binding.window_rows = std::addressof(runtime.window.rows);
    binding.window_width = std::addressof(runtime.window.width);
    binding.window_height = std::addressof(runtime.window.height);
    binding.host = request_.hostname;

    auto port = std::make_shared<AMInfra::terminal::RealtimeSSHChannelPort>(
        terminal_key, target_name, std::move(binding));
    if (!port) {
      out.rcm = Err(EC::InvalidHandle, "terminal.channel_port", target_name,
                    "Failed to create realtime SSH channel port");
      return out;
    }

    channels_[target_name] = port;
    out.data = port;
    out.rcm = OK;
    return out;
  }
  ECMData<AMT::ChannelCloseResult> CloseChannel(
      const AMT::ChannelCloseArgs &close_args,
      const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMT::ChannelCloseResult> out = {};
    std::unique_lock<std::recursive_mutex> lock(CoreMutex_());
    CacheSyncGuard_ cache_sync{this};

    const std::string target_name =
        ResolveTargetChannelName_(close_args.channel_name);
    if (target_name.empty()) {
      out.rcm = Err(EC::InvalidArg, "terminal.close", "channel_name",
                    "No channel_name provided and no active channel set");
      return out;
    }

    auto runtime_it = channel_runtimes_.find(target_name);
    if (runtime_it == channel_runtimes_.end()) {
      out.rcm = Err(EC::InvalidArg, "terminal.close", target_name,
                    "Target channel does not exist");
      return out;
    }

    auto channel_it = channels_.find(target_name);
    AMT::ChannelPortHandle channel_port =
        (channel_it != channels_.end()) ? channel_it->second : nullptr;
    out.data.channel_name = target_name;

    lock.unlock();
    if (channel_port) {
      auto close_result = channel_port->Close(close_args.force, control);
      out.rcm = close_result.rcm;
      out.data.exit_code = close_result.data.exit_code;
    } else {
      out.rcm = OK;
    }
    lock.lock();

    auto current_it = channel_runtimes_.find(target_name);
    if (current_it != channel_runtimes_.end()) {
      if (out.data.exit_code < 0) {
        out.data.exit_code = current_it->second.exit_status;
      }
      channel_runtimes_.erase(current_it);
    }
    channels_.erase(target_name);
    if (current_channel_.has_value() && *current_channel_ == target_name) {
      current_channel_ = std::nullopt;
    }

    out.data.closed =
        channel_runtimes_.find(target_name) == channel_runtimes_.end();
    if (out.rcm.code == ErrorCode::Success ||
        out.rcm.code == ErrorCode::Terminate ||
        out.rcm.code == ErrorCode::OperationTimeout) {
      out.rcm = OK;
    }
    return out;
  }
  ECMData<AMT::ChannelRenameResult> RenameChannel(
      const AMT::ChannelRenameArgs &rename_args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)control;
    ECMData<AMT::ChannelRenameResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
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
      out.rcm =
          Err(EC::InvalidArg, "terminal.rename", src_name + "->" + dst_name,
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
    if (channel_runtimes_.find(dst_name) != channel_runtimes_.end()) {
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

  ECMData<AMT::ChannelListResult> ListChannels(
      const AMT::ChannelListArgs &list_args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)list_args;
    (void)control;
    ECMData<AMT::ChannelListResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
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

  ECMData<AMT::CheckSessionResult> CheckSession(
      const AMT::CheckSessionArgs &check_args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)check_args;
    ECMData<AMT::CheckSessionResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
    CacheSyncGuard_ cache_sync{this};

    out.data.is_supported = true;
    out.data.can_resize = true;
    if (current_channel_.has_value()) {
      out.data.current_channel = *current_channel_;
    }

    if (!sftp_core_) {
      out.rcm = Err(EC::NoSession, "terminal.check_session", request_.hostname,
                    "SFTP IO core is unavailable");
      out.data.status = StatusFromEC_(out.rcm.code);
      out.data.is_open = false;
      return out;
    }

    auto check_result =
        sftp_core_->Check(AMDomain::filesystem::CheckArgs{}, control);
    out.rcm = check_result.rcm;
    out.data.status = check_result.data.status;

    if (current_channel_.has_value()) {
      auto it = channel_runtimes_.find(*current_channel_);
      out.data.is_open =
          (it != channel_runtimes_.end()) && IsChannelAlive_(&(it->second));
    } else {
      out.data.is_open = false;
    }
    return out;
  }

  ECMData<AMT::ChannelCheckResult> CheckChannel(
      const AMT::ChannelCheckArgs &check_args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)control;
    ECMData<AMT::ChannelCheckResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(CoreMutex_());
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

    out.data.exists = true;
    out.data.is_open = IsChannelAlive_(&(it->second));
    out.data.is_active =
        current_channel_.has_value() && (*current_channel_ == target_name);
    out.rcm = OK;
    return out;
  }

  [[nodiscard]] AMDomain::filesystem::CheckResult
  GetSessionState() const override {
    auto guard = const_cast<AMAtomic<TerminalStateCache> &>(attr_cache_).lock();
    return (*guard).session_state;
  }

  [[nodiscard]] std::optional<ECM>
  GetChannelState(const std::string &channel_name) const override {
    auto guard = const_cast<AMAtomic<TerminalStateCache> &>(attr_cache_).lock();
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

  [[nodiscard]] std::vector<std::string>
  GetCachedChannelNames() const override {
    auto guard = const_cast<AMAtomic<TerminalStateCache> &>(attr_cache_).lock();
    std::vector<std::string> names = {};
    names.reserve((*guard).channel_states.size());
    for (const auto &entry : (*guard).channel_states) {
      names.push_back(entry.first);
    }
    return names;
  }
};

} // namespace AMInfra::client::SFTP::terminal
