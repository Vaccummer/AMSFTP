#pragma once
#include "infrastructure/client/sftp/SFTP.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace AMInfra::client::SFTP::terminal {
namespace AMFSI = AMDomain::filesystem;
class ITerminalPort : public AMDomain::client::IClientTerminalPort {
public:
  ~ITerminalPort() override = default;

  [[nodiscard]] virtual ConRequest GetRequest() const = 0;
};

class TerminalPortBase : public ITerminalPort {
protected:
  struct TerminalWindowInfo {
    int cols = 80;
    int rows = 24;
    int width = 0;
    int height = 0;
    std::string term = "xterm-256color";
  };

  [[nodiscard]] static TerminalWindowInfo
  OpenWindow_(const AMFSI::TerminalOpenArgs &args,
              const TerminalWindowInfo &fallback) {
    TerminalWindowInfo out = fallback;
    out.cols = args.cols;
    out.rows = args.rows;
    out.width = args.width;
    out.height = args.height;
    if (!args.term.empty()) {
      out.term = args.term;
    }
    if (out.term.empty()) {
      out.term = "xterm-256color";
    }
    return out;
  }

  static void ResizeWindow_(const AMFSI::TerminalResizeArgs &args,
                            TerminalWindowInfo *window) {
    if (!window) {
      return;
    }
    window->cols = args.cols;
    window->rows = args.rows;
    window->width = args.width;
    window->height = args.height;
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
  ConRequest request_ = {};
  std::vector<std::string> private_keys_ = {};
  TraceCallback trace_cb_ = {};
  ConnectStateCallback connect_state_cb_ = {};
  AuthCallback auth_cb_ = {};
  KnownHostCallback known_host_cb_ = {};
  std::unique_ptr<AMInfra::client::ClientConfigStore> config_store_ = {};
  std::unique_ptr<AMInfra::client::ClientControlToken> control_store_ = {};
  std::unique_ptr<AMSFTPIOCore> sftp_core_ = {};

  mutable std::recursive_mutex mtx_;
  LIBSSH2_SESSION *session_ = nullptr;
  std::unique_ptr<detail::SafeChannel> terminal_channel_ = {};
  TerminalWindowInfo terminal_window_ = {};
  bool terminal_eof_ = false;
  int terminal_exit_status_ = -1;
  AMDomain::client::ClientStatus status_ =
      AMDomain::client::ClientStatus::NotInitialized;

  void SyncCoreHandles_() {
    if (!sftp_core_) {
      session_ = nullptr;
      return;
    }
    session_ = sftp_core_->session;
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

  void SyncCallbacksToCore_() {
    if (!sftp_core_) {
      return;
    }
    if (trace_cb_) {
      sftp_core_->RegisterTraceCallback(trace_cb_);
    } else {
      sftp_core_->UnregisterTraceCallback();
    }
    if (connect_state_cb_) {
      sftp_core_->RegisterConnectStateCallback(connect_state_cb_);
    } else {
      sftp_core_->UnregisterConnectStateCallback();
    }
    if (auth_cb_) {
      sftp_core_->RegisterAuthCallback(auth_cb_);
    } else {
      sftp_core_->UnregisterAuthCallback();
    }
    if (known_host_cb_) {
      sftp_core_->RegisterKnownHostCallback(known_host_cb_);
    } else {
      sftp_core_->UnregisterKnownHostCallback();
    }
  }

  void ResetTerminalState_(bool keep_window = true) {
    if (!keep_window) {
      terminal_window_ = {};
    }
    terminal_channel_.reset();
    terminal_eof_ = false;
    terminal_exit_status_ = -1;
  }

  [[nodiscard]] bool IsTerminalAlive_() {
    if (!terminal_channel_ || !terminal_channel_->channel) {
      return false;
    }
    if (terminal_channel_->closed) {
      terminal_eof_ = true;
      return false;
    }
    if (libssh2_channel_eof(terminal_channel_->channel) != 0) {
      terminal_eof_ = true;
      terminal_exit_status_ =
          libssh2_channel_get_exit_status(terminal_channel_->channel);
      return false;
    }
    return true;
  }

  void DisconnectSession_() {
    (void)CloseChannel_(true);
    sftp_core_.reset();
    control_store_.reset();
    config_store_.reset();
    session_ = nullptr;
    status_ = AMDomain::client::ClientStatus::NoConnection;
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
  EnsureConnected_(bool force,
                   const AMDomain::client::ClientControlComponent &control) {
    if (control.IsInterrupted()) {
      return {ErrorCode::Terminate, "terminal.connect", request_.hostname,
              "Interrupted by user"};
    }
    if (control.IsTimeout()) {
      return {ErrorCode::OperationTimeout, "terminal.connect",
              request_.hostname, "Operation timed out"};
    }
    SyncCoreHandles_();
    const bool connected =
        session_ != nullptr && status_ == AMDomain::client::ClientStatus::OK;
    if (connected) {
      if (!force) {
        return OK;
      }
      (void)CloseChannel_(true);
      const auto reconnect_result =
          sftp_core_->Connect(AMFSI::ConnectArgs{true}, control);
      status_ = reconnect_result.data.status;
      SyncCoreHandles_();
      return reconnect_result.rcm;
    }

    if (!config_store_) {
      config_store_ =
          std::make_unique<AMInfra::client::ClientConfigStore>(request_);
    } else {
      config_store_->SetRequest(request_);
    }
    if (!control_store_) {
      control_store_ = std::make_unique<AMInfra::client::ClientControlToken>();
    }
    if (!sftp_core_) {
      sftp_core_ = std::make_unique<AMSFTPIOCore>(
          config_store_.get(), control_store_.get(), private_keys_, trace_cb_,
          auth_cb_, known_host_cb_);
    }
    SyncCallbacksToCore_();
    const auto connect_result =
        sftp_core_->Connect(AMFSI::ConnectArgs{force}, control);
    status_ = connect_result.data.status;
    SyncCoreHandles_();
    if (connect_result.rcm.code == ErrorCode::Success) {
      request_ = config_store_->GetRequest();
      return OK;
    }
    return connect_result.rcm;
  }

  [[nodiscard]] ECM
  OpenChannel_(const AMDomain::client::ClientControlComponent &control) {
    if (!session_) {
      return {ErrorCode::NoSession, "terminal.open", request_.hostname,
              "Session is null"};
    }
    ResetTerminalState_(true);
    terminal_channel_ = std::make_unique<detail::SafeChannel>();
    ECM init_ecm = terminal_channel_->Init(
        session_, [&control]() { return control.IsInterrupted(); },
        TimeoutMs_(control), AMTime::miliseconds());
    if (init_ecm.code != ErrorCode::Success) {
      ResetTerminalState_(true);
      return init_ecm;
    }
    libssh2_session_set_blocking(session_, 0);

    auto pty_res = NBCall_(control, [&]() {
      return libssh2_channel_request_pty_ex(
          terminal_channel_->channel, terminal_window_.term.c_str(),
          static_cast<unsigned int>(terminal_window_.term.size()), nullptr, 0,
          terminal_window_.cols, terminal_window_.rows, terminal_window_.width,
          terminal_window_.height);
    });
    if (!pty_res || pty_res.value != 0) {
      ECM ecm = {LastEC_(), "terminal.request_pty", terminal_window_.term,
                 LastError_()};
      ResetTerminalState_(true);
      return ecm;
    }

    auto shell_res = NBCall_(control, [&]() {
      return libssh2_channel_shell(terminal_channel_->channel);
    });
    if (!shell_res || shell_res.value != 0) {
      ECM ecm = {LastEC_(), "terminal.start_shell", terminal_window_.term,
                 LastError_()};
      ResetTerminalState_(true);
      return ecm;
    }
    terminal_eof_ = false;
    terminal_exit_status_ = -1;
    return OK;
  }

  [[nodiscard]] ECM CloseChannel_(bool send_exit) {
    if (!terminal_channel_ || !terminal_channel_->channel) {
      ResetTerminalState_(true);
      return OK;
    }
    terminal_exit_status_ =
        libssh2_channel_get_exit_status(terminal_channel_->channel);
    ECM close_rcm = terminal_channel_->graceful_exit(send_exit, 50, true);
    terminal_channel_.reset();
    terminal_eof_ = true;
    return close_rcm.code == ErrorCode::Success ? OK : close_rcm;
  }

  [[nodiscard]] ECM
  ReadChunk_(LIBSSH2_CHANNEL *channel, std::string *output, size_t max_bytes,
             const AMDomain::client::ClientControlComponent &control,
             ssize_t (*reader)(LIBSSH2_CHANNEL *, char *, size_t)) {
    if (!channel || !output) {
      return {ErrorCode::InvalidArg, "terminal.read", request_.hostname,
              "Invalid read state"};
    }
    std::array<char, 4096> buffer = {};
    while (output->size() < max_bytes) {
      const size_t left = max_bytes - output->size();
      const size_t cap = std::min(buffer.size(), left);
      const ssize_t rc = reader(channel, buffer.data(), cap);
      if (rc > 0) {
        output->append(buffer.data(), static_cast<size_t>(rc));
        continue;
      }
      if (rc == 0) {
        terminal_eof_ = libssh2_channel_eof(channel) != 0;
        if (terminal_eof_) {
          terminal_exit_status_ = libssh2_channel_get_exit_status(channel);
        }
        return OK;
      }
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        terminal_eof_ = libssh2_channel_eof(channel) != 0;
        if (terminal_eof_) {
          terminal_exit_status_ = libssh2_channel_get_exit_status(channel);
        }
        return OK;
      }
      if (control.IsInterrupted()) {
        return {ErrorCode::Terminate, "terminal.read", terminal_window_.term,
                "Interrupted"};
      }
      if (control.IsTimeout()) {
        return {ErrorCode::OperationTimeout, "terminal.read",
                terminal_window_.term, "Timed out"};
      }
      return {LastEC_(), "terminal.read", terminal_window_.term, LastError_()};
    }
    return OK;
  }

public:
  SSHTerminalPort(const ConRequest &request,
                  const std::vector<std::string> &private_keys = {},
                  TraceCallback trace_cb = {}, AuthCallback auth_cb = {},
                  KnownHostCallback known_host_cb = {})
      : request_(request), private_keys_(private_keys),
        trace_cb_(std::move(trace_cb)), auth_cb_(std::move(auth_cb)),
        known_host_cb_(std::move(known_host_cb)) {}

  ~SSHTerminalPort() override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    DisconnectSession_();
  }

  [[nodiscard]] ConRequest GetRequest() const override { return request_; }

  void RegisterTraceCallback(TraceCallback trace_cb) override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    trace_cb_ = std::move(trace_cb);
    SyncCallbacksToCore_();
  }

  void UnregisterTraceCallback() override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    trace_cb_ = {};
    SyncCallbacksToCore_();
  }

  void RegisterConnectStateCallback(
      ConnectStateCallback connect_state_cb) override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    connect_state_cb_ = std::move(connect_state_cb);
    SyncCallbacksToCore_();
  }

  void UnregisterConnectStateCallback() override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    connect_state_cb_ = {};
    SyncCallbacksToCore_();
  }

  void RegisterAuthCallback(AuthCallback auth_cb) override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    auth_cb_ = std::move(auth_cb);
    SyncCallbacksToCore_();
  }

  void UnregisterAuthCallback() override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    auth_cb_ = {};
    SyncCallbacksToCore_();
  }

  void RegisterKnownHostCallback(KnownHostCallback known_host_cb) override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    known_host_cb_ = std::move(known_host_cb);
    SyncCallbacksToCore_();
  }

  void UnregisterKnownHostCallback() override {
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    known_host_cb_ = {};
    SyncCallbacksToCore_();
  }

  ECMData<AMFSI::TerminalOpenResult> TerminalOpen(
      const AMFSI::TerminalOpenArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::TerminalOpenResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    terminal_window_ = OpenWindow_(args, terminal_window_);
    out.rcm = EnsureConnected_(false, control);
    if (out.rcm.code != ErrorCode::Success) {
      return out;
    }
    if (!IsTerminalAlive_()) {
      out.rcm = OpenChannel_(control);
    }
    out.data.opened = out.rcm.code == ErrorCode::Success && IsTerminalAlive_();
    return out;
  }

  ECMData<AMFSI::TerminalReadResult> TerminalRead(
      const AMFSI::TerminalReadArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::TerminalReadResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    if (!terminal_channel_ || !terminal_channel_->channel) {
      out.rcm = {ErrorCode::NoConnection, "terminal.read",
                 terminal_window_.term, "Interactive shell not initialized"};
      out.data.eof = true;
      return out;
    }
    const size_t max_bytes =
        (args.max_bytes == 0U ? static_cast<size_t>(32 * AMKB)
                              : args.max_bytes);
    auto drain_output = [&]() -> ECM {
      ECM read_rcm = ReadChunk_(terminal_channel_->channel, &out.data.output,
                                max_bytes, control,
                                [](LIBSSH2_CHANNEL *channel, char *buf,
                                   size_t size) {
                                  return libssh2_channel_read(channel, buf,
                                                              size);
                                });
      if (!(read_rcm)) {
        return read_rcm;
      }
      if (out.data.output.size() >= max_bytes || terminal_eof_) {
        return OK;
      }
      ECM stderr_rcm = ReadChunk_(
          terminal_channel_->channel, &out.data.output, max_bytes, control,
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
      out.data.eof = terminal_eof_;
      return out;
    }
    if (!out.data.output.empty() || terminal_eof_) {
      out.data.eof = terminal_eof_;
      return out;
    }

    if (control.RemainingTimeMs().has_value()) {
      const WaitResult wr = WaitSocket_(detail::SocketWaitType::Read, control);
      if (wr == WaitResult::Interrupted) {
        out.rcm = {ErrorCode::Terminate, "terminal.read", terminal_window_.term,
                   "Interrupted while waiting output"};
        out.data.eof = terminal_eof_;
        return out;
      }
      if (wr == WaitResult::Timeout) {
        out.rcm = {ErrorCode::OperationTimeout, "terminal.read",
                   terminal_window_.term, "Timed out while waiting output"};
        out.data.eof = terminal_eof_;
        return out;
      }
      if (wr == WaitResult::Error) {
        out.rcm = {ErrorCode::SocketRecvError, "terminal.read",
                   terminal_window_.term, "Socket error while waiting output"};
        out.data.eof = terminal_eof_;
        return out;
      }

      out.rcm = drain_output();
    }
    out.data.eof = terminal_eof_;
    return out;
  }

  ECMData<AMFSI::TerminalWriteResult> TerminalWrite(
      const AMFSI::TerminalWriteArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::TerminalWriteResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    if (!terminal_channel_ || !terminal_channel_->channel || terminal_eof_) {
      out.rcm = {ErrorCode::NoConnection, "terminal.write",
                 terminal_window_.term, "Interactive shell not initialized"};
      return out;
    }
    size_t offset = 0;
    while (offset < args.input.size()) {
      const ssize_t rc = libssh2_channel_write(
          terminal_channel_->channel, args.input.data() + offset,
          static_cast<int>(args.input.size() - offset));
      if (rc > 0) {
        offset += static_cast<size_t>(rc);
        continue;
      }
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        const WaitResult wr =
            WaitSocket_(detail::SocketWaitType::Write, control);
        if (wr == WaitResult::Ready) {
          continue;
        }
        if (wr == WaitResult::Interrupted) {
          out.rcm = {ErrorCode::Terminate, "terminal.write",
                     terminal_window_.term, "Interrupted while waiting write"};
        } else if (wr == WaitResult::Timeout) {
          out.rcm = {ErrorCode::OperationTimeout, "terminal.write",
                     terminal_window_.term, "Timed out while waiting write"};
        } else {
          out.rcm = {ErrorCode::SocketRecvError, "terminal.write",
                     terminal_window_.term, "Socket error while waiting write"};
        }
        out.data.bytes_written = offset;
        return out;
      }
      out.rcm = {LastEC_(), "terminal.write", terminal_window_.term,
                 LastError_()};
      out.data.bytes_written = offset;
      return out;
    }
    out.rcm = OK;
    out.data.bytes_written = offset;
    return out;
  }

  ECMData<AMFSI::TerminalResizeResult> TerminalResize(
      const AMFSI::TerminalResizeArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::TerminalResizeResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    ResizeWindow_(args, &terminal_window_);
    if (!terminal_channel_ || !terminal_channel_->channel || terminal_eof_) {
      out.rcm = OK;
      out.data.resized = false;
      return out;
    }
    auto resize_res = NBCall_(control, [&]() {
      return libssh2_channel_request_pty_size_ex(
          terminal_channel_->channel, terminal_window_.cols,
          terminal_window_.rows, terminal_window_.width,
          terminal_window_.height);
    });
    if (!resize_res || resize_res.value != 0) {
      out.rcm = {LastEC_(), "terminal.resize", terminal_window_.term,
                 LastError_()};
      out.data.resized = false;
      return out;
    }
    out.rcm = OK;
    out.data.resized = true;
    return out;
  }

  ECMData<AMFSI::TerminalCloseResult> TerminalClose(
      const AMFSI::TerminalCloseArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)control;
    ECMData<AMFSI::TerminalCloseResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    out.rcm = CloseChannel_(!args.force);
    out.data.closed = !IsTerminalAlive_();
    out.data.exit_code = terminal_exit_status_;
    if (out.rcm.code == ErrorCode::Success ||
        out.rcm.code == ErrorCode::Terminate ||
        out.rcm.code == ErrorCode::OperationTimeout) {
      out.rcm = OK;
    }
    return out;
  }

  ECMData<AMFSI::TerminalStatusResult> TerminalStatus(
      const AMFSI::TerminalStatusArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    (void)control;
    ECMData<AMFSI::TerminalStatusResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(mtx_);
    out.data.is_supported = true;
    out.data.is_open = IsTerminalAlive_();
    out.data.can_resize = true;
    out.data.status = status_;
    out.rcm = OK;
    return out;
  }
};

} // namespace AMInfra::client::SFTP::terminal
