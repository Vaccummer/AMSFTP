#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "Isocline/isocline.h"
#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/terminal.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <string_view>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace AMInterface::filesystem {
namespace {

AMDomain::client::ClientControlComponent
ResolveControl_(AMDomain::client::amf default_interrupt_flag,
                const std::optional<AMDomain::client::ClientControlComponent>
                    &control_opt) {
  return control_opt.has_value() ? control_opt.value()
                                 : AMDomain::client::ClientControlComponent(
                                       default_interrupt_flag, -1);
}

int ResolveTerminalOpTimeoutMs_(
    const AMDomain::client::ClientControlComponent &control,
    int configured_timeout_ms) {
  int effective_timeout_ms = configured_timeout_ms;
  if (effective_timeout_ms == 0) {
    effective_timeout_ms = -1;
  }
  if (effective_timeout_ms < -1) {
    effective_timeout_ms = -1;
  }

  const auto remain_opt = control.RemainingTimeMs();
  if (!remain_opt.has_value()) {
    return effective_timeout_ms;
  }
  const int remain_ms = static_cast<int>(std::min<unsigned int>(
      remain_opt.value(), static_cast<unsigned int>(std::numeric_limits<int>::max())));
  if (effective_timeout_ms < 0) {
    return remain_ms;
  }
  return std::min(effective_timeout_ms, remain_ms);
}

AMDomain::client::ClientControlComponent BuildTerminalOpControl_(
    const AMDomain::client::ClientControlComponent &control,
    int configured_timeout_ms) {
  return AMDomain::client::ClientControlComponent(
      control.ControlToken(),
      ResolveTerminalOpTimeoutMs_(control, configured_timeout_ms));
}

struct TerminalLoopOutcome_ {
  ECM rcm = OK;
  bool force_close = true;
};

[[nodiscard]] ECM BuildTerminalUnsupportedError_(const std::string &nickname) {
  return Err(EC::OperationUnsupported, "terminal", nickname,
             "Current client does not support interactive terminal mode");
}

constexpr const char *kDefaultTerminalType_ = "xterm-256color";

struct TerminalTargetSpec_ {
  std::string nickname = "local";
  std::optional<std::string> channel_name = std::nullopt;
};

[[nodiscard]] ECMData<TerminalTargetSpec_>
ParseTerminalTargetSpec_(const std::string &target_spec,
                         const std::string &default_nickname) {
  TerminalTargetSpec_ out = {};
  out.nickname =
      default_nickname.empty() ? std::string("local") : default_nickname;

  const std::string token = AMStr::Strip(target_spec);
  if (token.empty()) {
    return {out, OK};
  }

  const size_t at_pos = token.find('@');
  if (at_pos == std::string::npos) {
    out.channel_name = token;
    return {out, OK};
  }

  const std::string nickname_part = AMStr::Strip(token.substr(0, at_pos));
  const std::string channel_part = AMStr::Strip(token.substr(at_pos + 1));

  if (!nickname_part.empty()) {
    const std::string normalized =
        AMDomain::host::HostService::NormalizeNickname(nickname_part);
    if (!AMDomain::host::HostService::IsLocalNickname(normalized) &&
        !AMDomain::host::HostService::ValidateNickname(normalized)) {
      return {TerminalTargetSpec_{},
              Err(EC::InvalidArg, "launch_terminal.parse", nickname_part,
                  "Invalid nickname in terminal target spec")};
    }
    out.nickname = normalized.empty() ? out.nickname : normalized;
  }
  if (!channel_part.empty()) {
    out.channel_name = channel_part;
  } else {
    out.channel_name = std::nullopt;
  }

  return {out, OK};
}

void RestoreCliPromptStateAfterTerminalExit_() {
#ifdef _WIN32
  HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  if (input != INVALID_HANDLE_VALUE) {
    (void)FlushConsoleInputBuffer(input);
  }
#else
  (void)tcflush(STDIN_FILENO, TCIFLUSH);
#endif
  ic_term_reset();
  ic_term_flush();
}

class ScopedPromptOutputCache_ final : NonCopyableNonMovable {
public:
  explicit ScopedPromptOutputCache_(
      AMInterface::prompt::AMPromptIOManager *prompt_io_manager)
      : prompt_io_manager_(prompt_io_manager) {
    if (prompt_io_manager_ != nullptr) {
      prompt_io_manager_->SetCacheOutputOnly(true);
      active_ = true;
    }
  }

  ~ScopedPromptOutputCache_() override { Disable(); }

  void Disable() {
    if (!active_ || prompt_io_manager_ == nullptr) {
      return;
    }
    prompt_io_manager_->SetCacheOutputOnly(false);
    active_ = false;
  }

private:
  AMInterface::prompt::AMPromptIOManager *prompt_io_manager_ = nullptr;
  bool active_ = false;
};

std::string SubstituteTemplateVars_(
    const std::string &cmd_template,
    const std::unordered_map<std::string, std::string> &vars) {
  if (cmd_template.empty()) {
    return cmd_template;
  }
  std::string out = {};
  out.reserve(cmd_template.size());

  size_t i = 0;
  while (i < cmd_template.size()) {
    if (cmd_template[i] == '{' && i + 1 < cmd_template.size() &&
        cmd_template[i + 1] == '$') {
      const size_t close = cmd_template.find('}', i + 2);
      if (close == std::string::npos) {
        out.append(cmd_template.substr(i));
        break;
      }
      const std::string key =
          AMStr::Strip(cmd_template.substr(i + 2, close - (i + 2)));
      const auto it = vars.find(key);
      if (it != vars.end()) {
        out.append(it->second);
      } else {
        out.append(cmd_template.substr(i, close - i + 1));
      }
      i = close + 1;
      continue;
    }
    out.push_back(cmd_template[i]);
    ++i;
  }
  return out;
}

enum class LocalInputPollStatus_ { Ready, Closed, Error };
enum class TerminalWaitStatus_ {
  Ready,
  LocalInput,
  RemoteReady,
  Interrupted,
  Timeout,
  Error
};

struct TerminalWaitResult_ {
  TerminalWaitStatus_ status = TerminalWaitStatus_::Ready;
  std::string error = {};
};

void WriteTerminalBytes_(const std::string &text) {
  if (text.empty()) {
    return;
  }
  (void)std::fwrite(text.data(), 1, text.size(), stdout);
  std::fflush(stdout);
}

struct LocalControlInputProcessResult_ {
  std::string forward_bytes = {};
  bool request_exit = false;
};

LocalControlInputProcessResult_
ProcessLocalControlInput_(const std::string &input, bool *in_control_state) {
  LocalControlInputProcessResult_ result = {};
  if (in_control_state == nullptr || input.empty()) {
    return result;
  }

  result.forward_bytes.reserve(input.size());
  for (const char ch : input) {
    if (!(*in_control_state)) {
      if (ch == '\x1d') { // Ctrl+]
        *in_control_state = true;
        continue;
      }
      result.forward_bytes.push_back(ch);
      continue;
    }

    if (ch == 'q' || ch == 'Q') {
      result.request_exit = true;
      *in_control_state = false;
      break;
    }

    *in_control_state = false;
    result.forward_bytes.push_back(ch);
  }
  return result;
}

class ScopedRawTerminal_ final : public NonCopyableNonMovable {
public:
  ScopedRawTerminal_() = default;
  ~ScopedRawTerminal_() override { Restore(); }

  bool Activate() {
#ifdef _WIN32
    input_ = GetStdHandle(STD_INPUT_HANDLE);
    output_ = GetStdHandle(STD_OUTPUT_HANDLE);
    if (input_ == INVALID_HANDLE_VALUE || output_ == INVALID_HANDLE_VALUE) {
      error_ = "Console handle is invalid";
      return false;
    }
    if (GetConsoleMode(input_, &input_mode_) == 0) {
      error_ = "Failed to query console input mode";
      return false;
    }
    if (GetConsoleMode(output_, &output_mode_) == 0) {
      error_ = "Failed to query console output mode";
      return false;
    }

    DWORD raw_input_mode = input_mode_;
    raw_input_mode &=
        ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
    raw_input_mode |= ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_EXTENDED_FLAGS;
    raw_input_mode &=
        ~(ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_QUICK_EDIT_MODE);
    if (SetConsoleMode(input_, raw_input_mode) == 0) {
      error_ = "Failed to enable raw console input";
      return false;
    }

    DWORD raw_output_mode = output_mode_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    (void)SetConsoleMode(output_, raw_output_mode);
#else
    stdin_flags_ = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (stdin_flags_ < 0) {
      error_ = "Failed to query stdin flags";
      return false;
    }
    if (tcgetattr(STDIN_FILENO, &termios_) != 0) {
      error_ = "Failed to query terminal attributes";
      return false;
    }
    termios raw = termios_;
    raw.c_iflag &=
        static_cast<tcflag_t>(~(BRKINT | ICRNL | INPCK | ISTRIP | IXON));
    raw.c_oflag &= static_cast<tcflag_t>(~(OPOST));
    raw.c_cflag |= CS8;
    raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON | IEXTEN | ISIG));
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
      error_ = "Failed to enable raw terminal mode";
      return false;
    }
    if (fcntl(STDIN_FILENO, F_SETFL, stdin_flags_ | O_NONBLOCK) != 0) {
      error_ = "Failed to enable non-blocking stdin";
      (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_);
      return false;
    }
#endif
    active_ = true;
    return true;
  }

  void Restore() {
    if (!active_) {
      return;
    }
#ifdef _WIN32
    (void)SetConsoleMode(input_, input_mode_);
    (void)SetConsoleMode(output_, output_mode_);
#else
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_);
    (void)fcntl(STDIN_FILENO, F_SETFL, stdin_flags_);
#endif
    active_ = false;
  }

  [[nodiscard]] const std::string &Error() const { return error_; }

private:
  bool active_ = false;
  std::string error_ = {};
#ifdef _WIN32
  HANDLE input_ = INVALID_HANDLE_VALUE;
  HANDLE output_ = INVALID_HANDLE_VALUE;
  DWORD input_mode_ = 0;
  DWORD output_mode_ = 0;
#else
  termios termios_ = {};
  int stdin_flags_ = -1;
#endif
};

LocalInputPollStatus_ PollLocalTerminalInput_(std::string *out,
                                              std::string *error) {
  if (out == nullptr || error == nullptr) {
    return LocalInputPollStatus_::Error;
  }
  out->clear();
  error->clear();

#ifdef _WIN32
  HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  if (input == INVALID_HANDLE_VALUE) {
    *error = "Console input handle is invalid";
    return LocalInputPollStatus_::Error;
  }
  while (true) {
    DWORD event_count = 0;
    if (GetNumberOfConsoleInputEvents(input, &event_count) == 0) {
      *error = "Console input event query failed";
      return LocalInputPollStatus_::Error;
    }
    if (event_count == 0) {
      return LocalInputPollStatus_::Ready;
    }

    INPUT_RECORD record = {};
    DWORD peeked = 0;
    if (PeekConsoleInputW(input, &record, 1, &peeked) == 0) {
      *error = "Console input peek failed";
      return LocalInputPollStatus_::Error;
    }
    if (peeked == 0) {
      return LocalInputPollStatus_::Ready;
    }

    const bool key_down =
        record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown;
    if (key_down) {
      break;
    }

    DWORD consumed = 0;
    if (ReadConsoleInputW(input, &record, 1, &consumed) == 0) {
      *error = "Console input consume failed";
      return LocalInputPollStatus_::Error;
    }
    if (consumed == 0) {
      return LocalInputPollStatus_::Ready;
    }
  }

  const DWORD wait_rc = WaitForSingleObject(input, 0);
  if (wait_rc == WAIT_TIMEOUT) {
    return LocalInputPollStatus_::Ready;
  }
  if (wait_rc != WAIT_OBJECT_0) {
    *error = "Console input wait failed";
    return LocalInputPollStatus_::Error;
  }

  std::array<char, 256> buffer = {};
  DWORD read_bytes = 0;
  if (ReadFile(input, buffer.data(), static_cast<DWORD>(buffer.size()),
               &read_bytes, nullptr) == 0) {
    *error = "Console input read failed";
    return LocalInputPollStatus_::Error;
  }
  if (read_bytes == 0) {
    return LocalInputPollStatus_::Ready;
  }
  out->assign(buffer.data(), static_cast<size_t>(read_bytes));
  return LocalInputPollStatus_::Ready;
#else
  std::array<char, 256> buffer = {};
  const ssize_t nread = read(STDIN_FILENO, buffer.data(), buffer.size());
  if (nread > 0) {
    out->assign(buffer.data(), static_cast<size_t>(nread));
    return LocalInputPollStatus_::Ready;
  }
  if (nread == 0) {
    return LocalInputPollStatus_::Closed;
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
    return LocalInputPollStatus_::Ready;
  }
  *error = std::strerror(errno);
  return LocalInputPollStatus_::Error;
#endif
}

class InteractiveTerminalWaiter_ final : NonCopyableNonMovable {
public:
  InteractiveTerminalWaiter_(
      AMDomain::terminal::ITerminalPort &terminal,
      const AMDomain::client::ClientControlComponent &control)
      : terminal_(terminal), control_(control) {}

  ~InteractiveTerminalWaiter_() override { Shutdown_(); }

  ECM Init() {
    if (initialized_) {
      return OK;
    }
    auto remote_socket_result = terminal_.GetRemoteSocketHandle();
    if (remote_socket_result.rcm && remote_socket_result.data >= 0) {
      remote_socket_ = remote_socket_result.data;
    }

#ifdef _WIN32
    InitWindows_();
#else
    InitPosix_();
#endif

    initialized_ = true;
    return OK;
  }

  [[nodiscard]] TerminalWaitResult_ Wait() {
    if (control_.IsInterrupted()) {
      return {TerminalWaitStatus_::Interrupted, {}};
    }
    if (control_.IsTimeout()) {
      return {TerminalWaitStatus_::Timeout, {}};
    }
    if (!initialized_) {
      return {TerminalWaitStatus_::Error,
              "InteractiveTerminalWaiter not initialized"};
    }

#ifdef _WIN32
    return WaitWindows_();
#else
    return WaitPosix_();
#endif
  }

private:
#ifdef _WIN32
  static constexpr DWORD kInvalidIndex_ = static_cast<DWORD>(-1);

  void PushWaitHandle_(HANDLE handle, DWORD *index_slot) {
    if (index_slot == nullptr || handle == nullptr ||
        handle == INVALID_HANDLE_VALUE || wait_count_ >= wait_handles_.size()) {
      return;
    }
    *index_slot = wait_count_;
    wait_handles_[wait_count_++] = handle;
  }

  void InitWindows_() {
    input_handle_ = GetStdHandle(STD_INPUT_HANDLE);
    PushWaitHandle_(input_handle_, &input_index_);

    if (control_.ControlToken()) {
      wake_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
      if (wake_event_ != nullptr) {
        wake_guard_ =
            std::make_unique<AMDomain::client::ControlTokenWakeupSafeGaurd>(
                control_.ControlToken(),
                [wake_event = wake_event_]() { (void)SetEvent(wake_event); });
        PushWaitHandle_(wake_event_, &wake_index_);
      }
    }

    if (remote_socket_ >= 0) {
      remote_sock_ = static_cast<SOCKET>(remote_socket_);
      socket_event_ = WSACreateEvent();
      if (socket_event_ != WSA_INVALID_EVENT) {
        if (WSAEventSelect(remote_sock_, socket_event_,
                           FD_READ | FD_WRITE | FD_CLOSE) == 0) {
          PushWaitHandle_(socket_event_, &socket_index_);
        } else {
          (void)WSACloseEvent(socket_event_);
          socket_event_ = WSA_INVALID_EVENT;
          remote_sock_ = INVALID_SOCKET;
        }
      }
    }
  }

  [[nodiscard]] TerminalWaitResult_ WaitWindows_() {
    if (wait_count_ == 0) {
      return {TerminalWaitStatus_::Ready, {}};
    }

    const auto remain_opt = control_.RemainingTimeMs();
    DWORD timeout_ms = INFINITE;
    if (remain_opt.has_value()) {
      timeout_ms = static_cast<DWORD>(std::min<unsigned int>(
          *remain_opt, (std::numeric_limits<DWORD>::max)()));
    }

    const DWORD wait_rc = WaitForMultipleObjects(
        wait_count_, wait_handles_.data(), FALSE, timeout_ms);
    if (wait_rc == WAIT_TIMEOUT) {
      return {TerminalWaitStatus_::Timeout, {}};
    }
    if (wait_rc == WAIT_FAILED) {
      return {TerminalWaitStatus_::Error,
              AMStr::fmt("WaitForMultipleObjects failed: {}",
                         static_cast<unsigned long>(GetLastError()))};
    }

    const DWORD signaled_index = wait_rc - WAIT_OBJECT_0;
    if (wake_index_ != kInvalidIndex_ && signaled_index == wake_index_) {
      return {control_.IsInterrupted() ? TerminalWaitStatus_::Interrupted
                                       : TerminalWaitStatus_::Ready,
              {}};
    }
    if (socket_index_ != kInvalidIndex_ && signaled_index == socket_index_) {
      if (socket_event_ != WSA_INVALID_EVENT &&
          remote_sock_ != INVALID_SOCKET) {
        WSANETWORKEVENTS events = {};
        (void)WSAEnumNetworkEvents(remote_sock_, socket_event_, &events);
      }
      return {TerminalWaitStatus_::RemoteReady, {}};
    }
    if (input_index_ != kInvalidIndex_ && signaled_index == input_index_) {
      return {TerminalWaitStatus_::LocalInput, {}};
    }
    return {TerminalWaitStatus_::Ready, {}};
  }

  void ShutdownWindows_() {
    wake_guard_.reset();

    if (socket_event_ != WSA_INVALID_EVENT) {
      if (remote_sock_ != INVALID_SOCKET) {
        (void)WSAEventSelect(remote_sock_, socket_event_, 0);
      }
      (void)WSACloseEvent(socket_event_);
      socket_event_ = WSA_INVALID_EVENT;
    }
    if (wake_event_ != nullptr) {
      (void)CloseHandle(wake_event_);
      wake_event_ = nullptr;
    }
    remote_sock_ = INVALID_SOCKET;
    input_handle_ = INVALID_HANDLE_VALUE;
    wait_count_ = 0;
    wait_handles_ = {};
    input_index_ = kInvalidIndex_;
    wake_index_ = kInvalidIndex_;
    socket_index_ = kInvalidIndex_;
  }
#else
  void InitPosix_() {
    if (control_.ControlToken() && pipe(wake_pipe_) == 0) {
      const int read_flags = fcntl(wake_pipe_[0], F_GETFL, 0);
      const int write_flags = fcntl(wake_pipe_[1], F_GETFL, 0);
      if (read_flags >= 0) {
        (void)fcntl(wake_pipe_[0], F_SETFL, read_flags | O_NONBLOCK);
      }
      if (write_flags >= 0) {
        (void)fcntl(wake_pipe_[1], F_SETFL, write_flags | O_NONBLOCK);
      }
      wake_guard_ =
          std::make_unique<AMDomain::client::ControlTokenWakeupSafeGaurd>(
              control_.ControlToken(), [wake_write_fd = wake_pipe_[1]]() {
                const char c = 1;
                (void)write(wake_write_fd, &c, 1);
              });
    } else {
      wake_pipe_[0] = -1;
      wake_pipe_[1] = -1;
    }

    if (remote_socket_ >= 0) {
      const int remote_fd = static_cast<int>(remote_socket_);
      if (remote_fd >= 0 && remote_fd < FD_SETSIZE) {
        remote_fd_ = remote_fd;
      }
    }
  }

  [[nodiscard]] TerminalWaitResult_ WaitPosix_() {
    fd_set readfds = {};
    FD_ZERO(&readfds);
    int max_fd = -1;

    FD_SET(STDIN_FILENO, &readfds);
    max_fd = std::max(max_fd, STDIN_FILENO);

    if (remote_fd_ >= 0) {
      FD_SET(remote_fd_, &readfds);
      max_fd = std::max(max_fd, remote_fd_);
    }
    if (wake_pipe_[0] >= 0 && wake_pipe_[0] < FD_SETSIZE) {
      FD_SET(wake_pipe_[0], &readfds);
      max_fd = std::max(max_fd, wake_pipe_[0]);
    }

    if (max_fd < 0) {
      return {TerminalWaitStatus_::Ready, {}};
    }

    const auto remain_opt = control_.RemainingTimeMs();
    timeval tv = {};
    timeval *timeout_ptr = nullptr;
    if (remain_opt.has_value()) {
      const unsigned int remain_ms = *remain_opt;
      tv.tv_sec = static_cast<time_t>(remain_ms / 1000U);
      tv.tv_usec = static_cast<suseconds_t>((remain_ms % 1000U) * 1000U);
      timeout_ptr = &tv;
    }

    const int rc = select(max_fd + 1, &readfds, nullptr, nullptr, timeout_ptr);
    if (rc < 0) {
      if (errno == EINTR) {
        return {control_.IsInterrupted() ? TerminalWaitStatus_::Interrupted
                                         : TerminalWaitStatus_::Ready,
                {}};
      }
      return {TerminalWaitStatus_::Error, std::strerror(errno)};
    }
    if (rc == 0) {
      return {TerminalWaitStatus_::Timeout, {}};
    }

    if (wake_pipe_[0] >= 0 && FD_ISSET(wake_pipe_[0], &readfds)) {
      std::array<char, 64> drain_buffer = {};
      while (read(wake_pipe_[0], drain_buffer.data(), drain_buffer.size()) >
             0) {
      }
    }

    if (control_.IsInterrupted()) {
      return {TerminalWaitStatus_::Interrupted, {}};
    }
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      return {TerminalWaitStatus_::LocalInput, {}};
    }
    if (remote_fd_ >= 0 && FD_ISSET(remote_fd_, &readfds)) {
      return {TerminalWaitStatus_::RemoteReady, {}};
    }
    return {TerminalWaitStatus_::Ready, {}};
  }

  void ShutdownPosix_() {
    wake_guard_.reset();
    if (wake_pipe_[0] >= 0) {
      (void)close(wake_pipe_[0]);
      wake_pipe_[0] = -1;
    }
    if (wake_pipe_[1] >= 0) {
      (void)close(wake_pipe_[1]);
      wake_pipe_[1] = -1;
    }
    remote_fd_ = -1;
  }
#endif

  void Shutdown_() {
    if (!initialized_) {
      return;
    }
#ifdef _WIN32
    ShutdownWindows_();
#else
    ShutdownPosix_();
#endif
    initialized_ = false;
  }

private:
  AMDomain::terminal::ITerminalPort &terminal_;
  const AMDomain::client::ClientControlComponent &control_;
  bool initialized_ = false;
  std::intptr_t remote_socket_ = -1;

#ifdef _WIN32
  std::array<HANDLE, 3> wait_handles_ = {nullptr, nullptr, nullptr};
  DWORD wait_count_ = 0;
  DWORD input_index_ = kInvalidIndex_;
  DWORD wake_index_ = kInvalidIndex_;
  DWORD socket_index_ = kInvalidIndex_;
  HANDLE input_handle_ = INVALID_HANDLE_VALUE;
  HANDLE wake_event_ = nullptr;
  SOCKET remote_sock_ = INVALID_SOCKET;
  WSAEVENT socket_event_ = WSA_INVALID_EVENT;
  std::unique_ptr<AMDomain::client::ControlTokenWakeupSafeGaurd> wake_guard_ =
      nullptr;
#else
  int wake_pipe_[2] = {-1, -1};
  int remote_fd_ = -1;
  std::unique_ptr<AMDomain::client::ControlTokenWakeupSafeGaurd> wake_guard_ =
      nullptr;
#endif
};

[[nodiscard]] AMDomain::terminal::ChannelOpenArgs
BuildChannelOpenArgs_(const std::string &channel_name,
                      const AMTerminalTools::TerminalViewportInfo &geometry) {
  AMDomain::terminal::ChannelOpenArgs args = {};
  args.channel_name = channel_name;
  args.cols = geometry.cols;
  args.rows = geometry.rows;
  args.width = geometry.width;
  args.height = geometry.height;
  args.term = kDefaultTerminalType_;
  return args;
}

ECM ExecuteTerminalSession_(
    AMDomain::terminal::ITerminalPort &terminal,
    const TerminalTargetSpec_ &target,
    const AMDomain::client::ClientControlComponent &control,
    int read_timeout_ms,
    int send_timeout_ms,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager) {
  enum class BreakReason_ {
    None = 0,
    LocalEscape,
    RemoteChannelClosed,
    ConnectionBroken,
    Interrupted,
    Timeout,
    Error
  };

  const AMTerminalTools::TerminalViewportInfo geometry =
      AMTerminalTools::GetTerminalViewportInfo();
  auto status_result = terminal.CheckSession({}, control);
  if (!status_result.rcm) {
    if (status_result.rcm.code == EC::OperationUnsupported) {
      return BuildTerminalUnsupportedError_(target.nickname);
    }
    return status_result.rcm;
  }
  if (!status_result.data.is_supported) {
    return BuildTerminalUnsupportedError_(target.nickname);
  }

  std::string channel_name = {};
  bool refresh_prompt_on_enter = false;
  const std::string requested_channel =
      target.channel_name.has_value() ? AMStr::Strip(*target.channel_name) : "";

  if (!requested_channel.empty()) {
    auto check_result = terminal.CheckChannel(
        {std::optional<std::string>(requested_channel)}, control);
    if (!(check_result.rcm)) {
      if (check_result.rcm.code != EC::ClientNotFound) {
        return check_result.rcm;
      }
      auto open_result = terminal.OpenChannel(
          BuildChannelOpenArgs_(requested_channel, geometry), control);
      if (!(open_result.rcm) &&
          open_result.rcm.code != EC::TargetAlreadyExists) {
        return open_result.rcm;
      }
    } else {
      if (!check_result.data.exists || !check_result.data.is_open) {
        return Err(EC::NoConnection, "terminal.channel.check",
                   requested_channel, "Target channel is not available");
      }
      refresh_prompt_on_enter = true;
    }

    auto active_result = terminal.ActiveChannel({requested_channel}, control);
    if (!(active_result.rcm) || !active_result.data.activated) {
      return active_result.rcm
                 ? Err(EC::CommonFailure, "terminal.channel.active",
                       requested_channel, "Failed to activate terminal channel")
                 : active_result.rcm;
    }
    channel_name = requested_channel;
  } else {
    const std::string current_channel =
        AMStr::Strip(status_result.data.current_channel);
    if (current_channel.empty()) {
      return Err(EC::InvalidArg, "terminal.channel.current", target.nickname,
                 "No active channel in terminal");
    }
    auto check_result = terminal.CheckChannel({std::nullopt}, control);
    if (!(check_result.rcm)) {
      return check_result.rcm;
    }
    if (!check_result.data.exists || !check_result.data.is_open) {
      return Err(EC::NoConnection, "terminal.channel.current", current_channel,
                 "Current channel is not available");
    }
    refresh_prompt_on_enter = true;
    channel_name = check_result.data.channel_name.empty()
                       ? current_channel
                       : check_result.data.channel_name;
  }

  ScopedPromptOutputCache_ prompt_cache_guard(&prompt_io_manager);
  ScopedRawTerminal_ raw_terminal = {};
  if (!raw_terminal.Activate()) {
    prompt_cache_guard.Disable();
    return Err(EC::CommonFailure, "terminal.raw_mode", "<stdin>",
               raw_terminal.Error());
  }
  InteractiveTerminalWaiter_ terminal_waiter(terminal, control);
  ECM wait_init_rcm = terminal_waiter.Init();
  if (!wait_init_rcm) {
    raw_terminal.Restore();
    prompt_cache_guard.Disable();
    return wait_init_rcm;
  }

  TerminalLoopOutcome_ loop_outcome = {};
  AMTerminalTools::TerminalViewportInfo last_geometry =
      AMTerminalTools::GetTerminalViewportInfo();
  auto initial_resize_result = terminal.ResizeChannel(
      AMDomain::terminal::ChannelResizeArgs{
          std::optional<std::string>(channel_name), last_geometry.cols,
          last_geometry.rows, last_geometry.width, last_geometry.height},
      control);
  if (!(initial_resize_result.rcm)) {
    raw_terminal.Restore();
    RestoreCliPromptStateAfterTerminalExit_();
    prompt_cache_guard.Disable();
    prompt_io_manager.Print("");
    return initial_resize_result.rcm;
  }
  bool pending_prompt_refresh = refresh_prompt_on_enter;
  bool in_local_control_state = false;
  BreakReason_ break_reason = BreakReason_::None;

  while (true) {
    bool had_activity = false;
    if (control.IsInterrupted()) {
      loop_outcome = {Err(EC::Terminate, "terminal.loop", "<terminal>",
                          "Terminal interrupted"),
                      true};
      break_reason = BreakReason_::Interrupted;
      break;
    }
    if (control.IsTimeout()) {
      loop_outcome = {Err(EC::OperationTimeout, "terminal.loop", "<terminal>",
                          "Terminal timed out"),
                      true};
      break_reason = BreakReason_::Timeout;
      break;
    }

    if (pending_prompt_refresh) {
      const auto write_control =
          BuildTerminalOpControl_(control, send_timeout_ms);
      auto write_result = terminal.WriteChannel(
          AMDomain::terminal::ChannelWriteArgs{
              std::optional<std::string>(channel_name), "\n"},
          write_control);
      if (!write_result.rcm) {
        loop_outcome = {write_result.rcm, true};
        break_reason = BreakReason_::Error;
        break;
      }
      pending_prompt_refresh = false;
      had_activity = true;
    }

    std::string input = {};
    std::string input_error = {};
    const auto input_status = PollLocalTerminalInput_(&input, &input_error);
    if (input_status == LocalInputPollStatus_::Error) {
      loop_outcome = {Err(EC::LocalFileReadError, "terminal.input", "<stdin>",
                          input_error.empty() ? "Local terminal input failed"
                                              : input_error),
                      true};
      break_reason = BreakReason_::Error;
      break;
    }
    if (input_status == LocalInputPollStatus_::Closed) {
      loop_outcome = {OK, false};
      break_reason = BreakReason_::LocalEscape;
      break;
    }

    const auto control_process_result =
        ProcessLocalControlInput_(input, &in_local_control_state);
    if (!control_process_result.forward_bytes.empty()) {
      had_activity = true;
      const auto write_control =
          BuildTerminalOpControl_(control, send_timeout_ms);
      auto write_result = terminal.WriteChannel(
          AMDomain::terminal::ChannelWriteArgs{
              std::optional<std::string>(channel_name),
              control_process_result.forward_bytes},
          write_control);
      if (!write_result.rcm) {
        loop_outcome = {write_result.rcm, true};
        break_reason = BreakReason_::Error;
        break;
      }
    }
    if (control_process_result.request_exit) {
      loop_outcome = {OK, false};
      break_reason = BreakReason_::LocalEscape;
      break;
    }

    const AMTerminalTools::TerminalViewportInfo current_geometry =
        AMTerminalTools::GetTerminalViewportInfo();
    if (current_geometry.cols != last_geometry.cols ||
        current_geometry.rows != last_geometry.rows ||
        current_geometry.width != last_geometry.width ||
        current_geometry.height != last_geometry.height) {
      auto resize_result = terminal.ResizeChannel(
          AMDomain::terminal::ChannelResizeArgs{
              std::optional<std::string>(channel_name), current_geometry.cols,
              current_geometry.rows, current_geometry.width,
              current_geometry.height},
          control);
      if (!(resize_result.rcm)) {
        loop_outcome = {resize_result.rcm, true};
        break_reason = BreakReason_::Error;
        break;
      }
      last_geometry = current_geometry;
      had_activity = true;
    }

    const auto read_control = BuildTerminalOpControl_(control, read_timeout_ms);
    auto read_result = terminal.ReadChannel(
        AMDomain::terminal::ChannelReadArgs{
            std::optional<std::string>(channel_name), 32U * 1024U},
        read_control);
    if (!read_result.rcm) {
      if (read_result.rcm.code == EC::OperationTimeout) {
        continue;
      }
      bool classify_remote_closed = false;
      const auto session_state = terminal.GetSessionState();
      auto check_result = terminal.CheckChannel(
          {std::optional<std::string>(channel_name)}, control);
      if (session_state == AMDomain::client::ClientStatus::OK) {
        if ((check_result.rcm &&
             (!check_result.data.exists || !check_result.data.is_open)) ||
            (check_result.rcm.code == EC::ClientNotFound)) {
          classify_remote_closed = true;
        }
      }
      loop_outcome = {read_result.rcm, true};
      break_reason =
          classify_remote_closed
              ? BreakReason_::RemoteChannelClosed
              : ((session_state ==
                      AMDomain::client::ClientStatus::NoConnection ||
                  session_state ==
                      AMDomain::client::ClientStatus::ConnectionBroken)
                     ? BreakReason_::ConnectionBroken
                     : BreakReason_::Error);
      break;
    }
    if (!read_result.data.output.empty()) {
      WriteTerminalBytes_(read_result.data.output);
      had_activity = true;
    }
    if (read_result.data.eof) {
      loop_outcome = {OK, false};
      break_reason = BreakReason_::RemoteChannelClosed;
      break;
    }
    if (!had_activity) {
      const TerminalWaitResult_ wait_result = terminal_waiter.Wait();
      if (wait_result.status == TerminalWaitStatus_::Interrupted) {
        loop_outcome = {Err(EC::Terminate, "terminal.wait", "<terminal>",
                            "Terminal interrupted"),
                        true};
        break_reason = BreakReason_::Interrupted;
        break;
      }
      if (wait_result.status == TerminalWaitStatus_::Timeout) {
        loop_outcome = {Err(EC::OperationTimeout, "terminal.wait", "<terminal>",
                            "Terminal wait timed out"),
                        true};
        break_reason = BreakReason_::Timeout;
        break;
      }
      if (wait_result.status == TerminalWaitStatus_::Error) {
        const auto session_state = terminal.GetSessionState();
        loop_outcome = {Err(EC::SocketRecvError, "terminal.wait", "<terminal>",
                            wait_result.error.empty() ? "Terminal wait failed"
                                                      : wait_result.error),
                        true};
        break_reason =
            (session_state == AMDomain::client::ClientStatus::NoConnection ||
             session_state == AMDomain::client::ClientStatus::ConnectionBroken)
                ? BreakReason_::ConnectionBroken
                : BreakReason_::Error;
        break;
      }
    }
  }

  raw_terminal.Restore();
  RestoreCliPromptStateAfterTerminalExit_();
  prompt_cache_guard.Disable();
  prompt_io_manager.Print("");

  ECM final_rcm = loop_outcome.rcm;
  if (break_reason == BreakReason_::RemoteChannelClosed) {
    auto close_result = terminal.CloseChannel({channel_name, true}, control);
    if (!close_result.rcm && close_result.rcm.code != EC::ClientNotFound &&
        final_rcm.code == EC::Success) {
      final_rcm = close_result.rcm;
    }
  }
  return final_rcm;
}
} // namespace

ECM FilesystemInterfaceSerivce::ShellRun(
    const FilesystemShellRunArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const std::string command = AMStr::Strip(arg.cmd);
  if (command.empty()) {
    const ECM rcm = Err(EC::InvalidArg, __func__, "", "cmd cannot be empty");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (arg.max_time_s < -1) {
    const ECM rcm =
        Err(EC::InvalidArg, __func__, "", "max_time_s must be >= -1");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto base_control =
      ResolveControl_(default_interrupt_flag_, control_opt);
  AMDomain::client::ClientControlComponent run_control = base_control;
  if (arg.max_time_s >= 0) {
    constexpr int kMaxSafeSeconds = std::numeric_limits<int>::max() / 1000;
    const int safe_seconds = std::min(arg.max_time_s, kMaxSafeSeconds);
    run_control = AMDomain::client::ClientControlComponent(
        base_control.ControlToken(), safe_seconds * 1000);
  }

  std::string nickname = filesystem_service_.CurrentNickname();
  if (nickname.empty()) {
    nickname = "local";
  }

  std::string final_cmd = command;
  auto metadata_client_result = client_service_.GetClient(nickname, true);
  if ((metadata_client_result.rcm) && metadata_client_result.data) {
    auto metadata_opt =
        AMApplication::client::ClientAppService::GetClientMetadata(
            metadata_client_result.data);
    if (metadata_opt.has_value()) {
      const std::string cmd_template = AMStr::Strip(metadata_opt->cmd_template);
      if (!cmd_template.empty()) {
        std::unordered_map<std::string, std::string> vars = {};
        const auto dict = metadata_opt->GetStrDict();
        vars.reserve(dict.size() + 2);
        for (const auto &entry : dict) {
          vars[entry.first] = entry.second;
        }
        vars["cmd"] = command;
        vars["escaped_cmd"] = command;
        final_cmd = SubstituteTemplateVars_(cmd_template, vars);
      }
    }
  }

  prompt_io_manager_.FmtPrint("Final cmd: {}", final_cmd);

  auto client_result = filesystem_service_.GetClient(nickname, run_control);
  if (!(client_result.rcm) || !client_result.data) {
    const ECM rcm = (client_result.rcm) ? Err(EC::InvalidHandle, __func__, "",
                                              "Resolved client is null")
                                        : client_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto shell_result = client_result.data->IOPort().ConductCmd(
      {final_cmd,
       [this](std::string_view chunk) {
         if (chunk.empty()) {
           return;
         }
         prompt_io_manager_.PrintRaw(std::string(chunk));
       }},
      run_control);
  prompt_io_manager_.FmtPrint("Exit with code {}", shell_result.data.exit_code);

  if (!(shell_result.rcm)) {
    prompt_io_manager_.ErrorFormat(shell_result.rcm);
    return shell_result.rcm;
  }
  return OK;
}

ECM FilesystemInterfaceSerivce::LaunchTerminal(
    const FilesystemTerminalArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const auto fs_arg = filesystem_service_.GetInitArg();
  const int read_timeout_ms = fs_arg.terminal_read_timeout_ms;
  const int send_timeout_ms = fs_arg.terminal_send_timeout_ms;
  std::string default_nickname = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(filesystem_service_.CurrentNickname()));
  if (default_nickname.empty()) {
    default_nickname = "local";
  }

  auto target_result = ParseTerminalTargetSpec_(arg.target, default_nickname);

  if (!target_result.rcm) {
    prompt_io_manager_.ErrorFormat(target_result.rcm);
    return target_result.rcm;
  }

  const TerminalTargetSpec_ target = target_result.data;

  auto managed_terminal_result =
      terminal_service_.GetTerminalByNickname(target.nickname, false);

  if (managed_terminal_result.rcm && managed_terminal_result.data) {
    const ECM run_rcm = ExecuteTerminalSession_(
        *(managed_terminal_result.data), target, control, read_timeout_ms,
        send_timeout_ms, prompt_io_manager_);
    if (!run_rcm) {
      prompt_io_manager_.ErrorFormat(run_rcm);
    }
    return run_rcm;
  }

  if (managed_terminal_result.rcm && !managed_terminal_result.data) {
    const ECM rcm = Err(EC::InvalidHandle, __func__, target.nickname,
                        "Managed terminal handle is null");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  if (managed_terminal_result.rcm.code != EC::ClientNotFound) {
    prompt_io_manager_.ErrorFormat(managed_terminal_result.rcm);
    return managed_terminal_result.rcm;
  }

  auto temp_client_result =
      client_service_.CreateClient(target.nickname, control, false, false);
  if (!temp_client_result.rcm || !temp_client_result.data) {
    const ECM rcm = temp_client_result.rcm
                        ? Err(EC::InvalidHandle, __func__, target.nickname,
                              "Temporary client is null")
                        : temp_client_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto temp_terminal_result =
      terminal_service_.CreateTerminal(temp_client_result.data, false);
  if (!(temp_terminal_result.rcm) || !temp_terminal_result.data) {
    const ECM rcm = (temp_terminal_result.rcm.code == EC::OperationUnsupported)
                        ? BuildTerminalUnsupportedError_(target.nickname)
                        : temp_terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const ECM run_rcm = ExecuteTerminalSession_(
      *temp_terminal_result.data, target, control, read_timeout_ms,
      send_timeout_ms, prompt_io_manager_);
  if (!(run_rcm)) {
    prompt_io_manager_.ErrorFormat(run_rcm);
  }
  return run_rcm;
}

ECM FilesystemInterfaceSerivce::AddTerminal(
    const FilesystemTermAddArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string nickname = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(arg.nickname));
  if (nickname.empty()) {
    nickname = AMDomain::host::HostService::NormalizeNickname(
        AMStr::Strip(filesystem_service_.CurrentNickname()));
  }
  if (nickname.empty()) {
    nickname = "local";
  }

  auto existing = terminal_service_.GetTerminalByNickname(nickname, false);
  if (existing.rcm && existing.data) {
    if (!arg.force) {
      const ECM rcm = Err(EC::TargetAlreadyExists, __func__, nickname,
                          "Terminal already exists");
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
    const ECM rm_rcm = terminal_service_.RemoveTerminal(nickname, control);
    if (!(rm_rcm)) {
      prompt_io_manager_.ErrorFormat(rm_rcm);
      return rm_rcm;
    }
  } else if (existing.rcm.code != EC::ClientNotFound) {
    prompt_io_manager_.ErrorFormat(existing.rcm);
    return existing.rcm;
  }

  auto client_result = client_service_.CreateClient(nickname, control, false);
  if (!(client_result.rcm) || !client_result.data) {
    const ECM rcm = (client_result.rcm)
                        ? Err(EC::InvalidHandle, __func__, nickname,
                              "Created client is null")
                        : client_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto terminal_result =
      terminal_service_.CreateTerminal(client_result.data, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = (terminal_result.rcm.code == EC::OperationUnsupported)
                        ? BuildTerminalUnsupportedError_(nickname)
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  prompt_io_manager_.FmtPrint("✅ Terminal added: {}", nickname);
  return OK;
}

ECM FilesystemInterfaceSerivce::ListTerminals(
    const FilesystemTermListArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  (void)arg;
  (void)control_opt;
  const auto names = terminal_service_.ListTerminalNames();
  prompt_io_manager_.Print("Terminals:");
  if (names.empty()) {
    prompt_io_manager_.Print("  (empty)");
    return OK;
  }
  for (const auto &name : names) {
    auto terminal_result = terminal_service_.GetTerminalByNickname(name, true);
    if (!(terminal_result.rcm) || !terminal_result.data) {
      prompt_io_manager_.FmtPrint("  - {} (unknown)", name);
      continue;
    }
    const auto state = terminal_result.data->GetSessionState();
    std::string state_name = "Unknown";
    switch (state) {
    case AMDomain::client::ClientStatus::NotInitialized:
      state_name = "NotInitialized";
      break;
    case AMDomain::client::ClientStatus::NoConnection:
      state_name = "NoConnection";
      break;
    case AMDomain::client::ClientStatus::ConnectionBroken:
      state_name = "ConnectionBroken";
      break;
    case AMDomain::client::ClientStatus::OK:
      state_name = "OK";
      break;
    default:
      break;
    }
    prompt_io_manager_.FmtPrint("  - {} ({})", name, state_name);
  }
  return OK;
}

ECM FilesystemInterfaceSerivce::RemoveTerminal(
    const FilesystemTermRemoveArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string nickname = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(arg.nickname));
  if (nickname.empty()) {
    nickname = AMDomain::host::HostService::NormalizeNickname(
        AMStr::Strip(filesystem_service_.CurrentNickname()));
  }
  if (nickname.empty()) {
    nickname = "local";
  }

  const ECM rcm = terminal_service_.RemoveTerminal(nickname, control);
  if (!(rcm)) {
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  prompt_io_manager_.FmtPrint("✅ Terminal removed: {}", nickname);
  return OK;
}

ECM FilesystemInterfaceSerivce::AddChannel(
    const FilesystemChannelAddArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string default_nickname = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(filesystem_service_.CurrentNickname()));
  if (default_nickname.empty()) {
    default_nickname = "local";
  }

  auto target_result = ParseTerminalTargetSpec_(arg.target, default_nickname);
  if (!(target_result.rcm)) {
    prompt_io_manager_.ErrorFormat(target_result.rcm);
    return target_result.rcm;
  }
  const TerminalTargetSpec_ target = target_result.data;
  const std::string channel_name =
      target.channel_name.has_value() ? AMStr::Strip(*target.channel_name) : "";
  if (channel_name.empty()) {
    const ECM rcm =
        Err(EC::InvalidArg, __func__, arg.target, "Channel name is required");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(target.nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm
                        ? Err(EC::InvalidHandle, __func__, target.nickname,
                              "Terminal handle is null")
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (terminal_result.data->GetSessionState() !=
      AMDomain::client::ClientStatus::OK) {
    const ECM rcm = Err(EC::NoConnection, __func__, target.nickname,
                        "Terminal session is disconnected");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const AMTerminalTools::TerminalViewportInfo geometry =
      AMTerminalTools::GetTerminalViewportInfo();
  auto open_result = terminal_result.data->OpenChannel(
      BuildChannelOpenArgs_(channel_name, geometry), control);
  if (!(open_result.rcm)) {
    prompt_io_manager_.ErrorFormat(open_result.rcm);
    return open_result.rcm;
  }
  prompt_io_manager_.FmtPrint("✅ Channel added: {}@{}", target.nickname,
                              channel_name);
  return OK;
}

ECM FilesystemInterfaceSerivce::ListChannels(
    const FilesystemChannelListArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string nickname = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(arg.nickname));
  if (nickname.empty()) {
    nickname = AMDomain::host::HostService::NormalizeNickname(
        AMStr::Strip(filesystem_service_.CurrentNickname()));
  }
  if (nickname.empty()) {
    nickname = "local";
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm
                        ? Err(EC::InvalidHandle, __func__, nickname,
                              "Terminal handle is null")
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto list_result = terminal_result.data->ListChannels({}, control);
  if (!(list_result.rcm)) {
    prompt_io_manager_.ErrorFormat(list_result.rcm);
    return list_result.rcm;
  }

  const std::string current = AMStr::Strip(list_result.data.current_channel);
  prompt_io_manager_.FmtPrint("Terminal channels [{}]:", nickname);
  if (list_result.data.channel_names.empty()) {
    prompt_io_manager_.Print("  (empty)");
    return OK;
  }
  for (const auto &name : list_result.data.channel_names) {
    const bool active = (!current.empty() && name == current);
    prompt_io_manager_.FmtPrint("  {} {}", active ? "*" : "-", name);
  }
  return OK;
}

ECM FilesystemInterfaceSerivce::RemoveChannel(
    const FilesystemChannelRemoveArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string default_nickname = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(filesystem_service_.CurrentNickname()));
  if (default_nickname.empty()) {
    default_nickname = "local";
  }

  auto target_result = ParseTerminalTargetSpec_(arg.target, default_nickname);
  if (!(target_result.rcm)) {
    prompt_io_manager_.ErrorFormat(target_result.rcm);
    return target_result.rcm;
  }
  const TerminalTargetSpec_ target = target_result.data;
  const std::string channel_name =
      target.channel_name.has_value() ? AMStr::Strip(*target.channel_name) : "";
  if (channel_name.empty()) {
    const ECM rcm =
        Err(EC::InvalidArg, __func__, arg.target, "Channel name is required");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(target.nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm
                        ? Err(EC::InvalidHandle, __func__, target.nickname,
                              "Terminal handle is null")
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (terminal_result.data->GetSessionState() !=
      AMDomain::client::ClientStatus::OK) {
    const ECM rcm = Err(EC::NoConnection, __func__, target.nickname,
                        "Terminal session is disconnected");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto close_result =
      terminal_result.data->CloseChannel({channel_name, arg.force}, control);
  if (!(close_result.rcm)) {
    prompt_io_manager_.ErrorFormat(close_result.rcm);
    return close_result.rcm;
  }
  prompt_io_manager_.FmtPrint("✅ Channel removed: {}@{}", target.nickname,
                              channel_name);
  return OK;
}

ECM FilesystemInterfaceSerivce::RenameChannel(
    const FilesystemChannelRenameArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string default_nickname = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(filesystem_service_.CurrentNickname()));
  if (default_nickname.empty()) {
    default_nickname = "local";
  }

  auto src_result = ParseTerminalTargetSpec_(arg.src, default_nickname);
  if (!(src_result.rcm)) {
    prompt_io_manager_.ErrorFormat(src_result.rcm);
    return src_result.rcm;
  }
  auto dst_result = ParseTerminalTargetSpec_(arg.dst, default_nickname);
  if (!(dst_result.rcm)) {
    prompt_io_manager_.ErrorFormat(dst_result.rcm);
    return dst_result.rcm;
  }

  const TerminalTargetSpec_ src_target = src_result.data;
  const TerminalTargetSpec_ dst_target = dst_result.data;
  const std::string src_channel = src_target.channel_name.has_value()
                                      ? AMStr::Strip(*src_target.channel_name)
                                      : "";
  const std::string dst_channel = dst_target.channel_name.has_value()
                                      ? AMStr::Strip(*dst_target.channel_name)
                                      : "";
  if (src_channel.empty() || dst_channel.empty()) {
    const ECM rcm = Err(EC::InvalidArg, __func__, "channel_name",
                        "Both source and destination channels are required");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (src_target.nickname != dst_target.nickname) {
    const ECM rcm = Err(EC::InvalidArg, __func__, arg.dst,
                        "Channel rename must stay in the same terminal scope");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(src_target.nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm
                        ? Err(EC::InvalidHandle, __func__, src_target.nickname,
                              "Terminal handle is null")
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (terminal_result.data->GetSessionState() !=
      AMDomain::client::ClientStatus::OK) {
    const ECM rcm = Err(EC::NoConnection, __func__, src_target.nickname,
                        "Terminal session is disconnected");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto rename_result =
      terminal_result.data->RenameChannel({src_channel, dst_channel}, control);
  if (!(rename_result.rcm)) {
    prompt_io_manager_.ErrorFormat(rename_result.rcm);
    return rename_result.rcm;
  }
  prompt_io_manager_.FmtPrint("✅ Channel renamed: {}@{} -> {}@{}",
                              src_target.nickname, src_channel,
                              dst_target.nickname, dst_channel);
  return OK;
}

} // namespace AMInterface::filesystem
