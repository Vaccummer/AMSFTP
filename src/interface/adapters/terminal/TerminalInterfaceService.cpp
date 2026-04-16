#include "interface/adapters/terminal/TerminalInterfaceService.hpp"
#include "Isocline/isocline.h"
#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/terminal.hpp"
#include "interface/style/StyleIndex.hpp"
#include "interface/style/StyleManager.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <stop_token>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#endif

namespace AMInterface::terminal {
namespace {
AMDomain::client::ControlComponent
ResolveControl_(AMDomain::client::amf default_interrupt_flag,
                const std::optional<AMDomain::client::ControlComponent>
                    &control_opt) {
  return control_opt.has_value() ? control_opt.value()
                                  : AMDomain::client::ControlComponent(
                                        default_interrupt_flag, 0);
}

[[nodiscard]] ECM BuildTerminalUnsupportedError_(const std::string &nickname) {
  return Err(EC::OperationUnsupported, "terminal", nickname,
             "Current client does not support interactive terminal mode");
}

constexpr const char *kDefaultTerminalType_ = "xterm-256color";

[[nodiscard]] AMDomain::terminal::ChannelOpenArgs
BuildChannelOpenArgs_(const std::string &channel_name,
                      const AMTerminalTools::TerminalViewportInfo &geometry) {
  AMDomain::terminal::ChannelOpenArgs out = {};
  out.channel_name = AMStr::Strip(channel_name);
  out.cols = std::max(1, geometry.cols);
  out.rows = std::max(1, geometry.rows);
  out.width = std::max(0, geometry.width);
  out.height = std::max(0, geometry.height);
  out.term = kDefaultTerminalType_;
  return out;
}

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

std::vector<std::string>
NormalizeTerminalNicknames_(const std::vector<std::string> &raw_nicknames) {
  std::vector<std::string> out = {};
  out.reserve(raw_nicknames.size());
  std::unordered_set<std::string> seen = {};

  for (const auto &raw_nickname : raw_nicknames) {
    const std::string stripped = AMStr::Strip(raw_nickname);
    if (stripped.empty()) {
      continue;
    }
    const std::string nickname =
        AMDomain::host::HostService::NormalizeNickname(stripped);
    if (nickname.empty()) {
      continue;
    }
    if (!seen.insert(nickname).second) {
      continue;
    }
    out.push_back(nickname);
  }
  return out;
}

[[nodiscard]] std::string
JoinChannelSummary_(const std::vector<std::string> &channels) {
  if (channels.empty()) {
    return "(empty)";
  }
  std::string out = {};
  for (size_t i = 0; i < channels.size(); ++i) {
    if (i > 0) {
      out += "   ";
    }
    out += channels[i];
  }
  return out;
}

[[nodiscard]] ECMData<std::string> BuildTerminalSummaryLine_(
    const std::string &terminal_name,
    AMDomain::terminal::ITerminalPort *terminal,
    const AMDomain::client::ControlComponent &control,
    AMInterface::style::AMStyleService &style_service) {
  if (terminal == nullptr) {
    const std::string styled_header = style_service.Format(
        "[" + terminal_name + "]",
        AMInterface::style::StyleIndex::DisconnectedTerminalName);
    return {styled_header + ": (terminal unavailable)",
            Err(ErrorCode::InvalidHandle, "term.summary", terminal_name,
                "terminal handle is null")};
  }

  auto session_result = terminal->CheckSession({}, control);
  const bool terminal_ok =
      (session_result.rcm) &&
      (session_result.data.status == AMDomain::client::ClientStatus::OK);
  const auto terminal_style =
      terminal_ok ? AMInterface::style::StyleIndex::TerminalName
                  : AMInterface::style::StyleIndex::DisconnectedTerminalName;
  const std::string styled_header =
      style_service.Format("[" + terminal_name + "]", terminal_style);

  auto channels_result = terminal->ListChannels({}, control);
  if (!(channels_result.rcm)) {
    return {styled_header + ": (channel list unavailable)",
            channels_result.rcm};
  }

  std::vector<std::string> styled_channels = {};
  styled_channels.reserve(channels_result.data.channel_names.size());
  for (const auto &channel_name : channels_result.data.channel_names) {
    auto check_result = terminal->CheckChannel(
        {std::optional<std::string>(channel_name)}, control);
    const bool channel_ok = (check_result.rcm) && check_result.data.exists &&
                            check_result.data.is_open;
    const auto channel_style =
        channel_ok ? AMInterface::style::StyleIndex::ChannelName
                   : AMInterface::style::StyleIndex::DisconnectedChannelName;
    styled_channels.push_back(
        style_service.Format(channel_name, channel_style));
  }

  return {styled_header + ": " + JoinChannelSummary_(styled_channels), OK};
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
void WriteTerminalBytes_(std::string_view text) {
  if (text.empty()) {
    return;
  }
  (void)std::fwrite(text.data(), 1, text.size(), stdout);
  std::fflush(stdout);
}

constexpr const char *kTerminalExitAlternateScreen_ = "\x1b[?1049l";

class MainScreenRenderTracker_ final : NonCopyableNonMovable {
public:
  MainScreenRenderTracker_() = default;
  ~MainScreenRenderTracker_() override = default;

  void Reset(int viewport_cols, bool in_alternate_screen) {
    cols_ = std::max(1, viewport_cols);
    in_alternate_screen_ = in_alternate_screen;
    cursor_col_ = 0;
    rows_rendered_ = 0;
    current_row_has_content_ = false;
    touched_main_screen_ = false;
    first_row_confirmed_new_region_ = false;
    parser_state_ = ParserState_::None;
    escape_buffer_.clear();
  }

  void SetViewportCols(int viewport_cols) {
    cols_ = std::max(1, viewport_cols);
  }

  void SetAlternateScreen(bool in_alternate_screen) {
    in_alternate_screen_ = in_alternate_screen;
  }

  void Observe(std::string_view chunk) {
    for (unsigned char ch : chunk) {
      ProcessByte_(ch);
    }
  }

  [[nodiscard]] size_t RenderedRows() const { return EffectiveRenderedRows_(); }

  void ClearRenderedRowsInTerminal() {
    const size_t rows_to_clear = EffectiveRenderedRows_();
    if (rows_to_clear == 0U) {
      return;
    }
    for (size_t i = 0; i < rows_to_clear; ++i) {
      WriteTerminalBytes_("\r\x1b[2K");
      if (i + 1U < rows_to_clear) {
        WriteTerminalBytes_("\x1b[1A");
      }
    }
    rows_rendered_ = 0;
    current_row_has_content_ = false;
    touched_main_screen_ = false;
    first_row_confirmed_new_region_ = false;
    cursor_col_ = 0;
  }

private:
  enum class ParserState_ { None = 0, Esc, Csi };

  [[nodiscard]] size_t EffectiveRenderedRows_() const {
    if (rows_rendered_ == 0U) {
      return 0U;
    }
    // Keep cleanup scoped to rows that actually contain rendered content.
    // Avoid clearing one extra line when the stream leaves an empty trailing
    // row (for example after '\n' or wrap-to-next-row with no further output).
    if (!current_row_has_content_ && rows_rendered_ > 0U) {
      size_t rows = rows_rendered_ - 1U;
      if (!first_row_confirmed_new_region_ && rows > 0U) {
        --rows;
      }
      return rows;
    }
    if (!first_row_confirmed_new_region_ && rows_rendered_ > 0U) {
      return rows_rendered_ - 1U;
    }
    return rows_rendered_;
  }

  void ProcessByte_(unsigned char ch) {
    if (parser_state_ == ParserState_::None) {
      if (ch == 0x1bU) {
        parser_state_ = ParserState_::Esc;
        escape_buffer_.clear();
        escape_buffer_.push_back(static_cast<char>(ch));
        return;
      }
      ProcessVisibleByte_(ch);
      return;
    }

    if (parser_state_ == ParserState_::Esc) {
      escape_buffer_.push_back(static_cast<char>(ch));
      if (ch == static_cast<unsigned char>('[')) {
        parser_state_ = ParserState_::Csi;
      } else {
        parser_state_ = ParserState_::None;
        escape_buffer_.clear();
      }
      return;
    }

    escape_buffer_.push_back(static_cast<char>(ch));
    if (escape_buffer_.size() > 24U) {
      parser_state_ = ParserState_::None;
      escape_buffer_.clear();
      return;
    }

    if (ch >= 0x40U && ch <= 0x7eU) {
      ApplyTerminalModeEscape_(escape_buffer_);
      parser_state_ = ParserState_::None;
      escape_buffer_.clear();
    }
  }

  void ApplyTerminalModeEscape_(const std::string &sequence) {
    if (sequence == "\x1b[?1049h" || sequence == "\x1b[?1047h" ||
        sequence == "\x1b[?47h") {
      in_alternate_screen_ = true;
      return;
    }
    if (sequence == "\x1b[?1049l" || sequence == "\x1b[?1047l" ||
        sequence == "\x1b[?47l") {
      in_alternate_screen_ = false;
      return;
    }
  }

  void EnsureMainScreenTouched_() {
    if (touched_main_screen_) {
      return;
    }
    touched_main_screen_ = true;
    rows_rendered_ = 1U;
    first_row_confirmed_new_region_ = false;
  }

  void ProcessVisibleByte_(unsigned char ch) {
    if (in_alternate_screen_) {
      return;
    }

    if (ch == static_cast<unsigned char>('\r')) {
      cursor_col_ = 0;
      return;
    }
    if (ch == static_cast<unsigned char>('\n')) {
      if (!touched_main_screen_) {
        // The very first newline may originate from the remote side to move
        // away from the local command line. Do not count the origin row.
        touched_main_screen_ = true;
        rows_rendered_ = 1U;
        first_row_confirmed_new_region_ = true;
      } else {
        ++rows_rendered_;
      }
      cursor_col_ = 0;
      current_row_has_content_ = false;
      return;
    }
    if (ch == static_cast<unsigned char>('\b')) {
      if (cursor_col_ > 0) {
        --cursor_col_;
      }
      return;
    }
    if (ch == static_cast<unsigned char>('\t')) {
      EnsureMainScreenTouched_();
      int next_tab_col = ((cursor_col_ / 8) + 1) * 8;
      while (next_tab_col >= cols_) {
        ++rows_rendered_;
        next_tab_col -= cols_;
      }
      cursor_col_ = next_tab_col;
      current_row_has_content_ = (cursor_col_ > 0);
      return;
    }

    if (ch < 0x20U || ch == 0x7fU) {
      return;
    }

    EnsureMainScreenTouched_();
    ++cursor_col_;
    current_row_has_content_ = true;
    if (cursor_col_ >= cols_) {
      ++rows_rendered_;
      cursor_col_ = 0;
      current_row_has_content_ = false;
    }
  }

private:
  int cols_ = 80;
  int cursor_col_ = 0;
  size_t rows_rendered_ = 0U;
  bool current_row_has_content_ = false;
  bool touched_main_screen_ = false;
  bool first_row_confirmed_new_region_ = false;
  bool in_alternate_screen_ = false;
  ParserState_ parser_state_ = ParserState_::None;
  std::string escape_buffer_ = {};
};

} // namespace

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

class KeyboardInputMonitor_ final : NonCopyableNonMovable {
public:
  KeyboardInputMonitor_() = default;
  ~KeyboardInputMonitor_() override {
    Stop();
    CloseWake_();
  }

  ECM Start() {
    if (running_) {
      return OK;
    }
    const ECM ensure_rcm = EnsureWake_();
    if (!(ensure_rcm)) {
      return ensure_rcm;
    }

    stop_requested_.store(false, std::memory_order_release);
    closed_.store(false, std::memory_order_release);
    capture_enabled_.store(false, std::memory_order_release);
    {
      auto guard = key_cache_.lock();
      guard->clear();
    }
    {
      std::lock_guard<std::mutex> lock(fatal_mutex_);
      fatal_error_.clear();
    }

#ifdef _WIN32
    (void)ResetEvent(stop_event_);
    (void)ResetEvent(activate_event_);
    (void)ResetEvent(deactivate_event_);
#else
    DrainSignal();
#endif

    reader_thread_ = std::jthread(
        [this](std::stop_token stop_token) { ReaderLoop_(stop_token); });
    running_ = true;
    return OK;
  }

  void Stop() {
    if (!running_) {
      return;
    }
    stop_requested_.store(true, std::memory_order_release);
#ifdef _WIN32
    if (stop_event_ != nullptr) {
      (void)SetEvent(stop_event_);
    }
    if (activate_event_ != nullptr) {
      (void)SetEvent(activate_event_);
    }
    if (deactivate_event_ != nullptr) {
      (void)SetEvent(deactivate_event_);
    }
#else
    SignalKey_();
#endif
    if (reader_thread_.joinable()) {
      reader_thread_.request_stop();
      reader_thread_.join();
    }
    running_ = false;
    capture_enabled_.store(false, std::memory_order_release);
  }

  ECM ActivateCapture() {
    const ECM start_rcm = Start();
    if (!(start_rcm)) {
      return start_rcm;
    }
    closed_.store(false, std::memory_order_release);
    {
      auto guard = key_cache_.lock();
      guard->clear();
    }
    {
      std::lock_guard<std::mutex> lock(fatal_mutex_);
      fatal_error_.clear();
    }
    capture_enabled_.store(true, std::memory_order_release);
#ifdef _WIN32
    if (activate_event_ != nullptr) {
      (void)SetEvent(activate_event_);
    }
#endif
    return OK;
  }

  void DeactivateCapture() {
    capture_enabled_.store(false, std::memory_order_release);
#ifdef _WIN32
    if (deactivate_event_ != nullptr) {
      (void)SetEvent(deactivate_event_);
    }
#endif
    {
      auto guard = key_cache_.lock();
      guard->clear();
    }
  }

  [[nodiscard]] std::intptr_t WaitHandle() const {
#ifdef _WIN32
    return reinterpret_cast<std::intptr_t>(key_event_);
#else
    return static_cast<std::intptr_t>(key_pipe_[0]);
#endif
  }

  [[nodiscard]] AMAtomic<std::vector<char>> *KeyCache() { return &key_cache_; }

  void DrainSignal() {
#ifdef _WIN32
    if (key_event_ == nullptr) {
      return;
    }
    while (WaitForSingleObject(key_event_, 0) == WAIT_OBJECT_0) {
    }
#else
    if (key_pipe_[0] < 0) {
      return;
    }
    std::array<char, 64> buffer = {};
    while (read(key_pipe_[0], buffer.data(), buffer.size()) > 0) {
    }
#endif
  }

  bool PopInput(std::string *out) {
    if (out == nullptr) {
      return false;
    }
    auto guard = key_cache_.lock();
    if (guard->empty()) {
      out->clear();
      return false;
    }
    out->assign(guard->data(), guard->size());
    guard->clear();
    return true;
  }

  bool ConsumeFatalError(std::string *error) {
    if (error == nullptr) {
      return false;
    }
    std::lock_guard<std::mutex> lock(fatal_mutex_);
    if (fatal_error_.empty()) {
      error->clear();
      return false;
    }
    *error = fatal_error_;
    fatal_error_.clear();
    return true;
  }

  [[nodiscard]] bool IsClosed() const {
    return closed_.load(std::memory_order_acquire);
  }

private:
  ECM EnsureWake_() {
#ifdef _WIN32
    if (key_event_ == nullptr) {
      key_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
      if (key_event_ == nullptr) {
        return Err(EC::CommonFailure, "terminal.keyboard.start", "<event>",
                   "Failed to create keyboard event");
      }
    }
    if (stop_event_ == nullptr) {
      stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (stop_event_ == nullptr) {
        return Err(EC::CommonFailure, "terminal.keyboard.start", "<event>",
                   "Failed to create keyboard stop event");
      }
    }
    if (activate_event_ == nullptr) {
      activate_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
      if (activate_event_ == nullptr) {
        return Err(EC::CommonFailure, "terminal.keyboard.start", "<event>",
                   "Failed to create keyboard activate event");
      }
    }
    if (deactivate_event_ == nullptr) {
      deactivate_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
      if (deactivate_event_ == nullptr) {
        return Err(EC::CommonFailure, "terminal.keyboard.start", "<event>",
                   "Failed to create keyboard deactivate event");
      }
    }
#else
    if (key_pipe_[0] < 0 || key_pipe_[1] < 0) {
      if (pipe(key_pipe_) != 0) {
        key_pipe_[0] = -1;
        key_pipe_[1] = -1;
        return Err(EC::CommonFailure, "terminal.keyboard.start", "<pipe>",
                   "Failed to create keyboard wake pipe");
      }
      const int read_flags = fcntl(key_pipe_[0], F_GETFL, 0);
      const int write_flags = fcntl(key_pipe_[1], F_GETFL, 0);
      if (read_flags >= 0) {
        (void)fcntl(key_pipe_[0], F_SETFL, read_flags | O_NONBLOCK);
      }
      if (write_flags >= 0) {
        (void)fcntl(key_pipe_[1], F_SETFL, write_flags | O_NONBLOCK);
      }
    }
#endif
    return OK;
  }

  void CloseWake_() {
#ifdef _WIN32
    if (deactivate_event_ != nullptr) {
      (void)CloseHandle(deactivate_event_);
      deactivate_event_ = nullptr;
    }
    if (activate_event_ != nullptr) {
      (void)CloseHandle(activate_event_);
      activate_event_ = nullptr;
    }
    if (stop_event_ != nullptr) {
      (void)CloseHandle(stop_event_);
      stop_event_ = nullptr;
    }
    if (key_event_ != nullptr) {
      (void)CloseHandle(key_event_);
      key_event_ = nullptr;
    }
#else
    if (key_pipe_[0] >= 0) {
      (void)close(key_pipe_[0]);
      key_pipe_[0] = -1;
    }
    if (key_pipe_[1] >= 0) {
      (void)close(key_pipe_[1]);
      key_pipe_[1] = -1;
    }
#endif
  }

  void SignalKey_() {
#ifdef _WIN32
    if (key_event_ != nullptr) {
      (void)SetEvent(key_event_);
    }
#else
    if (key_pipe_[1] >= 0) {
      const char c = 1;
      (void)write(key_pipe_[1], &c, 1);
    }
#endif
  }

  void ReaderLoop_(std::stop_token stop_token) {
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == INVALID_HANDLE_VALUE || input == nullptr) {
      std::lock_guard<std::mutex> lock(fatal_mutex_);
      fatal_error_ = "Console input handle is invalid";
      SignalKey_();
      return;
    }

    while (!stop_requested_.load(std::memory_order_acquire) &&
           !stop_token.stop_requested()) {
      if (!capture_enabled_.load(std::memory_order_acquire)) {
        std::array<HANDLE, 2> inactive_wait = {stop_event_, activate_event_};
        const DWORD rc =
            WaitForMultipleObjects(static_cast<DWORD>(inactive_wait.size()),
                                   inactive_wait.data(), FALSE, INFINITE);
        if (rc == WAIT_OBJECT_0) {
          break;
        }
        continue;
      }

      std::array<HANDLE, 3> waiters = {stop_event_, deactivate_event_, input};
      const DWORD rc = WaitForMultipleObjects(
          static_cast<DWORD>(waiters.size()), waiters.data(), FALSE, INFINITE);
      if (rc == WAIT_OBJECT_0) {
        break;
      }
      if (rc == WAIT_OBJECT_0 + 1U) {
        continue;
      }
      if (rc != WAIT_OBJECT_0 + 2U) {
        std::lock_guard<std::mutex> lock(fatal_mutex_);
        fatal_error_ = AMStr::fmt("Keyboard wait failed: {}", GetLastError());
        SignalKey_();
        break;
      }

      if (!capture_enabled_.load(std::memory_order_acquire)) {
        continue;
      }

      std::array<char, 256> buffer = {};
      DWORD read_bytes = 0;
      if (ReadFile(input, buffer.data(), static_cast<DWORD>(buffer.size()),
                   &read_bytes, nullptr) == 0) {
        std::lock_guard<std::mutex> lock(fatal_mutex_);
        fatal_error_ = AMStr::fmt("Keyboard read failed: {}", GetLastError());
        SignalKey_();
        continue;
      }
      if (read_bytes == 0) {
        closed_.store(true, std::memory_order_release);
        SignalKey_();
        continue;
      }

      {
        auto guard = key_cache_.lock();
        guard->insert(guard->end(), buffer.begin(),
                      buffer.begin() + static_cast<ptrdiff_t>(read_bytes));
      }
      SignalKey_();
    }
#else
    while (!stop_requested_.load(std::memory_order_acquire) &&
           !stop_token.stop_requested()) {
      std::string input = {};
      std::string input_error = {};
      const auto status = PollLocalTerminalInput_(&input, &input_error);
      if (status == LocalInputPollStatus_::Error) {
        std::lock_guard<std::mutex> lock(fatal_mutex_);
        fatal_error_ =
            input_error.empty() ? "Local terminal input failed" : input_error;
        SignalKey_();
        return;
      }
      if (status == LocalInputPollStatus_::Closed) {
        closed_.store(true, std::memory_order_release);
        SignalKey_();
        return;
      }
      if (!capture_enabled_.load(std::memory_order_acquire)) {
        continue;
      }
      if (!input.empty()) {
        auto guard = key_cache_.lock();
        guard->insert(guard->end(), input.begin(), input.end());
        SignalKey_();
      }
    }
#endif
  }

private:
  std::atomic<bool> stop_requested_ = false;
  std::atomic<bool> closed_ = false;
  std::atomic<bool> capture_enabled_ = false;
  bool running_ = false;
  std::jthread reader_thread_ = {};
  AMAtomic<std::vector<char>> key_cache_ = {};
  mutable std::mutex fatal_mutex_ = {};
  std::string fatal_error_ = {};
#ifdef _WIN32
  HANDLE key_event_ = nullptr;
  HANDLE stop_event_ = nullptr;
  HANDLE activate_event_ = nullptr;
  HANDLE deactivate_event_ = nullptr;
#else
  int key_pipe_[2] = {-1, -1};
#endif
};

struct TerminalInterfaceService::SharedKeyboardMonitor_ {
  KeyboardInputMonitor_ monitor = {};
  mutable std::mutex session_mutex = {};
};

TerminalInterfaceService::~TerminalInterfaceService() {
  if (shared_keyboard_monitor_) {
    shared_keyboard_monitor_->monitor.Stop();
  }
}

TerminalInterfaceService::TerminalInterfaceService(
    AMApplication::client::ClientAppService &client_service,
    AMApplication::terminal::TermAppService &terminal_service,
    AMApplication::filesystem::FilesystemAppService &filesystem_service,
    AMInterface::style::AMStyleService &style_service,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager)
    : client_service_(client_service), terminal_service_(terminal_service),
      filesystem_service_(filesystem_service), style_service_(style_service),
      prompt_io_manager_(prompt_io_manager), default_interrupt_flag_(nullptr),
      shared_keyboard_monitor_(std::make_shared<SharedKeyboardMonitor_>()) {
  if (shared_keyboard_monitor_) {
    (void)shared_keyboard_monitor_->monitor.Start();
  }
}

void TerminalInterfaceService::SetDefaultControlToken(
    const AMDomain::client::amf &token) {
  default_interrupt_flag_ = token;
}

AMDomain::client::amf TerminalInterfaceService::GetDefaultControlToken() const {
  return default_interrupt_flag_;
}

ECM TerminalInterfaceService::ShellRun(
    const TerminalShellRunArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
    const {
  const std::string command = AMStr::Strip(arg.cmd);
  if (command.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "cmd cannot be empty");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (arg.max_time_s < -1) {
    const ECM rcm =
        Err(EC::InvalidArg, "", "", "max_time_s must be >= -1");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto base_control =
      ResolveControl_(default_interrupt_flag_, control_opt);
  AMDomain::client::ControlComponent run_control = base_control;
  if (arg.max_time_s >= 0) {
    constexpr int kMaxSafeSeconds = std::numeric_limits<int>::max() / 1000;
    const int safe_seconds = std::min(arg.max_time_s, kMaxSafeSeconds);
    run_control = AMDomain::client::ControlComponent(
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
    const ECM rcm = (client_result.rcm) ? Err(EC::InvalidHandle, "", "",
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

ECM TerminalInterfaceService::LaunchTerminal(
    const TerminalLaunchArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const int send_timeout_ms =
      filesystem_service_.GetInitArg().terminal_send_timeout_ms;
  const int write_kick_timeout_ms =
      (send_timeout_ms < 0) ? 0 : send_timeout_ms;
  std::string default_nickname = filesystem_service_.CurrentNickname();
  if (default_nickname.empty()) {
    default_nickname = AMDomain::host::klocalname;
  }

  auto target_result = ParseTerminalTargetSpec_(arg.target, default_nickname);
  if (!target_result.rcm) {
    prompt_io_manager_.ErrorFormat(target_result.rcm);
    return target_result.rcm;
  }
  const TerminalTargetSpec_ target = target_result.data;

  if (!shared_keyboard_monitor_) {
    shared_keyboard_monitor_ = std::make_shared<SharedKeyboardMonitor_>();
  }
  if (!shared_keyboard_monitor_) {
    const ECM rcm = Err(EC::InvalidHandle, "", target.nickname,
                        "Failed to initialize shared keyboard monitor");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  std::lock_guard<std::mutex> session_lock(
      shared_keyboard_monitor_->session_mutex);
  KeyboardInputMonitor_ *keyboard_monitor =
      &(shared_keyboard_monitor_->monitor);

  auto managed_terminal_result =
      terminal_service_.GetTerminalByNickname(target.nickname, false);

  AMDomain::terminal::TerminalHandle terminal_handle = nullptr;
  if (managed_terminal_result.rcm && managed_terminal_result.data) {
    terminal_handle = managed_terminal_result.data;
  } else if (managed_terminal_result.rcm && !managed_terminal_result.data) {
    const ECM rcm = Err(EC::InvalidHandle, "", target.nickname,
                        "Managed terminal handle is null");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  } else if (managed_terminal_result.rcm.code == EC::ClientNotFound) {
    auto temp_client_result =
        client_service_.CreateClient(target.nickname, control, false, false);
    if (!temp_client_result.rcm || !temp_client_result.data) {
      const ECM rcm = temp_client_result.rcm
                          ? Err(EC::InvalidHandle, "", target.nickname,
                                "Temporary client is null")
                          : temp_client_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }

    auto temp_terminal_result =
        terminal_service_.CreateTerminal(temp_client_result.data, false);
    if (!temp_terminal_result.rcm || !temp_terminal_result.data) {
      const ECM rcm =
          (temp_terminal_result.rcm.code == EC::OperationUnsupported)
              ? BuildTerminalUnsupportedError_(target.nickname)
              : temp_terminal_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
    terminal_handle = temp_terminal_result.data;
  } else {
    prompt_io_manager_.ErrorFormat(managed_terminal_result.rcm);
    return managed_terminal_result.rcm;
  }

  if (!terminal_handle) {
    const ECM rcm = Err(EC::InvalidHandle, "", target.nickname,
                        "Resolved terminal handle is null");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto protocol = terminal_handle->GetRequest().protocol;
  if (protocol != AMDomain::host::ClientProtocol::SFTP &&
      protocol != AMDomain::host::ClientProtocol::LOCAL) {
    const ECM rcm =
        Err(EC::OperationUnsupported, "", target.nickname,
            "Windows realtime terminal launch currently supports SFTP and "
            "LOCAL channels only");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto status_result = terminal_handle->CheckSession({}, control);
  if (!status_result.rcm) {
    prompt_io_manager_.ErrorFormat(status_result.rcm);
    return status_result.rcm;
  }

  const AMTerminalTools::TerminalViewportInfo geometry =
      AMTerminalTools::GetTerminalViewportInfo();
  const std::string requested_channel =
      target.channel_name.has_value() ? *target.channel_name : "";
  std::string channel_name = {};
  bool refresh_prompt_on_enter = false;

  if (!requested_channel.empty()) {
    auto check_result = terminal_handle->CheckChannel(
        {std::optional<std::string>(requested_channel)}, control);
    if (!(check_result.rcm)) {
      if (check_result.rcm.code != EC::ClientNotFound) {
        prompt_io_manager_.ErrorFormat(check_result.rcm);
        return check_result.rcm;
      }
      auto open_result = terminal_handle->OpenChannel(
          BuildChannelOpenArgs_(requested_channel, geometry), control);
      if (!(open_result.rcm) &&
          open_result.rcm.code != EC::TargetAlreadyExists) {
        prompt_io_manager_.ErrorFormat(open_result.rcm);
        return open_result.rcm;
      }
    } else {
      if (!check_result.data.exists || !check_result.data.is_open) {
        const ECM rcm = Err(EC::NoConnection, "", requested_channel,
                            "Target channel is not available");
        prompt_io_manager_.ErrorFormat(rcm);
        return rcm;
      }
      refresh_prompt_on_enter = true;
    }

    auto active_result =
        terminal_handle->ActiveChannel({requested_channel}, control);
    if (!(active_result.rcm) || !active_result.data.activated) {
      const ECM rcm = active_result.rcm
                          ? Err(EC::CommonFailure, "", requested_channel,
                                "Failed to activate target channel")
                          : active_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
    channel_name = requested_channel;
  } else {
    const std::string current_channel =
        AMStr::Strip(status_result.data.current_channel);
    if (current_channel.empty()) {
      const ECM rcm = Err(EC::InvalidArg, "", target.nickname,
                          "No active channel in terminal");
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }

    auto check_result = terminal_handle->CheckChannel({std::nullopt}, control);
    if (!(check_result.rcm)) {
      prompt_io_manager_.ErrorFormat(check_result.rcm);
      return check_result.rcm;
    }
    if (!check_result.data.exists || !check_result.data.is_open) {
      const ECM rcm = Err(EC::NoConnection, "", current_channel,
                          "Current channel is not available");
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }

    refresh_prompt_on_enter = true;
    channel_name = check_result.data.channel_name.empty()
                       ? current_channel
                       : check_result.data.channel_name;
  }

  auto channel_port_result = terminal_service_.EnsureChannelPort(
      target.nickname, channel_name, control);
  if (!(channel_port_result.rcm) || !channel_port_result.data) {
    const ECM rcm = channel_port_result.rcm
                        ? Err(EC::InvalidHandle, "", channel_name,
                              "Channel port handle is null")
                        : channel_port_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  const auto channel_port = channel_port_result.data;

  const ECM loop_rcm = channel_port->EnsureLoopStarted(
      {control, write_kick_timeout_ms});
  if (!(loop_rcm)) {
    prompt_io_manager_.ErrorFormat(loop_rcm);
    return loop_rcm;
  }

  const ECM keyboard_start_rcm = keyboard_monitor->Start();
  if (!(keyboard_start_rcm)) {
    prompt_io_manager_.ErrorFormat(keyboard_start_rcm);
    return keyboard_start_rcm;
  }

  ScopedPromptOutputCache_ prompt_cache_guard(&prompt_io_manager_);
  ScopedRawTerminal_ raw_terminal = {};
  if (!raw_terminal.Activate()) {
    const ECM rcm = Err(EC::CommonFailure, "terminal.raw_mode", "<stdin>",
                        raw_terminal.Error());
    prompt_io_manager_.ErrorFormat(rcm);
    prompt_cache_guard.Disable();
    prompt_io_manager_.Print("");
    return rcm;
  }

  const ECM activate_capture_rcm = keyboard_monitor->ActivateCapture();
  if (!(activate_capture_rcm)) {
    raw_terminal.Restore();
    RestoreCliPromptStateAfterTerminalExit_();
    prompt_cache_guard.Disable();
    prompt_io_manager_.Print("");
    prompt_io_manager_.ErrorFormat(activate_capture_rcm);
    return activate_capture_rcm;
  }

  MainScreenRenderTracker_ render_tracker = {};
  render_tracker.Reset(geometry.cols, false);
  std::mutex render_mutex = {};
  auto write_tracked = [&](std::string_view chunk) {
    if (chunk.empty()) {
      return;
    }
    std::lock_guard<std::mutex> guard(render_mutex);
    const int viewport_cols = AMTerminalTools::GetTerminalViewportInfo().cols;
    render_tracker.SetViewportCols(viewport_cols);
    render_tracker.Observe(chunk);
    WriteTerminalBytes_(chunk);
  };

  AMDomain::terminal::ChannelForegroundBindArgs bind_args = {};
  bind_args.processor = write_tracked;
  bind_args.key_event_handle = keyboard_monitor->WaitHandle();
  bind_args.key_cache = keyboard_monitor->KeyCache();
  bind_args.control = control;
  bind_args.write_kick_timeout_ms = write_kick_timeout_ms;

  auto bind_result = channel_port->BindForeground(bind_args);
  if (!(bind_result.rcm)) {
    keyboard_monitor->DeactivateCapture();
    raw_terminal.Restore();
    RestoreCliPromptStateAfterTerminalExit_();
    prompt_cache_guard.Disable();
    prompt_io_manager_.Print("");
    prompt_io_manager_.ErrorFormat(bind_result.rcm);
    return bind_result.rcm;
  }

  bool stream_in_alternate_screen = bind_result.data.in_alternate_screen;
  {
    std::lock_guard<std::mutex> guard(render_mutex);
    render_tracker.SetAlternateScreen(stream_in_alternate_screen);
  }

  if (bind_result.data.soft_limit_hit) {
    prompt_io_manager_.Print(
        "⚠ Terminal output cache reached soft limit (32MB)");
  }

  if (refresh_prompt_on_enter &&
      (bind_result.data.replayed_bytes + bind_result.data.fallback_bytes) ==
          0U &&
      !bind_result.data.closed) {
    write_tracked("\r\n[terminal resumed]\r\n");
  }

  if (bind_result.data.closed) {
    (void)channel_port->UnbindForeground();
    keyboard_monitor->DeactivateCapture();
    raw_terminal.Restore();
    RestoreCliPromptStateAfterTerminalExit_();
    prompt_cache_guard.Disable();
    prompt_io_manager_.Print("");
    const ECM rcm = (bind_result.data.last_error)
                        ? bind_result.data.last_error
                        : Err(EC::NoConnection, "", channel_name,
                              "Channel is already closed");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

#ifdef _WIN32
  HANDLE control_event = nullptr;
  std::unique_ptr<AMDomain::client::InterruptWakeupSafeGuard> control_guard =
      nullptr;
  if (control.ControlToken()) {
    control_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (control_event != nullptr) {
      control_guard =
          std::make_unique<AMDomain::client::InterruptWakeupSafeGuard>(
              control.ControlToken(),
              [control_event]() { (void)SetEvent(control_event); });
    }
  }
#endif

  ECM wait_rcm = OK;
  bool detached = false;
  while (true) {
    const auto loop_state = channel_port->GetLoopState();
    if (loop_state.detach_requested || !loop_state.foreground_bound) {
      detached = true;
      break;
    }
    if (loop_state.closed) {
      wait_rcm = (loop_state.last_error) ? loop_state.last_error : OK;
      break;
    }

#ifdef _WIN32
    if (loop_state.state_wait_handle <= 0) {
      wait_rcm = Err(EC::CommonFailure, "", channel_name,
                     "Channel loop wait handle is invalid");
      break;
    }

    std::array<HANDLE, 2> waiters = {
        reinterpret_cast<HANDLE>(loop_state.state_wait_handle), nullptr};
    DWORD wait_count = 1;
    if (control_event != nullptr) {
      waiters[wait_count++] = control_event;
    }

    const DWORD wait_rc =
        WaitForMultipleObjects(wait_count, waiters.data(), FALSE, INFINITE);
    if (wait_rc == WAIT_FAILED) {
      wait_rcm =
          Err(EC::CommonFailure, "", channel_name,
              AMStr::fmt("WaitForMultipleObjects failed: {}", GetLastError()));
      break;
    }
    if (control_event != nullptr && wait_rc == WAIT_OBJECT_0 + 1U) {
      (void)channel_port->RequestForegroundDetach();
      continue;
    }
#else
    if (control.IsInterrupted()) {
      (void)channel_port->RequestForegroundDetach();
      detached = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
#endif
  }

  const auto final_state = channel_port->GetLoopState();
  if (final_state.closed && !detached && (wait_rcm) &&
      !(final_state.last_error)) {
    wait_rcm = final_state.last_error;
  }

  keyboard_monitor->DeactivateCapture();

  const auto channel_state_after = channel_port->GetState();
  if (stream_in_alternate_screen || channel_state_after.in_alternate_screen) {
    write_tracked(kTerminalExitAlternateScreen_);
    std::lock_guard<std::mutex> guard(render_mutex);
    render_tracker.SetAlternateScreen(false);
  }

  size_t cleared_rows = 0U;
  {
    std::lock_guard<std::mutex> guard(render_mutex);
    cleared_rows = render_tracker.RenderedRows();
    render_tracker.ClearRenderedRowsInTerminal();
  }

  raw_terminal.Restore();
  RestoreCliPromptStateAfterTerminalExit_();
  prompt_cache_guard.Disable();
  if (cleared_rows == 0U) {
    prompt_io_manager_.Print("");
  }

  (void)channel_port->UnbindForeground();

#ifdef _WIN32
  control_guard.reset();
  if (control_event != nullptr) {
    (void)CloseHandle(control_event);
    control_event = nullptr;
  }
#endif

  if (!(wait_rcm)) {
    prompt_io_manager_.ErrorFormat(wait_rcm);
    return wait_rcm;
  }
  return OK;
}
ECM TerminalInterfaceService::AddTerminal(
    const TerminalAddArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const auto nicknames = NormalizeTerminalNicknames_(arg.nicknames);
  if (nicknames.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "<targets>",
                        "term add requires at least one target nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  ECM status = OK;
  for (const auto &nickname : nicknames) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", nickname, "Interrupted by user");
    }

    auto existing = terminal_service_.GetTerminalByNickname(nickname, false);
    if (existing.rcm && existing.data) {
      if (!arg.force) {
        const ECM rcm = Err(EC::TargetAlreadyExists, "", nickname,
                            "Terminal already exists");
        prompt_io_manager_.ErrorFormat(rcm);
        if ((status)) {
          status = rcm;
        }
        continue;
      }
      const ECM rm_rcm = terminal_service_.RemoveTerminal(nickname, control);
      if (!(rm_rcm)) {
        prompt_io_manager_.ErrorFormat(rm_rcm);
        if ((status)) {
          status = rm_rcm;
        }
        continue;
      }
    } else if (existing.rcm.code != EC::ClientNotFound) {
      prompt_io_manager_.ErrorFormat(existing.rcm);
      if ((status)) {
        status = existing.rcm;
      }
      continue;
    }

    auto client_result = client_service_.CreateClient(nickname, control, false);
    if (!(client_result.rcm) || !client_result.data) {
      const ECM rcm = (client_result.rcm)
                          ? Err(EC::InvalidHandle, "", nickname,
                                "Created client is null")
                          : client_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }

    auto terminal_result =
        terminal_service_.CreateTerminal(client_result.data, false);
    if (!(terminal_result.rcm) || !terminal_result.data) {
      const ECM rcm = (terminal_result.rcm.code == EC::OperationUnsupported)
                          ? BuildTerminalUnsupportedError_(nickname)
                          : terminal_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }

    prompt_io_manager_.FmtPrint("✅ Terminal added: {}", nickname);
  }
  return status;
}

ECM TerminalInterfaceService::ListTerminals(
    const TerminalListArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
    const {
  (void)arg;
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const auto names = terminal_service_.ListTerminalNames();
  if (names.empty()) {
    prompt_io_manager_.Print("(empty)");
    return OK;
  }

  for (const auto &name : names) {
    auto terminal_result = terminal_service_.GetTerminalByNickname(name, true);
    auto line_result = BuildTerminalSummaryLine_(
        name, terminal_result.data.get(), control, style_service_);
    prompt_io_manager_.Print(line_result.data);
  }
  return OK;
}

ECM TerminalInterfaceService::RemoveTerminal(
    const TerminalRemoveArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  if (arg.nicknames.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "<targets>",
                        "term rm requires at least one target nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  std::vector<std::string> valid_targets = {};
  valid_targets.reserve(arg.nicknames.size());
  std::unordered_set<std::string> seen = {};
  std::unordered_map<std::string, AMDomain::terminal::TerminalHandle> targets =
      {};
  ECM status = OK;
  for (const auto &raw_nickname : arg.nicknames) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "", "Operation timed out");
    }

    const std::string stripped = AMStr::Strip(raw_nickname);
    if (stripped.empty()) {
      const ECM rcm =
          Err(EC::InvalidArg, "", "", "invalid empty terminal nickname");
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }

    const std::string normalized =
        AMDomain::host::HostService::NormalizeNickname(stripped);
    if (normalized.empty() ||
        (!AMDomain::host::HostService::IsLocalNickname(normalized) &&
         !AMDomain::host::HostService::ValidateNickname(normalized))) {
      const ECM rcm =
          Err(EC::InvalidArg, "", "",
              AMStr::fmt("invalid terminal nickname literal: {}", stripped));
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }

    if (!seen.insert(normalized).second) {
      continue;
    }

    auto terminal_result =
        terminal_service_.GetTerminalByNickname(normalized, true);
    if (!(terminal_result.rcm) || !terminal_result.data) {
      const ECM rcm = terminal_result.rcm
                          ? Err(EC::ClientNotFound, "", normalized,
                                "terminal not found")
                          : terminal_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }
    valid_targets.push_back(normalized);
    targets[normalized] = terminal_result.data;
  }

  if (valid_targets.empty()) {
    return status;
  }

  for (const auto &nickname : valid_targets) {
    auto it = targets.find(nickname);
    AMDomain::terminal::ITerminalPort *terminal =
        (it == targets.end()) ? nullptr : it->second.get();
    auto line_result =
        BuildTerminalSummaryLine_(nickname, terminal, control, style_service_);
    prompt_io_manager_.Print(line_result.data);
  }

  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      "Are you sure to remove these clients? (y/n): ", &canceled);
  if (canceled || !confirmed) {
    prompt_io_manager_.PrintOperationAbort();
    return OK;
  }

  for (const auto &nickname : valid_targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", nickname, "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", nickname,
                 "Operation timed out");
    }

    const ECM rcm = terminal_service_.RemoveTerminal(nickname, control);
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }
    prompt_io_manager_.FmtPrint("✅ Terminal removed: {}", nickname);
  }
  return status;
}

ECM TerminalInterfaceService::AddChannel(
    const ChannelAddArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
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
        Err(EC::InvalidArg, "", arg.target, "Channel name is required");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(target.nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm
                        ? Err(EC::InvalidHandle, "", target.nickname,
                              "Terminal handle is null")
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (terminal_result.data->GetSessionState().status !=
      AMDomain::client::ClientStatus::OK) {
    const ECM rcm = Err(EC::NoConnection, "", target.nickname,
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

ECM TerminalInterfaceService::ListChannels(
    const ChannelListArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string nickname =
      AMDomain::host::HostService::NormalizeNickname(arg.nickname);
  if (arg.nickname.empty()) {
    nickname = client_service_.CurrentNickname();
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm
                        ? Err(EC::InvalidHandle, "", nickname,
                              "Terminal handle is null")
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto summary_result = BuildTerminalSummaryLine_(
      nickname, terminal_result.data.get(), control, style_service_);
  prompt_io_manager_.Print(summary_result.data);
  if (!(summary_result.rcm)) {
    prompt_io_manager_.ErrorFormat(summary_result.rcm);
    return summary_result.rcm;
  }
  return OK;
}

ECM TerminalInterfaceService::RemoveChannel(
    const ChannelRemoveArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
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
        Err(EC::InvalidArg, "", arg.target, "Channel name is required");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(target.nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm
                        ? Err(EC::InvalidHandle, "", target.nickname,
                              "Terminal handle is null")
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (terminal_result.data->GetSessionState().status !=
      AMDomain::client::ClientStatus::OK) {
    const ECM rcm = Err(EC::NoConnection, "", target.nickname,
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
  const ECM stop_stream_rcm =
      terminal_service_.DropChannelPort(target.nickname, channel_name);
  if (!(stop_stream_rcm)) {
    prompt_io_manager_.ErrorFormat(stop_stream_rcm);
    return stop_stream_rcm;
  }
  prompt_io_manager_.FmtPrint("✅ Channel removed: {}@{}", target.nickname,
                              channel_name);
  return OK;
}

ECM TerminalInterfaceService::RenameChannel(
    const ChannelRenameArg &arg,
    const std::optional<AMDomain::client::ControlComponent> &control_opt)
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
    const ECM rcm = Err(EC::InvalidArg, "", "channel_name",
                        "Both source and destination channels are required");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (src_target.nickname != dst_target.nickname) {
    const ECM rcm = Err(EC::InvalidArg, "", arg.dst,
                        "Channel rename must stay in the same terminal scope");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(src_target.nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm
                        ? Err(EC::InvalidHandle, "", src_target.nickname,
                              "Terminal handle is null")
                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (terminal_result.data->GetSessionState().status !=
      AMDomain::client::ClientStatus::OK) {
    const ECM rcm = Err(EC::NoConnection, "", src_target.nickname,
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
  const ECM stop_stream_rcm =
      terminal_service_.DropChannelPort(src_target.nickname, src_channel);
  if (!(stop_stream_rcm)) {
    prompt_io_manager_.ErrorFormat(stop_stream_rcm);
    return stop_stream_rcm;
  }
  prompt_io_manager_.FmtPrint("✅ Channel renamed: {}@{} -> {}@{}",
                              src_target.nickname, src_channel,
                              dst_target.nickname, dst_channel);
  return OK;
}

} // namespace AMInterface::terminal


