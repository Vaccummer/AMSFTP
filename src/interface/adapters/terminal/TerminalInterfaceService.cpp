#include "interface/adapters/terminal/TerminalInterfaceService.hpp"
#include "Isocline/isocline.h"
#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/terminal.hpp"
#include "interface/parser/LuaInterpreter.hpp"
#include "interface/style/StyleIndex.hpp"
#include "interface/style/StyleManager.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <optional>
#include <stop_token>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

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
ControlComponent
ResolveControl_(AMDomain::client::amf default_interrupt_flag,
                const std::optional<ControlComponent> &control_opt) {
  return control_opt.has_value() ? control_opt.value()
                                 : ControlComponent(default_interrupt_flag);
}

[[nodiscard]] ECM BuildTerminalUnsupportedError_(const std::string &nickname) {
  return Err(EC::OperationUnsupported, "terminal", nickname,
             "Current client does not support interactive terminal mode");
}

constexpr const char *kDefaultTerminalType_ = "xterm-256color";
constexpr std::string_view kLocalWheelUpInput_("\0AMSFTP_WHEEL_UP\0", 17);
constexpr std::string_view kLocalWheelDownInput_("\0AMSFTP_WHEEL_DOWN\0", 19);

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

[[nodiscard]] ECM TimeoutSecondsToMs_(double timeout_s, const char *operation,
                                      int *out_timeout_ms) {
  if (out_timeout_ms == nullptr) {
    return Err(EC::InvalidArg, operation, "timeout", "Timeout output is null");
  }
  if (!std::isfinite(timeout_s) || timeout_s <= 0.0) {
    return Err(EC::InvalidArg, operation, "timeout",
               "Timeout must be greater than 0 seconds");
  }
  const double timeout_ms = timeout_s * 1000.0;
  if (timeout_ms > static_cast<double>(std::numeric_limits<int>::max())) {
    return Err(EC::InvalidArg, operation, "timeout", "Timeout is too large");
  }
  *out_timeout_ms = std::max(1, static_cast<int>(std::llround(timeout_ms)));
  return OK;
}

[[nodiscard]] ECM MergeStatus_(const ECM &current, const ECM &next) {
  return (next) ? current : next;
}

[[nodiscard]] ECMData<std::string>
BuildTerminalSummaryLine_(const std::string &terminal_name,
                          AMDomain::terminal::ITerminalPort *terminal,
                          const ControlComponent &control,
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
  styled_channels.reserve(channels_result.data.channels.size());
  for (const auto &[channel_name, channel_port] :
       channels_result.data.channels) {
    const bool channel_ok =
        channel_port != nullptr && !channel_port->GetState().closed;
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

[[nodiscard]] bool MouseProtocolStateChanged_(
    const AMDomain::terminal::ChannelVtSnapshot &lhs,
    const AMDomain::terminal::ChannelVtSnapshot &rhs) {
  return lhs.mouse_reporting_active != rhs.mouse_reporting_active ||
         lhs.mouse_report_click != rhs.mouse_report_click ||
         lhs.mouse_drag != rhs.mouse_drag ||
         lhs.mouse_motion != rhs.mouse_motion ||
         lhs.mouse_sgr_encoding != rhs.mouse_sgr_encoding ||
         lhs.mouse_utf8_encoding != rhs.mouse_utf8_encoding;
}

[[nodiscard]] bool InputProtocolStateChanged_(
    const AMDomain::terminal::ChannelVtSnapshot &lhs,
    const AMDomain::terminal::ChannelVtSnapshot &rhs) {
  return MouseProtocolStateChanged_(lhs, rhs) ||
         lhs.app_cursor_keys != rhs.app_cursor_keys ||
         lhs.app_keypad != rhs.app_keypad ||
         lhs.alternate_scroll != rhs.alternate_scroll;
}

[[nodiscard]] std::string BuildTerminalInputProtocolAnsi_(
    const AMDomain::terminal::ChannelVtSnapshot &vt_snapshot,
    bool local_browse_active, bool allow_local_wheel_capture = true) {
  constexpr std::string_view kDisableMouseProtocols =
      "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1007l";
  std::string out(kDisableMouseProtocols);
  out += "\x1b[?1l";
  out += "\x1b>";

  const bool capture_local_wheel =
      allow_local_wheel_capture &&
      (local_browse_active || !vt_snapshot.available ||
       (!vt_snapshot.in_alternate_screen &&
        !vt_snapshot.mouse_reporting_active));
  if (vt_snapshot.available) {
    if (!local_browse_active && vt_snapshot.mouse_reporting_active) {
      if (vt_snapshot.mouse_report_click) {
        out += "\x1b[?1000h";
      }
      if (vt_snapshot.mouse_drag) {
        out += "\x1b[?1002h";
      }
      if (vt_snapshot.mouse_motion) {
        out += "\x1b[?1003h";
      }
      if (vt_snapshot.mouse_utf8_encoding) {
        out += "\x1b[?1005h";
      }
      if (vt_snapshot.mouse_sgr_encoding) {
        out += "\x1b[?1006h";
      }
    }
    if (!local_browse_active && vt_snapshot.in_alternate_screen &&
        !vt_snapshot.mouse_reporting_active && vt_snapshot.alternate_scroll) {
      out += "\x1b[?1007h";
    }
    if (vt_snapshot.app_cursor_keys) {
      out += "\x1b[?1h";
    }
    if (vt_snapshot.app_keypad) {
      out += "\x1b=";
    }
  }
  if (capture_local_wheel) {
    out += "\x1b[?1000h\x1b[?1006h";
  }
  return out;
}

class ScopedPromptOutputCache_ final : NonCopyableNonMovable {
public:
  explicit ScopedPromptOutputCache_(
      AMInterface::prompt::PromptIOManager *prompt_io_manager)
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
  AMInterface::prompt::PromptIOManager *prompt_io_manager_ = nullptr;
  bool active_ = false;
};

AMInterface::prompt::PromptVarMap
BuildShellRunLuaVars_(const AMDomain::host::ConRequest &request,
                      const AMDomain::host::ClientMetaData &metadata,
                      const std::string &cmd) {
  using AMInterface::prompt::PromptVarMap;
  using AMInterface::prompt::PromptVarValue;

  PromptVarMap vars = {};
  vars["cmd"] = PromptVarValue{cmd};
  vars["nickname"] = PromptVarValue{request.nickname};
  vars["protocol"] =
      PromptVarValue{AMStr::lowercase(AMStr::ToString(request.protocol))};
  vars["hostname"] = PromptVarValue{request.hostname};
  vars["username"] = PromptVarValue{request.username};
  vars["port"] = PromptVarValue{request.port};
  vars["password"] = PromptVarValue{request.password};
  vars["keyfile"] = PromptVarValue{request.keyfile};
  vars["compression"] = PromptVarValue{request.compression};
  vars["trash_dir"] = PromptVarValue{metadata.trash_dir};
  vars["login_dir"] = PromptVarValue{metadata.login_dir};
  vars["cwd"] = PromptVarValue{metadata.cwd};
  vars["cmd_template"] = PromptVarValue{metadata.cmd_template};
  vars["is_cwd_exists"] = PromptVarValue{!AMStr::Strip(metadata.cwd).empty()};
  return vars;
}

std::pair<std::string, std::optional<ECM>>
ResolveShellRunCommand_(const AMDomain::host::ConRequest &request,
                        const AMDomain::host::ClientMetaData &metadata,
                        const std::string &cmd) {
  const std::string cmd_template = AMStr::Strip(metadata.cmd_template);
  if (cmd_template.empty()) {
    return {cmd, std::nullopt};
  }

  const auto render = AMInterface::prompt::LUARender(
      {cmd_template}, BuildShellRunLuaVars_(request, metadata, cmd));
  if (!(render.rcm)) {
    return {cmd, render.rcm};
  }
  return {render.data, std::nullopt};
}

enum class LocalInputPollStatus_ { Ready, Closed, Error };
void WriteTerminalBytes_(std::string_view text) {
  if (text.empty()) {
    return;
  }
  (void)std::fwrite(text.data(), 1, text.size(), stdout);
  std::fflush(stdout);
}

[[nodiscard]] std::vector<std::string>
SplitAnsiFrameLines_(std::string_view frame) {
  std::vector<std::string> lines = {};
  if (frame.empty()) {
    return lines;
  }

  size_t start = 0;
  while (start < frame.size()) {
    size_t end = frame.find("\r\n", start);
    if (end == std::string_view::npos) {
      lines.emplace_back(frame.substr(start));
      return lines;
    }
    lines.emplace_back(frame.substr(start, end - start));
    start = end + 2U;
  }

  if (frame.ends_with("\r\n")) {
    lines.emplace_back();
  }
  return lines;
}

constexpr const char *kTerminalEnterAlternateScreen_ = "\x1b[?1049h";
constexpr const char *kTerminalExitAlternateScreen_ = "\x1b[?1049l";
constexpr const char *kTerminalClearAndHome_ = "\x1b[H\x1b[2J";

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
    main_screen_buffer_.clear();
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

  [[nodiscard]] size_t RenderedRows() const {
    return RenderedRowsForViewport(cols_);
  }

  [[nodiscard]] size_t RenderedRowsForViewport(int viewport_cols) const {
    MainScreenRenderTracker_ replay = {};
    replay.Reset(std::max(1, viewport_cols), false);
    replay.Observe(main_screen_buffer_);
    return replay.EffectiveRenderedRows_();
  }

  void ClearRowsInTerminal(size_t rows_to_clear) {
    const int viewport_cols = AMTerminalTools::GetTerminalViewportInfo().cols;
    MainScreenRenderTracker_ replay = {};
    replay.Reset(std::max(1, viewport_cols), false);
    replay.Observe(main_screen_buffer_);
    if (rows_to_clear == 0U) {
      return;
    }
    if (!replay.current_row_has_content_ &&
        replay.rows_rendered_ > rows_to_clear) {
      WriteTerminalBytes_("\x1b[1A");
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
    main_screen_buffer_.clear();
  }

private:
  enum class ParserState_ { None = 0, Esc, Csi, TerminalString, StringEsc };

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
      } else if (ch == static_cast<unsigned char>(']') ||
                 ch == static_cast<unsigned char>('P') ||
                 ch == static_cast<unsigned char>('_') ||
                 ch == static_cast<unsigned char>('^') ||
                 ch == static_cast<unsigned char>('X')) {
        parser_state_ = ParserState_::TerminalString;
        escape_buffer_.clear();
      } else {
        parser_state_ = ParserState_::None;
        escape_buffer_.clear();
      }
      return;
    }

    if (parser_state_ == ParserState_::TerminalString) {
      if (ch == 0x07U) {
        parser_state_ = ParserState_::None;
        escape_buffer_.clear();
        return;
      }
      if (ch == 0x1bU) {
        parser_state_ = ParserState_::StringEsc;
      }
      return;
    }

    if (parser_state_ == ParserState_::StringEsc) {
      if (ch == static_cast<unsigned char>('\\')) {
        parser_state_ = ParserState_::None;
        escape_buffer_.clear();
        return;
      }
      parser_state_ = (ch == 0x1bU) ? ParserState_::StringEsc
                                    : ParserState_::TerminalString;
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
    main_screen_buffer_.push_back(static_cast<char>(ch));

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
  std::string main_screen_buffer_ = {};
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
    raw_input_mode &= ~(ENABLE_WINDOW_INPUT | ENABLE_QUICK_EDIT_MODE);
    raw_input_mode &= ~ENABLE_MOUSE_INPUT;
    if (SetConsoleMode(input_, raw_input_mode) == 0) {
      error_ = "Failed to enable raw console input";
      return false;
    }
    raw_input_mode_ = raw_input_mode;
    mouse_input_enabled_ = false;

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

#ifdef _WIN32
  void SetMouseInputEnabled(bool enabled) {
    if (!active_ || input_ == INVALID_HANDLE_VALUE) {
      return;
    }
    if (mouse_input_enabled_ == enabled) {
      return;
    }
    DWORD mode = raw_input_mode_;
    if (enabled) {
      mode |= ENABLE_MOUSE_INPUT;
    } else {
      mode &= ~ENABLE_MOUSE_INPUT;
    }
    if (SetConsoleMode(input_, mode) == 0) {
      return;
    }
    raw_input_mode_ = mode;
    mouse_input_enabled_ = enabled;
  }
#endif

private:
  bool active_ = false;
  std::string error_ = {};
#ifdef _WIN32
  HANDLE input_ = INVALID_HANDLE_VALUE;
  HANDLE output_ = INVALID_HANDLE_VALUE;
  DWORD input_mode_ = 0;
  DWORD output_mode_ = 0;
  DWORD raw_input_mode_ = 0;
  bool mouse_input_enabled_ = false;
#else
  termios termios_ = {};
  int stdin_flags_ = -1;
#endif
};

[[maybe_unused]] LocalInputPollStatus_
PollLocalTerminalInput_(std::string *out, std::string *error) {
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

    if (record.EventType == MOUSE_EVENT) {
      DWORD consumed = 0;
      if (ReadConsoleInputW(input, &record, 1, &consumed) == 0) {
        *error = "Console input consume failed";
        return LocalInputPollStatus_::Error;
      }
      if (consumed == 0) {
        return LocalInputPollStatus_::Ready;
      }

      auto const &mouse = record.Event.MouseEvent;
      if ((mouse.dwEventFlags & (MOUSE_WHEELED | MOUSE_HWHEELED)) != 0U) {
        SHORT const delta = static_cast<SHORT>(HIWORD(mouse.dwButtonState));
        std::string_view const token =
            (delta > 0) ? kLocalWheelUpInput_ : kLocalWheelDownInput_;
        out->assign(token.data(), token.size());
        return LocalInputPollStatus_::Ready;
      }
      continue;
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

      std::string input_chunk = {};
      std::string input_error = {};
      auto const status = PollLocalTerminalInput_(&input_chunk, &input_error);
      if (status == LocalInputPollStatus_::Error) {
        std::lock_guard<std::mutex> lock(fatal_mutex_);
        fatal_error_ =
            input_error.empty() ? "Console input read failed" : input_error;
        SignalKey_();
        continue;
      }
      if (status == LocalInputPollStatus_::Closed) {
        closed_.store(true, std::memory_order_release);
        SignalKey_();
        continue;
      }
      if (input_chunk.empty()) {
        continue;
      }

      {
        auto guard = key_cache_.lock();
        guard->insert(guard->end(), input_chunk.begin(), input_chunk.end());
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
    AMInterface::prompt::PromptIOManager &prompt_io_manager)
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
    const std::optional<ControlComponent> &control_opt) const {
  const std::string command = AMStr::Strip(arg.cmd);
  if (command.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "cmd cannot be empty");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (arg.max_time_s < -1) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "max_time_s must be >= -1");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto base_control =
      ResolveControl_(default_interrupt_flag_, control_opt);
  ControlComponent run_control = base_control;
  if (arg.max_time_s >= 0) {
    constexpr int kMaxSafeSeconds = std::numeric_limits<int>::max() / 1000;
    const int safe_seconds = std::min(arg.max_time_s, kMaxSafeSeconds);
    run_control =
        ControlComponent(base_control.ControlToken(), safe_seconds * 1000);
  }

  std::string nickname = filesystem_service_.CurrentNickname();
  if (nickname.empty()) {
    nickname = "local";
  }

  std::string final_cmd = command;
  auto metadata_client_result = client_service_.GetClient(nickname, true);
  if ((metadata_client_result.rcm) && metadata_client_result.data) {
    const auto request = metadata_client_result.data->ConfigPort().GetRequest();
    auto metadata_opt =
        AMApplication::client::ClientAppService::GetClientMetadata(
            metadata_client_result.data);
    if (metadata_opt.has_value()) {
      auto [resolved_cmd, render_error] =
          ResolveShellRunCommand_(request, metadata_opt.value(), command);
      final_cmd = std::move(resolved_cmd);
      if (render_error.has_value()) {
        prompt_io_manager_.Print(
            AMStr::fmt("cmd_template lua render failed, fallback to cmd: {}",
                       render_error->msg()));
      }
    }
  }

  prompt_io_manager_.FmtPrint(
      "🚀 Final Command: {}",
      style_service_.Format(AMStr::BBCEscape(final_cmd),
                            style::StyleIndex::ShellCmd));

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
  std::string icon_f = shell_result.data.exit_code == 0 ? "✅" : "❌";
  prompt_io_manager_.FmtPrint("{} Exit with code {}", icon_f,
                              shell_result.data.exit_code);

  if (!(shell_result.rcm)) {
    prompt_io_manager_.ErrorFormat(shell_result.rcm);
    return shell_result.rcm;
  }
  return OK;
}

ECM TerminalInterfaceService::LaunchTerminal(
    const TerminalLaunchArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const int send_timeout_ms = terminal_service_.GetInitArg().send_timeout_ms;
  const int write_kick_timeout_ms = (send_timeout_ms < 0) ? 0 : send_timeout_ms;
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
    auto channel_port_result = terminal_handle->GetChannelPort(
        std::optional<std::string>(requested_channel), control);
    if (!(channel_port_result.rcm)) {
      if (channel_port_result.rcm.code != EC::ClientNotFound) {
        prompt_io_manager_.ErrorFormat(channel_port_result.rcm);
        return channel_port_result.rcm;
      }
      auto open_result = terminal_handle->OpenChannel(
          BuildChannelOpenArgs_(requested_channel, geometry), control);
      if (!(open_result.rcm) &&
          open_result.rcm.code != EC::TargetAlreadyExists) {
        prompt_io_manager_.ErrorFormat(open_result.rcm);
        return open_result.rcm;
      }
    } else {
      if (!channel_port_result.data ||
          channel_port_result.data->GetState().closed) {
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

    auto channel_port_result =
        terminal_handle->GetChannelPort(std::nullopt, control);
    if (!(channel_port_result.rcm)) {
      prompt_io_manager_.ErrorFormat(channel_port_result.rcm);
      return channel_port_result.rcm;
    }
    if (!channel_port_result.data ||
        channel_port_result.data->GetState().closed) {
      const ECM rcm = Err(EC::NoConnection, "", current_channel,
                          "Current channel is not available");
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }

    refresh_prompt_on_enter = true;
    channel_name = current_channel;
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

  const ECM loop_rcm =
      channel_port->EnsureLoopStarted({control, write_kick_timeout_ms});
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

  std::mutex render_mutex = {};
  std::mutex local_input_mutex = {};
  bool physical_alt_screen_active = false;
  bool have_last_server_screen_state = false;
  bool last_server_in_alternate_screen = false;
  bool last_local_browse_active = false;
  AMTerminalTools::TerminalViewportInfo last_render_geometry = geometry;
  std::vector<std::string> last_rendered_lines = {};
  bool have_last_vt_snapshot = false;
  AMDomain::terminal::ChannelVtSnapshot last_vt_snapshot = {};
  std::atomic<uint64_t> local_viewport_offset = 0;
  std::atomic<bool> local_browse_active = false;
  std::string pending_local_input = {};
  AMTerminalTools::TerminalViewportInfo last_geometry = geometry;
  auto clear_keyboard_capture_buffers = [&]() {
    if (keyboard_monitor == nullptr) {
      return;
    }
    keyboard_monitor->DeactivateCapture();
    keyboard_monitor->DrainSignal();
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input != INVALID_HANDLE_VALUE && input != nullptr) {
      (void)FlushConsoleInputBuffer(input);
    }
#else
    (void)tcflush(STDIN_FILENO, TCIFLUSH);
#endif
    std::string discarded_input = {};
    (void)keyboard_monitor->PopInput(&discarded_input);
  };
  auto enter_physical_alt_screen = [&]() {
    std::lock_guard<std::mutex> guard(render_mutex);
    if (physical_alt_screen_active) {
      return;
    }
    WriteTerminalBytes_(kTerminalEnterAlternateScreen_);
    WriteTerminalBytes_(kTerminalClearAndHome_);
    physical_alt_screen_active = true;
  };
  auto leave_physical_alt_screen = [&]() {
    {
      std::lock_guard<std::mutex> guard(render_mutex);
      if (!physical_alt_screen_active) {
        return;
      }
#ifdef _WIN32
      raw_terminal.SetMouseInputEnabled(false);
#endif
      WriteTerminalBytes_(BuildTerminalInputProtocolAnsi_({}, false, false));
      WriteTerminalBytes_(kTerminalExitAlternateScreen_);
      physical_alt_screen_active = false;
      have_last_server_screen_state = false;
      last_server_in_alternate_screen = false;
      last_local_browse_active = false;
      last_render_geometry = geometry;
      last_rendered_lines.clear();
      have_last_vt_snapshot = false;
      last_vt_snapshot = {};
    }
    local_viewport_offset.store(0, std::memory_order_release);
    local_browse_active.store(false, std::memory_order_release);
    {
      std::lock_guard<std::mutex> input_guard(local_input_mutex);
      pending_local_input.clear();
    }
  };
  auto render_frame_result_to_terminal =
      [&](AMDomain::terminal::ChannelRenderFrameResult frame_result) {
    std::string frame = std::move(frame_result.vt_visible_frame_ansi);
    if (frame.empty()) {
      frame = std::move(frame_result.vt_main_replay_ansi);
    }
    AMDomain::terminal::ChannelVtSnapshot vt_snapshot =
        frame_result.vt_snapshot;
    bool const browse_active = local_browse_active.load(std::memory_order_acquire);
    const uint64_t viewport_offset =
        local_viewport_offset.load(std::memory_order_acquire);
    if (browse_active || viewport_offset != 0U) {
      vt_snapshot.cursor_visible = false;
    }
    std::lock_guard<std::mutex> guard(render_mutex);
    if (!physical_alt_screen_active) {
      return;
    }
    auto const current_geometry = AMTerminalTools::GetTerminalViewportInfo();
    const std::vector<std::string> current_lines = SplitAnsiFrameLines_(frame);
    const std::string input_protocol_ansi =
        BuildTerminalInputProtocolAnsi_(vt_snapshot, browse_active);
#ifdef _WIN32
    bool const enable_local_wheel_capture =
        browse_active ||
        !vt_snapshot.available ||
        (!vt_snapshot.in_alternate_screen && !vt_snapshot.mouse_reporting_active);
    raw_terminal.SetMouseInputEnabled(enable_local_wheel_capture);
#endif
    const bool force_full_clear =
        !have_last_server_screen_state ||
        current_geometry.cols != last_render_geometry.cols ||
        current_geometry.rows != last_render_geometry.rows ||
        last_server_in_alternate_screen != vt_snapshot.in_alternate_screen;
    const bool lines_changed = force_full_clear || current_lines != last_rendered_lines;
    const bool input_protocol_changed =
        !have_last_vt_snapshot ||
        InputProtocolStateChanged_(vt_snapshot, last_vt_snapshot) ||
        browse_active != last_local_browse_active;

    if (!lines_changed && vt_snapshot.available && have_last_vt_snapshot) {
      const bool cursor_changed =
          vt_snapshot.cursor_row != last_vt_snapshot.cursor_row ||
          vt_snapshot.cursor_col != last_vt_snapshot.cursor_col ||
          vt_snapshot.cursor_visible != last_vt_snapshot.cursor_visible;
      if (!cursor_changed && !input_protocol_changed) {
        return;
      }
      std::string cursor_only = {};
      cursor_only.reserve(input_protocol_ansi.size() + 48U);
      if (input_protocol_changed) {
        cursor_only += input_protocol_ansi;
      }
      const int cursor_row =
          std::clamp(vt_snapshot.cursor_row + 1, 1,
                     std::max(1, current_geometry.rows));
      const int cursor_col =
          std::clamp(vt_snapshot.cursor_col + 1, 1,
                     std::max(1, current_geometry.cols));
      cursor_only += AMStr::fmt("\x1b[{};{}H", cursor_row, cursor_col);
      cursor_only += vt_snapshot.cursor_visible ? "\x1b[?25h" : "\x1b[?25l";
      WriteTerminalBytes_(cursor_only);
      last_local_browse_active = browse_active;
      last_render_geometry = current_geometry;
      last_vt_snapshot = vt_snapshot;
      return;
    }

    std::string repaint = {};
    repaint.reserve(input_protocol_ansi.size() + frame.size() +
                    current_lines.size() * 24U + 128U);
    repaint += input_protocol_ansi;
    repaint += "\x1b[?25l";
    repaint += "\x1b[0m";
    if (force_full_clear) {
      repaint += kTerminalClearAndHome_;
      for (size_t i = 0; i < current_lines.size(); ++i) {
        repaint += AMStr::fmt("\x1b[{};1H", static_cast<int>(i + 1U));
        repaint += "\x1b[2K\x1b[0m";
        repaint += current_lines[i];
      }
    } else {
      const size_t overlap = std::min(last_rendered_lines.size(), current_lines.size());
      for (size_t i = 0; i < overlap; ++i) {
        if (last_rendered_lines[i] == current_lines[i]) {
          continue;
        }
        repaint += AMStr::fmt("\x1b[{};1H", static_cast<int>(i + 1U));
        repaint += "\x1b[2K\x1b[0m";
        repaint += current_lines[i];
      }
      for (size_t i = overlap; i < current_lines.size(); ++i) {
        repaint += AMStr::fmt("\x1b[{};1H", static_cast<int>(i + 1U));
        repaint += "\x1b[2K\x1b[0m";
        repaint += current_lines[i];
      }
      for (size_t i = current_lines.size(); i < last_rendered_lines.size(); ++i) {
        repaint += AMStr::fmt("\x1b[{};1H\x1b[2K", static_cast<int>(i + 1U));
      }
    }
    if (vt_snapshot.available) {
      const int cursor_row =
          std::clamp(vt_snapshot.cursor_row + 1, 1,
                     std::max(1, current_geometry.rows));
      const int cursor_col =
          std::clamp(vt_snapshot.cursor_col + 1, 1,
                     std::max(1, current_geometry.cols));
      repaint += AMStr::fmt("\x1b[{};{}H", cursor_row, cursor_col);
      repaint += vt_snapshot.cursor_visible ? "\x1b[?25h" : "\x1b[?25l";
      have_last_server_screen_state = true;
      last_server_in_alternate_screen = vt_snapshot.in_alternate_screen;
    } else {
      repaint += "\x1b[?25h";
      have_last_server_screen_state = false;
      last_server_in_alternate_screen = false;
    }
    WriteTerminalBytes_(repaint);
    last_rendered_lines = current_lines;
    last_local_browse_active = browse_active;
    last_render_geometry = current_geometry;
    have_last_vt_snapshot = vt_snapshot.available;
    last_vt_snapshot = vt_snapshot;
  };
  std::function<void()> render_current_frame = [&]() {
    AMDomain::terminal::ChannelRenderFrameResult frame_result = {};
    if (channel_port) {
      AMDomain::terminal::ChannelRenderFrameArgs render_args = {};
      render_args.viewport_offset =
          local_viewport_offset.load(std::memory_order_acquire);
      auto result = channel_port->GetRenderFrame(render_args);
      if ((result.rcm)) {
        frame_result = std::move(result.data);
      }
    }
    render_frame_result_to_terminal(std::move(frame_result));
  };
  auto render_from_channel_frame =
      [&](const AMDomain::terminal::ChannelRenderFrameResult &frame_result) {
    const bool browse_active =
        local_browse_active.load(std::memory_order_acquire);
    const uint64_t viewport_offset =
        local_viewport_offset.load(std::memory_order_acquire);
    if (browse_active || viewport_offset != 0U) {
      render_current_frame();
      return;
    }
    render_frame_result_to_terminal(frame_result);
  };
  auto render_from_channel_update = [&](std::string_view chunk) {
    (void)chunk;
  };
  AMDomain::terminal::ChannelForegroundBindArgs bind_args = {};
  auto load_vt_snapshot = [&]() -> AMDomain::terminal::ChannelVtSnapshot {
    if (!channel_port) {
      return {};
    }
    auto frame_result = channel_port->GetRenderFrame();
    if (!(frame_result.rcm)) {
      return {};
    }
    return frame_result.data.vt_snapshot;
  };
  auto clamp_local_viewport_offset =
      [&](uint64_t desired_offset) -> uint64_t {
    const auto vt_snapshot = load_vt_snapshot();
    if (!vt_snapshot.available || vt_snapshot.in_alternate_screen) {
      return 0U;
    }
    const uint64_t max_offset =
        vt_snapshot.history_lines + vt_snapshot.display_offset;
    return std::min(desired_offset, max_offset);
  };
  auto apply_local_viewport_offset =
      [&](uint64_t desired_offset) -> bool {
    const uint64_t clamped = clamp_local_viewport_offset(desired_offset);
    const bool browse_active = clamped != 0U;
    const bool old_browse_active =
        local_browse_active.exchange(browse_active, std::memory_order_acq_rel);
    const uint64_t old_offset =
        local_viewport_offset.exchange(clamped, std::memory_order_acq_rel);
    if (old_offset == clamped && old_browse_active == browse_active) {
      return false;
    }
    render_current_frame();
    return true;
  };
  auto exit_local_scrollback = [&]() -> bool {
    local_browse_active.store(false, std::memory_order_release);
    return apply_local_viewport_offset(0U);
  };
  auto sync_channel_resize_if_needed = [&]() {
    if (!channel_port) {
      return;
    }
    auto const current_geometry = AMTerminalTools::GetTerminalViewportInfo();
    if (current_geometry.cols == last_geometry.cols &&
        current_geometry.rows == last_geometry.rows &&
        current_geometry.width == last_geometry.width &&
        current_geometry.height == last_geometry.height) {
      return;
    }

    AMDomain::terminal::ChannelResizeArgs resize_args = {};
    resize_args.cols = std::max(1, current_geometry.cols);
    resize_args.rows = std::max(1, current_geometry.rows);
    resize_args.width = std::max(0, current_geometry.width);
    resize_args.height = std::max(0, current_geometry.height);
    auto resize_result = channel_port->Resize(resize_args, control);
    if (!(resize_result.rcm)) {
      return;
    }

    last_geometry = current_geometry;
    local_viewport_offset.store(
        clamp_local_viewport_offset(
            local_viewport_offset.load(std::memory_order_acquire)),
        std::memory_order_release);
    render_current_frame();
  };
  auto passthrough_escape_sequence =
      [&](std::string &passthrough, size_t length) {
    if (length == 0U || pending_local_input.size() < length) {
      return;
    }
    if (local_browse_active.load(std::memory_order_acquire)) {
      (void)exit_local_scrollback();
    }
    passthrough.append(pending_local_input.data(), length);
    pending_local_input.erase(0, length);
  };
  bind_args.input_transformer = [&](std::string_view chunk) -> std::string {
    std::lock_guard<std::mutex> input_guard(local_input_mutex);
    pending_local_input.append(chunk.data(), chunk.size());
    std::string passthrough = {};
    constexpr uint64_t kMouseWheelStep = 3U;
    auto page_step = [&]() -> uint64_t {
      const auto vt_snapshot = load_vt_snapshot();
      return static_cast<uint64_t>(std::max(1, vt_snapshot.rows));
    };
    auto try_handle_mouse_sequence = [&](const std::string &seq) -> bool {
      uint64_t button = 0;
      if (seq.size() >= 6U && seq.starts_with("\x1b[<")) {
        size_t const first_sep = seq.find(';', 3U);
        if (first_sep == std::string::npos || first_sep <= 3U) {
          return false;
        }
        auto const *begin = seq.data() + 3;
        auto const *end = seq.data() + first_sep;
        auto const parse_result = std::from_chars(begin, end, button);
        if (parse_result.ec != std::errc{} || parse_result.ptr != end) {
          return false;
        }
      } else if (seq.size() == 6U && seq.starts_with("\x1b[M")) {
        unsigned char const encoded = static_cast<unsigned char>(seq[3]);
        if (encoded < 32U) {
          return false;
        }
        button = static_cast<uint64_t>(encoded - 32U);
      } else {
        return false;
      }

      auto const vt_snapshot = load_vt_snapshot();
      bool const wheel = (button & 64U) != 0U && (button & 3U) <= 1U;
      if (local_browse_active.load(std::memory_order_acquire)) {
        if (wheel) {
          uint64_t const current =
              local_viewport_offset.load(std::memory_order_acquire);
          if ((button & 1U) == 0U) {
            uint64_t const desired =
                (current > std::numeric_limits<uint64_t>::max() - kMouseWheelStep)
                    ? std::numeric_limits<uint64_t>::max()
                    : current + kMouseWheelStep;
            (void)apply_local_viewport_offset(desired);
          } else {
            (void)apply_local_viewport_offset(
                current > kMouseWheelStep ? current - kMouseWheelStep : 0U);
          }
        }
        return true;
      }

      if (vt_snapshot.available && vt_snapshot.mouse_reporting_active) {
        passthrough.append(seq);
        return true;
      }

      if (wheel && vt_snapshot.available && !vt_snapshot.in_alternate_screen) {
        local_browse_active.store(true, std::memory_order_release);
        uint64_t const current =
            local_viewport_offset.load(std::memory_order_acquire);
        if ((button & 1U) == 0U) {
          uint64_t const desired =
              (current > std::numeric_limits<uint64_t>::max() - kMouseWheelStep)
                  ? std::numeric_limits<uint64_t>::max()
                  : current + kMouseWheelStep;
          (void)apply_local_viewport_offset(desired);
        } else {
          (void)apply_local_viewport_offset(
              current > kMouseWheelStep ? current - kMouseWheelStep : 0U);
        }
        return true;
      }

      return true;
    };

    while (!pending_local_input.empty()) {
      if (pending_local_input.starts_with(kLocalWheelUpInput_)) {
        local_browse_active.store(true, std::memory_order_release);
        uint64_t const current =
            local_viewport_offset.load(std::memory_order_acquire);
        uint64_t const desired =
            (current > std::numeric_limits<uint64_t>::max() - kMouseWheelStep)
                ? std::numeric_limits<uint64_t>::max()
                : current + kMouseWheelStep;
        (void)apply_local_viewport_offset(desired);
        pending_local_input.erase(0, kLocalWheelUpInput_.size());
        continue;
      }
      if (pending_local_input.starts_with(kLocalWheelDownInput_)) {
        local_browse_active.store(true, std::memory_order_release);
        uint64_t const current =
            local_viewport_offset.load(std::memory_order_acquire);
        (void)apply_local_viewport_offset(
            current > kMouseWheelStep ? current - kMouseWheelStep : 0U);
        pending_local_input.erase(0, kLocalWheelDownInput_.size());
        continue;
      }

      unsigned char const first =
          static_cast<unsigned char>(pending_local_input.front());
      if (first != 0x1bU) {
        if (local_browse_active.load(std::memory_order_acquire)) {
          (void)exit_local_scrollback();
        }
        passthrough.push_back(pending_local_input.front());
        pending_local_input.erase(0, 1U);
        continue;
      }

      if (pending_local_input.size() == 1U) {
        break;
      }

      if (pending_local_input[1] == '[') {
        if (pending_local_input.size() >= 6U &&
            pending_local_input[2] == 'M') {
          std::string const seq = pending_local_input.substr(0, 6U);
          if (try_handle_mouse_sequence(seq)) {
            pending_local_input.erase(0, seq.size());
            continue;
          }
        }

        size_t final_pos = 2U;
        while (final_pos < pending_local_input.size()) {
          unsigned char const ch =
              static_cast<unsigned char>(pending_local_input[final_pos]);
          if (ch >= 0x40U && ch <= 0x7eU) {
            break;
          }
          ++final_pos;
        }
        if (final_pos >= pending_local_input.size()) {
          break;
        }

        std::string const seq = pending_local_input.substr(0, final_pos + 1U);
        if (try_handle_mouse_sequence(seq)) {
          pending_local_input.erase(0, seq.size());
          continue;
        }
        if (seq == "\x1b[5~") {
          local_browse_active.store(true, std::memory_order_release);
          uint64_t const current =
              local_viewport_offset.load(std::memory_order_acquire);
          uint64_t const step = page_step();
          uint64_t const desired =
              (current > std::numeric_limits<uint64_t>::max() - step)
                  ? std::numeric_limits<uint64_t>::max()
                  : current + step;
          (void)apply_local_viewport_offset(desired);
          pending_local_input.erase(0, seq.size());
          continue;
        }
        if (seq == "\x1b[6~") {
          local_browse_active.store(true, std::memory_order_release);
          uint64_t const current =
              local_viewport_offset.load(std::memory_order_acquire);
          uint64_t const step = page_step();
          (void)apply_local_viewport_offset(
              current > step ? current - step : 0U);
          pending_local_input.erase(0, seq.size());
          continue;
        }
        if (seq == "\x1b[H" || seq == "\x1b[1~") {
          local_browse_active.store(true, std::memory_order_release);
          (void)apply_local_viewport_offset(
              std::numeric_limits<uint64_t>::max());
          pending_local_input.erase(0, seq.size());
          continue;
        }
        if (seq == "\x1b[F" || seq == "\x1b[4~") {
          (void)exit_local_scrollback();
          pending_local_input.erase(0, seq.size());
          continue;
        }

        passthrough_escape_sequence(passthrough, seq.size());
        continue;
      }

      if (pending_local_input[1] == 'O') {
        if (pending_local_input.size() < 3U) {
          break;
        }
        std::string const seq = pending_local_input.substr(0, 3U);
        if (seq == "\x1bOH") {
          local_browse_active.store(true, std::memory_order_release);
          (void)apply_local_viewport_offset(
              std::numeric_limits<uint64_t>::max());
          pending_local_input.erase(0, seq.size());
          continue;
        }
        if (seq == "\x1bOF") {
          (void)exit_local_scrollback();
          pending_local_input.erase(0, seq.size());
          continue;
        }

        passthrough_escape_sequence(passthrough, seq.size());
        continue;
      }

      if (pending_local_input.size() < 2U) {
        break;
      }
      passthrough_escape_sequence(passthrough, 2U);
    }
    return passthrough;
  };

  bind_args.processor = render_from_channel_update;
  bind_args.render_processor = render_from_channel_frame;
  bind_args.key_event_handle = keyboard_monitor->WaitHandle();
  bind_args.key_cache = keyboard_monitor->KeyCache();
  bind_args.control = control;
  bind_args.write_kick_timeout_ms = write_kick_timeout_ms;

  enter_physical_alt_screen();

  auto bind_result = channel_port->BindForeground(bind_args);
  if (!(bind_result.rcm)) {
    leave_physical_alt_screen();
    clear_keyboard_capture_buffers();
    raw_terminal.Restore();
    RestoreCliPromptStateAfterTerminalExit_();
    prompt_cache_guard.Disable();
    prompt_io_manager_.Print("");
    prompt_io_manager_.ErrorFormat(bind_result.rcm);
    return bind_result.rcm;
  }

  sync_channel_resize_if_needed();
  render_current_frame();

  if (bind_result.data.soft_limit_hit) {
    const size_t threshold_bytes = bind_result.data.soft_limit_threshold_bytes;
    prompt_io_manager_.Print(
        AMStr::fmt("🚨 Terminal output cache reached soft limit ({})",
                   AMStr::FormatSize(threshold_bytes)));
  }

  if (refresh_prompt_on_enter &&
      (bind_result.data.replayed_bytes + bind_result.data.fallback_bytes) ==
          0U &&
      !bind_result.data.closed) {
    render_current_frame();
  }

  if (bind_result.data.closed) {
    (void)channel_port->UnbindForeground();
    leave_physical_alt_screen();
    clear_keyboard_capture_buffers();
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
    sync_channel_resize_if_needed();

    const auto loop_state = channel_port->GetLoopState();
    if (loop_state.closed) {
      wait_rcm = (loop_state.last_error) ? loop_state.last_error : OK;
      break;
    }
    if (loop_state.detach_requested || !loop_state.foreground_bound) {
      detached = true;
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
        WaitForMultipleObjects(wait_count, waiters.data(), FALSE, 40);
    if (wait_rc == WAIT_TIMEOUT) {
      sync_channel_resize_if_needed();
      continue;
    }
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
    sync_channel_resize_if_needed();
#else
    if (control.IsInterrupted()) {
      (void)channel_port->RequestForegroundDetach();
      detached = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    sync_channel_resize_if_needed();
#endif
  }

  const auto final_state = channel_port->GetLoopState();
  if (final_state.closed && !detached && (wait_rcm) &&
      !(final_state.last_error)) {
    wait_rcm = final_state.last_error;
  }
  const bool remove_closed_channel = final_state.closed && !detached;

  clear_keyboard_capture_buffers();
  leave_physical_alt_screen();
  raw_terminal.Restore();
  RestoreCliPromptStateAfterTerminalExit_();
  prompt_cache_guard.Disable();

  if (remove_closed_channel) {
    const auto close_result =
        terminal_handle->CloseChannel({channel_name, true}, control);
    if (!(close_result.rcm) && (wait_rcm)) {
      wait_rcm = close_result.rcm;
    }
  } else {
    (void)channel_port->UnbindForeground();
  }

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
    const std::optional<ControlComponent> &control_opt) const {
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
      const ECM rcm = (client_result.rcm) ? Err(EC::InvalidHandle, "", nickname,
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
    const std::optional<ControlComponent> &control_opt) const {
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
    const std::optional<ControlComponent> &control_opt) const {
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
      const ECM rcm =
          terminal_result.rcm
              ? Err(EC::ClientNotFound, "", normalized, "terminal not found")
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
      return Err(EC::OperationTimeout, "", nickname, "Operation timed out");
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

ECM TerminalInterfaceService::ClearTerminals(
    const TerminalClearArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  constexpr const char *kOp = "term.clear";
  int timeout_ms = 0;
  ECM timeout_rcm = TimeoutSecondsToMs_(arg.timeout_s, kOp, &timeout_ms);
  if (!(timeout_rcm)) {
    prompt_io_manager_.ErrorFormat(timeout_rcm);
    return timeout_rcm;
  }

  const auto base_control =
      ResolveControl_(default_interrupt_flag_, control_opt);
  const auto names = terminal_service_.ListTerminalNames();
  if (names.empty()) {
    prompt_io_manager_.FmtPrint(
        "term clear: checked=0 removed=0 kept=0 timeout={}s", arg.timeout_s);
    return OK;
  }

  ECM status = OK;
  size_t checked_count = 0U;
  size_t removed_count = 0U;
  size_t kept_count = 0U;
  for (const auto &name : names) {
    if (base_control.IsInterrupted()) {
      return Err(EC::Terminate, kOp, name, "Interrupted by user");
    }

    ++checked_count;
    auto terminal_result = terminal_service_.GetTerminalByNickname(name, true);
    const ControlComponent check_control(base_control.ControlToken(),
                                         timeout_ms);
    bool healthy = false;
    ECM check_rcm = terminal_result.rcm;
    AMDomain::client::ClientStatus session_status =
        AMDomain::client::ClientStatus::NotInitialized;
    if ((terminal_result.rcm) && terminal_result.data) {
      auto session_result =
          terminal_result.data->CheckSession({}, check_control);
      check_rcm = session_result.rcm;
      session_status = session_result.data.status;
      healthy = (session_result.rcm) &&
                session_status == AMDomain::client::ClientStatus::OK &&
                session_result.data.is_supported;
    }

    if (healthy) {
      ++kept_count;
      prompt_io_manager_.FmtPrint("✅ Terminal kept: {} ({})", name,
                                  AMStr::ToString(session_status));
      continue;
    }

    const ControlComponent remove_control(base_control.ControlToken(),
                                          timeout_ms);
    const ECM remove_rcm =
        terminal_service_.RemoveTerminal(name, remove_control);
    if (!(remove_rcm)) {
      status = MergeStatus_(status, remove_rcm);
      prompt_io_manager_.FmtPrint("❌ Terminal remove failed: {} {} {}", name,
                                  AMStr::ToString(remove_rcm.code),
                                  remove_rcm.msg());
      continue;
    }

    ++removed_count;
    prompt_io_manager_.FmtPrint("🧹 Terminal removed: {} {} {}", name,
                                AMStr::ToString(check_rcm.code),
                                check_rcm.msg());
  }

  prompt_io_manager_.FmtPrint(
      "term clear: checked={} removed={} kept={} timeout={}s", checked_count,
      removed_count, kept_count, arg.timeout_s);
  return status;
}

ECM TerminalInterfaceService::AddChannel(
    const ChannelAddArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
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
    const std::optional<ControlComponent> &control_opt) const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string nickname =
      AMDomain::host::HostService::NormalizeNickname(arg.nickname);
  if (arg.nickname.empty()) {
    nickname = client_service_.CurrentNickname();
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm ? Err(EC::InvalidHandle, "", nickname,
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
    const std::optional<ControlComponent> &control_opt) const {
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
    const std::optional<ControlComponent> &control_opt) const {
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

ECM TerminalInterfaceService::ClearChannels(
    const ChannelClearArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  constexpr const char *kOp = "channel.clear";
  int timeout_ms = 0;
  ECM timeout_rcm = TimeoutSecondsToMs_(arg.timeout_s, kOp, &timeout_ms);
  if (!(timeout_rcm)) {
    prompt_io_manager_.ErrorFormat(timeout_rcm);
    terminal_service_.TraceRuntimeEvent(timeout_rcm, "<channel>", kOp,
                                        "invalid timeout");
    return timeout_rcm;
  }

  const auto base_control =
      ResolveControl_(default_interrupt_flag_, control_opt);
  std::string nickname = AMDomain::host::HostService::NormalizeNickname(
      AMStr::Strip(arg.nickname));
  if (nickname.empty()) {
    nickname = AMDomain::host::HostService::NormalizeNickname(
        AMStr::Strip(client_service_.CurrentNickname()));
  }
  if (AMDomain::host::HostService::IsLocalNickname(nickname)) {
    nickname = "local";
  }

  auto terminal_result =
      terminal_service_.GetTerminalByNickname(nickname, false);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    const ECM rcm = terminal_result.rcm ? Err(EC::ClientNotFound, kOp, nickname,
                                              "Terminal not found")
                                        : terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    terminal_service_.TraceRuntimeEvent(rcm, nickname,
                                        "terminal.channel.clear.resolve",
                                        "terminal unavailable");
    return rcm;
  }

  auto list_result = terminal_result.data->ListChannels({}, base_control);
  if (!(list_result.rcm)) {
    prompt_io_manager_.ErrorFormat(list_result.rcm);
    terminal_service_.TraceRuntimeEvent(list_result.rcm, nickname,
                                        "terminal.channel.clear.list",
                                        "failed to list channels");
    return list_result.rcm;
  }

  terminal_service_.TraceRuntimeEvent(
      OK, nickname, "terminal.channel.clear.start",
      AMStr::fmt("channels={} timeout_ms={}", list_result.data.channels.size(),
                 timeout_ms));

  const AMTerminalTools::TerminalViewportInfo geometry =
      AMTerminalTools::GetTerminalViewportInfo();
  ECM status = OK;
  size_t checked_count = 0U;
  size_t removed_count = 0U;
  size_t kept_count = 0U;
  for (const auto &[channel_name, channel_port] : list_result.data.channels) {
    if (base_control.IsInterrupted()) {
      return Err(EC::Terminate, kOp, channel_name, "Interrupted by user");
    }

    ++checked_count;
    ECM check_rcm = OK;
    bool healthy = false;
    if (!channel_port) {
      check_rcm =
          Err(EC::InvalidHandle, kOp, channel_name, "Channel handle is null");
    } else {
      const auto before_state = channel_port->GetState();
      if (before_state.closed) {
        check_rcm =
            before_state.last_error
                ? Err(EC::NoConnection, kOp, channel_name, "Channel is closed")
                : before_state.last_error;
      } else {
        const ControlComponent check_control(base_control.ControlToken(),
                                             timeout_ms);
        AMDomain::terminal::ChannelResizeArgs resize_args = {};
        resize_args.cols = std::max(1, geometry.cols);
        resize_args.rows = std::max(1, geometry.rows);
        resize_args.width = std::max(0, geometry.width);
        resize_args.height = std::max(0, geometry.height);
        auto resize_result = channel_port->Resize(resize_args, check_control);
        const auto after_state = channel_port->GetState();
        check_rcm = resize_result.rcm;
        healthy = (resize_result.rcm) && !after_state.closed;
        if (!healthy && (check_rcm)) {
          check_rcm = after_state.last_error
                          ? Err(EC::NoConnection, kOp, channel_name,
                                "Channel is closed")
                          : after_state.last_error;
        }
      }
    }

    if (healthy) {
      ++kept_count;
      prompt_io_manager_.FmtPrint("✅ Channel kept: {}@{}", nickname,
                                  channel_name);
      continue;
    }

    const ControlComponent remove_control(base_control.ControlToken(),
                                          timeout_ms);
    auto close_result = terminal_result.data->CloseChannel({channel_name, true},
                                                           remove_control);
    ECM remove_rcm = close_result.rcm;
    if ((remove_rcm)) {
      remove_rcm = terminal_service_.DropChannelPort(nickname, channel_name,
                                                     remove_control);
    }
    if (!(remove_rcm)) {
      status = MergeStatus_(status, remove_rcm);
      prompt_io_manager_.FmtPrint(
          "❌ Channel remove failed: {}@{} {} {}", nickname, channel_name,
          AMStr::ToString(remove_rcm.code), remove_rcm.msg());
      terminal_service_.TraceRuntimeEvent(
          remove_rcm, nickname, "terminal.channel.clear.remove",
          AMStr::fmt("channel={} check={} check_error={}", channel_name,
                     AMStr::ToString(check_rcm.code), check_rcm.msg()));
      continue;
    }

    ++removed_count;
    prompt_io_manager_.FmtPrint("🧹 Channel removed: {}@{} {} {}", nickname,
                                channel_name, AMStr::ToString(check_rcm.code),
                                check_rcm.msg());
    terminal_service_.TraceRuntimeEvent(
        OK, nickname, "terminal.channel.clear.remove",
        AMStr::fmt("channel={} check={} check_error={}", channel_name,
                   AMStr::ToString(check_rcm.code), check_rcm.msg()));
  }

  prompt_io_manager_.FmtPrint(
      "channel clear: terminal={} checked={} removed={} kept={} timeout={}s",
      nickname, checked_count, removed_count, kept_count, arg.timeout_s);
  terminal_service_.TraceRuntimeEvent(
      status, nickname, "terminal.channel.clear.summary",
      AMStr::fmt("checked={} removed={} kept={} timeout_ms={}", checked_count,
                 removed_count, kept_count, timeout_ms));
  return status;
}

} // namespace AMInterface::terminal
