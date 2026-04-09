#include "Isocline/isocline.h"
#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/terminal.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <limits>
#include <string_view>
#include <thread>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
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

struct TerminalLoopOutcome_ {
  ECM rcm = OK;
  bool force_close = true;
};

[[nodiscard]] ECM BuildTerminalUnsupportedError_(const std::string &nickname) {
  return Err(EC::OperationUnsupported, "terminal", nickname,
             "Current client does not support interactive terminal mode");
}

constexpr const char *kDefaultTerminalChannelName_ = "default";
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

void WriteTerminalBytes_(const std::string &text) {
  if (text.empty()) {
    return;
  }
  (void)std::fwrite(text.data(), 1, text.size(), stdout);
  std::fflush(stdout);
}

bool ConsumeLocalExitByte_(std::string *input) {
  if (input == nullptr || input->empty()) {
    return false;
  }
  const size_t pos = input->find('\x1d'); // Ctrl+]
  if (pos == std::string::npos) {
    return false;
  }
  input->resize(pos);
  return true;
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

ECM EnsureExistingTerminalChannel_(
    AMDomain::terminal::ITerminalPort &terminal,
    const std::optional<std::string> &requested_channel_name,
    const AMDomain::terminal::CheckSessionResult &status,
    const AMTerminalTools::TerminalViewportInfo &geometry,
    const AMDomain::client::ClientControlComponent &control,
    std::string *resolved_channel_name) {
  if (resolved_channel_name == nullptr) {
    return Err(EC::InvalidArg, "terminal.channel.resolve", "<output>",
               "resolved channel output is null");
  }
  *resolved_channel_name = "";

  const std::string requested = requested_channel_name.has_value()
                                    ? AMStr::Strip(*requested_channel_name)
                                    : "";
  if (!requested.empty()) {
    auto active_result = terminal.ActiveChannel({requested}, control);
    if (!(active_result.rcm) || !active_result.data.activated) {
      return active_result.rcm
                 ? Err(EC::CommonFailure, "terminal.channel.active", requested,
                       "Failed to activate terminal channel")
                 : active_result.rcm;
    }
    *resolved_channel_name = requested;
    return OK;
  }

  const std::string current_channel = AMStr::Strip(status.current_channel);
  if (!current_channel.empty()) {
    *resolved_channel_name = current_channel;
    return OK;
  }

  const std::string default_channel = kDefaultTerminalChannelName_;
  auto open_result = terminal.OpenChannel(
      BuildChannelOpenArgs_(default_channel, geometry), control);
  if (!(open_result.rcm) && open_result.rcm.code != EC::TargetAlreadyExists) {
    return open_result.rcm;
  }

  auto active_result = terminal.ActiveChannel({default_channel}, control);
  if (!(active_result.rcm) || !active_result.data.activated) {
    return active_result.rcm
               ? Err(EC::CommonFailure, "terminal.channel.active",
                     default_channel, "Failed to activate terminal channel")
               : active_result.rcm;
  }
  *resolved_channel_name = default_channel;
  return OK;
}

ECM EnsureNewTerminalChannel_(
    AMDomain::terminal::ITerminalPort &terminal,
    const std::optional<std::string> &requested_channel_name,
    const AMTerminalTools::TerminalViewportInfo &geometry,
    const AMDomain::client::ClientControlComponent &control,
    std::string *resolved_channel_name) {
  if (resolved_channel_name == nullptr) {
    return Err(EC::InvalidArg, "terminal.channel.open", "<output>",
               "resolved channel output is null");
  }
  *resolved_channel_name = "";

  std::string channel_name = requested_channel_name.has_value()
                                 ? AMStr::Strip(*requested_channel_name)
                                 : "";
  if (channel_name.empty()) {
    channel_name = kDefaultTerminalChannelName_;
  }

  auto open_result = terminal.OpenChannel(
      BuildChannelOpenArgs_(channel_name, geometry), control);
  if (!(open_result.rcm) && open_result.rcm.code != EC::TargetAlreadyExists) {
    return open_result.rcm;
  }

  auto active_result = terminal.ActiveChannel({channel_name}, control);
  if (!(active_result.rcm) || !active_result.data.activated) {
    return active_result.rcm
               ? Err(EC::CommonFailure, "terminal.channel.active", channel_name,
                     "Failed to activate terminal channel")
               : active_result.rcm;
  }
  *resolved_channel_name = channel_name;
  return OK;
}

template <typename WriteFn, typename ResizeFn, typename ReadFn>
TerminalLoopOutcome_ BridgeInteractiveTerminalCore_(
    const std::string &channel_name,
    const AMDomain::client::ClientControlComponent &base_control,
    WriteFn write_channel, ResizeFn resize_channel, ReadFn read_channel) {
  ScopedRawTerminal_ raw_terminal = {};
  if (!raw_terminal.Activate()) {
    return {Err(EC::CommonFailure, "terminal.raw_mode", "<stdin>",
                raw_terminal.Error()),
            true};
  }

  AMTerminalTools::TerminalViewportInfo last_geometry =
      AMTerminalTools::GetTerminalViewportInfo();
  constexpr int kIdleSleepMs = 5;

  while (true) {
    bool had_activity = false;
    if (base_control.IsInterrupted()) {
      return {Err(EC::Terminate, "terminal.loop", "<terminal>",
                  "Terminal interrupted"),
              true};
    }
    if (base_control.IsTimeout()) {
      return {Err(EC::OperationTimeout, "terminal.loop", "<terminal>",
                  "Terminal timed out"),
              true};
    }

    std::string input = {};
    std::string input_error = {};
    const auto input_status = PollLocalTerminalInput_(&input, &input_error);
    if (input_status == LocalInputPollStatus_::Error) {
      return {Err(EC::LocalFileReadError, "terminal.input", "<stdin>",
                  input_error.empty() ? "Local terminal input failed"
                                      : input_error),
              true};
    }
    if (input_status == LocalInputPollStatus_::Closed) {
      return {OK, false};
    }

    const bool request_local_exit = ConsumeLocalExitByte_(&input);
    if (!input.empty()) {
      had_activity = true;
      auto write_result = write_channel(
          AMDomain::terminal::ChannelWriteArgs{
              std::optional<std::string>(channel_name), input},
          base_control);
      if (!(write_result.rcm)) {
        return {write_result.rcm, true};
      }
    }
    if (request_local_exit) {
      return {OK, false};
    }

    const AMTerminalTools::TerminalViewportInfo geometry =
        AMTerminalTools::GetTerminalViewportInfo();
    if (geometry.cols != last_geometry.cols ||
        geometry.rows != last_geometry.rows ||
        geometry.width != last_geometry.width ||
        geometry.height != last_geometry.height) {
      auto resize_result = resize_channel(
          AMDomain::terminal::ChannelResizeArgs{
              std::optional<std::string>(channel_name), geometry.cols,
              geometry.rows, geometry.width, geometry.height},
          base_control);
      if (!(resize_result.rcm)) {
        return {resize_result.rcm, true};
      }
      last_geometry = geometry;
      had_activity = true;
    }

    auto read_result = read_channel(
        AMDomain::terminal::ChannelReadArgs{
            std::optional<std::string>(channel_name), 32U * 1024U},
        base_control);
    if (!(read_result.rcm)) {
      return {read_result.rcm, true};
    }
    if (!read_result.data.output.empty()) {
      WriteTerminalBytes_(read_result.data.output);
      had_activity = true;
    }
    if (read_result.data.eof) {
      return {OK, false};
    }
    if (!had_activity) {
      std::this_thread::sleep_for(std::chrono::milliseconds(kIdleSleepMs));
    }
  }
}

TerminalLoopOutcome_ BridgeInteractiveTerminal_(
    AMDomain::terminal::ITerminalPort &terminal,
    const std::string &channel_name,
    const AMDomain::client::ClientControlComponent &base_control) {
  return BridgeInteractiveTerminalCore_(
      channel_name, base_control,
      [&terminal](const AMDomain::terminal::ChannelWriteArgs &write_args,
                  const AMDomain::client::ClientControlComponent &control) {
        return terminal.WriteChannel(write_args, control);
      },
      [&terminal](const AMDomain::terminal::ChannelResizeArgs &resize_args,
                  const AMDomain::client::ClientControlComponent &control) {
        return terminal.ResizeChannel(resize_args, control);
      },
      [&terminal](const AMDomain::terminal::ChannelReadArgs &read_args,
                  const AMDomain::client::ClientControlComponent &control) {
        return terminal.ReadChannel(read_args, control);
      });
}

ECM ExecuteTerminalSession_(
    AMDomain::terminal::ITerminalPort &terminal,
    const TerminalTargetSpec_ &target,
    const AMDomain::client::ClientControlComponent &control,
    bool reuse_existing_channel,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager) {
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
  ECM channel_rcm =
      reuse_existing_channel
          ? EnsureExistingTerminalChannel_(terminal, target.channel_name,
                                           status_result.data, geometry,
                                           control, &channel_name)
          : EnsureNewTerminalChannel_(terminal, target.channel_name, geometry,
                                      control, &channel_name);
  if (!(channel_rcm)) {
    return channel_rcm;
  }

  ScopedPromptOutputCache_ prompt_cache_guard(&prompt_io_manager);
  TerminalLoopOutcome_ loop_outcome =
      BridgeInteractiveTerminal_(terminal, channel_name, control);

  auto close_result = terminal.CloseChannel(
      AMDomain::terminal::ChannelCloseArgs{channel_name,
                                           loop_outcome.force_close},
      control);
  RestoreCliPromptStateAfterTerminalExit_();
  prompt_cache_guard.Disable();
  prompt_io_manager.Print("");

  ECM final_rcm = loop_outcome.rcm;
  if (!close_result.rcm && final_rcm.code == EC::Success) {
    final_rcm = close_result.rcm;
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
    const ECM run_rcm =
        ExecuteTerminalSession_(*(managed_terminal_result.data), target,
                                control, true, prompt_io_manager_);
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
      filesystem_service_.GetClient(target.nickname, control, true);
  if (!(temp_client_result.rcm) || !temp_client_result.data) {
    const ECM rcm = temp_client_result.rcm
                        ? Err(EC::InvalidHandle, __func__, target.nickname,
                              "Temporary client is null")
                        : temp_client_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto temp_terminal_result =
      terminal_service_.CreateTerminal(temp_client_result.data, true);
  if (!(temp_terminal_result.rcm) || !temp_terminal_result.data) {
    const ECM rcm = (temp_terminal_result.rcm.code == EC::OperationUnsupported)
                        ? BuildTerminalUnsupportedError_(target.nickname)
                        : temp_terminal_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const ECM run_rcm = ExecuteTerminalSession_(
      *temp_terminal_result.data, target, control, false, prompt_io_manager_);
  if (!(run_rcm)) {
    prompt_io_manager_.ErrorFormat(run_rcm);
  }
  return run_rcm;
}

} // namespace AMInterface::filesystem
