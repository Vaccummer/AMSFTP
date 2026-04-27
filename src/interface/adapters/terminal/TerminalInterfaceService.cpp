#include "interface/adapters/terminal/TerminalInterfaceService.hpp"
#include "Isocline/isocline.h"
#include "domain/host/HostDomainService.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/terminal.hpp"
#include "foundation/tools/prompt_ui.hpp"
#include "interface/parser/LuaInterpreter.hpp"
#include "interface/style/StyleIndex.hpp"
#include "interface/style/StyleManager.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <unordered_map>
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

enum class TerminalBannerAlign_ { Left = 0, Center = 1, Right = 2 };

struct TerminalBannerConfig_ {
  std::string text = {};
  std::string background = {};
  std::string foreground = {};
  TerminalBannerAlign_ align = TerminalBannerAlign_::Left;
};

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

[[nodiscard]] AMTerminalTools::TerminalViewportInfo
BuildContentGeometry_(const AMTerminalTools::TerminalViewportInfo &geometry,
                      int fixed_header_rows) {
  auto out = geometry;
  out.rows = std::max(1, geometry.rows - std::max(0, fixed_header_rows));
  return out;
}

[[nodiscard]] int FixedHeaderLineCount_(
    const std::vector<std::string> &banner_lines,
    const std::vector<std::string> &hint_lines,
    bool show_hint,
    int terminal_rows) {
  const int requested =
      static_cast<int>(banner_lines.size() +
                       (show_hint ? hint_lines.size() : 0U));
  if (requested <= 0) {
    return 0;
  }
  return std::min(requested, std::max(0, terminal_rows - 1));
}

struct TerminalTargetSpec_ {
  std::string client_name = "local";
  std::string term_name = {};
  std::string term_key = {};
  bool use_last_entered = false;
};

[[nodiscard]] ECMData<TerminalTargetSpec_>
ParseTermTargetSpec_(const std::string &target_spec,
                     const std::string &default_client_name,
                     bool allow_empty_as_last) {
  TerminalTargetSpec_ out = {};
  out.client_name =
      default_client_name.empty() ? std::string("local") : default_client_name;

  const std::string token = AMStr::Strip(target_spec);
  if (token.empty()) {
    out.use_last_entered = allow_empty_as_last;
    return {out, OK};
  }

  const size_t at_pos = token.find('@');
  if (at_pos == std::string::npos) {
    out.term_name = token;
  } else {
    const std::string client_part = AMStr::Strip(token.substr(0, at_pos));
    const std::string term_part = AMStr::Strip(token.substr(at_pos + 1));
    if (!client_part.empty()) {
      const std::string normalized =
          AMDomain::host::HostService::NormalizeNickname(client_part);
      if (!AMDomain::host::HostService::IsLocalNickname(normalized) &&
          !AMDomain::host::HostService::ValidateNickname(normalized)) {
        return {TerminalTargetSpec_{},
                Err(EC::InvalidArg, "term.target.parse", client_part,
                    "Invalid host nickname in term target")};
      }
      out.client_name = normalized.empty() ? out.client_name : normalized;
    }
    out.term_name = term_part;
  }

  out.client_name =
      AMDomain::host::HostService::NormalizeNickname(out.client_name);
  if (AMDomain::host::HostService::IsLocalNickname(out.client_name)) {
    out.client_name = "local";
  }
  out.term_name = AMStr::Strip(out.term_name);
  if (out.client_name.empty()) {
    return {TerminalTargetSpec_{},
            Err(EC::InvalidArg, "term.target.parse", "clientname",
                "Term client name is empty")};
  }
  if (out.term_name.empty()) {
    return {TerminalTargetSpec_{},
            Err(EC::InvalidArg, "term.target.parse", "nickname",
                "Term nickname is empty")};
  }
  if (!AMDomain::host::HostService::ValidateNickname(out.term_name)) {
    return {TerminalTargetSpec_{},
            Err(EC::InvalidArg, "term.target.parse", out.term_name,
                "Invalid term nickname")};
  }

  out.term_key = out.client_name + "@" + out.term_name;
  return {out, OK};
}

[[nodiscard]] std::vector<TerminalTargetSpec_>
NormalizeTermTargets_(const std::vector<std::string> &raw_targets,
                      const std::string &default_client_name, ECM *out_rcm) {
  std::vector<TerminalTargetSpec_> out = {};
  out.reserve(raw_targets.size());
  std::unordered_set<std::string> seen = {};
  ECM status = OK;

  for (const auto &raw_target : raw_targets) {
    auto parsed = ParseTermTargetSpec_(raw_target, default_client_name, false);
    if (!(parsed.rcm)) {
      if ((status)) {
        status = parsed.rcm;
      }
      continue;
    }
    if (parsed.data.term_key.empty()) {
      continue;
    }
    if (!seen.insert(parsed.data.term_key).second) {
      continue;
    }
    out.push_back(std::move(parsed.data));
  }
  if (out_rcm != nullptr) {
    *out_rcm = status;
  }
  return out;
}

[[nodiscard]] std::optional<std::string>
AdjacentTermKey_(const AMApplication::terminal::TermAppService &service,
                 const std::string &current_key, int direction) {
  auto names = service.ListTerminalNames();
  if (names.empty()) {
    return std::nullopt;
  }
  std::ranges::sort(names);
  auto it = std::ranges::find(names, current_key);
  if (it == names.end()) {
    return names.front();
  }
  if (names.size() == 1U) {
    return *it;
  }
  const size_t pos = static_cast<size_t>(std::distance(names.begin(), it));
  if (direction < 0) {
    return names[(pos + names.size() - 1U) % names.size()];
  }
  return names[(pos + 1U) % names.size()];
}

[[nodiscard]] bool StartsWithAny_(const std::string &text,
                                  std::initializer_list<std::string_view> seqs,
                                  size_t *out_len = nullptr) {
  for (std::string_view seq : seqs) {
    if (text.size() >= seq.size() &&
        std::string_view(text.data(), seq.size()) == seq) {
      if (out_len != nullptr) {
        *out_len = seq.size();
      }
      return true;
    }
  }
  return false;
}

[[nodiscard]] size_t CompleteEscapeSequenceLength_(const std::string &text) {
  if (text.size() < 2U || text.front() != '\x1b') {
    return 0U;
  }
  if (text[1] == '[') {
    size_t final_pos = 2U;
    while (final_pos < text.size()) {
      const unsigned char ch = static_cast<unsigned char>(text[final_pos]);
      if (ch >= 0x40U && ch <= 0x7eU) {
        return final_pos + 1U;
      }
      ++final_pos;
    }
    return 0U;
  }
  if (text[1] == 'O') {
    return text.size() >= 3U ? 3U : 0U;
  }
  return 1U;
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

  const std::string state_text = terminal_ok ? "running" : "disconnected";
  return {styled_header + ": " + state_text, OK};
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
    bool local_input_active) {
  constexpr std::string_view kDisableMouseProtocols =
      "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1007l";
  std::string out(kDisableMouseProtocols);
  out += "\x1b[?1l";
  out += "\x1b>";

  if (vt_snapshot.available) {
    if (!local_input_active && vt_snapshot.mouse_reporting_active) {
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
    if (!local_input_active && vt_snapshot.in_alternate_screen &&
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

AMInterface::prompt::PromptVarMap
BuildTerminalBannerLuaVars_(const TerminalTargetSpec_ &target,
                            const AMDomain::host::ConRequest &request,
                            AMDomain::client::OS_TYPE os_type,
                            const AMDomain::style::CLIPromptIconsStyle &icons) {
  using AMInterface::prompt::PromptVarMap;
  using AMInterface::prompt::PromptVarValue;

  auto resolve_sysicon = [&]() -> std::string {
    const std::string fallback = icons.default_icon;
    switch (os_type) {
    case AMDomain::client::OS_TYPE::Windows:
      return icons.windows.empty() ? fallback : icons.windows;
    case AMDomain::client::OS_TYPE::Linux:
      return icons.linux.empty() ? fallback : icons.linux;
    case AMDomain::client::OS_TYPE::MacOS:
      return icons.macos.empty() ? fallback : icons.macos;
    case AMDomain::client::OS_TYPE::FreeBSD:
      return icons.freebsd.empty() ? fallback : icons.freebsd;
    case AMDomain::client::OS_TYPE::Unix:
      return icons.unix.empty() ? fallback : icons.unix;
    case AMDomain::client::OS_TYPE::Unknown:
    case AMDomain::client::OS_TYPE::Uncertain:
    default:
      return fallback;
    }
  };

  PromptVarMap vars = {};
  vars["os_type"] =
      PromptVarValue{AMStr::lowercase(AMStr::ToString(os_type))};
  vars["clientname"] = PromptVarValue{target.client_name};
  vars["termname"] = PromptVarValue{target.term_name};
  vars["hostname"] = PromptVarValue{request.hostname};
  vars["username"] = PromptVarValue{request.username};
  vars["nickname"] = PromptVarValue{target.term_name};
  vars["port"] = PromptVarValue{request.port};
  vars["sysicon"] = PromptVarValue{resolve_sysicon()};
  return vars;
}

TerminalBannerAlign_ ParseTerminalBannerAlign_(std::string_view raw_align) {
  const std::string align =
      AMStr::lowercase(AMStr::Strip(std::string(raw_align)));
  if (align == "center") {
    return TerminalBannerAlign_::Center;
  }
  if (align == "right") {
    return TerminalBannerAlign_::Right;
  }
  return TerminalBannerAlign_::Left;
}

TerminalBannerConfig_ ResolveTerminalBanner_(
    const AMInterface::style::AMStyleService &style_service,
    const TerminalTargetSpec_ &target,
    const AMDomain::host::ConRequest &request,
    AMDomain::client::OS_TYPE os_type) {
  TerminalBannerConfig_ out = {};
  const auto style_config = style_service.GetInitArg().style;
  const auto &banner = style_config.terminal.banner;
  const std::string banner_template = banner.template_text.empty()
                                          ? style_config.terminal.banner_template
                                          : banner.template_text;
  out.background = banner.background;
  out.align = ParseTerminalBannerAlign_(banner.align);
  if (AMStr::Strip(banner_template).empty()) {
    return out;
  }

  const auto render = AMInterface::prompt::LUARender(
      {banner_template},
      BuildTerminalBannerLuaVars_(target, request, os_type,
                                  style_config.cli_prompt.icons));
  if (!(render.rcm)) {
    out.text = banner_template;
    return out;
  }
  out.text = render.data;
  return out;
}

TerminalBannerConfig_ ResolveTerminalControlNote_(
    const AMInterface::style::AMStyleService &style_service,
    const TerminalTargetSpec_ &target,
    const AMDomain::host::ConRequest &request,
    AMDomain::client::OS_TYPE os_type) {
  TerminalBannerConfig_ out = {};
  const auto style_config = style_service.GetInitArg().style;
  const auto &control_note = style_config.terminal.control_note;
  out.background = control_note.background;
  out.foreground = control_note.foreground;
  out.align = ParseTerminalBannerAlign_(control_note.align);
  if (AMStr::Strip(control_note.template_text).empty()) {
    return out;
  }

  const auto render = AMInterface::prompt::LUARender(
      {control_note.template_text},
      BuildTerminalBannerLuaVars_(target, request, os_type,
                                  style_config.cli_prompt.icons));
  if (!(render.rcm)) {
    out.text = control_note.template_text;
    return out;
  }
  out.text = render.data;
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

[[nodiscard]] std::vector<std::string>
SplitTerminalBannerLines_(std::string_view banner) {
  std::vector<std::string> lines = {};
  size_t start = 0;
  while (start < banner.size()) {
    const size_t cr = banner.find('\r', start);
    const size_t lf = banner.find('\n', start);
    size_t end = std::string_view::npos;
    if (cr == std::string_view::npos) {
      end = lf;
    } else if (lf == std::string_view::npos) {
      end = cr;
    } else {
      end = std::min(cr, lf);
    }

    if (end == std::string_view::npos) {
      lines.emplace_back(banner.substr(start));
      break;
    }

    lines.emplace_back(banner.substr(start, end - start));
    start = end + 1U;
    if (end + 1U < banner.size() && banner[end] == '\r' &&
        banner[end + 1U] == '\n') {
      start = end + 2U;
    }
  }
  return lines;
}

[[nodiscard]] std::optional<std::array<int, 3>>
ParseBannerBackgroundRgb_(std::string_view raw_background) {
  const std::string text = AMStr::Strip(std::string(raw_background));
  if (text.empty()) {
    return std::nullopt;
  }
  for (size_t i = 0; i + 7U <= text.size(); ++i) {
    if (text[i] != '#') {
      continue;
    }
    const std::string_view hex(text.data() + i + 1U, 6U);
    bool all_hex = true;
    for (char ch : hex) {
      if (!std::isxdigit(static_cast<unsigned char>(ch))) {
        all_hex = false;
        break;
      }
    }
    if (!all_hex) {
      continue;
    }
    int value = 0;
    const auto result =
        std::from_chars(hex.data(), hex.data() + hex.size(), value, 16);
    if (result.ec != std::errc{} || result.ptr != hex.data() + hex.size()) {
      continue;
    }
    return std::array<int, 3>{(value >> 16) & 0xff, (value >> 8) & 0xff,
                              value & 0xff};
  }
  return std::nullopt;
}

[[nodiscard]] std::string
BuildBackgroundAnsi_(std::string_view raw_background) {
  const auto rgb = ParseBannerBackgroundRgb_(raw_background);
  if (!rgb.has_value()) {
    return {};
  }
  return AMStr::fmt("\x1b[48;2;{};{};{}m", (*rgb)[0], (*rgb)[1], (*rgb)[2]);
}

[[nodiscard]] std::string BuildForegroundAnsi_(std::string_view raw_foreground) {
  const auto rgb = ParseBannerBackgroundRgb_(raw_foreground);
  if (!rgb.has_value()) {
    return {};
  }
  return AMStr::fmt("\x1b[38;2;{};{};{}m", (*rgb)[0], (*rgb)[1], (*rgb)[2]);
}

[[nodiscard]] bool AppendTerminalBbcodeTokenAnsi_(std::string_view token,
                                                  std::string *out) {
  if (out == nullptr) {
    return false;
  }
  const std::string text = AMStr::Strip(std::string(token));
  if (text.empty()) {
    return false;
  }
  if (text == "/") {
    *out += "\x1b[0m";
    return true;
  }

  bool handled = false;
  size_t pos = 0U;
  while (pos < text.size()) {
    while (pos < text.size() &&
           std::isspace(static_cast<unsigned char>(text[pos])) != 0) {
      ++pos;
    }
    const size_t start = pos;
    while (pos < text.size() &&
           std::isspace(static_cast<unsigned char>(text[pos])) == 0) {
      ++pos;
    }
    if (start == pos) {
      continue;
    }

    const std::string_view part(text.data() + start, pos - start);
    if (part == "b" || part == "bold") {
      *out += "\x1b[1m";
      handled = true;
    } else if (part == "u" || part == "underline") {
      *out += "\x1b[4m";
      handled = true;
    } else if (part == "i" || part == "italic") {
      *out += "\x1b[3m";
      handled = true;
    } else if (part == "!b") {
      *out += "\x1b[22m";
      handled = true;
    } else if (part == "!u") {
      *out += "\x1b[24m";
      handled = true;
    } else if (part == "!i") {
      *out += "\x1b[23m";
      handled = true;
    } else if (part.size() == 7U && part.front() == '#') {
      *out += BuildForegroundAnsi_(part);
      handled = true;
    }
  }
  return handled;
}

[[nodiscard]] std::string RenderTerminalBbcodeAnsi_(const std::string &line) {
  std::string out = {};
  out.reserve(line.size() + 32U);
  for (size_t i = 0U; i < line.size(); ++i) {
    const char ch = line[i];
    if (ch == '\\' && i + 1U < line.size() &&
        (line[i + 1U] == '[' || line[i + 1U] == ']')) {
      out.push_back(line[i + 1U]);
      ++i;
      continue;
    }
    if (ch == '[') {
      const size_t close = line.find(']', i + 1U);
      if (close != std::string::npos) {
        const std::string_view token(line.data() + i + 1U, close - i - 1U);
        if (AMPromptUI::detail::IsLegalBBCodeTagToken(token)) {
          (void)AppendTerminalBbcodeTokenAnsi_(token, &out);
          i = close;
          continue;
        }
      }
    }
    out.push_back(ch);
  }
  return out;
}

[[nodiscard]] size_t MeasureBannerLineWidth_(const std::string &line) {
  std::string plain = AMPromptUI::StripStyleForMeasure(line);
  plain = AMPromptUI::NormalizeMeasureLine(plain);
  return AMStr::DisplayWidthUtf8(plain);
}

[[nodiscard]] std::pair<size_t, size_t>
ComputeBannerPadding_(const std::string &line, int cols,
                      TerminalBannerAlign_ align) {
  const size_t width = MeasureBannerLineWidth_(line);
  const size_t target = static_cast<size_t>(std::max(1, cols));
  if (width >= target) {
    return {0U, 0U};
  }
  const size_t padding = target - width;
  if (align == TerminalBannerAlign_::Right) {
    return {padding, 0U};
  }
  if (align == TerminalBannerAlign_::Center) {
    return {padding / 2U, padding - padding / 2U};
  }
  return {0U, padding};
}

void AppendTerminalFixedLine_(std::string *out, int row, int cols,
                              const std::string &line,
                              const std::string &background_ansi,
                              const std::string &foreground_ansi,
                              TerminalBannerAlign_ align) {
  if (out == nullptr) {
    return;
  }
  *out += AMStr::fmt("\x1b[{};1H\x1b[2K\x1b[0m", row);
  const auto [left_pad, right_pad] = ComputeBannerPadding_(line, cols, align);
  if (!background_ansi.empty()) {
    *out += background_ansi;
  }
  if (!foreground_ansi.empty()) {
    *out += foreground_ansi;
  }
  if (left_pad > 0U) {
    *out += std::string(left_pad, ' ');
  }
  if (!line.empty()) {
    *out += RenderTerminalBbcodeAnsi_(line);
  }
  if (!background_ansi.empty()) {
    *out += background_ansi;
  }
  if (!foreground_ansi.empty()) {
    *out += foreground_ansi;
  }
  if (right_pad > 0U) {
    *out += std::string(right_pad, ' ');
  }
  if (!background_ansi.empty() || !foreground_ansi.empty()) {
    *out += "\x1b[0m";
  }
}

void AppendTerminalFixedHeader_(std::string *out,
                                const std::vector<std::string> &banner_lines,
                                const TerminalBannerConfig_ &banner_config,
                                const std::vector<std::string> &control_lines,
                                const TerminalBannerConfig_ &control_config,
                                bool show_control, int visible_header_rows,
                                int cols) {
  if (out == nullptr || visible_header_rows <= 0) {
    return;
  }
  const std::string banner_background_ansi =
      BuildBackgroundAnsi_(banner_config.background);
  const std::string banner_foreground_ansi =
      BuildForegroundAnsi_(banner_config.foreground);
  const std::string control_background_ansi =
      BuildBackgroundAnsi_(control_config.background);
  const std::string control_foreground_ansi =
      BuildForegroundAnsi_(control_config.foreground);
  int row = 1;
  for (const auto &line : banner_lines) {
    if (row > visible_header_rows) {
      return;
    }
    AppendTerminalFixedLine_(out, row, cols, line, banner_background_ansi,
                             banner_foreground_ansi, banner_config.align);
    ++row;
  }
  if (!show_control) {
    return;
  }
  for (const auto &line : control_lines) {
    if (row > visible_header_rows) {
      return;
    }
    AppendTerminalFixedLine_(out, row, cols, line, control_background_ansi,
                             control_foreground_ansi, control_config.align);
    ++row;
  }
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
    raw_input_mode &= ~ENABLE_WINDOW_INPUT;
    raw_input_mode &= ~ENABLE_MOUSE_INPUT;
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

    reader_thread_ = std::thread([this]() { ReaderLoop_(); });
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
#else
    SignalKey_();
#endif
    return OK;
  }

  void DeactivateCapture() {
    capture_enabled_.store(false, std::memory_order_release);
#ifdef _WIN32
    if (deactivate_event_ != nullptr) {
      (void)SetEvent(deactivate_event_);
    }
#else
    SignalKey_();
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

  void InjectInput(std::string_view input) {
    if (input.empty()) {
      return;
    }
    {
      auto guard = key_cache_.lock();
      guard->insert(guard->end(), input.begin(), input.end());
    }
    SignalKey_();
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

#ifndef _WIN32
  [[nodiscard]] bool WaitForPosixInputOrSignal_() {
    while (!stop_requested_.load(std::memory_order_acquire)) {
      pollfd waiters[2] = {};
      waiters[0].fd = key_pipe_[0];
      waiters[0].events = POLLIN;
      nfds_t waiter_count = 1;
      if (capture_enabled_.load(std::memory_order_acquire)) {
        waiters[1].fd = STDIN_FILENO;
        waiters[1].events = POLLIN;
        waiter_count = 2;
      }

      const int ready = poll(waiters, waiter_count, -1);
      if (ready < 0) {
        if (errno == EINTR) {
          continue;
        }
        std::lock_guard<std::mutex> lock(fatal_mutex_);
        fatal_error_ = std::strerror(errno);
        return false;
      }
      if ((waiters[0].revents & POLLIN) != 0) {
        DrainSignal();
      }
      if (waiter_count > 1 &&
          (waiters[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
        return true;
      }
      if ((waiters[0].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
        return false;
      }
    }
    return false;
  }
#endif

  void ReaderLoop_() {
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == INVALID_HANDLE_VALUE || input == nullptr) {
      std::lock_guard<std::mutex> lock(fatal_mutex_);
      fatal_error_ = "Console input handle is invalid";
      SignalKey_();
      return;
    }

    while (!stop_requested_.load(std::memory_order_acquire)) {
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
    while (!stop_requested_.load(std::memory_order_acquire)) {
      if (!WaitForPosixInputOrSignal_()) {
        if (!stop_requested_.load(std::memory_order_acquire)) {
          SignalKey_();
        }
        return;
      }
      if (!capture_enabled_.load(std::memory_order_acquire)) {
        continue;
      }

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
  std::thread reader_thread_ = {};
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

  auto target_result = ParseTermTargetSpec_(arg.target, default_nickname, true);
  if (!target_result.rcm) {
    prompt_io_manager_.ErrorFormat(target_result.rcm);
    return target_result.rcm;
  }
  TerminalTargetSpec_ target = target_result.data;
  if (target.use_last_entered) {
    std::lock_guard<std::mutex> lock(last_entered_term_mutex_);
    if (last_entered_term_key_.empty()) {
      const ECM rcm = Err(EC::InvalidArg, "", "ssh",
                          "No previous term in this program run");
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
    auto last_target =
        ParseTermTargetSpec_(last_entered_term_key_, default_nickname, false);
    if (!(last_target.rcm)) {
      prompt_io_manager_.ErrorFormat(last_target.rcm);
      return last_target.rcm;
    }
    target = std::move(last_target.data);
  }

  if (!shared_keyboard_monitor_) {
    shared_keyboard_monitor_ = std::make_shared<SharedKeyboardMonitor_>();
  }
  if (!shared_keyboard_monitor_) {
    const ECM rcm = Err(EC::InvalidHandle, "", target.term_key,
                        "Failed to initialize shared keyboard monitor");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  std::unique_lock<std::mutex> session_lock(
      shared_keyboard_monitor_->session_mutex);
  KeyboardInputMonitor_ *keyboard_monitor =
      &(shared_keyboard_monitor_->monitor);

  auto managed_terminal_result =
      terminal_service_.GetTerminalByNickname(target.term_key, true);

  AMDomain::terminal::TerminalHandle terminal_handle = nullptr;
  AMDomain::client::OS_TYPE terminal_os_type =
      AMDomain::client::OS_TYPE::Unknown;
  if (managed_terminal_result.rcm && managed_terminal_result.data) {
    terminal_handle = managed_terminal_result.data;
  } else if (managed_terminal_result.rcm && !managed_terminal_result.data) {
    const ECM rcm = Err(EC::InvalidHandle, "", target.term_key,
                        "Managed terminal handle is null");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  } else if (managed_terminal_result.rcm.code == EC::ClientNotFound) {
    auto temp_client_result =
        client_service_.CreateClient(target.client_name, control, false, false);
    if (!temp_client_result.rcm || !temp_client_result.data) {
      const ECM rcm = temp_client_result.rcm
                          ? Err(EC::InvalidHandle, "", target.client_name,
                                "Temporary client is null")
                          : temp_client_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
    terminal_os_type = temp_client_result.data->ConfigPort().GetOSType();
    temp_client_result.data->ConfigPort().SetNickname(target.term_key);

    auto temp_terminal_result =
        terminal_service_.CreateTerminal(temp_client_result.data, false);
    if (!temp_terminal_result.rcm || !temp_terminal_result.data) {
      const ECM rcm =
          (temp_terminal_result.rcm.code == EC::OperationUnsupported)
              ? BuildTerminalUnsupportedError_(target.client_name)
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
    const ECM rcm = Err(EC::InvalidHandle, "", target.term_key,
                        "Resolved terminal handle is null");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto terminal_request = terminal_handle->GetRequest();
  const auto protocol = terminal_request.protocol;
  if (protocol != AMDomain::host::ClientProtocol::SFTP &&
      protocol != AMDomain::host::ClientProtocol::LOCAL) {
    const ECM rcm =
        Err(EC::OperationUnsupported, "", target.client_name,
            "Windows realtime terminal launch currently supports SFTP and "
            "LOCAL channels only");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  {
    std::lock_guard<std::mutex> lock(last_entered_term_mutex_);
    last_entered_term_key_ = target.term_key;
  }

  const auto status_result = terminal_handle->CheckSession({}, control);
  if (!status_result.rcm) {
    prompt_io_manager_.ErrorFormat(status_result.rcm);
    return status_result.rcm;
  }

  const TerminalBannerConfig_ terminal_banner = ResolveTerminalBanner_(
      style_service_, target, terminal_request, terminal_os_type);
  const TerminalBannerConfig_ terminal_control_note =
      ResolveTerminalControlNote_(style_service_, target, terminal_request,
                                  terminal_os_type);
  const std::vector<std::string> terminal_banner_lines =
      SplitTerminalBannerLines_(terminal_banner.text);
  const std::vector<std::string> terminal_control_note_lines =
      SplitTerminalBannerLines_(terminal_control_note.text);
  const AMTerminalTools::TerminalViewportInfo geometry =
      AMTerminalTools::GetTerminalViewportInfo();
  const int initial_header_rows = FixedHeaderLineCount_(
      terminal_banner_lines, terminal_control_note_lines,
      arg.start_in_god_mode, geometry.rows);
  const AMTerminalTools::TerminalViewportInfo initial_content_geometry =
      BuildContentGeometry_(geometry, initial_header_rows);
  std::string channel_name = AMStr::Strip(status_result.data.current_channel);
  if (channel_name.empty()) {
    channel_name = AMDomain::terminal::kDefaultTerminalChannelName;
  }

  auto current_channel_result = terminal_handle->GetChannelPort(
      std::optional<std::string>(channel_name), control);
  if (!(current_channel_result.rcm) ||
      (current_channel_result.data &&
       current_channel_result.data->GetState().closed)) {
    auto open_result = terminal_handle->OpenChannel(
        BuildChannelOpenArgs_(channel_name, initial_content_geometry), control);
    if (!(open_result.rcm) && open_result.rcm.code != EC::TargetAlreadyExists) {
      prompt_io_manager_.ErrorFormat(open_result.rcm);
      return open_result.rcm;
    }
    current_channel_result = terminal_handle->GetChannelPort(
        std::optional<std::string>(channel_name), control);
  }
  if (!(current_channel_result.rcm) || !current_channel_result.data ||
      current_channel_result.data->GetState().closed) {
    const ECM rcm = current_channel_result.rcm
                        ? Err(EC::NoConnection, "", channel_name,
                              "Term channel is not available")
                        : current_channel_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto active_result = terminal_handle->ActiveChannel({channel_name}, control);
  if (!(active_result.rcm) || !active_result.data.activated) {
    const ECM rcm = active_result.rcm
                        ? Err(EC::CommonFailure, "", channel_name,
                              "Failed to activate term channel")
                        : active_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  bool refresh_prompt_on_enter = true;

  auto channel_port_result = terminal_service_.EnsureChannelPort(
      target.term_key, channel_name, control);
  if (!(channel_port_result.rcm) || !channel_port_result.data) {
    const ECM rcm = channel_port_result.rcm
                        ? Err(EC::InvalidHandle, "", channel_name,
                              "Channel port handle is null")
                        : channel_port_result.rcm;
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  const auto channel_port = channel_port_result.data;
  const auto *vt_frame_port = channel_port->GetVtFramePort();

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
  bool last_local_input_active = false;
  AMTerminalTools::TerminalViewportInfo last_render_geometry = geometry;
  std::vector<std::string> last_rendered_lines = {};
  bool have_last_vt_snapshot = false;
  AMDomain::terminal::ChannelVtSnapshot last_vt_snapshot = {};
  bool last_control_layer_active = false;
  std::atomic<uint64_t> local_viewport_offset = 0;
  std::atomic<bool> local_browse_active = false;
  std::atomic<bool> control_layer_active{arg.start_in_god_mode};
  std::string pending_local_input = {};
  std::mutex requested_switch_mutex = {};
  std::string requested_switch_key = {};
  AMTerminalTools::TerminalViewportInfo last_geometry = {};
  int last_fixed_header_rows = -1;
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
      WriteTerminalBytes_(BuildTerminalInputProtocolAnsi_({}, false));
      WriteTerminalBytes_(kTerminalExitAlternateScreen_);
      physical_alt_screen_active = false;
      have_last_server_screen_state = false;
      last_server_in_alternate_screen = false;
      last_local_input_active = false;
      last_render_geometry = geometry;
      last_rendered_lines.clear();
      have_last_vt_snapshot = false;
      last_vt_snapshot = {};
      last_control_layer_active = false;
    }
    local_viewport_offset.store(0, std::memory_order_release);
    local_browse_active.store(false, std::memory_order_release);
    control_layer_active.store(false, std::memory_order_release);
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
    bool const browse_active =
        local_browse_active.load(std::memory_order_acquire);
    const uint64_t viewport_offset =
        local_viewport_offset.load(std::memory_order_acquire);
    const bool control_active =
        control_layer_active.load(std::memory_order_acquire);
    if (browse_active || viewport_offset != 0U || control_active) {
      vt_snapshot.cursor_visible = false;
    }
    std::lock_guard<std::mutex> guard(render_mutex);
    if (!physical_alt_screen_active) {
      return;
    }
    auto const current_geometry = AMTerminalTools::GetTerminalViewportInfo();
    const int row_offset = FixedHeaderLineCount_(
        terminal_banner_lines, terminal_control_note_lines, control_active,
        current_geometry.rows);
    const std::vector<std::string> current_lines = SplitAnsiFrameLines_(frame);
    const bool local_input_active = browse_active || control_active;
    const std::string input_protocol_ansi =
        BuildTerminalInputProtocolAnsi_(vt_snapshot, local_input_active);
    const bool force_full_clear =
        !have_last_server_screen_state ||
        current_geometry.cols != last_render_geometry.cols ||
        current_geometry.rows != last_render_geometry.rows ||
        last_server_in_alternate_screen != vt_snapshot.in_alternate_screen ||
        last_control_layer_active != control_active;
    const bool lines_changed =
        force_full_clear || current_lines != last_rendered_lines;
    const bool input_protocol_changed =
        !have_last_vt_snapshot ||
        InputProtocolStateChanged_(vt_snapshot, last_vt_snapshot) ||
        local_input_active != last_local_input_active;

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
          std::clamp(vt_snapshot.cursor_row + 1 + row_offset, 1,
                     std::max(1, current_geometry.rows));
      const int cursor_col =
          std::clamp(vt_snapshot.cursor_col + 1, 1,
                     std::max(1, current_geometry.cols));
      cursor_only += AMStr::fmt("\x1b[{};{}H", cursor_row, cursor_col);
      cursor_only += vt_snapshot.cursor_visible ? "\x1b[?25h" : "\x1b[?25l";
      WriteTerminalBytes_(cursor_only);
      last_local_input_active = local_input_active;
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
        const int target_row = static_cast<int>(i + 1U + row_offset);
        if (target_row > current_geometry.rows) {
          break;
        }
        repaint += AMStr::fmt("\x1b[{};1H", target_row);
        repaint += "\x1b[2K\x1b[0m";
        repaint += current_lines[i];
      }
    } else {
      const size_t overlap = std::min(last_rendered_lines.size(), current_lines.size());
      for (size_t i = 0; i < overlap; ++i) {
        if (last_rendered_lines[i] == current_lines[i]) {
          continue;
        }
        const int target_row = static_cast<int>(i + 1U + row_offset);
        if (target_row > current_geometry.rows) {
          continue;
        }
        repaint += AMStr::fmt("\x1b[{};1H", target_row);
        repaint += "\x1b[2K\x1b[0m";
        repaint += current_lines[i];
      }
      for (size_t i = overlap; i < current_lines.size(); ++i) {
        const int target_row = static_cast<int>(i + 1U + row_offset);
        if (target_row > current_geometry.rows) {
          break;
        }
        repaint += AMStr::fmt("\x1b[{};1H", target_row);
        repaint += "\x1b[2K\x1b[0m";
        repaint += current_lines[i];
      }
      for (size_t i = current_lines.size(); i < last_rendered_lines.size(); ++i) {
        const int target_row = static_cast<int>(i + 1U + row_offset);
        if (target_row > current_geometry.rows) {
          break;
        }
        repaint += AMStr::fmt("\x1b[{};1H\x1b[2K", target_row);
      }
    }
    std::string restore_cursor_after_banner = {};
    if (vt_snapshot.available) {
      const int cursor_row =
          std::clamp(vt_snapshot.cursor_row + 1 + row_offset, 1,
                     std::max(1, current_geometry.rows));
      const int cursor_col =
          std::clamp(vt_snapshot.cursor_col + 1, 1,
                     std::max(1, current_geometry.cols));
      restore_cursor_after_banner =
          AMStr::fmt("\x1b[{};{}H", cursor_row, cursor_col);
      restore_cursor_after_banner +=
          vt_snapshot.cursor_visible ? "\x1b[?25h" : "\x1b[?25l";
      have_last_server_screen_state = true;
      last_server_in_alternate_screen = vt_snapshot.in_alternate_screen;
    } else {
      restore_cursor_after_banner = "\x1b[?25h";
      have_last_server_screen_state = false;
      last_server_in_alternate_screen = false;
    }
    if (row_offset > 0) {
      AppendTerminalFixedHeader_(
          &repaint, terminal_banner_lines, terminal_banner,
          terminal_control_note_lines, terminal_control_note, control_active,
          row_offset, current_geometry.cols);
    }
    repaint += restore_cursor_after_banner;
    WriteTerminalBytes_(repaint);
    last_rendered_lines = current_lines;
    last_local_input_active = local_input_active;
    last_render_geometry = current_geometry;
    have_last_vt_snapshot = vt_snapshot.available;
    last_vt_snapshot = vt_snapshot;
    last_control_layer_active = control_active;
  };
  std::function<void()> render_current_frame = [&]() {
    AMDomain::terminal::ChannelRenderFrameResult frame_result = {};
    if (vt_frame_port != nullptr) {
      AMDomain::terminal::ChannelRenderFrameArgs render_args = {};
      render_args.viewport_offset =
          local_viewport_offset.load(std::memory_order_acquire);
      auto result = vt_frame_port->RenderFrame(render_args);
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
  AMDomain::terminal::ChannelForegroundBindArgs bind_args = {};
  auto load_vt_snapshot = [&]() -> AMDomain::terminal::ChannelVtSnapshot {
    if (vt_frame_port == nullptr) {
      return {};
    }
    return vt_frame_port->Snapshot();
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
    const bool control_active =
        control_layer_active.load(std::memory_order_acquire);
    const int fixed_header_rows = FixedHeaderLineCount_(
        terminal_banner_lines, terminal_control_note_lines, control_active,
        current_geometry.rows);
    if (current_geometry.cols == last_geometry.cols &&
        current_geometry.rows == last_geometry.rows &&
        current_geometry.width == last_geometry.width &&
        current_geometry.height == last_geometry.height &&
        fixed_header_rows == last_fixed_header_rows) {
      return;
    }

    const auto content_geometry =
        BuildContentGeometry_(current_geometry, fixed_header_rows);
    AMDomain::terminal::ChannelResizeArgs resize_args = {};
    resize_args.cols = std::max(1, content_geometry.cols);
    resize_args.rows = std::max(1, content_geometry.rows);
    resize_args.width = std::max(0, content_geometry.width);
    resize_args.height = std::max(0, content_geometry.height);
    auto resize_result = channel_port->Resize(resize_args, control);
    if (!(resize_result.rcm)) {
      return;
    }

    last_geometry = current_geometry;
    last_fixed_header_rows = fixed_header_rows;
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
    auto page_step = [&]() -> uint64_t {
      const auto vt_snapshot = load_vt_snapshot();
      return static_cast<uint64_t>(std::max(1, vt_snapshot.rows));
    };
    auto scroll_history_up = [&](uint64_t step) {
      uint64_t const current =
          local_viewport_offset.load(std::memory_order_acquire);
      uint64_t const desired =
          (current > std::numeric_limits<uint64_t>::max() - step)
              ? std::numeric_limits<uint64_t>::max()
              : current + step;
      local_browse_active.store(true, std::memory_order_release);
      (void)apply_local_viewport_offset(desired);
    };
    auto scroll_history_down = [&](uint64_t step) {
      uint64_t const current =
          local_viewport_offset.load(std::memory_order_acquire);
      local_browse_active.store(true, std::memory_order_release);
      (void)apply_local_viewport_offset(current > step ? current - step : 0U);
    };
    auto request_term_switch = [&](int direction) {
      auto next_key = AdjacentTermKey_(terminal_service_, target.term_key,
                                      direction);
      if (!next_key.has_value() || next_key->empty() ||
          *next_key == target.term_key) {
        return;
      }
      {
        std::lock_guard<std::mutex> switch_guard(requested_switch_mutex);
        requested_switch_key = *next_key;
      }
      (void)channel_port->RequestForegroundDetach();
    };

    while (!pending_local_input.empty()) {
      if (control_layer_active.load(std::memory_order_acquire)) {
        size_t seq_len = 0U;
        if (pending_local_input.front() == '\x1d') {
          passthrough.push_back('\x1d');
          pending_local_input.erase(0, 1U);
          control_layer_active.store(false, std::memory_order_release);
          (void)exit_local_scrollback();
          render_current_frame();
          continue;
        }
        if (pending_local_input.front() == '\t') {
          pending_local_input.erase(0, 1U);
          request_term_switch(1);
          continue;
        }
        if (pending_local_input.front() == 'q' ||
            pending_local_input.front() == 'Q') {
          pending_local_input.erase(0, 1U);
          control_layer_active.store(false, std::memory_order_release);
          (void)channel_port->RequestForegroundDetach();
          continue;
        }
        if (pending_local_input.front() == 'e' ||
            pending_local_input.front() == 'E') {
          pending_local_input.erase(0, 1U);
          control_layer_active.store(false, std::memory_order_release);
          (void)exit_local_scrollback();
          render_current_frame();
          continue;
        }
        if (StartsWithAny_(pending_local_input,
                           {"\x1b[A", "\x1bOA"}, &seq_len)) {
          pending_local_input.erase(0, seq_len);
          scroll_history_up(1U);
          continue;
        }
        if (StartsWithAny_(pending_local_input,
                           {"\x1b[B", "\x1bOB"}, &seq_len)) {
          pending_local_input.erase(0, seq_len);
          scroll_history_down(1U);
          continue;
        }
        if (StartsWithAny_(pending_local_input,
                           {"\x1b[D", "\x1bOD", "\x1b[1;2D"}, &seq_len)) {
          pending_local_input.erase(0, seq_len);
          request_term_switch(-1);
          continue;
        }
        if (StartsWithAny_(pending_local_input,
                           {"\x1b[C", "\x1bOC", "\x1b[1;2C"}, &seq_len)) {
          pending_local_input.erase(0, seq_len);
          request_term_switch(1);
          continue;
        }
        if (StartsWithAny_(pending_local_input, {"\x1b[Z"}, &seq_len)) {
          pending_local_input.erase(0, seq_len);
          request_term_switch(-1);
          continue;
        }
        if (pending_local_input.front() == '\x1b') {
          if (pending_local_input.size() == 1U) {
            pending_local_input.erase(0, 1U);
            control_layer_active.store(false, std::memory_order_release);
            (void)exit_local_scrollback();
            render_current_frame();
            continue;
          }
          const size_t esc_len = CompleteEscapeSequenceLength_(pending_local_input);
          if (esc_len == 0U) {
            break;
          }
          if (esc_len == 1U) {
            pending_local_input.erase(0, 1U);
            control_layer_active.store(false, std::memory_order_release);
            (void)exit_local_scrollback();
            render_current_frame();
            continue;
          }
          const std::string seq = pending_local_input.substr(0, esc_len);
          if (seq == "\x1b[5~") {
            pending_local_input.erase(0, esc_len);
            scroll_history_up(page_step());
            continue;
          }
          if (seq == "\x1b[6~") {
            pending_local_input.erase(0, esc_len);
            scroll_history_down(page_step());
            continue;
          }
          if (seq == "\x1b[H" || seq == "\x1b[1~" || seq == "\x1b[7~" ||
              seq.ends_with("H")) {
            pending_local_input.erase(0, esc_len);
            local_browse_active.store(true, std::memory_order_release);
            (void)apply_local_viewport_offset(
                std::numeric_limits<uint64_t>::max());
            continue;
          }
          if (seq == "\x1b[F" || seq == "\x1b[4~" || seq == "\x1b[8~" ||
              seq.ends_with("F")) {
            pending_local_input.erase(0, esc_len);
            (void)exit_local_scrollback();
            continue;
          }
          if (seq.ends_with("A")) {
            pending_local_input.erase(0, esc_len);
            scroll_history_up(1U);
            continue;
          }
          if (seq.ends_with("B")) {
            pending_local_input.erase(0, esc_len);
            scroll_history_down(1U);
            continue;
          }
          pending_local_input.erase(0, esc_len);
          continue;
        }
        pending_local_input.erase(0, 1U);
        continue;
      }

      unsigned char const first =
          static_cast<unsigned char>(pending_local_input.front());
      if (first == 0x1dU) {
        if (local_browse_active.load(std::memory_order_acquire)) {
          (void)exit_local_scrollback();
        }
        pending_local_input.erase(0, 1U);
        control_layer_active.store(true, std::memory_order_release);
        render_current_frame();
        continue;
      }
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
        passthrough_escape_sequence(passthrough, seq.size());
        continue;
      }

      if (pending_local_input[1] == 'O') {
        if (pending_local_input.size() < 3U) {
          break;
        }
        std::string const seq = pending_local_input.substr(0, 3U);
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
    const ECM remove_rcm = terminal_service_.RemoveTerminal(target.term_key, control);
    if (!(remove_rcm) && (wait_rcm)) {
      wait_rcm = remove_rcm;
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

  std::string switch_key = {};
  {
    std::lock_guard<std::mutex> switch_guard(requested_switch_mutex);
    switch_key = requested_switch_key;
  }
  if (!switch_key.empty() && (wait_rcm)) {
    session_lock.unlock();
    TerminalLaunchArg switch_arg = {};
    switch_arg.target = switch_key;
    switch_arg.start_in_god_mode = true;
    return LaunchTerminal(switch_arg, control_opt);
  }

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
  std::string default_client = filesystem_service_.CurrentNickname();
  if (default_client.empty()) {
    default_client = AMDomain::host::klocalname;
  }
  ECM normalize_status = OK;
  const auto targets =
      NormalizeTermTargets_(arg.nicknames, default_client, &normalize_status);
  if (targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "<targets>",
                        "term add requires at least one target: host@name");
    prompt_io_manager_.ErrorFormat(rcm);
    return normalize_status ? rcm : normalize_status;
  }

  ECM status = normalize_status;
  for (const auto &target : targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", target.term_key, "Interrupted by user");
    }

    auto existing =
        terminal_service_.GetTerminalByNickname(target.term_key, true);
    if (existing.rcm && existing.data) {
      if (!arg.force) {
        const ECM rcm = Err(EC::TargetAlreadyExists, "", target.term_key,
                            "Terminal already exists");
        prompt_io_manager_.ErrorFormat(rcm);
        if ((status)) {
          status = rcm;
        }
        continue;
      }
      const ECM rm_rcm =
          terminal_service_.RemoveTerminal(target.term_key, control);
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

    auto client_result =
        client_service_.CreateClient(target.client_name, control, false);
    if (!(client_result.rcm) || !client_result.data) {
      const ECM rcm =
          (client_result.rcm) ? Err(EC::InvalidHandle, "", target.client_name,
                                    "Created client is null")
                              : client_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }
    client_result.data->ConfigPort().SetNickname(target.term_key);

    auto terminal_result =
        terminal_service_.CreateTerminal(client_result.data, false);
    if (!(terminal_result.rcm) || !terminal_result.data) {
      const ECM rcm = (terminal_result.rcm.code == EC::OperationUnsupported)
                          ? BuildTerminalUnsupportedError_(target.client_name)
                          : terminal_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }

    prompt_io_manager_.FmtPrint("✅ Term added: {}", target.term_key);
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

  std::string default_client = filesystem_service_.CurrentNickname();
  if (default_client.empty()) {
    default_client = AMDomain::host::klocalname;
  }
  ECM status = OK;
  const auto parsed_targets =
      NormalizeTermTargets_(arg.nicknames, default_client, &status);
  std::vector<std::string> valid_targets = {};
  valid_targets.reserve(parsed_targets.size());
  std::unordered_map<std::string, AMDomain::terminal::TerminalHandle> targets =
      {};
  for (const auto &target : parsed_targets) {
    auto terminal_result =
        terminal_service_.GetTerminalByNickname(target.term_key, true);
    if (!(terminal_result.rcm) || !terminal_result.data) {
      const ECM rcm =
          terminal_result.rcm
              ? Err(EC::ClientNotFound, "", target.term_key,
                    "terminal not found")
              : terminal_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      if ((status)) {
        status = rcm;
      }
      continue;
    }
    valid_targets.push_back(target.term_key);
    targets[target.term_key] = terminal_result.data;
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
      "Are you sure to remove these terms? (y/n): ", &canceled);
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
    prompt_io_manager_.FmtPrint("✅ Term removed: {}", nickname);
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

} // namespace AMInterface::terminal
