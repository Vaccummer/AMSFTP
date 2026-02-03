#include "AMCLI/InteractiveLoop.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/Path.hpp"
#include "AMCLI/CommandPreprocess.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <magic_enum/magic_enum.hpp>
#include <sstream>

namespace {
/**
 * @brief Track prompt rendering state across iterations.
 */
struct PromptState {
  ECM last_rcm = {EC::Success, ""};
  std::string last_elapsed = "-";
  std::string cached_prefix;
  std::string last_nickname;
};

/**
 * @brief Parse a hex color token (#RGB or #RRGGBB) into RGB components.
 *
 * @param hex Color token with or without a leading '#'.
 * @param r Output red component.
 * @param g Output green component.
 * @param b Output blue component.
 * @return True if parsing succeeds; false otherwise.
 */
bool ParseHexColor_(const std::string &hex, int *r, int *g, int *b) {
  if (!r || !g || !b) {
    return false;
  }

  std::string value = hex;
  if (!value.empty() && value.front() == '#') {
    value.erase(value.begin());
  }
  if (!(value.size() == 3 || value.size() == 6)) {
    return false;
  }

  auto hex_to_int = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
      return 10 + (c - 'A');
    }
    return -1;
  };

  if (value.size() == 3) {
    const int r_n = hex_to_int(value[0]);
    const int g_n = hex_to_int(value[1]);
    const int b_n = hex_to_int(value[2]);
    if (r_n < 0 || g_n < 0 || b_n < 0) {
      return false;
    }
    *r = r_n * 17;
    *g = g_n * 17;
    *b = b_n * 17;
    return true;
  }

  for (char c : value) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }

  *r = std::stoi(value.substr(0, 2), nullptr, 16);
  *g = std::stoi(value.substr(2, 2), nullptr, 16);
  *b = std::stoi(value.substr(4, 2), nullptr, 16);
  return true;
}

/**
 * @brief Convert a tagged string like "[#RRGGBB b]text[/]" into ANSI color.
 *
 * @param tagged Tagged string with bbcode-style colors.
 * @param converted Output string with ANSI escape sequences.
 * @return True if conversion succeeded; false if format is invalid.
 */
bool TryConvertTaggedTextToAnsi_(const std::string &tagged,
                                 std::string *converted) {
  if (!converted) {
    return false;
  }
  converted->clear();

  if (tagged.size() < 6 || tagged.front() != '[') {
    return false;
  }

  const size_t close = tagged.find(']');
  if (close == std::string::npos) {
    return false;
  }
  const size_t suffix_pos = tagged.rfind("[/]");
  if (suffix_pos == std::string::npos || suffix_pos <= close) {
    return false;
  }

  const std::string tag = tagged.substr(1, close - 1);
  const std::string content =
      tagged.substr(close + 1, suffix_pos - (close + 1));

  bool bold = false;
  bool italic = false;
  bool underline = false;
  bool reverse = false;
  bool expect_bg = false;
  bool has_style = false;
  int fg_r = -1;
  int fg_g = -1;
  int fg_b = -1;
  int bg_r = -1;
  int bg_g = -1;
  int bg_b = -1;

  std::istringstream iss(tag);
  std::string token;
  while (iss >> token) {
    if (token == "on") {
      expect_bg = true;
      continue;
    }
    if (token == "b") {
      bold = true;
      has_style = true;
      continue;
    }
    if (token == "i") {
      italic = true;
      has_style = true;
      continue;
    }
    if (token == "u") {
      underline = true;
      has_style = true;
      continue;
    }
    if (token == "r") {
      reverse = true;
      has_style = true;
      continue;
    }

    bool is_bg = expect_bg;
    expect_bg = false;
    if (token.rfind("color=", 0) == 0) {
      token = token.substr(6);
      is_bg = false;
    } else if (token.rfind("bgcolor=", 0) == 0) {
      token = token.substr(8);
      is_bg = true;
    } else if (token.rfind("bg=", 0) == 0) {
      token = token.substr(3);
      is_bg = true;
    }

    int r = 0;
    int g = 0;
    int b = 0;
    if (token.rfind('#', 0) == 0 && ParseHexColor_(token, &r, &g, &b)) {
      if (is_bg) {
        bg_r = r;
        bg_g = g;
        bg_b = b;
      } else {
        fg_r = r;
        fg_g = g;
        fg_b = b;
      }
      has_style = true;
      continue;
    }
  }

  if (!has_style) {
    return false;
  }

  std::ostringstream oss;
  oss << "\x1b[";
  bool first = true;
  auto append_code = [&oss, &first](const std::string &code) {
    if (code.empty()) {
      return;
    }
    if (!first) {
      oss << ";";
    }
    oss << code;
    first = false;
  };

  if (bold) {
    append_code("1");
  }
  if (italic) {
    append_code("3");
  }
  if (underline) {
    append_code("4");
  }
  if (reverse) {
    append_code("7");
  }
  if (fg_r >= 0) {
    append_code(AMStr::amfmt("38;2;{};{};{}", fg_r, fg_g, fg_b));
  }
  if (bg_r >= 0) {
    append_code(AMStr::amfmt("48;2;{};{};{}", bg_r, bg_g, bg_b));
  }

  oss << "m" << content << "\x1b[0m";
  *converted = oss.str();
  return true;
}

/**
 * @brief Extract inner text from a tagged string like "[...]text[/]".
 *
 * @param tagged Tagged string to extract from.
 * @param extracted Output string with the inner content only.
 * @return True if extraction succeeded; false otherwise.
 */
bool TryExtractTaggedText_(const std::string &tagged,
                           std::string *extracted) {
  if (!extracted) {
    return false;
  }
  extracted->clear();

  const size_t close = tagged.find(']');
  if (close == std::string::npos) {
    return false;
  }
  const size_t suffix_pos = tagged.rfind("[/]");
  if (suffix_pos == std::string::npos || suffix_pos <= close) {
    return false;
  }

  *extracted = tagged.substr(close + 1, suffix_pos - (close + 1));
  return true;
}

/**
 * @brief Apply a bbcode style tag from settings to text and convert to ANSI.
 *
 * @param config_manager Config manager used to resolve style values.
 * @param path Settings path under the style tree.
 * @param text Raw text to style.
 * @return Styled text with ANSI escape sequences when possible.
 */
std::string ApplyStyleFromConfig_(AMConfigManager &config_manager,
                                  const AMConfigManager::Path &path,
                                  const std::string &text) {
  if (text.empty()) {
    return text;
  }

  std::string raw =
      AMStr::TrimWhitespaceCopy(config_manager.GetSettingString(path, ""));
  if (raw.empty()) {
    return text;
  }
  if (raw.front() != '[' || raw.back() != ']') {
    return text;
  }
  if (raw.find("[/") != std::string::npos) {
    return text;
  }

  const std::string tagged = raw + text + "[/]";
  std::string converted;
  if (TryConvertTaggedTextToAnsi_(tagged, &converted)) {
    return converted;
  }

  std::string extracted;
  if (TryExtractTaggedText_(tagged, &extracted)) {
    return extracted;
  }
  return text;
}

/**
 * @brief Return the active client or the local client fallback.
 */
std::shared_ptr<BaseClient>
ResolveActiveClient_(AMClientManager &client_manager) {
  if (client_manager.CLIENT) {
    return client_manager.CLIENT;
  }
  return client_manager.LOCAL;
}

/**
 * @brief Resolve prompt username/hostname with environment fallbacks.
 */
std::pair<std::string, std::string>
ResolveUserHost_(const std::shared_ptr<BaseClient> &client) {
  std::string username;
  std::string hostname;
  if (client) {
    ConRequst request = client->GetRequest();
    username = request.username;
    hostname = request.hostname;
  }

  auto read_env = [](const char *key) { return GetEnvCopy(key); };

  if (username.empty()) {
#ifdef _WIN32
    username = read_env("USERNAME");
#else
    username = read_env("USER");
#endif
  }
  if (hostname.empty()) {
#ifdef _WIN32
    hostname = read_env("COMPUTERNAME");
#else
    hostname = read_env("HOSTNAME");
#endif
  }
  if (username.empty()) {
    username = "user";
  }
  if (hostname.empty()) {
    hostname = "localhost";
  }
  return {username, hostname};
}

/**
 * @brief Select the system icon from settings based on OS type.
 */
std::string ResolveSysIcon_(AMConfigManager &config_manager, OS_TYPE os_type) {
  std::string key = "windows";
  switch (os_type) {
  case OS_TYPE::Windows:
    key = "windows";
    break;
  case OS_TYPE::Linux:
    key = "linux";
    break;
  case OS_TYPE::MacOS:
    key = "macos";
    break;
  default:
    key = "windows";
    break;
  }

  std::string icon =
      config_manager.GetSettingString({"style", "Icons", key}, "");
  if (icon.empty()) {
    icon = "💻";
  }
  std::string converted;
  if (TryConvertTaggedTextToAnsi_(icon, &converted)) {
    return converted;
  }
  std::string extracted;
  if (TryExtractTaggedText_(icon, &extracted)) {
    return extracted;
  }
  return icon;
}

/**
 * @brief Build the prompt string and update cached prefix when needed.
 */
std::string BuildPrompt_(PromptState &state, AMClientManager &client_manager,
                         AMConfigManager &config_manager) {
  auto client = ResolveActiveClient_(client_manager);
  std::string nickname = client ? client->GetNickname() : std::string("local");
  if (nickname.empty()) {
    nickname = "local";
  }

  if (state.cached_prefix.empty() || state.last_nickname != nickname) {
    OS_TYPE os_type = OS_TYPE::Unknown;
    if (client) {
      try {
        os_type = client->GetOSType();
      } catch (const std::exception &) {
        os_type = OS_TYPE::Unknown;
      }
    }
    std::string sysicon = ResolveSysIcon_(config_manager, os_type);
    auto [username, hostname] = ResolveUserHost_(client);
    std::string styled_user = ApplyStyleFromConfig_(
        config_manager, {"style", "Prompt", "username"}, username);
    std::string styled_host = ApplyStyleFromConfig_(
        config_manager, {"style", "Prompt", "hostname"}, hostname);
    state.cached_prefix =
        AMStr::amfmt("{} {}@{}", sysicon, styled_user, styled_host);
    state.last_nickname = nickname;
  }

  const std::string elapsed =
      state.last_elapsed.empty() ? "-" : state.last_elapsed;
  const bool ok = state.last_rcm.first == EC::Success;
  const std::string status = ok ? "✅" : "❌";
  const std::string ec_name =
      ok ? "" : std::string(magic_enum::enum_name(state.last_rcm.first));

  const std::string styled_elapsed = ApplyStyleFromConfig_(
      config_manager, {"style", "SystemInfo", "info"}, elapsed);
  const std::string styled_status = ApplyStyleFromConfig_(
      config_manager,
      {"style", "SystemInfo", ok ? "success" : "error"},
      status);
  std::string line1 = AMStr::amfmt("{}  {}  {}", state.cached_prefix,
                                   styled_elapsed, styled_status);
  if (!ec_name.empty()) {
    const std::string styled_ec = ApplyStyleFromConfig_(
        config_manager, {"style", "SystemInfo", "error"}, ec_name);
    line1 += " " + styled_ec;
  }

  std::string workdir = "/";
  if (client) {
    workdir = client_manager.GetOrInitWorkdir(client);
  }
  const std::string styled_nickname = ApplyStyleFromConfig_(
      config_manager, {"style", "Prompt", "nickname"}, nickname);
  const std::string styled_cwd = ApplyStyleFromConfig_(
      config_manager, {"style", "Prompt", "cwd"}, workdir);
  const std::string styled_dollar = ApplyStyleFromConfig_(
      config_manager, {"style", "Prompt", "dollarsign"}, "$");
  std::string line2 =
      AMStr::amfmt("({}){} {}", styled_nickname, styled_cwd, styled_dollar);
  return line1 + "\n" + line2 + " ";
}

/**
 * @brief Split a potentially multi-line prompt into a header and a single input
 * line.
 *
 * @param full_prompt Full prompt text that may contain newline separators.
 * @param header Output header string to print before readline (empty if none).
 * @param line Output single-line prompt to pass into ic_readline.
 */
static void SplitPromptForReadline_(const std::string &full_prompt,
                                    std::string *header, std::string *line) {
  if (header) {
    header->clear();
  }
  if (!line) {
    return;
  }
  line->clear();
  if (full_prompt.empty()) {
    return;
  }
  const size_t split = full_prompt.find_last_of('\n');
  if (split == std::string::npos) {
    *line = full_prompt;
    return;
  }
  if (header) {
    *header = full_prompt.substr(0, split);
  }
  *line = full_prompt.substr(split + 1);
}

/**
 * @brief Print an ECM error message if the code is not Success.
 */
void PrintECM_(AMPromptManager &prompt, const ECM &rcm) {
  if (rcm.first == EC::Success) {
    return;
  }
  std::string name = std::string(magic_enum::enum_name(rcm.first));
  if (rcm.second.empty()) {
    prompt.Print(AMStr::amfmt("❌ {}", name));
    return;
  }
  prompt.Print(AMStr::amfmt("❌ {}: {}", name, rcm.second));
}

/**
 * @brief Execute a shell command via ConductCmd and return the raw result.
 */
CR ExecuteShellCommand_(AMClientManager &client_manager,
                        AMConfigManager &config_manager,
                        const std::string &command) {
  auto client = ResolveActiveClient_(client_manager);
  if (!client) {
    return {ECM{EC::ClientNotFound, "No active client"}, {"", -1}};
  }
  if (client->GetProtocol() != ClientProtocol::SFTP) {
    return {ECM{EC::OperationUnsupported,
                "Shell command only supported by SFTP client"},
            {"", -1}};
  }

  const int timeout_ms = config_manager.ResolveTimeoutMs(5000);
  return client->ConductCmd(command, timeout_ms, amgif);
}

/**
 * @brief Update prompt state with the latest result and elapsed duration.
 */
void UpdatePromptState_(PromptState &state, const ECM &rcm,
                        std::chrono::steady_clock::duration elapsed) {
  state.last_rcm = rcm;
  const auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
  state.last_elapsed = AMStr::amfmt("{}ms", ms);
}
} // namespace

/**
 * @brief Run the core interactive loop until the user exits.
 */
int RunInteractiveLoop(const std::string &app_name,
                       const CliManagers &managers) {
  AMIsInteractive.store(true);

  AMPromptManager &prompt = AMPromptManager::Instance();
  AMConfigManager &config_manager = *managers.config_manager;
  AMClientManager &client_manager = *managers.client_manager;
  AMFileSystem &filesystem = *managers.filesystem;

  AMCommandPreprocessor preprocessor(config_manager);
  PromptState prompt_state;

  (void)filesystem;

  while (true) {
    if (amgif && amgif->iskill()) {
      break;
    }

    auto history_client = ResolveActiveClient_(client_manager);
    std::string history_nickname =
        history_client ? history_client->GetNickname() : std::string("local");
    if (history_nickname.empty()) {
      history_nickname = "local";
    }
    prompt.LoadHistory(config_manager, history_nickname);

    const std::string prompt_text =
        BuildPrompt_(prompt_state, client_manager, config_manager);

    std::string prompt_header;
    std::string prompt_line;
    SplitPromptForReadline_(prompt_text, &prompt_header, &prompt_line);
    if (!prompt_header.empty()) {
      std::cout << prompt_header << std::endl;
    }

    std::string line;
    AMCliSignalMonitor &monitor = AMCliSignalMonitor::Instance();
    (void)config_manager.ConfigBackupIfNeeded();
    monitor.SilenceHook("GLOBAL");
    monitor.ResumeHook("COREPROMPT");
    if (amgif) {
      amgif->reset();
    }

    bool canceled = prompt.PromptCore(prompt_line, &line);

    monitor.SilenceHook("COREPROMPT");
    monitor.ResumeHook("GLOBAL");

    if (amgif && amgif->iskill()) {
      break;
    }
    if (amgif && amgif->check()) {
      prompt.Print("Interrupted. Type 'exit' to quit.");
      continue;
    }
    if (canceled) {
      continue;
    }

    const auto input_confirmed = std::chrono::steady_clock::now();

    std::string trimmed = AMStr::TrimWhitespaceCopy(line);
    if (trimmed.empty()) {
      continue;
    }
    prompt.AddHistoryEntry(trimmed);

    if (AMStr::lowercase(trimmed) == "exit") {
      break;
    }

    AMCommandPreprocessor::Result pre_result = preprocessor.Preprocess(trimmed);

    if (pre_result.rcm.first != EC::Success) {
      PrintECM_(prompt, pre_result.rcm);
      SetCliExitCode(static_cast<int>(pre_result.rcm.first));
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, pre_result.rcm,
                         iter_end - input_confirmed);
      continue;
    }

    if (pre_result.action == AMCommandPreprocessor::Action::Handled) {
      SetCliExitCode(static_cast<int>(pre_result.rcm.first));
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, pre_result.rcm,
                         iter_end - input_confirmed);
      continue;
    }

    if (pre_result.action == AMCommandPreprocessor::Action::Shell) {
      CR shell_result = ExecuteShellCommand_(client_manager, config_manager,
                                             pre_result.command);
      if (shell_result.first.first == EC::Success) {
        const std::string &msg = shell_result.second.first;
        if (!msg.empty()) {
          prompt.Print(msg);
        }
        prompt.Print(AMStr::amfmt("\nCommand exit with code {}",
                                  shell_result.second.second));
      } else {
        PrintECM_(prompt, shell_result.first);
      }
      SetCliExitCode(static_cast<int>(shell_result.first.first));
      const auto shell_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, shell_result.first,
                         shell_end - input_confirmed);
      continue;
    }

    if (pre_result.action != AMCommandPreprocessor::Action::Cli) {
      continue;
    }

    if (pre_result.command.empty()) {
      continue;
    }

    CLI::App app{"AMSFTP Interactive", app_name};
    CliArgsPool args_pool;
    CliCommands cli_commands = BindCliOptions(app, args_pool);

    try {
      std::vector<std::string> cli_args =
          AMCommandPreprocessor::SplitCliTokens(pre_result.command);
      // CLI11 consumes args via pop_back, so reverse to preserve order.
      std::reverse(cli_args.begin(), cli_args.end());
      app.parse(cli_args);
    } catch (const CLI::CallForHelp &e) {
      prompt.Print(app.help());
      ECM parse_rcm = {EC::Success, ""};
      SetCliExitCode(e.get_exit_code());
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, parse_rcm, iter_end - input_confirmed);
      continue;
    } catch (const CLI::CallForAllHelp &e) {
      prompt.Print(app.help("", CLI::AppFormatMode::All));
      ECM parse_rcm = {EC::Success, ""};
      SetCliExitCode(e.get_exit_code());
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, parse_rcm, iter_end - input_confirmed);
      continue;
    } catch (const CLI::CallForVersion &e) {
      prompt.Print(app.version());
      ECM parse_rcm = {EC::Success, ""};
      SetCliExitCode(e.get_exit_code());
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, parse_rcm, iter_end - input_confirmed);
      continue;
    } catch (const CLI::ParseError &e) {
      const std::string parse_msg = e.what();
      prompt.Print(parse_msg);
      ECM parse_rcm = {EC::InvalidArg, parse_msg};
      SetCliExitCode(static_cast<int>(parse_rcm.first));
      const auto iter_end = std::chrono::steady_clock::now();
      UpdatePromptState_(prompt_state, parse_rcm, iter_end - input_confirmed);
      continue;
    }

    DispatchResult dispatch =
        DispatchCliCommands(cli_commands, managers, pre_result.async, true);
    const auto exec_end = std::chrono::steady_clock::now();
    UpdatePromptState_(prompt_state, dispatch.rcm, exec_end - input_confirmed);
  }

  prompt.FlushHistory(config_manager);
  AMIsInteractive.store(false);
  return g_cli_exit_code;
}
