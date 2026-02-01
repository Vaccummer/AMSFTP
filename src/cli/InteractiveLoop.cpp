#include "AMCLI/InteractiveLoop.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/Path.hpp"
#include "AMCLI/CommandPreprocess.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <magic_enum/magic_enum.hpp>

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
 * @brief Convert a tagged icon string like "[#RRGGBB]text[/]" into ANSI color.
 *
 * @param tagged Tagged icon string.
 * @param converted Output string with ANSI escape sequences.
 * @return True if conversion succeeded; false if format is invalid.
 */
bool TryConvertTaggedIconToAnsi_(const std::string &tagged,
                                 std::string *converted) {
  if (!converted) {
    return false;
  }

  if (tagged.size() < 10) {
    return false;
  }
  if (tagged[0] != '[' || tagged[1] != '#') {
    return false;
  }

  const size_t close = tagged.find(']');
  if (close != 8) {
    return false;
  }

  const size_t suffix_pos = tagged.size() - 3;
  if (tagged.compare(suffix_pos, 3, "[/]") != 0) {
    return false;
  }

  const std::string hex = tagged.substr(2, 6);
  for (char c : hex) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }

  const std::string content =
      tagged.substr(close + 1, suffix_pos - (close + 1));
  const int r = std::stoi(hex.substr(0, 2), nullptr, 16);
  const int g = std::stoi(hex.substr(2, 2), nullptr, 16);
  const int b = std::stoi(hex.substr(4, 2), nullptr, 16);

  std::ostringstream oss;
  oss << "\x1b[38;2;" << r << ";" << g << ";" << b << "m" << content
      << "\x1b[0m";
  *converted = oss.str();
  return true;
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
  if (TryConvertTaggedIconToAnsi_(icon, &converted)) {
    return converted;
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
    state.cached_prefix = AMStr::amfmt("{} {}@{}", sysicon, username, hostname);
    state.last_nickname = nickname;
  }

  const std::string elapsed =
      state.last_elapsed.empty() ? "-" : state.last_elapsed;
  const bool ok = state.last_rcm.first == EC::Success;
  const std::string status = ok ? "✅" : "❌";
  const std::string ec_name =
      ok ? "" : std::string(magic_enum::enum_name(state.last_rcm.first));

  std::string line1 =
      AMStr::amfmt("{}  {}  {}", state.cached_prefix, elapsed, status);
  if (!ec_name.empty()) {
    line1 += " " + ec_name;
  }

  std::string workdir = "/";
  if (client) {
    workdir = client_manager.GetOrInitWorkdir(client);
  }
  std::string line2 = AMStr::amfmt("({}){} $", nickname, workdir);
  return line1 + "\n" + line2 + " ";
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

    std::string line;
    AMCliSignalMonitor &monitor = AMCliSignalMonitor::Instance();
    (void)config_manager.ConfigBackupIfNeeded();
    monitor.SilenceHook("GLOBAL");
    monitor.ResumeHook("COREPROMPT");
    if (amgif) {
      amgif->reset();
    }

    bool canceled = prompt.PromptCore(prompt_text, &line);

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
