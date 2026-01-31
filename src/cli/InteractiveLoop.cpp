#include "AMCLI/InteractiveLoop.hpp"
#include "AMCLI/CommandPreprocess.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/Path.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <chrono>
#include <cstdlib>
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
    hostname = "host";
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
  if (!icon.empty()) {
    return icon;
  }
  return config_manager.GetSettingString({"style", "Icons", "windows"}, "*");
}

/**
 * @brief Build the prompt string and update cached prefix when needed.
 */
std::string BuildPrompt_(PromptState &state, AMClientManager &client_manager,
                         AMConfigManager &config_manager) {
  auto client = ResolveActiveClient_(client_manager);
  std::string nickname =
      client ? client->GetNickname() : std::string("local");
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
    state.cached_prefix =
        AMStr::amfmt("{} {}@{}", sysicon, username, hostname);
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
 * @brief Split a command line into argv tokens with simple quoting support.
 */
bool SplitCommandLine_(const std::string &line,
                       std::vector<std::string> *tokens,
                       std::string *error) {
  if (!tokens) {
    return false;
  }
  tokens->clear();

  std::string current;
  bool in_single = false;
  bool in_double = false;

  for (char c : line) {
    if (!in_double && c == '\'') {
      in_single = !in_single;
      continue;
    }
    if (!in_single && c == '"') {
      in_double = !in_double;
      continue;
    }
    if (!in_single && !in_double && AMStr::IsWhitespace(c)) {
      if (!current.empty()) {
        tokens->push_back(current);
        current.clear();
      }
      continue;
    }
    current.push_back(c);
  }

  if (in_single || in_double) {
    if (error) {
      *error = "Unclosed quote in command line";
    }
    return false;
  }

  if (!current.empty()) {
    tokens->push_back(current);
  }
  return true;
}

/**
 * @brief Execute a shell command via ConductCmd on the current client.
 */
ECM ExecuteShellCommand_(AMPromptManager &prompt,
                         AMClientManager &client_manager,
                         AMConfigManager &config_manager,
                         const std::string &command) {
  auto client = ResolveActiveClient_(client_manager);
  if (!client) {
    return {EC::ClientNotFound, "No active client"};
  }
  if (client->GetProtocol() != ClientProtocol::SFTP) {
    return {EC::OperationUnsupported,
            "Shell command only supported by SFTP client"};
  }

  const int timeout_ms = config_manager.ResolveTimeoutMs(5000);
  auto result = client->ConductCmd(command, timeout_ms, amgif);
  if (result.first.first != EC::Success) {
    return result.first;
  }
  if (!result.second.first.empty()) {
    prompt.Print(result.second.first);
  }
  return result.first;
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

    const std::string prompt_text =
        BuildPrompt_(prompt_state, client_manager, config_manager);

    std::string line;
    AMCliSignalMonitor &monitor = AMCliSignalMonitor::Instance();
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

    std::string trimmed = AMStr::TrimWhitespaceCopy(line);
    if (trimmed.empty()) {
      continue;
    }

    std::string lowered = AMStr::lowercase(trimmed);
    if (lowered == "exit") {
      break;
    }

    const auto pre_start = std::chrono::steady_clock::now();
    AMCommandPreprocessor::Result pre_result =
        preprocessor.Preprocess(trimmed);
    const auto pre_end = std::chrono::steady_clock::now();

    if (pre_result.rcm.first != EC::Success) {
      PrintECM_(prompt, pre_result.rcm);
      SetCliExitCode(static_cast<int>(pre_result.rcm.first));
      UpdatePromptState_(prompt_state, pre_result.rcm, pre_end - pre_start);
      continue;
    }

    if (pre_result.action == AMCommandPreprocessor::Action::Handled) {
      SetCliExitCode(static_cast<int>(pre_result.rcm.first));
      UpdatePromptState_(prompt_state, pre_result.rcm, pre_end - pre_start);
      continue;
    }

    if (pre_result.action == AMCommandPreprocessor::Action::Shell) {
      const auto shell_start = std::chrono::steady_clock::now();
      ECM rcm = ExecuteShellCommand_(prompt, client_manager, config_manager,
                                     pre_result.command);
      const auto shell_end = std::chrono::steady_clock::now();
      if (rcm.first != EC::Success) {
        PrintECM_(prompt, rcm);
      }
      SetCliExitCode(static_cast<int>(rcm.first));
      UpdatePromptState_(prompt_state, rcm, shell_end - shell_start);
      continue;
    }

    if (pre_result.action != AMCommandPreprocessor::Action::Cli) {
      continue;
    }

    if (pre_result.command.empty()) {
      continue;
    }

    std::vector<std::string> argv;
    std::string parse_error;
    if (!SplitCommandLine_(pre_result.command, &argv, &parse_error)) {
      prompt.Print(parse_error);
      continue;
    }
    if (argv.empty()) {
      continue;
    }
    argv.insert(argv.begin(), app_name);

    CLI::App app{"AMSFTP CLI", app_name};
    CliArgsPool args_pool;
    CliCommands cli_commands = BindCliOptions(app, args_pool);

    try {
      app.parse(argv);
    } catch (const CLI::ParseError &e) {
      prompt.Print(e.what());
      continue;
    }

    const auto exec_start = std::chrono::steady_clock::now();
    DispatchResult dispatch =
        DispatchCliCommands(cli_commands, managers, pre_result.async, true);
    const auto exec_end = std::chrono::steady_clock::now();

    UpdatePromptState_(prompt_state, dispatch.rcm, exec_end - exec_start);
  }

  AMIsInteractive.store(false);
  return g_cli_exit_code;
}
