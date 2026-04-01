#include "interface/cli/InteractiveLoop.hpp"
#include "application/client/ClientAppService.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/time.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/completion/CompletionRuntimeAdapter.hpp"
#include "interface/completion/Proxy.hpp"
#include "interface/parser/CommandPreprocess.hpp"
#include "interface/parser/TokenAnalyzerRuntimeAdapter.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/parser/TokenTypeAnalyzer.hpp"
#include "interface/prompt/CLICorePrompt.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <magic_enum/magic_enum.hpp>
#include <memory>
#include <vector>

namespace AMInterface::cli {

namespace {
using OS_TYPE = AMDomain::client::OS_TYPE;
using DocumentKind = AMDomain::config::DocumentKind;

/**
 * @brief Return the active client or the local client fallback.
 */
AMDomain::client::ClientHandle
ResolveActiveClient_(AMApplication::client::ClientAppService &client_service) {
  return client_service.GetCurrentClient();
}

/**
 * @brief Resolve prompt username/hostname with environment fallbacks.
 */
std::pair<std::string, std::string>
ResolveUserHost_(const AMDomain::client::ClientHandle &client) {
  std::string username;
  std::string hostname;
  if (client) {
    AMDomain::client::ConRequest request = client->ConfigPort().GetRequest();
    username = request.username;
    hostname = request.hostname;
  }

  auto read_env = [](const char *key) {
    std::string value;
    if (AMStr::GetEnv(key, &value)) {
      return value;
    }
    return std::string();
  };

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
 * @brief Resolve prompt cwd from client runtime metadata.
 */
std::string ResolvePromptCwd_(const AMDomain::client::ClientHandle &client) {
  if (!client) {
    return "/";
  }

  auto normalize = [](const std::string &raw) {
    std::string path = AMStr::Strip(raw);
    if (path.empty()) {
      return std::string();
    }
    return AMPath::UnifyPathSep(path, "/");
  };

  auto metadata =
      client->MetaDataPort().QueryTypedValue<AMDomain::host::ClientMetaData>();
  if (metadata.has_value()) {
    std::string cwd = normalize(metadata->cwd);
    if (!cwd.empty()) {
      return cwd;
    }
    cwd = normalize(metadata->login_dir);
    if (!cwd.empty()) {
      return cwd;
    }
  }

  const std::string home = normalize(client->ConfigPort().GetHomeDir());
  if (!home.empty()) {
    return home;
  }
  return "/";
}

/**
 * @brief Reload settings when `settings.toml` changed on disk.
 *
 * This makes external edits effective without requiring process restart.
 */
ECM ReloadSettingsIfUpdated_(
    AMInterface::prompt::IsoclineProfileManager &prompt_profile_history_manager,
    AMApplication::config::AMConfigAppService &config_service,
    bool *reloaded = nullptr) {
  if (reloaded) {
    *reloaded = false;
  }
  std::filesystem::path settings_path;
  if (!config_service.GetDataPath(DocumentKind::Settings, &settings_path) ||
      settings_path.empty()) {
    return Ok();
  }

  std::error_code ec;
  const auto current_write_time =
      std::filesystem::last_write_time(settings_path, ec);
  if (ec) {
    return Ok();
  }

  static std::filesystem::file_time_type last_write_time{};
  static bool has_last_write_time = false;
  if (!has_last_write_time) {
    last_write_time = current_write_time;
    has_last_write_time = true;
    return Ok();
  }
  if (current_write_time <= last_write_time) {
    return Ok();
  }

  // Avoid clobbering in-memory updates that have not been dumped yet.
  if (config_service.IsDirty(DocumentKind::Settings)) {
    return Ok();
  }

  ECM load_rcm = config_service.Load(DocumentKind::Settings, true);
  if (load_rcm.first != EC::Success) {
    return load_rcm;
  }
  (void)prompt_profile_history_manager;
  last_write_time = current_write_time;
  if (reloaded) {
    *reloaded = true;
  }
  return Ok();
}

/**
 * @brief Print an ECM error message if the code is not Success.
 */
void PrintECM_(AMInterface::prompt::AMPromptIOManager &prompt, const ECM &rcm) {
  if (rcm.first == EC::Success) {
    return;
  }
  std::string name = std::string(magic_enum::enum_name(rcm.first));
  if (rcm.second.empty()) {
    prompt.FmtPrint("❌ {}", name);
    return;
  }
  prompt.FmtPrint("❌ {}: {}", name, rcm.second);
}

void RegisterPromptGetters_(AMInterface::prompt::CLIPromtRender &core_prompt,
                            const CLIServices &managers) {
  core_prompt.RegisterGetter("cwd", [&managers]() {
    auto client = managers.client_service->GetCurrentClient();
    return ResolvePromptCwd_(client);
  });
  core_prompt.RegisterGetter("username", [&managers]() {
    auto client = ResolveActiveClient_(managers.client_service.Get());
    return ResolveUserHost_(client).first;
  });
  core_prompt.RegisterGetter("hostname", [&managers]() {
    auto client = ResolveActiveClient_(managers.client_service.Get());
    return ResolveUserHost_(client).second;
  });
  core_prompt.RegisterGetter("os_type", [&managers]() {
    OS_TYPE os_type = OS_TYPE::Unknown;
    auto client = ResolveActiveClient_(managers.client_service.Get());
    if (client) {
      try {
        os_type = client->ConfigPort().GetOSType();
      } catch (const std::exception &) {
        os_type = OS_TYPE::Unknown;
      }
    }
    switch (os_type) {
    case OS_TYPE::Linux:
      return std::string("linux");
    case OS_TYPE::MacOS:
      return std::string("macos");
    case OS_TYPE::Windows:
    default:
      return std::string("windows");
    }
  });
  core_prompt.RegisterGetter("task_pending", [&managers]() {
    size_t pending_count = 0;
    size_t running_count = 0;
    managers.transfer_service->GetTaskCounts(&pending_count, &running_count);
    return std::to_string(pending_count);
  });
  core_prompt.RegisterGetter("task_running", [&managers]() {
    size_t pending_count = 0;
    size_t running_count = 0;
    managers.transfer_service->GetTaskCounts(&pending_count, &running_count);
    return std::to_string(running_count);
  });
}
} // namespace

/**
 * @brief Register callback into one callback vector.
 */
void AMInteractiveEventRegistry::RegisterCallback_(
    std::vector<std::function<void()> *> *callbacks,
    std::function<void()> *clear_fn) {
  if (!callbacks || !clear_fn) {
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if (std::find(callbacks->begin(), callbacks->end(), clear_fn) !=
      callbacks->end()) {
    return;
  }
  callbacks->push_back(clear_fn);
}

/**
 * @brief Register callback for PromptCore-return phase.
 */
void AMInteractiveEventRegistry::RegisterOnCorePromptReturn(
    std::function<void()> *clear_fn) {
  RegisterCallback_(&core_prompt_return_callbacks_, clear_fn);
}

/**
 * @brief Register callback for interactive-loop-exit phase.
 */
void AMInteractiveEventRegistry::RegisterOnInteractiveLoopExit(
    std::function<void()> *clear_fn) {
  RegisterCallback_(&interactive_loop_exit_callbacks_, clear_fn);
}

/**
 * @brief Execute callbacks from one callback vector.
 */
void AMInteractiveEventRegistry::RunCallbacks_(
    const std::vector<std::function<void()> *> &callbacks) {
  for (auto *fn : callbacks) {
    if (!fn || !(*fn)) {
      continue;
    }
    try {
      (*fn)();
    } catch (...) {
    }
  }
}

/**
 * @brief Execute all callbacks for PromptCore-return phase.
 */
void AMInteractiveEventRegistry::RunOnCorePromptReturn() {
  std::vector<std::function<void()> *> callbacks;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks = core_prompt_return_callbacks_;
  }
  RunCallbacks_(callbacks);
}

/**
 * @brief Execute all callbacks for interactive-loop-exit phase.
 */
void AMInteractiveEventRegistry::RunOnInteractiveLoopExit() {
  std::vector<std::function<void()> *> callbacks;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks = interactive_loop_exit_callbacks_;
  }
  RunCallbacks_(callbacks);
}

/**
 * @brief Run the core interactive loop until the user exits.
 */
int RunInteractiveLoop(CLI::App &app, const CliCommands &cli_commands,
                       AMInterface::parser::CommandNode &command_tree,
                       const CLIServices &managers, CliRunContext &ctx) {
  bool skip_loop_exit_callbacks = false;
  const amf &cflag = ctx.task_control_token;

  auto store_exit_code = [&ctx](int code) {
    if (ctx.exit_code) {
      ctx.exit_code->store(code, std::memory_order_relaxed);
    }
  };

  AMInterface::parser::TokenTypeAnalyzer token_type_analyzer;
  token_type_analyzer.SetCommandTree(&command_tree);
  auto analyzer_runtime =
      std::make_shared<AMInterface::parser::TokenAnalyzerRuntimeAdapter>(
          managers.client_service.Get(), managers.host_service.Get(),
          managers.var_service.Get(), managers.var_interface_service.Get(),
          managers.style_service.Get(), managers.PromptProfileManager());
  auto completion_runtime =
      std::make_shared<AMInterface::completion::CompletionRuntimeAdapter>(
          managers.client_service.Get(), managers.host_service.Get(),
          managers.var_service.Get(), managers.var_interface_service.Get(),
          managers.style_service.Get(), managers.PromptProfileManager(),
          managers.transfer_pool.Get());
  token_type_analyzer.SetRuntime(analyzer_runtime);
  token_type_analyzer.BindInteractiveEventRegistry(
      &managers.interactive_event_registry);
  AMInterface::parser::AMInputPreprocess input_preprocess(
      managers.var_interface_service.Get(), token_type_analyzer);

  AMCompleter completer{&command_tree, &token_type_analyzer,
                        completion_runtime,
                        &managers.interactive_event_registry};
  completer.Install();

  AMInterface::prompt::CLIPromtRender core_prompt(managers.style_service.Get());
  RegisterPromptGetters_(core_prompt, managers);

  ECM last_dispatch_result = Ok();
  int64_t last_dispatch_elapsed_ms = 0;
  AMInterface::prompt::CLIPromtRender::RenderArg prompt_arg = {};

  while (true) {
    if (cflag->IsInterrupted()) {
      cflag->ClearInterrupt();
      continue;
    }

    // bool settings_reloaded = false;
    // ECM reload_settings_rcm =
    //     ReloadSettingsIfUpdated_(prompt_profile_history_manager,
    //                              managers.config_service,
    //                              &settings_reloaded);
    // if (reload_settings_rcm.first != EC::Success) {
    //   PrintECM_(prompt, reload_settings_rcm);
    // } else if (settings_reloaded) {
    //   core_prompt.InvalidateCache();
    // }

    prompt_arg.current_nickname =
        AMStr::Strip(managers.client_service->CurrentNickname());
    prompt_arg.elapsed_time_ms = last_dispatch_elapsed_ms;
    prompt_arg.result = last_dispatch_result;

    const std::string prompt_text = core_prompt.Render(prompt_arg);
    std::string line;
    (void)managers.config_service->BackupIfNeeded();

    // monitor.SilenceHook("GLOBAL");
    // monitor.ResumeHook("COREPROMPT");
    // ctx.task_control_token->ClearInterrupt();
    bool canceled = !managers.prompt_io_manager->PromptCore(
        prompt_text, &line, &token_type_analyzer);
    // ctx.task_control_token->ClearInterrupt();
    // monitor.SilenceHook("COREPROMPT");
    // monitor.ResumeHook("GLOBAL");
    managers.interactive_event_registry.RunOnCorePromptReturn();

    if (canceled) {
      last_dispatch_result = Ok();
      last_dispatch_elapsed_ms = 0;
      continue;
    }

    std::string trimmed = AMStr::Strip(line);
    if (trimmed.empty()) {
      continue;
    }
    const auto dispatch_begin = AMTime::SteadyNow();
    try {
      auto prep = input_preprocess.Preprocess(trimmed);
      if (prep.rcm.first != EC::Success) {
        PrintECM_(managers.prompt_io_manager.Get(), prep.rcm);
        store_exit_code(static_cast<int>(prep.rcm.first));
        last_dispatch_result = prep.rcm;
        last_dispatch_elapsed_ms = std::max<int64_t>(
            0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
        continue;
      }
      std::vector<std::string> cli_args = std::move(prep.data);
      if (cli_args.empty()) {
        continue;
      }
      // CLI11 consumes args via pop_back, so reverse to preserve order.
      std::reverse(cli_args.begin(), cli_args.end());
      app.clear();
      app.parse(cli_args);
    } catch (const CLI::CallForHelp &e) {
      managers.prompt_io_manager->Print(app.help());
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      last_dispatch_result = parse_rcm;
      last_dispatch_elapsed_ms = std::max<int64_t>(
          0, std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now() - dispatch_begin)
                 .count());
      continue;
    } catch (const CLI::CallForAllHelp &e) {
      managers.prompt_io_manager->Print(app.help("", CLI::AppFormatMode::All));
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      last_dispatch_result = parse_rcm;
      last_dispatch_elapsed_ms =
          AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow());
      continue;
    } catch (const CLI::CallForVersion &e) {
      managers.prompt_io_manager->Print(app.version());
      ECM parse_rcm = {EC::Success, ""};
      store_exit_code(e.get_exit_code());
      last_dispatch_result = parse_rcm;
      last_dispatch_elapsed_ms = std::max<int64_t>(
          0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
      continue;
    } catch (const CLI::ParseError &e) {
      const std::string parse_msg = e.what();
      managers.prompt_io_manager->Print(parse_msg);
      ECM parse_rcm = {EC::InvalidArg, parse_msg};
      store_exit_code(static_cast<int>(parse_rcm.first));
      last_dispatch_result = parse_rcm;
      last_dispatch_elapsed_ms = std::max<int64_t>(
          0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
      continue;
    }

    ctx.async = false;
    ctx.enforce_interactive = true;
    DispatchCliCommands(cli_commands, managers, ctx);
    last_dispatch_result = ctx.rcm;
    last_dispatch_elapsed_ms = std::max<int64_t>(
        0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));

    if (ctx.request_exit) {
      skip_loop_exit_callbacks = ctx.skip_loop_exit_callbacks;
      break;
    }
  }

  if (!skip_loop_exit_callbacks) {
    managers.interactive_event_registry.RunOnInteractiveLoopExit();
  }
  ctx.is_interactive->store(false, std::memory_order_relaxed);
  return ctx.exit_code ? ctx.exit_code->load(std::memory_order_relaxed) : 0;
}

} // namespace AMInterface::cli
