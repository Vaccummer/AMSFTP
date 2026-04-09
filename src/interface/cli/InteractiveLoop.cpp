#include "interface/cli/InteractiveLoop.hpp"
#include "application/client/ClientAppService.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/time.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/completion/CompletionRuntimeAdapter.hpp"
#include "interface/completion/Engine.hpp"
#include "interface/parser/CommandPreprocess.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/prompt/CLICorePrompt.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntimeAdapter.hpp"
#include "interface/token_analyser/TokenTypeAnalyzer.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <magic_enum/magic_enum.hpp>
#include <memory>
#include <vector>

namespace AMInterface::cli {

namespace {
using OS_TYPE = AMDomain::client::OS_TYPE;
using ClientStatus = AMDomain::client::ClientStatus;
using DocumentKind = AMDomain::config::DocumentKind;
constexpr int kEventIdCorePromptFilesystemCacheClear = 7001;
constexpr int kEventIdCorePromptHighlightCacheClear = 7002;
constexpr int kEventIdCorePromptCompletionCacheClear = 7003;
constexpr int kEventIdCorePromptBackupIfNeeded = 7004;
constexpr int kEventIdCorePromptCompletionCancelAsync = 7005;
constexpr int kEventIdLoopExitConfigSaveAll = 7101;

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
    const std::string unified = AMPath::UnifyPathSep(path, "/");
    const std::string normalized = AMPath::NormalizeJoinedPath(unified, "/");
    return normalized.empty() ? unified : normalized;
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
    AMApplication::config::ConfigAppService &config_service,
    bool *reloaded = nullptr) {
  if (reloaded) {
    *reloaded = false;
  }
  std::filesystem::path settings_path;
  if (!config_service.GetDataPath(DocumentKind::Settings, &settings_path) ||
      settings_path.empty()) {
    return OK;
  }

  std::error_code ec;
  const auto current_write_time =
      std::filesystem::last_write_time(settings_path, ec);
  if (ec) {
    return OK;
  }

  static std::filesystem::file_time_type last_write_time{};
  static bool has_last_write_time = false;
  if (!has_last_write_time) {
    last_write_time = current_write_time;
    has_last_write_time = true;
    return OK;
  }
  if (current_write_time <= last_write_time) {
    return OK;
  }

  // Avoid clobbering in-memory updates that have not been dumped yet.
  if (config_service.IsDirty(DocumentKind::Settings)) {
    return OK;
  }

  ECM load_rcm = config_service.Load(DocumentKind::Settings, true);
  if (load_rcm.code != EC::Success) {
    return load_rcm;
  }
  (void)prompt_profile_history_manager;
  last_write_time = current_write_time;
  if (reloaded) {
    *reloaded = true;
  }
  return OK;
}

/**
 * @brief Print an ECM error message if the code is not Success.
 */
void PrintECM_(AMInterface::prompt::AMPromptIOManager &prompt, const ECM &rcm) {
  if (rcm.code == EC::Success) {
    return;
  }
  std::string name = std::string(magic_enum::enum_name(rcm.code));
  const std::string message = rcm.msg();
  if (message.empty()) {
    prompt.FmtPrint("❌ {}", name);
    return;
  }
  prompt.FmtPrint("❌ {}: {}", name, message);
}

void RegisterPromptGetters_(AMInterface::prompt::CLIPromtRender &core_prompt,
                            const CLIServices &managers) {
  core_prompt.RegisterGetter("cwd", [&managers]() {
    auto client = managers.application.client_service->GetCurrentClient();
    return ResolvePromptCwd_(client);
  });
  core_prompt.RegisterGetter("username", [&managers]() {
    auto client =
        ResolveActiveClient_(managers.application.client_service.Get());
    return ResolveUserHost_(client).first;
  });
  core_prompt.RegisterGetter("hostname", [&managers]() {
    auto client =
        ResolveActiveClient_(managers.application.client_service.Get());
    return ResolveUserHost_(client).second;
  });
  core_prompt.RegisterGetter("os_type", [&managers]() {
    OS_TYPE os_type = OS_TYPE::Unknown;
    auto client =
        ResolveActiveClient_(managers.application.client_service.Get());
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
    managers.interfaces.transfer_service->GetTaskCounts(&pending_count,
                                                        &running_count);
    return std::to_string(pending_count);
  });
  core_prompt.RegisterGetter("task_running", [&managers]() {
    size_t pending_count = 0;
    size_t running_count = 0;
    managers.interfaces.transfer_service->GetTaskCounts(&pending_count,
                                                        &running_count);
    return std::to_string(running_count);
  });
}

class ScopedInteractiveEventCallbacks_ : public NonCopyableNonMovable {
public:
  explicit ScopedInteractiveEventCallbacks_(
      AMInterface::cli::InteractiveEventRegistry *registry)
      : registry_(registry) {}

  ~ScopedInteractiveEventCallbacks_() override {
    if (!registry_) {
      return;
    }
    for (const auto &entry : entries_) {
      (void)registry_->Unregister(entry.first, entry.second);
    }
  }

  bool Register(InteractiveEventCategory category, int id,
                std::function<void()> fn) {
    if (!registry_) {
      return false;
    }
    (void)registry_->Unregister(category, id);
    const bool ok = registry_->Register(category, id, std::move(fn));
    if (ok) {
      entries_.push_back({category, id});
    }
    return ok;
  }

private:
  AMInterface::cli::InteractiveEventRegistry *registry_ = nullptr;
  std::vector<std::pair<InteractiveEventCategory, int>> entries_ = {};
};
} // namespace

/**
 * @brief Run the core interactive loop until the user exits.
 */
int RunInteractiveLoop(CLI::App &app, const CliCommands &cli_commands,
                       AMInterface::parser::CommandNode &command_tree,
                       const CLIServices &managers, CliRunContext &ctx) {
  // Keep Unix-style absolute paths (e.g. /home/user) as positional args.
  app.allow_windows_style_options(false);

  auto store_exit_code = [&ctx](int code) {
    if (ctx.exit_code) {
      ctx.exit_code->store(code, std::memory_order_relaxed);
    }
  };

  AMInterface::parser::TokenTypeAnalyzer token_type_analyzer;
  token_type_analyzer.SetCommandTree(&command_tree);
  auto analyzer_runtime =
      std::make_shared<AMInterface::parser::TokenAnalyzerRuntimeAdapter>(
          managers.application.client_service.Get(),
          managers.application.host_service.Get(),
          managers.application.var_service.Get(),
          managers.interfaces.var_interface_service.Get(),
          managers.interfaces.style_service.Get(),
          managers.application.prompt_profile_manager.Get());
  auto completion_runtime =
      std::make_shared<AMInterface::completion::CompletionRuntimeAdapter>(
          managers.application.client_service.Get(),
          managers.application.host_service.Get(),
          managers.application.var_service.Get(),
          managers.interfaces.var_interface_service.Get(),
          managers.interfaces.style_service.Get(),
          managers.application.prompt_profile_manager.Get(),
          managers.domain.transfer_pool.Get());
  token_type_analyzer.SetRuntime(analyzer_runtime);
  AMInterface::parser::AMInputPreprocess input_preprocess(
      managers.interfaces.var_interface_service.Get(), token_type_analyzer);

  AMInterface::completer::AMCompleteEngine completion_engine{
      &command_tree, &token_type_analyzer, completion_runtime,
      &managers.application.completer_config_manager.Get(),
      &managers.interfaces.style_service.Get()};
  completion_engine.LoadConfig();
  completion_engine.Install();

  ScopedInteractiveEventCallbacks_ interactive_callbacks(
      &managers.runtime.interactive_event_registry);
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      kEventIdCorePromptFilesystemCacheClear,
      [&managers]() { managers.application.filesystem_service->ClearCache(); });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      kEventIdCorePromptHighlightCacheClear,
      []() { AMInterface::parser::TokenTypeAnalyzer::ClearTokenCache(); });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      kEventIdCorePromptCompletionCacheClear,
      [&completion_engine]() { completion_engine.ClearCache(); });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      kEventIdCorePromptBackupIfNeeded, [&managers]() {
        managers.interfaces.prompt_io_manager->SyncCurrentHistory();
        (void)managers.application.config_service->BackupIfNeeded();
      });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      kEventIdCorePromptCompletionCancelAsync,
      [&completion_engine]() { completion_engine.CancelPendingAsync(); });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::InteractiveLoopExit,
      kEventIdLoopExitConfigSaveAll, [&managers]() {
        (void)managers.interfaces.config_interface_service->SaveAll();
      });

  AMInterface::prompt::CLIPromtRender core_prompt(
      managers.interfaces.style_service.Get());
  RegisterPromptGetters_(core_prompt, managers);

  AMInterface::prompt::CLIPromtRender::RenderArg prompt_arg = {};

  while (true) {
    if (ctx.task_control_token->IsInterrupted()) {
      ctx.task_control_token->ClearInterrupt();
      continue;
    }

    // bool settings_reloaded = false;
    // ECM reload_settings_rcm =
    //     ReloadSettingsIfUpdated_(prompt_profile_history_manager,
    //                              managers.application.config_service,
    //                              &settings_reloaded);
    // if (reload_settings_rcm.code != EC::Success) {
    //   PrintECM_(prompt, reload_settings_rcm);
    // } else if (settings_reloaded) {
    //   core_prompt.InvalidateCache();
    // }

    prompt_arg.current_nickname =
        AMStr::Strip(managers.application.client_service->CurrentNickname());
    prompt_arg.current_client_connected = true;
    if (auto client =
            ResolveActiveClient_(managers.application.client_service.Get());
        client) {
      const auto state = client->ConfigPort().GetState();
      prompt_arg.current_client_connected =
          (state.data.status == ClientStatus::OK);
    }
    prompt_arg.elapsed_time_ms = 0;
    prompt_arg.result = OK;

    // managers.interfaces.prompt_io_manager->Print("");
    const std::string prompt_text = core_prompt.Render(prompt_arg);

    std::optional<std::string> line_opt = std::nullopt;
    if (auto profile = managers.interfaces.prompt_profile_history_manager
                           ->CurrentProfile();
        profile && profile->Use()) {
      completion_engine.Install();
      auto highlighter_guard = profile->TemporarySetHighlighter(
          &AMInterface::parser::TokenTypeAnalyzer::PromptHighlighter_,
          &token_type_analyzer);
      (void)highlighter_guard;
      line_opt = managers.interfaces.prompt_io_manager->PromptCore(prompt_text);
    } else {
      line_opt = managers.interfaces.prompt_io_manager->PromptCore(prompt_text);
    }
    managers.runtime.interactive_event_registry.Run(
        InteractiveEventCategory::CorePromptReturn);

    if (!line_opt.has_value()) {
      prompt_arg.result = OK;
      prompt_arg.elapsed_time_ms = 0;
      continue;
    }

    std::string trimmed = AMStr::Strip(*line_opt);
    if (trimmed.empty()) {
      continue;
    }
    const auto dispatch_begin = AMTime::SteadyNow();
    auto prep = input_preprocess.Preprocess(trimmed);
    if (prep.rcm.code != EC::Success) {
      PrintECM_(managers.interfaces.prompt_io_manager.Get(), prep.rcm);
      store_exit_code(static_cast<int>(prep.rcm.code));
      prompt_arg.result = prep.rcm;
      prompt_arg.elapsed_time_ms = std::max<int64_t>(
          0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
      continue;
    }
    std::vector<std::string> cli_args = std::move(prep.data);
    if (cli_args.empty()) {
      continue;
    }
    // CLI11 consumes args via pop_back, so reverse to preserve order.
    std::reverse(cli_args.begin(), cli_args.end());

    try {
      app.clear();
      app.parse(cli_args);
    } catch (const CLI::CallForHelp &e) {
      managers.interfaces.prompt_io_manager->Print(app.help());
      ECM parse_rcm = OK;
      store_exit_code(e.get_exit_code());
      prompt_arg.result = parse_rcm;
      prompt_arg.elapsed_time_ms = std::max<int64_t>(
          0, std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now() - dispatch_begin)
                 .count());
      continue;
    } catch (const CLI::CallForAllHelp &e) {
      managers.interfaces.prompt_io_manager->Print(
          app.help("", CLI::AppFormatMode::All));
      ECM parse_rcm = OK;
      store_exit_code(e.get_exit_code());
      prompt_arg.result = parse_rcm;
      prompt_arg.elapsed_time_ms =
          AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow());
      continue;
    } catch (const CLI::CallForVersion &e) {
      managers.interfaces.prompt_io_manager->Print(app.version());
      ECM parse_rcm = OK;
      store_exit_code(e.get_exit_code());
      prompt_arg.result = parse_rcm;
      prompt_arg.elapsed_time_ms = std::max<int64_t>(
          0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
      continue;
    } catch (const CLI::ParseError &e) {
      const std::string parse_msg = e.what();
      managers.interfaces.prompt_io_manager->Print(parse_msg);
      ECM parse_rcm = {EC::InvalidArg, __func__, "", parse_msg};
      store_exit_code(static_cast<int>(parse_rcm.code));
      prompt_arg.result = parse_rcm;
      prompt_arg.elapsed_time_ms = std::max<int64_t>(
          0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
      continue;
    }

    ctx.async = false;
    ctx.enforce_interactive = true;
    DispatchCliCommands(cli_commands, managers, ctx);
    prompt_arg.result = ctx.rcm;
    prompt_arg.elapsed_time_ms = std::max<int64_t>(
        0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));

    if (ctx.request_exit) {
      break;
    }
  }

  if (!ctx.skip_loop_exit_callbacks) {
    managers.runtime.interactive_event_registry.Run(
        InteractiveEventCategory::InteractiveLoopExit);
  }
  ctx.is_interactive->store(false, std::memory_order_relaxed);
  return ctx.exit_code ? ctx.exit_code->load(std::memory_order_relaxed) : 0;
}

} // namespace AMInterface::cli
