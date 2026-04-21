#include "interface/cli/InteractiveLoop.hpp"
#include "application/client/ClientAppService.hpp"
#include "application/prompt/PromptRenderDTO.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/time.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/cli/CliParseFlow.hpp"
#include "interface/cli/InteractiveLoopRuntime.hpp"
#include "interface/completion/Engine.hpp"
#include "interface/parser/CommandPreprocess.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/prompt/CLIPromtRender.hpp"
#include <algorithm>
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
[[maybe_unused]] ECM ReloadSettingsIfUpdated_(
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
void PrintECM_(AMInterface::prompt::PromptIOManager &prompt, const ECM &rcm) {
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

std::string ResolvePromptOsType_(const AMDomain::client::ClientHandle &client) {
  OS_TYPE os_type = OS_TYPE::Unknown;
  if (client) {
    try {
      os_type = client->ConfigPort().GetOSType();
    } catch (const std::exception &) {
      os_type = OS_TYPE::Unknown;
    }
  }

  switch (os_type) {
  case OS_TYPE::Linux:
    return "linux";
  case OS_TYPE::MacOS:
    return "macos";
  case OS_TYPE::Windows:
  default:
    return "windows";
  }
}

std::string
ResolvePromptSysIcon_(AMInterface::style::AMStyleService &style_service,
                      const std::string &os_type) {
  const auto icons = style_service.GetInitArg().style.cli_prompt.icons;
  const std::string normalized = AMStr::lowercase(AMStr::Strip(os_type));
  if (normalized == "linux") {
    return icons.linux.empty() ? std::string("PC") : icons.linux;
  }
  if (normalized == "macos" || normalized == "mac") {
    return icons.macos.empty() ? std::string("PC") : icons.macos;
  }
  return icons.windows.empty() ? std::string("PC") : icons.windows;
}

AMApplication::prompt::PromptRenderDTO
BuildPromptRenderDTO_(const CLIServices &managers, const ECM &result,
                      int64_t elapsed_time_ms) {
  AMApplication::prompt::PromptRenderDTO dto = {};
  auto client = ResolveActiveClient_(managers.application.client_service.Get());

  dto.nickname =
      AMStr::Strip(managers.application.client_service->CurrentNickname());
  if (dto.nickname.empty()) {
    dto.nickname = "local";
  }

  dto.client_connected = true;
  if (client) {
    const auto state = client->ConfigPort().GetState();
    dto.client_connected = (state.data.status == ClientStatus::OK);
  }

  const auto [username, hostname] = ResolveUserHost_(client);
  dto.username = username;
  dto.hostname = hostname;
  dto.cwd = ResolvePromptCwd_(client);
  dto.os_type = ResolvePromptOsType_(client);
  dto.sysicon = ResolvePromptSysIcon_(managers.interfaces.style_service.Get(),
                                      dto.os_type);

  size_t pending_count = 0;
  size_t running_count = 0;
  managers.interfaces.transfer_service->GetTaskCounts(&pending_count,
                                                      &running_count);
  const int64_t paused_count = static_cast<int64_t>(
      managers.application.transfer_service->GetPausedTasks().size());
  dto.task_pending = static_cast<int64_t>(pending_count);
  dto.task_running = static_cast<int64_t>(running_count);
  dto.task_paused = paused_count;
  dto.task_num = std::max<int64_t>(0, dto.task_pending) +
                 std::max<int64_t>(0, dto.task_running);

  dto.time_now = FormatTime(static_cast<size_t>(AMTime::seconds()), "%H:%M:%S");
  dto.time_clock = dto.time_now;
  dto.elapsed = AMStr::fmt("{}ms", std::max<int64_t>(0, elapsed_time_ms));
  dto.success = (result.code == EC::Success);
  dto.ec_name = dto.success ? std::string()
                            : std::string(magic_enum::enum_name(result.code));
  return dto;
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
      (void)registry_->Unregister(entry.category, entry.id);
    }
  }

  InteractiveEventRegistry::RegistrationId
  Register(InteractiveEventCategory category, std::function<void()> fn) {
    if (!registry_) {
      return 0;
    }
    const auto id = registry_->Register(category, std::move(fn));
    if (id != 0) {
      entries_.push_back({category, id});
    }
    return id;
  }

private:
  struct ScopedEntry {
    InteractiveEventCategory category =
        InteractiveEventCategory::CorePromptReturn;
    InteractiveEventRegistry::RegistrationId id = 0;
  };

  AMInterface::cli::InteractiveEventRegistry *registry_ = nullptr;
  std::vector<ScopedEntry> entries_ = {};
};

ECM EnsureInteractiveLoopRuntime_(
    AMInterface::parser::CommandNode &command_tree,
    const CLIServices &managers) {
  if (!managers.runtime.interactive_loop_runtime.IsReady()) {
    managers.runtime.interactive_loop_runtime.SetInstance(
        std::make_unique<InteractiveLoopRuntime>());
  }
  return managers.runtime.interactive_loop_runtime->Setup(command_tree,
                                                          managers);
}
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

  const ECM setup_rcm = EnsureInteractiveLoopRuntime_(command_tree, managers);
  if (setup_rcm.code != EC::Success) {
    PrintECM_(managers.interfaces.prompt_io_manager.Get(), setup_rcm);
    store_exit_code(static_cast<int>(setup_rcm.code));
    ctx.is_interactive->store(false, std::memory_order_relaxed);
    return ctx.exit_code ? ctx.exit_code->load(std::memory_order_relaxed)
                         : static_cast<int>(setup_rcm.code);
  }

  auto &interactive_runtime = managers.runtime.interactive_loop_runtime.Get();
  auto &input_analyzer = interactive_runtime.Analyzer();
  auto &completion_engine = interactive_runtime.CompletionEngine();
  AMInterface::parser::AMInputPreprocess input_preprocess(
      managers.interfaces.var_interface_service.Get(), input_analyzer);

  ScopedInteractiveEventCallbacks_ interactive_callbacks(
      &managers.runtime.interactive_event_registry);
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      [&managers]() { managers.application.filesystem_service->ClearCache(); });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      [&input_analyzer]() { input_analyzer.ClearTokenCache(); });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      [&completion_engine]() { completion_engine.ClearCache(); });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn, [&managers]() {
        if (managers.application.config_service->IsBackupNeeded()) {
          managers.interfaces.prompt_io_manager->SyncCurrentHistory();
        }
        (void)managers.application.config_service->BackupIfNeeded();
      });
  (void)interactive_callbacks.Register(
      InteractiveEventCategory::CorePromptReturn,
      [&completion_engine]() { completion_engine.CancelPendingAsync(); });
  // (void)interactive_callbacks.Register(
  //     InteractiveEventCategory::InteractiveLoopExit, [&managers]() {
  //       managers.interfaces.prompt_io_manager->SyncCurrentHistory();
  //     });

  AMInterface::prompt::CLIPromtRender core_prompt(
      managers.interfaces.style_service.Get());
  std::string last_core_prompt_render_error = "";

  AMApplication::prompt::PromptRenderDTO prompt_dto = {};

  while (true) {
    if (ctx.task_control_token->IsInterrupted()) {
      ctx.task_control_token->ClearInterrupt();
      continue;
    }
    prompt_dto = BuildPromptRenderDTO_(managers, OK, 0);

    // managers.interfaces.prompt_io_manager->Print("");
    const std::string prompt_text = core_prompt.Render(prompt_dto);
    if (!core_prompt.State().render_ok) {
      std::string err = core_prompt.State().render_error;
      if (err.empty()) {
        err = "failed to render core prompt template";
      }
      if (err != last_core_prompt_render_error) {
        managers.interfaces.prompt_io_manager->FmtPrint(
            "❌ CorePrompt render failed: {}", AMStr::BBCEscape(err));
        last_core_prompt_render_error = err;
      }
    } else {
      last_core_prompt_render_error.clear();
    }

    std::optional<std::string> line_opt = std::nullopt;
    line_opt = managers.interfaces.prompt_io_manager->PromptCore(prompt_text);

    managers.runtime.interactive_event_registry.Run(
        InteractiveEventCategory::CorePromptReturn);

    if (!line_opt.has_value()) {
      prompt_dto = BuildPromptRenderDTO_(managers, OK, 0);
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
      prompt_dto = BuildPromptRenderDTO_(
          managers, prep.rcm,
          std::max<int64_t>(
              0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow())));
      continue;
    }
    std::vector<std::string> cli_args = std::move(prep.data);
    if (cli_args.empty()) {
      continue;
    }

    const CliParseOutcome parse_outcome = ParseCliTokens(
        {
            .app = &app,
            .command_tree = &command_tree,
            .style_service = &managers.interfaces.style_service.Get(),
            .validate_unknown_command = true,
            .require_command = false,
            .show_all_help_when_no_command = false,
        },
        std::move(cli_args));
    if (!parse_outcome.ShouldDispatch()) {
      if (!parse_outcome.message.empty()) {
        managers.interfaces.prompt_io_manager->Print(parse_outcome.message);
      }
      store_exit_code(parse_outcome.exit_code != 0
                          ? parse_outcome.exit_code
                          : static_cast<int>(parse_outcome.rcm.code));
      prompt_dto = BuildPromptRenderDTO_(
          managers, parse_outcome.rcm,
          std::max<int64_t>(
              0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow())));
      continue;
    }

    ctx.async = false;
    ctx.enforce_interactive = true;
    DispatchCliCommands(cli_commands, managers, ctx);
    prompt_dto = BuildPromptRenderDTO_(
        managers, ctx.rcm,
        std::max<int64_t>(
            0, AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow())));

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
