#include "CLI/CLI.hpp"
#include "bootstrap/runtime/AppHandle.hpp"
#include "bootstrap/runtime/SessionHandle.hpp"
#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/prompt/PromptHistoryManager.hpp"
#include "application/prompt/PromptProfileManager.hpp"
#include "application/style/StyleAppService.hpp"
#include "domain/log/LoggerManager.hpp"
#include "foundation/core/DataClass.hpp"
#include "infrastructure/signal_monitor/SignalMonitor.hpp"
#include "domain/host/HostManager.hpp"
#include "application/transfer/TransferAppService.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/cli/InteractiveLoop.hpp"
#include "interface/prompt/Prompt.hpp"
#include <atomic>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>

int main(int argc, char **argv) {
  try {
    auto time_start = std::chrono::steady_clock::now();
    const std::string app_name =
        fs::path(argc > 0 ? argv[0] : "amsftp").filename().string();
    CLI::App app{"AMSFTP CLI\nauthor: Vaccummer\ngithub: "
                 "https://github.com/Vaccummer/AMSFTP",
                 app_name};
    app.set_version_flag("-v,--version", "Show version information");

    CliArgsPool args_pool;
    CliCommands cli_commands = BindCliOptions(app, args_pool);
    try {
      app.parse(argc, argv);
    } catch (const CLI::CallForHelp &e) {
      std::cout << app.help() << std::endl;
      return e.get_exit_code();
    } catch (const CLI::CallForAllHelp &e) {
      std::cout << app.help("", CLI::AppFormatMode::All) << std::endl;
      return e.get_exit_code();
    } catch (const CLI::CallForVersion &e) {
      std::cout << app.version() << std::endl;
      return e.get_exit_code();
    } catch (const CLI::ParseError &e) {
      return app.exit(e);
    }
    time_start = std::chrono::steady_clock::now();
    AMInfraCliSignalMonitor signal_monitor{};
    AMApplication::prompt::PromptProfileManager app_prompt_profile_manager{};
    AMApplication::prompt::PromptHistoryManager app_prompt_history_manager{};
    AMApplication::style::AMStyleConfigManager app_style_config_manager{};
    AMInterface::prompt::IsoclineProfileManager prompt_profile_history_manager(
        app_prompt_profile_manager, app_prompt_history_manager,
        app_style_config_manager);
    AMInterface::prompt::AMPromptIOManager prompt_io_manager(prompt_profile_history_manager);
    AMDomain::host::AMHostConfigManager host_config_manager{};
    AMDomain::host::AMKnownHostsManager known_hosts_manager{};
    AMLoggerManager log_manager{};
    AMDomain::client::ClientServiceArg client_arg = {};
    client_arg.heartbeat_interval_s = 60;
    client_arg.heartbeat_timeout_ms = 100;
    auto host_app_service = std::make_shared<AMApplication::host::AMHostAppService>();
    auto known_hosts_app_service =
        std::make_shared<AMApplication::host::AMKnownHostsAppService>();
    auto client_service =
        std::make_shared<AMApplication::client::ClientAppService>(std::move(client_arg));
    AMDomain::filesystem::FilesystemArg filesystem_arg = {};
    auto filesystem_service =
        std::make_shared<AMApplication::filesystem::FilesystemAppService>(
            filesystem_arg, host_app_service, client_service);

    AMApplication::TransferWorkflow::TransferAppService transfer_service(
        *client_service, client_service->PublicPool(), filesystem_service);
    AMBootstrap::AppHandle app_handle(
        signal_monitor, *host_app_service, *known_hosts_app_service,
        prompt_profile_history_manager,
        prompt_io_manager, host_config_manager, known_hosts_manager,
        log_manager, *client_service, *filesystem_service, transfer_service);
    AMBootstrap::SessionHandle session_handle;
    ECM init_rcm = app_handle.Init(session_handle.task_control_token);
    if (!isok(init_rcm)) {
      return static_cast<int>(init_rcm.first);
    }
    struct RuntimeBindingGuard {
      explicit RuntimeBindingGuard(AMBootstrap::AppHandle *app)
          : app_handle(app) {}
      ~RuntimeBindingGuard() {
        if (app_handle) {
          app_handle->ResetRuntimeBindings();
        }
      }
      AMBootstrap::AppHandle *app_handle = nullptr;
    } runtime_binding_guard(&app_handle);

    auto register_sync_participants = [&]() -> ECM {
      auto &config_service = app_handle.managers.config_service;
      auto *style_sync_holder = &app_handle.managers.style_service;

      auto client_participant =
          config_service.RegisterSyncParticipant<AMDomain::client::ClientServiceArg>(
              [client_service]() {
                return client_service && client_service->IsConfigDirty();
              },
              [client_service]() {
                return client_service ? client_service->ExportConfigSnapshot()
                                      : AMDomain::client::ClientServiceArg{};
              },
              [client_service]() {
                if (client_service) {
                  client_service->ClearConfigDirty();
                }
              });
      if (!isok(client_participant.rcm)) {
        return client_participant.rcm;
      }

      auto prompt_profile_participant = config_service
                                            .RegisterSyncParticipant<AMDomain::prompt::
                                                                         PromptProfileArg>(
                                                [&app_prompt_profile_manager]() {
                                                  return app_prompt_profile_manager
                                                      .IsConfigDirty();
                                                },
                                                [&app_prompt_profile_manager]() {
                                                  return app_prompt_profile_manager
                                                      .ExportConfigSnapshot();
                                                },
                                                [&app_prompt_profile_manager]() {
                                                  app_prompt_profile_manager
                                                      .ClearConfigDirty();
                                                });
      if (!isok(prompt_profile_participant.rcm)) {
        return prompt_profile_participant.rcm;
      }

      auto prompt_history_participant = config_service
                                            .RegisterSyncParticipant<AMDomain::prompt::
                                                                         PromptHistoryArg>(
                                                [&app_prompt_history_manager]() {
                                                  return app_prompt_history_manager
                                                      .IsConfigDirty();
                                                },
                                                [&app_prompt_history_manager]() {
                                                  return app_prompt_history_manager
                                                      .ExportConfigSnapshot();
                                                },
                                                [&app_prompt_history_manager]() {
                                                  app_prompt_history_manager
                                                      .ClearConfigDirty();
                                                });
      if (!isok(prompt_history_participant.rcm)) {
        return prompt_history_participant.rcm;
      }

      auto style_participant =
          config_service.RegisterSyncParticipant<AMDomain::style::StyleConfigArg>(
              [style_sync_holder]() {
                return style_sync_holder && style_sync_holder->IsConfigDirty();
              },
              [style_sync_holder]() {
                return style_sync_holder
                           ? style_sync_holder->ExportConfigSnapshot()
                           : AMDomain::style::StyleConfigArg{};
              },
              [style_sync_holder]() {
                if (style_sync_holder) {
                  style_sync_holder->ClearConfigDirty();
                }
              });
      if (!isok(style_participant.rcm)) {
        return style_participant.rcm;
      }

      if (client_service) {
        client_service->ClearConfigDirty();
      }
      app_prompt_profile_manager.ClearConfigDirty();
      app_prompt_history_manager.ClearConfigDirty();
      if (style_sync_holder) {
        style_sync_holder->ClearConfigDirty();
      }
      return Ok();
    };

    ECM register_sync_rcm = register_sync_participants();
    if (!isok(register_sync_rcm)) {
      return static_cast<int>(register_sync_rcm.first);
    }

    session_handle.ResetRunContext();
    CliRunContext &run_ctx = session_handle.run_context;
    run_ctx.is_interactive =
        app_handle.managers.client_service.GetInteractiveFlag();
    if (run_ctx.is_interactive) {
      run_ctx.is_interactive->store(false, std::memory_order_relaxed);
    }

#ifdef _WIN32
    AMInitWSA();
#endif
    auto time_end = std::chrono::steady_clock::now();
    std::cout << "Init time: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     time_end - time_start)
                     .count()
              << "ms" << std::endl;

    DispatchCliCommands(cli_commands, app_handle.managers, run_ctx);
    if (run_ctx.enter_interactive) {
      app_handle.managers.prompt_profile_history_manager.ChangeClient(
          app_handle.managers.client_service.CurrentNickname());
      RunInteractiveLoop(app_name, app_handle.managers, run_ctx);
    }
    if (run_ctx.rcm.first != EC::Success) {
      return static_cast<int>(run_ctx.rcm.first);
    }
    return run_ctx.exit_code
               ? run_ctx.exit_code->load(std::memory_order_relaxed)
               : 0;
  } catch (const std::exception &e) {
    std::cerr << "❌Uncatched RuntimeError: " << e.what() << "\n";
    return static_cast<int>(EC::UnknownError);
  }
}









