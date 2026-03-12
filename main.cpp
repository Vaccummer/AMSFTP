#include "CLI/CLI.hpp"
#include "bootstrap/AppHandle.hpp"
#include "bootstrap/SessionHandle.hpp"
#include "application/client/ClientAppService.hpp"
#include "domain/log/LoggerManager.hpp"
#include "foundation/DataClass.hpp"
#include "infrastructure/client/runtime/ClientFactoryAdapter.hpp"
#include "infrastructure/signal_monitor/SignalMonitor.hpp"
#include "domain/filesystem/FileSystemManager.hpp"
#include "domain/host/HostManager.hpp"
#include "application/transfer/TransferAppService.hpp"
#include "interface/cli/CLIBind.hpp"
#include "interface/cli/InteractiveLoop.hpp"
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
    auto &prompt_manager = AMPromptManager::Instance();
    AMDomain::host::AMHostConfigManager host_config_manager{};
    AMDomain::host::AMKnownHostsManager known_hosts_manager{};
    AMLoggerManager log_manager{};
    AMInfra::ClientRuntime::ClientFactoryAdapter client_factory(
        host_config_manager);
    AMApplication::client::ClientAppService client_service(
        host_config_manager, client_factory);
    auto &transfer_manager = AMDomain::transfer::AMTransferManager::Instance();
    AMApplication::TransferWorkflow::TransferAppService transfer_service(transfer_manager);
    auto &filesystem = AMDomain::filesystem::AMFileSystem::Instance();
    AMBootstrap::AppHandle app_handle(
        signal_monitor, prompt_manager, host_config_manager,
        known_hosts_manager, log_manager, client_service, transfer_service,
        filesystem);
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
      app_handle.managers.prompt_manager.ChangeClient(
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






