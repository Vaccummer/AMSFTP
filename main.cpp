#include "foundation/DataClass.hpp"
#include "interface/ApplicationAdapters.hpp"
#include "interface/CLIBind.hpp"
#include "interface/InteractiveLoop.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/FileSystem.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Logger.hpp"
#include "AMManager/SignalMonitor.hpp"
#include "AMManager/Transfer.hpp"
#include "AMManager/Var.hpp"
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
    auto &signal_monitor = AMCliSignalMonitor::Instance();
    auto &config_manager = AMConfigManager::Instance();
    auto &prompt_manager = AMPromptManager::Instance();
    auto &host_manager = AMHostManager::Instance();
    auto &var_manager = VarCLISet::Instance();
    auto &log_manager = AMLogManager::Instance();
    auto &client_manager = AMClientManager::Instance();
    auto &transfer_manager = AMTransferManager::Instance();
    auto &filesystem = AMFileSystem::Instance();
    CliManagers managers(signal_monitor, config_manager, prompt_manager,
                         host_manager, var_manager, log_manager, client_manager,
                         transfer_manager, filesystem);
    ECM init_rcm = managers.Init();
    if (!isok(init_rcm)) {
      return static_cast<int>(init_rcm.first);
    }
    AMInterface::ApplicationAdapters::Runtime::RuntimeBindings runtime_bindings{};
    runtime_bindings.host_manager = &managers.host_manager;
    runtime_bindings.client_manager = &managers.client_manager;
    runtime_bindings.transfer_manager = &managers.transfer_manager;
    runtime_bindings.var_manager = &managers.var_manager;
    runtime_bindings.signal_monitor = &managers.signal_monitor;
    runtime_bindings.prompt_manager = &managers.prompt_manager;
    runtime_bindings.config_manager = &managers.config_manager;
    runtime_bindings.filesystem = &managers.filesystem;
    AMInterface::ApplicationAdapters::Runtime::Bind(runtime_bindings);

    auto &run_ctx = CliRunContext::Instance();
    run_ctx.rcm = {EC::Success, ""};
    run_ctx.async = false;
    run_ctx.enforce_interactive = false;
    run_ctx.command_name.clear();
    run_ctx.enter_interactive = false;
    run_ctx.request_exit = false;
    run_ctx.skip_loop_exit_callbacks = false;
    if (!run_ctx.exit_code) {
      run_ctx.exit_code = std::make_shared<std::atomic<int>>(0);
    }
    run_ctx.exit_code->store(0, std::memory_order_relaxed);
    run_ctx.is_interactive = managers.client_manager.GetIsInteractiveFlag();
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

    DispatchCliCommands(cli_commands, managers, run_ctx);
    if (run_ctx.enter_interactive) {
      managers.prompt_manager.ChangeClient(
          managers.client_manager.CurrentNickname());
      RunInteractiveLoop(app_name, managers, run_ctx);
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

