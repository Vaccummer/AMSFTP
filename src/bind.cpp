#include "AMCLI/CLIBind.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

/** Entry point for AMSFTP CLI (non-interactive). */
int main2(int argc, char **argv) {
  try {
    auto &signal_monitor = AMCliSignalMonitor::Instance();
    signal_monitor.InstallHandlers();
    signal_monitor.Start();
    struct SignalMonitorGuard {
      AMCliSignalMonitor &monitor;
      explicit SignalMonitorGuard(AMCliSignalMonitor &ref) : monitor(ref) {}
      ~SignalMonitorGuard() { monitor.Stop(); }
    } guard(signal_monitor);

    auto &config_manager = AMConfigManager::Instance();
    auto init_status = config_manager.Init();
    if (init_status.first != EC::Success) {
      std::cerr << init_status.second << std::endl;
      return static_cast<int>(init_status.first);
    }

    auto &client_manager = AMClientManager::Instance(config_manager);
    auto &filesystem = AMFileSystem::Instance(client_manager, config_manager);
    AMClientManager::global_interrupt_flag = amgif;
    AMFileSystem::global_interrupt_flag = amgif;
    AMIsInteractive.store(false);

    const std::string app_name =
        fs::path(argc > 0 ? argv[0] : "amsftp").filename().string();
    CLI::App app{"AMSFTP CLI", app_name};

    CliArgsPool args_pool;
    CliCommands cli_commands = BindCliOptions(app, args_pool);

    try {
      CLI11_PARSE(app, argc, argv);
    } catch (const CLI::ParseError &e) {
      return app.exit(e);
    }

    CliManagers managers;
    managers.config_manager =
        std::shared_ptr<AMConfigManager>(&config_manager, [](auto *) {});
    managers.client_manager =
        std::shared_ptr<AMClientManager>(&client_manager, [](auto *) {});
    managers.filesystem =
        std::shared_ptr<AMFileSystem>(&filesystem, [](auto *) {});

    DispatchCliCommands(cli_commands, managers);
    return g_cli_exit_code;
  } catch (const std::exception &e) {
    std::cerr << "Unexpected error: " << e.what() << std::endl;
    return -13;
  }
}


