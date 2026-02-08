#include "AMCLI/CLIBind.hpp"
#include "AMCLI/InteractiveLoop.hpp"
#include "AMClient/IOCore.hpp"
#include "AMClient/SFTP.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <atomic>
#include <filesystem>
#include <iostream>

// static auto bar = ProgressBar(0);
/** @brief No-op total-size callback placeholder for transfer progress. */
void total_cb([[maybe_unused]] int64_t total_size) {}
/** @brief No-op progress callback placeholder that keeps transfers running. */
std::optional<TransferControl>
progress_cb([[maybe_unused]] const ProgressCBInfo &info) {
  // bar.update(info.this_size);
  return std::nullopt;
}
/** @brief Print transfer error details to stderr for diagnostics. */
void error_cb(const ErrorCBInfo &info) {
  std::cerr << "Error: " << info.ecm.second << std::endl;
}
/** @brief Temporary development entry point for ad-hoc SFTP testing. */
int main2() {
#ifdef _WIN32
  WSADATA wsaData;
  int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (result != 0) {
    throw std::runtime_error("WSAStartup failed");
  }
  is_wsa_initialized.store(true, std::memory_order_relaxed);
#endif
  auto wsl_con = ConRequst("wsl", "172.26.36.83", "am", 22, "1984");
  auto wsl = std::make_shared<AMSFTPClient>(wsl_con);

  auto rcm = wsl->Connect();
  if (rcm.first != EC::Success) {
    std::cerr << "Connect failed: " << rcm.second << std::endl;
    return 1;
  }
  return 1;
}

namespace fs = std::filesystem;

/** @brief Temporary development entry point for signal monitor testing. */
int main224(int argc, char **argv) {
  auto &signal_monitor = AMCliSignalMonitor::Instance();
  signal_monitor.InstallHandlers();
  signal_monitor.Start();
  std::string tmp_test = "";
  std::cin >> tmp_test;
  return 0;
}

/** @brief Program entry point that forwards to the AMSFTP CLI runner. */
/** @brief Core AMSFTP CLI entry that initializes managers and dispatches. */
int main(int argc, char **argv) {
  try {
    auto time_start = std::chrono::steady_clock::now();
    const std::string app_name =
        fs::path(argc > 0 ? argv[0] : "amsftp").filename().string();
    CLI::App app{"AMSFTP CLI", app_name};

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
    signal_monitor.InstallHandlers();
    signal_monitor.Start();

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
    AMIsInteractive.store(false, std::memory_order_relaxed);

    CliManagers managers;
    managers.config_manager =
        std::shared_ptr<AMConfigManager>(&config_manager, [](auto *) {});
    managers.client_manager =
        std::shared_ptr<AMClientManager>(&client_manager, [](auto *) {});
    managers.filesystem =
        std::shared_ptr<AMFileSystem>(&filesystem, [](auto *) {});
    auto time_end = std::chrono::steady_clock::now();
    std::cout << "Init time: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     time_end - time_start)
                     .count()
              << "ms" << std::endl;
#ifdef _WIN32
    AMInitWSA();
    std::atexit([]() {
      if (is_wsa_initialized.exchange(false)) {
        WSACleanup();
      }
    });
#endif
    DispatchResult dispatch = DispatchCliCommands(cli_commands, managers);
    if (dispatch.enter_interactive) {
      RunInteractiveLoop(app_name, managers);
    }
    if (dispatch.rcm.first != EC::Success) {
      std::cerr << dispatch.rcm.second << std::endl;
      return static_cast<int>(dispatch.rcm.first);
    }
    time_end = std::chrono::steady_clock::now();
    std::cout << "alltime: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     time_end - time_start)
                     .count()
              << "ms" << std::endl;
    return g_cli_exit_code;
  } catch (const std::exception &e) {
    std::cerr << "Unexpected error: " << e.what() << std::endl;
    return -13;
  }
}
