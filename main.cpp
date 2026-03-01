#include "AMBase/DataClass.hpp"
#include "AMCLI/CLIBind.hpp"
#include "AMCLI/InteractiveLoop.hpp"
#include <atomic>
#include <filesystem>
#include <iostream>
#include <stdexcept>

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
    auto &managers = CliManagers::Instance();
    ECM init_rcm = managers.Init();
    if (!isok(init_rcm)) {
      if (!init_rcm.second.empty()) {
        std::cerr << init_rcm.second << std::endl;
      }
      return static_cast<int>(init_rcm.first);
    }
    AMIsInteractive.store(false, std::memory_order_relaxed);

#ifdef _WIN32
    AMInitWSA();
    std::atexit([]() {
      if (is_wsa_initialized.exchange(false)) {
        WSACleanup();
      }
    });
#endif

    auto time_end = std::chrono::steady_clock::now();
    std::cout << "Init time: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     time_end - time_start)
                     .count()
              << "ms" << std::endl;

    DispatchResult dispatch = DispatchCliCommands(cli_commands, managers);
    if (dispatch.enter_interactive) {
      managers.prompt_manager.ChangeClient(managers.client_manager.CurrentNickname());
      RunInteractiveLoop(app_name, managers);
    }
    if (dispatch.rcm.first != EC::Success) {
      return static_cast<int>(dispatch.rcm.first);
    }
    return g_cli_exit_code;
  } catch (const std::runtime_error &e) {
    std::cerr << "Uncatched RuntimeError: " << e.what() << std::endl;
    return static_cast<int>(EC::UnknownError);
  }
}
