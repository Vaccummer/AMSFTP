#include "AMBase/DataClass.hpp"
#include "AMCLI/CLIBind.hpp"
#include "AMCLI/InteractiveLoop.hpp"
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
    auto &managers = CliManagers::Instance();
    ECM init_rcm = managers.Init();
    if (!isok(init_rcm)) {
      return static_cast<int>(init_rcm.first);
    }
    auto &run_ctx = CliRunContext::Instance();
    run_ctx.rcm = {EC::Success, ""};
    run_ctx.async = false;
    run_ctx.enforce_interactive = false;
    run_ctx.command_name.clear();
    run_ctx.enter_interactive = nullptr;
    run_ctx.request_exit = nullptr;
    run_ctx.skip_loop_exit_callbacks = nullptr;
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

    DispatchResult dispatch =
        DispatchCliCommands(cli_commands, managers, run_ctx);
    if (dispatch.enter_interactive) {
      managers.prompt_manager.ChangeClient(
          managers.client_manager.CurrentNickname());
      RunInteractiveLoop(app_name, managers, run_ctx);
    }
    if (dispatch.rcm.first != EC::Success) {
      return static_cast<int>(dispatch.rcm.first);
    }
    return run_ctx.exit_code
               ? run_ctx.exit_code->load(std::memory_order_relaxed)
               : 0;
  } catch (const std::exception &e) {
    std::cerr << "❌Uncatched RuntimeError: " << e.what() << "\n";
    return static_cast<int>(EC::UnknownError);
  }
}
