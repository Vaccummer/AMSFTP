#include "bootstrap/AppRuntime.hpp"
#include "bootstrap/BootstrapEnvironment.hpp"
#include "bootstrap/CLIRun.hpp"
#include <exception>
#include <filesystem>
#include <iostream>

namespace {
namespace fs = std::filesystem;
}

int main(int argc, char **argv) {
  AMBootstrap::AppRuntime runtime = {};
  int exit_code = static_cast<int>(EC::UnknownError);

  try {
    const std::string app_name =
        argc > 0 ? fs::path(argv[0]).filename().string() : "amsftp.exe";
    const std::string app_description =
        "AMSFTP CLI\nVaccummer@https://github.com/Vaccummer/AMSFTP\nA CLI "
        "programm for multi-hosts SFTP/FTP/HTTP file management and SSH "
        "session.";
    const std::string app_version = "dev";
    auto root_result = AMBootstrap::ResolveRootDir();
    if (!root_result.rcm) {
      AMBootstrap::PrintBootstrapWarn(root_result.rcm.msg());
      return static_cast<int>(root_result.rcm.code);
    }

    const ECM build_rcm =
        runtime.Build(app_name, app_description, app_version, root_result.data);
    if (!build_rcm) {
      AMBootstrap::PrintBootstrapWarn(build_rcm.msg());
      return static_cast<int>(build_rcm.code);
    }

    exit_code = AMBootstrap::RunCLI(runtime, argc, argv);

    const ECM cleanup_rcm = runtime.Shutdown();
    if (!cleanup_rcm) {
      AMBootstrap::PrintBootstrapWarn(cleanup_rcm.msg());
      if (exit_code != static_cast<int>(EC::Success)) {
        exit_code = static_cast<int>(cleanup_rcm.code);
      }
    }

    return exit_code;
  } catch (const std::exception &e) {
    std::cerr << "💀 Escaped Runtime Exception: " << e.what() << std::endl;
    return static_cast<int>(EC::UnknownError);
  }
}
