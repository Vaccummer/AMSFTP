#include "bootstrap/BootstrapServices.hpp"
#include "bootstrap/CLIRun.hpp"
#include <exception>
#include <filesystem>
#include <iostream>

namespace {
namespace fs = std::filesystem;
}

int main(int argc, char **argv) {
  try {
    auto time_n = AMTime::miliseconds();
    const std::string app_name =
        fs::path(argc > 0 ? argv[0] : "amsftp").filename().string();
    const fs::path root_dir = fs::current_path();

    auto build_result = AMBootstrap::BuildBootstrapServices(app_name, root_dir);

    if (!build_result.ok() || !build_result.data) {
      const EC ec =
          build_result.ok() ? EC::InvalidHandle : build_result.rcm.code;
      const std::string detail = build_result.ok()
                                     ? "bootstrap service build returned null"
                                     : build_result.rcm.msg();
      AMBootstrap::PrintBootstrapWarn(detail);
      return static_cast<int>(ec);
    }

    return AMBootstrap::RunCLI(*build_result.data, argc, argv);

  } catch (const std::exception &e) {
    std::cerr << "Uncaught runtime error: " << e.what() << std::endl;
    return static_cast<int>(EC::UnknownError);
  }
}
