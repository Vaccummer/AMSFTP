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
    const std::string app_name =
        argc > 0 ? fs::path(argv[0]).filename().string() : "amsftp";
    auto root_result = AMBootstrap::ResolveRootDir();
    if (!root_result.rcm) {
      AMBootstrap::PrintBootstrapWarn(root_result.rcm.msg());
      return static_cast<int>(root_result.rcm.code);
    }
    const fs::path root_dir = root_result.data;

    auto build_result = AMBootstrap::BuildBootstrapServices(app_name, root_dir);

    if (!build_result.rcm || !build_result.data) {
      const EC ec =
          build_result.rcm ? EC::InvalidHandle : build_result.rcm.code;
      const std::string detail = build_result.rcm
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
