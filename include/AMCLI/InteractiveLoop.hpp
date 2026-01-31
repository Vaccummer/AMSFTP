#pragma once
#include "AMCLI/CLIBind.hpp"
#include <string>

/**
 * @brief Run the core interactive loop until the user exits.
 *
 * @param app_name CLI application name used for CLI11 parsing.
 * @param managers Shared manager references for command dispatch.
 * @return Exit code to use when terminating the program.
 */
int RunInteractiveLoop(const std::string &app_name,
                       const CliManagers &managers);
