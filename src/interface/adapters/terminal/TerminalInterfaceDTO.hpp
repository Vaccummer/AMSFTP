#pragma once

#include <string>
#include <vector>

namespace AMInterface::terminal {

struct TerminalShellRunArg {
  std::string cmd = {};
  int max_time_s = -1;
};

struct TerminalLaunchArg {
  std::string target = {};
  bool start_in_god_mode = false;
};

struct TerminalAddArg {
  std::vector<std::string> nicknames = {};
  bool force = false;
};

struct TerminalListArg {};

struct TerminalRemoveArg {
  std::vector<std::string> nicknames = {};
};

struct TerminalClearArg {
  double timeout_s = 2.0;
};

} // namespace AMInterface::terminal
