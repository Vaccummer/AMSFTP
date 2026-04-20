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
};

struct TerminalAddArg {
  std::vector<std::string> nicknames = {};
  bool force = false;
};

struct TerminalListArg {};

struct TerminalRemoveArg {
  std::vector<std::string> nicknames = {};
};

struct ChannelAddArg {
  std::string target = {};
};

struct ChannelListArg {
  std::string nickname = {};
};

struct ChannelRemoveArg {
  std::string target = {};
  bool force = false;
};

struct ChannelRenameArg {
  std::string src = {};
  std::string dst = {};
};

} // namespace AMInterface::terminal
