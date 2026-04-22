#pragma once

#include <algorithm>
#include "domain/client/ClientModel.hpp"
#include <cstddef>
#include <map>
#include <memory>
#include <string>

namespace AMDomain::terminal {
class IChannelPort;
using ClientStatus = AMDomain::client::ClientStatus;
constexpr const char *kDefaultTerminalChannelName = "default";
constexpr int kTerminalRemoveCloseTimeoutMs = 1500;

struct ChannelCacheThresholdBytes {
  size_t warning = 32U * 1024U * 1024U;
  size_t terminate = 128U * 1024U * 1024U;
};

/**
 * @brief Settings payload for `Options.TerminalManager`.
 */
struct TerminalManagerArg {
  int read_timeout_ms = -1;
  int send_timeout_ms = 0;
  ChannelCacheThresholdBytes channel_cache_threshold_bytes = {};
};

inline void NormalizeTerminalManagerArg(TerminalManagerArg *arg) {
  if (!arg) {
    return;
  }
  if (arg->read_timeout_ms == 0 || arg->read_timeout_ms < -1) {
    arg->read_timeout_ms = -1;
  }
  if (arg->send_timeout_ms < -1) {
    arg->send_timeout_ms = 0;
  }
  arg->channel_cache_threshold_bytes.warning =
      std::max<size_t>(1U, arg->channel_cache_threshold_bytes.warning);
  arg->channel_cache_threshold_bytes.terminate =
      std::max(arg->channel_cache_threshold_bytes.warning,
               arg->channel_cache_threshold_bytes.terminate);
}

struct ChannelOpenArgs {
  std::string channel_name = "";
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
  std::string term = "xterm-256color";
};

struct ChannelActiveArgs {
  std::string channel_name = "";
};

struct ChannelReadArgs {
  size_t max_bytes = 4096;
};

struct ChannelWriteArgs {
  std::string input = "";
};

struct ChannelResizeArgs {
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
};

struct ChannelCloseArgs {
  std::string channel_name = "";
  bool force = false;
};

struct ChannelRenameArgs {
  std::string src_channel_name = "";
  std::string dst_channel_name = "";
};

struct ChannelListArgs {
  std::string channel_name = "";
};

struct CheckSessionArgs {};

struct ChannelOpenResult {
  bool opened = false;
  std::string channel_name = "";
};

struct ChannelActiveResult {
  bool activated = false;
  std::string channel_name = "";
};

struct ChannelReadResult {
  std::string output = "";
  bool eof = false;
  std::string channel_name = "";
};

struct ChannelWriteResult {
  size_t bytes_written = 0;
  std::string channel_name = "";
};

struct ChannelResizeResult {
  bool resized = false;
  std::string channel_name = "";
};

struct ChannelCloseResult {
  bool closed = false;
  int exit_code = -1;
  std::string channel_name = "";
};

struct ChannelRenameResult {
  bool renamed = false;
  std::string src_channel_name = "";
  std::string dst_channel_name = "";
};

struct ChannelListResult {
  std::map<std::string, std::shared_ptr<IChannelPort>> channels = {};
  std::string current_channel = "";
};

struct CheckSessionResult {
  bool is_supported = false;
  bool is_open = false;
  bool can_resize = false;
  ClientStatus status = ClientStatus::NotInitialized;
  std::string current_channel = "";
};

} // namespace AMDomain::terminal
