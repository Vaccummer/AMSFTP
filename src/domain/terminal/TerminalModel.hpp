#pragma once

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
