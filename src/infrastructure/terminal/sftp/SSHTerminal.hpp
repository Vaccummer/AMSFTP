#pragma once

#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/tools/string.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"
#include "infrastructure/terminal/sftp/SSHChannel.hpp"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace AMInfra::terminal::SFTP {
using AMDomain::host::ClientProtocol;
using AMDomain::host::ConRequest;
using AMInfra::client::SFTP::AMSFTPIOCore;
namespace AMT = AMDomain::terminal;
static constexpr int kDefaultCloseTimeoutMs_ = 1500;

class SSHTerminalPort final : public AMT::ITerminalPort {
private:
  using ChannelMap_ = std::map<std::string, AMT::ChannelPortHandle>;

  struct TerminalBinding_ {
    AMT::ClientHandle owner_client = nullptr;
    AMSFTPIOCore *sftp_core = nullptr;
    AMT::BufferExceedCallback buffer_exceed_callback = {};
    AMT::TerminalManagerArg terminal_manager_arg = {};
  };

  struct TerminalStateCache {
    std::optional<std::string> current_channel = std::nullopt;
  };

  mutable AMAtomic<TerminalStateCache> attr_cache_ =
      AMAtomic<TerminalStateCache>(TerminalStateCache{});
  mutable AMAtomic<TerminalBinding_> binding_ =
      AMAtomic<TerminalBinding_>(TerminalBinding_{});
  mutable AMAtomic<ChannelMap_> channels_ =
      AMAtomic<ChannelMap_>(ChannelMap_{});

  [[nodiscard]] TerminalBinding_ GetBindingSnapshot_() const {
    return binding_.lock().load();
  }

  [[nodiscard]] ConRequest GetRequestSnapshot_() const {
    const auto binding = GetBindingSnapshot_();
    if (!binding.owner_client) {
      return {};
    }
    return binding.owner_client->ConfigPort().GetRequest();
  }

  [[nodiscard]] ECM EnsureSessionReady_(const ControlComponent &control) {
    const auto request = GetRequestSnapshot_();
    const auto binding = GetBindingSnapshot_();
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "terminal.session", request.hostname,
                 "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "terminal.session", request.hostname,
                 "Operation timed out");
    }
    if (!binding.owner_client || !binding.sftp_core) {
      return Err(EC::NoSession, "terminal.session", request.hostname,
                 "SFTP IO core is unavailable");
    }
    if (!binding.sftp_core->Session()) {
      return Err(EC::NoConnection, "terminal.session", request.hostname,
                 "Client session is not connected");
    }
    return OK;
  }

  [[nodiscard]] std::string ResolveTargetChannelName_(
      const std::optional<std::string> &requested_name) const {
    const std::string requested =
        requested_name.has_value() ? AMStr::Strip(*requested_name) : "";
    if (!requested.empty()) {
      return requested;
    }
    auto guard = attr_cache_.lock();
    auto current_channel = guard->current_channel;
    if (current_channel.has_value()) {
      return *current_channel;
    }
    return "";
  }

public:
  SSHTerminalPort(AMT::ClientHandle owner_client,
                  AMT::BufferExceedCallback buffer_exceed_callback = {},
                  AMT::TerminalManagerArg terminal_manager_arg = {}) {
    if (!owner_client) {
      throw std::invalid_argument("owner_client cannot be null");
    }
    if (owner_client->ConfigPort().GetProtocol() != ClientProtocol::SFTP) {
      throw std::invalid_argument(
          "owner_client protocol is not compatible with SSHTerminalPort");
    }
    auto *sftp_core = dynamic_cast<AMSFTPIOCore *>(&owner_client->IOPort());
    if (!sftp_core) {
      throw std::invalid_argument(
          "owner_client's IOPort is not compatible with AMSFTPIOCore");
    }
    {
      auto binding = binding_.lock();
      binding.store(
          {std::move(owner_client), sftp_core,
           std::move(buffer_exceed_callback),
           std::move(terminal_manager_arg)});
    }
  }

  ~SSHTerminalPort() override = default;

  [[nodiscard]] ConRequest GetRequest() const override {
    return GetRequestSnapshot_();
  }

  ECMData<AMT::ChannelOpenResult>
  OpenChannel(const AMT::ChannelOpenArgs &open_args,
              const ControlComponent &control) override {
    ECMData<AMT::ChannelOpenResult> out = {};

    const std::string channel_name = AMStr::Strip(open_args.channel_name);
    if (channel_name.empty()) {
      out.rcm = Err(EC::InvalidArg, "terminal.open", "channel_name",
                    "channel_name is required");
      return out;
    }
    if (!AMDomain::host::HostService::ValidateNickname(channel_name)) {
      out.rcm = Err(EC::InvalidArg, "terminal.open", channel_name,
                    "Invalid channel_name literal");
      return out;
    }
    auto channels = channels_.lock();
    if (channels->contains(channel_name)) {
      out.rcm = Err(EC::TargetAlreadyExists, "terminal.open", channel_name,
                    "Channel name already exists");
      return out;
    }

    const auto binding = GetBindingSnapshot_();
    auto port = std::make_shared<RealtimeSSHChannelPort>(
        binding.owner_client, channel_name, binding.buffer_exceed_callback,
        binding.terminal_manager_arg);
    if (!port) {
      out.rcm = Err(EC::InvalidHandle, "terminal.open", channel_name,
                    "Failed to create realtime SSH channel port");
      return out;
    }

    AMT::ChannelInitArgs init_args = {};
    init_args.cols = open_args.cols;
    init_args.rows = open_args.rows;
    init_args.width = open_args.width;
    init_args.height = open_args.height;
    init_args.term = open_args.term;
    out.rcm = port->Init(init_args, control);
    if (!(out.rcm)) {
      return out;
    }

    const ECM loop_rcm = port->EnsureLoopStarted(AMT::ChannelLoopStartArgs{});
    if (!loop_rcm) {
      (void)port->Close(true, kDefaultCloseTimeoutMs_, control);
      out.rcm = loop_rcm;
      return out;
    }

    (*channels)[channel_name] = port;
    out.data.channel_name = channel_name;
    out.data.opened = true;
    out.rcm = OK;
    return out;
  }

  ECMData<AMT::ChannelActiveResult>
  ActiveChannel(const AMT::ChannelActiveArgs &active_args,
                const ControlComponent &control) override {
    (void)control;
    ECMData<AMT::ChannelActiveResult> out = {};

    const std::string channel_name = AMStr::Strip(active_args.channel_name);
    if (channel_name.empty()) {
      out.rcm = Err(EC::InvalidArg, "terminal.active", "channel_name",
                    "channel_name is required");
      return out;
    }

    auto channels = channels_.lock();
    auto it = channels->find(channel_name);
    if (it == channels->end() || !it->second) {
      out.rcm = Err(EC::InvalidArg, "terminal.active", channel_name,
                    "Target channel does not exist");
      return out;
    }

    auto state = it->second->GetState();
    if (state.closed) {
      out.rcm = !(state.last_error)
                    ? state.last_error
                    : Err(EC::NoConnection, "terminal.active", channel_name,
                          "Target channel is not alive");
      return out;
    }

    {
      auto guard = attr_cache_.lock();
      guard->current_channel = channel_name;
    }
    out.data.channel_name = channel_name;
    out.data.activated = true;
    out.rcm = OK;
    return out;
  }

  ECMData<AMT::ChannelPortHandle>
  GetChannelPort(const std::optional<std::string> &channel_name,
                 const ControlComponent &control) override {
    (void)control;
    ECMData<AMT::ChannelPortHandle> out = {};

    const std::string target_name = ResolveTargetChannelName_(channel_name);
    if (target_name.empty()) {
      out.rcm = Err(EC::InvalidArg, "terminal.channel_port", "channel_name",
                    "No channel_name provided and no active channel set");
      return out;
    }

    auto channels = channels_.lock();
    auto it = channels->find(target_name);
    if (it == channels->end() || !it->second) {
      out.rcm = Err(EC::ClientNotFound, "terminal.channel_port", target_name,
                    "Target channel does not exist");
      return out;
    }

    out.data = it->second;
    out.rcm = OK;
    return out;
  }

  ECMData<AMT::ChannelCloseResult>
  CloseChannel(const AMT::ChannelCloseArgs &close_args,
               const ControlComponent &control) override {
    ECMData<AMT::ChannelCloseResult> out = {};
    AMT::ChannelPortHandle channel_port = nullptr;
    std::string target_name = {};
    {
      target_name = ResolveTargetChannelName_(close_args.channel_name);
      if (target_name.empty()) {
        out.rcm = Err(EC::InvalidArg, "terminal.close", "channel_name",
                      "No channel_name provided and no active channel set");
        return out;
      }
      auto channels = channels_.lock();
      auto it = channels->find(target_name);
      if (it == channels->end() || !it->second) {
        out.rcm = Err(EC::InvalidArg, "terminal.close", target_name,
                      "Target channel does not exist");
        return out;
      }
      out.data.channel_name = target_name;
      channel_port = it->second;
      channels->erase(it);
      auto guard = attr_cache_.lock();
      auto current_channel = guard->current_channel;
      if (current_channel.has_value() && *current_channel == target_name) {
        guard->current_channel = std::nullopt;
      }
    }

    auto close_result = channel_port->Close(close_args.force,
                                            close_args.grace_period_ms,
                                            control);
    out.rcm = close_result.rcm;
    out.data.exit_code = close_result.data.exit_code;
    out.data.closed = true;
    if (out.rcm.code == ErrorCode::Success ||
        out.rcm.code == ErrorCode::Terminate ||
        out.rcm.code == ErrorCode::OperationTimeout) {
      out.rcm = OK;
    }
    return out;
  }

  ECMData<AMT::ChannelRenameResult>
  RenameChannel(const AMT::ChannelRenameArgs &rename_args,
                const ControlComponent &control) override {
    (void)control;
    ECMData<AMT::ChannelRenameResult> out = {};

    const std::string src_name = AMStr::Strip(rename_args.src_channel_name);
    const std::string dst_name = AMStr::Strip(rename_args.dst_channel_name);
    out.data.src_channel_name = src_name;
    out.data.dst_channel_name = dst_name;
    if (src_name.empty() || dst_name.empty()) {
      out.rcm = Err(EC::InvalidArg, "terminal.rename", "channel_name",
                    "src_channel_name and dst_channel_name must be non-empty");
      return out;
    }
    if (!AMDomain::host::HostService::ValidateNickname(src_name) ||
        !AMDomain::host::HostService::ValidateNickname(dst_name)) {
      out.rcm =
          Err(EC::InvalidArg, "terminal.rename", src_name + "->" + dst_name,
              "Channel names must be valid nicknames");
      return out;
    }
    if (src_name == dst_name) {
      out.rcm = OK;
      out.data.renamed = true;
      return out;
    }

    auto channels = channels_.lock();
    auto src_it = channels->find(src_name);
    if (src_it == channels->end() || !src_it->second) {
      out.rcm = Err(EC::ClientNotFound, "terminal.rename", src_name,
                    "Source channel does not exist");
      return out;
    }
    if (channels->contains(dst_name)) {
      out.rcm = Err(EC::TargetAlreadyExists, "terminal.rename", dst_name,
                    "Target channel already exists");
      return out;
    }

    out.rcm = src_it->second->Rename(dst_name);
    if (!(out.rcm)) {
      return out;
    }

    (*channels)[dst_name] = src_it->second;
    channels->erase(src_it);
    auto guard = attr_cache_.lock();
    auto current_channel = guard->current_channel;
    if (current_channel.has_value() && *current_channel == src_name) {
      guard->current_channel = dst_name;
    }
    out.data.renamed = true;
    out.rcm = OK;
    return out;
  }

  ECMData<AMT::ChannelListResult>
  ListChannels(const AMT::ChannelListArgs &list_args,
               const ControlComponent &control) override {
    (void)list_args;
    (void)control;
    ECMData<AMT::ChannelListResult> out = {};
    auto channels = channels_.lock();
    for (const auto &entry : *channels) {
      if (entry.second) {
        out.data.channels[entry.first] = entry.second;
      }
    }
    auto guard = attr_cache_.lock();
    auto current_channel = guard->current_channel;
    if (current_channel.has_value()) {
      out.data.current_channel = *current_channel;
    }
    out.rcm = OK;
    return out;
  }

  ECMData<AMT::CheckSessionResult>
  CheckSession(const AMT::CheckSessionArgs &check_args,
               const ControlComponent &control) override {
    (void)check_args;
    ECMData<AMT::CheckSessionResult> out = {};

    out.data.is_supported = true;
    out.data.can_resize = true;
    auto guard = attr_cache_.lock();
    auto current_channel = guard->current_channel;
    if (current_channel.has_value()) {
      out.data.current_channel = *current_channel;
    }

    const auto binding = GetBindingSnapshot_();
    const auto request = GetRequestSnapshot_();
    if (!binding.sftp_core) {
      out.rcm = Err(EC::NoSession, "terminal.check_session", request.hostname,
                    "SFTP IO core is unavailable");
      out.data.status = AMDomain::client::ClientStatus::NotInitialized;
      out.data.is_open = false;
      return out;
    }

    auto check_result =
        binding.sftp_core->Check(AMDomain::filesystem::CheckArgs{}, control);
    out.rcm = check_result.rcm;
    out.data.status = check_result.data.status;

    if (current_channel.has_value()) {
      auto channels = channels_.lock();
      auto it = channels->find(*current_channel);
      out.data.is_open = (it != channels->end() && it->second &&
                          !it->second->GetState().closed);
    } else {
      out.data.is_open = false;
    }
    return out;
  }

  [[nodiscard]] AMDomain::filesystem::CheckResult
  GetSessionState() const override {
    const auto binding = GetBindingSnapshot_();
    if (!binding.owner_client) {
      return {AMDomain::client::ClientStatus::NotInitialized};
    }
    return binding.owner_client->ConfigPort().GetState().data;
  }
};

} // namespace AMInfra::terminal::SFTP
