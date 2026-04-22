#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/terminal/ChannelPort.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/core/DataClass.hpp"

#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace AMApplication::log {
class LoggerAppService;
}

namespace AMApplication::terminal {
using ClientHandle = AMDomain::client::ClientHandle;
using TerminalHandle = AMDomain::terminal::TerminalHandle;
using ChannelPortHandle = AMDomain::terminal::ChannelPortHandle;

class TermAppService final : public NonCopyableNonMovable {
public:
  explicit TermAppService(
      AMDomain::terminal::BufferExceedCallback buffer_exceed_callback = {},
      AMApplication::log::LoggerAppService *logger = nullptr)
      : buffer_exceed_callback_(std::move(buffer_exceed_callback)),
        logger_(logger) {}
  ~TermAppService() override;

  [[nodiscard]] ECMData<TerminalHandle>
  CreateTerminal(const ClientHandle &client, bool detach = false);

  [[nodiscard]] ECMData<TerminalHandle>
  AddTerminal(const ClientHandle &client, const TerminalHandle &terminal,
              bool force = false);

  [[nodiscard]] ECMData<TerminalHandle>
  EnsureTerminal(const ClientHandle &client);

  [[nodiscard]] ECMData<TerminalHandle>
  GetTerminalByNickname(const std::string &nickname,
                        bool case_sensitive = true) const;

  [[nodiscard]] std::vector<std::string> ListTerminalNames() const;

  ECM RemoveTerminal(const std::string &nickname,
                     const ControlComponent &control = {});

  [[nodiscard]] ECMData<ChannelPortHandle>
  EnsureChannelPort(const std::string &terminal_nickname,
                    const std::string &channel_name,
                    const ControlComponent &control = {});

  ECM DropChannelPort(const std::string &terminal_nickname,
                      const std::string &channel_name,
                      const ControlComponent &control = {});

  ECM DropTerminalChannelPorts(const std::string &terminal_nickname,
                               const ControlComponent &control = {});

  void TraceRuntimeEvent(const ECM &rcm, const std::string &target,
                         const std::string &action,
                         const std::string &message = {}) const;

private:
  [[nodiscard]] static std::string BuildTerminalKey_(const ClientHandle &client,
                                                     const char *action);

  [[nodiscard]] static std::string
  NormalizeTerminalKey_(const std::string &nickname);

  [[nodiscard]] ECMData<TerminalHandle>
  QueryTerminal_(const std::string &terminal_key) const;

  void DropAllTerminalChannelPortsByKey_(const std::string &terminal_key,
                                         const ControlComponent &control);

private:
  mutable std::mutex mutex_ = {};
  std::map<std::string, TerminalHandle> terminals_ = {};
  AMDomain::terminal::BufferExceedCallback buffer_exceed_callback_ = {};
  AMApplication::log::LoggerAppService *logger_ = nullptr;
};

} // namespace AMApplication::terminal
