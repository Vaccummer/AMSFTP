#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/terminal/TermAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/prompt/Prompt.hpp"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::style {
class AMStyleService;
}

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

class TerminalInterfaceService final : public NonCopyableNonMovable {
public:
  TerminalInterfaceService(
      AMApplication::client::ClientAppService &client_service,
      AMApplication::terminal::TermAppService &terminal_service,
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMInterface::style::AMStyleService &style_service,
      AMInterface::prompt::AMPromptIOManager &prompt_io_manager);
  ~TerminalInterfaceService() override;

  void SetDefaultControlToken(const AMDomain::client::amf &token);
  [[nodiscard]] AMDomain::client::amf GetDefaultControlToken() const;

  ECM ShellRun(const TerminalShellRunArg &arg,
               const std::optional<AMDomain::client::ClientControlComponent>
                   &control_opt = std::nullopt) const;

  ECM LaunchTerminal(
      const TerminalLaunchArg &arg = {},
      const std::optional<AMDomain::client::ClientControlComponent>
          &control_opt = std::nullopt) const;

  ECM AddTerminal(const TerminalAddArg &arg,
                  const std::optional<AMDomain::client::ClientControlComponent>
                      &control_opt = std::nullopt) const;

  ECM ListTerminals(
      const TerminalListArg &arg = {},
      const std::optional<AMDomain::client::ClientControlComponent>
          &control_opt = std::nullopt) const;

  ECM RemoveTerminal(
      const TerminalRemoveArg &arg,
      const std::optional<AMDomain::client::ClientControlComponent>
          &control_opt = std::nullopt) const;

  ECM AddChannel(const ChannelAddArg &arg,
                 const std::optional<AMDomain::client::ClientControlComponent>
                     &control_opt = std::nullopt) const;

  ECM ListChannels(const ChannelListArg &arg,
                   const std::optional<AMDomain::client::ClientControlComponent>
                       &control_opt = std::nullopt) const;

  ECM RemoveChannel(
      const ChannelRemoveArg &arg,
      const std::optional<AMDomain::client::ClientControlComponent>
          &control_opt = std::nullopt) const;

  ECM RenameChannel(
      const ChannelRenameArg &arg,
      const std::optional<AMDomain::client::ClientControlComponent>
          &control_opt = std::nullopt) const;

private:
  struct SharedKeyboardMonitor_;

  AMApplication::client::ClientAppService &client_service_;
  AMApplication::terminal::TermAppService &terminal_service_;
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::style::AMStyleService &style_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
  AMDomain::client::amf default_interrupt_flag_ = nullptr;
  mutable std::shared_ptr<SharedKeyboardMonitor_> shared_keyboard_monitor_ =
      nullptr;
};

} // namespace AMInterface::terminal
