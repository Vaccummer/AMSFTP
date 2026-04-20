#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/terminal/TermAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/adapters/terminal/TerminalInterfaceDTO.hpp"
#include "interface/prompt/Prompt.hpp"
#include <memory>
#include <optional>

namespace AMInterface::style {
class AMStyleService;
}

namespace AMInterface::terminal {

class TerminalInterfaceService final : public NonCopyableNonMovable {
public:
  TerminalInterfaceService(
      AMApplication::client::ClientAppService &client_service,
      AMApplication::terminal::TermAppService &terminal_service,
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMInterface::style::AMStyleService &style_service,
      AMInterface::prompt::PromptIOManager &prompt_io_manager);
  ~TerminalInterfaceService() override;

  void SetDefaultControlToken(const AMDomain::client::amf &token);
  [[nodiscard]] AMDomain::client::amf GetDefaultControlToken() const;

  ECM ShellRun(
      const TerminalShellRunArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  ECM LaunchTerminal(
      const TerminalLaunchArg &arg = {},
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  ECM AddTerminal(
      const TerminalAddArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  ECM ListTerminals(
      const TerminalListArg &arg = {},
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  ECM RemoveTerminal(
      const TerminalRemoveArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  ECM AddChannel(
      const ChannelAddArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  ECM ListChannels(
      const ChannelListArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  ECM RemoveChannel(
      const ChannelRemoveArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  ECM RenameChannel(
      const ChannelRenameArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

private:
  struct SharedKeyboardMonitor_;

  AMApplication::client::ClientAppService &client_service_;
  AMApplication::terminal::TermAppService &terminal_service_;
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::style::AMStyleService &style_service_;
  AMInterface::prompt::PromptIOManager &prompt_io_manager_;
  AMDomain::client::amf default_interrupt_flag_ = nullptr;
  mutable std::shared_ptr<SharedKeyboardMonitor_> shared_keyboard_monitor_ =
      nullptr;
};

} // namespace AMInterface::terminal
