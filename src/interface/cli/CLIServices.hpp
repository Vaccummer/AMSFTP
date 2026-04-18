#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/completion/CompleterAppService.hpp"
#include "application/config/ConfigAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/log/LoggerAppService.hpp"
#include "application/terminal/TermAppService.hpp"
#include "application/transfer/TransferAppService.hpp"
#include "application/var/VarAppService.hpp"
#include "domain/signal/SignalMonitorPort.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/adapters/config/ConfigInterfaceService.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "interface/adapters/terminal/TerminalInterfaceService.hpp"
#include "interface/adapters/transfer/TransferInterfaceService.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/cli/InteractiveEventRegistry.hpp"
#include "interface/prompt/Prompt.hpp"
#include "interface/style/StyleManager.hpp"
#include <atomic>
#include <memory>
#include <stdexcept>
#include <string>

namespace AMInterface::cli {

template <typename T> class ServiceHolder final : public NonCopyableNonMovable {
public:
  ServiceHolder() = default;
  ~ServiceHolder() override = default;

  void SetInstance(std::unique_ptr<T> instance) const {
    instance_ = std::move(instance);
  }

  [[nodiscard]] bool IsReady() const { return instance_ != nullptr; }

  T &Get() const {
    if (!instance_) {
      throw std::runtime_error("Service is not initialized");
    }
    return *instance_;
  }

  T *operator->() const { return &Get(); }
  operator T &() const { return Get(); }

private:
  mutable std::unique_ptr<T> instance_ = nullptr;
};

/**
 * @brief Manager references for CLI dispatch.
 */
struct CLIServices : public NonCopyableNonMovable {
  struct DomainLayerServices {
    mutable ServiceHolder<AMDomain::signal::SignalMonitor> signal_monitor = {};
    mutable ServiceHolder<AMDomain::transfer::ITransferPoolPort> transfer_pool =
        {};
  };

  struct ApplicationLayerServices {
    mutable ServiceHolder<AMApplication::config::ConfigAppService>
        config_service = {};
    mutable ServiceHolder<AMApplication::host::HostAppService> host_service =
        {};
    mutable ServiceHolder<AMApplication::host::KnownHostsAppService>
        known_hosts_service = {};
    mutable ServiceHolder<AMApplication::var::VarAppService> var_service = {};
    mutable ServiceHolder<AMApplication::completion::CompleterConfigManager>
        completer_config_manager = {};
    mutable ServiceHolder<AMApplication::log::LoggerAppService> log_manager =
        {};
    mutable ServiceHolder<AMApplication::client::ClientAppService>
        client_service = {};
    mutable ServiceHolder<AMApplication::terminal::TermAppService>
        terminal_service = {};
    mutable ServiceHolder<AMApplication::filesystem::FilesystemAppService>
        filesystem_service = {};
    mutable ServiceHolder<AMApplication::transfer::TransferAppService>
        transfer_service = {};
    mutable ServiceHolder<AMApplication::prompt::PromptProfileManager>
        prompt_profile_manager = {};
    mutable ServiceHolder<AMApplication::prompt::PromptHistoryManager>
        prompt_history_manager = {};
  };

  struct InterfaceLayerServices {
    mutable ServiceHolder<AMInterface::style::AMStyleService> style_service =
        {};
    mutable ServiceHolder<AMInterface::config::ConfigInterfaceService>
        config_interface_service = {};
    mutable ServiceHolder<AMInterface::prompt::IsoclineProfileManager>
        prompt_profile_history_manager = {};
    mutable ServiceHolder<AMInterface::prompt::AMPromptIOManager>
        prompt_io_manager = {};
    mutable ServiceHolder<AMInterface::client::ClientInterfaceService>
        client_interface_service = {};
    mutable ServiceHolder<AMInterface::filesystem::FilesystemInterfaceSerivce>
        filesystem_interface_service = {};
    mutable ServiceHolder<AMInterface::terminal::TerminalInterfaceService>
        terminal_interface_service = {};
    mutable ServiceHolder<AMInterface::var::VarInterfaceService>
        var_interface_service = {};
    mutable ServiceHolder<AMInterface::transfer::TransferInterfaceService>
        transfer_service = {};
  };

  struct RuntimeLayerServices {
    mutable InteractiveEventRegistry interactive_event_registry = {};
  };

  CLIServices() = default;
  ECM Init(amf task_control_token);

  mutable DomainLayerServices domain = {};
  mutable ApplicationLayerServices application = {};
  mutable InterfaceLayerServices interfaces = {};
  mutable RuntimeLayerServices runtime = {};
};

/**
 * @brief Runtime context for invoking Args::Run.
 */
struct CliRunContext : NonCopyableNonMovable {
  CliRunContext() = default;
  ~CliRunContext() override = default;
  ECM rcm = OK;
  bool async = false;
  bool enforce_interactive = false;
  std::string command_name;
  mutable bool enter_interactive = false;
  mutable bool request_exit = false;
  mutable bool skip_loop_exit_callbacks = false;
  amf task_control_token = nullptr;
  std::shared_ptr<std::atomic<int>> exit_code =
      std::make_shared<std::atomic<int>>(0);
  std::shared_ptr<std::atomic<bool>> is_interactive =
      std::make_shared<std::atomic<bool>>(false);
};

} // namespace AMInterface::cli
