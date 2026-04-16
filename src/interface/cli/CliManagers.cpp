#include "interface/cli/CLIServices.hpp"
#include "Isocline/isocline.h"
#include <csignal>

namespace AMInterface::cli {

ECM CLIServices::Init(amf task_control_token) {
  if (!task_control_token) {
    return Err(EC::InvalidArg, "", "<context>", "CLIServices::Init requires task control token");
  }

  if (!domain.signal_monitor.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "signal monitor is not initialized");
  }
  if (!application.host_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "host service is not initialized");
  }
  if (!application.client_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "client service is not initialized");
  }
  if (!application.terminal_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "terminal service is not initialized");
  }
  if (!interfaces.client_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "client interface service is not initialized");
  }
  if (!interfaces.config_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "config interface service is not initialized");
  }
  if (!interfaces.filesystem_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "filesystem interface service is not initialized");
  }
  if (!interfaces.terminal_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "terminal interface service is not initialized");
  }
  if (!interfaces.var_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "var interface service is not initialized");
  }
  if (!application.completer_config_manager.IsReady()) {
    return Err(EC::InvalidHandle, "", "<context>", "completer config manager is not initialized");
  }

  application.client_service->BindHostConfigManager(application.host_service.operator->());

  ECM rcm = domain.signal_monitor->Init();
  if (!(rcm)) {
    return rcm;
  }

  AMDomain::signal::SignalHook hook = {};
  hook.callback = [token = task_control_token](int signal_num) {
    if (signal_num != SIGINT && signal_num != SIGTERM) {
      return;
    }
    if (token) {
      token->RequestInterrupt();
    }
    if (signal_num == SIGINT && ic_is_editline_active()) {
      (void)ic_async_stop();
    }
  };
  hook.priority = 500;
  hook.consume = false;
  (void)domain.signal_monitor->RegisterHook("session-control", hook);
  return OK;
}

} // namespace AMInterface::cli

