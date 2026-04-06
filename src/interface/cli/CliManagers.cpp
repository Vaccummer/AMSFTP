#include "interface/cli/CLIServices.hpp"
#include "Isocline/isocline.h"
#include <csignal>

namespace AMInterface::cli {

ECM CLIServices::Init(amf task_control_token) {
  if (!task_control_token) {
    return Err(EC::InvalidArg, "", "", "CLIServices::Init requires task control token");
  }

  if (!domain.signal_monitor.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "signal monitor is not initialized");
  }
  if (!application.host_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "host service is not initialized");
  }
  if (!application.client_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "client service is not initialized");
  }
  if (!interfaces.client_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "client interface service is not initialized");
  }
  if (!interfaces.config_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "config interface service is not initialized");
  }
  if (!interfaces.filesystem_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "filesystem interface service is not initialized");
  }
  if (!interfaces.var_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "var interface service is not initialized");
  }
  if (!application.completer_config_manager.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "completer config manager is not initialized");
  }

  application.client_service->BindHostConfigManager(application.host_service.operator->());

  ECM rcm = domain.signal_monitor->Init();
  if (!(rcm)) {
    return rcm;
  }

  AMDomain::signal::SignalHook hook = {};
  hook.callback = [token = task_control_token](int signal_num) {
    if (signal_num != SIGINT) {
      return;
    }
    if (ic_is_editline_active()) {
      (void)ic_async_stop();
      return;
    }
    if (token) {
      token->RequestInterrupt();
    }
  };
  hook.priority = 500;
  hook.consume = false;
  (void)domain.signal_monitor->RegisterHook("session-control", hook);
  return OK;
}

} // namespace AMInterface::cli

