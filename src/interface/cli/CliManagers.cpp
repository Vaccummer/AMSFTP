#include "interface/cli/CLIArg.hpp"
#include "Isocline/isocline.h"
#include <csignal>

namespace AMInterface::cli {

void CLIServices::SetPromptProfileManager(
    std::unique_ptr<AMApplication::prompt::PromptProfileManager> manager)
    const {
  prompt_profile_manager_.SetInstance(std::move(manager));
}

void CLIServices::SetPromptHistoryManager(
    std::unique_ptr<AMApplication::prompt::PromptHistoryManager> manager)
    const {
  prompt_history_manager_.SetInstance(std::move(manager));
}

AMApplication::prompt::PromptProfileManager &
CLIServices::PromptProfileManager() const {
  return prompt_profile_manager_.Get();
}

AMApplication::prompt::PromptHistoryManager &
CLIServices::PromptHistoryManager() const {
  return prompt_history_manager_.Get();
}

ECM CLIServices::Init(amf task_control_token) {
  if (!task_control_token) {
    return Err(EC::InvalidArg, "", "", "CLIServices::Init requires task control token");
  }

  if (!signal_monitor.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "signal monitor is not initialized");
  }
  if (!host_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "host service is not initialized");
  }
  if (!client_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "client service is not initialized");
  }
  if (!client_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "client interface service is not initialized");
  }
  if (!filesystem_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "filesystem interface service is not initialized");
  }
  if (!var_interface_service.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "var interface service is not initialized");
  }
  if (!completer_config_manager.IsReady()) {
    return Err(EC::InvalidHandle, "", "", "completer config manager is not initialized");
  }

  client_service->BindHostConfigManager(host_service.operator->());

  ECM rcm = signal_monitor->Init();
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
  (void)signal_monitor->RegisterHook("session-control", hook);
  return OK;
}

} // namespace AMInterface::cli
