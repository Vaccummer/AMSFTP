#include "AMManager/Client.hpp"

namespace AMClientManage {

Manager &Manager::Instance(AMConfigManager &cfg) {
  static Manager instance(cfg);
  return instance;
}

Manager::Manager(AMConfigManager &cfg)
    : PathOps(cfg, *this), log_manager_(AMLogManager::Instance(cfg)),
      local_client_(nullptr) {
  password_cb_ = BuiltinPasswordCallback_();
  disconnect_cb_ = BuiltinDisconnectCallback_();

  const ssize_t trace_num = cfg.ResolveTraceNum();
  local_client_ = CreateLocalClient_(cfg, log_manager_);
  auto clients = std::make_shared<ClientMaintainer>(
      cfg.ResolveHeartbeatInterval(),
      [this](const auto &client, const ECM &ecm) { OnDisconnect(client, ecm); },
      local_client_);
  ConfigureState(clients, clients->GetHost(""), trace_num);

  auto local_cfg = GetClientConfig("local");
  if (local_cfg.first.first == EC::Success) {
    ApplyLoginDir("local", LocalClientBase(), local_cfg.second.login_dir,
                  global_interrupt_flag);
  } else {
    InitClientWorkdir(LocalClientBase());
  }
}

AuthCallback Manager::BuildAuthCallback_(const AuthCallback &auth_cb,
                                         bool quiet,
                                         std::atomic<bool> *spinner_running) {
  if (!auth_cb) {
    return {};
  }
  return [this, auth_cb, quiet, spinner_running](const AuthCBInfo &info) {
    RequestSpinnerStop_();
    if (spinner_running) {
      spinner_running->store(false, std::memory_order_relaxed);
    }
    int prev_level = -99999;
    if (quiet) {
      prev_level = log_manager_.TraceLevel();
      log_manager_.TraceLevel(-1);
    }
    std::optional<std::string> result;
    if (auth_cb) {
      result = auth_cb(info);
    }
    if (quiet) {
      log_manager_.TraceLevel(prev_level);
    }
    return result;
  };
}

void Manager::ApplyKnownHostCallback_(
    const std::shared_ptr<BaseClient> &client) {
  if (!client) {
    return;
  }
  if (client->GetProtocol() != ClientProtocol::SFTP) {
    return;
  }
  auto sftp_client = std::dynamic_pointer_cast<AMSFTPClient>(client);
  if (!sftp_client) {
    return;
  }
  auto known_cb = BuildKnownHostCallback();
  sftp_client->SetKnownHostCallback(
      [this, known_cb](AMConfigManager::KnownHostEntry entry) -> ECM {
        RequestSpinnerStop_();
        if (!known_cb) {
          return {EC::Success, ""};
        }
        return known_cb(std::move(entry));
      });
}

void Manager::ResetSpinnerStop_() { ResetSpinnerState(); }
void Manager::RequestSpinnerStop_() { RequestSpinnerStop(); }

std::shared_ptr<AMLocalClient>
Manager::CreateLocalClient_(AMConfigManager &cfg, AMLogManager &log_manager) {
  auto trace_cb = log_manager.TraceCallbackFunc();

  Reader info_reader(cfg);
  auto cfg_result = info_reader.GetClientConfig("local");
  if (cfg_result.first.first != EC::Success) {
    (void)cfg.SetHostField("local", "hostname", std::string("localhost"),
                           false);
    (void)cfg.SetHostField("local", "protocol", std::string("local"), false);
    (void)cfg.SetHostField("local", "port", int64_t(22), false);
    (void)cfg.SetHostField("local", "buffer_size", int64_t(-1), false);
    (void)cfg.SetHostField("local", "login_dir", std::string(""), true);
    cfg_result = info_reader.GetClientConfig("local");
  }

  ConRequst request = cfg_result.second.request;
  auto client =
      std::make_shared<AMLocalClient>(request, 10, std::move(trace_cb));

  if (!request.trash_dir.empty()) {
    auto result = client->TrashDir(request.trash_dir);
    if (std::holds_alternative<ECM>(result)) {
      const auto &ecm = std::get<ECM>(result);
      if (ecm.first != EC::Success) {
        prompt_.ErrorFormat(ecm);
      }
    }
  }

  if (cfg_result.second.buffer_size > 0) {
    client->TransferRingBufferSize(cfg_result.second.buffer_size);
  }

  return client;
}

void Manager::OnDisconnect(const std::shared_ptr<BaseClient> &client,
                           const ECM &ecm) {
  if (disconnect_cb_) {
    CallCallbackSafe(disconnect_cb_, client, ecm);
  }
}

std::optional<std::string>
Manager::DefaultPasswordCallback(const AuthCBInfo &info) {
  std::lock_guard<std::mutex> lock(auth_io_mtx_);

  const std::string client_name =
      info.request.nickname.empty() ? "unknown" : info.request.nickname;

  if (info.NeedPassword) {
    const std::string prompt =
        AMStr::amfmt("❔ [{}] Require Password: ", client_name);
    std::string password;
    if (!prompt_.SecurePrompt(prompt, &password)) {
      return std::string();
    }
    return password;
  }

  if (!info.iscorrect) {
    if (info.password_n.empty()) {
      return std::nullopt;
    }
    prompt_.Print(AMStr::amfmt("❌ [{}] Wrong Password!", client_name));
    return std::nullopt;
  }

  prompt_.Print(
      AMStr::amfmt("✅ [{}] Password authorization successful!", client_name));
  (void)config_.SetClientPasswordEncrypted(client_name, info.password_n, true);
  return std::nullopt;
}

void Manager::DefaultDisconnectCallback(
    const std::shared_ptr<BaseClient> &client, const ECM &ecm) {
  if (!client) {
    return;
  }
  if (ecm.first == EC::Success) {
    return;
  }
  prompt_.ErrorFormat(
      ECM{ecm.first,
          AMStr::amfmt("Client disconnected [{}]: {}", client->GetNickname(),
                       ecm.second.empty() ? std::string(AM_ENUM_NAME(ecm.first))
                                          : ecm.second)});
}

Manager::PasswordCallback Manager::BuiltinPasswordCallback_() {
  return
      [this](const AuthCBInfo &info) { return DefaultPasswordCallback(info); };
}

Manager::DisconnectCallback Manager::BuiltinDisconnectCallback_() {
  return [this](const std::shared_ptr<BaseClient> &client, const ECM &ecm) {
    DefaultDisconnectCallback(client, ecm);
  };
}

} // namespace AMClientManage
