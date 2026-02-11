#include "AMManager/Client.hpp"

namespace AMClientManage {

Operator::Operator(AMConfigManager &config, Manager &manager)
    : Reader(config), manager_(manager) {}

void Operator::SetPasswordCallback(AuthCallback cb) {
  manager_.password_cb_ =
      cb ? std::move(cb) : manager_.BuiltinPasswordCallback_();
}

void Operator::SetDisconnectCallback(DisconnectCallback cb) {
  manager_.disconnect_cb_ =
      cb ? std::move(cb) : manager_.BuiltinDisconnectCallback_();
}

ClientMaintainer &Operator::Clients() { return *clients_; }

std::vector<std::string> Operator::GetClientNames() {
  return clients_ ? clients_->get_nicknames() : std::vector<std::string>{};
}

std::vector<std::shared_ptr<BaseClient>> Operator::GetClients() {
  return clients_ ? clients_->get_clients()
                  : std::vector<std::shared_ptr<BaseClient>>{};
}

std::shared_ptr<AMLocalClient> Operator::LocalClient() const {
  return manager_.local_client_;
}

std::shared_ptr<BaseClient> Operator::LocalClientBase() const {
  return local_client_base_;
}

std::shared_ptr<BaseClient> Operator::CurrentClient() const {
  return current_client_;
}

void Operator::SetCurrentClient(const std::shared_ptr<BaseClient> &client) {
  current_client_ = client;
}

void Operator::ConfigureState(
    const std::shared_ptr<ClientMaintainer> &clients,
    const std::shared_ptr<BaseClient> &local_client_base, ssize_t trace_num) {
  clients_ = clients;
  local_client_base_ = local_client_base;
  current_client_ = local_client_base;
  trace_num_ = trace_num;
}

void Operator::ResetSpinnerState() {
  spinner_stop_requested_.store(false, std::memory_order_relaxed);
  spinner_line_len_.store(0, std::memory_order_relaxed);
}

void Operator::SetSpinnerLineLen(size_t line_len) {
  spinner_line_len_.store(line_len, std::memory_order_relaxed);
}

bool Operator::SpinnerStopRequested() const {
  return spinner_stop_requested_.load(std::memory_order_relaxed);
}

void Operator::RequestSpinnerStop() {
  if (spinner_stop_requested_.exchange(true, std::memory_order_relaxed)) {
    return;
  }
  const size_t line_len = spinner_line_len_.load(std::memory_order_relaxed);
  if (line_len > 0) {
    std::cout << '\r' << std::string(line_len, ' ') << '\r' << std::flush;
  }
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::AddClient(const std::string &nickname,
                    std::shared_ptr<ClientMaintainer> maintainer, bool force,
                    bool quiet, TraceCallback trace_cb, amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : Manager::global_interrupt_flag;
  Manager::ClientMaintainerRef &target = maintainer ? *maintainer : *clients_;

  if (!trace_cb) {
    trace_cb = manager_.log_manager_.TraceCallbackFunc();
  }
  if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
    return {ECM{EC::Success, ""}, target.GetHost("")};
  }

  auto existing = target.GetHost(nickname);
  if (existing) {
    if (force) {
      manager_.ApplyKnownHostCallback_(existing);
    }
    ECM rcm = existing->Connect(force, flag);
    if (rcm.first != EC::Success) {
      return {rcm, existing};
    }
    auto existing_cfg = manager_.GetClientConfig(nickname);
    if (existing_cfg.first.first == EC::Success) {
      manager_.ApplyLoginDir(nickname, existing, existing_cfg.second.login_dir,
                             flag);
    } else {
      manager_.InitClientWorkdir(existing);
    }
    return {ECM{EC::Success, ""}, existing};
  }

  auto client_config = manager_.GetClientConfig(nickname);
  if (client_config.first.first != EC::Success) {
    return {client_config.first, nullptr};
  }

  auto keys_result = manager_.config_.PrivateKeys(false);
  if (keys_result.first.first != EC::Success) {
    return {keys_result.first, nullptr};
  }

  std::atomic<bool> spinner_running(false);
  ResetSpinnerState();
  auto auth_cb = manager_.BuildAuthCallback_(manager_.password_cb_, quiet,
                                             &spinner_running);
  auto base_client = CreateClient(
      client_config.second.request, client_config.second.protocol, trace_num_,
      std::move(trace_cb), client_config.second.buffer_size, keys_result.second,
      std::move(auth_cb));
  if (!base_client) {
    return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
  }
  manager_.ApplyKnownHostCallback_(base_client);

  std::thread spinner_thread;
  std::string spinner_line;
  size_t spinner_line_len = 0;
  if (!quiet) {
    const std::string protocol_label =
        std::string(AM_ENUM_NAME(base_client->GetProtocol()));
    spinner_line = AMStr::amfmt("Connecting to {} Server   [{}]",
                                protocol_label, nickname);
    spinner_line_len = spinner_line.size() + 3;
    SetSpinnerLineLen(spinner_line_len);
    spinner_running.store(true, std::memory_order_relaxed);
    spinner_thread = std::thread([&spinner_running, spinner_line, this]() {
      const std::vector<std::string> frames = {"▖", "▘", "▝", "▗"};
      size_t idx = 0;
      while (spinner_running.load(std::memory_order_relaxed) &&
             !SpinnerStopRequested()) {
        std::string indicator = frames[idx % frames.size()];
        std::cout << '\r' << indicator << "  " << spinner_line << std::flush;
        idx++;
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
      }
    });
  }

  ECM rcm = base_client->Connect(force, flag);
  spinner_running.store(false, std::memory_order_relaxed);
  if (spinner_thread.joinable()) {
    spinner_thread.join();
    if (spinner_line_len > 0) {
      std::cout << '\r' << std::string(spinner_line_len, ' ') << '\r'
                << std::flush;
    }
  }
  if (rcm.first != EC::Success) {
    return {rcm, base_client};
  }
  manager_.ApplyLoginDir(nickname, base_client, client_config.second.login_dir,
                         flag);
  target.add_client(nickname, base_client, true);
  return {ECM{EC::Success, ""}, base_client};
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::AddClient(const std::string &nickname, bool force, bool quiet,
                    TraceCallback trace_cb, amf interrupt_flag,
                    bool register_to_manager) {
  if (register_to_manager) {
    return AddClient(nickname, nullptr, force, quiet, std::move(trace_cb),
                     interrupt_flag);
  }

  amf flag = interrupt_flag ? interrupt_flag : Manager::global_interrupt_flag;
  if (nickname.empty() || nickname == "local") {
    return {ECM{EC::Success, ""}, local_client_base_};
  }

  if (!trace_cb) {
    trace_cb = manager_.log_manager_.TraceCallbackFunc();
  }

  auto client_config = manager_.GetClientConfig(nickname);
  if (client_config.first.first != EC::Success) {
    return {client_config.first, nullptr};
  }

  auto keys_result = manager_.config_.PrivateKeys(false);
  if (keys_result.first.first != EC::Success) {
    return {keys_result.first, nullptr};
  }

  std::atomic<bool> spinner_running(false);
  ResetSpinnerState();
  auto auth_cb = manager_.BuildAuthCallback_(manager_.password_cb_, quiet,
                                             &spinner_running);
  auto base_client = CreateClient(
      client_config.second.request, client_config.second.protocol, trace_num_,
      std::move(trace_cb), client_config.second.buffer_size, keys_result.second,
      std::move(auth_cb));
  if (!base_client) {
    return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
  }

  manager_.ApplyKnownHostCallback_(base_client);

  std::thread spinner_thread;
  std::string spinner_line;
  size_t spinner_line_len = 0;
  if (!quiet) {
    const std::string protocol_label =
        std::string(AM_ENUM_NAME(base_client->GetProtocol()));
    spinner_line = AMStr::amfmt("Connecting to {} Server   [{}]",
                                protocol_label, nickname);
    spinner_line_len = spinner_line.size() + 3;
    SetSpinnerLineLen(spinner_line_len);
    spinner_running.store(true, std::memory_order_relaxed);
    spinner_thread = std::thread([&spinner_running, spinner_line, this]() {
      const std::vector<std::string> frames = {"▖", "▘", "▝", "▗"};
      size_t idx = 0;
      while (spinner_running.load(std::memory_order_relaxed) &&
             !SpinnerStopRequested()) {
        std::string indicator = frames[idx % frames.size()];
        std::cout << '\r' << indicator << "  " << spinner_line << std::flush;
        idx++;
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
      }
    });
  }

  ECM rcm = base_client->Connect(force, flag);
  spinner_running.store(false, std::memory_order_relaxed);
  if (spinner_thread.joinable()) {
    spinner_thread.join();
    if (spinner_line_len > 0) {
      std::cout << '\r' << std::string(spinner_line_len, ' ') << '\r'
                << std::flush;
    }
  }
  if (rcm.first != EC::Success) {
    return {rcm, base_client};
  }
  manager_.ApplyLoginDir(nickname, base_client, client_config.second.login_dir,
                         flag);
  return {ECM{EC::Success, ""}, base_client};
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::Connect(const std::string &nickname, const std::string &hostname,
                  const std::string &username, ClientProtocol protocol,
                  int64_t port, const std::string &password,
                  const std::string &keyfile,
                  std::shared_ptr<ClientMaintainer> maintainer, bool quiet,
                  TraceCallback trace_cb, amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : Manager::global_interrupt_flag;
  Manager::ClientMaintainerRef &target = maintainer ? *maintainer : *clients_;

  if (protocol == ClientProtocol::LOCAL ||
      protocol == ClientProtocol::Unknown) {
    return {ECM{EC::InvalidArg, "Unsupported protocol for remote connect"},
            nullptr};
  }

  AMPromptManager &prompt = AMPromptManager::Instance();
  std::string resolved_nickname = nickname;
  std::string error;
  bool canceled = false;
  while (true) {
    error.clear();
    if (resolved_nickname == "local") {
      error = "Nickname cannot be 'local'.";
    }
    if (error.empty() &&
        manager_.config_.ValidateNickname(resolved_nickname, &error)) {
      break;
    }
    if (!error.empty()) {
      prompt.Print(AMStr::amfmt("Invalid nickname: {}", error));
    }
    const bool ok =
        prompt.PromptLine("Enter a legal nickname: ", &resolved_nickname, "",
                          false, &canceled, false);
    if (!ok && canceled) {
      return {ECM{EC::ConfigCanceled, "Nickname input canceled"}, nullptr};
    }
    if (!ok) {
      continue;
    }
  }

  std::vector<std::string> keys;
  if (keyfile.empty()) {
    auto keys_result = manager_.config_.PrivateKeys(false);
    if (keys_result.first.first != EC::Success) {
      return {keys_result.first, nullptr};
    }
    keys = std::move(keys_result.second);
  } else {
    keys.push_back(keyfile);
  }

  const std::string password_enc = AMAuth::EncryptPassword(password);
  ConRequst request(resolved_nickname, hostname, username,
                    static_cast<int>(port), password_enc, keyfile, false, "");
  if (!trace_cb) {
    trace_cb = manager_.log_manager_.TraceCallbackFunc();
  }
  auto auth_cb =
      manager_.BuildAuthCallback_(manager_.password_cb_, quiet, nullptr);
  auto base_client =
      CreateClient(request, protocol, trace_num_, std::move(trace_cb), -1,
                   std::move(keys), std::move(auth_cb));
  if (!base_client) {
    return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
  }

  manager_.ApplyKnownHostCallback_(base_client);

  ECM rcm = base_client->Connect(false, flag);
  if (rcm.first != EC::Success) {
    return {rcm, base_client};
  }

  ECM save_rcm = manager_.config_.SetHostField(resolved_nickname, "hostname",
                                               hostname, false);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }
  save_rcm = manager_.config_.SetHostField(resolved_nickname, "username",
                                           username, false);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }
  save_rcm =
      manager_.config_.SetHostField(resolved_nickname, "port", port, false);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }
  save_rcm = manager_.config_.SetHostField(resolved_nickname, "keyfile",
                                           keyfile, false);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }
  save_rcm =
      manager_.config_.SetHostField(resolved_nickname, "protocol",
                                    std::string(AM_ENUM_NAME(protocol)), false);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }
  save_rcm = manager_.config_.SetHostField(resolved_nickname, "buffer_size",
                                           int64_t(-1), false);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }
  save_rcm = manager_.config_.SetClientPasswordEncrypted(resolved_nickname,
                                                         password_enc, false);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }
  save_rcm = manager_.config_.SetHostField(resolved_nickname, "login_dir",
                                           std::string(""), true);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }

  manager_.ApplyLoginDir(resolved_nickname, base_client, "", flag);
  target.add_client(resolved_nickname, base_client, true);
  return {ECM{EC::Success, ""}, base_client};
}

ECM Operator::RemoveClient(const std::string &nickname,
                           std::shared_ptr<ClientMaintainer> maintainer) {
  if (nickname.empty() || nickname == "local") {
    return {EC::InvalidArg, "Local client cannot be removed"};
  }
  Manager::ClientMaintainerRef &target = maintainer ? *maintainer : *clients_;
  auto existing = target.GetHost(nickname);
  if (!existing) {
    return {EC::ClientNotFound, "Client not found"};
  }
  target.remove_client(nickname);
  return {EC::Success, ""};
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::CheckClient(const std::string &nickname,
                      const std::shared_ptr<ClientMaintainer> &maintainer,
                      bool update, amf interrupt_flag, int timeout_ms,
                      int64_t start_time) {
  amf flag = interrupt_flag ? interrupt_flag : Manager::global_interrupt_flag;
  Manager::ClientMaintainerRef &target = maintainer ? *maintainer : *clients_;
  return target.test_client(nickname, update, flag, timeout_ms, start_time);
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::EnsureClient(const std::string &nickname, amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : Manager::global_interrupt_flag;
  if (nickname.empty() || nickname == "local") {
    return {ECM{EC::Success, ""}, local_client_base_};
  }

  auto existing = clients_ ? clients_->GetHost(nickname) : nullptr;
  if (!existing) {
    std::cout << "Connecting to " << nickname << "..." << std::endl;
    return AddClient(nickname, nullptr, false, true, {}, flag);
  }

  ECM rcm = existing->Connect(false, flag);
  if (rcm.first != EC::Success) {
    return {rcm, existing};
  }
  return {ECM{EC::Success, ""}, existing};
}

} // namespace AMClientManage
