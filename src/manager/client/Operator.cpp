#include "AMClient/Base.hpp"
#include "AMManager/Client.hpp"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace AMClientManage {
namespace {
inline bool IsLocalNickname_(const std::string &nickname) {
  const std::string lowered = AMStr::lowercase(AMStr::Strip(nickname));
  return lowered.empty() || lowered == "local";
}

inline void InitClientWorkdir_(const std::shared_ptr<BaseClient> &client) {
  if (!client) {
    return;
  }
  std::string value;
  if (client->GetPublicValue("workdir", &value)) {
    return;
  }
  (void)client->SetPulbicValue(
      "workdir", AMPathStr::UnifyPathSep(client->GetHomeDir(), "/"), true);
}

inline void ApplyLoginDir_(AMHostManager &hostm, const std::string &nickname,
                           const std::shared_ptr<BaseClient> &client,
                           const std::string &login_dir, const amf &flag) {
  if (!client) {
    return;
  }

  std::string resolved = login_dir;
  bool need_persist = false;
  if (resolved.empty()) {
    resolved = client->GetHomeDir();
    need_persist = true;
  } else {
    bool exists = false;
    if (client->GetProtocol() == ClientProtocol::LOCAL) {
      std::error_code ec;
      exists = std::filesystem::exists(resolved, ec);
    } else {
      auto [rcm, info] = client->stat(resolved, false, flag);
      exists = rcm.first == EC::Success && info.type == PathType::DIR;
    }
    if (!exists) {
      resolved = client->GetHomeDir();
      need_persist = true;
    }
  }

  const std::string normalized = AMPathStr::UnifyPathSep(resolved, "/");
  (void)client->SetPulbicValue("workdir", normalized, true);
  (void)client->SetPulbicValue("login_dir", normalized, true);
  if (need_persist && !IsLocalNickname_(nickname)) {
    (void)hostm.SetHostValue(nickname, configkn::login_dir, resolved);
  }
}
} // namespace

void Operator::SetPasswordCallback(AuthCallback cb) {
  password_cb_ = cb ? std::move(cb) : BuiltinPasswordCallback_();
}

void Operator::SetDisconnectCallback(DisconnectCallback cb) {
  disconnect_cb_ = cb ? std::move(cb) : BuiltinDisconnectCallback_();
  if (clients_) {
    clients_->disconnect_cb = disconnect_cb_;
    clients_->is_disconnect_cb = static_cast<bool>(disconnect_cb_);
  }
}

ClientMaintainer &Operator::Clients() {
  if (!clients_) {
    clients_ =
        std::make_shared<ClientMaintainer>(60, disconnect_cb_, LocalClient());
  }
  return *clients_;
}

std::vector<std::string> Operator::GetClientNames() {
  return clients_ ? clients_->get_nicknames() : std::vector<std::string>{};
}

std::vector<std::shared_ptr<BaseClient>> Operator::GetClients() {
  return clients_ ? clients_->get_clients()
                  : std::vector<std::shared_ptr<BaseClient>>{};
}

/**
 * @brief Return one managed client by nickname.
 */
std::shared_ptr<BaseClient>
Operator::GetClient(const std::string &nickname) const {
  if (clients_) {
    return clients_->get_client(nickname);
  }
  if (IsLocalNickname_(nickname)) {
    return LocalClient();
  }
  return nullptr;
}

std::shared_ptr<BaseClient> Operator::LocalClient() const {
  return local_client_base_;
}

std::string Operator::CurrentNickname() const {
  return current_client_->GetNickname();
}

std::shared_ptr<BaseClient> Operator::CurrentClient() const {
  if (current_client_) {
    return current_client_;
  } else {
    return LocalClient();
  }
}

void Operator::SetCurrentClient(const std::shared_ptr<BaseClient> &client) {
  current_client_ = client;
}

// void Operator::ConfigureState(
//     const std::shared_ptr<ClientMaintainer> &clients,
//     const std::shared_ptr<BaseClient> &local_client_base, ssize_t trace_num)
//     {
//   clients_ = clients;
//   local_client_base_ = local_client_base;
//   current_client_ = local_client_base;
//   trace_num_ = trace_num;
//   if (clients_) {
//     clients_->disconnect_cb = disconnect_cb_;
//     clients_->is_disconnect_cb = static_cast<bool>(disconnect_cb_);
//   }
// }

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
  amf flag = interrupt_flag ? interrupt_flag : amgif;
  ClientMaintainer &target = maintainer ? *maintainer : Clients();

  if (!trace_cb) {
    trace_cb = log_manager_.TraceCallbackFunc();
  }
  if (IsLocalNickname_(nickname)) {
    return {Ok(), LocalClient()};
  }

  auto existing = target.GetHost(nickname);
  if (existing) {
    if (force) {
      ApplyKnownHostCallback_(existing);
    }
    ECM rcm = existing->Connect(force, flag);
    if (rcm.first != EC::Success) {
      return {rcm, existing};
    }
    auto existing_cfg = hostm_.GetClientConfig(nickname);
    if (existing_cfg.first.first == EC::Success) {
      ApplyLoginDir_(hostm_, nickname, existing, existing_cfg.second.login_dir,
                     flag);
    } else {
      InitClientWorkdir_(existing);
    }
    return {Ok(), existing};
  }

  auto [rcm2, client_config] = hostm_.GetClientConfig(nickname);
  if (rcm2.first != EC::Success) {
    return {rcm2, nullptr};
  }

  auto keys_result = hostm_.PrivateKeys(false);
  if (keys_result.first.first != EC::Success) {
    return {keys_result.first, nullptr};
  }

  std::atomic<bool> spinner_running(false);
  ResetSpinnerState();
  auto auth_cb = BuildAuthCallback_(password_cb_, quiet, &spinner_running);
  auto base_client = CreateClient(
      client_config.request, client_config.protocol, 10, std::move(trace_cb),
      client_config.buffer_size, keys_result.second, std::move(auth_cb));
  if (!base_client) {
    return {Err(EC::OperationUnsupported, "Unsupported protocol"), nullptr};
  }
  ApplyKnownHostCallback_(base_client);

  std::thread spinner_thread;
  size_t spinner_line_len = 0;
  if (!quiet) {
    const std::string protocol_label =
        std::string(AM_ENUM_NAME(base_client->GetProtocol()));
    const std::string spinner_line = AMStr::amfmt(
        "Connecting to {} Server   [{}]", protocol_label, nickname);
    spinner_line_len = spinner_line.size() + 3;
    SetSpinnerLineLen(spinner_line_len);
    spinner_running.store(true, std::memory_order_relaxed);
    spinner_thread = std::thread([&spinner_running, spinner_line, this]() {
      const std::vector<std::string> frames = {"|", "/", "-", "\\"};
      size_t idx = 0;
      while (spinner_running.load(std::memory_order_relaxed) &&
             !SpinnerStopRequested()) {
        std::cout << '\r' << frames[idx % frames.size()] << "  " << spinner_line
                  << std::flush;
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

  ApplyLoginDir_(hostm_, nickname, base_client, client_config.login_dir, flag);
  target.add_client(nickname, base_client, true);
  return {Ok(), base_client};
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::AddClient(const std::string &nickname, bool force, bool quiet,
                    TraceCallback trace_cb, amf interrupt_flag,
                    bool register_to_manager) {
  if (register_to_manager) {
    return AddClient(nickname, nullptr, force, quiet, std::move(trace_cb),
                     interrupt_flag);
  }

  amf flag = interrupt_flag ? interrupt_flag : amgif;
  if (IsLocalNickname_(nickname)) {
    return {Ok(), LocalClient()};
  }
  if (!trace_cb) {
    trace_cb = log_manager_.TraceCallbackFunc();
  }

  auto client_config = hostm_.GetClientConfig(nickname);
  if (client_config.first.first != EC::Success) {
    return {client_config.first, nullptr};
  }

  auto keys_result = hostm_.PrivateKeys(false);
  if (keys_result.first.first != EC::Success) {
    return {keys_result.first, nullptr};
  }

  std::atomic<bool> spinner_running(false);
  ResetSpinnerState();
  auto auth_cb = BuildAuthCallback_(password_cb_, quiet, &spinner_running);
  auto base_client =
      CreateClient(client_config.second.request, client_config.second.protocol,
                   10, std::move(trace_cb), client_config.second.buffer_size,
                   keys_result.second, std::move(auth_cb));
  if (!base_client) {
    return {Err(EC::OperationUnsupported, "Unsupported protocol"), nullptr};
  }
  ApplyKnownHostCallback_(base_client);

  std::thread spinner_thread;
  size_t spinner_line_len = 0;
  if (!quiet) {
    const std::string protocol_label =
        std::string(AM_ENUM_NAME(base_client->GetProtocol()));
    const std::string spinner_line = AMStr::amfmt(
        "Connecting to {} Server   [{}]", protocol_label, nickname);
    spinner_line_len = spinner_line.size() + 3;
    SetSpinnerLineLen(spinner_line_len);
    spinner_running.store(true, std::memory_order_relaxed);
    spinner_thread = std::thread([&spinner_running, spinner_line, this]() {
      const std::vector<std::string> frames = {"|", "/", "-", "\\"};
      size_t idx = 0;
      while (spinner_running.load(std::memory_order_relaxed) &&
             !SpinnerStopRequested()) {
        std::cout << '\r' << frames[idx % frames.size()] << "  " << spinner_line
                  << std::flush;
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

  ApplyLoginDir_(hostm_, nickname, base_client, client_config.second.login_dir,
                 flag);
  return {Ok(), base_client};
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::Connect(const std::string &nickname, const std::string &hostname,
                  const std::string &username, ClientProtocol protocol,
                  int64_t port, const std::string &password,
                  const std::string &keyfile,
                  std::shared_ptr<ClientMaintainer> maintainer, bool quiet,
                  TraceCallback trace_cb, amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : amgif;
  ClientMaintainer &target = maintainer ? *maintainer : Clients();

  if (protocol == ClientProtocol::LOCAL ||
      protocol == ClientProtocol::Unknown) {
    return {Err(EC::InvalidArg, "Unsupported protocol for remote connect"),
            nullptr};
  }

  std::string resolved_nickname = AMStr::Strip(nickname);
  std::string error = "";
  while (true) {
    error.clear();
    if (resolved_nickname.empty()) {
      error = "Nickname cannot be empty.";
    } else if (AMStr::lowercase(resolved_nickname) == "local") {
      error = "Nickname cannot be 'local'.";
    } else if (!configkn::ValidateNickname(resolved_nickname)) {
      error = "Nickname must match [A-Za-z0-9_-]+.";
    }
    if (error.empty()) {
      break;
    }
    prompt_.ErrorFormat(Err(EC::InvalidArg, error));
    if (!prompt_.Prompt("Enter a legal nickname: ", "", &resolved_nickname)) {
      return {Err(EC::ConfigCanceled, "Nickname input canceled"), nullptr};
    }
    resolved_nickname = AMStr::Strip(resolved_nickname);
  }

  std::vector<std::string> keys;
  if (keyfile.empty()) {
    auto keys_result = hostm_.PrivateKeys(false);
    if (keys_result.first.first != EC::Success) {
      return {keys_result.first, nullptr};
    }
    keys = std::move(keys_result.second);
  } else {
    keys.push_back(keyfile);
  }

  std::string password_enc = AMStr::Strip(password);
  if (!password_enc.empty() && !AMAuth::IsEncrypted(password_enc)) {
    password_enc = AMAuth::EncryptPassword(password_enc);
  }

  ConRequst request(resolved_nickname, hostname, username,
                    static_cast<int>(port), password_enc, keyfile, false, "");
  if (!trace_cb) {
    trace_cb = log_manager_.TraceCallbackFunc();
  }
  auto auth_cb = BuildAuthCallback_(password_cb_, quiet, nullptr);
  auto base_client = CreateClient(request, protocol, 10, std::move(trace_cb),
                                  AMDefaultRemoteBufferSize, std::move(keys),
                                  std::move(auth_cb));
  if (!base_client) {
    return {Err(EC::OperationUnsupported, "Unsupported protocol"), nullptr};
  }

  ApplyKnownHostCallback_(base_client);
  ECM rcm = base_client->Connect(false, flag);
  if (rcm.first != EC::Success) {
    return {rcm, base_client};
  }

  ClientConfig entry;
  entry.request = request;
  entry.protocol = protocol;
  entry.buffer_size = AMDefaultRemoteBufferSize;
  entry.login_dir = "";
  ECM save_rcm = hostm_.UpsertHost(entry, true);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }

  ApplyLoginDir_(hostm_, resolved_nickname, base_client, "", flag);
  target.add_client(resolved_nickname, base_client, true);
  return {Ok(), base_client};
}

ECM Operator::RemoveClient(const std::string &nickname,
                           std::shared_ptr<ClientMaintainer> maintainer) {
  if (IsLocalNickname_(nickname)) {
    return Err(EC::InvalidArg, "Local client cannot be removed");
  }
  ClientMaintainer &target = maintainer ? *maintainer : Clients();
  auto existing = target.GetHost(nickname);
  if (!existing) {
    return Err(EC::ClientNotFound, "Client not found");
  }
  target.remove_client(nickname);
  return Ok();
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::CheckClient(const std::string &nickname,
                      const std::shared_ptr<ClientMaintainer> &maintainer,
                      bool update, amf interrupt_flag, int timeout_ms,
                      int64_t start_time) {
  amf flag = interrupt_flag ? interrupt_flag : amgif;
  ClientMaintainer &target = maintainer ? *maintainer : Clients();
  return target.test_client(nickname, update, flag, timeout_ms, start_time);
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::EnsureClient(const std::string &nickname, amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : amgif;
  if (IsLocalNickname_(nickname)) {
    return {Ok(), LocalClient()};
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
  return {Ok(), existing};
}

AuthCallback Operator::BuildAuthCallback_(const AuthCallback &auth_cb,
                                          bool quiet,
                                          std::atomic<bool> *spinner_running) {
  if (!auth_cb) {
    return {};
  }
  return [this, auth_cb, quiet, spinner_running](const AuthCBInfo &info) {
    RequestSpinnerStop();
    if (spinner_running) {
      spinner_running->store(false, std::memory_order_relaxed);
    }
    std::optional<std::string> result;
    if (auth_cb) {
      result = auth_cb(info);
    }
    return result;
  };
}

void Operator::ApplyKnownHostCallback_(
    const std::shared_ptr<BaseClient> &client) {
  if (!client || client->GetProtocol() != ClientProtocol::SFTP) {
    return;
  }
  auto sftp_client = std::dynamic_pointer_cast<AMSFTPClient>(client);
  if (!sftp_client) {
    return;
  }
  sftp_client->SetKnownHostCallback([this](const KnownHostQuery &query) -> ECM {
    RequestSpinnerStop();
    if (!query.IsValid()) {
      return Err(EC::InvalidArg, "invalid known host query");
    }
    KnownHostQuery stored = query;
    ECM find_rcm = hostm_.FindKnownHost(stored);
    if (find_rcm.first != EC::Success) {
      bool canceled = false;
      bool accepted = true;
      if (AMIsInteractive.load(std::memory_order_relaxed)) {
        prompt_.Print(AMStr::amfmt(
            "Unknown host: {}:{}  User: {} Protocol: [!se][{}][/se]",
            query.hostname, query.port, query.username, query.protocol));
        prompt_.Print(AMStr::amfmt("Fingerprint: {}",
                                   AMStr::Strip(query.GetFingerprint())));
        accepted =
            prompt_.PromptYesNo("Trust this host key? (y/N): ", &canceled);
      }
      if (canceled || !accepted) {
        return Err(EC::ConfigCanceled, "Known host fingerprint add canceled");
      }
      return hostm_.UpsertKnownHost(query, true);
    }
    if (find_rcm.first != EC::Success) {
      return find_rcm;
    }

    const std::string expected = AMStr::Strip(stored.GetFingerprint());
    const std::string actual = AMStr::Strip(query.GetFingerprint());
    if (expected != actual) {
      return Err(EC::HostFingerprintMismatch,
                 AMStr::amfmt("{}:{} {} fingerprint mismatches", query.hostname,
                              query.port, query.protocol));
    }
    return Ok();
  });
}

std::optional<std::string>
Operator::DefaultPasswordCallback(const AuthCBInfo &info) {
  std::lock_guard<std::mutex> lock(auth_io_mtx_);

  const std::string client_name =
      info.request.nickname.empty() ? "unknown" : info.request.nickname;

  if (info.NeedPassword) {
    const std::string prompt =
        AMStr::amfmt("Password required [{}]: ", client_name);
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
    prompt_.Print(AMStr::amfmt("Wrong password [{}]", client_name));
    return std::nullopt;
  }

  auto cfg = hostm_.GetClientConfig(client_name);
  if (cfg.first.first == EC::Success) {
    cfg.second.request.password = info.password_n;
    (void)hostm_.UpsertHost(cfg.second, true);
  }
  return std::nullopt;
}

void Operator::DefaultDisconnectCallback(
    const std::shared_ptr<BaseClient> &client, const ECM &ecm) {
  if (!client || ecm.first == EC::Success) {
    return;
  }
  prompt_.ErrorFormat(
      ECM{ecm.first,
          AMStr::amfmt("Client disconnected [{}]: {}", client->GetNickname(),
                       ecm.second.empty() ? std::string(AM_ENUM_NAME(ecm.first))
                                          : ecm.second)});
}

AuthCallback Operator::BuiltinPasswordCallback_() {
  return
      [this](const AuthCBInfo &info) { return DefaultPasswordCallback(info); };
}

Operator::DisconnectCallback Operator::BuiltinDisconnectCallback_() {
  return [this](const std::shared_ptr<BaseClient> &client, const ECM &ecm) {
    DefaultDisconnectCallback(client, ecm);
  };
}

std::shared_ptr<BaseClient> Operator::CreateLocalClient_() {
  auto [rcm, cfg] = hostm_.GetLocalConfig();
  auto client_t = CreateClient(cfg.request, ClientProtocol::LOCAL, 10,
                               std::move(log_manager_.TraceCallbackFunc()),
                               cfg.buffer_size, {}, {});
  if (!client_t) {
    std::cerr << "Failed to create local client: Unsupported protocol"
              << std::endl;
    std::exit(1);
  }
  (void)client_t->SetPulbicValue(
      "workdir", AMPathStr::UnifyPathSep(cfg.login_dir, "/"), true);
  (void)client_t->SetPulbicValue(
      "login_dir", AMPathStr::UnifyPathSep(cfg.login_dir, "/"), true);
  return client_t;
}

} // namespace AMClientManage
