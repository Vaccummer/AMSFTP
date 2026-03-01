#include "AMClient/Base.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Logger.hpp"
#include "AMManager/Prompt.hpp"
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
  const std::string value = AMPathStr::UnifyPathSep(client->GetCwd(), "/");
  if (!value.empty()) {
    return;
  }
  const std::string home = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
  client->SetCwd(home);
}

inline void ApplyLoginDir_(AMHostManager &hostm, const std::string &nickname,
                           const std::shared_ptr<BaseClient> &client,
                           const std::string &login_dir, amf flag) {
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
  client->SetCwd(normalized);
  client->SetLoginDir(normalized);
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
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  ClientMaintainer &target = maintainer ? *maintainer : Clients();

  if (!trace_cb) {
    trace_cb = AMLogManager::Instance().TraceCallbackFunc();
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
    auto existing_cfg = AMHostManager::Instance().GetClientConfig(nickname);
    if (existing_cfg.first.first == EC::Success) {
      existing->SetClientMetaData(existing_cfg.second.metadata);
      ApplyLoginDir_(AMHostManager::Instance(), nickname, existing,
                     existing_cfg.second.metadata.login_dir, flag);
    } else {
      InitClientWorkdir_(existing);
    }
    return {Ok(), existing};
  }

  auto [rcm2, client_config] = AMHostManager::Instance().GetClientConfig(nickname);
  if (rcm2.first != EC::Success) {
    return {rcm2, nullptr};
  }

  auto keys_result = AMHostManager::Instance().PrivateKeys(false);
  if (keys_result.first.first != EC::Success) {
    return {keys_result.first, nullptr};
  }

  std::atomic<bool> spinner_running(false);
  ResetSpinnerState();
  auto auth_cb = BuildAuthCallback_(password_cb_, quiet, &spinner_running);
  auto base_client = CreateClient(client_config.request, 10, std::move(trace_cb),
                                  keys_result.second, std::move(auth_cb));
  if (!base_client) {
    return {Err(EC::OperationUnsupported, "Unsupported protocol"), nullptr};
  }
  ApplyKnownHostCallback_(base_client);

  std::thread spinner_thread;
  size_t spinner_line_len = 0;
  if (!quiet) {
    const std::string protocol_label =
        std::string(AMStr::ToString(base_client->GetProtocol()));
    const std::string spinner_line = AMStr::fmt(
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

  base_client->SetClientMetaData(client_config.metadata);
  ApplyLoginDir_(AMHostManager::Instance(), nickname, base_client, client_config.metadata.login_dir, flag);
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

  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  if (IsLocalNickname_(nickname)) {
    return {Ok(), LocalClient()};
  }
  if (!trace_cb) {
    trace_cb = AMLogManager::Instance().TraceCallbackFunc();
  }

  auto client_config = AMHostManager::Instance().GetClientConfig(nickname);
  if (client_config.first.first != EC::Success) {
    return {client_config.first, nullptr};
  }

  auto keys_result = AMHostManager::Instance().PrivateKeys(false);
  if (keys_result.first.first != EC::Success) {
    return {keys_result.first, nullptr};
  }

  std::atomic<bool> spinner_running(false);
  ResetSpinnerState();
  auto auth_cb = BuildAuthCallback_(password_cb_, quiet, &spinner_running);
  auto base_client = CreateClient(client_config.second.request, 10,
                                  std::move(trace_cb), keys_result.second,
                                  std::move(auth_cb));
  if (!base_client) {
    return {Err(EC::OperationUnsupported, "Unsupported protocol"), nullptr};
  }
  ApplyKnownHostCallback_(base_client);

  std::thread spinner_thread;
  size_t spinner_line_len = 0;
  if (!quiet) {
    const std::string protocol_label =
        std::string(AMStr::ToString(base_client->GetProtocol()));
    const std::string spinner_line = AMStr::fmt(
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

  base_client->SetClientMetaData(client_config.second.metadata);
  ApplyLoginDir_(AMHostManager::Instance(), nickname, base_client, client_config.second.metadata.login_dir,
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
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
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
    AMPromptManager::Instance().ErrorFormat(Err(EC::InvalidArg, error));
    if (!AMPromptManager::Instance().Prompt("Enter a legal nickname: ", "", &resolved_nickname)) {
      return {Err(EC::ConfigCanceled, "Nickname input canceled"), nullptr};
    }
    resolved_nickname = AMStr::Strip(resolved_nickname);
  }

  std::vector<std::string> keys;
  if (keyfile.empty()) {
    auto keys_result = AMHostManager::Instance().PrivateKeys(false);
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

  ConRequest request = {};
  request.nickname = resolved_nickname;
  request.hostname = hostname;
  request.username = username;
  request.port = static_cast<int>(port);
  request.password = password_enc;
  request.keyfile = keyfile;
  request.compression = false;
  request.trash_dir = "";
  request.buffer_size = AMDefaultRemoteBufferSize;
  request.protocol = protocol;
  if (!trace_cb) {
    trace_cb = AMLogManager::Instance().TraceCallbackFunc();
  }
  auto auth_cb = BuildAuthCallback_(password_cb_, quiet, nullptr);
  auto base_client = CreateClient(request, 10, std::move(trace_cb),
                                  std::move(keys), std::move(auth_cb));
  if (!base_client) {
    return {Err(EC::OperationUnsupported, "Unsupported protocol"), nullptr};
  }

  ApplyKnownHostCallback_(base_client);
  ECM rcm = base_client->Connect(false, flag);
  if (rcm.first != EC::Success) {
    return {rcm, base_client};
  }

  HostConfig entry;
  entry.request = request;
  entry.request.protocol = protocol;
  entry.request.buffer_size = AMDefaultRemoteBufferSize;
  entry.metadata.login_dir = "";
  ECM save_rcm = AMHostManager::Instance().UpsertHost(entry, true);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }

  base_client->SetClientMetaData(entry.metadata);
  ApplyLoginDir_(AMHostManager::Instance(), resolved_nickname, base_client, "", flag);
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
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  ClientMaintainer &target = maintainer ? *maintainer : Clients();
  return target.test_client(nickname, update, flag, timeout_ms, start_time);
}

std::pair<ECM, std::shared_ptr<BaseClient>>
Operator::EnsureClient(const std::string &nickname, amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
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
    ECM find_rcm = AMHostManager::Instance().FindKnownHost(stored);
    if (find_rcm.first != EC::Success) {
      bool canceled = false;
      bool accepted = true;
      if (AMIsInteractive.load(std::memory_order_relaxed)) {
        AMPromptManager::Instance().FmtPrint(
            "Unknown host: {}:{}  User: {} Protocol: [!se][{}][/se]",
            query.hostname, query.port, query.username, query.protocol);
        AMPromptManager::Instance().FmtPrint("Fingerprint: {}",
                                   AMStr::Strip(query.GetFingerprint()));
        accepted =
            AMPromptManager::Instance().PromptYesNo("Trust this host key? (y/N): ", &canceled);
      }
      if (canceled || !accepted) {
        return Err(EC::ConfigCanceled, "Known host fingerprint add canceled");
      }
      return AMHostManager::Instance().UpsertKnownHost(query, true);
    }
    if (find_rcm.first != EC::Success) {
      return find_rcm;
    }

    const std::string expected = AMStr::Strip(stored.GetFingerprint());
    const std::string actual = AMStr::Strip(query.GetFingerprint());
    if (expected != actual) {
      return Err(EC::HostFingerprintMismatch,
                 AMStr::fmt("{}:{} {} fingerprint mismatches", query.hostname,
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
        AMStr::fmt("Password required [{}]: ", client_name);
    std::string password;
    if (!AMPromptManager::Instance().SecurePrompt(prompt, &password)) {
      return std::string();
    }
    return password;
  }

  if (!info.iscorrect) {
    if (info.password_n.empty()) {
      return std::nullopt;
    }
    AMPromptManager::Instance().FmtPrint("Wrong password [{}]", client_name);
    return std::nullopt;
  }

  auto cfg = AMHostManager::Instance().GetClientConfig(client_name);
  if (cfg.first.first == EC::Success) {
    cfg.second.request.password = info.password_n;
    (void)AMHostManager::Instance().UpsertHost(cfg.second, true);
  }
  return std::nullopt;
}

void Operator::DefaultDisconnectCallback(
    const std::shared_ptr<BaseClient> &client, const ECM &ecm) {
  if (!client || ecm.first == EC::Success) {
    return;
  }
  AMPromptManager::Instance().ErrorFormat(
      ECM{ecm.first,
          AMStr::fmt("Client disconnected [{}]: {}", client->GetNickname(),
                       ecm.second.empty() ? std::string(AMStr::ToString(ecm.first))
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
  auto [rcm, cfg] = AMHostManager::Instance().GetLocalConfig();
  auto client_t = CreateClient(cfg.request, 10,
                               std::move(AMLogManager::Instance().TraceCallbackFunc()), {},
                               {});
  if (!client_t) {
    std::cerr << "Failed to create local client: Unsupported protocol"
              << std::endl;
    std::exit(1);
  }
  ClientMetaData metadata = cfg.metadata;
  metadata.login_dir = AMPathStr::UnifyPathSep(cfg.metadata.login_dir, "/");
  metadata.cwd = metadata.login_dir;
  client_t->SetClientMetaData(metadata);
  return client_t;
}

} // namespace AMClientManage

