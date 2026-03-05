#include "infrastructure/client/common/Base.hpp"
#include "interface/ApplicationAdapters.hpp"
#include "infrastructure/client/runtime/IOCore.hpp"
#include "domain/client/ClientManager.hpp"
#include "infrastructure/Config.hpp"
#include "domain/host/HostManager.hpp"
#include "infrastructure/Logger.hpp"
#include "interface/Prompt.hpp"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

using ClientHandle = AMDomain::client::AMClientOperator::ClientHandle;
using AuthCallback = AMDomain::client::AMClientOperator::AuthCallback;
using TraceCallback = AMDomain::client::AMClientOperator::TraceCallback;

namespace {
/**
 * @brief Resolve heartbeat check timeout from settings with clamped range.
 */
int ResolveHeartbeatTimeoutMsFromSettings_() {
  std::function<int(int)> clamp_timeout = [](int value) -> int {
    if (value < 10) {
      return 10;
    }
    if (value > 10000) {
      return 10000;
    }
    return value;
  };
  return AMInterface::ApplicationAdapters::Runtime::ConfigManagerOrThrow().ResolveArg(
      DocumentKind::Settings,
      {"Options", "ClientManager", "heartbeat_timeout_ms"}, 100, clamp_timeout);
}

inline bool IsLocalNickname_(const std::string &nickname) {
  const std::string lowered = AMStr::lowercase(AMStr::Strip(nickname));
  return lowered.empty() || lowered == "local";
}

inline ClientMaintainer::DisconnectCallback
BuildMaintainerDisconnectCallback_(
    const AMDomain::client::AMClientOperator::DisconnectCallback &cb) {
  return cb;
}

inline void InitClientWorkdir_(const ClientHandle &client) {
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

inline void ApplyLoginDir_(AMDomain::host::AMHostManager &hostm, const std::string &nickname,
                           const ClientHandle &client,
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

inline void StoreClientMetadata_(const ClientHandle &client,
                                 const ClientMetaData &metadata) {
  if (!client) {
    return;
  }
  (void)client->StoreNamedData(AMDomain::client::kClientMetadataStoreName,
                               metadata, true);
}
} // namespace

ECM AMDomain::client::AMClientManager::Init() {
  SetPasswordCallback();
  SetDisconnectCallback();
  local_client_base_ = CreateLocalClient_();
  if (!local_client_base_) {
    return Err(EC::ProgrammInitializeFailed, "Failed to create local client");
  }
  const int heartbeat_timeout_ms = ResolveHeartbeatTimeoutMsFromSettings_();
  clients_ = std::make_shared<ClientMaintainer>(
      60, heartbeat_timeout_ms,
      BuildMaintainerDisconnectCallback_(disconnect_cb_),
      local_client_base_);
  clients_->SetDisconnectCallback(
      BuildMaintainerDisconnectCallback_(disconnect_cb_));
  current_client_ = local_client_base_;
  return Ok();
}

void AMDomain::client::AMClientOperator::SetPasswordCallback(AuthCallback cb) {
  password_cb_ = cb ? std::move(cb) : BuiltinPasswordCallback_();
}

void AMDomain::client::AMClientOperator::SetDisconnectCallback(DisconnectCallback cb) {
  disconnect_cb_ = cb ? std::move(cb) : BuiltinDisconnectCallback_();
  if (clients_) {
    clients_->SetDisconnectCallback(
        BuildMaintainerDisconnectCallback_(disconnect_cb_));
  }
}

ClientMaintainer &AMDomain::client::AMClientOperator::Clients() {
  if (!clients_) {
    const int heartbeat_timeout_ms = ResolveHeartbeatTimeoutMsFromSettings_();
    clients_ = std::make_shared<ClientMaintainer>(
        60, heartbeat_timeout_ms,
        BuildMaintainerDisconnectCallback_(disconnect_cb_),
        LocalClient());
  }
  return *clients_;
}

std::vector<std::string> AMDomain::client::AMClientOperator::GetClientNames() {
  return clients_ ? clients_->GetNicknames() : std::vector<std::string>{};
}

std::vector<ClientHandle> AMDomain::client::AMClientOperator::GetClients() {
  return clients_ ? clients_->GetClients() : std::vector<ClientHandle>{};
}

/**
 * @brief Return one managed client by nickname.
 */
ClientHandle AMDomain::client::AMClientOperator::GetClient(const std::string &nickname) const {
  if (clients_) {
    return clients_->GetClient(nickname);
  }
  if (IsLocalNickname_(nickname)) {
    return LocalClient();
  }
  return nullptr;
}

ClientHandle AMDomain::client::AMClientOperator::LocalClient() const {
  return local_client_base_;
}

std::string AMDomain::client::AMClientOperator::CurrentNickname() const {
  return current_client_->GetNickname();
}

ClientHandle AMDomain::client::AMClientOperator::CurrentClient() const {
  if (current_client_) {
    return current_client_;
  } else {
    return LocalClient();
  }
}

void AMDomain::client::AMClientOperator::SetCurrentClient(const ClientHandle &client) {
  current_client_ = client;
}

// void AMDomain::client::AMClientOperator::ConfigureState(
//     const std::shared_ptr<ClientMaintainer> &clients,
//     const ClientHandle &local_client_base, ssize_t trace_num)
//     {
//   clients_ = clients;
//   local_client_base_ = local_client_base;
//   current_client_ = local_client_base;
//   trace_num_ = trace_num;
//   if (clients_) {
//     clients_->SetDisconnectCallback(
//         BuildMaintainerDisconnectCallback_(disconnect_cb_));
//   }
// }

void AMDomain::client::AMClientOperator::ResetSpinnerState() {
  spinner_stop_requested_.store(false, std::memory_order_relaxed);
  spinner_line_len_.store(0, std::memory_order_relaxed);
}

void AMDomain::client::AMClientOperator::SetSpinnerLineLen(size_t line_len) {
  spinner_line_len_.store(line_len, std::memory_order_relaxed);
}

bool AMDomain::client::AMClientOperator::SpinnerStopRequested() const {
  return spinner_stop_requested_.load(std::memory_order_relaxed);
}

void AMDomain::client::AMClientOperator::RequestSpinnerStop() {
  if (spinner_stop_requested_.exchange(true, std::memory_order_relaxed)) {
    return;
  }
  const size_t line_len = spinner_line_len_.load(std::memory_order_relaxed);
  if (line_len > 0) {
    std::cout << '\r' << std::string(line_len, ' ') << '\r' << std::flush;
  }
}

std::pair<ECM, ClientHandle>
AMDomain::client::AMClientOperator::AddClient(const std::string &nickname,
                           std::shared_ptr<ClientMaintainer> maintainer,
                           bool force, bool quiet, TraceCallback trace_cb,
                           amf interrupt_flag) {
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
    auto existing_cfg = AMDomain::host::AMHostManager::Instance().GetClientConfig(nickname);
    if (existing_cfg.first.first == EC::Success) {
      StoreClientMetadata_(existing, existing_cfg.second.metadata);
      ApplyLoginDir_(AMDomain::host::AMHostManager::Instance(), nickname, existing,
                     existing_cfg.second.metadata.login_dir, flag);
    } else {
      InitClientWorkdir_(existing);
    }
    return {Ok(), existing};
  }

  auto [rcm2, client_config] = AMDomain::host::AMHostManager::Instance().GetClientConfig(nickname);
  if (rcm2.first != EC::Success) {
    return {rcm2, nullptr};
  }

  auto keys_result = AMDomain::host::AMHostManager::Instance().PrivateKeys(false);
  if (keys_result.first.first != EC::Success) {
    return {keys_result.first, nullptr};
  }

  std::atomic<bool> spinner_running(false);
  ResetSpinnerState();
  auto auth_cb = BuildAuthCallback_(password_cb_, quiet, &spinner_running);
  auto base_client = AMInfra::ClientRuntime::CreateClient(
      client_config.request, 10, std::move(trace_cb), keys_result.second,
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

  StoreClientMetadata_(base_client, client_config.metadata);
  ApplyLoginDir_(AMDomain::host::AMHostManager::Instance(), nickname, base_client, client_config.metadata.login_dir, flag);
  target.add_client(nickname, base_client, true);
  return {Ok(), base_client};
}

std::pair<ECM, ClientHandle>
AMDomain::client::AMClientOperator::AddClient(const std::string &nickname, bool force,
                           bool quiet, TraceCallback trace_cb,
                           amf interrupt_flag, bool register_to_manager) {
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

  auto client_config = AMDomain::host::AMHostManager::Instance().GetClientConfig(nickname);
  if (client_config.first.first != EC::Success) {
    return {client_config.first, nullptr};
  }

  auto keys_result = AMDomain::host::AMHostManager::Instance().PrivateKeys(false);
  if (keys_result.first.first != EC::Success) {
    return {keys_result.first, nullptr};
  }

  std::atomic<bool> spinner_running(false);
  ResetSpinnerState();
  auto auth_cb = BuildAuthCallback_(password_cb_, quiet, &spinner_running);
  auto base_client = AMInfra::ClientRuntime::CreateClient(
      client_config.second.request, 10, std::move(trace_cb),
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

  StoreClientMetadata_(base_client, client_config.second.metadata);
  ApplyLoginDir_(AMDomain::host::AMHostManager::Instance(), nickname, base_client, client_config.second.metadata.login_dir,
                 flag);
  return {Ok(), base_client};
}

std::pair<ECM, ClientHandle>
AMDomain::client::AMClientOperator::Connect(const std::string &nickname,
                         const std::string &hostname,
                         const std::string &username,
                         ClientProtocol protocol, int64_t port,
                         const std::string &password,
                         const std::string &keyfile,
                         std::shared_ptr<ClientMaintainer> maintainer,
                         bool quiet, TraceCallback trace_cb,
                         amf interrupt_flag) {
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
    auto keys_result = AMDomain::host::AMHostManager::Instance().PrivateKeys(false);
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
  auto base_client = AMInfra::ClientRuntime::CreateClient(
      request, 10, std::move(trace_cb), std::move(keys), std::move(auth_cb));
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
  ECM save_rcm = AMDomain::host::AMHostManager::Instance().UpsertHost(entry, true);
  if (save_rcm.first != EC::Success) {
    return {save_rcm, base_client};
  }

  StoreClientMetadata_(base_client, entry.metadata);
  ApplyLoginDir_(AMDomain::host::AMHostManager::Instance(), resolved_nickname, base_client, "", flag);
  target.add_client(resolved_nickname, base_client, true);
  return {Ok(), base_client};
}

ECM AMDomain::client::AMClientOperator::RemoveClient(
    const std::string &nickname, std::shared_ptr<ClientMaintainer> maintainer) {
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

std::pair<ECM, ClientHandle>
AMDomain::client::AMClientOperator::CheckClient(const std::string &nickname,
                             const std::shared_ptr<ClientMaintainer> &maintainer,
                             bool update, amf interrupt_flag, int timeout_ms,
                             int64_t start_time) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  ClientMaintainer &target = maintainer ? *maintainer : Clients();
  auto client = target.GetClient(nickname);
  if (!client) {
    const std::string display =
        AMStr::Strip(nickname).empty() ? "local" : AMStr::Strip(nickname);
    return {Err(EC::ClientNotFound, AMStr::fmt("Client not found: {}", display)),
            nullptr};
  }

  const int64_t begin_time =
      start_time == -1 ? AMTime::miliseconds() : start_time;
  if (!update) {
    ECM rcm = client->GetState();
    if (rcm.first != EC::Success) {
      rcm = client->Check(flag, timeout_ms, begin_time);
    }
    return {rcm, client};
  }
  return {client->Check(flag, timeout_ms, begin_time), client};
}

std::pair<ECM, ClientHandle>
AMDomain::client::AMClientOperator::EnsureClient(const std::string &nickname,
                               amf interrupt_flag) {
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

void AMDomain::client::AMClientOperator::SetIsInteractiveFlag(
    const std::shared_ptr<std::atomic<bool>> &is_interactive) {
  if (!is_interactive) {
    return;
  }
  is_interactive_ = is_interactive;
}

bool AMDomain::client::AMClientOperator::IsInteractive() const {
  if (!is_interactive_) {
    return false;
  }
  return is_interactive_->load(std::memory_order_relaxed);
}

std::shared_ptr<std::atomic<bool>> AMDomain::client::AMClientOperator::GetIsInteractiveFlag()
    const {
  return is_interactive_;
}

AuthCallback AMDomain::client::AMClientOperator::BuildAuthCallback_(
    const AuthCallback &auth_cb, bool quiet,
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

void AMDomain::client::AMClientOperator::ApplyKnownHostCallback_(const ClientHandle &client) {
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
    ECM find_rcm = AMDomain::host::AMHostManager::Instance().FindKnownHost(stored);
    if (find_rcm.first != EC::Success) {
      bool canceled = false;
      bool accepted = true;
      if (IsInteractive()) {
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
      return AMDomain::host::AMHostManager::Instance().UpsertKnownHost(query, true);
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
AMDomain::client::AMClientOperator::DefaultPasswordCallback(const AuthCBInfo &info) {
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

  auto cfg = AMDomain::host::AMHostManager::Instance().GetClientConfig(client_name);
  if (cfg.first.first == EC::Success) {
    cfg.second.request.password = info.password_n;
    (void)AMDomain::host::AMHostManager::Instance().UpsertHost(cfg.second, true);
  }
  return std::nullopt;
}

void AMDomain::client::AMClientOperator::DefaultDisconnectCallback(
    const ClientHandle &client, const ECM &ecm) {
  if (!client || ecm.first == EC::Success) {
    return;
  }
  AMPromptManager::Instance().ErrorFormat(
      ECM{ecm.first,
          AMStr::fmt("Client disconnected [{}]: {}", client->GetNickname(),
                       ecm.second.empty() ? std::string(AMStr::ToString(ecm.first))
                                          : ecm.second)});
}

AuthCallback AMDomain::client::AMClientOperator::BuiltinPasswordCallback_() {
  return
      [this](const AuthCBInfo &info) { return DefaultPasswordCallback(info); };
}

AMDomain::client::AMClientOperator::DisconnectCallback
AMDomain::client::AMClientOperator::BuiltinDisconnectCallback_() {
  return [this](const ClientHandle &client, const ECM &ecm) {
    DefaultDisconnectCallback(client, ecm);
  };
}

ClientHandle AMDomain::client::AMClientOperator::CreateLocalClient_() {
  auto [rcm, cfg] = AMDomain::host::AMHostManager::Instance().GetLocalConfig();
  auto client_t = AMInfra::ClientRuntime::CreateClient(
      cfg.request, 10, std::move(AMLogManager::Instance().TraceCallbackFunc()),
      {}, {});
  if (!client_t) {
    std::cerr << "Failed to create local client: Unsupported protocol"
              << std::endl;
    std::exit(1);
  }
  ClientMetaData metadata = cfg.metadata;
  metadata.login_dir = AMPathStr::UnifyPathSep(cfg.metadata.login_dir, "/");
  metadata.cwd = metadata.login_dir;
  StoreClientMetadata_(client_t, metadata);
  client_t->SetLoginDir(metadata.login_dir);
  client_t->SetCwd(metadata.cwd);
  return client_t;
}



