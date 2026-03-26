#include "interface/adapters/client/ClientInterfaceService.hpp"

#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>

namespace AMInterface::client {
class ClientConnectSpinner final : public NonCopyableNonMovable {
public:
  explicit ClientConnectSpinner(AMPromptIOManager &prompt_io_manager)
      : prompt_io_manager_(prompt_io_manager) {}
  ~ClientConnectSpinner() override { Stop(); }

  void Start(const AMDomain::host::HostConfig &config, bool quiet) {
    Stop();
    if (quiet) {
      return;
    }

    const std::string spinner_line = AMStr::fmt(
        "Connecting to {} Server   [{}]",
        AMStr::ToString(config.request.protocol), config.request.nickname);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stop_requested_.store(false, std::memory_order_relaxed);
      running_.store(true, std::memory_order_relaxed);
      refresh_active_ = true;
      prompt_io_manager_.RefreshBegin(1);
      worker_ =
          std::thread([this, spinner_line]() { RenderLoop_(spinner_line); });
    }
  }

  void Stop() {
    std::thread worker = {};
    bool should_refresh_end = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!refresh_active_ && !worker_.joinable() &&
          !running_.load(std::memory_order_relaxed)) {
        return;
      }

      stop_requested_.store(true, std::memory_order_relaxed);
      running_.store(false, std::memory_order_relaxed);
      if (worker_.joinable()) {
        worker = std::move(worker_);
      }
      should_refresh_end = refresh_active_;
      refresh_active_ = false;
    }

    if (worker.joinable()) {
      worker.join();
    }
    if (should_refresh_end) {
      prompt_io_manager_.RefreshEnd();
    }
  }

  void StopForPrompt() { Stop(); }

  [[nodiscard]] bool IsRunning() const {
    return running_.load(std::memory_order_relaxed);
  }

private:
  void RenderLoop_(const std::string &spinner_line) {
    static const std::vector<std::string> frames = {"|", "/", "-", "\\"};
    size_t idx = 0;
    while (running_.load(std::memory_order_relaxed) &&
           !stop_requested_.load(std::memory_order_relaxed)) {
      prompt_io_manager_.RefreshRender(
          {AMStr::fmt("{}  {}", frames[idx % frames.size()], spinner_line)});
      ++idx;
      std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
  }

  AMPromptIOManager &prompt_io_manager_;
  mutable std::mutex mutex_ = {};
  std::thread worker_ = {};
  std::atomic<bool> running_ = false;
  std::atomic<bool> stop_requested_ = true;
  bool refresh_active_ = false;
};

namespace {
using ClientHandle = AMDomain::client::ClientHandle;
using HostConfig = AMDomain::host::HostConfig;
using ClientMetaData = AMDomain::host::ClientMetaData;
using ClientProtocol = AMDomain::host::ClientProtocol;
using AMDomain::host::HostService::IsLocalNickname;
using AMDomain::host::HostService::ValidateNickname;

struct ClientStatusFormat {
  size_t protocol_width = 0;
  size_t nickname_width = 0;
  size_t cwd_width = 0;
};

ECM MergeStatus_(const ECM &current, const ECM &next) {
  return isok(next) ? current : next;
}

std::string
FindClientNicknameCaseInsensitive_(const std::vector<std::string> &names,
                                   const std::string &target) {
  const std::string lowered = AMStr::lowercase(AMStr::Strip(target));
  for (const auto &name : names) {
    if (AMStr::lowercase(name) == lowered) {
      return name;
    }
  }
  return "";
}

bool ParseUserAtHost_(const std::string &user_at_host, std::string *username,
                      std::string *hostname) {
  if (!username || !hostname) {
    return false;
  }
  const size_t at_pos = user_at_host.find('@');
  if (at_pos == std::string::npos || at_pos == 0 ||
      at_pos + 1 >= user_at_host.size()) {
    return false;
  }
  *username = user_at_host.substr(0, at_pos);
  *hostname = user_at_host.substr(at_pos + 1);
  return !AMStr::Strip(*username).empty() && !AMStr::Strip(*hostname).empty();
}

std::string ResolveClientCwd_(const ClientHandle &client) {
  if (!client) {
    return ".";
  }
  std::string cwd = "";
  const ClientMetaData *metadata =
      client->MetaDataPort().QueryTypedValue<ClientMetaData>();
  if (metadata) {
    cwd = AMStr::Strip(metadata->cwd);
  }
  if (cwd.empty()) {
    cwd = AMStr::Strip(client->ConfigPort().GetHomeDir());
  }
  return cwd.empty() ? "." : cwd;
}

ClientStatusFormat BuildClientStatusFormat_(
    const std::vector<std::pair<std::string, ClientHandle>> &clients) {
  ClientStatusFormat format = {};
  for (const auto &entry : clients) {
    if (!entry.second) {
      continue;
    }
    const std::string protocol =
        "[" +
        std::string(AMStr::ToString(entry.second->ConfigPort().GetProtocol())) +
        "]";
    format.protocol_width = std::max(format.protocol_width, protocol.size());
    format.nickname_width = std::max(format.nickname_width, entry.first.size());
    format.cwd_width =
        std::max(format.cwd_width, ResolveClientCwd_(entry.second).size());
  }
  return format;
}

std::string PadRight_(const std::string &text, size_t width) {
  if (text.size() >= width) {
    return text;
  }
  return text + std::string(width - text.size(), ' ');
}

void PrintClientStatusLine_(AMPromptIOManager &prompt,
                            const std::string &nickname,
                            const ClientHandle &client, const ECM &rcm,
                            const ClientStatusFormat &format) {
  const std::string protocol =
      client ? "[" +
                   std::string(
                       AMStr::ToString(client->ConfigPort().GetProtocol())) +
                   "]"
             : "[Unknown]";
  const std::string cwd = ResolveClientCwd_(client);
  std::ostringstream line;
  line << (isok(rcm) ? "✅  " : "❌  ")
       << PadRight_(protocol, format.protocol_width) << "  "
       << PadRight_(nickname, format.nickname_width) << "  "
       << PadRight_(cwd, format.cwd_width);
  if (!isok(rcm)) {
    const std::string ec_name = std::string(AMStr::ToString(rcm.first));
    const std::string msg = rcm.second.empty()
                                ? std::string(AMStr::ToString(rcm.first))
                                : rcm.second;
    line << "  " << ec_name << "  " << msg;
  }
  prompt.Print(line.str());
}

void PrintClientDetail_(AMPromptIOManager &prompt, const std::string &nickname,
                        const ClientHandle &client, bool print_title = true) {
  if (!client) {
    return;
  }
  ClientMetaData metadata = {};
  if (const auto *stored =
          client->MetaDataPort().QueryTypedValue<ClientMetaData>()) {
    metadata = *stored;
  }
  const std::string cwd = ResolveClientCwd_(client);
  metadata.cwd = cwd;
  if (metadata.login_dir.empty()) {
    metadata.login_dir = cwd;
  }

  const AMDomain::host::ConRequest request = client->ConfigPort().GetRequest();
  auto values = request.GetStrDict();
  auto metadata_values = metadata.GetStrDict();
  values.insert(values.end(), metadata_values.begin(), metadata_values.end());

  if (print_title) {
    prompt.Print("[" + nickname + "]");
  }

  size_t width = 0;
  for (const auto &field : values) {
    if (field.first == "nickname") {
      continue;
    }
    width = std::max(width, field.first.size());
  }

  for (const auto &field : values) {
    if (field.first == "nickname") {
      continue;
    }
    std::string render_value = field.second;
    if (field.first == "cmd_prefix") {
      render_value = "\"" + render_value + "\"";
    } else if (render_value.empty()) {
      render_value = "\"\"";
    }
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field.first
         << " :   " << render_value;
    prompt.Print(line.str());
  }
}

void PrintCheckDetail_(AMPromptIOManager &prompt, const std::string &nickname,
                       const ClientHandle &client, const ECM &rcm) {
  prompt.Print(AMStr::fmt("[{}] {}", nickname, isok(rcm) ? "✅" : "❌"));
  if (!isok(rcm)) {
    const std::string error_code = std::string(AMStr::ToString(rcm.first));
    const std::string error_msg = rcm.second.empty()
                                      ? std::string(AMStr::ToString(rcm.first))
                                      : rcm.second;
    prompt.Print(AMStr::fmt("error_code :   {}", error_code));
    prompt.Print(AMStr::fmt("error_msg  :   {}", error_msg));
  }
  PrintClientDetail_(prompt, nickname, client, false);
}

} // namespace

ClientInterfaceService::ClientInterfaceService(
    ClientAppService &client_service, AMHostConfigManager &host_config_manager,
    AMKnownHostsManager &known_hosts_manager,
    AMPromptIOManager &prompt_io_manager)
    : client_service_(client_service),
      host_config_manager_(host_config_manager),
      known_hosts_manager_(known_hosts_manager),
      prompt_io_manager_(prompt_io_manager),
      spinner_(std::make_unique<ClientConnectSpinner>(prompt_io_manager)) {}

ClientInterfaceService::~ClientInterfaceService() = default;

void ClientInterfaceService::SetDefaultControlToken(const amf &token) {
  default_control_token_ = token;
}

amf ClientInterfaceService::GetDefaultControlToken() const {
  return default_control_token_;
}

void ClientInterfaceService::BindInteractionCallbacks() {
  AMDomain::client::KnownHostCallback known_host_callback =
      [this](const AMDomain::client::KnownHostQuery &query) -> ECM {
    if (spinner_) {
      spinner_->StopForPrompt();
    }
    if (!AMDomain::host::KnownHostRules::ValidateConfig(query)) {
      return Err(EC::InvalidArg, "invalid known host query");
    }

    auto stored = query;
    const ECM find_rcm = known_hosts_manager_.FindKnownHost(stored);
    if (!isok(find_rcm)) {
      bool canceled = false;
      prompt_io_manager_.FmtPrint(
          "Unknown host: {}:{}  User: {} Protocol: [!se][{}][/se]",
          query.hostname, query.port, query.username, query.protocol);
      prompt_io_manager_.FmtPrint("Fingerprint: {}",
                                  AMStr::Strip(query.GetFingerprint()));
      const bool accepted = prompt_io_manager_.PromptYesNo(
          "Trust this host key? (y/N): ", &canceled);
      if (canceled || !accepted) {
        return Err(EC::ConfigCanceled, "Known host fingerprint add canceled");
      }
      return known_hosts_manager_.UpsertKnownHost(query, true);
    }

    const std::string expected = AMStr::Strip(stored.GetFingerprint());
    const std::string actual = AMStr::Strip(query.GetFingerprint());
    if (expected != actual) {
      return Err(EC::HostFingerprintMismatch,
                 AMStr::fmt("{}:{} {} fingerprint mismatches", query.hostname,
                            query.port, query.protocol));
    }
    return Ok();
  };

  AMDomain::client::AuthCallback auth_callback =
      [this](const AMDomain::client::AuthCBInfo &info)
      -> std::optional<std::string> {
    if (spinner_) {
      spinner_->StopForPrompt();
    }
    const std::string client_name =
        info.request.nickname.empty() ? "unknown" : info.request.nickname;
    if (info.NeedPassword) {
      std::string password = "";
      if (!prompt_io_manager_.SecurePrompt(
              AMStr::fmt("Password required [{}]: ", client_name), &password)) {
        return std::string();
      }
      return password;
    }
    if (!info.iscorrect) {
      if (info.password_n.empty()) {
        return std::nullopt;
      }
      prompt_io_manager_.FmtPrint("Wrong password [{}]", client_name);
      return std::nullopt;
    }

    auto cfg = host_config_manager_.GetClientConfig(client_name);
    if (isok(cfg.first)) {
      std::string password = info.password_n;
      if (!password.empty() && !AMAuth::IsEncrypted(password)) {
        password = AMAuth::EncryptPassword(password);
      }
      cfg.second.request.password = password;
      (void)host_config_manager_.AddHost(cfg.second, true);
    }
    return std::nullopt;
  };

  client_service_.RegisterMaintainerCallbacks(
      std::nullopt, std::nullopt, known_host_callback, auth_callback);
  client_service_.RegisterPublicCallbacks(std::nullopt, std::nullopt,
                                          known_host_callback, auth_callback);
  ClientAppService::ConnectHooks hooks = {};
  hooks.before_connect = [this](const HostConfig &hook_config,
                                const ClientHandle &, bool silent) {
    if (spinner_) {
      spinner_->Start(hook_config, silent);
    }
  };
  hooks.after_connect = [this](const HostConfig &, const ClientHandle &, bool,
                               const ECM &) {
    if (spinner_) {
      spinner_->Stop();
    }
  };
  connect_hooks_guard_ =
      client_service_.UseScopedConnectHooks(std::move(hooks));
}

ECMData<ClientHandle>
ClientInterfaceService::UICreateClient(const HostConfig &config,
                                       const ClientControlComponent &control,
                                       bool quiet) {
  if (control.IsInterrupted()) {
    return {nullptr, Err(EC::Terminate, "Interrupted by user")};
  }
  return client_service_.CreateClient(config, control, quiet);
}

ClientControlComponent ClientInterfaceService::ResolveControl_(
    const std::optional<ClientControlComponent> &component) const {
  if (component.has_value()) {
    return component.value();
  }
  return AMDomain::client::MakeClientControlComponent(default_control_token_);
}

ECM ClientInterfaceService::Connect(
    const ConnectRequest &request,
    const std::optional<ClientControlComponent> &component) {
  if (request.nicknames.empty()) {
    return Err(EC::InvalidArg, "connect requires at least one nickname");
  }
  const std::vector<std::string> targets =
      AMStr::UniqueTargetsKeepOrder(request.nicknames);
  const ClientControlComponent control = ResolveControl_(component);
  ECM status = Ok();

  for (const auto &raw : targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }

    const std::string nickname = AMStr::Strip(raw);
    if (nickname.empty()) {
      status = MergeStatus_(status, Err(EC::InvalidArg, "Empty nickname"));
      continue;
    }
    if (!IsLocalNickname(nickname) &&
        !AMDomain::host::HostService::ValidateNickname(nickname)) {
      status = MergeStatus_(status, Err(EC::InvalidArg, "Invalid nickname"));
      continue;
    }
    if (IsLocalNickname(nickname)) {
      continue;
    }

    if (!request.force) {
      auto ensured =
          client_service_.EnsureClient(nickname, control, true, false);
      status = MergeStatus_(status, ensured.rcm);
      continue;
    }

    auto [cfg_rcm, cfg] = host_config_manager_.GetClientConfig(nickname);
    if (!isok(cfg_rcm)) {
      status = MergeStatus_(status, cfg_rcm);
      continue;
    }

    auto created = UICreateClient(cfg, control, false);
    if (!isok(created.rcm) || !created.data) {
      status = MergeStatus_(status, created.rcm);
      continue;
    }

    ECM add_rcm = client_service_.AddClient(created.data, request.force);
    status = MergeStatus_(status, add_rcm);
  }
  return status;
}

ECM ClientInterfaceService::ChangeClient(
    const ChangeClientRequest &request,
    const std::optional<ClientControlComponent> &component) {
  const std::string nickname = AMStr::Strip(request.nickname);
  if (nickname.empty()) {
    return Ok();
  }

  const ClientControlComponent control = ResolveControl_(component);
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, "Interrupted by user");
  }

  auto changed = client_service_.ChangeClient(nickname, control, request.quiet);
  if (!isok(changed.rcm) || !changed.data) {
    return changed.rcm;
  }
  return prompt_io_manager_.ChangeClient(
      changed.data->ConfigPort().GetNickname());
}

ECM ClientInterfaceService::ConnectProtocol_(
    const ProtocolConnectRequest &request, ClientProtocol protocol,
    const std::optional<ClientControlComponent> &component) {
  std::string nickname = AMStr::Strip(request.nickname);
  const ClientControlComponent control = ResolveControl_(component);
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, "Interrupted by user");
  }

  if (nickname.empty()) {
    while (true) {
      if (control.IsInterrupted()) {
        return Err(EC::Terminate, "Interrupted by user");
      }
      std::string prompted_nickname = "";
      if (!prompt_io_manager_.Prompt("Enter a legal nickname: ", "",
                                     &prompted_nickname)) {
        return Err(EC::ConfigCanceled, "Nickname input canceled");
      }
      nickname = AMStr::Strip(prompted_nickname);
      if (nickname.empty()) {
        prompt_io_manager_.ErrorFormat(
            Err(EC::InvalidArg, "Nickname cannot be empty"));
        continue;
      }
      if (!AMDomain::host::HostService::ValidateNickname(nickname)) {
        prompt_io_manager_.ErrorFormat(Err(EC::InvalidArg, "Invalid nickname"));
        continue;
      }
      break;
    }
  } else if (!AMDomain::host::HostService::ValidateNickname(nickname)) {
    return Err(EC::InvalidArg, "Invalid nickname");
  }
  std::string username = "";
  std::string hostname = "";
  if (!ParseUserAtHost_(request.user_at_host, &username, &hostname)) {
    return Err(EC::InvalidArg, "Invalid user@host format");
  }
  if (request.port <= 0 || request.port > 65535) {
    return Err(EC::InvalidArg, "Port must be in range [1, 65535]");
  }

  HostConfig cfg = {};
  cfg.request.nickname = nickname;
  cfg.request.protocol = protocol;
  cfg.request.username = username;
  cfg.request.hostname = hostname;
  cfg.request.port = request.port;
  cfg.request.password = request.password;
  cfg.request.keyfile = request.keyfile;

  ECM validate_rcm = AMDomain::host::HostService::ValidateConfig(cfg);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }

  ECM persist_rcm = host_config_manager_.AddHost(cfg, true);
  if (!isok(persist_rcm)) {
    return persist_rcm;
  }

  auto created = UICreateClient(cfg, control, false);
  if (!isok(created.rcm) || !created.data) {
    return created.rcm;
  }

  ECM add_rcm = client_service_.AddClient(created.data, true);
  if (!isok(add_rcm)) {
    return add_rcm;
  }

  client_service_.SetCurrentClient(created.data);
  return prompt_io_manager_.ChangeClient(
      created.data->ConfigPort().GetNickname());
}

ECM ClientInterfaceService::ConnectSftp(
    const ProtocolConnectRequest &request,
    const std::optional<ClientControlComponent> &component) {
  return ConnectProtocol_(request, ClientProtocol::SFTP, component);
}

ECM ClientInterfaceService::ConnectFtp(
    const ProtocolConnectRequest &request,
    const std::optional<ClientControlComponent> &component) {
  return ConnectProtocol_(request, ClientProtocol::FTP, component);
}

ECM ClientInterfaceService::RemoveClients(
    const RemoveClientsRequest &request,
    const std::optional<ClientControlComponent> &component) {
  if (request.nicknames.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "Empty nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const ClientControlComponent control = ResolveControl_(component);
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, "Interrupted by user");
  }

  const std::vector<std::string> targets =
      AMStr::UniqueTargetsKeepOrder(request.nicknames);
  const std::vector<std::string> names = client_service_.GetClientNames();
  const std::string current = client_service_.CurrentNickname();
  const std::string current_lower = AMStr::lowercase(current);

  ECM last = Ok();
  std::vector<std::string> valid_targets = {};
  std::vector<std::string> show_targets = {};
  valid_targets.reserve(targets.size());
  show_targets.reserve(targets.size());

  for (const auto &target : targets) {
    const std::string stripped = AMStr::Strip(target);
    const std::string lowered = AMStr::lowercase(stripped);
    if (stripped.empty()) {
      last = Err(EC::InvalidArg, "Invalid Empty Client Name");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }
    if (lowered == "local") {
      last = Err(EC::InvalidArg, "Local client cannot be removed");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }
    if (!current_lower.empty() && lowered == current_lower) {
      last = Err(EC::InvalidArg, "Cannot remove current client");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }

    const std::string resolved =
        FindClientNicknameCaseInsensitive_(names, stripped);
    if (resolved.empty()) {
      last = Err(EC::ClientNotFound,
                 AMStr::fmt("Client not established: {}", stripped));
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }

    valid_targets.push_back(resolved);
    show_targets.push_back(resolved);
  }

  if (show_targets.empty()) {
    return isok(last) ? Err(EC::ClientNotFound, "no valid clients to remove")
                      : last;
  }

  std::string target_line = "";
  for (size_t i = 0; i < show_targets.size(); ++i) {
    if (i > 0) {
      target_line += ", ";
    }
    target_line += show_targets[i];
  }

  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      AMStr::fmt("Remove clients: {} ? (y/N): ", target_line), &canceled);
  if (canceled || !confirmed) {
    const std::string msg = "Remove clients canceled";
    prompt_io_manager_.FmtPrint("🚫  {}\n", msg);
    prompt_io_manager_.ErrorFormat(Err(EC::ConfigCanceled, msg));
    return Err(EC::Terminate, msg);
  }

  for (const auto &target : valid_targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    ECM rcm = client_service_.RemoveClient(target);
    if (!isok(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
      last = rcm;
    }
  }
  return last;
}

ECM ClientInterfaceService::CheckClients(
    const CheckClientsRequest &request,
    const std::optional<ClientControlComponent> &component) {
  std::vector<std::string> targets = request.nicknames;
  if (targets.empty()) {
    targets = client_service_.GetClientNames();
  }
  targets = AMStr::UniqueTargetsKeepOrder(targets);
  if (targets.empty()) {
    return Err(EC::ClientNotFound, "No client to check");
  }

  const ClientControlComponent control = ResolveControl_(component);
  ECM status = Ok();
  std::vector<std::pair<std::string, ClientHandle>> resolved_clients = {};
  resolved_clients.reserve(targets.size());

  const std::vector<std::string> names = client_service_.GetClientNames();
  for (const auto &target : targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    const std::string stripped = AMStr::Strip(target);
    if (stripped.empty()) {
      ECM rcm = Err(EC::InvalidArg, "Empty nickname");
      prompt_io_manager_.ErrorFormat(rcm);
      status = MergeStatus_(status, rcm);
      continue;
    }

    if (IsLocalNickname(stripped)) {
      ClientHandle local = client_service_.GetLocalClient();
      if (!local) {
        ECM rcm = Err(EC::ClientNotFound, "local client not initialized");
        prompt_io_manager_.ErrorFormat(rcm);
        status = MergeStatus_(status, rcm);
        continue;
      }
      resolved_clients.emplace_back("local", local);
      continue;
    }

    const std::string resolved =
        FindClientNicknameCaseInsensitive_(names, stripped);
    if (resolved.empty()) {
      ECM rcm =
          Err(EC::ClientNotFound, AMStr::fmt("Client not found: {}", stripped));
      prompt_io_manager_.ErrorFormat(rcm);
      status = MergeStatus_(status, rcm);
      continue;
    }
    auto client = client_service_.GetClient(resolved, true);
    if (!isok(client.rcm) || !client.data) {
      ECM rcm =
          Err(EC::ClientNotFound, AMStr::fmt("Client not found: {}", resolved));
      prompt_io_manager_.ErrorFormat(rcm);
      status = MergeStatus_(status, rcm);
      continue;
    }
    resolved_clients.emplace_back(resolved, client.data);
  }

  const ClientStatusFormat format = BuildClientStatusFormat_(resolved_clients);
  for (const auto &entry : resolved_clients) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    const std::optional<AMDomain::filesystem::CheckResult> check_result =
        client_service_.CheckClient(entry.first, false, true, control);
    const ECM rcm = check_result.has_value()
                        ? check_result.value().rcm
                        : Err(EC::ClientNotFound,
                              AMStr::fmt("Client not found: {}", entry.first));
    status = MergeStatus_(status, rcm);
    if (request.detail) {
      PrintCheckDetail_(prompt_io_manager_, entry.first, entry.second, rcm);
    } else {
      PrintClientStatusLine_(prompt_io_manager_, entry.first, entry.second, rcm,
                             format);
    }
  }
  return status;
}
} // namespace AMInterface::client
