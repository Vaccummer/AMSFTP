#include "interface/adapters/client/ClientInterfaceService.hpp"

#include "domain/client/ClientDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/core/Enum.hpp"
#include "foundation/tools/path.hpp"
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
#include <unordered_set>
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
using AMDomain::host::HostService::NormalizeNickname;
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

ECM ValidateChangeClientNickname_(
    const AMHostConfigManager &host_config_manager, const std::string &raw,
    std::string *normalized) {
  if (normalized == nullptr) {
    return Err(EC::InvalidArg, "null nickname output");
  }

  std::string candidate = NormalizeNickname(AMStr::Strip(raw));
  if (candidate.empty()) {
    return Err(EC::InvalidArg, "nickname cannot be empty");
  }

  if (IsLocalNickname(candidate)) {
    *normalized = "local";
    return Ok();
  }
  if (!ValidateNickname(candidate)) {
    return Err(EC::InvalidArg, "invalid nickname");
  }
  if (!host_config_manager.HostExists(candidate)) {
    return Err(EC::HostConfigNotFound,
               AMStr::fmt("host profile not found: {}", candidate));
  }

  *normalized = candidate;
  return Ok();
}

ECM ResolveChangeClientNickname_(
    AMPromptIOManager &prompt, const AMHostConfigManager &host_config_manager,
    const std::string &raw_nickname, std::string *normalized) {
  if (normalized == nullptr) {
    return Err(EC::InvalidArg, "null nickname output");
  }

  const std::string seeded = AMStr::Strip(raw_nickname);
  if (!seeded.empty()) {
    return ValidateChangeClientNickname_(host_config_manager, seeded,
                                         normalized);
  }

  std::vector<std::string> candidates = host_config_manager.ListNames();
  candidates.emplace_back("local");
  std::vector<std::pair<std::string, std::string>> prompt_candidates = {};
  prompt_candidates.reserve(candidates.size());
  for (const auto &item : candidates) {
    prompt_candidates.emplace_back(item, "");
  }

  while (true) {
    std::string input = {};
    if (!prompt.Prompt("Profile nickname(host): ", "", &input, {},
                       prompt_candidates)) {
      return Err(EC::ConfigCanceled, "profile edit canceled");
    }
    input = AMStr::Strip(input);
    if (input.empty()) {
      continue;
    }

    const ECM rcm =
        ValidateChangeClientNickname_(host_config_manager, input, normalized);
    if (isok(rcm)) {
      return Ok();
    }
    prompt.ErrorFormat(rcm);
  }
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
  const auto metadata = client->MetaDataPort().QueryTypedValue<ClientMetaData>();
  if (metadata.has_value()) {
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

namespace render {
void PrintClientStatusLine(AMPromptIOManager &prompt,
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
       << AMStr::PadRightUtf8(protocol, format.protocol_width) << "  "
       << AMStr::PadRightUtf8(nickname, format.nickname_width) << "  "
       << AMStr::PadRightUtf8(cwd, format.cwd_width);
  if (!isok(rcm)) {
    const std::string ec_name = std::string(AMStr::ToString(rcm.first));
    const std::string msg = rcm.second.empty()
                                ? std::string(AMStr::ToString(rcm.first))
                                : rcm.second;
    line << "  " << ec_name << "  " << msg;
  }
  prompt.Print(line.str());
}

void PrintHostConfigDetail(AMPromptIOManager &prompt,
                           const std::string &nickname,
                           const HostConfig &config) {
  const auto values = config.GetStrDict();
  prompt.Print("\\[" + nickname + "]");

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
} // namespace render

namespace hostui {
bool ParseBool_(const std::string &text, bool *out) {
  if (!out) {
    return false;
  }
  const std::string normalized = AMStr::lowercase(AMStr::Strip(text));
  if (normalized == "true" || normalized == "1" || normalized == "yes" ||
      normalized == "on") {
    *out = true;
    return true;
  }
  if (normalized == "false" || normalized == "0" || normalized == "no" ||
      normalized == "off") {
    *out = false;
    return true;
  }
  return false;
}

bool ParseInt64_(const std::string &text, int64_t *out) {
  if (!out) {
    return false;
  }
  const std::string trimmed = AMStr::Strip(text);
  if (trimmed.empty()) {
    return false;
  }
  std::istringstream iss(trimmed);
  int64_t value = 0;
  char extra = '\0';
  if (!(iss >> value)) {
    return false;
  }
  if (iss >> extra) {
    return false;
  }
  *out = value;
  return true;
}

std::vector<std::string> DedupTargets_(const std::vector<std::string> &targets) {
  std::vector<std::string> out = {};
  std::unordered_set<std::string> seen = {};
  out.reserve(targets.size());
  for (const auto &target : targets) {
    const std::string value = AMStr::Strip(target);
    if (value.empty()) {
      continue;
    }
    if (seen.insert(value).second) {
      out.push_back(value);
    }
  }
  return out;
}

std::string ResolveLocalUsername_() {
  std::string local_user = "";
#ifdef _WIN32
  AMStr::GetEnv("USERNAME", &local_user);
#else
  AMStr::GetEnv("USER", &local_user);
#endif
  return local_user.empty() ? std::string("local") : local_user;
}

int DefaultPortForProtocol_(ClientProtocol protocol) {
  if (protocol == ClientProtocol::FTP) {
    return AMDomain::host::DefaultFTPPort;
  }
  return AMDomain::host::DefaultSFTPPort;
}

std::string DefaultUsernameForProtocol_(ClientProtocol protocol) {
  if (protocol == ClientProtocol::FTP) {
    return "anonymous";
  }
  return ResolveLocalUsername_();
}

bool PromptHostText_(AMPromptIOManager &prompt, const std::string &label,
                     const std::string &placeholder, std::string *out,
                     bool allow_empty) {
  if (!out) {
    return false;
  }
  auto checker = [allow_empty](const std::string &value) {
    return allow_empty || !AMStr::Strip(value).empty();
  };
  return prompt.Prompt(label, placeholder, out, checker, {});
}

bool PromptHostBool_(AMPromptIOManager &prompt, const std::string &label,
                     bool current, bool *out) {
  if (!out) {
    return false;
  }
  std::string input = current ? "true" : "false";
  const std::vector<std::pair<std::string, std::string>> literals = {
      {"true", "Enable"},
      {"false", "Disable"},
  };
  if (!prompt.LiteralPrompt(label, input, &input, literals)) {
    return false;
  }
  bool parsed = current;
  if (!ParseBool_(input, &parsed)) {
    return false;
  }
  *out = parsed;
  return true;
}

bool PromptHostProtocol_(AMPromptIOManager &prompt, ClientProtocol current,
                         ClientProtocol *out) {
  if (!out) {
    return false;
  }
  std::string input = AMStr::lowercase(AMStr::ToString(current));
  if (input.empty() || input == "unknown") {
    input = "sftp";
  }
  const std::vector<std::pair<std::string, std::string>> literals = {
      {"sftp", "SFTP protocol"},
      {"ftp", "FTP protocol"},
      {"local", "Local protocol"},
  };
  if (!prompt.LiteralPrompt("Protocol: ", input, &input, literals)) {
    return false;
  }
  *out = AMDomain::host::HostService::StrToProtocol(
      AMStr::lowercase(AMStr::Strip(input)));
  return true;
}

bool PromptHostInt64_(AMPromptIOManager &prompt, const std::string &label,
                      int64_t current, int64_t min_v, int64_t max_v,
                      int64_t *out, bool allow_empty = false) {
  if (!out) {
    return false;
  }
  std::string input = std::to_string(current);
  auto checker = [min_v, max_v, allow_empty](const std::string &value) {
    if (allow_empty && AMStr::Strip(value).empty()) {
      return true;
    }
    int64_t parsed = 0;
    if (!ParseInt64_(value, &parsed)) {
      return false;
    }
    return parsed >= min_v && parsed <= max_v;
  };
  if (!prompt.Prompt(label, input, &input, checker, {})) {
    return false;
  }
  if (allow_empty && AMStr::Strip(input).empty()) {
    return true;
  }
  int64_t parsed = current;
  if (!ParseInt64_(input, &parsed)) {
    return false;
  }
  *out = parsed;
  return true;
}

ECM ResolveHostConfig_(AMHostConfigManager &host_config_manager,
                       const std::string &nickname, HostConfig *out) {
  if (!out) {
    return Err(EC::InvalidArg, "null host config output");
  }
  std::pair<ECM, HostConfig> result = {};
  if (IsLocalNickname(nickname)) {
    result = host_config_manager.GetLocalConfig();
  } else {
    result = host_config_manager.GetClientConfig(nickname);
  }
  if (!isok(result.first)) {
    return result.first;
  }
  *out = result.second;
  return Ok();
}

void PrintHostCompact_(AMPromptIOManager &prompt,
                       const std::vector<std::string> &nicknames) {
  if (nicknames.empty()) {
    prompt.Print("");
    return;
  }
  const size_t max_width = 80;
  size_t current_width = 0;
  std::ostringstream line;
  for (const auto &nickname : nicknames) {
    const size_t display_len = nickname.size();
    const size_t separator_len = current_width == 0 ? 0 : 3;
    if (current_width + separator_len + display_len > max_width &&
        current_width > 0) {
      prompt.Print(line.str());
      line.str(std::string());
      line.clear();
      current_width = 0;
    }
    if (current_width > 0) {
      line << "   ";
      current_width += 3;
    }
    line << nickname;
    current_width += display_len;
  }
  if (current_width > 0) {
    prompt.Print(line.str());
  }
}

std::string HostFieldDisplay_(const HostConfig &entry,
                              const std::string &field) {
  if (field == "hostname") {
    return entry.request.hostname;
  }
  if (field == "username") {
    return entry.request.username;
  }
  if (field == "port") {
    return std::to_string(entry.request.port);
  }
  if (field == "protocol") {
    return AMStr::lowercase(AMStr::ToString(entry.request.protocol));
  }
  if (field == "password") {
    return entry.request.password.empty() ? "\"\"" : "***";
  }
  if (field == "buffer_size") {
    return std::to_string(entry.request.buffer_size);
  }
  if (field == "compression") {
    return entry.request.compression ? "true" : "false";
  }
  if (field == "cmd_prefix") {
    return entry.metadata.cmd_prefix;
  }
  if (field == "wrap_cmd") {
    return entry.metadata.wrap_cmd ? "true" : "false";
  }
  if (field == "keyfile") {
    return entry.request.keyfile;
  }
  if (field == "trash_dir") {
    return entry.metadata.trash_dir;
  }
  if (field == "login_dir") {
    return entry.metadata.login_dir;
  }
  return "";
}

ECM PromptAddHostConfig_(AMPromptIOManager &prompt,
                         AMHostConfigManager &host_config_manager,
                         const std::string &nickname, HostConfig *out) {
  if (!out) {
    return Err(EC::InvalidArg, "null host config output");
  }
  HostConfig entry = {};

  std::string nickname_input = AMStr::Strip(nickname);
  while (true) {
    if (nickname_input.empty() &&
        !PromptHostText_(prompt, "Nickname: ", "", &nickname_input, false)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    nickname_input = AMStr::Strip(nickname_input);
    if (!ValidateNickname(nickname_input)) {
      prompt.ErrorFormat(Err(
          EC::InvalidArg,
          "invalid nickname, pattern is [a-zA-Z0-9_-]+"));
      nickname_input.clear();
      continue;
    }
    if (IsLocalNickname(nickname_input)) {
      prompt.ErrorFormat(Err(EC::InvalidArg, "Nickname 'local' is reserved"));
      nickname_input.clear();
      continue;
    }
    if (host_config_manager.HostExists(nickname_input)) {
      prompt.ErrorFormat(Err(EC::KeyAlreadyExists, "nickname already exists"));
      nickname_input.clear();
      continue;
    }
    entry.request.nickname = nickname_input;
    break;
  }

  while (true) {
    if (!PromptHostProtocol_(prompt, ClientProtocol::SFTP,
                             &entry.request.protocol)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    const std::string protocol =
        AMStr::lowercase(AMStr::ToString(entry.request.protocol));
    if (protocol == "sftp" || protocol == "ftp" || protocol == "local") {
      break;
    }
    prompt.ErrorFormat(Err(EC::InvalidArg,
                           "protocol must be sftp, ftp or local"));
  }

  const bool hostname_required = entry.request.protocol != ClientProtocol::LOCAL;
  while (true) {
    std::string hostname = entry.request.hostname;
    if (!PromptHostText_(prompt, "Hostname: ", hostname, &hostname,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      prompt.ErrorFormat(Err(EC::InvalidArg, "hostname cannot be empty"));
      continue;
    }
    entry.request.hostname = hostname;
    break;
  }

  const std::string default_username =
      DefaultUsernameForProtocol_(entry.request.protocol);
  entry.request.username = default_username;
  while (true) {
    std::string username = entry.request.username;
    if (!PromptHostText_(prompt, "Username: ", default_username, &username,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = default_username;
    }
    if (hostname_required && username.empty()) {
      prompt.ErrorFormat(Err(EC::InvalidArg, "username cannot be empty"));
      continue;
    }
    entry.request.username = username;
    break;
  }

  int64_t port = DefaultPortForProtocol_(entry.request.protocol);
  if (!PromptHostInt64_(prompt, AMStr::fmt("Port(default {}): ", port), port, 1,
                        65535, &port, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  entry.request.port = static_cast<int>(port);

  while (true) {
    std::string first = "";
    std::string second = "";
    if (!prompt.SecurePrompt("password(optional): ", &first) ||
        !prompt.SecurePrompt("confirm password: ", &second)) {
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      return Err(EC::ConfigCanceled, "input canceled");
    }
    if (first != second) {
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      prompt.ErrorFormat(Err(EC::InvalidArg, "Passwords do not match"));
      continue;
    }
    if (first.empty()) {
      entry.request.password.clear();
    } else {
      entry.request.password = AMAuth::EncryptPassword(first);
    }
    AMAuth::SecureZero(first);
    AMAuth::SecureZero(second);
    break;
  }

  if (!PromptHostText_(prompt, "keyfile(optional): ", entry.request.keyfile,
                       &entry.request.keyfile, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }

  int64_t buffer_size = 24 * AMMB;
  if (!PromptHostInt64_(prompt, "Buffer size: ", buffer_size,
                        AMDomain::client::ClientService::AMMinBufferSize,
                        AMDomain::client::ClientService::AMMaxBufferSize,
                        &buffer_size, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  entry.request.buffer_size = buffer_size;

  if (!PromptHostBool_(prompt, "compression: ", false,
                       &entry.request.compression)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }

  if (!PromptHostText_(prompt, "trash_dir(optional): ", entry.metadata.trash_dir,
                       &entry.metadata.trash_dir, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "cmd_prefix(optional): ", entry.metadata.cmd_prefix,
                       &entry.metadata.cmd_prefix, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostBool_(prompt, "wrap_cmd(true/false): ", entry.metadata.wrap_cmd,
                       &entry.metadata.wrap_cmd)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }

  *out = entry;
  return Ok();
}

ECM PromptModifyHostConfig_(AMPromptIOManager &prompt,
                            const std::string &nickname, HostConfig *inout) {
  if (!inout) {
    return Err(EC::InvalidArg, "null host config");
  }
  HostConfig entry = *inout;
  const ClientProtocol original_protocol = entry.request.protocol;

  while (true) {
    if (!PromptHostProtocol_(prompt, entry.request.protocol,
                             &entry.request.protocol)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    const std::string protocol =
        AMStr::lowercase(AMStr::ToString(entry.request.protocol));
    if (protocol == "sftp" || protocol == "ftp" || protocol == "local") {
      break;
    }
    prompt.ErrorFormat(Err(EC::InvalidArg,
                           "protocol must be sftp, ftp or local"));
  }

  const ClientProtocol selected_protocol = entry.request.protocol;
  const bool protocol_changed = selected_protocol != original_protocol;
  const bool hostname_required = selected_protocol != ClientProtocol::LOCAL;
  const std::string default_username =
      DefaultUsernameForProtocol_(selected_protocol);
  const int default_port = DefaultPortForProtocol_(selected_protocol);

  while (true) {
    std::string hostname = entry.request.hostname;
    if (!PromptHostText_(prompt, "Hostname: ", hostname, &hostname,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      prompt.ErrorFormat(Err(EC::InvalidArg, "hostname cannot be empty"));
      continue;
    }
    entry.request.hostname = hostname;
    break;
  }

  while (true) {
    std::string username =
        (protocol_changed || entry.request.username.empty())
            ? default_username
            : entry.request.username;
    if (!PromptHostText_(prompt, "Username: ", username, &username,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "input canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = default_username;
    }
    if (hostname_required && username.empty()) {
      prompt.ErrorFormat(Err(EC::InvalidArg, "username cannot be empty"));
      continue;
    }
    entry.request.username = username;
    break;
  }

  int64_t port = (protocol_changed || entry.request.port <= 0 ||
                  entry.request.port > 65535)
                     ? default_port
                     : entry.request.port;
  if (!PromptHostInt64_(prompt, AMStr::fmt("Port(default {}): ", default_port),
                        port, 1, 65535, &port, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  entry.request.port = static_cast<int>(port);

  bool canceled = false;
  const bool change_password =
      prompt.PromptYesNo("Change password? (y/N): ", &canceled);
  if (canceled) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (change_password) {
    while (true) {
      std::string first = "";
      std::string second = "";
      if (!prompt.SecurePrompt("password(optional): ", &first) ||
          !prompt.SecurePrompt("confirm password: ", &second)) {
        AMAuth::SecureZero(first);
        AMAuth::SecureZero(second);
        return Err(EC::ConfigCanceled, "input canceled");
      }
      if (first != second) {
        AMAuth::SecureZero(first);
        AMAuth::SecureZero(second);
        prompt.ErrorFormat(Err(EC::InvalidArg, "Passwords do not match"));
        continue;
      }
      entry.request.password =
          first.empty() ? std::string() : AMAuth::EncryptPassword(first);
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      break;
    }
  }

  if (!PromptHostText_(prompt, "keyfile(optional): ", entry.request.keyfile,
                       &entry.request.keyfile, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }

  int64_t buffer_size =
      entry.request.buffer_size > 0 ? entry.request.buffer_size : 24 * AMMB;
  if (!PromptHostInt64_(prompt, "Buffer size: ", buffer_size,
                        AMDomain::client::ClientService::AMMinBufferSize,
                        AMDomain::client::ClientService::AMMaxBufferSize,
                        &buffer_size, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  entry.request.buffer_size = buffer_size;

  if (!PromptHostBool_(prompt, "Compression (true/false): ",
                       entry.request.compression, &entry.request.compression)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "trash_dir(optional): ", entry.metadata.trash_dir,
                       &entry.metadata.trash_dir, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostText_(prompt, "cmd_prefix(optional): ", entry.metadata.cmd_prefix,
                       &entry.metadata.cmd_prefix, true)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }
  if (!PromptHostBool_(prompt, "wrap_cmd(true/false): ", entry.metadata.wrap_cmd,
                       &entry.metadata.wrap_cmd)) {
    return Err(EC::ConfigCanceled, "input canceled");
  }

  entry.request.nickname = nickname;
  *inout = entry;
  return Ok();
}
} // namespace hostui

} // namespace

ClientInterfaceService::ClientInterfaceService(
    ClientAppService &client_service, FilesystemAppService &filesystem_service,
    AMHostConfigManager &host_config_manager,
    AMKnownHostsManager &known_hosts_manager,
    AMPromptIOManager &prompt_io_manager)
    : client_service_(client_service), filesystem_service_(filesystem_service),
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
  return AMDomain::client::ClientControlComponent(default_control_token_);
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
      auto existing = client_service_.GetClient(nickname, true);
      const bool existed_before = isok(existing.rcm) && existing.data;

      auto ensured =
          client_service_.EnsureClient(nickname, control, true, false);
      status = MergeStatus_(status, ensured.rcm);
      if (!isok(ensured.rcm) || !ensured.data) {
        continue;
      }

      if (existed_before) {
        const std::string ensured_nickname =
            ensured.data->ConfigPort().GetNickname();
        const std::optional<AMDomain::filesystem::CheckResult> checked =
            client_service_.CheckClient(ensured_nickname, false, true, control);
        if (!checked.has_value()) {
          status = MergeStatus_(
              status, Err(EC::ClientNotFound, AMStr::fmt("Client not found: {}",
                                                         ensured_nickname)));
          continue;
        }
        if (!isok(checked.value().rcm)) {
          const std::optional<AMDomain::filesystem::CheckResult> rechecked =
              client_service_.CheckClient(ensured_nickname, true, true,
                                          control);
          if (!rechecked.has_value()) {
            status = MergeStatus_(status, Err(EC::ClientNotFound,
                                              AMStr::fmt("Client not found: {}",
                                                         ensured_nickname)));
            continue;
          }
          status = MergeStatus_(status, rechecked.value().rcm);
        }
      }
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
  const ClientControlComponent control = ResolveControl_(component);
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, "Interrupted by user");
  }

  std::string nickname = {};
  ECM resolve_rcm = ResolveChangeClientNickname_(
      prompt_io_manager_, host_config_manager_, request.nickname, &nickname);
  if (!isok(resolve_rcm)) {
    return resolve_rcm;
  }

  auto changed = client_service_.ChangeClient(nickname, control, request.quiet);
  if (!isok(changed.rcm) || !changed.data) {
    return changed.rcm;
  }
  ECM ensure_cwd_rcm =
      filesystem_service_.EnsureClientWorkdir(changed.data, control);
  if (!isok(ensure_cwd_rcm)) {
    return ensure_cwd_rcm;
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

ECM ClientInterfaceService::ListClients(
    const ListClientsRequest &request,
    const std::optional<ClientControlComponent> &component) {
  std::vector<std::string> targets = request.nicknames;
  if (targets.empty()) {
    targets = client_service_.GetClientNames();
  }
  targets = AMStr::UniqueTargetsKeepOrder(targets);
  if (targets.empty()) {
    return Err(EC::ClientNotFound, "No client to list");
  }

  const ClientControlComponent control = ResolveControl_(component);
  ECM status = Ok();
  std::vector<std::string> resolved_names = {};
  resolved_names.reserve(targets.size());
  const std::vector<std::string> client_names =
      client_service_.GetClientNames();
  const std::vector<std::string> host_names = host_config_manager_.ListNames();

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
      resolved_names.emplace_back("local");
      continue;
    }

    std::string resolved =
        FindClientNicknameCaseInsensitive_(client_names, stripped);
    if (resolved.empty()) {
      resolved = FindClientNicknameCaseInsensitive_(host_names, stripped);
    }
    if (resolved.empty()) {
      ECM rcm =
          Err(EC::ClientNotFound, AMStr::fmt("Client not found: {}", stripped));
      prompt_io_manager_.ErrorFormat(rcm);
      status = MergeStatus_(status, rcm);
      continue;
    }
    resolved_names.emplace_back(resolved);
  }

  resolved_names = AMStr::UniqueTargetsKeepOrder(resolved_names);
  if (resolved_names.empty()) {
    return isok(status) ? Err(EC::ClientNotFound, "No valid clients to list")
                        : status;
  }

  if (!request.check && !request.detail) {
    prompt_io_manager_.Print(AMStr::join(resolved_names, " "));
    return status;
  }

  auto print_host_detail = [this, &status](const std::string &nickname) {
    std::pair<ECM, HostConfig> config_data = {};
    if (IsLocalNickname(nickname)) {
      config_data = host_config_manager_.GetLocalConfig();
    } else {
      config_data = host_config_manager_.GetClientConfig(nickname);
    }
    if (!isok(config_data.first)) {
      prompt_io_manager_.ErrorFormat(config_data.first);
      status = MergeStatus_(status, config_data.first);
      return;
    }
    render::PrintHostConfigDetail(prompt_io_manager_, nickname,
                                  config_data.second);
  };

  if (!request.check && request.detail) {
    for (const auto &nickname : resolved_names) {
      if (control.IsInterrupted()) {
        return Err(EC::Terminate, "Interrupted by user");
      }
      print_host_detail(nickname);
    }
    return status;
  }

  std::vector<std::pair<std::string, ClientHandle>> resolved_clients = {};
  resolved_clients.reserve(resolved_names.size());
  for (const auto &nickname : resolved_names) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    if (IsLocalNickname(nickname)) {
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
    auto client = client_service_.GetClient(nickname, true);
    if (!isok(client.rcm) || !client.data) {
      ECM rcm =
          Err(EC::ClientNotFound, AMStr::fmt("Client not found: {}", nickname));
      prompt_io_manager_.ErrorFormat(rcm);
      status = MergeStatus_(status, rcm);
      continue;
    }
    resolved_clients.emplace_back(nickname, client.data);
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
    render::PrintClientStatusLine(prompt_io_manager_, entry.first, entry.second,
                                  rcm, format);
  }
  if (request.detail) {
    for (const auto &nickname : resolved_names) {
      if (control.IsInterrupted()) {
        return Err(EC::Terminate, "Interrupted by user");
      }
      print_host_detail(nickname);
    }
  }
  return status;
}

ECM ClientInterfaceService::ListPrivateKeys(bool detail) {
  const std::vector<std::string> keys = host_config_manager_.PrivateKeys();
  if (!detail) {
    return Ok();
  }

  prompt_io_manager_.Print("[SSH Private Keys]");
  for (size_t i = 0; i < keys.size(); ++i) {
    const std::string abs_path =
        AMPath::abspath(keys[i], true, AMPath::HomePath());
    prompt_io_manager_.Print(AMStr::fmt("[{}]  {}", i, abs_path));
  }
  return Ok();
}

ECM ClientInterfaceService::AddHost(const std::string &nickname) {
  std::string normalized = NormalizeNickname(AMStr::Strip(nickname));
  if (!normalized.empty()) {
    if (!ValidateNickname(normalized)) {
      const ECM rcm = Err(
          EC::InvalidArg,
          "invalid nickname, pattern is [a-zA-Z0-9_-]+");
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
    if (IsLocalNickname(normalized)) {
      const ECM rcm = Err(EC::InvalidArg, "Nickname 'local' is reserved");
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
    if (host_config_manager_.HostExists(normalized)) {
      const ECM rcm = Err(EC::KeyAlreadyExists, "nickname already exists");
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
  }

  HostConfig entry = {};
  const ECM prompt_rcm = hostui::PromptAddHostConfig_(
      prompt_io_manager_, host_config_manager_, normalized, &entry);
  if (!isok(prompt_rcm)) {
    return prompt_rcm;
  }

  const ECM add_rcm = host_config_manager_.AddHost(entry, true);
  if (!isok(add_rcm)) {
    prompt_io_manager_.ErrorFormat(add_rcm);
  }
  return add_rcm;
}

ECM ClientInterfaceService::ModifyHost(const std::string &nickname) {
  if (!host_config_manager_.HostExists(nickname)) {
    const ECM rcm = Err(EC::HostConfigNotFound, "host not found");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  HostConfig updated = {};
  const ECM get_rcm =
      hostui::ResolveHostConfig_(host_config_manager_, nickname, &updated);
  if (!isok(get_rcm)) {
    prompt_io_manager_.ErrorFormat(get_rcm);
    return get_rcm;
  }

  const ECM prompt_rcm =
      hostui::PromptModifyHostConfig_(prompt_io_manager_, nickname, &updated);
  if (!isok(prompt_rcm)) {
    return prompt_rcm;
  }

  const ECM add_rcm = host_config_manager_.AddHost(updated, true);
  if (!isok(add_rcm)) {
    prompt_io_manager_.ErrorFormat(add_rcm);
  }
  return add_rcm;
}

ECM ClientInterfaceService::RenameHost(const std::string &old_nickname,
                                       const std::string &new_nickname) {
  ECM rcm = Ok();
  if (old_nickname.empty() || new_nickname.empty()) {
    rcm = Err(EC::InvalidArg, "empty nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (old_nickname == new_nickname) {
    rcm = Err(EC::InvalidArg, "new nickname same as old nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (!ValidateNickname(new_nickname)) {
    rcm =
        Err(EC::InvalidArg, "invalid new nickname, pattern is [a-zA-Z0-9_-]+");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (host_config_manager_.HostExists(new_nickname)) {
    rcm = Err(EC::KeyAlreadyExists, "new nickname already exists");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (!host_config_manager_.HostExists(old_nickname)) {
    rcm = Err(EC::HostConfigNotFound, "old nickname not found");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  rcm = host_config_manager_.Rename(old_nickname, new_nickname);
  if (!isok(rcm)) {
    prompt_io_manager_.ErrorFormat(rcm);
  }
  return rcm;
}

ECM ClientInterfaceService::RemoveHosts(
    const std::vector<std::string> &nicknames) {
  const std::vector<std::string> uniq_targets = hostui::DedupTargets_(nicknames);
  if (uniq_targets.empty()) {
    return Ok();
  }

  ECM rcm = Ok();
  std::vector<std::string> valid_targets = {};
  valid_targets.reserve(uniq_targets.size());

  for (const auto &name : uniq_targets) {
    if (IsLocalNickname(name)) {
      rcm = Err(EC::InvalidArg, "local host cannot be removed");
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    if (!host_config_manager_.HostExists(name)) {
      rcm = Err(EC::InvalidArg, AMStr::fmt("invalid host nickname: {}", name));
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    valid_targets.push_back(name);
  }

  if (valid_targets.empty()) {
    return rcm;
  }

  std::string listing = "";
  for (size_t i = 0; i < valid_targets.size(); ++i) {
    if (i > 0) {
      listing += ", ";
    }
    listing += valid_targets[i];
  }

  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      AMStr::fmt("Delete {} host(s): {} ? (y/N): ", valid_targets.size(),
                 listing),
      &canceled);
  if (canceled || !confirmed) {
    prompt_io_manager_.Print("Delete aborted.");
    return Ok();
  }

  for (const auto &name : valid_targets) {
    rcm = host_config_manager_.DelHost(name);
    if (!isok(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
  }

  return Ok();
}

ECM ClientInterfaceService::SetHostValue(const SetHostValueRequest &request) {
  const std::string nickname = AMStr::Strip(request.nickname);
  const std::string field = AMStr::lowercase(AMStr::Strip(request.attrname));
  if (nickname.empty()) {
    const ECM err = Err(EC::InvalidArg, "empty nickname");
    prompt_io_manager_.ErrorFormat(err);
    return err;
  }
  if (!host_config_manager_.HostExists(nickname)) {
    const ECM err = Err(EC::HostConfigNotFound, "host not found");
    prompt_io_manager_.ErrorFormat(err);
    return err;
  }

  static const std::vector<std::string> kAllowedFields = {
      "hostname",    "username",   "port",      "buffer_size",
      "compression", "cmd_prefix", "wrap_cmd",  "protocol",
      "password",    "keyfile",    "trash_dir", "login_dir"};
  bool field_validated = false;
  for (const auto &allowed : kAllowedFields) {
    if (field == allowed) {
      field_validated = true;
      break;
    }
  }
  if (!field_validated) {
    const ECM err = Err(EC::InvalidArg, "unsupported property name");
    prompt_io_manager_.ErrorFormat(err);
    return err;
  }

  HostConfig before = {};
  const ECM before_rcm =
      hostui::ResolveHostConfig_(host_config_manager_, nickname, &before);
  if (!isok(before_rcm)) {
    prompt_io_manager_.ErrorFormat(before_rcm);
    return before_rcm;
  }

  std::string resolved_value = request.value;
  if (field == "password" && AMStr::Strip(resolved_value).empty()) {
    if (!prompt_io_manager_.SecurePrompt("Password: ", &resolved_value)) {
      const ECM err = Err(EC::ConfigCanceled, "password input canceled");
      prompt_io_manager_.ErrorFormat(err);
      return err;
    }
  }

  const std::string old_value = hostui::HostFieldDisplay_(before, field);
  const ECM set_rcm =
      host_config_manager_.SetHostValue(nickname, field, resolved_value);
  if (!isok(set_rcm)) {
    prompt_io_manager_.ErrorFormat(set_rcm);
    return set_rcm;
  }

  HostConfig after = {};
  const ECM after_rcm =
      hostui::ResolveHostConfig_(host_config_manager_, nickname, &after);
  const std::string new_value =
      isok(after_rcm) ? hostui::HostFieldDisplay_(after, field) : resolved_value;

  prompt_io_manager_.Print(
      AMStr::fmt("{}.{}: {} -> {}", nickname, field, old_value, new_value));
  return Ok();
}

ECM ClientInterfaceService::ListHosts(bool detail) {
  const std::vector<std::string> nicknames = host_config_manager_.ListNames();
  if (!detail) {
    hostui::PrintHostCompact_(prompt_io_manager_, nicknames);
    return Ok();
  }

  if (nicknames.empty()) {
    prompt_io_manager_.Print("");
    return Ok();
  }

  for (const auto &nickname : nicknames) {
    HostConfig entry = {};
    const ECM get_rcm =
        hostui::ResolveHostConfig_(host_config_manager_, nickname, &entry);
    if (!isok(get_rcm)) {
      return get_rcm;
    }
    render::PrintHostConfigDetail(prompt_io_manager_, nickname, entry);
    prompt_io_manager_.Print("");
  }
  return Ok();
}
} // namespace AMInterface::client
